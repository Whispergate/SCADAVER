//! MQTT broker probing over raw TCP: anonymous connect, $SYS recon, credential testing.
//!
//! Implements MQTT 3.1.1 wire protocol directly over `std::net::TcpStream` — no external
//! async crate required, consistent with the rest of the sync library.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default plaintext MQTT port.
pub const MQTT_PORT: u16 = 1883;

const TIMEOUT: Duration = Duration::from_secs(5);
const RECON_TIMEOUT: Duration = Duration::from_millis(1500);

/// Information retrieved from an MQTT broker.
#[derive(Debug, Clone)]
pub struct MqttDevice {
    pub ip: String,
    pub port: u16,
    /// True when the broker returned CONNACK 0x00 with no username/password.
    pub anonymous: bool,
    /// First `$SYS/broker/*` topic and value received, if any. e.g. "$SYS/broker/version: mosquitto 2.0.18"
    pub broker_info: Option<String>,
    /// True when at least one `spBv1.0/` PUBLISH was observed after subscribing (Sparkplug B SCADA node present).
    pub sparkplug: bool,
}

// ─── Wire protocol helpers ───────────────────────────────────────────────────

fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        // len % 128 is always 0..=127 so try_from always succeeds; unwrap_or is a no-op fallback.
        let mut byte = u8::try_from(len % 128).unwrap_or(0);
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

fn decode_remaining_length(stream: &mut TcpStream) -> Result<usize> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for _ in 0..4 {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        let encoded = buf[0];
        value = value.saturating_add((encoded & 0x7F) as usize * multiplier);
        multiplier = multiplier.saturating_mul(128);
        if encoded & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

fn utf8_field(s: &str) -> Vec<u8> {
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(2 + s.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

// ─── Packet builders ─────────────────────────────────────────────────────────

/// Build an MQTT 3.1.1 CONNECT packet.
///
/// Anonymous (both `None`): Connect Flags = 0x02 (clean session only).
/// With credentials (both `Some`): Connect Flags = 0xC2 (username + password + clean session).
pub fn build_connect(client_id: &str, user: Option<&str>, pass: Option<&str>) -> Vec<u8> {
    let connect_flags: u8 = if user.is_some() && pass.is_some() {
        0xC2 // bit7=username, bit6=password, bit1=clean session
    } else {
        0x02 // bit1=clean session only
    };

    // Variable header: protocol name "MQTT" (2+4 bytes), level 4, flags, keep-alive 60s
    let mut var_header: Vec<u8> = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, connect_flags, 0x00, 0x3C];

    let mut payload = utf8_field(client_id);
    if let (Some(u), Some(p)) = (user, pass) {
        payload.extend_from_slice(&utf8_field(u));
        payload.extend_from_slice(&utf8_field(p));
    }

    let remaining = var_header.len() + payload.len();
    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x10); // CONNECT packet type
    packet.extend_from_slice(&encode_remaining_length(remaining));
    packet.append(&mut var_header);
    packet.extend_from_slice(&payload);
    packet
}

/// Build an MQTT 3.1.1 SUBSCRIBE packet for one topic at `QoS` 0.
fn build_subscribe(packet_id: u16, topic: &str) -> Vec<u8> {
    let topic_field = utf8_field(topic);
    let remaining = 2 + topic_field.len() + 1; // packet ID + topic + QoS byte
    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x82); // SUBSCRIBE (type 8 << 4) + mandatory reserved bits 0010
    packet.extend_from_slice(&encode_remaining_length(remaining));
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.extend_from_slice(&topic_field);
    packet.push(0x00); // QoS 0
    packet
}

fn build_disconnect() -> [u8; 2] {
    [0xE0, 0x00]
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Read and parse a CONNACK packet. Returns the return code byte.
/// CONNACK wire format: `20 02 <ack_flags> <return_code>` (always 4 bytes).
pub fn parse_connack(stream: &mut TcpStream) -> Result<u8> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).context("CONNACK: short response")?;
    if buf[0] != 0x20 || buf[1] != 0x02 {
        anyhow::bail!("CONNACK: unexpected packet byte {:#04x} len {}", buf[0], buf[1]);
    }
    Ok(buf[3]) // return code; buf[2] = ack flags (Session Present in bit 0)
}

// ─── Recon helpers ───────────────────────────────────────────────────────────

/// After subscribing to `$SYS/#`, read packets until we get a `$SYS/broker/*` PUBLISH or time out.
/// Returns the first "$SYS/broker/…: <payload>" string found.
fn read_sys_publish(stream: &mut TcpStream) -> Option<String> {
    for _ in 0..12 {
        let mut type_byte = [0u8; 1];
        stream.read_exact(&mut type_byte).ok()?;
        let packet_type = (type_byte[0] >> 4) & 0x0F;
        let qos = (type_byte[0] >> 1) & 0x03;

        let remaining_len = decode_remaining_length(stream).ok()?;
        if remaining_len > 4096 {
            // Drain to keep stream in sync before returning.
            let mut discard = vec![0u8; remaining_len.min(4096)];
            let _ = stream.read_exact(&mut discard);
            return None;
        }
        let mut body = vec![0u8; remaining_len];
        stream.read_exact(&mut body).ok()?;

        if packet_type != 3 || body.len() < 2 {
            continue; // SUBACK or other control packet — skip
        }

        let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + topic_len {
            continue;
        }
        let topic = String::from_utf8_lossy(&body[2..2 + topic_len]);
        // Packet ID present only when QoS > 0; skip it so payload starts correctly.
        let payload_start = 2 + topic_len + if qos > 0 { 2 } else { 0 };
        let payload = if body.len() > payload_start {
            String::from_utf8_lossy(&body[payload_start..]).into_owned()
        } else {
            String::new()
        };

        if topic.starts_with("$SYS/broker") {
            return Some(format!("{topic}: {payload}"));
        }
    }
    None
}

/// After the $SYS subscribe, subscribe to `spBv1.0/#` and check whether any PUBLISH arrives
/// on a Sparkplug B topic. Returns true if a Sparkplug B node is present.
fn probe_sparkplug(stream: &mut TcpStream) -> bool {
    let sub = build_subscribe(2, "spBv1.0/#");
    if stream.write_all(&sub).is_err() {
        return false;
    }
    for _ in 0..5 {
        let mut type_byte = [0u8; 1];
        if stream.read_exact(&mut type_byte).is_err() {
            return false;
        }
        let packet_type = (type_byte[0] >> 4) & 0x0F;
        let Ok(remaining_len) = decode_remaining_length(stream) else { return false };
        if remaining_len > 4096 {
            // Drain to keep stream in sync before returning.
            let mut discard = vec![0u8; remaining_len.min(4096)];
            let _ = stream.read_exact(&mut discard);
            return false;
        }
        let mut body = vec![0u8; remaining_len];
        if stream.read_exact(&mut body).is_err() {
            return false;
        }
        if packet_type == 3 && body.len() >= 2 {
            let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            if body.len() >= 2 + topic_len {
                let topic = String::from_utf8_lossy(&body[2..2 + topic_len]);
                if topic.starts_with("spBv1.0/") {
                    return true;
                }
            }
        }
    }
    false
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Attempt an anonymous CONNECT on the given port.
///
/// Returns `Some(MqttDevice)` when the broker returns CONNACK 0x00 (accepted).
/// Also attempts `$SYS/#` recon and Sparkplug B detection within a 1.5-second window.
pub fn probe(ip: &str, port: u16) -> Option<MqttDevice> {
    let addr = format!("{ip}:{port}");
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, TIMEOUT).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;

    let connect = build_connect("scadaver-probe", None, None);
    stream.write_all(&connect).ok()?;

    let return_code = parse_connack(&mut stream).ok()?;
    if return_code != 0x00 {
        return None;
    }

    // Broker accepted anonymous connect. Switch to a shorter timeout for recon.
    let _ = stream.set_read_timeout(Some(RECON_TIMEOUT));

    let sub = build_subscribe(1, "$SYS/#");
    stream.write_all(&sub).ok()?;

    let broker_info = read_sys_publish(&mut stream);
    let sparkplug = probe_sparkplug(&mut stream);

    let _ = stream.write_all(&build_disconnect());

    Some(MqttDevice {
        ip: ip.to_string(),
        port,
        anonymous: true,
        broker_info,
        sparkplug,
    })
}

/// Test a single credential pair against an MQTT broker.
///
/// Returns `Some(true)` on CONNACK 0x00 (accepted), `Some(false)` on explicit rejection
/// (0x04 bad username/password, 0x05 not authorized), and `None` on network/protocol errors.
/// Creates a fresh TCP connection per attempt.
pub fn try_credential(ip: &str, port: u16, user: &str, pass: &str) -> Option<bool> {
    let addr = format!("{ip}:{port}");
    let mut stream =
        TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(3)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(3))).ok()?;

    let connect = build_connect("scadaver-spray", Some(user), Some(pass));
    stream.write_all(&connect).ok()?;

    let return_code = parse_connack(&mut stream).ok()?;
    let _ = stream.write_all(&build_disconnect());

    Some(return_code == 0x00)
}
