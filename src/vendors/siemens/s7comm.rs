use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default S7comm / ISO-on-TCP port.
pub const S7_PORT: u16 = 102;
const BUFFER_SIZE: usize = 65000;

// COTP destination TSAP candidates tried in order
const COTP_TSAPS: &[&str] = &[
    "c2020101", // S7-1200/1500 slot 1
    "c2020102", // S7-300 slot 2
    "c2020100", // S7-1200/1500 slot 0
    "c2020300", // S7-400
];

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) { return vec![]; }
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Establish a COTP + `S7Comm` session.
pub fn setup_connection(ip: &str, port: u16, timeout_secs: u64) -> Option<TcpStream> {
    for tsap in COTP_TSAPS {
        let addr = format!("{ip}:{port}");
        let Ok(mut stream) = TcpStream::connect_timeout(
            &addr.parse().ok()?,
            Duration::from_secs(timeout_secs),
        ) else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));

        // COTP Connection Request
        let cotp_pkt = format!(
            "03000016 11e00000000100c0010ac1020100{tsap}"
        );
        let Some(cotp_resp) = send_recv(&mut stream, &hex_decode(&cotp_pkt)) else {
            continue;
        };
        let cotp_hex = hex_encode(&cotp_resp);
        if cotp_hex.len() < 12 || &cotp_hex[10..12] != "d0" {
            continue; // Wrong TSAP
        }

        // S7Comm Setup: randomize PDU reference to avoid fixed-invoke-ID fingerprint
        let invoke = rand::random::<u16>();
        let s7_pkt = format!("0300001902f08032010000{invoke:04x}00080000f0000001000101e0");
        let Some(s7_resp) = send_recv(&mut stream, &hex_decode(&s7_pkt)) else { continue };
        let s7_hex = hex_encode(&s7_resp);
        if s7_hex.len() < 20 || &s7_hex[18..20] != "00" {
            continue;
        }

        return Some(stream);
    }
    None
}

fn send_recv(stream: &mut TcpStream, data: &[u8]) -> Option<Vec<u8>> {
    stream.write_all(data).ok()?;
    // TPKT header: version(1) + reserved(1) + total_length(2, big-endian)
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).ok()?;
    let total_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if total_len < 4 {
        return None;
    }
    let body_len = total_len - 4;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).ok()?;
    let mut full = hdr.to_vec();
    full.extend_from_slice(&body);
    Some(full)
}

/// Send an `S7Comm` `UserData` SZL read request and return the raw TPKT response.
fn read_szl(stream: &mut TcpStream, szl_id: u16, szl_index: u16) -> Option<Vec<u8>> {
    let [id_hi, id_lo] = szl_id.to_be_bytes();
    let [idx_hi, idx_lo] = szl_index.to_be_bytes();
    let invoke = rand::random::<u16>();
    // S7 UserData payload = 26 bytes → TPKT total = 33 = 0x21
    let pkt = hex_decode(&format!(
        "0300002102f08032070000{invoke:04x}0008000800011204114401\
         00ff090004{id_hi:02x}{id_lo:02x}{idx_hi:02x}{idx_lo:02x}"
    ));
    send_recv(stream, &pkt)
}

/// Locate the first SZL record byte in a SZL read response.
///
/// Searches for the [0xFF, 0x09] data-section marker, verifies the returned SZL
/// ID matches `expected_id`, then returns the byte offset of the first record
/// (which begins with the record's 2-byte index field).
fn szl_records_start(resp: &[u8], expected_id: u16) -> Option<usize> {
    // Skip past the minimum TPKT+COTP+S7Comm header (19 bytes) before searching
    let search_start = 19usize;
    if resp.len() <= search_start {
        return None;
    }
    let offset = resp[search_start..]
        .windows(2)
        .position(|w| w == [0xFF, 0x09])?;
    let pos = search_start + offset;
    // pos+0: return_code(0xFF), +1: transport(0x09), +2..3: data_len,
    // +4..5: szl_id, +6..7: szl_idx, +8..9: count, +10..11: reclen
    // → first record at pos+12
    if resp.len() < pos + 12 {
        return None;
    }
    let got_id = u16::from_be_bytes([resp[pos + 4], resp[pos + 5]]);
    if got_id != expected_id {
        return None;
    }
    Some(pos + 12)
}

/// Read inputs, outputs, and merkers from an S7 PLC.
pub fn read_all_data(
    ip: &str,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> HashMap<String, Option<HashMap<String, u8>>> {
    let mut result: HashMap<String, Option<HashMap<String, u8>>> = HashMap::new();
    result.insert("inputs".into(), None);
    result.insert("outputs".into(), None);
    result.insert("merkers".into(), None);

    let Some(mut stream) = connect_authenticated(ip, port, timeout_secs, password) else {
        return result;
    };

    let base = "0300001f02f08032010000732f000e00000401120a1006000100008{area}000000";

    for (label, area) in &[("inputs", "1"), ("outputs", "2"), ("merkers", "3")] {
        let pkt_str = base.replace("{area}", area);
        let pkt = hex_decode(&pkt_str);
        let Some(resp) = send_recv(&mut stream, &pkt) else { continue };
        result.insert((*label).to_string(), parse_coil_data(&hex_encode(&resp), label));
    }

    result
}

fn parse_coil_data(s7_hex: &str, label: &str) -> Option<HashMap<String, u8>> {
    if s7_hex.len() < 20 || &s7_hex[18..20] != "00" {
        eprintln!("S7Comm error reading {label}");
        return None;
    }

    let s7_data = &s7_hex[14..];
    if s7_data.len() < 20 {
        return None;
    }
    let data_length = usize::from_str_radix(&s7_data[16..20], 16).ok()?;
    let items_start = 28;
    let items_end = items_start + data_length * 2;
    if s7_data.len() < items_end {
        return None;
    }
    let items = &s7_data[items_start..items_end];
    // Data item: return code (1) + transport size (1) + length (2) + payload.
    // Skip the 4-byte (8 hex char) prefix and decode every byte the PLC returned
    // instead of assuming a fixed 4-byte (DWORD) payload.
    if items.len() < 8 || &items[..2] != "ff" {
        return None;
    }

    let mut result = HashMap::new();
    for (i, chunk) in items.as_bytes()[8..].chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        let byte_val = u8::from_str_radix(hex, 16).unwrap_or(0);
        for bit in 0..8u8 {
            let val = u8::from(byte_val & (1 << bit) != 0);
            result.insert(format!("{i}.{bit}"), val);
        }
    }
    Some(result)
}

/// Write output bits to an S7 PLC.
pub fn set_outputs(ip: &str, binary_str: &str, port: u16, timeout_secs: u64, password: Option<&str>) -> bool {
    let hex_val = bits_to_hex_byte(binary_str);
    let Some(mut stream) = connect_authenticated(ip, port, timeout_secs, password) else {
        return false;
    };

    let pkt_str = format!(
        "03000024 02f08032010000732f000e00050501120a10020001000082000000000400 08{hex_val}"
    );
    let Some(resp) = send_recv(&mut stream, &hex_decode(&pkt_str)) else { return false };
    let hex = hex_encode(&resp);
    hex.len() >= 2 && &hex[hex.len() - 2..] == "ff"
}

/// Write merker bits at a given byte offset.
pub fn set_merkers(
    ip: &str,
    binary_str: &str,
    offset: u32,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> bool {
    let hex_val = bits_to_hex_byte(binary_str);
    if offset > 0x1F_FFFF {
        return false;
    }
    let bit_addr = offset * 8;
    let merker_offset = format!("{bit_addr:06x}");

    let Some(mut stream) = connect_authenticated(ip, port, timeout_secs, password) else {
        return false;
    };

    let pkt_str = format!(
        "03000025 02f080320100001500000e00060501120a10040001000083{merker_offset}00040010{hex_val}00"
    );
    let Some(resp) = send_recv(&mut stream, &hex_decode(&pkt_str)) else { return false };
    let hex = hex_encode(&resp);
    hex.len() >= 2 && &hex[hex.len() - 2..] == "ff"
}

/// Read `length` bytes from data block `db_num` starting at byte `offset`.
pub fn read_data_block(
    ip: &str,
    db_num: u16,
    offset: u16,
    length: u16,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let mut stream = connect_authenticated(ip, port, timeout_secs, password)
        .ok_or_else(|| anyhow::anyhow!("failed to establish S7Comm session to {ip}:{port}"))?;

    // S7Comm Read Area: area 0x84 (DB), transport size 0x02 (BYTE). The S7ANY
    // address is a bit address, so the byte offset is shifted left by 3.
    let bit_addr = u32::from(offset) * 8;
    let pkt_str = format!(
        "0300001f02f08032010000732f000e00000401120a1002{length:04x}{db_num:04x}84{bit_addr:06x}"
    );
    let resp = send_recv(&mut stream, &hex_decode(&pkt_str))
        .ok_or_else(|| anyhow::anyhow!("no response reading DB{db_num}"))?;
    let hex = hex_encode(&resp);

    if hex.len() < 20 || &hex[18..20] != "00" {
        anyhow::bail!("S7Comm protocol error reading DB{db_num} (offset {offset}, len {length})");
    }

    let s7_data = &hex[14..];
    if s7_data.len() < 20 {
        anyhow::bail!("short response reading DB{db_num}");
    }
    let data_length = usize::from_str_radix(&s7_data[16..20], 16)
        .map_err(|e| anyhow::anyhow!("invalid data length field reading DB{db_num}: {e}"))?;
    let items_start = 28;
    let items_end = items_start + data_length * 2;
    if s7_data.len() < items_end {
        anyhow::bail!("truncated data reading DB{db_num}");
    }
    let items = &s7_data[items_start..items_end];
    if items.len() < 8 || &items[..2] != "ff" {
        anyhow::bail!("read of DB{db_num} rejected by PLC (block missing or protected)");
    }
    Ok(hex_decode(&items[8..]))
}

/// Write `data` bytes to data block `db_num` at byte `offset`.
///
/// Returns `true` if the PLC acknowledged the write (last response byte = 0xFF).
pub fn write_data_block(
    ip: &str,
    db_num: u16,
    offset: u16,
    data: &[u8],
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> anyhow::Result<bool> {
    if data.is_empty() {
        anyhow::bail!("write_data_block: no data to write");
    }
    let n = data.len();
    if n > 8191 {
        anyhow::bail!("write_data_block: data too large ({n} bytes, max 8191)");
    }
    let mut stream = connect_authenticated(ip, port, timeout_secs, password)
        .ok_or_else(|| anyhow::anyhow!("failed to establish S7Comm session to {ip}:{port}"))?;
    let bit_addr = u32::from(offset) * 8;
    // data section: error_code(1) + transport_size(1) + bit_count(2) + data(n)
    let data_section_len = 4 + n;
    // param section: function(1) + items(1) + S7ANY item (12 bytes) = 14
    let param_len = 14usize;
    // TPKT total: header(4) + COTP(3) + S7Comm header(10) + param + data
    let tpkt_len = 31 + data_section_len;
    let bit_count = n * 8;
    let data_hex = hex_encode(data);

    // Parameter: write(0x05) | 1 item | S7ANY(0x12, len=10, transport=0x10, type=0x02)
    // | count | db_num | area(0x84=DB) | bit_address
    let pkt_str = format!(
        "0300{tpkt_len:04x}02f08032010000732f{param_len:04x}{data_section_len:04x}\
         0501120a1002{n:04x}{db_num:04x}84{bit_addr:06x}\
         0004{bit_count:04x}{data_hex}"
    );

    let resp = send_recv(&mut stream, &hex_decode(&pkt_str))
        .ok_or_else(|| anyhow::anyhow!("no response writing DB{db_num}"))?;
    let hex = hex_encode(&resp);
    Ok(hex.len() >= 2 && &hex[hex.len() - 2..] == "ff")
}

/// Enumerate readable data blocks on an S7 PLC.
///
/// Rather than parsing an SZL 0x0011 block list (whose binary layout varies
/// across CPU families), this probes DB1..=DB200 by attempting to read their
/// first 2 bytes via [`read_data_block`]. Blocks that respond successfully are
/// returned. The reported size is the number of bytes the probe read back, not
/// the block's full declared length.
pub fn list_data_blocks(ip: &str, port: u16, timeout_secs: u64, password: Option<&str>) -> Vec<(u16, u16)> {
    let mut blocks = Vec::new();
    for db_num in 1..=200u16 {
        if let Ok(data) = read_data_block(ip, db_num, 0, 2, port, timeout_secs, password) {
            if !data.is_empty() {
                blocks.push((db_num, u16::try_from(data.len()).unwrap_or(u16::MAX)));
            }
        }
    }
    blocks
}

fn cpu_state_from_stream(stream: &mut TcpStream) -> String {
    let Some(resp) = read_szl(stream, 0x0424, 0x0001) else {
        return "Unknown".to_string();
    };
    let Some(rec_start) = szl_records_start(&resp, 0x0424) else {
        return "Unknown".to_string();
    };
    let mode_off = rec_start + 2;
    if mode_off >= resp.len() {
        return "Unknown".to_string();
    }
    match resp[mode_off] {
        0x01 => "Running".to_string(),
        0x02 => "Startup".to_string(),
        0x03 => "Stopped".to_string(),
        0x04 => "Hold".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn module_info_from_stream(stream: &mut TcpStream) -> (Option<String>, Option<String>) {
    let Some(resp) = read_szl(stream, 0x0011, 0x0001) else {
        return (None, None);
    };
    let Some(rec_start) = szl_records_start(&resp, 0x0011) else {
        return (None, None);
    };
    if resp.len() < rec_start + 28 {
        return (None, None);
    }
    let mlfb = String::from_utf8_lossy(&resp[rec_start + 2..rec_start + 22])
        .trim_matches(|c: char| c == ' ' || c == '\0')
        .to_string();
    let hardware = if mlfb.is_empty() { None } else { Some(mlfb) };
    let fw_major = resp[rec_start + 26];
    let fw_minor = resp[rec_start + 27];
    let firmware = if fw_major == 0 && fw_minor == 0 {
        None
    } else {
        Some(format!("V{fw_major}.{fw_minor}"))
    };
    (hardware, firmware)
}

/// Enumerate hardware info and CPU state in a single COTP/S7Comm session.
///
/// More efficient than calling `get_module_info` and `get_cpu_state` separately
/// since it establishes the TSAP negotiation only once.
pub fn get_device_snapshot(
    ip: &str,
    port: u16,
    timeout_secs: u64,
) -> (Option<String>, Option<String>, String) {
    let Some(mut stream) = setup_connection(ip, port, timeout_secs) else {
        return (None, None, "Unknown".to_string());
    };
    let (hw, fw) = module_info_from_stream(&mut stream);
    let cpu_state = cpu_state_from_stream(&mut stream);
    (hw, fw, cpu_state)
}

/// Query the CPU operating state via SZL 0x0424.
///
/// Tries all four COTP TSAPs (S7-1200/1500/300/400) before giving up,
/// so this works across the full S7 family: not just slot-0 CPUs.
pub fn get_cpu_state(ip: &str, port: u16, timeout_secs: u64, password: Option<&str>) -> String {
    let Some(mut stream) = connect_authenticated(ip, port, timeout_secs, password) else {
        return "Unknown".to_string();
    };
    cpu_state_from_stream(&mut stream)
}

/// Toggle the CPU state (Running ↔ Stopped).
pub fn change_cpu_state(ip: &str, port: u16, timeout_secs: u64) -> bool {
    let cur_state = get_cpu_state(ip, port, timeout_secs, None);
    if cur_state == "Unknown" {
        println!("Cannot determine CPU state, aborting");
        return false;
    }

    let addr = format!("{ip}:{port}");
    let Ok(mut stream) = TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        Duration::from_secs(timeout_secs),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));

    // COTP CR for state change: validate Connection Confirm
    let Some(cotp_resp) = send_recv(
        &mut stream,
        &hex_decode("03000016 11e00000002500c1020600c2020600c0010a"),
    ) else {
        return false;
    };
    let cotp_hex = hex_encode(&cotp_resp);
    if cotp_hex.len() < 12 || &cotp_hex[10..12] != "d0" {
        return false;
    }

    // SubscriptionContainer: S7Comm UserData (type 7, subtype 0x72) session setup frame.
    // This initiates the OMS+ Debugger subscription used by TIA Portal for remote CPU control.
    // Packet structure: TPKT + COTP + S7 header + UserData group-7 (OMS) + ASN.1-encoded
    // session descriptor. The ASCII strings embedded in the blob decode to:
    //   "ServerSession_E6F548" (session ID), "1:::6.0:::" (version), "OMS+ Debugger" (role),
    //   "SubscriptionContainer" (object type).
    // Derived from captures of TIA Portal v15-v16 communicating with S7-1200/1500 CPUs.
    // cmd_byte 0xCE = RunMode request, 0x88 = StopMode request (OMS+ control PDU subtype).
    let Some(sub_resp) = send_recv(
        &mut stream,
        &hex_decode(
            "030000c002f080720100b131000004ca0000000200000120360000011d 00040000000000a1000000d3821f0000a3816900\
             1516 53657276657253657373696f6e5f453646353438 3534 34a3822100150b313a3a3a362e303a3a3a12a382 28\
             00150d4f4d532b204465627567676572a3822900 1500a3822a001500a3822b00048480808000a3822c0012 11e1a300\
             a3822d001500a1000000d3817f0000a3816900 1515537562736372697074696f6e436f6e7461696e 6572a2a2000000\
             0072010000",
        ),
    ) else {
        return false;
    };

    if sub_resp.len() < 25 {
        return false;
    }
    let sid_byte = ((u32::from(sub_resp[24]) + 0x80) & 0xFF) as u8;
    let sid = format!("{sid_byte:02x}");

    let cmd_byte = if cur_state == "Stopped" { "ce" } else { "88" };

    let state_pkt = format!(
        "0300007802f080720200693100000542000000030000 03{sid}34000003{cmd_byte}010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b31303538824100030003000000000 4e88969001200000000896a001300896b000400000000000072020000"
    );
    let _ = send_recv(&mut stream, &hex_decode(&state_pkt));

    let pkt2 = format!(
        "0300002b02f0807202001c31000004bb00000005000003{sid}34000000010000000000000000000072020000"
    );
    let _ = send_recv(&mut stream, &hex_decode(&pkt2));

    let pkt3 = format!(
        "0300002b02f0807202001c31000004bb00000006000003{sid}34000000020001010000000000000072020000"
    );
    let _ = send_recv(&mut stream, &hex_decode(&pkt3));

    // Drain
    let mut drain_buf = vec![0u8; BUFFER_SIZE];
    for _ in 0..10 {
        match stream.read(&mut drain_buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }

    let action_byte = if cur_state == "Stopped" { "03" } else { "01" };

    let final_pkt = format!(
        "0300004302f0807202003431000004f200000008000003{sid}36000000340190770008{action_byte}000004e889690012 00000000896a001300896b000400000000000000 72020000"
    );
    send_recv(&mut stream, &hex_decode(&final_pkt)).is_some()
}

/// XOR-encode a password for `S7Comm` `SetPassword` (padded to 8 bytes with spaces).
fn encode_password(pw: &str) -> [u8; 8] {
    let mut enc = [0x20u8; 8];
    for (i, &b) in pw.as_bytes().iter().take(8).enumerate() {
        enc[i] = b ^ if i % 2 == 0 { 0xAA } else { 0x55 };
    }
    enc
}

/// Send `SetPassword` (`S7Comm` `UserData` subfunction 0x45) on an existing session.
///
/// Returns `true` if the PLC accepted the password (error code in response = 0x0000).
pub fn set_password(stream: &mut TcpStream, password: &str) -> bool {
    let enc = encode_password(password);
    // UserData SetPassword: param_len=8, data_len=12 (4 data header + 8 encoded pw)
    // Total S7 payload = 30 bytes → TPKT total = 37 = 0x25
    let pkt = hex_decode(&format!(
        "0300002502f0803207000001000008000c0001120411450100\
         ff09000800{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        enc[0], enc[1], enc[2], enc[3], enc[4], enc[5], enc[6], enc[7]
    ));
    let Some(resp) = send_recv(stream, &pkt) else {
        return false;
    };
    // S7Comm response header error code at resp[17..19] (0x00 0x00 = success)
    resp.len() >= 19 && resp[17] == 0x00 && resp[18] == 0x00
}

/// Establish a session and optionally authenticate with a password.
///
/// Returns `None` if the connection fails or if a password was given but rejected.
pub fn connect_authenticated(
    ip: &str,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> Option<TcpStream> {
    let mut stream = setup_connection(ip, port, timeout_secs)?;
    if let Some(pw) = password {
        if !pw.is_empty() && !set_password(&mut stream, pw) {
            return None;
        }
    }
    Some(stream)
}

/// Returns true if the device accepts a COTP+S7Comm session but rejects an
/// unauthenticated SZL read with a non-zero error class: indicating that
/// password protection is enabled on this CPU.
pub fn probe_auth_required(ip: &str, port: u16, timeout_secs: u64) -> bool {
    let Some(mut stream) = setup_connection(ip, port, timeout_secs) else {
        return false; // unreachable: auth is not the blocker
    };
    match read_szl(&mut stream, 0x0011, 0x0000) {
        None => false, // no response (timeout/dead socket): not an auth rejection
        Some(resp) => resp.len() >= 19 && resp[17] != 0x00,
    }
}

/// Return `true` if a TCP connection to `ip:port` succeeds within a 1-second timeout.
pub(crate) fn scan_port(ip: &str, port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("{ip}:{port}")
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Probe the common Siemens ports (102, 502) and return those that are open.
pub(crate) fn tcp_scan(ip: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    if scan_port(ip, 102) {
        ports.push(102);
    }
    if scan_port(ip, 502) {
        ports.push(502);
    }
    ports
}

fn bits_to_hex_byte(bits: &str) -> String {
    use crate::core::bytes::bits_to_hex_byte;
    bits_to_hex_byte(bits)
}

/// Write a single output bit (Q area): read-modify-write on Q byte `byte_idx`.
pub fn write_output_bit(
    ip: &str,
    byte_idx: u8,
    bit_idx: u8,
    on: bool,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let data = read_all_data(ip, port, timeout_secs, password);
    let bits_map = data
        .get("outputs")
        .and_then(|v| v.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Failed to read S7 outputs for bit-write"))?;
    let binary_str = build_modified_byte(bits_map, byte_idx, bit_idx, on);
    if set_outputs(ip, &binary_str, port, timeout_secs, password) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("S7 set_outputs write failed"))
    }
}

/// Write a single merker bit (M area): read-modify-write on M byte `byte_idx`.
pub fn write_merker_bit(
    ip: &str,
    byte_idx: u8,
    bit_idx: u8,
    on: bool,
    port: u16,
    timeout_secs: u64,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let data = read_all_data(ip, port, timeout_secs, password);
    let bits_map = data
        .get("merkers")
        .and_then(|v| v.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Failed to read S7 merkers for bit-write"))?;
    let binary_str = build_modified_byte(bits_map, byte_idx, bit_idx, on);
    if set_merkers(ip, &binary_str, u32::from(byte_idx), port, timeout_secs, password) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("S7 set_merkers write failed"))
    }
}

/// Build an 8-char binary string (position i = bit i, LSB-first matching `bits_to_hex_byte`)
/// for byte `byte_idx` in the S7 bit map, with `bit_idx` set to `on`.
fn build_modified_byte(
    bits_map: &HashMap<String, u8>,
    byte_idx: u8,
    bit_idx: u8,
    on: bool,
) -> String {
    (0u8..8)
        .map(|bit| {
            let key = format!("{byte_idx}.{bit}");
            let current = bits_map.get(&key).copied().unwrap_or(0);
            if bit == bit_idx {
                if on { '1' } else { '0' }
            } else if current != 0 {
                '1'
            } else {
                '0'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_merkers_offset_overflow_returns_false() {
        // Guard fires before any network call: no live PLC needed.
        assert!(!set_merkers("127.0.0.1", "11111111", 0x20_0000, 102, 1, None));
    }

    #[test]
    fn write_data_block_too_large_is_rejected() {
        // Guard is now before connect_authenticated: no live PLC needed.
        let big = vec![0u8; 8192];
        let err = write_data_block("127.0.0.1", 1, 0, &big, 102, 1, None).unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "expected 'too large', got: {err}",
        );
    }

    #[test]
    fn hex_decode_odd_length_returns_empty() {
        assert!(hex_decode("A").is_empty());
        assert!(hex_decode("ABC").is_empty());
    }

    #[test]
    fn hex_decode_even_length_works() {
        assert_eq!(hex_decode("DEAD"), vec![0xDE, 0xAD]);
        assert_eq!(hex_decode("DE AD"), vec![0xDE, 0xAD]);
    }
}
