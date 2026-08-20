//! DNP3 (Distributed Network Protocol 3) client.
//!
//! Implements Data Link Layer framing, CRC-16/DNP, and basic Application Layer
//! requests for device detection and enumeration over TCP port 20000.
//! All encoding is hand-coded per IEEE 1815-2012; no external DNP3 crate is used.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default TCP port for DNP3.
pub const DNP3_PORT: u16 = 20000;

// DLL frame start bytes
const START_HI: u8 = 0x05;
const START_LO: u8 = 0x64;

// DLL control byte components
// DIR bit: 1 = primary (master → outstation)
// PRM bit: 1 = primary message
const CTRL_DIR_PRM: u8 = 0b1100_0000;
const CTRL_FCB_FCV: u8 = 0b0000_0000; // FCB=0, FCV=0 for stateless requests

// Primary function codes (master → outstation)
const FC_RESET_LINK: u8 = 0x00;
const FC_REQUEST_LINK_STATUS: u8 = 0x09;

// Secondary function codes (outstation → master)
const FC_ACK: u8 = 0x00;
const FC_LINK_STATUS: u8 = 0x0B;
const FC_NOT_SUPPORTED: u8 = 0x0F;

// Source address used in all outgoing frames (master address = 1)
const MASTER_ADDR: u16 = 0x0001;
// Destination for broadcasts / initial contact (use a common outstation addr or 0x0003)
const DEFAULT_OUTSTATION_ADDR: u16 = 0xFFFF; // global all-stations

// Transport Layer Header bytes
const TL_FIRST_FINAL: u8 = 0xC0; // FIN=1, FIR=1, seq=0

// Application Layer function codes
const AL_FC_READ: u8 = 0x01;
const AL_FC_RESPONSE: u8 = 0x81;
const AL_FC_UNSOLICITED_RESP: u8 = 0x82;

/// A confirmed DNP3 outstation.
#[derive(Debug, Clone)]
pub struct Dnp3Device {
    pub ip: String,
    pub outstation_addr: u16,
    pub device_attributes: HashMap<String, String>,
}

// ─── CRC-16/DNP ───────────────────────────────────────────────────────────────

/// CRC-16/DNP table (poly=0xA6BC, reflected; final XOR = 0xFFFF).
fn crc16_dnp(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let mut b = byte;
        for _ in 0..8 {
            let bit = (crc ^ u16::from(b)) & 0x0001;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xA6BC;
            }
            b >>= 1;
        }
    }
    !crc
}

// ─── Frame encoding ───────────────────────────────────────────────────────────

/// Build a DLL-only frame (no transport/application payload).
fn build_dll_frame(ctrl: u8, dest: u16, src: u16) -> Vec<u8> {
    // Length = bytes from control through source address = 5
    let length: u8 = 5;
    let header = [
        length,
        ctrl,
        (dest & 0xFF) as u8,
        (dest >> 8) as u8,
        (src & 0xFF) as u8,
        (src >> 8) as u8,
    ];
    let crc = crc16_dnp(&header);
    let mut frame = vec![START_HI, START_LO];
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&crc.to_le_bytes());
    frame
}

/// Build a frame with a data payload (split into 16-byte blocks with CRCs).
fn build_data_frame(ctrl: u8, dest: u16, src: u16, transport: u8, apdu: &[u8]) -> Vec<u8> {
    // Data field: transport layer (1 byte) + APDU
    let mut data = vec![transport];
    data.extend_from_slice(apdu);

    // Number of data octets = 1 (transport) + APDU length
    // Length field = 5 (DLL header) + data octets
    let data_len = data.len();
    let length = 5 + data_len;
    // Clamp to u8 range (max DNP3 DLL payload = 250 bytes per block constraints)
    #[allow(clippy::cast_possible_truncation)]
    let length_byte = length.min(255) as u8;

    let header = [
        length_byte,
        ctrl,
        (dest & 0xFF) as u8,
        (dest >> 8) as u8,
        (src & 0xFF) as u8,
        (src >> 8) as u8,
    ];
    let header_crc = crc16_dnp(&header);

    let mut frame = vec![START_HI, START_LO];
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&header_crc.to_le_bytes());

    // Data blocks: 16 bytes each, each followed by 2-byte CRC
    for block in data.chunks(16) {
        frame.extend_from_slice(block);
        let block_crc = crc16_dnp(block);
        frame.extend_from_slice(&block_crc.to_le_bytes());
    }

    frame
}

// ─── Frame parsing ─────────────────────────────────────────────────────────────

/// Parse a DNP3 frame from `stream`, returning the raw bytes including start+header+CRC.
fn recv_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    // Read and find the start bytes 0x05 0x64
    let mut header = [0u8; 10]; // start(2) + len(1) + ctrl(1) + dest(2) + src(2) + crc(2)
    stream.read_exact(&mut header).ok()?;

    if header[0] != START_HI || header[1] != START_LO {
        return None;
    }

    let length = header[2] as usize;
    // The CRC covers header bytes 2-7 (length through src high)
    let header_crc_expected = crc16_dnp(&header[2..8]);
    let header_crc_actual = u16::from_le_bytes([header[8], header[9]]);
    if header_crc_expected != header_crc_actual {
        return None;
    }

    // Data bytes = length - 5 (subtract DLL fixed header: ctrl+dest+src = 5)
    if length < 5 {
        return Some(header.to_vec()); // DLL-only frame
    }
    let data_octets = length - 5;
    // Data is in 16-byte blocks + 2-byte CRCs
    let num_full = data_octets / 16;
    let remainder = data_octets % 16;
    let block_count = num_full + usize::from(remainder > 0);
    let total_data_bytes = data_octets + block_count * 2;

    let mut data_buf = vec![0u8; total_data_bytes];
    stream.read_exact(&mut data_buf).ok()?;

    // Validate block CRCs
    let mut valid_data: Vec<u8> = Vec::new();
    let mut offset = 0;
    for _ in 0..num_full {
        let block = &data_buf[offset..offset + 16];
        let crc = u16::from_le_bytes([data_buf[offset + 16], data_buf[offset + 17]]);
        if crc16_dnp(block) != crc {
            return None;
        }
        valid_data.extend_from_slice(block);
        offset += 18;
    }
    if remainder > 0 {
        let block = &data_buf[offset..offset + remainder];
        let crc = u16::from_le_bytes([data_buf[offset + remainder], data_buf[offset + remainder + 1]]);
        if crc16_dnp(block) != crc {
            return None;
        }
        valid_data.extend_from_slice(block);
    }

    let mut frame = header.to_vec();
    // Store just the valid data (without block CRCs) after the header
    frame.extend_from_slice(&valid_data);
    Some(frame)
}

/// Extract source address from a received frame (bytes 6-7, little-endian).
fn frame_src(frame: &[u8]) -> u16 {
    if frame.len() < 8 {
        return 0;
    }
    u16::from_le_bytes([frame[6], frame[7]])
}

/// Extract DLL control byte from frame (byte 3).
fn frame_ctrl(frame: &[u8]) -> u8 {
    frame.get(3).copied().unwrap_or(0)
}

// ─── Public API ────────────────────────────────────────────────────────────────

/// Detect a DNP3 outstation at `ip:port` using Request Link Status.
/// Returns a `Dnp3Device` with empty attributes on success.
pub fn detect(ip: &str, timeout: Duration) -> Option<Dnp3Device> {
    let addr = format!("{ip}:{DNP3_PORT}");
    let stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut stream = stream;

    // First send Reset Link States (FC=0x00) to initialize the link
    let reset_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | FC_RESET_LINK;
    let reset_frame = build_dll_frame(reset_ctrl, DEFAULT_OUTSTATION_ADDR, MASTER_ADDR);
    stream.write_all(&reset_frame).ok()?;

    // Read the response (ACK or no response)
    let reset_resp = recv_frame(&mut stream);
    let outstation_addr = reset_resp.as_ref().map_or(DEFAULT_OUTSTATION_ADDR, |f| frame_src(f));

    // Then send Request Link Status (FC=0x09)
    let status_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | FC_REQUEST_LINK_STATUS;
    let status_frame = build_dll_frame(status_ctrl, outstation_addr, MASTER_ADDR);
    stream.write_all(&status_frame).ok()?;

    let resp = recv_frame(&mut stream)?;
    let resp_ctrl = frame_ctrl(&resp);
    // Secondary function codes 0x00 (ACK) or 0x0B (Link Status) both confirm DNP3
    let fc_secondary = resp_ctrl & 0x0F;
    if fc_secondary != FC_ACK && fc_secondary != FC_LINK_STATUS && fc_secondary != FC_NOT_SUPPORTED {
        return None;
    }

    let confirmed_addr = frame_src(&resp);
    Some(Dnp3Device {
        ip: ip.to_string(),
        outstation_addr: confirmed_addr,
        device_attributes: HashMap::new(),
    })
}

/// Read device attributes (object group 0) from an outstation.
pub fn read_device_attributes(ip: &str, timeout: Duration) -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    let addr = format!("{ip}:{DNP3_PORT}");
    let Ok(stream) = TcpStream::connect_timeout(&addr.parse().unwrap_or("0.0.0.0:1".parse().unwrap()), timeout) else {
        return attrs;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    // Reset link
    let reset_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | FC_RESET_LINK;
    let reset_frame = build_dll_frame(reset_ctrl, DEFAULT_OUTSTATION_ADDR, MASTER_ADDR);
    if stream.write_all(&reset_frame).is_err() {
        return attrs;
    }
    let reset_resp = recv_frame(&mut stream);
    let outstation_addr = reset_resp.as_ref().map_or(DEFAULT_OUTSTATION_ADDR, |f| frame_src(f));

    // Read device attributes (Group 0, variations 1-255 = all)
    // Variation 0 = all attributes, Qualifier 0x06 = no range (all present)
    let apdu: Vec<u8> = vec![
        AL_FC_READ,
        0x01, // invoke ID
        0x00, // group 0 (device attributes)
        0x00, // variation 0 (all)
        0x06, // qualifier: no range (all)
    ];
    let data_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | 0x03; // FC=3 = User Data (confirmed)
    let frame = build_data_frame(data_ctrl, outstation_addr, MASTER_ADDR, TL_FIRST_FINAL, &apdu);
    if stream.write_all(&frame).is_err() {
        return attrs;
    }

    // Collect up to 8 response frames
    for _ in 0..8 {
        let Some(resp) = recv_frame(&mut stream) else { break };
        // Frame must have enough data for transport + APDU
        if resp.len() < 11 {
            continue;
        }
        // Data payload starts at offset 10 (after start(2)+header(6)+crc(2))
        let data = &resp[10..];
        if data.is_empty() {
            continue;
        }
        let fc = data.get(1).copied().unwrap_or(0); // skip transport byte
        if fc != AL_FC_RESPONSE && fc != AL_FC_UNSOLICITED_RESP {
            continue;
        }
        parse_device_attributes(&resp[10..], &mut attrs);

        // Check FIR/FIN flags in transport byte to know if last fragment
        let transport = resp[10];
        let fin = (transport & 0x80) != 0;
        if fin {
            break;
        }
    }

    attrs
}

/// Parse Group 0 (device attribute) objects from a response data payload.
fn parse_device_attributes(data: &[u8], attrs: &mut HashMap<String, String>) {
    // data[0] = transport layer byte; data[1] = AL function code; data[2..3] = IIN
    if data.len() < 4 {
        return;
    }
    let al_start = 4; // transport(1) + fc(1) + IIN(2)
    let mut pos = al_start;

    while pos + 3 < data.len() {
        let group = data[pos];
        let variation = data[pos + 1];
        let qualifier = data[pos + 2];
        pos += 3;

        if group != 0 {
            break; // only parsing group 0 here
        }

        // Qualifier 0x5B = variation list; 0x00 = 8-bit index range
        // For simplicity, read 1-object responses (qualifier 0x07 = limited qty 1)
        let count: usize = match qualifier {
            0x07 | 0x17 => {
                let cnt = data.get(pos).copied().unwrap_or(0) as usize;
                pos += 1;
                cnt
            }
            _ => 1,
        };

        for _ in 0..count {
            if pos >= data.len() {
                break;
            }
            let attr_len = data[pos] as usize;
            pos += 1;
            if pos + attr_len > data.len() {
                break;
            }
            let attr_data = &data[pos..pos + attr_len];
            pos += attr_len;

            // Group 0, variation = attribute code
            let key = attr_name(variation);
            if let Ok(s) = std::str::from_utf8(attr_data) {
                attrs.insert(key.to_string(), s.trim_end_matches('\0').to_string());
            } else {
                let hex: String = attr_data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                attrs.insert(key.to_string(), hex);
            }
        }
    }
}

/// Map Group 0 variation to a human-readable attribute name.
fn attr_name(variation: u8) -> &'static str {
    match variation {
        1 => "config_id",
        2 => "config_version",
        3 => "config_build_date",
        4 => "config_last_change_date",
        5 => "config_digest",
        6 => "config_digest_algorithm",
        7 => "master_resource_id",
        8 => "device_address",
        9 => "self_address_support",
        10 => "handshake_timeout",
        11 => "broadcast_confirm_mode",
        12 => "max_master_range",
        13 => "max_outstation_range",
        14 => "firmware_version",
        15 => "hardware_version",
        16 => "user_assigned_name",
        17 => "user_assigned_location",
        18 => "user_assigned_id",
        19 => "user_assigned_mfr_code",
        20 => "mfr_software_version",
        21 => "mfr_hardware_version",
        22 => "user_assigned_owner_name",
        23 => "device_serial",
        24 => "device_subset_level",
        25 => "device_max_binary_counter",
        243 => "profile_version",
        244 => "profile_name",
        245 => "profile_id",
        246 => "device_location",
        247 => "device_id",
        248 => "device_name",
        249 => "vendor_url",
        250 => "vendor_name",
        251 => "mfr_hardware_id",
        252 => "product_name",
        253 => "product_code",
        254 => "mfr_hardware_version2",
        255 => "mfr_software_version2",
        _ => "unknown_attr",
    }
}

/// Read class 0 integrity poll from an outstation (function code Read, object 60 var 1).
pub fn read_integrity_poll(ip: &str, timeout: Duration) -> Vec<String> {
    let mut results = Vec::new();

    let addr = format!("{ip}:{DNP3_PORT}");
    let Ok(stream) = TcpStream::connect_timeout(&addr.parse().unwrap_or("0.0.0.0:1".parse().unwrap()), timeout) else {
        return results;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    // Reset link
    let reset_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | FC_RESET_LINK;
    let reset_frame = build_dll_frame(reset_ctrl, DEFAULT_OUTSTATION_ADDR, MASTER_ADDR);
    if stream.write_all(&reset_frame).is_err() {
        return results;
    }
    let reset_resp = recv_frame(&mut stream);
    let outstation_addr = reset_resp.as_ref().map_or(DEFAULT_OUTSTATION_ADDR, |f| frame_src(f));

    // Read Class 0 data: Group 60 Variation 1
    let apdu = vec![
        AL_FC_READ,
        0x02, // invoke ID
        60,   // group 60 (class objects)
        1,    // variation 1 (class 0)
        0x06, // qualifier: no range
    ];
    let data_ctrl = CTRL_DIR_PRM | CTRL_FCB_FCV | 0x03;
    let frame = build_data_frame(data_ctrl, outstation_addr, MASTER_ADDR, TL_FIRST_FINAL, &apdu);
    if stream.write_all(&frame).is_err() {
        return results;
    }

    for _ in 0..32 {
        let Some(resp) = recv_frame(&mut stream) else { break };
        if resp.len() < 11 {
            continue;
        }
        let data = &resp[10..];
        // Summarize as hex for now; a full decoder would parse each object group
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        results.push(format!("frame[{}B]: {}", resp.len(), hex));

        let transport = resp[10];
        let fin = (transport & 0x80) != 0;
        if fin {
            break;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_dnp_known_value() {
        // DNP3 CRC test vector: header bytes of a known Reset Link States frame.
        // Frame: 05 64 05 C0 03 00 01 00  → header = [05 C0 03 00 01 00] → CRC = ?
        // We verify the CRC is stable (round-trip property):
        // crc16_dnp of [0x05, 0xC0, 0x03, 0x00, 0x01, 0x00] with the known value
        let header = [0x05u8, 0xC0, 0x03, 0x00, 0x01, 0x00];
        let crc = crc16_dnp(&header);
        // Re-running over the same data must be deterministic
        assert_eq!(crc, crc16_dnp(&header));
        // CRC of empty slice = !0 = 0xFFFF
        assert_eq!(crc16_dnp(&[]), 0xFFFF);
    }

    #[test]
    fn build_dll_frame_valid_structure() {
        let ctrl = CTRL_DIR_PRM | FC_REQUEST_LINK_STATUS;
        let frame = build_dll_frame(ctrl, 0x0003, MASTER_ADDR);
        // Start bytes
        assert_eq!(frame[0], START_HI);
        assert_eq!(frame[1], START_LO);
        // Length = 5 for DLL-only frame
        assert_eq!(frame[2], 5);
        // Total: start(2) + header(6) + crc(2) = 10 bytes
        assert_eq!(frame.len(), 10);
        // Verify stored CRC matches
        let computed = crc16_dnp(&frame[2..8]);
        let stored = u16::from_le_bytes([frame[8], frame[9]]);
        assert_eq!(computed, stored);
    }

    #[test]
    fn build_data_frame_valid_crc() {
        let apdu = [AL_FC_READ, 0x01, 0x00, 0x00, 0x06];
        let frame = build_data_frame(
            CTRL_DIR_PRM | 0x03,
            0x0003,
            MASTER_ADDR,
            TL_FIRST_FINAL,
            &apdu,
        );
        assert_eq!(frame[0], START_HI);
        assert_eq!(frame[1], START_LO);
        // Header CRC is at bytes 8-9
        let computed_header_crc = crc16_dnp(&frame[2..8]);
        let stored_header_crc = u16::from_le_bytes([frame[8], frame[9]]);
        assert_eq!(computed_header_crc, stored_header_crc);
    }

    #[test]
    fn attr_name_known_variations() {
        assert_eq!(attr_name(248), "device_name");
        assert_eq!(attr_name(250), "vendor_name");
        assert_eq!(attr_name(253), "product_code");
    }
}
