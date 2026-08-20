//! `BACnet`/IP protocol client.
//!
//! Implements Who-Is/I-Am discovery and Read-Property over UDP port 47808 (0xBAC0).
//! All encoding is hand-coded per ANSI/ASHRAE 135; no external `BACnet` crate is used.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Default UDP port for BACnet/IP (0xBAC0).
pub const BACNET_PORT: u16 = 0xBAC0;

// BACnet/IP BVLC function codes
const BVLC_TYPE: u8 = 0x81;
const BVLC_UNICAST: u8 = 0x0A;
const BVLC_BROADCAST: u8 = 0x0B;

// APDU PDU types
const UNCONFIRMED_REQ: u8 = 0x10;
const CONFIRMED_REQ: u8 = 0x00;
const COMPLEX_ACK: u8 = 0x30;

// Unconfirmed service choices
const SVC_I_AM: u8 = 0x00;
const SVC_WHO_IS: u8 = 0x08;

// Confirmed service choice
const SVC_READ_PROPERTY: u8 = 0x0C;

// BACnet standard property identifiers (ANSI/ASHRAE 135)
pub const PROP_DESCRIPTION: u8 = 28;
pub const PROP_FIRMWARE_REVISION: u8 = 44;
pub const PROP_OBJECT_NAME: u8 = 77;
pub const PROP_VENDOR_IDENTIFIER: u8 = 112;
pub const PROP_VENDOR_NAME: u8 = 121;

/// Device object type (`BACnet` enumeration value = 8).
const DEVICE_OBJECT_TYPE: u32 = 8;

/// A `BACnet` device discovered through Who-Is/I-Am exchange.
#[derive(Debug, Clone)]
pub struct BacnetDevice {
    pub ip: String,
    pub instance_id: u32,
    pub vendor_id: u16,
    pub max_apdu: u16,
    pub object_name: String,
    pub vendor_name: String,
    pub description: String,
    pub firmware_revision: String,
}

fn bvlc_unicast(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(4 + payload.len()).unwrap_or(u16::MAX).to_be_bytes();
    let mut pkt = vec![BVLC_TYPE, BVLC_UNICAST, len[0], len[1]];
    pkt.extend_from_slice(payload);
    pkt
}

fn bvlc_broadcast(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(4 + payload.len()).unwrap_or(u16::MAX).to_be_bytes();
    let mut pkt = vec![BVLC_TYPE, BVLC_BROADCAST, len[0], len[1]];
    pkt.extend_from_slice(payload);
    pkt
}

/// Build NPDU + APDU for a unicast Who-Is (no range = discover all).
fn who_is_pdu() -> Vec<u8> {
    vec![
        0x01, 0x00,              // NPDU: version 1, no flags
        UNCONFIRMED_REQ, SVC_WHO_IS, // APDU: unconfirmed-req, Who-Is (no range params)
    ]
}

/// Build a Read-Property confirmed request APDU.
fn read_property_pdu(invoke_id: u8, instance: u32, property_id: u8) -> Vec<u8> {
    // BACnetObjectIdentifier: upper 10 bits = object type, lower 22 bits = instance
    let oid_val: u32 = (DEVICE_OBJECT_TYPE << 22) | (instance & 0x3F_FFFF);
    let oid_bytes = oid_val.to_be_bytes();

    let mut apdu = vec![
        CONFIRMED_REQ, // PDU type
        0x05,          // max-segs=0, max-APDU-size=5 (480 bytes)
        invoke_id,
        SVC_READ_PROPERTY,
        0x0C,          // Context tag 0, length 4: object-identifier
        oid_bytes[0],
        oid_bytes[1],
        oid_bytes[2],
        oid_bytes[3],
        0x19,          // Context tag 1, length 1: property-identifier
        property_id,
    ];

    // NPDU: version 1, expecting reply (bit 2)
    let mut pdu = vec![0x01u8, 0x04];
    pdu.append(&mut apdu);
    pdu
}

/// Send a unicast Who-Is to `ip:port` and return the raw I-Am response bytes, if any.
fn unicast_who_is(ip: &str, timeout: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let target: SocketAddr = format!("{ip}:{BACNET_PORT}").parse().ok()?;
    let pkt = bvlc_unicast(&who_is_pdu());
    socket.send_to(&pkt, target).ok()?;

    let mut buf = [0u8; 512];
    let (n, src) = socket.recv_from(&mut buf).ok()?;
    Some((buf[..n].to_vec(), src))
}

/// Parse an I-Am response into (`instance_id`, `vendor_id`, `max_apdu`).
/// Returns None if the packet is not a valid I-Am APDU.
fn parse_i_am(data: &[u8]) -> Option<(u32, u16, u16)> {
    // Need at least: BVLC(4) + NPDU(2) + APDU(2 unconfirmed header + ≥10 data)
    if data.len() < 16 {
        return None;
    }
    // Skip BVLC header (4 bytes)
    // NPDU starts at 4: skip variable-length NPDU
    let npdu_offset = 4;
    if data.len() <= npdu_offset + 1 {
        return None;
    }
    let npdu_ctrl = data[npdu_offset + 1];
    let mut apdu_offset = npdu_offset + 2;

    // If NPDU has destination info (bit 5 = 0x20), skip DNET(2)+DLEN(1)+hop(1) minimum
    if (npdu_ctrl & 0x20) != 0 {
        if apdu_offset + 4 > data.len() {
            return None;
        }
        let dlen = data[apdu_offset + 2] as usize;
        apdu_offset += 3 + dlen + 1; // DNET(2) + DLEN(1) + DADR(dlen) + hop(1)
    }
    // If NPDU has source info (bit 3 = 0x08), skip SNET(2)+SLEN(1)+SADR(slen)
    if (npdu_ctrl & 0x08) != 0 {
        if apdu_offset + 3 > data.len() {
            return None;
        }
        let slen = data[apdu_offset + 2] as usize;
        apdu_offset += 3 + slen;
    }

    if apdu_offset + 2 > data.len() {
        return None;
    }
    // APDU: pdu_type (0x10 = unconfirmed-req), service_choice (0x00 = I-Am)
    if data[apdu_offset] != UNCONFIRMED_REQ || data[apdu_offset + 1] != SVC_I_AM {
        return None;
    }
    let payload = &data[apdu_offset + 2..];

    // I-Am payload:
    // [0] tag byte: should be 0xC4 (app tag 12 = ObjectIdentifier, length 4)
    // [1-4] ObjectIdentifier value
    // [5] tag byte: app tag 2 (unsigned), length 1 or 2
    // [6..] max-APDU-length-accepted
    // then segmentation-supported (app tag 9, length 1)
    // then vendor-identifier (app tag 2, length 1 or 2)
    if payload.len() < 6 || payload[0] != 0xC4 {
        return None;
    }
    let oid = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let instance = oid & 0x3F_FFFF;

    // Parse max-APDU (tag 0x21 = len 1, or 0x22 = len 2)
    let mut pos = 5;
    let max_apdu = match payload.get(pos) {
        Some(0x21) if payload.len() > pos + 1 => {
            let v = u16::from(payload[pos + 1]);
            pos += 2;
            v
        }
        Some(0x22) if payload.len() > pos + 2 => {
            let v = u16::from_be_bytes([payload[pos + 1], payload[pos + 2]]);
            pos += 3;
            v
        }
        _ => {
            pos += 2; // best-effort skip
            0
        }
    };

    // Skip segmentation-supported (tag 0x91 = enum, 1 byte)
    if payload.get(pos).copied() == Some(0x91) {
        pos += 2;
    }

    // Parse vendor-id
    let vendor_id = match payload.get(pos) {
        Some(0x21) if payload.len() > pos + 1 => u16::from(payload[pos + 1]),
        Some(0x22) if payload.len() > pos + 2 => {
            u16::from_be_bytes([payload[pos + 1], payload[pos + 2]])
        }
        _ => 0,
    };

    Some((instance, vendor_id, max_apdu))
}

/// Parse a Complex-ACK response to Read-Property, returning the property value as a String.
fn parse_read_property_ack(data: &[u8]) -> Option<String> {
    // BVLC(4) + NPDU(≥2) + APDU
    if data.len() < 10 {
        return None;
    }
    let npdu_offset = 4;
    if data.len() <= npdu_offset + 1 {
        return None;
    }
    let npdu_ctrl = data[npdu_offset + 1];
    let mut apdu_offset = npdu_offset + 2;
    if (npdu_ctrl & 0x20) != 0 {
        if apdu_offset + 3 > data.len() {
            return None;
        }
        let dlen = data[apdu_offset + 2] as usize;
        apdu_offset += 3 + dlen + 1;
    }
    if (npdu_ctrl & 0x08) != 0 {
        if apdu_offset + 3 > data.len() {
            return None;
        }
        let slen = data[apdu_offset + 2] as usize;
        apdu_offset += 3 + slen;
    }

    // APDU for Complex-ACK: pdu_type=0x30, invoke_id, service_choice=0x0C
    if data.len() < apdu_offset + 3 {
        return None;
    }
    if (data[apdu_offset] & 0xF0) != COMPLEX_ACK || data[apdu_offset + 2] != SVC_READ_PROPERTY {
        return None;
    }

    // Skip: object-id (0x0C + 4 bytes), property-id (0x19 + 1 byte)
    let payload_start = apdu_offset + 3;
    let payload = &data[payload_start..];
    if payload.len() < 8 {
        return None;
    }

    // Find Context[3] open tag (0x3E)
    let open_pos = payload.iter().position(|&b| b == 0x3E)?;
    let value_data = &payload[open_pos + 1..];

    decode_application_value(value_data)
}

/// Decode the first application-tagged `BACnet` value into a String.
fn decode_application_value(data: &[u8]) -> Option<String> {
    let first = *data.first()?;
    let tag = (first >> 4) & 0x0F;
    let is_context = (first & 0x08) != 0;
    let length_bits = first & 0x07;

    if is_context {
        return None; // unexpected
    }

    match tag {
        2 => {
            // Unsigned integer
            let (len, start) = resolve_length(data, length_bits)?;
            let bytes = data.get(start..start + len)?;
            let mut val: u64 = 0;
            for &b in bytes {
                val = (val << 8) | u64::from(b);
            }
            Some(val.to_string())
        }
        7 => {
            // Character string: length includes encoding byte (1 byte)
            let (len, start) = resolve_length(data, length_bits)?;
            if len < 1 {
                return None;
            }
            let str_bytes = data.get(start + 1..start + len)?; // skip encoding byte
            String::from_utf8(str_bytes.to_vec()).ok()
        }
        4 => {
            // Octet string
            let (len, start) = resolve_length(data, length_bits)?;
            let bytes = data.get(start..start + len)?;
            Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
        }
        9 => {
            // Enumerated
            let (len, start) = resolve_length(data, length_bits)?;
            let bytes = data.get(start..start + len)?;
            let mut val: u64 = 0;
            for &b in bytes {
                val = (val << 8) | u64::from(b);
            }
            Some(val.to_string())
        }
        _ => {
            // Return hex for unhandled types
            let (len, start) = resolve_length(data, length_bits)?;
            let bytes = data.get(start..start + len.min(32))?;
            Some(format!("[type{tag}] {}", bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
        }
    }
}

/// Resolve `BACnet` tag length from the length bits and data slice.
/// Returns (`length_in_bytes`, `start_offset_of_value`).
fn resolve_length(data: &[u8], length_bits: u8) -> Option<(usize, usize)> {
    match length_bits {
        0..=4 => Some((length_bits as usize, 1)),
        5 => {
            let ext_len = *data.get(1)? as usize;
            Some((ext_len, 2))
        }
        6 => {
            let hi = *data.get(1)? as usize;
            let lo = *data.get(2)? as usize;
            Some(((hi << 8) | lo, 3))
        }
        _ => None,
    }
}

/// Probe a single IP for a `BACnet` device using unicast Who-Is.
/// Returns a `BacnetDevice` if the host responds with a valid I-Am.
pub fn scan_ip(ip: &str, timeout_secs: u64) -> Option<BacnetDevice> {
    let timeout = Duration::from_secs(timeout_secs);
    let (raw, _src) = unicast_who_is(ip, timeout)?;
    let (instance, vendor_id, max_apdu) = parse_i_am(&raw)?;

    // Read optional properties (best-effort, don't fail scan if unavailable)
    let object_name = read_property(ip, instance, PROP_OBJECT_NAME, timeout)
        .unwrap_or_default();
    let vendor_name = read_property(ip, instance, PROP_VENDOR_NAME, timeout)
        .unwrap_or_default();
    let description = read_property(ip, instance, PROP_DESCRIPTION, timeout)
        .unwrap_or_default();
    let firmware_revision = read_property(ip, instance, PROP_FIRMWARE_REVISION, timeout)
        .unwrap_or_default();

    Some(BacnetDevice {
        ip: ip.to_string(),
        instance_id: instance,
        vendor_id,
        max_apdu,
        object_name,
        vendor_name,
        description,
        firmware_revision,
    })
}

/// Read a single property from a `BACnet` device.
pub fn read_property(
    ip: &str,
    instance: u32,
    property_id: u8,
    timeout: Duration,
) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let target: SocketAddr = format!("{ip}:{BACNET_PORT}").parse().ok()?;
    let pdu = read_property_pdu(1, instance, property_id);
    let pkt = bvlc_unicast(&pdu);
    socket.send_to(&pkt, target).ok()?;

    let mut buf = [0u8; 1024];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    parse_read_property_ack(&buf[..n])
}

/// Broadcast Who-Is on the local network and collect all I-Am responses.
pub fn who_is_broadcast(timeout: Duration) -> Vec<BacnetDevice> {
    let socket = match UdpSocket::bind(format!("0.0.0.0:{BACNET_PORT}")) {
        Ok(s) => s,
        Err(_) => {
            // Fall back to ephemeral port
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            }
        }
    };
    let _ = socket.set_broadcast(true);
    let _ = socket.set_read_timeout(Some(timeout));

    let broadcast: SocketAddr = format!("255.255.255.255:{BACNET_PORT}").parse().unwrap();
    let pkt = bvlc_broadcast(&who_is_pdu());
    if socket.send_to(&pkt, broadcast).is_err() {
        return Vec::new();
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok((n, src)) = socket.recv_from(&mut buf) {
        let ip = src.ip().to_string();
        if let Some((instance, vendor_id, max_apdu)) = parse_i_am(&buf[..n]) {
            devices.push(BacnetDevice {
                ip: ip.clone(),
                instance_id: instance,
                vendor_id,
                max_apdu,
                object_name: String::new(),
                vendor_name: String::new(),
                description: String::new(),
                firmware_revision: String::new(),
            });
        }
    }

    // Enrich with Read-Property for each found device (best-effort)
    for dev in &mut devices {
        let t = Duration::from_secs(2);
        dev.object_name = read_property(&dev.ip, dev.instance_id, PROP_OBJECT_NAME, t)
            .unwrap_or_default();
        dev.vendor_name = read_property(&dev.ip, dev.instance_id, PROP_VENDOR_NAME, t)
            .unwrap_or_default();
    }

    devices
}

/// Build a human-readable summary map for a [`BacnetDevice`].
pub fn device_summary(dev: &BacnetDevice) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("instance_id".into(), dev.instance_id.to_string());
    m.insert("vendor_id".into(), dev.vendor_id.to_string());
    m.insert("max_apdu".into(), dev.max_apdu.to_string());
    if !dev.object_name.is_empty() {
        m.insert("object_name".into(), dev.object_name.clone());
    }
    if !dev.vendor_name.is_empty() {
        m.insert("vendor_name".into(), dev.vendor_name.clone());
    }
    if !dev.description.is_empty() {
        m.insert("description".into(), dev.description.clone());
    }
    if !dev.firmware_revision.is_empty() {
        m.insert("firmware_revision".into(), dev.firmware_revision.clone());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_i_am_valid_packet_returns_instance_and_vendor() {
        // Minimal I-Am: BVLC unicast + NPDU (no routing) + APDU I-Am
        // Device instance=1, max-APDU=480, seg=none(3), vendor-id=5
        let oid: u32 = (DEVICE_OBJECT_TYPE << 22) | 1;
        let oid_bytes = oid.to_be_bytes();
        let pkt = vec![
            0x81, 0x0A, 0x00, 0x12, // BVLC unicast, length=18
            0x01, 0x00,              // NPDU version 1, no flags
            UNCONFIRMED_REQ, SVC_I_AM, // APDU
            0xC4,                    // ObjectIdentifier tag (app tag 12, len 4)
            oid_bytes[0], oid_bytes[1], oid_bytes[2], oid_bytes[3],
            0x22, 0x01, 0xE0,        // max-APDU: 2 bytes = 480
            0x91, 0x03,              // segmentation: 1 byte = 3 (none)
            0x21, 0x05,              // vendor-id: 1 byte = 5
        ];
        let result = parse_i_am(&pkt);
        assert!(result.is_some());
        let (instance, vendor_id, max_apdu) = result.unwrap();
        assert_eq!(instance, 1);
        assert_eq!(vendor_id, 5);
        assert_eq!(max_apdu, 480);
    }

    #[test]
    fn parse_i_am_wrong_service_returns_none() {
        let pkt = vec![
            0x81, 0x0A, 0x00, 0x08,
            0x01, 0x00,
            UNCONFIRMED_REQ, SVC_WHO_IS, // Wrong: Who-Is, not I-Am
        ];
        assert!(parse_i_am(&pkt).is_none());
    }

    #[test]
    fn parse_i_am_too_short_returns_none() {
        assert!(parse_i_am(&[0x81, 0x0A]).is_none());
    }

    #[test]
    fn decode_application_value_unsigned_1byte() {
        // Tag 0x21 = type 2 (unsigned), length 1
        let data = [0x21u8, 0x42];
        assert_eq!(decode_application_value(&data), Some("66".to_string()));
    }

    #[test]
    fn decode_application_value_charstring() {
        // Tag 0x75 = type 7, extended length; next byte = 5; encoding byte = 0x00; "TEST"
        let data = [0x75u8, 5, 0x00, b'T', b'E', b'S', b'T'];
        assert_eq!(decode_application_value(&data), Some("TEST".to_string()));
    }

    #[test]
    fn bvlc_unicast_sets_correct_header() {
        let payload = [0x01u8, 0x00, 0x10, 0x08];
        let pkt = bvlc_unicast(&payload);
        assert_eq!(pkt[0], 0x81);
        assert_eq!(pkt[1], BVLC_UNICAST);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
    }
}
