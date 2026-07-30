use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;
use crate::vendors::enip::enums::{device_type_name, vendor_name};

const DISCOVERY_PACKET: &str = "630000000000000000000000000000000000000000000000";
const DEST_PORT: u16 = 44818;

/// An EtherNet/IP device identified via a List Identity response (product name, vendor, revision).
#[derive(Debug, Clone)]
pub struct EnipDevice {
    pub ip: String,
    pub product_name: String,
    pub vendor_id: String,
    pub device_type: u32,
    pub revision: String,
}

fn parse_list_identity(data: &[u8]) -> Option<EnipDevice> {
    if data.len() < 4 || data[0] != 0x63 || data[1] != 0x00 {
        return None;
    }

    let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    // EIP header is 24 bytes; payload follows
    if data.len() < 24 + data_len {
        return None;
    }
    let response_data = &data[24..24 + data_len];
    if response_data.len() < 6 {
        return None;
    }

    let item_count = u16::from_le_bytes([response_data[0], response_data[1]]);
    if item_count < 1 || response_data[2..4] != [0x0c, 0x00] {
        return None;
    }

    let item_len = u16::from_le_bytes([response_data[4], response_data[5]]) as usize;
    if response_data.len() < 6 + item_len {
        return None;
    }
    let item = &response_data[6..6 + item_len];
    if item.len() < 34 {
        return None;
    }

    let vendor_raw = u16::from_le_bytes([item[18], item[19]]);
    let device_type_id = u32::from(u16::from_le_bytes([item[20], item[21]]));
    let rev_major = item[24];
    let rev_minor = item[25];
    let revision = format!("{rev_major}.{rev_minor}");

    let name_len = item[32] as usize;
    if item.len() < 33 + name_len {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();

    let ip = if item.len() >= 10 {
        format!("{}.{}.{}.{}", item[6], item[7], item[8], item[9])
    } else {
        String::new()
    };

    Some(EnipDevice {
        ip,
        product_name,
        vendor_id: format!("{vendor_raw:04x}"),
        device_type: device_type_id,
        revision,
    })
}

/// Broadcast-scan for EtherNet/IP devices.
pub fn scan(interface: &NetworkInterface, timeout: u64, silent: bool) -> Result<Vec<EnipDevice>> {
    use crate::core::network::create_udp_broadcast_socket;

    let sock = create_udp_broadcast_socket(&interface.ip, timeout)?;
    let pkt = hex_decode(DISCOVERY_PACKET);
    sock.send_to(&pkt, format!("255.255.255.255:{DEST_PORT}"))?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if let Some(dev) = parse_list_identity(&buf[..n]) {
                    let d = if dev.ip.is_empty() || dev.ip == "0.0.0.0" {
                        EnipDevice {
                            ip: addr.ip().to_string(),
                            ..dev
                        }
                    } else {
                        dev
                    };
                    if !silent {
                        print_device(&d);
                    }
                    devices.push(d);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }

    if devices.is_empty() && !silent {
        println!("No EtherNet/IP devices found.");
    }

    Ok(devices)
}

/// Send List Identity to a specific IP.
pub fn scan_ip(ip: &str, timeout: u64, silent: bool) -> Result<Vec<EnipDevice>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    let pkt = hex_decode(DISCOVERY_PACKET);
    sock.send_to(&pkt, format!("{ip}:{DEST_PORT}"))?;

    let mut buf = [0u8; 1024];
    let Ok((n, addr)) = sock.recv_from(&mut buf) else {
        if !silent {
            println!("No EtherNet/IP response from {ip}");
        }
        return Ok(vec![]);
    };

    let Some(dev) = parse_list_identity(&buf[..n]) else {
        return Ok(vec![]);
    };

    let dev = if dev.ip.is_empty() || dev.ip == "0.0.0.0" {
        EnipDevice {
            ip: addr.ip().to_string(),
            ..dev
        }
    } else {
        dev
    };

    if !silent {
        print_device(&dev);
    }
    Ok(vec![dev])
}

fn print_device(d: &EnipDevice) {
    let vendor_id_int = u32::from_str_radix(&d.vendor_id, 16).unwrap_or(0);
    let vname = vendor_name(vendor_id_int);
    let dtype = device_type_name(d.device_type);
    println!(
        "  {:<25} | {:<16} | {:<30} | {:<20}",
        d.product_name, d.ip, dtype, vname
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) { return vec![]; }
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_odd_length_returns_empty() {
        assert!(hex_decode("A").is_empty());
        assert!(hex_decode("ABC").is_empty());
    }

    #[test]
    fn hex_decode_even_length_works() {
        assert_eq!(hex_decode("DEAD"), vec![0xDE, 0xAD]);
    }

    const LIST_ID_RESP: &[u8] = &[
        // EIP header (24 bytes)
        0x63, 0x00,
        0x2b, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // CPF body (43 bytes): item_count(2) + item_type(2) + item_len(2) + item(37)
        0x01, 0x00,
        0x0c, 0x00,
        0x25, 0x00,
        // Identity item (37 bytes): enc_version(2) + socket_addr(16) + ...
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00,   // vendor_id = 1
        0x0e, 0x00,   // device_type = 14
        0x01, 0x00,   // product_code = 1
        0x1f, 0x03,   // revision: major=31, minor=3
        0x00, 0x00,   // status
        0x78, 0x56, 0x34, 0x12,  // serial LE = 0x12345678
        0x03,         // name_len = 3
        b'P', b'L', b'C',
        0x03,         // state
    ];

    #[test]
    fn parse_list_identity_empty_returns_none() {
        assert!(parse_list_identity(&[]).is_none());
    }

    #[test]
    fn parse_list_identity_too_short_returns_none() {
        assert!(parse_list_identity(&[0x63, 0x00, 0x00]).is_none());
    }

    #[test]
    fn parse_list_identity_wrong_command_returns_none() {
        let mut buf = [0u8; 67];
        buf[..LIST_ID_RESP.len()].copy_from_slice(LIST_ID_RESP);
        buf[0] = 0x64;
        assert!(parse_list_identity(&buf).is_none());
    }

    #[test]
    fn parse_list_identity_claimed_len_overflow_returns_none() {
        // data[2..4] claims 0xFFFF bytes but buffer is tiny
        let buf = &[0x63u8, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_list_identity(buf).is_none());
    }

    #[test]
    fn parse_list_identity_valid_response_returns_device() {
        let dev = parse_list_identity(LIST_ID_RESP).unwrap();
        assert_eq!(dev.vendor_id, "0001");
        assert_eq!(dev.product_name, "PLC");
        assert_eq!(dev.device_type, 14);
        assert_eq!(dev.revision, "31.3");
    }
}
