use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;
use crate::vendors::enip::enums::{device_type_name, vendor_name};

const DISCOVERY_PACKET: &str = "630000000000000000000000000000000000000000000000";
const DEST_PORT: u16 = 44818;

#[derive(Debug, Clone)]
pub struct EnipDevice {
    pub ip: String,
    pub product_name: String,
    pub vendor_id: String,
    pub device_type: u32,
    pub product_code: u32,
    pub revision: String,
    pub serial: String,
    pub state: String,
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
    let device_type_id = u16::from_le_bytes([item[20], item[21]]) as u32;
    let product_code = u16::from_le_bytes([item[22], item[23]]) as u32;
    let rev_major = item[24];
    let rev_minor = item[25];
    let revision = format!("{rev_major}.{rev_minor}");
    let serial = format!(
        "{:08x}",
        u32::from_le_bytes([item[28], item[29], item[30], item[31]])
    );

    let name_len = item[32] as usize;
    if item.len() < 33 + name_len {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();
    let state = if item.len() > 33 + name_len {
        format!("{:02x}", item[33 + name_len])
    } else {
        "00".to_string()
    };

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
        product_code,
        revision,
        serial,
        state,
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
    let (n, addr) = match sock.recv_from(&mut buf) {
        Ok(v) => v,
        Err(_) => {
            if !silent {
                println!("No EtherNet/IP response from {ip}");
            }
            return Ok(vec![]);
        }
    };

    let dev = match parse_list_identity(&buf[..n]) {
        Some(d) => d,
        None => return Ok(vec![]),
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
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
