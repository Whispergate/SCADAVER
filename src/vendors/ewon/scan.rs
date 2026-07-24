use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;

const DISCOVERY_PORT: u16 = 1507;
const RESPONSE_PORT: u16 = 1506;

const DISCOVERY_PACKETS: &[&str] = &[
    "4950434f4e4600000000000000000000000000000000000000000000000000000000000000000000",
    "4950434f4e460000000000000000000a000000000000000000000000000000000000000000000000",
];

#[derive(Debug, Clone)]
pub struct EwonDevice {
    pub ip: Option<String>,
    pub netmask: Option<String>,
    pub mac: Option<String>,
    pub serial: Option<String>,
    pub product_code: Option<String>,
    pub firmware: Option<String>,
    pub identifier: Option<String>,
    pub response_type: String,
}

fn parse_device_info(data: &[u8]) -> EwonDevice {
    let to_hex = |b: u8| format!("{b:02x}");

    let ip = if data.len() >= 28 {
        Some(format!(
            "{}.{}.{}.{}",
            data[23], data[22], data[21], data[20]
        ))
    } else {
        None
    };

    let netmask = if data.len() >= 32 {
        Some(format!(
            "{}.{}.{}.{}",
            data[27], data[26], data[25], data[24]
        ))
    } else {
        None
    };

    let mac = if data.len() >= 38 {
        Some(format!(
            "{}:{}:{}:{}:{}:{}",
            to_hex(data[32]),
            to_hex(data[33]),
            to_hex(data[34]),
            to_hex(data[35]),
            to_hex(data[36]),
            to_hex(data[37])
        ))
    } else {
        None
    };

    let serial = if data.len() >= 20 {
        let serialp1 = data[19];
        let raw16 = if data.len() >= 19 {
            ((data[18] as u16) << 8) | (data[17] as u16)
        } else {
            0
        };
        let serialp2 = raw16 / 1000;
        let mut serialp3 = data.get(17).copied().unwrap_or(0);
        if raw16 % 1000 >= 500 {
            serialp3 = serialp3.wrapping_add(0x80);
        }
        let serialp4 = data.get(16).copied().unwrap_or(0);
        Some(format!("{serialp1}{serialp2}-{serialp3:04}-{serialp4}"))
    } else {
        None
    };

    let product_code = data.get(16).map(|b| b.to_string());
    let identifier = if data.len() >= 4 {
        Some(String::from_utf8_lossy(&data[..4]).to_string())
    } else {
        None
    };

    EwonDevice {
        ip,
        netmask,
        mac,
        serial,
        product_code,
        firmware: None,
        identifier,
        response_type: "device_info".into(),
    }
}

fn parse_firmware_info(data: &[u8]) -> EwonDevice {
    let firmware = if data.len() >= 20 {
        let raw = &data[20..];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..end]).trim().to_string())
    } else {
        None
    };

    EwonDevice {
        ip: None,
        netmask: None,
        mac: None,
        serial: None,
        product_code: None,
        firmware,
        identifier: None,
        response_type: "firmware_info".into(),
    }
}

fn parse_response(data: &[u8]) -> Option<EwonDevice> {
    if data.len() < 16 {
        return None;
    }
    match data[15] {
        2 => Some(parse_device_info(data)),
        5 => Some(parse_firmware_info(data)),
        _ => None,
    }
}

/// Broadcast-scan for eWON devices.
pub fn scan(_interface: &NetworkInterface, timeout: u64, silent: bool) -> Result<Vec<EwonDevice>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    let bind: std::net::SocketAddr = format!("0.0.0.0:{RESPONSE_PORT}").parse()?;
    if s.bind(&bind.into()).is_err() {
        // Fall back to any port if 1506 is in use
        let fallback: std::net::SocketAddr = "0.0.0.0:0".parse()?;
        s.bind(&fallback.into())?;
    }
    let sock = UdpSocket::from(s);

    if !silent {
        println!("Sending discovery packets, waiting {timeout}s for answers...");
    }

    for pkt_hex in DISCOVERY_PACKETS {
        let pkt = hex_decode(pkt_hex);
        let _ = sock.send_to(&pkt, format!("255.255.255.255:{DISCOVERY_PORT}"));
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(dev) = parse_response(&buf[..n]) {
                    if !silent {
                        print_device(&dev);
                    }
                    devices.push(dev);
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

    if !silent {
        println!("Got {} response(s).", devices.len() / 2);
    }
    Ok(devices)
}

/// Send eWON discovery to a specific IP.
pub fn scan_ip(ip: &str, timeout: u64, silent: bool) -> Result<Vec<EwonDevice>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    let bind: std::net::SocketAddr = format!("0.0.0.0:{RESPONSE_PORT}").parse()?;
    if s.bind(&bind.into()).is_err() {
        let fallback: std::net::SocketAddr = "0.0.0.0:0".parse()?;
        s.bind(&fallback.into())?;
    }
    let sock = UdpSocket::from(s);

    for pkt_hex in DISCOVERY_PACKETS {
        let pkt = hex_decode(pkt_hex);
        let _ = sock.send_to(&pkt, format!("{ip}:{DISCOVERY_PORT}"));
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(dev) = parse_response(&buf[..n]) {
                    if !silent {
                        print_device(&dev);
                    }
                    devices.push(dev);
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
        println!("No eWON response from {ip}");
    }
    Ok(devices)
}

fn print_device(dev: &EwonDevice) {
    if dev.response_type == "device_info" {
        println!(
            "  - {}, {}, {}, {}, Pcode: {}",
            dev.identifier.as_deref().unwrap_or("?"),
            dev.ip.as_deref().unwrap_or("?"),
            dev.netmask.as_deref().unwrap_or("?"),
            dev.mac.as_deref().unwrap_or("?"),
            dev.product_code.as_deref().unwrap_or("?")
        );
    } else if let Some(fw) = &dev.firmware {
        println!("    Firmware: {fw}");
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
