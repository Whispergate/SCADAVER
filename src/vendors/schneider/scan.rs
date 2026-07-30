use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::modbus::{self, ModbusDeviceId, ModbusTcpClient};
use crate::core::network::NetworkInterface;

const DEST_PORT: u16 = 1740;
const SOURCE_PORT: u16 = 1740;

#[derive(Debug, Clone)]
pub struct SchneiderDevice {
    pub ip: String,
    pub name: Option<String>,
    pub firmware: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub discovery_transport: Option<String>,
    pub modbus_unit_id: Option<u8>,
    pub identity_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Both,
}

fn build_discovery_packet(src_ip: &str, subnet: &str) -> Vec<u8> {
    let src_parts: Vec<u8> = src_ip
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    let sub_parts: Vec<u8> = subnet
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    // Subnet field in the Schneider discovery packet is the broadcast address
    let mut b_parts = [0u8; 4];
    for (i, b) in b_parts.iter_mut().enumerate() {
        let ip_byte = src_parts.get(i).copied().unwrap_or(0);
        let mask_byte = sub_parts.get(i).copied().unwrap_or(0);
        *b = ip_byte | !mask_byte;
    }

    let mut pkt = hex_decode("c574400300003d7d");
    pkt.extend_from_slice(&b_parts);
    pkt.extend(hex_decode("9000000002c203013b540000"));
    pkt
}

fn parse_response(data: &[u8], src_ip: &str) -> SchneiderDevice {
    let hexdata = hex_encode(data);
    let mut dev = SchneiderDevice {
        ip: src_ip.to_string(),
        name: None,
        firmware: None,
        protocol: None,
        port: None,
        discovery_transport: Some("udp".to_string()),
        modbus_unit_id: None,
        identity_match: false,
    };

    if data.len() >= 53 && hexdata.len() >= 106 {
        let fw = format!(
            "{}.{}.{}.{}",
            u8::from_str_radix(&hexdata[102..104], 16).unwrap_or(0),
            u8::from_str_radix(&hexdata[100..102], 16).unwrap_or(0),
            u8::from_str_radix(&hexdata[98..100], 16).unwrap_or(0),
            u8::from_str_radix(&hexdata[96..98], 16).unwrap_or(0),
        );
        dev.firmware = Some(fw);

        let raw_name = &data[52..];
        let name = raw_name
            .chunks(2)
            .filter(|c| c != &[0, 0])
            .flat_map(|c| {
                if c == [0] {
                    vec![]
                } else {
                    c.iter().filter(|&&b| b != 0).copied().collect::<Vec<_>>()
                }
            })
            .collect::<Vec<u8>>();
        dev.name = Some(String::from_utf8_lossy(&name).to_string());
        dev.identity_match = true;
    }
    dev
}

/// Broadcast-scan for Schneider Electric devices.
pub fn scan(
    interface: &NetworkInterface,
    timeout: u64,
    silent: bool,
) -> Result<Vec<SchneiderDevice>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.set_read_timeout(Some(Duration::from_secs(timeout)))?;
    let bind: std::net::SocketAddr = format!("{}:{SOURCE_PORT}", interface.ip).parse()?;
    s.bind(&bind.into())?;
    let sock = UdpSocket::from(s);

    let broadcast = crate::core::network::calculate_broadcast(&interface.ip, &interface.netmask);
    let pkt = build_discovery_packet(&interface.ip, &interface.netmask);

    if !silent {
        println!("Sending discovery packets, waiting {timeout}s for answers...");
    }
    sock.send_to(&pkt, format!("{broadcast}:{DEST_PORT}"))?;

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let src = addr.ip().to_string();
                if src == interface.ip {
                    continue;
                }
                let dev = parse_response(&buf[..n], &src);
                if !silent {
                    match (&dev.name, &dev.firmware) {
                        (Some(name), Some(fw)) => println!("  {}: {name} (firmware {fw})", dev.ip),
                        _ => println!("  {}: (short response)", dev.ip),
                    }
                }
                devices.push(dev);
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
        if devices.is_empty() {
            println!("No Schneider devices found.");
        } else {
            println!("Found {} device(s).", devices.len());
        }
    }
    Ok(devices)
}

/// Send discovery to a specific Schneider IP.
pub fn scan_ip(ip: &str, timeout: u64, silent: bool) -> Result<Vec<SchneiderDevice>> {
    scan_ip_with_port(ip, timeout, silent, 0)
}

/// Send discovery to a specific Schneider IP, falling back to Modbus TCP on `port`.
/// Pass `port = 0` to use the default Modbus TCP port (502).
pub fn scan_ip_with_port(
    ip: &str,
    timeout: u64,
    silent: bool,
    port: u16,
) -> Result<Vec<SchneiderDevice>> {
    scan_ip_with_transport(ip, timeout, silent, port, Transport::Both)
}

/// Scan a specific Schneider IP using UDP discovery, TCP Modbus, or both.
/// Pass `port = 0` to use the default Modbus TCP port (502).
pub fn scan_ip_with_transport(
    ip: &str,
    timeout: u64,
    silent: bool,
    port: u16,
    transport: Transport,
) -> Result<Vec<SchneiderDevice>> {
    match transport {
        Transport::Udp => scan_ip_udp(ip, timeout, silent),
        Transport::Tcp => Ok(tcp_fallback_scan(ip, timeout, silent, port)),
        Transport::Both => scan_ip_both(ip, timeout, silent, port),
    }
}

fn scan_ip_udp(ip: &str, timeout: u64, silent: bool) -> Result<Vec<SchneiderDevice>> {
    use crate::core::network::local_ip_for;

    let local_ip = local_ip_for(ip);
    let pkt = build_discovery_packet(&local_ip, "255.255.0.0");

    let bind_addr = format!("{local_ip}:{SOURCE_PORT}");
    let sock = UdpSocket::bind(&bind_addr).or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    sock.send_to(&pkt, format!("{ip}:{DEST_PORT}"))?;

    let mut buf = [0u8; 1024];
    if let Ok((n, addr)) = sock.recv_from(&mut buf) {
        let dev = parse_response(&buf[..n], &addr.ip().to_string());
        if dev.name.is_some() || dev.firmware.is_some() {
            if !silent {
                match (&dev.name, &dev.firmware) {
                    (Some(name), Some(fw)) => println!("  {}: {name} (firmware {fw})", dev.ip),
                    _ => println!("  {}: (short response)", dev.ip),
                }
            }
            return Ok(vec![dev]);
        }

        if !silent {
            match (&dev.name, &dev.firmware) {
                (Some(name), Some(fw)) => println!("  {}: {name} (firmware {fw})", dev.ip),
                _ => println!("  {}: (short response)", dev.ip),
            }
        }
        Ok(vec![dev])
    } else {
        if !silent {
            println!("No Schneider UDP discovery response from {ip}");
        }
        Ok(vec![])
    }
}

fn scan_ip_both(ip: &str, timeout: u64, silent: bool, port: u16) -> Result<Vec<SchneiderDevice>> {
    let udp_devs = scan_ip_udp(ip, timeout, true)?;
    if udp_devs
        .iter()
        .any(|d| d.name.is_some() || d.firmware.is_some())
    {
        if !silent {
            for dev in &udp_devs {
                match (&dev.name, &dev.firmware) {
                    (Some(name), Some(fw)) => println!("  {}: {name} (firmware {fw})", dev.ip),
                    _ => println!("  {}: (short response)", dev.ip),
                }
            }
        }
        return Ok(udp_devs);
    }

    if !silent {
        println!(
            "No Schneider UDP discovery response from {ip}; trying TCP {}...",
            effective_modbus_port(port)
        );
    }

    let tcp_devs = tcp_fallback_scan(ip, timeout, silent, port);
    if !tcp_devs.is_empty() {
        return Ok(tcp_devs);
    }

    if !udp_devs.is_empty() {
        if !silent {
            for dev in &udp_devs {
                match (&dev.name, &dev.firmware) {
                    (Some(name), Some(fw)) => println!("  {}: {name} (firmware {fw})", dev.ip),
                    _ => println!("  {}: (short response)", dev.ip),
                }
            }
        }
        return Ok(udp_devs);
    }

    Ok(vec![])
}

fn effective_modbus_port(port: u16) -> u16 {
    modbus::effective_port(port)
}

fn tcp_fallback_scan(ip: &str, timeout: u64, silent: bool, port: u16) -> Vec<SchneiderDevice> {
    let port = effective_modbus_port(port);
    if let Some(dev) = modbus_device_id(ip, timeout, port) {
        if !silent {
            match (&dev.name, &dev.firmware) {
                (Some(name), Some(fw)) => {
                    println!("  {}: {name} (Modbus TCP {port}, firmware {fw})", dev.ip);
                }
                (Some(name), None) => println!("  {}: {name} (Modbus TCP {port})", dev.ip),
                _ => println!("  {}: Schneider-compatible Modbus TCP {port}", dev.ip),
            }
        }
        return vec![dev];
    }

    if modbus_tcp_probe(ip, timeout, port) {
        let dev = SchneiderDevice {
            ip: ip.to_string(),
            name: Some(format!("Schneider-compatible Modbus TCP {port}")),
            firmware: None,
            protocol: Some("modbus_tcp".to_string()),
            port: Some(port),
            discovery_transport: Some("tcp".to_string()),
            modbus_unit_id: None,
            identity_match: false,
        };
        if !silent {
            println!(
                "  {}: Schneider-compatible Modbus TCP {port} (UDP discovery did not answer)",
                dev.ip
            );
        }
        return vec![dev];
    }

    vec![]
}

fn modbus_device_id(ip: &str, timeout: u64, port: u16) -> Option<SchneiderDevice> {
    let client = ModbusTcpClient::new(ip)
        .with_port(port)
        .with_timeout_secs(timeout);
    let id = client.read_device_id().ok()?;
    Some(device_from_modbus_id(ip, port, &id))
}

fn modbus_tcp_probe(ip: &str, timeout: u64, port: u16) -> bool {
    ModbusTcpClient::new(ip)
        .with_port(port)
        .with_timeout_secs(timeout)
        .probe_holding_register()
        .is_ok()
}

fn device_from_modbus_id(ip: &str, port: u16, id: &ModbusDeviceId) -> SchneiderDevice {
    let manufacturer = id.manufacturer().unwrap_or_default();
    let product = id.product_name().unwrap_or_default();
    let version = id.version().unwrap_or_default();
    let identity_match = id.objects.values().any(|value| is_schneider_name(value));

    let name = if !product.is_empty() {
        Some(product.to_string())
    } else if !manufacturer.is_empty() {
        Some(manufacturer.to_string())
    } else {
        None
    };

    SchneiderDevice {
        ip: ip.to_string(),
        name,
        firmware: if version.is_empty() {
            None
        } else {
            Some(version.to_string())
        },
        protocol: Some("modbus_tcp".to_string()),
        port: Some(port),
        discovery_transport: Some("tcp".to_string()),
        modbus_unit_id: Some(id.unit_id),
        identity_match,
    }
}

fn is_schneider_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("schneider")
        || value.contains("modicon")
        || value.contains("telemecanique")
        || value.contains("m340")
        || value.contains("m580")
        || value.contains("quantum")
        || value.contains("premium")
        || value.contains("tm221")
        || value.contains("tm241")
        || value.contains("tm251")
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn device_id(objects: &[(u8, &str)]) -> ModbusDeviceId {
        ModbusDeviceId {
            unit_id: 0x01,
            objects: objects
                .iter()
                .map(|(id, value)| (*id, (*value).to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn modbus_device_id_marks_schneider_identity() {
        let dev = device_from_modbus_id(
            "192.0.2.10",
            1502,
            &device_id(&[
                (0x00, "Schneider Electric"),
                (0x01, "TM241CE24T_U"),
                (0x02, "V05.01.09.14"),
            ]),
        );

        assert!(dev.identity_match);
        assert_eq!(dev.ip, "192.0.2.10");
        assert_eq!(dev.name.as_deref(), Some("TM241CE24T_U"));
        assert_eq!(dev.firmware.as_deref(), Some("V05.01.09.14"));
        assert_eq!(dev.protocol.as_deref(), Some("modbus_tcp"));
        assert_eq!(dev.port, Some(1502));
        assert_eq!(dev.discovery_transport.as_deref(), Some("tcp"));
        assert_eq!(dev.modbus_unit_id, Some(0x01));
    }

    #[test]
    fn modbus_device_id_keeps_generic_modbus_from_identity_match() {
        let dev = device_from_modbus_id(
            "192.0.2.20",
            502,
            &device_id(&[(0x00, "Generic Vendor"), (0x01, "Generic Modbus")]),
        );

        assert!(!dev.identity_match);
        assert_eq!(dev.name.as_deref(), Some("Generic Modbus"));
        assert_eq!(dev.protocol.as_deref(), Some("modbus_tcp"));
        assert_eq!(dev.port, Some(502));
        assert_eq!(dev.discovery_transport.as_deref(), Some("tcp"));
    }

    #[test]
    fn modbus_device_id_matches_modicon_product_family() {
        let dev = device_from_modbus_id(
            "192.0.2.30",
            502,
            &device_id(&[(0x00, "Vendor"), (0x01, "Modicon M580")]),
        );

        assert!(dev.identity_match);
        assert_eq!(dev.name.as_deref(), Some("Modicon M580"));
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

    #[test]
    fn parse_response_empty_slice_returns_default() {
        let dev = parse_response(&[], "1.2.3.4");
        assert_eq!(dev.ip, "1.2.3.4");
        assert!(dev.name.is_none());
        assert!(dev.firmware.is_none());
        assert!(!dev.identity_match);
    }

    #[test]
    fn parse_response_short_slice_skips_fields() {
        let data = vec![0u8; 52];
        let dev = parse_response(&data, "10.0.0.1");
        assert!(dev.firmware.is_none());
        assert!(!dev.identity_match);
    }

    #[test]
    fn parse_response_53_bytes_populates_firmware_and_name() {
        let mut data = vec![0u8; 54];
        // firmware: reversed — data[51].data[50].data[49].data[48]
        data[48] = 4;
        data[49] = 3;
        data[50] = 2;
        data[51] = 1;
        data[52] = b'M';
        data[53] = b'B';
        let dev = parse_response(&data, "192.168.1.1");
        assert_eq!(dev.firmware.as_deref(), Some("1.2.3.4"));
        assert_eq!(dev.ip, "192.168.1.1");
        assert!(dev.identity_match);
    }
}
