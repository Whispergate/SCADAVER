use anyhow::Result;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;

const DEST_PORT: u16 = 1740;
const SOURCE_PORT: u16 = 1740;
const MODBUS_PORT: u16 = 502;
const MODBUS_UNIT_IDS: &[u8] = &[0x01, 0xFF];

#[derive(Debug, Clone)]
pub struct SchneiderDevice {
    pub ip: String,
    pub name: Option<String>,
    pub firmware: Option<String>,
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
    for i in 0..4 {
        let ip_byte = src_parts.get(i).copied().unwrap_or(0);
        let mask_byte = sub_parts.get(i).copied().unwrap_or(0);
        b_parts[i] = ip_byte | !mask_byte;
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
                    c.iter()
                        .filter(|&&b| b != 0)
                        .copied()
                        .collect::<Vec<_>>()
                }
            })
            .collect::<Vec<u8>>();
        dev.name = Some(String::from_utf8_lossy(&name).to_string());
    }
    dev
}

/// Broadcast-scan for Schneider Electric devices.
pub fn scan(interface: &NetworkInterface, timeout: u64, silent: bool) -> Result<Vec<SchneiderDevice>> {
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
pub fn scan_ip_with_port(ip: &str, timeout: u64, silent: bool, port: u16) -> Result<Vec<SchneiderDevice>> {
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
    let sock = UdpSocket::bind(&bind_addr)
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    sock.send_to(&pkt, format!("{ip}:{DEST_PORT}"))?;

    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok((n, addr)) => {
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
        }
        Err(_) => {
            if !silent {
                println!("No Schneider UDP discovery response from {ip}");
            }
            Ok(vec![])
        }
    }
}

fn scan_ip_both(ip: &str, timeout: u64, silent: bool, port: u16) -> Result<Vec<SchneiderDevice>> {
    let udp_devs = scan_ip_udp(ip, timeout, true)?;
    if udp_devs.iter().any(|d| d.name.is_some() || d.firmware.is_some()) {
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
    if port == 0 { MODBUS_PORT } else { port }
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
    let pdu = [0x2B, 0x0E, 0x01, 0x00];
    for &unit_id in MODBUS_UNIT_IDS {
        let Ok(resp) = modbus_transact(ip, timeout, port, unit_id, &pdu) else {
            continue;
        };
        if resp.first().copied()? != 0x2B || resp.get(1).copied()? != 0x0E {
            continue;
        }

        let mut dev = SchneiderDevice {
            ip: ip.to_string(),
            name: None,
            firmware: None,
        };
        let obj_count = usize::from(*resp.get(6)?);
        let mut pos = 7usize;
        for _ in 0..obj_count.min(16) {
            let obj_id = *resp.get(pos)?;
            let obj_len = usize::from(*resp.get(pos + 1)?);
            let value = resp.get(pos + 2..pos + 2 + obj_len)?;
            let value = String::from_utf8_lossy(value).trim().to_string();
            match obj_id {
                0x00 if is_schneider_name(&value) => dev.name = Some(value),
                0x01 if !value.is_empty() => dev.name = Some(value),
                0x02 if !value.is_empty() => dev.firmware = Some(value),
                _ => {}
            }
            pos += 2 + obj_len;
        }

        return Some(dev);
    }
    None
}

fn modbus_tcp_probe(ip: &str, timeout: u64, port: u16) -> bool {
    let pdu = [0x03, 0x00, 0x00, 0x00, 0x01];
    MODBUS_UNIT_IDS.iter().any(|&unit_id| {
        modbus_transact(ip, timeout, port, unit_id, &pdu)
            .map(|resp| matches!(resp.first(), Some(0x03 | 0x83)))
            .unwrap_or(false)
    })
}

fn modbus_transact(ip: &str, timeout: u64, port: u16, unit_id: u8, pdu: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{ip}:{port}");
    let timeout = Duration::from_secs(timeout.max(1));
    let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut req = Vec::with_capacity(7 + pdu.len());
    req.extend_from_slice(&1u16.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&u16::try_from(pdu.len() + 1)?.to_be_bytes());
    req.push(unit_id);
    req.extend_from_slice(pdu);
    stream.write_all(&req)?;

    let mut header = [0u8; 7];
    stream.read_exact(&mut header)?;
    if header[2..4] != [0, 0] || header[6] != unit_id {
        anyhow::bail!("not a Modbus TCP response");
    }
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if len < 2 {
        anyhow::bail!("short Modbus TCP response");
    }
    let mut body = vec![0u8; len - 1];
    stream.read_exact(&mut body)?;
    Ok(body)
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
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
