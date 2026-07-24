use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;

const DEST_PORT: u16 = 1740;
const SOURCE_PORT: u16 = 1740;

#[derive(Debug, Clone)]
pub struct SchneiderDevice {
    pub ip: String,
    pub name: Option<String>,
    pub firmware: Option<String>,
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
                println!("No Schneider response from {ip}");
            }
            Ok(vec![])
        }
    }
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
