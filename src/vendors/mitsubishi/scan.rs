use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;
use crate::vendors::mitsubishi::slmp;

const DISCOVERY_PORT: u16 = 5561;
const SLMP_DISCOVERY_PORT: u16 = 5006;

const DISCOVERY_PACKET: &str = "57010000001111070000ffff030000fe0300001e001c0a161400000000000000000000000000000000000000 00000b2001000000";

const SLMP_DISCOVERY_PACKET: &str = "5000ffff03ff0c000101 00000000000000000000";

#[derive(Debug, Clone)]
pub struct MitsubishiDevice {
    pub ip: String,
    pub plc_type: String,
    pub title: Option<String>,
    pub comment: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub discovery_transport: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Both,
}

fn parse_gxworks_response(data: &[u8], ip: &str) -> MitsubishiDevice {
    let parts: Vec<&[u8]> = split_on(data, b"   ");

    let plc_type = parts
        .get(1)
        .and_then(|p| std::str::from_utf8(p).ok())
        .unwrap_or("Unknown")
        .to_string();

    let title = parts.get(2).and_then(|opt_data| {
        let len1 = *opt_data.first()? as usize;
        if opt_data.len() >= 6 + len1 {
            let raw = &opt_data[6..6 + len1];
            decode_utf16(raw)
        } else {
            None
        }
    });

    let comment = parts.get(2).and_then(|opt_data| {
        let len1 = *opt_data.first()? as usize;
        let len2 = opt_data.get(2).copied()? as usize;
        let start = 6 + len1;
        if opt_data.len() >= start + len2 {
            decode_utf16(&opt_data[start..start + len2])
        } else {
            None
        }
    });

    MitsubishiDevice {
        ip: ip.to_string(),
        plc_type,
        title,
        comment,
        protocol: Some("gxworks_udp".to_string()),
        port: Some(DISCOVERY_PORT),
        discovery_transport: Some("udp".to_string()),
    }
}

fn split_on<'a>(data: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut result = Vec::new();
    let mut start = 0;
    while start <= data.len() {
        match data[start..].windows(sep.len()).position(|w| w == sep) {
            Some(pos) => {
                result.push(&data[start..start + pos]);
                start += pos + sep.len();
            }
            None => {
                result.push(&data[start..]);
                break;
            }
        }
    }
    result
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let words: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&words).ok().filter(|s| !s.is_empty())
}

fn parse_slmp_response(data: &[u8], ip: &str) -> MitsubishiDevice {
    let model = data
        .get(11..)
        .and_then(|b| {
            let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
            std::str::from_utf8(&b[..end]).ok()
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Mitsubishi Q/L Series".to_string());

    MitsubishiDevice {
        ip: ip.to_string(),
        plc_type: model,
        title: None,
        comment: None,
        protocol: Some("slmp_udp".to_string()),
        port: Some(SLMP_DISCOVERY_PORT),
        discovery_transport: Some("udp".to_string()),
    }
}

fn tcp_device(ip: &str, port: u16) -> MitsubishiDevice {
    MitsubishiDevice {
        ip: ip.to_string(),
        plc_type: format!("Mitsubishi-compatible SLMP TCP {port}"),
        title: None,
        comment: None,
        protocol: Some("slmp_tcp".to_string()),
        port: Some(port),
        discovery_transport: Some("tcp".to_string()),
    }
}

/// Broadcast-scan for Mitsubishi MELSEC PLCs.
pub fn scan(
    interface: &NetworkInterface,
    timeout: u64,
    silent: bool,
) -> Result<Vec<MitsubishiDevice>> {
    use crate::core::network::create_udp_broadcast_socket;

    let sock = create_udp_broadcast_socket(&interface.ip, timeout)?;
    let pkt = hex_decode(DISCOVERY_PACKET);
    sock.send_to(&pkt, format!("255.255.255.255:{DISCOVERY_PORT}"))?;

    if !silent {
        println!("Scanning for Mitsubishi devices ({timeout}s timeout)...");
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let dev = parse_gxworks_response(&buf[..n], &addr.ip().to_string());
                if !silent {
                    print_device(&dev);
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

    if devices.is_empty() && !silent {
        println!("No Mitsubishi devices found.");
    }
    Ok(devices)
}

/// Send Mitsubishi discovery to a specific IP (GX Works3 first, then SLMP).
pub fn scan_ip(ip: &str, timeout: u64, silent: bool) -> Result<Vec<MitsubishiDevice>> {
    scan_ip_with_transport(ip, timeout, silent, 0, Transport::Both)
}

/// Scan a specific Mitsubishi IP using UDP discovery, TCP SLMP, or both.
/// Pass `port = 0` to use the default SLMP TCP port (5007).
pub fn scan_ip_with_transport(
    ip: &str,
    timeout: u64,
    silent: bool,
    port: u16,
    transport: Transport,
) -> Result<Vec<MitsubishiDevice>> {
    match transport {
        Transport::Udp => scan_ip_udp(ip, timeout, silent),
        Transport::Tcp => Ok(scan_ip_tcp(ip, timeout, silent, port)),
        Transport::Both => {
            let udp = scan_ip_udp(ip, timeout, true)?;
            if !udp.is_empty() {
                if !silent {
                    for dev in &udp {
                        print_device(dev);
                    }
                }
                return Ok(udp);
            }
            if !silent {
                println!(
                    "No Mitsubishi UDP discovery response from {ip}; trying TCP {}...",
                    effective_slmp_port(port)
                );
            }
            Ok(scan_ip_tcp(ip, timeout, silent, port))
        }
    }
}

fn scan_ip_udp(ip: &str, timeout: u64, silent: bool) -> Result<Vec<MitsubishiDevice>> {
    // GX Works3 probe
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    let pkt = hex_decode(DISCOVERY_PACKET);
    sock.send_to(&pkt, format!("{ip}:{DISCOVERY_PORT}"))?;

    let mut buf = [0u8; 1024];
    if let Ok((n, addr)) = sock.recv_from(&mut buf) {
        let dev = parse_gxworks_response(&buf[..n], &addr.ip().to_string());
        if !silent {
            print_device(&dev);
        }
        return Ok(vec![dev]);
    }
    drop(sock);

    // SLMP probe fallback
    let sock2 = UdpSocket::bind("0.0.0.0:0")?;
    sock2.set_read_timeout(Some(Duration::from_secs(timeout)))?;
    let slmp_pkt = hex_decode(SLMP_DISCOVERY_PACKET);
    sock2.send_to(&slmp_pkt, format!("{ip}:{SLMP_DISCOVERY_PORT}"))?;

    if let Ok((n, addr)) = sock2.recv_from(&mut buf) {
        let dev = parse_slmp_response(&buf[..n], &addr.ip().to_string());
        if !silent {
            println!("  Found {} at {} (SLMP)", dev.plc_type, dev.ip);
        }
        return Ok(vec![dev]);
    }

    if !silent {
        println!("No Mitsubishi response from {ip}");
    }
    Ok(vec![])
}

fn scan_ip_tcp(ip: &str, _timeout: u64, silent: bool, port: u16) -> Vec<MitsubishiDevice> {
    let port = effective_slmp_port(port);
    if slmp::read_word_devices(ip, port, "D", 0, 1).is_ok() {
        let dev = tcp_device(ip, port);
        if !silent {
            println!("  Found {} at {} (SLMP TCP {port})", dev.plc_type, dev.ip);
        }
        vec![dev]
    } else {
        if !silent {
            println!("No Mitsubishi TCP SLMP response from {ip}:{port}");
        }
        vec![]
    }
}

fn effective_slmp_port(port: u16) -> u16 {
    if port == 0 {
        slmp::DEFAULT_PORT
    } else {
        port
    }
}

fn print_device(d: &MitsubishiDevice) {
    let extra = match (&d.title, &d.comment) {
        (Some(t), Some(c)) => format!(" (CPU Title: {t}, Comment: {c})"),
        (Some(t), None) => format!(" (CPU Title: {t})"),
        (None, Some(c)) => format!(" (Comment: {c})"),
        _ => String::new(),
    };
    println!("  Found {} at {}{}", d.plc_type, d.ip, extra);
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
