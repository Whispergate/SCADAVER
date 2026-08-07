use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

/// OT-relevant default ports to scan when no extras are specified.
const DEFAULT_OT_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    80,    // HTTP / HMI web
    102,   // S7comm (Siemens)
    443,   // HTTPS / HMI web
    502,   // Modbus TCP
    2404,  // IEC 60870-5-104
    4840,  // OPC-UA
    5006,  // Mitsubishi SLMP (UDP primary, but TCP also used)
    8080,  // Alternate HTTP / HMI web
    9600,  // Omron FINS TCP
    20547, // ProfiNet RT
    44818, // EtherNet/IP (Rockwell)
    47808, // BACnet/IP
];

pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: &'static str,
    pub banner: Option<String>,
}

/// Scan `ip` for open OT-relevant TCP ports. `extra_ports` are appended to the default list.
pub fn scan_ot_ports(ip: &str, timeout_secs: u64, extra_ports: &[u16]) -> Vec<PortResult> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut ports: Vec<u16> = DEFAULT_OT_PORTS.to_vec();
    for &p in extra_ports {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports.sort_unstable();

    ports
        .into_iter()
        .map(|port| probe_port(ip, port, timeout))
        .collect()
}

fn probe_port(ip: &str, port: u16, timeout: Duration) -> PortResult {
    let addr = format!("{ip}:{port}");
    match TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("fallback addr")),
        timeout,
    ) {
        Err(_) => PortResult { port, open: false, service: service_name(port), banner: None },
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .ok();
            let mut buf = [0u8; 256];
            let banner = stream.read(&mut buf).ok().and_then(|n| {
                if n == 0 {
                    return None;
                }
                let s: String = buf[..n]
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() { None } else { Some(trimmed.chars().take(80).collect()) }
            });
            PortResult { port, open: true, service: service_name(port), banner }
        }
    }
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        80 => "HTTP",
        102 => "S7comm",
        443 => "HTTPS",
        502 => "Modbus/TCP",
        2404 => "IEC-104",
        4840 => "OPC-UA",
        5006 => "SLMP",
        8080 => "HTTP-alt",
        9600 => "Omron-FINS",
        20547 => "ProfiNet",
        44818 => "EtherNet/IP",
        47808 => "BACnet",
        _ => "unknown",
    }
}
