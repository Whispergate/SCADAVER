use anyhow::{bail, Result};
use dialoguer::{theme::ColorfulTheme, Select};
use network_interface::{Addr, NetworkInterfaceConfig};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub netmask: String,
    pub mac: Option<String>,
}

impl std::fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.ip)
    }
}

/// List all IPv4-capable network interfaces on the system.
pub fn get_interfaces() -> Vec<NetworkInterface> {
    let raw = match network_interface::NetworkInterface::show() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    raw.into_iter()
        .flat_map(|iface| {
            iface.addr.iter().filter_map(|addr| match addr {
                Addr::V4(v4) => {
                    let ip = v4.ip.to_string();
                    if ip.starts_with("127.") || ip == "0.0.0.0" {
                        return None;
                    }
                    Some(NetworkInterface {
                        name: iface.name.clone(),
                        ip,
                        netmask: v4
                            .netmask
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "255.255.255.0".to_string()),
                        mac: iface.mac_addr.clone(),
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>()
        })
        .collect()
}

/// Interactively prompt the user to choose one interface.
/// Returns the first if only one is available.
pub fn select_interface(interfaces: &[NetworkInterface]) -> Result<NetworkInterface> {
    if interfaces.is_empty() {
        bail!("No network interfaces found");
    }
    if interfaces.len() == 1 {
        return Ok(interfaces[0].clone());
    }

    let items: Vec<String> = interfaces
        .iter()
        .map(|i| format!("{} — {}/{}", i.name, i.ip, i.netmask))
        .collect();

    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select network interface")
        .items(&items)
        .default(0)
        .interact()?;

    Ok(interfaces[idx].clone())
}

/// Calculate the broadcast address for an interface.
pub fn calculate_broadcast(ip: &str, netmask: &str) -> String {
    let ip_parts: Vec<u8> = ip
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    let mask_parts: Vec<u8> = netmask
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    if ip_parts.len() != 4 || mask_parts.len() != 4 {
        return "255.255.255.255".to_string();
    }

    let bc: Vec<String> = ip_parts
        .iter()
        .zip(mask_parts.iter())
        .map(|(&i, &m)| (i | !m).to_string())
        .collect();

    bc.join(".")
}

/// Create a UDP socket configured for broadcasting.
pub fn create_broadcast_socket(
    bind_ip: &str,
    bind_port: u16,
    timeout_secs: u64,
) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;

    let bind_addr: SocketAddr = format!("{bind_ip}:{bind_port}").parse()?;
    sock.bind(&bind_addr.into())?;

    Ok(UdpSocket::from(sock))
}

/// Create a broadcast UDP socket bound to the unspecified address.
pub fn create_udp_broadcast_socket(bind_ip: &str, timeout_secs: u64) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;

    let bind_addr: SocketAddr = SocketAddr::new(bind_ip.parse::<Ipv4Addr>()?.into(), 0);
    sock.bind(&bind_addr.into())?;

    Ok(UdpSocket::from(sock))
}

/// Collect all UDP responses until timeout, returning (data, from_ip) pairs.
pub fn collect_responses(sock: &UdpSocket) -> Vec<(Vec<u8>, String)> {
    let mut results = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                results.push((buf[..n].to_vec(), addr.ip().to_string()));
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
    results
}

/// Detect the local IP used to route to a given destination.
pub fn local_ip_for(destination: &str) -> String {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return "0.0.0.0".to_string(),
    };
    if sock.connect(format!("{destination}:80")).is_ok() {
        sock.local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "0.0.0.0".to_string())
    } else {
        "0.0.0.0".to_string()
    }
}
