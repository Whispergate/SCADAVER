use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;

const FLASH_PORT: u16 = 27127;

/// Flash the status LED on a Schneider M340 PLC.
pub fn flash_led(interface: &NetworkInterface) -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_broadcast(true)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let bind: std::net::SocketAddr = format!("{}:0", interface.ip).parse()?;
    s.bind(&bind.into())?;
    let sock = UdpSocket::from(s);

    // Flash LED command
    let pkt = hex_decode("0054004b4954414b0000000000000000");
    sock.send_to(&pkt, format!("255.255.255.255:{FLASH_PORT}"))?;
    println!("Flash LED broadcast sent.");
    Ok(())
}

/// Flash LED to a specific IP.
pub fn flash_led_ip(target_ip: &str) -> Result<()> {
    let local_ip = crate::core::network::local_ip_for(target_ip);
    use socket2::{Domain, Protocol, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let bind: std::net::SocketAddr = format!("{local_ip}:0").parse()?;
    s.bind(&bind.into())?;
    let sock = UdpSocket::from(s);

    let pkt = hex_decode("0054004b4954414b0000000000000000");
    sock.send_to(&pkt, format!("{target_ip}:{FLASH_PORT}"))?;
    println!("Flash LED command sent to {target_ip}.");
    Ok(())
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
