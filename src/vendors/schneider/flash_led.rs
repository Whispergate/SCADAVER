//! Schneider Electric Modicon identification LED flash via proprietary UDP discovery.
//!
//! Port 27127 is used by Unity Pro / `EcoStruxure` Control Expert for device identification
//! on the local LAN. The packet format (`\0TKITAK\0...`) is the Schneider BootP/DHCP
//! identification magic used by the programming software to locate PLCs. Sending this
//! packet causes the targeted Modicon device to flash its identification LED.
//!
//! Affected: Modicon M340, M580, Quantum, Premium. Not documented in a public CVE.

use anyhow::Result;
use std::net::UdpSocket;
use std::time::Duration;

// Schneider Electric Unity Pro / EcoStruxure Control Expert device identification port.
const FLASH_PORT: u16 = 27127;

/// Flash LED to a specific IP.
pub fn flash_led_ip(target_ip: &str) -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    let local_ip = crate::core::network::local_ip_for(target_ip);

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
