use anyhow::{bail, Result};
use std::net::UdpSocket;
use std::time::Duration;

use crate::core::network::NetworkInterface;

const CONTROL_PORT: u16 = 5560;

const INIT_PACKETS: &[&str] = &[
    "5a000001",
    "5a000001",
    "5a000022",
    "5a000001",
    "5a000011",
    "5a0000ff",
    "57010000001111070000ffff030000fe030000200 01c0a161400000000000000000000000000000000000000000001210100000000 01",
    "570100000011110700 00ffff030000fe030000230 01c0a161400000000000000000000000000000000000000000001a0020000000854067dc9",
];

const CMD_STOP: &str = "57010000001111070000ffff030000fe030000200 01c0a161400000000000000000000000000000000000000000010020900000001 00";
const CMD_PAUSE: &str = "5701000000111107 0000ffff030000fe030000200 01c0a161400000000000000000000000000000000000000000010030900000001 00";
const CMD_RUN: &str = "57010000001111070000ffff030000fe030000220 01c0a161400000000000000000000000000000000000000000100101090000000100 0000";

/// Send a RUN, STOP, or PAUSE command to a Mitsubishi PLC.
pub fn set_state(interface: &NetworkInterface, action: &str) -> Result<bool> {
    let cmd = match action.to_lowercase().as_str() {
        "stop" => CMD_STOP,
        "pause" => CMD_PAUSE,
        "run" => CMD_RUN,
        _ => bail!("Invalid action '{action}'. Use: run, stop, pause"),
    };

    println!("Initializing connection...");
    init_connection(interface)?;

    println!("Sending {} command...", action.to_uppercase());
    let sock = create_socket(interface)?;

    let pkt = hex_decode(cmd);
    sock.send_to(&pkt, format!("255.255.255.255:{CONTROL_PORT}"))?;

    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            let hex = hex_encode(&buf[..n]);
            if hex.len() >= 8 && &hex[hex.len() - 8..] == "09000000" {
                println!("Command acknowledged by PLC.");
                Ok(true)
            } else {
                println!("Unexpected response from PLC.");
                Ok(false)
            }
        }
        Err(_) => {
            println!("No response from PLC.");
            Ok(false)
        }
    }
}

fn init_connection(interface: &NetworkInterface) -> Result<()> {
    let sock = create_socket(interface)?;
    for pkt_hex in INIT_PACKETS {
        let pkt = hex_decode(pkt_hex);
        let _ = sock.send_to(&pkt, format!("255.255.255.255:{CONTROL_PORT}"));
        let mut buf = [0u8; 1024];
        let _ = sock.recv_from(&mut buf);
    }
    Ok(())
}

fn create_socket(interface: &NetworkInterface) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.set_read_timeout(Some(Duration::from_secs(4)))?;
    let bind: std::net::SocketAddr = format!("{}:0", interface.ip).parse()?;
    s.bind(&bind.into())?;
    Ok(UdpSocket::from(s))
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
