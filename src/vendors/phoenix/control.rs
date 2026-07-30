use anyhow::Result;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const INFO_PORT: u16 = 1962;
const CONTROL_PORT_ILC150: u16 = 41100;
const CONTROL_PORT_ILC390: u16 = 20547;
const DEFAULT_TIMEOUT: u64 = 5;

const INIT_MONITOR_PACKETS: &[&str] = &[
    "0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200",
    "0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500",
    "0100000000002500000000000000d9ff4164652e52656d6f74696e672e53657276696365732e49466f726365536572766963653200",
    "010000000000240000000000000000004164652e52656d6f74696e672e53657276696365732e49466f7263655365727669636500",
    "0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300",
    "010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653300",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653200",
    "0100000000002900000000000000d5ff4164652e52656d6f74696e672e53657276696365732e49427265616b706f696e745365727669636500",
    "0100000000002800000000000000d6ff4164652e52656d6f74696e672e53657276696365732e4943616c6c737461636b5365727669636500",
    "010000000000250000000000000000004164652e52656d6f74696e672e53657276696365732e494465627567536572766963653200",
    "0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200",
    "0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500",
    "0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300",
    "010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200",
    "0100020000000e0003000300000000000500000012401340130011401200",
];

const INIT_MONITOR2_PACKETS: &[&str] = &[
    "cc01000dc0010000d517",
    "cc01000b4002000047ee",
    "cc01005b40031c00010000001c0000000100000002000000000000000000000000000000d79a",
    "cc01005b40041c00010000001c0000000100000004000000800000000000000000000000ea43",
    "cc01000640050000361e",
    "cc0100074006100026750000000000000000000000000000c682",
];

const QUERY_PACKET: &str = "010002000000080003000300000000000200000002400b40";
const KEEPALIVE_PACKET: &str = "0100020000001c0003000300000000000c000000070005000600080010000200110 00e000f000d0016401600";

const STOP_CMD: &str = "01000200000000000100070000000000";
const COLD_START_CMD: &str = "010002000000020001000600000000000100";
const WARM_START_CMD: &str = "010002000000020001000600000000000200";
const HOT_START_CMD: &str = "010002000000020001000600000000000300";

const ILC390_STATE_PACKETS: &[&str] = &[
    "cc01000f40070000eafa",
    "cc01000f400800002db0",
    "cc01000f40090000f1ea",
    "cc01000f400a00009505",
    "cc01000f400b0000495f",
    "cc01000f400c00004cd3",
    "cc01000f400d00009089",
];

/// Identity of a Phoenix Contact PLC read over the `ProConOS` info protocol (type, firmware, build).
#[derive(Debug, Clone)]
pub struct PhoenixDeviceInfo {
    pub plc_type: String,
    pub firmware: Option<String>,
    pub build: Option<String>,
}

fn send_recv(stream: &mut TcpStream, hex_data: &str) -> Option<Vec<u8>> {
    let pkt = hex_decode(hex_data);
    stream.write_all(&pkt).ok()?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Retrieve PLC type, firmware version. Pass `port = 0` to use the default (1962).
pub fn get_device_info(target_ip: &str, port: u16, silent: bool) -> Result<PhoenixDeviceInfo> {
    let effective_port = if port == 0 { INFO_PORT } else { port };
    let mut stream = TcpStream::connect_timeout(
        &format!("{target_ip}:{effective_port}").parse()?,
        Duration::from_secs(DEFAULT_TIMEOUT),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT)))?;

    let Some(resp) = send_recv(
        &mut stream,
        "0101001a005e000000000003000c494245544830314e305f4d00",
    ) else { anyhow::bail!("No response from Phoenix device") };

    if resp.len() < 18 {
        anyhow::bail!("Short response from Phoenix device");
    }

    let code = hex_encode(&resp[17..18]);

    let _ = send_recv(
        &mut stream,
        &format!("01050016005f000008ef00{code}00000022000402950000"),
    );
    let Some(ret) = send_recv(
        &mut stream,
        &format!("0106000e00610000881100{code}0400"),
    ) else { anyhow::bail!("No info response") };

    let plc_type = if ret.len() >= 50 {
        String::from_utf8_lossy(&ret[30..50])
            .trim_matches('\0')
            .trim()
            .to_string()
    } else {
        String::new()
    };

    let firmware = if ret.len() >= 70 {
        Some(
            String::from_utf8_lossy(&ret[66..70])
                .trim_matches('\0')
                .trim()
                .to_string(),
        )
    } else {
        None
    };

    let build = if ret.len() >= 100 {
        Some(
            String::from_utf8_lossy(&ret[79..100])
                .trim_matches('\0')
                .trim()
                .to_string(),
        )
    } else {
        None
    };

    // Complete handshake
    let _ = send_recv(
        &mut stream,
        &format!("0105002e006300000000 00{code}00000023001c02b0000c0000055b4433325d0b466c617368436865636b3101310000"),
    );
    let _ = send_recv(&mut stream, &format!("0106000e0065ffffff0f00{code}0400"));
    let _ = send_recv(
        &mut stream,
        &format!("010500160067000008ef00{code}00000024000402950000"),
    );
    let _ = send_recv(&mut stream, &format!("0106000e0069ffffff0f00{code}0400"));
    let _ = send_recv(&mut stream, &format!("0102000c006bffffff0f00{code}"));

    let _ = stream.shutdown(std::net::Shutdown::Both);

    if !silent {
        println!("PLC Type: {plc_type}");
        if let Some(fw) = &firmware {
            println!("Firmware: {fw}");
        }
        if let Some(b) = &build {
            println!("Build:    {b}");
        }
    }

    Ok(PhoenixDeviceInfo {
        plc_type,
        firmware,
        build,
    })
}

/// Control ILC 150 PLC (start/stop). Pass `port = 0` to use the default (41100).
pub fn control_ilc150(target_ip: &str, port: u16, action: &str, start_type: &str) -> Result<String> {
    let effective_port = if port == 0 { CONTROL_PORT_ILC150 } else { port };
    let mut stream = TcpStream::connect_timeout(
        &format!("{target_ip}:{effective_port}").parse()?,
        Duration::from_secs(DEFAULT_TIMEOUT),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT)))?;

    for pkt in INIT_MONITOR_PACKETS {
        let _ = send_recv(&mut stream, pkt);
    }

    if action == "stop" {
        println!("Sending STOP command...");
        let _ = send_recv(&mut stream, STOP_CMD);
    } else {
        let cmd = match start_type {
            "warm" => WARM_START_CMD,
            "hot" => HOT_START_CMD,
            _ => COLD_START_CMD,
        };
        println!("Sending {} START command...", start_type.to_uppercase());
        let _ = send_recv(&mut stream, cmd);
    }

    let _ = send_recv(&mut stream, KEEPALIVE_PACKET);
    let _ = send_recv(&mut stream, KEEPALIVE_PACKET);
    std::thread::sleep(Duration::from_millis(500));

    let Some(ret) = send_recv(&mut stream, QUERY_PACKET) else { return Ok("Unknown".to_string()) };

    let hex = hex_encode(&ret);
    let state = if hex.len() > 50 {
        match &hex[48..50] {
            "03" => "Running",
            "07" => "Stop",
            "00" => "On",
            other => return Ok(format!("Unknown ({other})")),
        }
    } else {
        "Unknown"
    };

    println!("PLC state: {state}");
    Ok(state.to_string())
}

/// Control ILC 390 PLC (start/stop). Pass `port = 0` to use the default (20547).
pub fn control_ilc390(target_ip: &str, port: u16, action: &str) -> Result<String> {
    let effective_port = if port == 0 { CONTROL_PORT_ILC390 } else { port };
    let mut stream = TcpStream::connect_timeout(
        &format!("{target_ip}:{effective_port}").parse()?,
        Duration::from_secs(DEFAULT_TIMEOUT),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT)))?;

    for pkt in INIT_MONITOR2_PACKETS {
        let _ = send_recv(&mut stream, pkt);
    }

    for pkt in &ILC390_STATE_PACKETS[..7] {
        let _ = send_recv(&mut stream, pkt);
    }

    if action == "stop" {
        println!("Sending STOP via ILC390 protocol...");
        let _ = send_recv(&mut stream, "cc010001400e00004c07");
    } else {
        println!("Sending START via ILC390 protocol...");
        let _ = send_recv(&mut stream, "cc010004400e0000182 1");
    }

    let _ = stream.shutdown(std::net::Shutdown::Both);

    let new_state = if action == "stop" { "Stopped" } else { "Running" };
    println!("PLC state: {new_state}");
    Ok(new_state.to_string())
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
}
