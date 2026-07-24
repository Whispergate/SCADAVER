/// Omron FINS (Factory Interface Network Service) protocol implementation.
///
/// Supports TCP (port 9600, 2-stage: address negotiation + command) and
/// UDP (port 9600, direct command send).
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

pub const FINS_TCP_PORT: u16 = 9600;
pub const FINS_UDP_PORT: u16 = 9600;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Memory area codes used in FINS Memory Area Read/Write commands.
pub const AREA_DM_WORD: u8 = 0x82;
pub const AREA_CIO_WORD: u8 = 0xB0;

/// Information retrieved from an Omron PLC via FINS.
#[derive(Debug, Clone)]
pub struct FinsDevice {
    pub ip: String,
    pub node_addr: u8,
    pub model: String,
    pub version: String,
}

impl FinsDevice {
    pub fn cpu_state_str(state: u8) -> &'static str {
        match state {
            0x00 => "Stop",
            0x01 => "Run",
            0x02 => "Monitor",
            0x04 => "Program",
            _ => "Unknown",
        }
    }
}

// ─── TCP helpers ────────────────────────────────────────────────────────────

fn tcp_connect(ip: &str) -> Result<TcpStream> {
    let addr = format!("{ip}:{FINS_TCP_PORT}");
    let stream = TcpStream::connect_timeout(&addr.parse()?, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

/// Stage 1: FINS/TCP address negotiation.
/// Sends the 20-byte FINS/TCP "hello" and returns the server node address.
fn negotiate_address(stream: &mut TcpStream) -> Result<u8> {
    // FINS/TCP header: "FINS" + length(4) + command(4) + error_code(4) + client_node(4)
    #[rustfmt::skip]
    let hello: [u8; 20] = [
        0x46, 0x49, 0x4E, 0x53,  // "FINS"
        0x00, 0x00, 0x00, 0x0C,  // length = 12
        0x00, 0x00, 0x00, 0x00,  // command = 0 (node address request)
        0x00, 0x00, 0x00, 0x00,  // error code = 0
        0x00, 0x00, 0x00, 0x00,  // client node = 0 (auto-assign)
    ];
    stream.write_all(&hello)?;
    let mut resp = [0u8; 24];
    stream.read_exact(&mut resp).context("FINS/TCP address negotiation: short response")?;
    // Server node address is at byte 19 (last byte of the 20-byte response body)
    // Actually the server returns a 24-byte frame; the assigned server node is at byte 23.
    Ok(resp[23])
}

fn fins_header(da1: u8, sid: u8) -> [u8; 10] {
    [
        0x80, // ICF: command, not split, response required
        0x00, // RSV
        0x02, // GCT (gateway count)
        0x00, // DNA (destination network)
        da1,  // DA1 (destination node = server)
        0x00, // DA2 (destination unit)
        0x00, // SNA (source network)
        0x63, // SA1 (source node = 0x63 = 99, arbitrary client node)
        0x00, // SA2 (source unit)
        sid,  // SID (service ID, used to match requests)
    ]
}

fn send_fins_tcp(stream: &mut TcpStream, server_node: u8, cmd: &[u8]) -> Result<Vec<u8>> {
    let header = fins_header(server_node, 0x01);
    let body_len = (header.len() + cmd.len()) as u32;
    // FINS/TCP wrapper: "FINS" + length(4) + command(2=execute) + error(4)
    let mut frame = Vec::with_capacity(16 + header.len() + cmd.len());
    frame.extend_from_slice(b"FINS");
    frame.extend_from_slice(&(body_len + 8).to_be_bytes()); // length field = content after "FINS"+len
    frame.extend_from_slice(&0x00000002u32.to_be_bytes()); // command: 2 = send FINS command
    frame.extend_from_slice(&0x00000000u32.to_be_bytes()); // error code
    frame.extend_from_slice(&header);
    frame.extend_from_slice(cmd);

    stream.write_all(&frame)?;

    let mut resp_header = [0u8; 16];
    stream.read_exact(&mut resp_header).context("FINS/TCP: short response header")?;
    let resp_len = u32::from_be_bytes([
        resp_header[4], resp_header[5], resp_header[6], resp_header[7],
    ]) as usize;
    if resp_len < 8 {
        anyhow::bail!("FINS/TCP: response length field too small");
    }
    let body_len = resp_len - 8; // subtract the "FINS", length, command, error fields
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).context("FINS/TCP: short response body")?;
    Ok(body)
}

// ─── UDP helper ─────────────────────────────────────────────────────────────

fn send_fins_udp(ip: &str, cmd: &[u8], server_node: u8) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(TIMEOUT))?;
    let header = fins_header(server_node, 0x01);
    let mut frame = Vec::with_capacity(header.len() + cmd.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(cmd);
    sock.send_to(&frame, format!("{ip}:{FINS_UDP_PORT}"))?;
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf)?;
    Ok(buf[..n].to_vec())
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Connect via TCP, negotiate address, and read controller model/version (command 05 01).
pub fn get_device_info_tcp(ip: &str) -> Result<FinsDevice> {
    let mut stream = tcp_connect(ip)?;
    let server_node = negotiate_address(&mut stream)?;
    // Controller Data Read: 05 01
    let resp = send_fins_tcp(&mut stream, server_node, &[0x05, 0x01])?;
    // Response body: FINS header (10) + response_code (2) + model (20) + version (20) + ...
    let model = if resp.len() >= 32 {
        String::from_utf8_lossy(&resp[12..32]).trim_end_matches('\0').trim().to_string()
    } else {
        "Unknown".to_string()
    };
    let version = if resp.len() >= 52 {
        String::from_utf8_lossy(&resp[32..52]).trim_end_matches('\0').trim().to_string()
    } else {
        "Unknown".to_string()
    };
    Ok(FinsDevice { ip: ip.to_string(), node_addr: server_node, model, version })
}

/// Probe via UDP for a FINS device. Returns None if no valid response.
pub fn scan_udp(ip: &str) -> Option<FinsDevice> {
    // Send Controller Data Read (05 01) directly via UDP
    let resp = send_fins_udp(ip, &[0x05, 0x01], 0x00).ok()?;
    // Check for valid FINS response: at least 12 bytes (header 10 + response_code 2)
    if resp.len() < 12 {
        return None;
    }
    // ICF byte should indicate a response (bit 6 set → 0xC0)
    if resp[0] & 0x40 == 0 {
        return None;
    }
    let server_node = resp[4]; // DA1 in the response is our original SA1
    let model = if resp.len() >= 32 {
        String::from_utf8_lossy(&resp[12..32]).trim_end_matches('\0').trim().to_string()
    } else {
        String::new()
    };
    let version = if resp.len() >= 52 {
        String::from_utf8_lossy(&resp[32..52]).trim_end_matches('\0').trim().to_string()
    } else {
        String::new()
    };
    Some(FinsDevice { ip: ip.to_string(), node_addr: server_node, model, version })
}

/// Read DM word area via TCP FINS (command 01 02, area 0x82).
pub fn read_dm_words(ip: &str, node: u8, start: u16, count: u16) -> Result<Vec<u16>> {
    let mut stream = tcp_connect(ip)?;
    let server_node = negotiate_address(&mut stream)?;
    let cmd = [
        0x01, 0x01, // Memory Area Read
        AREA_DM_WORD,
        (start >> 8) as u8,
        (start & 0xFF) as u8,
        0x00, // bit offset = 0
        (count >> 8) as u8,
        (count & 0xFF) as u8,
    ];
    let actual_node = if node == 0 { server_node } else { node };
    let resp = send_fins_tcp_node(&mut stream, actual_node, &cmd)?;
    // Response: header(10) + response_code(2) + data (count * 2 bytes)
    if resp.len() < 12 {
        anyhow::bail!("FINS read DM: response too short");
    }
    let end_code = u16::from_be_bytes([resp[10], resp[11]]);
    if end_code != 0x0000 {
        anyhow::bail!("FINS Memory Area Read error 0x{end_code:04x}");
    }
    let data = &resp[12..];
    let mut values = Vec::with_capacity(count as usize);
    for chunk in data.chunks_exact(2) {
        values.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(values)
}

/// Write DM word area via TCP FINS (command 01 02, area 0x82).
pub fn write_dm_words(ip: &str, node: u8, start: u16, values: &[u16]) -> Result<()> {
    let mut stream = tcp_connect(ip)?;
    let server_node = negotiate_address(&mut stream)?;
    let actual_node = if node == 0 { server_node } else { node };
    let count = values.len() as u16;
    let mut cmd = vec![
        0x01, 0x02, // Memory Area Write
        AREA_DM_WORD,
        (start >> 8) as u8,
        (start & 0xFF) as u8,
        0x00, // bit offset = 0
        (count >> 8) as u8,
        (count & 0xFF) as u8,
    ];
    for &v in values {
        cmd.push((v >> 8) as u8);
        cmd.push((v & 0xFF) as u8);
    }
    let resp = send_fins_tcp_node(&mut stream, actual_node, &cmd)?;
    if resp.len() < 12 {
        anyhow::bail!("FINS write DM: response too short");
    }
    let end_code = u16::from_be_bytes([resp[10], resp[11]]);
    if end_code != 0x0000 {
        anyhow::bail!("FINS Memory Area Write error 0x{end_code:04x}");
    }
    Ok(())
}

/// Read CPU operating status via FINS (command 06 01).
pub fn get_cpu_state(ip: &str, node: u8) -> Result<String> {
    let mut stream = tcp_connect(ip)?;
    let server_node = negotiate_address(&mut stream)?;
    let actual_node = if node == 0 { server_node } else { node };
    let resp = send_fins_tcp_node(&mut stream, actual_node, &[0x06, 0x01])?;
    if resp.len() < 13 {
        anyhow::bail!("FINS CPU status: response too short");
    }
    let end_code = u16::from_be_bytes([resp[10], resp[11]]);
    if end_code != 0x0000 {
        anyhow::bail!("FINS CPU Status Read error 0x{end_code:04x}");
    }
    // Byte 12 = operating mode: 0x00=Stop, 0x01=Program, 0x02=Monitor, 0x03=Run
    let mode = resp[12];
    Ok(FinsDevice::cpu_state_str(mode).to_string())
}

/// Change CPU operating mode via FINS (command 04 01).
/// `run=true` → Monitor mode (0x02), `run=false` → Stop mode (0x00).
pub fn set_cpu_mode(ip: &str, node: u8, run: bool) -> Result<bool> {
    let mut stream = tcp_connect(ip)?;
    let server_node = negotiate_address(&mut stream)?;
    let actual_node = if node == 0 { server_node } else { node };
    let mode_byte: u8 = if run { 0x02 } else { 0x00 };
    let cmd = [0x04, 0x01, mode_byte];
    let resp = send_fins_tcp_node(&mut stream, actual_node, &cmd)?;
    if resp.len() < 12 {
        anyhow::bail!("FINS CPU mode change: response too short");
    }
    let end_code = u16::from_be_bytes([resp[10], resp[11]]);
    Ok(end_code == 0x0000)
}

// ─── Internal helper (node override) ────────────────────────────────────────

fn send_fins_tcp_node(stream: &mut TcpStream, server_node: u8, cmd: &[u8]) -> Result<Vec<u8>> {
    let header = fins_header(server_node, 0x01);
    let body_len = (header.len() + cmd.len()) as u32;
    let mut frame = Vec::with_capacity(16 + header.len() + cmd.len());
    frame.extend_from_slice(b"FINS");
    frame.extend_from_slice(&(body_len + 8).to_be_bytes());
    frame.extend_from_slice(&0x00000002u32.to_be_bytes());
    frame.extend_from_slice(&0x00000000u32.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(cmd);

    stream.write_all(&frame)?;

    let mut resp_header = [0u8; 16];
    stream.read_exact(&mut resp_header).context("FINS/TCP: short response header")?;
    let resp_len = u32::from_be_bytes([
        resp_header[4], resp_header[5], resp_header[6], resp_header[7],
    ]) as usize;
    if resp_len < 8 {
        anyhow::bail!("FINS/TCP: response length field too small");
    }
    let body_len = resp_len - 8;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).context("FINS/TCP: short response body")?;
    Ok(body)
}
