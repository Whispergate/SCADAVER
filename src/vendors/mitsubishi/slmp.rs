use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Default SLMP TCP port.
pub const DEFAULT_PORT: u16 = 5007;
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WORD_COUNT: u16 = 960;
const MAX_BIT_COUNT: u16 = 3584;

const CMD_BATCH_READ: u16 = 0x0401;
const CMD_BATCH_WRITE: u16 = 0x1401;
const SUBCMD_WORD: u16 = 0x0000;
const SUBCMD_BIT: u16 = 0x0001;

/// A single SLMP device value: its display address, raw word, and formatted string.
pub struct SlmpValue {
    pub display: String,
    pub raw: u16,
    pub value_str: String,
}

/// Read word devices (D, W, R) via SLMP 3E batch read.
/// Pass `port = 0` to use the default SLMP port (5007).
pub fn read_word_devices(
    ip: &str,
    port: u16,
    device: &str,
    start: u32,
    count: u16,
) -> Result<Vec<SlmpValue>> {
    let code =
        device_code(device).ok_or_else(|| anyhow::anyhow!("unknown SLMP device \"{device}\""))?;
    let count = count.min(MAX_WORD_COUNT);
    let data = request(ip, port, SUBCMD_WORD, code, start, count)?;

    let expected = count as usize * 2;
    if data.len() < expected {
        anyhow::bail!(
            "short SLMP response: expected {expected} bytes, got {}",
            data.len()
        );
    }

    let mut values = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let raw = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        let address = start + u32::try_from(i).unwrap_or(u32::MAX);
        values.push(SlmpValue {
            display: format!("{device}{address}"),
            raw,
            value_str: raw.to_string(),
        });
    }
    Ok(values)
}

/// Read bit devices (M, X, Y, B) via SLMP 3E batch read.
/// Pass `port = 0` to use the default SLMP port (5007).
pub fn read_bit_devices(
    ip: &str,
    port: u16,
    device: &str,
    start: u32,
    count: u16,
) -> Result<Vec<SlmpValue>> {
    let code =
        device_code(device).ok_or_else(|| anyhow::anyhow!("unknown SLMP device \"{device}\""))?;
    let count = count.min(MAX_BIT_COUNT);
    let data = request(ip, port, SUBCMD_BIT, code, start, count)?;

    let expected = (count as usize).div_ceil(2);
    if data.len() < expected {
        anyhow::bail!(
            "short SLMP response: expected {expected} bytes, got {}",
            data.len()
        );
    }

    let mut values = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let byte = data[i / 2];
        let nibble = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
        let on = nibble != 0;
        let address = start + u32::try_from(i).unwrap_or(u32::MAX);
        values.push(SlmpValue {
            display: format!("{device}{address}"),
            raw: u16::from(on),
            value_str: if on {
                "ON".to_string()
            } else {
                "OFF".to_string()
            },
        });
    }
    Ok(values)
}

/// Batch write word devices (D, W, R) via SLMP 3E.
/// Pass `port = 0` to use the default SLMP port (5007).
pub fn write_word_devices(
    ip: &str,
    port: u16,
    device: &str,
    start: u32,
    values: &[u16],
) -> Result<()> {
    let code =
        device_code(device).ok_or_else(|| anyhow::anyhow!("unknown SLMP device \"{device}\""))?;
    if values.is_empty() {
        anyhow::bail!("write_word_devices: empty values slice");
    }
    let count = u16::try_from(values.len().min(usize::from(MAX_WORD_COUNT)))
        .context("word count overflow")?;
    let values = &values[..count as usize];
    let mut payload = Vec::with_capacity(count as usize * 2);
    for &v in values {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    write_request(ip, port, SUBCMD_WORD, code, start, count, &payload)
}

/// Batch write bit devices (M, X, Y, B) via SLMP 3E.
/// Each bool is encoded as a nibble (0x0=OFF, 0x1=ON), two per byte.
/// Pass `port = 0` to use the default SLMP port (5007).
pub fn write_bit_devices(
    ip: &str,
    port: u16,
    device: &str,
    start: u32,
    values: &[bool],
) -> Result<()> {
    let code =
        device_code(device).ok_or_else(|| anyhow::anyhow!("unknown SLMP device \"{device}\""))?;
    if values.is_empty() {
        anyhow::bail!("write_bit_devices: empty values slice");
    }
    let count = u16::try_from(values.len().min(usize::from(MAX_BIT_COUNT)))
        .context("bit count overflow")?;
    let values = &values[..count as usize];
    let packed_len = (count as usize).div_ceil(2);
    let mut payload = vec![0u8; packed_len];
    for (i, &on) in values.iter().enumerate() {
        let nibble: u8 = u8::from(on);
        if i % 2 == 0 {
            payload[i / 2] |= nibble;
        } else {
            payload[i / 2] |= nibble << 4;
        }
    }
    write_request(ip, port, SUBCMD_BIT, code, start, count, &payload)
}

fn write_request(
    ip: &str,
    port: u16,
    subcmd: u16,
    device_code: u8,
    start: u32,
    count: u16,
    payload: &[u8],
) -> Result<()> {
    // inner data: timer(2) + cmd(2) + subcmd(2) + device(1) + start(3) + count(2) + payload
    let inner_len =
        12u16 + u16::try_from(payload.len()).context("write payload too large for SLMP frame")?;
    let mut req = Vec::with_capacity(9 + inner_len as usize);
    req.extend_from_slice(&[0x50, 0x00]);
    req.extend_from_slice(&[0xFF, 0xFF]);
    req.extend_from_slice(&[0xFF, 0x03]);
    req.push(0x00);
    req.extend_from_slice(&inner_len.to_le_bytes());
    req.extend_from_slice(&0x0004u16.to_le_bytes());
    req.extend_from_slice(&CMD_BATCH_WRITE.to_le_bytes());
    req.extend_from_slice(&subcmd.to_le_bytes());
    req.push(device_code);
    req.extend_from_slice(&start.to_le_bytes()[..3]);
    req.extend_from_slice(&count.to_le_bytes());
    req.extend_from_slice(payload);

    let mut stream = connect(ip, port)?;
    stream.write_all(&req)?;

    let mut header = [0u8; 9];
    stream.read_exact(&mut header)?;
    if header[0] != 0xD0 {
        anyhow::bail!("unexpected SLMP response subheader 0x{:02x}", header[0]);
    }
    let data_len = u16::from_le_bytes([header[7], header[8]]) as usize;
    if data_len < 2 {
        anyhow::bail!("SLMP write response too short");
    }
    let mut rest = vec![0u8; data_len];
    stream.read_exact(&mut rest)?;
    let end_code = u16::from_le_bytes([rest[0], rest[1]]);
    if end_code != 0x0000 {
        anyhow::bail!("SLMP write error 0x{end_code:04x}");
    }
    Ok(())
}

fn device_code(device: &str) -> Option<u8> {
    match device {
        "M" => Some(0x90),
        "X" => Some(0x9C),
        "Y" => Some(0x9D),
        "B" => Some(0xA0),
        "D" => Some(0xA8),
        "W" => Some(0xB4),
        "R" => Some(0xAF),
        _ => None,
    }
}

fn request(
    ip: &str,
    port: u16,
    subcmd: u16,
    device_code: u8,
    start: u32,
    count: u16,
) -> Result<Vec<u8>> {
    let req = build_frame(subcmd, device_code, start, count);
    let mut stream = connect(ip, port)?;
    stream.write_all(&req)?;
    read_response(&mut stream)
}

fn connect(ip: &str, port: u16) -> Result<TcpStream> {
    let effective_port = if port == 0 { DEFAULT_PORT } else { port };
    let addr = format!("{ip}:{effective_port}");
    let sock_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {addr}"))?;
    let stream = TcpStream::connect_timeout(&sock_addr, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

fn build_frame(subcmd: u16, device_code: u8, start: u32, count: u16) -> Vec<u8> {
    let mut req = Vec::with_capacity(21);
    req.extend_from_slice(&[0x50, 0x00]); // subheader (3E frame)
    req.extend_from_slice(&[0xFF, 0xFF]); // network/PC no.
    req.extend_from_slice(&[0xFF, 0x03]); // request destination I/O no.
    req.push(0x00); // request destination multidrop station no.
    req.extend_from_slice(&0x000Cu16.to_le_bytes()); // data length (timer..end)
    req.extend_from_slice(&0x0004u16.to_le_bytes()); // monitoring timer (1s)
    req.extend_from_slice(&CMD_BATCH_READ.to_le_bytes());
    req.extend_from_slice(&subcmd.to_le_bytes());
    req.push(device_code);
    req.extend_from_slice(&start.to_le_bytes()[..3]); // 24-bit start device number
    req.extend_from_slice(&count.to_le_bytes());
    req
}

fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 9];
    stream.read_exact(&mut header)?;
    if header[0] != 0xD0 {
        anyhow::bail!("unexpected SLMP response subheader 0x{:02x}", header[0]);
    }

    let data_len = u16::from_le_bytes([header[7], header[8]]) as usize;
    if data_len < 2 {
        anyhow::bail!("SLMP response missing end code");
    }

    let mut rest = vec![0u8; data_len];
    stream.read_exact(&mut rest)?;

    let end_code = u16::from_le_bytes([rest[0], rest[1]]);
    if end_code != 0x0000 {
        anyhow::bail!("SLMP error 0x{end_code:04x}");
    }
    Ok(rest[2..].to_vec())
}
