use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MODBUS_PORT: u16 = 502;
const UNIT_IDS: &[u8] = &[0x01, 0xFF];
const TRANSACTION_ID: u16 = 0x0001;
const MAX_REGISTERS: u16 = 125;
const MAX_BITS: u16 = 2000;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterType {
    Coil,
    DiscreteInput,
    HoldingRegister,
    InputRegister,
}

#[derive(Debug, Clone)]
pub struct ModbusRegister {
    /// 0-based protocol address.
    pub address: u16,
    /// User-facing address (Modbus data-model offset applied).
    pub display_addr: u32,
    pub register_type: RegisterType,
    /// 0/1 for bits, register value for words.
    pub raw: u16,
    /// "ON"/"OFF" for bits, "12345 (0x3039)" for words.
    pub value_str: String,
}

/// Run a single Modbus TCP request/response over a fresh connection.
///
/// Wraps `pdu` in an MBAP header, sends it, and returns the response PDU bytes
/// that follow the function code (byte count + payload). Errors on Modbus
/// exception responses (function code with bit 7 set).
///
/// `port`: override the default 502; pass `0` to use `MODBUS_PORT`.
fn transact(ip: &str, port: u16, pdu: &[u8], expected_fc: u8) -> Result<Vec<u8>> {
    let mut last_err = None;
    for &unit_id in UNIT_IDS {
        match transact_unit(ip, port, unit_id, pdu, expected_fc) {
            Ok(data) => return Ok(data),
            Err(e) if retry_with_next_unit_id(&e) => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no Modbus unit IDs configured")))
}

fn retry_with_next_unit_id(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("reading MBAP header")
        || msg.contains("reading Modbus PDU")
        || msg.contains("empty Modbus PDU")
        || msg.contains("unexpected Modbus unit id")
}

fn transact_unit(ip: &str, port: u16, unit_id: u8, pdu: &[u8], expected_fc: u8) -> Result<Vec<u8>> {
    let effective_port = if port == 0 { MODBUS_PORT } else { port };
    let addr = (ip, effective_port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {ip}:{effective_port}"))?
        .next()
        .with_context(|| format!("no address for {ip}"))?;

    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)
        .with_context(|| format!("connecting to {ip}:{effective_port}"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;

    let length = u16::try_from(pdu.len() + 1).context("PDU too large for MBAP length")?;
    let mut request = Vec::with_capacity(7 + pdu.len());
    request.extend_from_slice(&TRANSACTION_ID.to_be_bytes());
    request.extend_from_slice(&0x0000u16.to_be_bytes()); // protocol id
    request.extend_from_slice(&length.to_be_bytes());
    request.push(unit_id);
    request.extend_from_slice(pdu);
    stream.write_all(&request)?;

    let mut header = [0u8; 7];
    stream.read_exact(&mut header).context("reading MBAP header")?;
    let resp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if resp_len < 2 {
        bail!("Modbus response length field too short: {resp_len}");
    }
    if header[6] != unit_id {
        bail!(
            "unexpected Modbus unit id {:#04x}, wanted {unit_id:#04x}",
            header[6]
        );
    }

    // resp_len covers the unit id plus the PDU; skip the unit id.
    let mut body = vec![0u8; resp_len - 1];
    stream.read_exact(&mut body).context("reading Modbus PDU")?;

    let fc = *body.first().context("empty Modbus PDU")?;
    if fc == expected_fc | 0x80 {
        let exception = body.get(1).copied().unwrap_or(0);
        bail!(
            "Modbus exception for function {expected_fc:#04x}: {} ({exception:#04x})",
            exception_name(exception)
        );
    }
    if fc != expected_fc {
        bail!("unexpected Modbus function code {fc:#04x}, wanted {expected_fc:#04x}");
    }

    Ok(body[1..].to_vec())
}

fn exception_name(code: u8) -> &'static str {
    match code {
        0x01 => "illegal function",
        0x02 => "illegal data address",
        0x03 => "illegal data value",
        0x04 => "slave device failure",
        0x05 => "acknowledge",
        0x06 => "slave device busy",
        0x08 => "memory parity error",
        0x0A => "gateway path unavailable",
        0x0B => "gateway target failed to respond",
        _ => "unknown exception",
    }
}

fn read_request_pdu(fc: u8, start: u16, count: u16) -> [u8; 5] {
    [
        fc,
        (start >> 8) as u8,
        start as u8,
        (count >> 8) as u8,
        count as u8,
    ]
}

/// Shared body for FC3 (holding) and FC4 (input) register reads.
fn read_words(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
    fc: u8,
    offset: u32,
    register_type: RegisterType,
) -> Result<Vec<ModbusRegister>> {
    let count = count.clamp(1, MAX_REGISTERS);
    let data = transact(ip, port, &read_request_pdu(fc, start, count), fc)?;

    let byte_count = usize::from(*data.first().context("register response missing byte count")?);
    let words = data
        .get(1..1 + byte_count)
        .context("register response truncated")?;

    let mut registers = Vec::with_capacity(byte_count / 2);
    for (i, word) in words.chunks_exact(2).enumerate() {
        let raw = u16::from_be_bytes([word[0], word[1]]);
        let address = start.wrapping_add(i as u16);
        registers.push(ModbusRegister {
            address,
            display_addr: u32::from(address) + offset,
            register_type,
            raw,
            value_str: format!("{raw} ({raw:#06x})"),
        });
    }
    Ok(registers)
}

/// Shared body for FC1 (coils) and FC2 (discrete inputs).
fn read_bits(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
    fc: u8,
    offset: u32,
    register_type: RegisterType,
) -> Result<Vec<ModbusRegister>> {
    let count = count.clamp(1, MAX_BITS);
    let data = transact(ip, port, &read_request_pdu(fc, start, count), fc)?;

    let byte_count = usize::from(*data.first().context("bit response missing byte count")?);
    let bytes = data
        .get(1..1 + byte_count)
        .context("bit response truncated")?;

    let mut registers = Vec::with_capacity(usize::from(count));
    for i in 0..usize::from(count) {
        let byte = *bytes
            .get(i / 8)
            .context("bit response shorter than requested count")?;
        let bit = (byte >> (i % 8)) & 1;
        let address = start.wrapping_add(i as u16);
        registers.push(ModbusRegister {
            address,
            display_addr: u32::from(address) + offset,
            register_type,
            raw: u16::from(bit),
            value_str: if bit == 1 { "ON" } else { "OFF" }.to_string(),
        });
    }
    Ok(registers)
}

/// FC3 (0x03): read holding registers. Display addresses start at 40001.
/// Pass `port = 0` to use the default Modbus port (502).
pub fn read_holding_registers(ip: &str, port: u16, start: u16, count: u16) -> Result<Vec<ModbusRegister>> {
    read_words(ip, port, start, count, 0x03, 40001, RegisterType::HoldingRegister)
}

/// FC4 (0x04): read input registers. Display addresses start at 30001.
pub fn read_input_registers(ip: &str, port: u16, start: u16, count: u16) -> Result<Vec<ModbusRegister>> {
    read_words(ip, port, start, count, 0x04, 30001, RegisterType::InputRegister)
}

/// FC1 (0x01): read coils. Display addresses start at 1.
pub fn read_coils(ip: &str, port: u16, start: u16, count: u16) -> Result<Vec<ModbusRegister>> {
    read_bits(ip, port, start, count, 0x01, 1, RegisterType::Coil)
}

/// FC2 (0x02): read discrete inputs. Display addresses start at 10001.
pub fn read_discrete_inputs(ip: &str, port: u16, start: u16, count: u16) -> Result<Vec<ModbusRegister>> {
    read_bits(ip, port, start, count, 0x02, 10001, RegisterType::DiscreteInput)
}

/// FC5 (0x05): write single coil. `on=true` drives ON (0xFF00), false drives OFF (0x0000).
pub fn write_single_coil(ip: &str, port: u16, address: u16, on: bool) -> Result<()> {
    let value: u16 = if on { 0xFF00 } else { 0x0000 };
    let pdu = [
        0x05,
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (value >> 8) as u8,
        (value & 0xFF) as u8,
    ];
    transact(ip, port, &pdu, 0x05)?;
    Ok(())
}

/// FC6 (0x06): write single holding register.
pub fn write_single_register(ip: &str, port: u16, address: u16, value: u16) -> Result<()> {
    let pdu = [
        0x06,
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (value >> 8) as u8,
        (value & 0xFF) as u8,
    ];
    transact(ip, port, &pdu, 0x06)?;
    Ok(())
}

/// FC15 (0x0F): write multiple coils, LSB-first bit packing. Returns quantity written.
pub fn write_multiple_coils(ip: &str, port: u16, start: u16, values: &[bool]) -> Result<u16> {
    if values.is_empty() {
        anyhow::bail!("write_multiple_coils: empty values slice");
    }
    let count = values.len().min(usize::from(MAX_BITS));
    let values = &values[..count];
    let count16 = count as u16;
    let byte_count = count.div_ceil(8);
    let mut packed = vec![0u8; byte_count];
    for (i, &on) in values.iter().enumerate() {
        if on {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    let mut pdu = vec![
        0x0F,
        (start >> 8) as u8,
        (start & 0xFF) as u8,
        (count16 >> 8) as u8,
        (count16 & 0xFF) as u8,
        byte_count as u8,
    ];
    pdu.extend_from_slice(&packed);
    let resp = transact(ip, port, &pdu, 0x0F)?;
    let written = resp.get(2..4).context("FC15 response truncated")?;
    Ok(u16::from_be_bytes([written[0], written[1]]))
}

/// FC16 (0x10): write multiple holding registers. Returns quantity written.
pub fn write_multiple_registers(ip: &str, port: u16, start: u16, values: &[u16]) -> Result<u16> {
    if values.is_empty() {
        anyhow::bail!("write_multiple_registers: empty values slice");
    }
    let count = values.len().min(usize::from(MAX_REGISTERS));
    let values = &values[..count];
    let count16 = count as u16;
    let byte_count = (count * 2) as u8;
    let mut pdu = vec![
        0x10,
        (start >> 8) as u8,
        (start & 0xFF) as u8,
        (count16 >> 8) as u8,
        (count16 & 0xFF) as u8,
        byte_count,
    ];
    for &v in values {
        pdu.push((v >> 8) as u8);
        pdu.push((v & 0xFF) as u8);
    }
    let resp = transact(ip, port, &pdu, 0x10)?;
    let written = resp.get(2..4).context("FC16 response truncated")?;
    Ok(u16::from_be_bytes([written[0], written[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn modbus_response(req: &[u8], unit_id: u8, value: u16) -> [u8; 11] {
        [
            req[0],
            req[1],
            0x00,
            0x00,
            0x00,
            0x05,
            unit_id,
            0x03,
            0x02,
            (value >> 8) as u8,
            value as u8,
        ]
    }

    #[test]
    fn read_holding_registers_uses_unit_id_one_first() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 12];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req[6], 0x01);
            stream.write_all(&modbus_response(&req, 0x01, 1234)).unwrap();
        });

        let regs = read_holding_registers("127.0.0.1", port, 0, 1).unwrap();
        handle.join().unwrap();
        assert_eq!(regs[0].raw, 1234);
    }

    #[test]
    fn read_holding_registers_falls_back_to_unit_id_ff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let mut first_req = [0u8; 12];
            first.read_exact(&mut first_req).unwrap();
            assert_eq!(first_req[6], 0x01);
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            let mut second_req = [0u8; 12];
            second.read_exact(&mut second_req).unwrap();
            assert_eq!(second_req[6], 0xFF);
            second
                .write_all(&modbus_response(&second_req, 0xFF, 4321))
                .unwrap();
        });

        let regs = read_holding_registers("127.0.0.1", port, 0, 1).unwrap();
        handle.join().unwrap();
        assert_eq!(regs[0].raw, 4321);
    }
}
