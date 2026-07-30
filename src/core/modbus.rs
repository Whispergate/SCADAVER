use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 502;
pub const DEFAULT_UNIT_IDS: &[u8] = &[0x01, 0xFF];

const TRANSACTION_ID: u16 = 0x0001;
const MAX_REGISTERS: u16 = 125;
const MAX_BITS: u16 = 2000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A single decoded Modbus register or bit, with both protocol and user-facing addresses.
#[derive(Debug, Clone)]
pub struct ModbusRegister {
    /// 0-based protocol address.
    pub address: u16,
    /// User-facing address (Modbus data-model offset applied).
    pub display_addr: u32,
    /// 0/1 for bits, register value for words.
    pub raw: u16,
    /// "ON"/"OFF" for bits, "12345 (0x3039)" for words.
    pub value_str: String,
}

/// A raw Modbus PDU response: the responding unit id and the bytes following the function code.
#[derive(Debug, Clone)]
pub struct ModbusReply {
    pub unit_id: u8,
    pub data: Vec<u8>,
}

/// Decoded Modbus "Read Device Identification" (FC 0x2B/MEI 0x0E) objects, keyed by object id.
#[derive(Debug, Clone)]
pub struct ModbusDeviceId {
    pub unit_id: u8,
    pub objects: BTreeMap<u8, String>,
}

impl ModbusDeviceId {
    /// Vendor name (object 0x00), if present.
    pub fn manufacturer(&self) -> Option<&str> {
        self.objects.get(&0x00).map(String::as_str)
    }

    /// Product code / model name (object 0x01), if present.
    pub fn product_name(&self) -> Option<&str> {
        self.objects.get(&0x01).map(String::as_str)
    }

    /// Firmware/major-minor revision (object 0x02), if present.
    pub fn version(&self) -> Option<&str> {
        self.objects.get(&0x02).map(String::as_str)
    }
}

/// A Modbus TCP client that transacts against a device, trying each configured unit id in turn.
#[derive(Debug, Clone)]
pub struct ModbusTcpClient {
    ip: String,
    port: u16,
    timeout: Duration,
    unit_ids: Vec<u8>,
}

impl ModbusTcpClient {
    /// Create a client for `ip` using the default port (502), 5s timeout, and unit ids [0x01, 0xFF].
    pub fn new(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            port: DEFAULT_PORT,
            timeout: DEFAULT_TIMEOUT,
            unit_ids: DEFAULT_UNIT_IDS.to_vec(),
        }
    }

    /// Override the TCP port; a port of 0 falls back to the default (502).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = effective_port(port);
        self
    }

    /// Override the connect/read/write timeout (clamped to at least 1 second).
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout = Duration::from_secs(timeout_secs.max(1));
        self
    }

    /// Send a PDU and return the reply, erroring if the device answers with a Modbus exception.
    pub fn transact(&self, pdu: &[u8], expected_fc: u8) -> Result<ModbusReply> {
        self.transact_inner(pdu, expected_fc, false)
    }

    /// Like [`Self::transact`] but returns a Modbus exception response as a successful reply
    /// (useful for reachability probes where any answer confirms the device is alive).
    pub fn transact_allow_exception(&self, pdu: &[u8], expected_fc: u8) -> Result<ModbusReply> {
        self.transact_inner(pdu, expected_fc, true)
    }

    /// Read and decode the device identification objects (vendor, product, version) over paged
    /// FC 0x2B/MEI 0x0E requests.
    pub fn read_device_id(&self) -> Result<ModbusDeviceId> {
        let mut objects = BTreeMap::new();
        let mut next_obj_id: u8 = 0;
        let mut unit_id: u8 = 0;

        for _ in 0..5u8 {
            let reply = self.transact(&[0x2B, 0x0E, 0x01, next_obj_id], 0x2B)?;
            unit_id = reply.unit_id;
            if reply.data.first().copied() != Some(0x0E) {
                bail!("Modbus Device ID response missing MEI type");
            }
            let obj_count = usize::from(
                *reply
                    .data
                    .get(5)
                    .context("Modbus Device ID response missing object count")?,
            );
            let mut pos = 6usize;
            for _ in 0..obj_count.min(32) {
                let obj_id = *reply
                    .data
                    .get(pos)
                    .context("Modbus Device ID object truncated")?;
                let obj_len = usize::from(
                    *reply
                        .data
                        .get(pos + 1)
                        .context("Modbus Device ID object length truncated")?,
                );
                let value = reply
                    .data
                    .get(pos + 2..pos + 2 + obj_len)
                    .context("Modbus Device ID object value truncated")?;
                objects.insert(
                    obj_id,
                    String::from_utf8_lossy(value).trim().to_string(),
                );
                pos += 2 + obj_len;
            }
            // data[3] = More Following (0xFF = more pages); data[4] = next object id
            if reply.data.get(3).copied() != Some(0xFF) {
                break;
            }
            next_obj_id = reply.data.get(4).copied().unwrap_or(0);
        }

        Ok(ModbusDeviceId { unit_id, objects })
    }

    /// Read a single holding register (FC 0x03), accepting an exception reply as proof of life.
    pub fn probe_holding_register(&self) -> Result<ModbusReply> {
        self.transact_allow_exception(&read_request_pdu(0x03, 0, 1), 0x03)
    }

    fn transact_inner(
        &self,
        pdu: &[u8],
        expected_fc: u8,
        allow_exception: bool,
    ) -> Result<ModbusReply> {
        let mut last_err = None;
        for &unit_id in &self.unit_ids {
            match self.transact_unit(unit_id, pdu, expected_fc, allow_exception) {
                Ok(reply) => return Ok(reply),
                Err(e) if retry_with_next_unit_id(&e) => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no Modbus unit IDs configured")))
    }

    fn transact_unit(
        &self,
        unit_id: u8,
        pdu: &[u8],
        expected_fc: u8,
        allow_exception: bool,
    ) -> Result<ModbusReply> {
        let addr = (self.ip.as_str(), self.port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {}:{}", self.ip, self.port))?
            .next()
            .with_context(|| format!("no address for {}", self.ip))?;

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .with_context(|| format!("connecting to {}:{}", self.ip, self.port))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let length = u16::try_from(pdu.len() + 1).context("PDU too large for MBAP length")?;
        let mut request = Vec::with_capacity(7 + pdu.len());
        request.extend_from_slice(&TRANSACTION_ID.to_be_bytes());
        request.extend_from_slice(&0x0000u16.to_be_bytes());
        request.extend_from_slice(&length.to_be_bytes());
        request.push(unit_id);
        request.extend_from_slice(pdu);
        stream.write_all(&request)?;

        let mut header = [0u8; 7];
        stream.read_exact(&mut header).context("reading MBAP header")?;
        if header[2..4] != [0, 0] {
            bail!("not a Modbus TCP response");
        }
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

        let mut body = vec![0u8; resp_len - 1];
        stream.read_exact(&mut body).context("reading Modbus PDU")?;

        let fc = *body.first().context("empty Modbus PDU")?;
        if fc == expected_fc | 0x80 {
            let exception = body.get(1).copied().unwrap_or(0);
            if allow_exception {
                return Ok(ModbusReply {
                    unit_id,
                    data: body.get(1..).unwrap_or_default().to_vec(),
                });
            }
            bail!(
                "Modbus exception for function {expected_fc:#04x}: {} ({exception:#04x})",
                exception_name(exception)
            );
        }
        if fc != expected_fc {
            bail!("unexpected Modbus function code {fc:#04x}, wanted {expected_fc:#04x}");
        }

        Ok(ModbusReply {
            unit_id,
            data: body[1..].to_vec(),
        })
    }
}

/// Return `port`, substituting the Modbus default (502) when it is 0.
pub fn effective_port(port: u16) -> u16 {
    if port == 0 {
        DEFAULT_PORT
    } else {
        port
    }
}

fn retry_with_next_unit_id(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("reading MBAP header")
        || msg.contains("reading Modbus PDU")
        || msg.contains("empty Modbus PDU")
        || msg.contains("unexpected Modbus unit id")
        || msg.contains("not a Modbus TCP response")
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
    let [sh, sl] = start.to_be_bytes();
    let [ch, cl] = count.to_be_bytes();
    [fc, sh, sl, ch, cl]
}

fn read_words(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
    fc: u8,
    offset: u32,
) -> Result<Vec<ModbusRegister>> {
    let count = count.clamp(1, MAX_REGISTERS);
    let client = ModbusTcpClient::new(ip).with_port(port);
    let reply = client.transact(&read_request_pdu(fc, start, count), fc)?;

    let byte_count = usize::from(
        *reply
            .data
            .first()
            .context("register response missing byte count")?,
    );
    let words = reply
        .data
        .get(1..1 + byte_count)
        .context("register response truncated")?;

    let mut registers = Vec::with_capacity(byte_count / 2);
    for (i, word) in words.chunks_exact(2).enumerate() {
        let raw = u16::from_be_bytes([word[0], word[1]]);
        let address = start.wrapping_add(u16::try_from(i).unwrap_or(u16::MAX));
        registers.push(ModbusRegister {
            address,
            display_addr: u32::from(address) + offset,
            raw,
            value_str: format!("{raw} ({raw:#06x})"),
        });
    }
    Ok(registers)
}

fn read_bits(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
    fc: u8,
    offset: u32,
) -> Result<Vec<ModbusRegister>> {
    let count = count.clamp(1, MAX_BITS);
    let client = ModbusTcpClient::new(ip).with_port(port);
    let reply = client.transact(&read_request_pdu(fc, start, count), fc)?;

    let byte_count = usize::from(
        *reply
            .data
            .first()
            .context("bit response missing byte count")?,
    );
    let bytes = reply
        .data
        .get(1..1 + byte_count)
        .context("bit response truncated")?;

    let mut registers = Vec::with_capacity(usize::from(count));
    for i in 0..usize::from(count) {
        let byte = *bytes
            .get(i / 8)
            .context("bit response shorter than requested count")?;
        let bit = (byte >> (i % 8)) & 1;
        let address = start.wrapping_add(u16::try_from(i).unwrap_or(u16::MAX));
        registers.push(ModbusRegister {
            address,
            display_addr: u32::from(address) + offset,
            raw: u16::from(bit),
            value_str: if bit == 1 { "ON" } else { "OFF" }.to_string(),
        });
    }
    Ok(registers)
}

/// Read `count` holding registers (FC 0x03) starting at `start`; display addresses use the 4xxxx range.
pub fn read_holding_registers(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
) -> Result<Vec<ModbusRegister>> {
    read_words(ip, port, start, count, 0x03, 40001)
}

/// Read `count` input registers (FC 0x04) starting at `start`; display addresses use the 3xxxx range.
pub fn read_input_registers(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
) -> Result<Vec<ModbusRegister>> {
    read_words(ip, port, start, count, 0x04, 30001)
}

/// Read `count` coils (FC 0x01) starting at `start`; each register decodes to "ON"/"OFF".
pub fn read_coils(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
) -> Result<Vec<ModbusRegister>> {
    read_bits(ip, port, start, count, 0x01, 1)
}

/// Read `count` discrete inputs (FC 0x02) starting at `start`; display addresses use the 1xxxx range.
pub fn read_discrete_inputs(
    ip: &str,
    port: u16,
    start: u16,
    count: u16,
) -> Result<Vec<ModbusRegister>> {
    read_bits(ip, port, start, count, 0x02, 10001)
}

/// Write a single coil (FC 0x05) to on/off at `address`.
pub fn write_single_coil(ip: &str, port: u16, address: u16, on: bool) -> Result<()> {
    let value: u16 = if on { 0xFF00 } else { 0x0000 };
    let pdu = [
        0x05,
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (value >> 8) as u8,
        (value & 0xFF) as u8,
    ];
    ModbusTcpClient::new(ip).with_port(port).transact(&pdu, 0x05)?;
    Ok(())
}

/// Write a single holding register (FC 0x06) at `address`.
pub fn write_single_register(ip: &str, port: u16, address: u16, value: u16) -> Result<()> {
    let pdu = [
        0x06,
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (value >> 8) as u8,
        (value & 0xFF) as u8,
    ];
    ModbusTcpClient::new(ip).with_port(port).transact(&pdu, 0x06)?;
    Ok(())
}

/// Write consecutive holding registers (FC 0x10) starting at `start`; returns the count written
/// (values are capped at the Modbus per-request maximum of 125).
pub fn write_multiple_registers(ip: &str, port: u16, start: u16, values: &[u16]) -> Result<u16> {
    if values.is_empty() {
        bail!("write_multiple_registers: empty values slice");
    }
    let count = values.len().min(usize::from(MAX_REGISTERS));
    let values = &values[..count];
    // count is bounded by MAX_REGISTERS (125), so these casts are safe
    let count16 = u16::try_from(count).unwrap_or(u16::MAX);
    let byte_count = u8::try_from(count * 2).unwrap_or(u8::MAX);
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
    let reply = ModbusTcpClient::new(ip).with_port(port).transact(&pdu, 0x10)?;
    let written = reply.data.get(2..4).context("FC16 response truncated")?;
    Ok(u16::from_be_bytes([written[0], written[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn modbus_response(req: &[u8], unit_id: u8, fc: u8, data: &[u8]) -> Vec<u8> {
        let length = u16::try_from(data.len() + 2).unwrap();
        let mut resp = vec![req[0], req[1], 0x00, 0x00];
        resp.extend_from_slice(&length.to_be_bytes());
        resp.push(unit_id);
        resp.push(fc);
        resp.extend_from_slice(data);
        resp
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
            stream
                .write_all(&modbus_response(&req, 0x01, 0x03, &[0x02, 0x04, 0xD2]))
                .unwrap();
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
                .write_all(&modbus_response(&second_req, 0xFF, 0x03, &[0x02, 0x10, 0xE1]))
                .unwrap();
        });

        let regs = read_holding_registers("127.0.0.1", port, 0, 1).unwrap();
        handle.join().unwrap();
        assert_eq!(regs[0].raw, 4321);
    }

    #[test]
    fn read_device_id_parses_objects_and_unit_id() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 11];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req[6], 0x01);
            let data = b"\x0e\x01\x01\x00\x00\x03\x00\x09Schneider\x01\x0aTM241CE24T\x02\x05V1.00";
            stream
                .write_all(&modbus_response(&req, 0x01, 0x2B, data))
                .unwrap();
        });

        let id = ModbusTcpClient::new("127.0.0.1")
            .with_port(port)
            .read_device_id()
            .unwrap();
        handle.join().unwrap();
        assert_eq!(id.unit_id, 0x01);
        assert_eq!(id.manufacturer(), Some("Schneider"));
        assert_eq!(id.product_name(), Some("TM241CE24T"));
        assert_eq!(id.version(), Some("V1.00"));
    }

    #[test]
    fn probe_accepts_modbus_exception_as_reachable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 12];
            stream.read_exact(&mut req).unwrap();
            stream
                .write_all(&modbus_response(&req, 0x01, 0x83, &[0x02]))
                .unwrap();
        });

        let reply = ModbusTcpClient::new("127.0.0.1")
            .with_port(port)
            .probe_holding_register()
            .unwrap();
        handle.join().unwrap();
        assert_eq!(reply.unit_id, 0x01);
        assert_eq!(reply.data, vec![0x02]);
    }
}
