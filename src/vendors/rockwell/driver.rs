use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const EIP_PORT: u16 = 44818;
const DEFAULT_TIMEOUT: u64 = 5;

// EtherNet/IP Register Session request
const REG_SESSION: &[u8] = &[
    0x65, 0x00, // Command: Register Session
    0x04, 0x00, // Length: 4
    0x00, 0x00, 0x00, 0x00, // Session Handle
    0x00, 0x00, 0x00, 0x00, // Status
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender Context
    0x00, 0x00, 0x00, 0x00, // Options
    0x01, 0x00, // Protocol version
    0x00, 0x00, // Options flags
];

/// A tag from a Logix controller's symbol table: its name, encoded type word, and array rank.
#[derive(Debug, Clone)]
pub struct LogixTag {
    pub name: String,
    pub tag_type: u16,
    pub dimensions: u8,
    pub instance_id: u32,
}

/// Identity of an EtherNet/IP / Logix device (vendor, product type/code, revision, serial, name).
#[derive(Debug, Clone)]
pub struct LogixDevice {
    pub vendor: String,
    pub product_type: String,
    pub product_code: u16,
    pub revision: String,
    pub serial: String,
    pub product_name: String,
}

struct EipSession {
    stream: TcpStream,
    session_handle: u32,
}

impl EipSession {
    fn connect(ip: &str, port: u16) -> Result<Self> {
        let effective_port = if port == 0 { EIP_PORT } else { port };
        let stream = TcpStream::connect_timeout(
            &format!("{ip}:{effective_port}").parse()?,
            Duration::from_secs(DEFAULT_TIMEOUT),
        )
        .context("TCP connect failed")?;
        stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT)))?;

        let mut session = EipSession {
            stream,
            session_handle: 0,
        };
        session.register()?;
        Ok(session)
    }

    fn register(&mut self) -> Result<()> {
        self.stream.write_all(REG_SESSION)?;
        let mut buf = [0u8; 28];
        self.stream.read_exact(&mut buf)?;
        let status = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if status != 0 {
            anyhow::bail!("EIP RegisterSession rejected: status 0x{status:08x}");
        }
        self.session_handle = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok(())
    }

    /// Send a CIP Read Tag request and return the raw CIP response payload.
    ///
    /// The returned slice starts with the 2-byte type word echo, followed by
    /// the element data — pass it directly to `decode_value`.
    fn read_tag_cip(&mut self, tag_name: &str) -> Result<Vec<u8>> {
        const CIP_OFF: usize = 40;
        let name_bytes = tag_name.as_bytes();
        if name_bytes.len() > 255 {
            anyhow::bail!("Tag name too long (max 255 bytes for CIP ANSI Symbolic Segment)");
        }
        // name_bytes.len() ≤ 255, so these casts are safe
        let path_size = u8::try_from(1 + name_bytes.len().div_ceil(2)).unwrap_or(u8::MAX);

        let mut cip = vec![0x4c, path_size, 0x91, u8::try_from(name_bytes.len()).unwrap_or(u8::MAX)];
        cip.extend_from_slice(name_bytes);
        if !name_bytes.len().is_multiple_of(2) {
            cip.push(0); // pad to even
        }
        cip.extend_from_slice(&[0x01, 0x00]); // element count = 1

        let resp = self.send_rr_data(&cip)?;
        if resp.len() < CIP_OFF + 4 {
            anyhow::bail!("Short read response ({} bytes)", resp.len());
        }
        let d = &resp[CIP_OFF..];
        if d[2] != 0 {
            anyhow::bail!("CIP read error 0x{:02x}", d[2]);
        }
        let skip = 4 + usize::from(d[3]) * 2;
        if d.len() < skip {
            anyhow::bail!("CIP read response truncated (ext_status_size={})", d[3]);
        }
        Ok(d[skip..].to_vec()) // [type_lo, type_hi, val_bytes...]
    }

    fn send_rr_data(&mut self, cip_data: &[u8]) -> Result<Vec<u8>> {
        let handle_bytes = self.session_handle.to_le_bytes();

        // Send RR Data encapsulation
        let payload_len = 16 + cip_data.len();
        let payload_len_u16 = u16::try_from(payload_len)
            .context("CIP payload too large for EIP encapsulation")?;
        let mut packet = Vec::with_capacity(24 + payload_len);

        // EIP header
        packet.extend_from_slice(&[0x6F, 0x00]); // Command: SendRRData (0x006F)
        packet.extend_from_slice(&payload_len_u16.to_le_bytes());
        packet.extend_from_slice(&handle_bytes);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // status
        packet.extend_from_slice(&[0x00; 8]); // sender context
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // options

        // CPF (Common Packet Format)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // interface handle
        packet.extend_from_slice(&[0x00, 0x00]); // timeout
        packet.extend_from_slice(&[0x02, 0x00]); // item count = 2
        // Item 1: Null Address
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Item 2: Unconnected Data
        packet.extend_from_slice(&[0xb2, 0x00]);
        packet.extend_from_slice(&u16::try_from(cip_data.len()).unwrap_or(u16::MAX).to_le_bytes());
        packet.extend_from_slice(cip_data);

        self.stream.write_all(&packet)?;

        // Read the fixed 24-byte EIP header, then the variable-length payload.
        let mut hdr = [0u8; 24];
        self.stream.read_exact(&mut hdr).context("EIP: short response header")?;
        let eip_status = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        if eip_status != 0 {
            anyhow::bail!("EIP encapsulation error 0x{eip_status:08x}");
        }
        let body_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; body_len];
        self.stream.read_exact(&mut body).context("EIP: short response body")?;
        let mut full = hdr.to_vec();
        full.extend_from_slice(&body);
        Ok(full)
    }
}

/// Read the identity object from an EtherNet/IP device.
///
/// Tries List Identity first (supported by all EtherNet/IP devices), then falls back
/// to CIP Get Attribute All (Logix-only). Pass `port = 0` to use the default (44818).
pub fn get_device_info(ip: &str, port: u16) -> Result<LogixDevice> {
    if let Ok(dev) = list_identity_tcp(ip, port) {
        return Ok(dev);
    }
    get_device_info_cip(ip, port)
}

/// EtherNet/IP List Identity (command 0x63) over TCP — no session required.
/// Works on every compliant EtherNet/IP device.
fn list_identity_tcp(ip: &str, port: u16) -> Result<LogixDevice> {
    let effective_port = if port == 0 { EIP_PORT } else { port };
    let mut stream = TcpStream::connect_timeout(
        &format!("{ip}:{effective_port}").parse()?,
        Duration::from_secs(DEFAULT_TIMEOUT),
    )
    .context("TCP connect failed")?;
    stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT)))?;

    // List Identity request: command 0x63, zero payload
    let req = [
        0x63u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&req)?;

    // Read the fixed 24-byte EIP header, then the variable-length payload.
    let mut hdr = [0u8; 24];
    stream.read_exact(&mut hdr).context("List Identity: short header")?;
    let body_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).context("List Identity: short body")?;
    let mut buf = hdr.to_vec();
    buf.extend_from_slice(&body);

    parse_list_identity_response(&buf, ip)
}

fn parse_list_identity_response(data: &[u8], _ip: &str) -> Result<LogixDevice> {
    if data.len() < 4 || data[0] != 0x63 || data[1] != 0x00 {
        anyhow::bail!("Not a List Identity response");
    }
    let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 24 + data_len || data_len < 6 {
        anyhow::bail!("List Identity response too short");
    }
    let resp = &data[24..24 + data_len];

    // CPF item: type 0x000C = Identity
    if resp[2..4] != [0x0c, 0x00] {
        anyhow::bail!("Unexpected CPF item type");
    }
    let item_len = u16::from_le_bytes([resp[4], resp[5]]) as usize;
    if resp.len() < 6 + item_len || item_len < 33 {
        anyhow::bail!("Identity item too short");
    }
    let item = &resp[6..6 + item_len];

    // item layout: 2 enc_version + 16 socket_addr = 18 bytes before identity fields
    let vendor_id  = u16::from_le_bytes([item[18], item[19]]);
    let dev_type   = u16::from_le_bytes([item[20], item[21]]);
    let prod_code  = u16::from_le_bytes([item[22], item[23]]);
    let revision   = format!("{}.{}", item[24], item[25]);
    let serial     = format!("{:08X}", u32::from_le_bytes([item[28], item[29], item[30], item[31]]));
    let name_len   = item[32] as usize;
    let product_name = if item.len() >= 33 + name_len {
        String::from_utf8_lossy(&item[33..33 + name_len]).to_string()
    } else {
        String::new()
    };

    Ok(LogixDevice {
        vendor: vendor_name(vendor_id).to_string(),
        product_type: product_type_name(dev_type).to_string(),
        product_code: prod_code,
        revision,
        serial,
        product_name,
    })
}

fn get_device_info_cip(ip: &str, port: u16) -> Result<LogixDevice> {
    // CIP starts at offset 40 (24-byte EIP header + 16-byte CPF overhead).
    // d[0]=service_echo, d[1]=reserved, d[2]=status, d[3]=ext_status_size, d[4..]=data.
    const CIP_OFF: usize = 40;
    let mut session = EipSession::connect(ip, port).context("EIP session failed")?;

    // CIP Get Attribute All on Identity Object (class 0x01, instance 1) — Logix only
    let cip = &[0x01, 0x02, 0x20, 0x01, 0x24, 0x01];
    let resp = session.send_rr_data(cip)?;
    if resp.len() < CIP_OFF + 18 {
        anyhow::bail!(
            "Device returned {} bytes — not a Logix controller, or CIP Get Attribute All \
             is not supported. Try List Tags only on ControlLogix/CompactLogix.",
            resp.len()
        );
    }

    let status = resp[CIP_OFF + 2];
    if status != 0 {
        anyhow::bail!("CIP error 0x{status:02x}");
    }

    let d = &resp[CIP_OFF + 4..];
    if d.len() < 14 {
        anyhow::bail!("CIP identity data too short ({} bytes)", d.len());
    }

    let vendor_id    = u16::from_le_bytes([d[0], d[1]]);
    let product_type = u16::from_le_bytes([d[2], d[3]]);
    let product_code = u16::from_le_bytes([d[4], d[5]]);
    let revision     = format!("{}.{}", d[6], d[7]);
    let serial       = format!("{:08X}", u32::from_le_bytes([d[10], d[11], d[12], d[13]]));
    let name_len     = d.get(14).copied().unwrap_or(0) as usize;
    let product_name = if d.len() >= 15 + name_len {
        String::from_utf8_lossy(&d[15..15 + name_len]).to_string()
    } else {
        String::new()
    };

    Ok(LogixDevice {
        vendor: vendor_name(vendor_id).to_string(),
        product_type: product_type_name(product_type).to_string(),
        product_code,
        revision,
        serial,
        product_name,
    })
}

/// Enumerate tags from Logix controller's symbol list. Pass `port = 0` for the default (44818).
#[allow(clippy::too_many_lines)]
pub fn enumerate_tags(ip: &str, port: u16) -> Result<Vec<LogixTag>> {
    const CIP_OFF: usize = 40;
    let mut session = EipSession::connect(ip, port).context("EIP session failed")?;
    let mut tags = Vec::new();
    let mut last_instance = 0u32;

    loop {
        // CIP path uses a 16-bit instance segment (0x25); guard against wrap-around.
        if last_instance > 0xFFFF {
            break;
        }
        // CIP: Read Tag Service, Get Instance Attribute List
        let instance_bytes = last_instance.to_le_bytes();
        let cip = vec![
            0x55, // Get Instance Attribute List
            0x03, // Path size (words)
            0x20,
            0x6b, // Class 0x6b = Symbol Object
            0x25,
            0x00, // Pad
            instance_bytes[0],
            instance_bytes[1], // Instance (16-bit)
            0x02,
            0x00, // Attribute count = 2
            0x01,
            0x00, // Attr 1: tag name
            0x02,
            0x00, // Attr 2: tag type
        ];

        let resp = session.send_rr_data(&cip)?;

        // CIP starts at offset 40; need at least status byte at +2.
        if resp.len() < CIP_OFF + 4 {
            break;
        }

        let d = &resp[CIP_OFF..];
        // d[0]=service_echo, d[1]=reserved, d[2]=status, d[3]=ext_status_size
        let status = d[2];
        let more = status == 0x06; // partial transfer — more data follows

        if status != 0x00 && status != 0x06 {
            if tags.is_empty() {
                return Err(match status {
                    0x08 => anyhow::anyhow!(
                        "Tag enumeration not supported (CIP 0x08: service not supported). \
                         Symbol Object (class 0x6B) requires a Logix controller \
                         (ControlLogix, CompactLogix, or Micro800)."
                    ),
                    0x14 => anyhow::anyhow!(
                        "Tag enumeration not supported (CIP 0x14: attribute not supported). \
                         This device does not expose a symbol table."
                    ),
                    _ => anyhow::anyhow!(
                        "Tag enumeration failed: CIP status 0x{status:02x}. \
                         Device may not be a Logix controller."
                    ),
                });
            }
            break;
        }

        // ext_status_size words precede the actual data
        let ext_size = d[3] as usize;
        let skip = 4 + ext_size * 2;
        if d.len() < skip {
            break;
        }
        let attr_data = &d[skip..];
        let mut pos = 0;

        while pos + 4 <= attr_data.len() {
            let instance_id = u32::from_le_bytes([
                attr_data[pos],
                attr_data[pos + 1],
                attr_data[pos + 2],
                attr_data[pos + 3],
            ]);
            pos += 4;

            if pos + 2 > attr_data.len() {
                break;
            }
            let name_len = u16::from_le_bytes([attr_data[pos], attr_data[pos + 1]]) as usize;
            pos += 2;

            if pos + name_len > attr_data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&attr_data[pos..pos + name_len]).to_string();
            pos += name_len;
            // SSTRING is padded to an even byte boundary
            if !name_len.is_multiple_of(2) {
                pos += 1;
            }

            if pos + 2 > attr_data.len() {
                break;
            }
            let tag_type = u16::from_le_bytes([attr_data[pos], attr_data[pos + 1]]);
            // Bits 14-12 of symbol type encode the dimension count (0=scalar, 1-3=array dims)
            let dimensions = ((tag_type >> 12) & 0x07) as u8;
            pos += 2;

            last_instance = match instance_id.checked_add(1) {
                Some(n) => n,
                None => break,
            };

            if !name.starts_with("__") {
                tags.push(LogixTag {
                    name,
                    tag_type,
                    dimensions,
                    instance_id,
                });
            }
        }

        if !more {
            break;
        }
    }

    Ok(tags)
}

/// Read a single named tag's raw value bytes (opens its own session).
/// Pass `port = 0` for the default EtherNet/IP port (44818).
pub fn read_tag(ip: &str, port: u16, tag_name: &str) -> Result<Vec<u8>> {
    EipSession::connect(ip, port)?.read_tag_cip(tag_name)
}

/// Read multiple scalar tag values over a single reused EIP session.
///
/// Returns one `Option<Vec<u8>>` per name: `Some(cip_payload)` on success,
/// `None` if the tag read failed or the initial connect failed.
/// Each payload has the same layout as `read_tag`: `[type_lo, type_hi, val...]`.
/// Pass `port = 0` for the default EtherNet/IP port (44818).
pub fn read_tags_bulk(ip: &str, port: u16, tag_names: &[&str]) -> Vec<Option<Vec<u8>>> {
    if tag_names.is_empty() {
        return Vec::new();
    }
    let Ok(mut session) = EipSession::connect(ip, port) else { return vec![None; tag_names.len()] };
    tag_names
        .iter()
        .map(|name| session.read_tag_cip(name).ok())
        .collect()
}

/// Decode a CIP Read Tag response payload into a human-readable value string.
///
/// `cip_data` is the payload returned by `read_tag` / `read_tags_bulk`:
/// first 2 bytes are the type word echo, the rest are the element bytes.
pub fn decode_value(tag_type: u16, cip_data: &[u8]) -> String {
    if cip_data.len() < 2 {
        return "-".to_string();
    }
    let val = &cip_data[2..]; // skip 2-byte type word echo
    let type_code = (tag_type & 0xFF) as u8;

    match type_code {
        // BOOL — 1 byte; value is 0 or non-zero
        0x00..=0x1F | 0xC1 => {
            if val.is_empty() { return "?".to_string(); }
            if val[0] != 0 { "true  (1)".to_string() } else { "false (0)".to_string() }
        }
        // SINT — 1-byte signed
        0xC2 => {
            if val.is_empty() { return "?".to_string(); }
            i8::from_ne_bytes([val[0]]).to_string()
        }
        // INT — 2-byte signed
        0xC3 => {
            if val.len() < 2 { return "?".to_string(); }
            i16::from_le_bytes([val[0], val[1]]).to_string()
        }
        // DINT — 4-byte signed
        0xC4 => {
            if val.len() < 4 { return "?".to_string(); }
            i32::from_le_bytes([val[0], val[1], val[2], val[3]]).to_string()
        }
        // LINT — 8-byte signed
        0xC5 => {
            if val.len() < 8 { return "?".to_string(); }
            i64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]).to_string()
        }
        // USINT — 1-byte unsigned
        0xC6 => {
            if val.is_empty() { return "?".to_string(); }
            val[0].to_string()
        }
        // UINT — 2-byte unsigned
        0xC7 => {
            if val.len() < 2 { return "?".to_string(); }
            u16::from_le_bytes([val[0], val[1]]).to_string()
        }
        // UDINT — 4-byte unsigned
        0xC8 => {
            if val.len() < 4 { return "?".to_string(); }
            u32::from_le_bytes([val[0], val[1], val[2], val[3]]).to_string()
        }
        // ULINT — 8-byte unsigned
        0xC9 => {
            if val.len() < 8 { return "?".to_string(); }
            u64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]).to_string()
        }
        // REAL — 4-byte IEEE 754 single
        0xCA => {
            if val.len() < 4 { return "?".to_string(); }
            let f = f32::from_le_bytes([val[0], val[1], val[2], val[3]]);
            format!("{f}")
        }
        // LREAL — 8-byte IEEE 754 double
        0xCB => {
            if val.len() < 8 { return "?".to_string(); }
            let f = f64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]);
            format!("{f}")
        }
        // STRING — Logix format: 4-byte length + chars
        0xD0 => {
            if val.len() < 4 { return "\"?\"".to_string(); }
            let len = u32::from_le_bytes([val[0], val[1], val[2], val[3]]) as usize;
            if val.len() >= 4 + len {
                format!("\"{}\"", String::from_utf8_lossy(&val[4..4 + len]))
            } else {
                "\"?\"".to_string()
            }
        }
        // Everything else — show raw hex
        _ => {
            use std::fmt::Write;
            if val.is_empty() { return "-".to_string(); }
            let hex = val.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            format!("0x{hex}")
        }
    }
}

/// Write raw bytes to a named tag.
/// Pass `port = 0` for the default EtherNet/IP port (44818).
pub fn write_tag(ip: &str, port: u16, tag_name: &str, type_code: u16, value_bytes: &[u8]) -> Result<()> {
    const CIP_OFF: usize = 40;
    let mut session = EipSession::connect(ip, port)?;

    let name_bytes = tag_name.as_bytes();
    // CIP ANSI Extended Symbolic Segment uses a 1-byte length field (max 255).
    if name_bytes.len() > 255 {
        anyhow::bail!("Tag name too long (max 255 bytes for CIP ANSI Symbolic Segment)");
    }
    // name_bytes.len() ≤ 255, so these casts are safe
    let path_size = u8::try_from(1 + name_bytes.len().div_ceil(2)).unwrap_or(u8::MAX);

    let mut cip = vec![
        0x4d, // Write Tag service
        path_size,
        0x91,
        u8::try_from(name_bytes.len()).unwrap_or(u8::MAX),
    ];
    cip.extend_from_slice(name_bytes);
    if !name_bytes.len().is_multiple_of(2) {
        cip.push(0);
    }
    cip.extend_from_slice(&type_code.to_le_bytes());
    cip.extend_from_slice(&[0x01, 0x00]); // element count = 1
    cip.extend_from_slice(value_bytes);

    let resp = session.send_rr_data(&cip)?;
    if resp.len() < CIP_OFF + 4 {
        anyhow::bail!("Short write response ({} bytes)", resp.len());
    }

    let status = resp[CIP_OFF + 2];
    if status != 0 {
        anyhow::bail!("Write failed: CIP status 0x{status:02x}");
    }
    Ok(())
}

/// Decode a Logix symbol type word into a human-readable string.
///
/// Bit 15: UDT/template flag.  Bits 14–12: array dimension count (1–3; >3 = DWORD offset,
/// not a real dimension).  Bits 7–0: CIP base type code.  Type codes 0x00–0x1F are
/// bit-packed BOOLs — the lower byte is the bit index within a storage DWORD.
pub fn type_name(tag_type: u16) -> String {
    let is_struct = tag_type & 0x8000 != 0;

    if is_struct {
        let id   = tag_type & 0x0FFF;
        let dims = (tag_type >> 12) & 0x07;
        let base = format!("STRUCT({id:#05x})");
        return if dims == 0 { base } else { format!("{base}[{dims}D]") };
    }

    let type_code = (tag_type & 0xFF) as u8;
    if matches!(type_code, 0x00..=0x1F) {
        let dims = ((tag_type & 0x7FFF) >> 12) & 0x07;
        return if dims == 0 || dims > 3 {
            format!("BOOL.b{type_code}")
        } else {
            format!("BOOL.b{type_code}[{dims}D]")
        };
    }
    let base: &str = match type_code {
        0xC1 => "BOOL",
        0xC2 => "SINT",
        0xC3 => "INT",
        0xC4 => "DINT",
        0xC5 => "LINT",
        0xC6 => "USINT",
        0xC7 => "UINT",
        0xC8 => "UDINT",
        0xC9 => "ULINT",
        0xCA => "REAL",
        0xCB => "LREAL",
        0xCC => "STIME",
        0xCD => "DATE",
        0xCE => "TIME_OF_DAY",
        0xCF => "DATE_AND_TIME",
        0xD0 => "STRING",
        0xD1 => "BYTE",
        0xD2 => "WORD",
        0xD3 => "DWORD",
        0xD4 => "LWORD",
        0xDB => "TIME",
        _ => return format!("?{type_code:#04x}"),
    };

    // Logix supports at most 3 array dimensions; upper byte > 3 means it's a
    // DWORD offset for packed BOOLs, not an actual array dimension count.
    let dims = ((tag_type & 0x7FFF) >> 12) & 0x07;
    if dims == 0 || dims > 3 {
        base.to_string()
    } else {
        format!("{base}[{dims}D]")
    }
}

/// Decodes the type word into `(base_type_name, dims_label)`.
///
/// `base_type_name` — e.g. `"BOOL"`, `"DINT"`, `"STRUCT(0x012)"`
/// `dims_label`     — `"1D"` / `"2D"` / `"3D"` or `"-"` for scalars
pub fn type_parts(tag_type: u16) -> (String, &'static str) {
    let is_struct = tag_type & 0x8000 != 0;

    let dims_label = |dims: u16| match dims {
        1 => "1D",
        2 => "2D",
        3 => "3D",
        _ => "-",
    };

    if is_struct {
        let id   = tag_type & 0x0FFF;
        let dims = (tag_type >> 12) & 0x07;
        return (format!("STRUCT({id:#05x})"), dims_label(dims));
    }

    let type_code = (tag_type & 0xFF) as u8;
    if matches!(type_code, 0x00..=0x1F) {
        let dims = ((tag_type & 0x7FFF) >> 12) & 0x07;
        return (format!("BOOL.b{type_code}"), dims_label(if dims > 3 { 0 } else { dims }));
    }
    let base: &str = match type_code {
        0xC1 => "BOOL",  0xC2 => "SINT",         0xC3 => "INT",
        0xC4 => "DINT",  0xC5 => "LINT",         0xC6 => "USINT",
        0xC7 => "UINT",  0xC8 => "UDINT",        0xC9 => "ULINT",
        0xCA => "REAL",  0xCB => "LREAL",        0xCC => "STIME",
        0xCD => "DATE",  0xCE => "TIME_OF_DAY",  0xCF => "DATE_AND_TIME",
        0xD0 => "STRING",0xD1 => "BYTE",         0xD2 => "WORD",
        0xD3 => "DWORD", 0xD4 => "LWORD",        0xDB => "TIME",
        _ => return (format!("?{type_code:#04x}"), "-"),
    };

    let dims = ((tag_type & 0x7FFF) >> 12) & 0x07;
    (base.to_string(), dims_label(if dims > 3 { 0 } else { dims }))
}

fn vendor_name(id: u16) -> &'static str {
    match id {
        1 => "Rockwell Automation / Allen-Bradley",
        2 => "Namco Controls Corp.",
        3 => "Honeywell Inc.",
        9 => "Omron Corporation",
        19 => "Parker Hannifin Corporation",
        24 => "Eaton Corporation",
        25 => "Digital Equipment Corp.",
        36 => "Molex Incorporated",
        47 => "SEW-Eurodrive GmbH & Co.",
        48 => "Festo AG & Co.",
        55 => "Bosch Rexroth Corp.",
        75 => "Siemens Energy & Automation Inc.",
        _ => "Unknown Vendor",
    }
}

fn product_type_name(id: u16) -> &'static str {
    match id {
        0x00 => "Generic Device",
        0x02 => "AC Drive",
        0x03 => "Motor Overload",
        0x04 => "Limit Switch",
        0x05 => "Inductive Proximity Switch",
        0x06 => "Photoelectric Sensor",
        0x07 => "General Purpose Discrete I/O",
        0x09 => "Resolver",
        0x0c => "Communications Adapter",
        0x0e => "Programmable Logic Controller",
        0x10 => "Positional Controller",
        0x13 => "DC Drive",
        0x15 => "Contactor",
        0x16 => "Motor Starter",
        0x17 => "Soft Start",
        0x18 => "Human-Machine Interface",
        0x1a => "Mass Flow Controller",
        0x1b => "Pneumatic Valve",
        0x1c => "Vacuum Pressure Gauge",
        0x1d => "Process Control Valve",
        0x1e => "Residual Gas Analyzer",
        0x1f => "DC Power Generator",
        0x20 => "RF Power Generator",
        0x21 => "Turbomolecular Vacuum Pump",
        0x22 => "Encoder",
        0x23 => "Safety Discrete I/O Device",
        0x24 => "Fluid Flow Controller",
        0x25 => "CIP Motion Drive",
        0x26 => "CompoNet Repeater",
        _ => "Unknown Product Type",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_value, parse_list_identity_response, type_name, type_parts};

    // 67-byte List Identity response matching the eip_sim.py format.
    // EIP header (24) + CPF body (43): item_count(2) + item_type(2) + item_len(2) + item(37).
    const LIST_ID_RESP: &[u8] = &[
        // EIP header
        0x63, 0x00,
        0x2b, 0x00,  // data_len = 43
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // CPF body
        0x01, 0x00,  // item_count = 1
        0x0c, 0x00,  // item_type = Identity
        0x25, 0x00,  // item_len = 37
        // Identity item: enc_version(2) + socket_addr(16) + vendor(2) + dev_type(2)
        //   + prod_code(2) + revision(2) + status(2) + serial(4) + name_len(1) + name(3) + state(1)
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00,  // vendor_id = 1
        0x0e, 0x00,  // device_type = 0x0E (Programmable Logic Controller)
        0x01, 0x00,  // product_code = 1
        0x1f, 0x03,  // revision: major=31, minor=3
        0x00, 0x00,  // status
        0x78, 0x56, 0x34, 0x12,  // serial LE → "12345678"
        0x03,        // name_len = 3
        b'P', b'L', b'C',
        0x03,        // state
    ];

    // ── decode_value ──────────────────────────────────────────────────────────

    #[test]
    fn decode_value_too_short_returns_dash() {
        assert_eq!(decode_value(0xC3, &[0x00]), "-");
    }

    #[test]
    fn decode_value_bool_true() {
        assert_eq!(decode_value(0xC1, &[0, 0, 1]), "true  (1)");
    }

    #[test]
    fn decode_value_bool_false() {
        assert_eq!(decode_value(0xC1, &[0, 0, 0]), "false (0)");
    }

    #[test]
    fn decode_value_bool_empty_val_returns_question() {
        assert_eq!(decode_value(0xC1, &[0, 0]), "?");
    }

    #[test]
    fn decode_value_sint_neg1() {
        assert_eq!(decode_value(0xC2, &[0, 0, 0xFF]), "-1");
    }

    #[test]
    fn decode_value_int_1337() {
        // 1337 LE = 0x39, 0x05
        assert_eq!(decode_value(0xC3, &[0, 0, 0x39, 0x05]), "1337");
    }

    #[test]
    fn decode_value_dint_max() {
        assert_eq!(decode_value(0xC4, &[0, 0, 0xFF, 0xFF, 0xFF, 0x7F]), "2147483647");
    }

    #[test]
    fn decode_value_lint_neg1() {
        assert_eq!(
            decode_value(0xC5, &[0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            "-1"
        );
    }

    #[test]
    fn decode_value_usint_255() {
        assert_eq!(decode_value(0xC6, &[0, 0, 255]), "255");
    }

    #[test]
    fn decode_value_uint_max() {
        assert_eq!(decode_value(0xC7, &[0, 0, 0xFF, 0xFF]), "65535");
    }

    #[test]
    fn decode_value_udint_max() {
        assert_eq!(decode_value(0xC8, &[0, 0, 0xFF, 0xFF, 0xFF, 0xFF]), "4294967295");
    }

    #[test]
    fn decode_value_real_one() {
        // 1.0f32 LE = [0x00, 0x00, 0x80, 0x3F]
        assert_eq!(decode_value(0xCA, &[0, 0, 0x00, 0x00, 0x80, 0x3F]), "1");
    }

    #[test]
    fn decode_value_string_hello() {
        let cip_data: &[u8] = &[0, 0, 5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_value(0xD0, cip_data), "\"hello\"");
    }

    #[test]
    fn decode_value_string_truncated_returns_question() {
        // length field says 5 but only 1 byte of data present
        assert_eq!(decode_value(0xD0, &[0, 0, 0x05]), "\"?\"");
    }

    #[test]
    fn decode_value_unknown_type_shows_hex() {
        assert_eq!(decode_value(0xFF, &[0, 0, 0xAB, 0xCD]), "0xabcd");
    }

    #[test]
    fn decode_value_unknown_type_empty_val_returns_dash() {
        assert_eq!(decode_value(0xFF, &[0, 0]), "-");
    }

    // ── type_name ─────────────────────────────────────────────────────────────

    #[test]
    fn type_name_dint_scalar() {
        assert_eq!(type_name(0xC4), "DINT");
    }

    #[test]
    fn type_name_dint_1d() {
        assert_eq!(type_name(0x10C4), "DINT[1D]");
    }

    #[test]
    fn type_name_dint_2d() {
        assert_eq!(type_name(0x20C4), "DINT[2D]");
    }

    #[test]
    fn type_name_dint_3d() {
        assert_eq!(type_name(0x30C4), "DINT[3D]");
    }

    #[test]
    fn type_name_dint_dims4_treated_as_scalar() {
        assert_eq!(type_name(0x40C4), "DINT");
    }

    #[test]
    fn type_name_real_scalar() {
        assert_eq!(type_name(0xCA), "REAL");
    }

    #[test]
    fn type_name_string_scalar() {
        assert_eq!(type_name(0xD0), "STRING");
    }

    #[test]
    fn type_name_bool_bit5() {
        assert_eq!(type_name(0x0005), "BOOL.b5");
    }

    #[test]
    fn type_name_bool_bit5_1d() {
        assert_eq!(type_name(0x1005), "BOOL.b5[1D]");
    }

    #[test]
    fn type_name_struct_scalar() {
        assert_eq!(type_name(0x8042), "STRUCT(0x042)");
    }

    #[test]
    fn type_name_struct_1d() {
        // (0x9042 >> 12) & 7 = 9 & 7 = 1 → 1D
        assert_eq!(type_name(0x9042), "STRUCT(0x042)[1D]");
    }

    #[test]
    fn type_name_unknown_code_shows_hex() {
        assert_eq!(type_name(0x00AB), "?0xab");
    }

    // ── type_parts ────────────────────────────────────────────────────────────

    #[test]
    fn type_parts_dint_scalar() {
        assert_eq!(type_parts(0xC4), ("DINT".to_string(), "-"));
    }

    #[test]
    fn type_parts_dint_1d() {
        assert_eq!(type_parts(0x10C4), ("DINT".to_string(), "1D"));
    }

    #[test]
    fn type_parts_struct_scalar() {
        assert_eq!(type_parts(0x8042), ("STRUCT(0x042)".to_string(), "-"));
    }

    #[test]
    fn type_parts_struct_1d() {
        assert_eq!(type_parts(0x9042), ("STRUCT(0x042)".to_string(), "1D"));
    }

    #[test]
    fn type_parts_bool_bit5() {
        assert_eq!(type_parts(0x0005), ("BOOL.b5".to_string(), "-"));
    }

    #[test]
    fn type_parts_unknown_code() {
        assert_eq!(type_parts(0x00AB), ("?0xab".to_string(), "-"));
    }

    // ── parse_list_identity_response ─────────────────────────────────────────

    #[test]
    fn parse_list_identity_response_empty_is_err() {
        assert!(parse_list_identity_response(&[], "1.2.3.4").is_err());
    }

    #[test]
    fn parse_list_identity_response_wrong_command_is_err() {
        let buf = &[0x64u8, 0x00, 0x00, 0x00];
        assert!(parse_list_identity_response(buf, "1.2.3.4").is_err());
    }

    #[test]
    fn parse_list_identity_response_claimed_len_overflow_is_err() {
        // data_len = 9999, but buffer is only 4 bytes — triggers "too short"
        let buf = &[0x63u8, 0x00, 0x0F, 0x27];
        let err = parse_list_identity_response(buf, "1.2.3.4").unwrap_err();
        assert!(err.to_string().contains("too short"), "got: {err}");
    }

    #[test]
    fn parse_list_identity_response_wrong_cpf_item_type_is_err() {
        // 30-byte frame: valid EIP header with data_len=6, CPF with item_type=0x000D
        let mut frame = vec![0u8; 30];
        frame[0] = 0x63;
        frame[2] = 0x06;  // data_len = 6
        frame[25] = 0x01; // item_count = 1
        frame[26] = 0x0d; // item_type ≠ 0x0C
        let err = parse_list_identity_response(&frame, "1.2.3.4").unwrap_err();
        assert!(err.to_string().contains("CPF item type"), "got: {err}");
    }

    #[test]
    fn parse_list_identity_response_item_too_short_is_err() {
        // 34-byte frame: valid EIP header, CPF with item_type=0x000C, item_len=4 (< 33)
        let mut frame = vec![0u8; 34];
        frame[0] = 0x63;
        frame[2] = 0x0A;  // data_len = 10
        frame[25] = 0x01; // item_count = 1
        frame[26] = 0x0c; // item_type = Identity
        frame[28] = 0x04; // item_len = 4 (< 33) → triggers "Identity item too short"
        let err = parse_list_identity_response(&frame, "1.2.3.4").unwrap_err();
        assert!(err.to_string().contains("Identity item too short"), "got: {err}");
    }

    #[test]
    fn parse_list_identity_response_valid_returns_device() {
        let dev = parse_list_identity_response(LIST_ID_RESP, "1.2.3.4").unwrap();
        assert_eq!(dev.product_name, "PLC");
        assert_eq!(dev.serial, "12345678");
        assert_eq!(dev.revision, "31.3");
        assert_eq!(dev.product_code, 1);
        assert_eq!(dev.product_type, "Programmable Logic Controller");
    }
}
