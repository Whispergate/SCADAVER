use anyhow::{Context, Result};
use std::fmt::Write as FmtWrite;
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

/// A field within a Logix UDT, as decoded from the Template Object (class 0x6C).
///
/// `type_info` is the raw first word of the 8-byte member descriptor. Its meaning depends
/// on the member type: an element count for array members, a bit position for packed BOOLs.
/// Use [`TemplateField::array_len`] and [`TemplateField::bit_pos`] rather than reading it
/// directly.
#[derive(Debug, Clone)]
pub struct TemplateField {
    pub name: String,
    pub cip_type: u16,
    pub type_info: u16,
    pub offset: u32,
}

impl TemplateField {
    /// Array dimension count from bits 14-13 of the member type word (0 = scalar).
    #[must_use]
    pub fn dimensions(&self) -> u8 {
        u8::try_from((self.cip_type >> 13) & 0x03).unwrap_or(0)
    }

    /// True when the member is an array rather than a scalar.
    #[must_use]
    pub fn is_array(&self) -> bool {
        self.dimensions() > 0
    }

    /// Element count for array members; 1 for scalars.
    #[must_use]
    pub fn array_len(&self) -> u16 {
        if self.is_array() { self.type_info.max(1) } else { 1 }
    }

    /// Bit position within the byte at `offset` for a packed BOOL member.
    #[must_use]
    pub fn bit_pos(&self) -> u8 {
        u8::try_from(self.type_info & 0x07).unwrap_or(0)
    }

    /// True when this member is itself a structure (nested UDT).
    #[must_use]
    pub fn is_struct(&self) -> bool {
        self.cip_type & 0x8000 != 0
    }

    /// Template id of a nested UDT member.
    #[must_use]
    pub fn nested_template_id(&self) -> u16 {
        self.cip_type & 0x0FFF
    }
}

/// A decoded UDT definition: its members plus the byte size of one instance.
///
/// `size` is Template Object attribute 5 when the controller reports it, otherwise an extent
/// computed from the member layout. It is the stride used to walk an array of this UDT.
#[derive(Debug, Clone)]
pub struct TemplateDef {
    pub fields: Vec<TemplateField>,
    pub size: Option<u32>,
}

impl TemplateDef {
    /// Build a definition from fields alone, deriving the stride from the member layout.
    #[must_use]
    pub fn from_fields(fields: Vec<TemplateField>) -> Self {
        Self { size: None, fields }
    }

    /// Byte stride for one instance: the reported size, else the computed member extent.
    ///
    /// The computed extent can undershoot the real stride because Logix pads structures for
    /// alignment, which is why the reported size is preferred when available.
    #[must_use]
    pub fn stride(&self) -> Option<usize> {
        if let Some(size) = self.size.filter(|&s| s > 0) {
            return Some(size as usize);
        }
        let mut extent = 0usize;
        for f in &self.fields {
            let width = cip_type_size(f.cip_type)?.checked_mul(f.array_len() as usize)?;
            extent = extent.max((f.offset as usize).checked_add(width)?);
        }
        (extent > 0).then_some(extent)
    }
}

/// Maps `template_id` (lower 12 bits of a struct `tag_type`) to its definition.
pub type TemplateMap = std::collections::HashMap<u16, TemplateDef>;

/// Byte width of one element of an atomic CIP type.
///
/// Returns `None` for structures, strings and unrecognised codes. Callers use that to decline
/// an operation rather than guessing a width and reading at the wrong stride.
#[must_use]
pub fn cip_type_size(cip_type: u16) -> Option<usize> {
    if cip_type & 0x8000 != 0 {
        return None; // structure: size comes from its own TemplateDef
    }
    match (cip_type & 0xFF) as u8 {
        0x00..=0x1F | 0xC1 | 0xC2 | 0xC6 => Some(1),
        0xC3 | 0xC7 | 0xCD | 0xD2 | 0xD8 => Some(2),
        0xC4 | 0xC8 | 0xCA | 0xCC | 0xCE | 0xD3 | 0xD6 | 0xDB => Some(4),
        0xC5 | 0xC9 | 0xCB | 0xCF | 0xD4 | 0xD7 => Some(8),
        _ => None,
    }
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
    /// the element data: pass it directly to `decode_value`.
    fn read_tag_cip(&mut self, tag_name: &str) -> Result<Vec<u8>> {
        const CIP_OFF: usize = 40;
        let path = symbolic_path(tag_name)?;

        let mut cip = vec![0x4c, path_size_words(&path)?];
        cip.extend_from_slice(&path);
        cip.extend_from_slice(&[0x01, 0x00]); // element count = 1

        let resp = self.send_rr_data(&cip)?;
        if resp.len() < CIP_OFF + 4 {
            anyhow::bail!("Short read response ({} bytes)", resp.len());
        }
        let d = &resp[CIP_OFF..];
        let status = d[2];
        // 0x06 means the value did not fit in one reply; restart using Read Tag Fragmented.
        if status == 0x06 {
            return self.read_tag_fragmented(tag_name);
        }
        if status != 0 {
            anyhow::bail!(
                "CIP read of '{tag_name}' failed: 0x{status:02x} ({})",
                cip_status_name(status)
            );
        }
        let skip = 4 + usize::from(d[3]) * 2;
        if d.len() < skip {
            anyhow::bail!("CIP read response truncated (ext_status_size={})", d[3]);
        }
        Ok(d[skip..].to_vec()) // [type_lo, type_hi, val_bytes...]
    }

    /// Read a tag whose value spans multiple replies, via Read Tag Fragmented (0x52).
    ///
    /// Request data is element count then a 32-bit byte offset — the reverse of the
    /// Template Read layout. Each reply repeats the 2- or 4-byte type prefix, so only the
    /// first one's prefix is kept and later fragments contribute value bytes alone.
    fn read_tag_fragmented(&mut self, tag_name: &str) -> Result<Vec<u8>> {
        const CIP_OFF: usize = 40;
        let path = symbolic_path(tag_name)?;
        let path_size = path_size_words(&path)?;
        let mut out: Vec<u8> = Vec::new();
        let mut offset: u32 = 0;
        let mut prefix_len = 0usize;

        loop {
            let off = offset.to_le_bytes();
            let mut cip = vec![0x52, path_size]; // Read Tag Fragmented
            cip.extend_from_slice(&path);
            cip.extend_from_slice(&[0x01, 0x00]); // element count = 1
            cip.extend_from_slice(&off);

            let resp = self.send_rr_data(&cip)?;
            if resp.len() < CIP_OFF + 4 {
                anyhow::bail!("Fragmented read of '{tag_name}': response too short");
            }
            let d = &resp[CIP_OFF..];
            let status = d[2];
            let partial = status == 0x06;
            if status != 0 && !partial {
                anyhow::bail!(
                    "Fragmented read of '{tag_name}' failed: 0x{status:02x} ({})",
                    cip_status_name(status)
                );
            }
            let skip = 4 + usize::from(d[3]) * 2;
            let payload = d
                .get(skip..)
                .context("Fragmented read: truncated extended status")?;

            if out.is_empty() {
                // Keep the type prefix from the first fragment only.
                prefix_len = if payload.len() >= 4 && payload[0] == 0xA0 && payload[1] == 0x02 {
                    4
                } else {
                    2
                };
                out.extend_from_slice(payload);
            } else {
                let body = payload.get(prefix_len..).unwrap_or(&[]);
                if partial && body.is_empty() {
                    anyhow::bail!(
                        "Fragmented read of '{tag_name}': empty fragment at offset {offset}"
                    );
                }
                out.extend_from_slice(body);
            }

            if !partial {
                break;
            }
            let advanced = u32::try_from(out.len().saturating_sub(prefix_len)).unwrap_or(u32::MAX);
            if advanced <= offset {
                anyhow::bail!("Fragmented read of '{tag_name}': made no progress at {offset}");
            }
            offset = advanced;
        }

        Ok(out)
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

/// Human-readable name for a CIP General Status code.
///
/// Covers the ODVA General Status table as documented by Rockwell; unknown codes
/// render as `"unknown"` so the caller still reports the raw hex value.
pub fn cip_status_name(status: u8) -> &'static str {
    match status {
        0x00 => "success",
        0x01 => "connection failure",
        0x02 => "resource unavailable",
        0x03 => "invalid parameter value",
        0x04 => "path segment error",
        0x05 => "path destination unknown",
        0x06 => "partial transfer",
        0x07 => "connection lost",
        0x08 => "service not supported",
        0x09 => "invalid attribute value",
        0x0A => "attribute list error",
        0x0B => "already in requested mode/state",
        0x0C => "object state conflict",
        0x0D => "object already exists",
        0x0E => "attribute not settable",
        0x0F => "privilege violation",
        0x10 => "device state conflict",
        0x11 => "reply data too large",
        0x12 => "fragmentation of a primitive value",
        0x13 => "not enough data",
        0x14 => "attribute not supported",
        0x15 => "too much data",
        0x16 => "object does not exist",
        0x17 => "service fragmentation sequence not in progress",
        0x18 => "no stored attribute data",
        0x19 => "store operation failure",
        0x1A => "routing failure, request packet too large",
        0x1B => "routing failure, response packet too large",
        0x1C => "missing attribute list entry data",
        0x1D => "invalid attribute value list",
        0x1E => "embedded service error",
        0x1F => "vendor specific error",
        0x20 => "invalid parameter",
        0x21 => "write-once value or medium already written",
        0x22 => "invalid reply received",
        0x23 => "buffer overflow",
        0x24 => "invalid message format",
        0x25 => "key failure in path",
        0x26 => "path size invalid",
        0x27 => "unexpected attribute in list",
        0x28 => "invalid member ID",
        0x29 => "member not settable",
        0x2A => "group 2 only server general failure",
        0x2B => "unknown Modbus error",
        0x2C => "attribute not gettable",
        _ => "unknown",
    }
}

/// Template Object (class 0x6C) attributes needed to read and parse a UDT definition.
#[derive(Debug, Clone, Copy)]
struct TemplateInfo {
    /// Attribute 4: size of the template definition in 32-bit words.
    object_definition_size: u32,
    /// Attribute 2: number of members in the template.
    member_count: u16,
    /// Attribute 1: structure handle. Distinct from the template instance id.
    handle: u16,
    /// Attribute 5: byte size of one instance. `None` when the controller declines it.
    structure_size: Option<u32>,
}

/// Fetch Template Object attributes via service 0x03 (`Get_Attribute_List`) on class 0x6C.
///
/// Requests attributes 4 (object definition size, UDINT), 2 (member count, UINT),
/// 1 (structure handle, UINT) and 5 (structure size, UDINT).
///
/// Order matters. A non-zero per-attribute status omits that attribute's value, so there is no
/// safe way to resync and the parse must stop — everything after a failed attribute is lost.
/// pycomm3 requests attribute 5 where pylogix requests 3, so 5 is the one in doubt; putting it
/// **last** means an unsupported attribute 5 costs only the optional stride, never the three
/// attributes template parsing actually depends on.
fn get_template_attributes(session: &mut EipSession, template_id: u16) -> Result<TemplateInfo> {
    const CIP_OFF: usize = 40;
    let id = template_id.to_le_bytes();
    let cip: Vec<u8> = vec![
        0x03,       // Get_Attribute_List
        0x03,       // path size = 3 words
        0x20, 0x6C, // class 0x6C (Template Object)
        0x25, 0x00, // 16-bit instance segment (pad)
        id[0], id[1],
        0x04, 0x00, // request 4 attributes
        0x04, 0x00, // attr 4: Template Object Definition Size (UDINT)
        0x02, 0x00, // attr 2: Template Member Count (UINT)
        0x01, 0x00, // attr 1: Structure Handle (UINT)
        0x05, 0x00, // attr 5: Structure Size (UDINT) — optional, requested last
    ];
    let resp = session.send_rr_data(&cip)?;
    if resp.len() < CIP_OFF + 4 {
        anyhow::bail!("Template 0x{template_id:03X} attributes: response too short");
    }
    let d = &resp[CIP_OFF..];
    let status = d[2];
    if status != 0 {
        anyhow::bail!(
            "Template 0x{template_id:03X} attributes: CIP 0x{status:02x} ({})",
            cip_status_name(status)
        );
    }
    let ext = d[3] as usize;
    let data = d
        .get(4 + ext * 2..)
        .context("Template attributes: truncated extended status")?;
    parse_template_attributes(data)
        .with_context(|| format!("Template 0x{template_id:03X} attributes"))
}

/// Parse a `Get_Attribute_List` reply body for attributes 4 (UDINT), 2 (UINT), 1 (UINT).
///
/// Body layout: `attr_count(UINT)` then, per attribute, `id(UINT) status(UINT) value`.
/// Values appear in the order requested, each at its own width.
fn parse_template_attributes(data: &[u8]) -> Result<TemplateInfo> {
    if data.len() < 2 {
        anyhow::bail!("empty attribute list");
    }
    let mut pos = 2usize;
    let mut object_definition_size = 0u32;
    let mut member_count = 0u16;
    let mut handle = 0u16;
    let mut structure_size = None;

    for &(expected_id, width) in &[(4u16, 4usize), (2, 2), (1, 2), (5, 4)] {
        if pos + 4 > data.len() {
            break;
        }
        let attr_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let attr_status = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;
        if attr_status != 0 || attr_id != expected_id {
            break; // value is absent on error: no safe way to resync
        }
        if pos + width > data.len() {
            break;
        }
        match attr_id {
            4 => {
                object_definition_size =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            }
            2 => member_count = u16::from_le_bytes([data[pos], data[pos + 1]]),
            1 => handle = u16::from_le_bytes([data[pos], data[pos + 1]]),
            5 => {
                structure_size = Some(u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]));
            }
            _ => {}
        }
        pos += width;
    }

    if member_count == 0 {
        anyhow::bail!("member count is 0");
    }
    if object_definition_size == 0 {
        anyhow::bail!("object definition size is 0");
    }

    Ok(TemplateInfo { object_definition_size, member_count, handle, structure_size })
}

/// Number of bytes the controller does not return from the template definition.
///
/// pycomm3 uses 21; the Rockwell data-access manual is cited as 23. The fragment loop
/// below is driven by CIP status rather than this figure, so a small error only changes
/// how many round trips happen — the controller reports 0x00 when it has sent everything.
const TEMPLATE_DEF_OVERHEAD: u32 = 23;

/// Read a Template Object definition via service 0x4C (Template Read).
///
/// Request data is `offset` (UDINT) *then* byte count (UINT) — both pycomm3 and pylogix
/// agree on this order. Loops while the controller reports 0x06 (Partial Transfer).
/// Returns `[member_count × 8 descriptor bytes] ++ [NUL-terminated name strings]`.
fn read_template_body(
    session: &mut EipSession,
    template_id: u16,
    info: TemplateInfo,
) -> Result<Vec<u8>> {
    const CIP_OFF: usize = 40;
    let id = template_id.to_le_bytes();
    let total = info
        .object_definition_size
        .saturating_mul(4)
        .saturating_sub(TEMPLATE_DEF_OVERHEAD);
    let mut raw_body: Vec<u8> = Vec::new();
    let mut offset: u32 = 0;

    loop {
        let remaining = total.saturating_sub(offset);
        if remaining == 0 {
            break;
        }
        let off = offset.to_le_bytes();
        let count = u16::try_from(remaining).unwrap_or(u16::MAX).to_le_bytes();
        let cip: Vec<u8> = vec![
            0x4C,       // service: Template Read (Rockwell extension of Read Tag)
            0x03,       // path size in words
            0x20, 0x6C, // class 0x6C (Template Object)
            0x25, 0x00, // 16-bit instance segment
            id[0], id[1],
            off[0], off[1], off[2], off[3], // byte offset (UDINT) — must precede the count
            count[0], count[1],             // bytes requested (UINT)
        ];
        let resp = session.send_rr_data(&cip)?;
        if resp.len() < CIP_OFF + 4 {
            anyhow::bail!("Template 0x{template_id:03X} read: response too short");
        }
        let d = &resp[CIP_OFF..];
        let status = d[2];
        let partial = status == 0x06;
        if status != 0 && !partial {
            anyhow::bail!(
                "Template 0x{template_id:03X} read: CIP 0x{status:02x} ({})",
                cip_status_name(status)
            );
        }
        let ext = d[3] as usize;
        let chunk_data = d
            .get(4 + ext * 2..)
            .context("Template read: truncated extended status")?;

        // A 0x06 with no payload would leave `offset` unchanged and spin forever.
        if partial && chunk_data.is_empty() {
            anyhow::bail!(
                "Template 0x{template_id:03X} read: empty partial fragment at offset {offset}"
            );
        }
        raw_body.extend_from_slice(chunk_data);
        if !partial {
            break;
        }
        offset = offset.saturating_add(u32::try_from(chunk_data.len()).unwrap_or(u32::MAX));
    }

    Ok(raw_body)
}

/// Download the Template Object (class 0x6C) for one UDT instance.
///
/// Returns the member fields plus the instance byte size, or an error if the controller does
/// not support the Template Object or the `template_id` is unknown.
fn download_template(session: &mut EipSession, template_id: u16) -> Result<TemplateDef> {
    // Body layout (descriptors start at byte 0 — there is no leading header):
    //   [0 .. member_count*8)   member descriptors, 8 bytes each
    //   [member_count*8 ..]     NUL-terminated ASCII strings
    //
    // Each descriptor is:  type_info(UINT) | type word(UINT) | byte offset(UDINT)
    // The first string is the *template's own* name and carries a ';' separator
    // (e.g. "LIT_Type;n0_ABC"); member names follow it in order.
    // Members whose name starts with '?' are Rockwell-internal and are skipped.

    let info = get_template_attributes(session, template_id)?;

    if info.member_count > 512 {
        anyhow::bail!(
            "Template 0x{template_id:03X}: implausible member count {}",
            info.member_count
        );
    }

    let raw_body = read_template_body(session, template_id, info)?;
    let descriptors_len = info.member_count as usize * 8;

    if raw_body.len() < descriptors_len {
        anyhow::bail!(
            "Template 0x{template_id:03X}: definition is {} bytes, need {descriptors_len} \
             for {} members (definition size {} words, handle 0x{:04X})",
            raw_body.len(),
            info.member_count,
            info.object_definition_size,
            info.handle
        );
    }

    Ok(TemplateDef {
        fields: parse_template_body(&raw_body, info.member_count),
        size: info.structure_size,
    })
}

/// Parse a Template Object definition body into member fields.
///
/// `raw` must hold at least `member_count * 8` bytes. Descriptors come first, then a run of
/// NUL-terminated strings whose first `';'`-bearing entry is the template's own name.
fn parse_template_body(raw: &[u8], member_count: u16) -> Vec<TemplateField> {
    let descriptors_len = member_count as usize * 8;
    if raw.len() < descriptors_len {
        return Vec::new();
    }

    // Consume the template's own name, then take one name per member in order.
    let mut strings = raw[descriptors_len..]
        .split(|&b| b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned());
    let _template_name = strings
        .by_ref()
        .find(|s| s.contains(';'))
        .map(|s| s.split(';').next().unwrap_or_default().to_string());

    let mut fields = Vec::with_capacity(member_count as usize);
    for i in 0..member_count as usize {
        let base = i * 8;
        let type_info = u16::from_le_bytes([raw[base], raw[base + 1]]);
        let cip_type = u16::from_le_bytes([raw[base + 2], raw[base + 3]]);
        let offset = u32::from_le_bytes([raw[base + 4], raw[base + 5], raw[base + 6], raw[base + 7]]);
        let Some(name) = strings.next() else { break };

        if is_visible_member(&name) {
            fields.push(TemplateField { name, cip_type, type_info, offset });
        }
    }

    fields
}

/// True for UDT members a user authored, false for compiler-generated ones.
///
/// Logix pads and bit-hosts UDTs with synthetic members: `?`-prefixed internals,
/// `ZZZZZZZZZZ`-prefixed hidden padding (e.g. `ZZZZZZZZZZATS_IBF_UD0`) and `__`-prefixed
/// bit hosts (e.g. `__BitHost00`). None correspond to anything in the Studio 5000 view.
fn is_visible_member(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('?')
        && !name.starts_with("ZZZZZZZZZZ")
        && !name.starts_with("__")
}

/// Return true if a symbol-table entry is a tag a user would want to see.
///
/// Filters the controller's bookkeeping entries while keeping I/O module tags. Module tags
/// are named `<module>:<slot>:<C|I|O|S>` (e.g. `Local:1:C`) and hold real config/input/output
/// data, so a blanket rejection of names containing `':'` would discard them.
pub fn is_user_tag(name: &str, tag_type: u16) -> bool {
    if tag_type & 0x1000 != 0 {
        return false; // bit 12: controller-internal type
    }
    if name.starts_with("__") {
        return false;
    }
    if name.starts_with("Program:") || name.starts_with("Routine:") || name.starts_with("Task:") {
        return false;
    }
    if name.contains("Map:") || name.contains("Cxn:") {
        return false;
    }
    // Keep I/O module tags; reject any other namespaced name.
    let is_io_tag = [":C", ":I", ":O", ":S"].iter().any(|sfx| name.contains(sfx));
    !name.contains(':') || is_io_tag
}

/// Build the CIP path for a tag name, supporting UDT member access and array indices.
///
/// Logix resolves `Pump.Cmd.SP` as **three** ANSI Extended Symbolic segments (0x91), one per
/// component — not one segment holding the dotted string. Array subscripts become logical
/// element segments (0x28 for values under 256, else 0x29).
///
/// Returns the path bytes; each segment is padded to an even length as the encoding requires.
fn symbolic_path(tag_name: &str) -> Result<Vec<u8>> {
    if tag_name.is_empty() {
        anyhow::bail!("Tag name is empty");
    }
    let mut path = Vec::new();
    for part in tag_name.split('.') {
        // Split "Array[3]" into the name and any subscripts.
        let (name, subscripts) = match part.split_once('[') {
            Some((name, rest)) => (name, rest.trim_end_matches(']')),
            None => (part, ""),
        };
        if name.is_empty() {
            anyhow::bail!("Malformed tag path '{tag_name}': empty component");
        }
        let bytes = name.as_bytes();
        let len = u8::try_from(bytes.len())
            .map_err(|_| anyhow::anyhow!("Tag component '{name}' exceeds 255 bytes"))?;
        path.push(0x91);
        path.push(len);
        path.extend_from_slice(bytes);
        if !bytes.len().is_multiple_of(2) {
            path.push(0); // pad to a 16-bit boundary
        }
        for idx in subscripts.split(',').filter(|s| !s.trim().is_empty()) {
            let n: u32 = idx
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid array index '{idx}' in '{tag_name}'"))?;
            if let Ok(small) = u8::try_from(n) {
                path.extend_from_slice(&[0x28, small]);
            } else if let Ok(medium) = u16::try_from(n) {
                path.extend_from_slice(&[0x29, 0x00]);
                path.extend_from_slice(&medium.to_le_bytes());
            } else {
                path.extend_from_slice(&[0x2A, 0x00]);
                path.extend_from_slice(&n.to_le_bytes());
            }
        }
    }
    if path.len() % 2 != 0 {
        anyhow::bail!("Internal error: odd CIP path length for '{tag_name}'");
    }
    Ok(path)
}

/// Path size in 16-bit words, as the byte that follows a CIP service code.
fn path_size_words(path: &[u8]) -> Result<u8> {
    u8::try_from(path.len() / 2).map_err(|_| anyhow::anyhow!("CIP path too long"))
}

/// Array dimension count from bits 14-13 of a symbol type word (0 = scalar, max 3).
///
/// Bit 15 is the structure flag and bit 12 marks a controller-internal type; neither is
/// part of the dimension count, so masking wider than two bits lets them leak in.
#[must_use]
pub fn symbol_dimensions(tag_type: u16) -> u8 {
    u8::try_from((tag_type >> 13) & 0x03).unwrap_or(0)
}

/// Return true if `tag_type` is a user UDT (bit 15 set, bit 12 clear).
///
/// Bit 15 = structure flag; bit 12 = system/internal type (CONTROL, COUNTER, TIMER, etc.).
/// System structs (bit 12 set) have template IDs below 0x100 and no user-readable fields.
pub fn is_struct_type(tag_type: u16) -> bool {
    tag_type & 0x8000 != 0 && tag_type & 0x1000 == 0
}

/// Download UDT templates for every struct-typed tag and return the resulting map.
///
/// Opens its own EIP session. Errors on individual templates are silently skipped;
/// those tags will fall back to hex display.
pub fn enumerate_templates(ip: &str, port: u16, tags: &[LogixTag]) -> TemplateMap {
    /// Guards against a malformed template graph turning into unbounded CIP traffic.
    const MAX_TEMPLATES: usize = 512;

    let mut map = TemplateMap::new();

    // Only user UDTs: bit 15 set, bit 12 clear. The template id is bits 11-0.
    let mut pending: Vec<u16> = tags
        .iter()
        .filter(|t| is_struct_type(t.tag_type))
        .map(|t| t.tag_type & 0x0FFF)
        .collect();
    pending.sort_unstable();
    pending.dedup();

    if pending.is_empty() {
        return map;
    }

    let effective_port = if port == 0 { EIP_PORT } else { port };
    let Ok(mut session) = EipSession::connect(ip, effective_port) else {
        return map;
    };

    // Members can themselves be UDTs, so resolve transitively.
    let mut seen: std::collections::HashSet<u16> = pending.iter().copied().collect();
    while let Some(id) = pending.pop() {
        if map.len() >= MAX_TEMPLATES {
            break;
        }
        let Ok(def) = download_template(&mut session, id) else { continue };
        if def.fields.is_empty() {
            continue;
        }
        for nested in def.fields.iter().filter(|f| f.is_struct()) {
            let nested_id = nested.nested_template_id();
            if seen.insert(nested_id) {
                pending.push(nested_id);
            }
        }
        map.insert(id, def);
    }

    map
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

/// EtherNet/IP List Identity (command 0x63) over TCP: no session required.
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

    // CIP Get Attribute All on Identity Object (class 0x01, instance 1): Logix only
    let cip = &[0x01, 0x02, 0x20, 0x01, 0x24, 0x01];
    let resp = session.send_rr_data(cip)?;
    if resp.len() < CIP_OFF + 18 {
        anyhow::bail!(
            "Device returned {} bytes: not a Logix controller, or CIP Get Attribute All \
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
        let more = status == 0x06; // partial transfer: more data follows

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
            // CIP symbol record has NO padding after the name — symbol_type follows immediately.

            if pos + 2 > attr_data.len() {
                break;
            }
            let tag_type = u16::from_le_bytes([attr_data[pos], attr_data[pos + 1]]);
            let dimensions = symbol_dimensions(tag_type);
            pos += 2;

            last_instance = match instance_id.checked_add(1) {
                Some(n) => n,
                None => break,
            };

            if is_user_tag(&name, tag_type) {
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

/// Render a UDT/struct value as `{ Field: val, ... }` using downloaded template metadata.
///
/// Shows up to 8 fields; remaining fields are summarised as `... (N more fields)`.
/// Falls back gracefully when templates are unavailable.
fn decode_struct(data: &[u8], template_id: u16, templates: Option<&TemplateMap>) -> String {
    let def = templates
        .and_then(|m| m.get(&template_id))
        .filter(|d| !d.fields.is_empty());
    let Some(def) = def else {
        return format!("STRUCT(0x{template_id:03X})[{} bytes]", data.len());
    };
    let fields = &def.fields;

    // Logix STRING and its variants are structures; render them as text, not as fields.
    if let Some(text) = decode_logix_string(data, fields) {
        return text;
    }

    let mut parts = Vec::new();
    for field in fields.iter().take(8) {
        let start = field.offset as usize;
        if start >= data.len() {
            continue;
        }
        let field_raw = &data[start..];

        // BOOL members are packed: the descriptor's type_info is the bit within this byte.
        let val = if is_bool_type(field.cip_type) && !field.is_array() {
            let set = field_raw[0] & (1u8 << field.bit_pos()) != 0;
            if set { "true  (1)".to_string() } else { "false (0)".to_string() }
        } else {
            // Synthesise a CIP payload header so decode_value can be reused verbatim.
            let mut synthetic = vec![(field.cip_type & 0xFF) as u8, (field.cip_type >> 8) as u8];
            synthetic.extend_from_slice(field_raw);
            let elem = decode_value(field.cip_type, &synthetic, templates);
            if field.is_array() {
                format!("[{elem}, ... ×{}]", field.array_len())
            } else {
                elem
            }
        };
        parts.push(format!("{}: {}", field.name, val));
    }
    if fields.len() > 8 {
        parts.push(format!("... ({} more fields)", fields.len() - 8));
    }
    if parts.is_empty() {
        return format!("STRUCT(0x{template_id:03X})[{} bytes]", data.len());
    }
    format!("{{ {} }}", parts.join(", "))
}

/// True for CIP BOOL, including the packed-bit type codes Logix uses for BOOL members.
fn is_bool_type(cip_type: u16) -> bool {
    let code = (cip_type & 0xFF) as u8;
    code == 0xC1 || matches!(code, 0x00..=0x1F)
}

/// Render a Logix `STRING`-shaped structure as quoted text.
///
/// Logix `STRING` is a structure of `DINT Len` followed by `SINT DATA[n]`. Detecting the
/// shape rather than a specific structure handle covers `STRING`, `STRING_20` and any
/// user-defined string type with the same layout.
fn decode_logix_string(data: &[u8], fields: &[TemplateField]) -> Option<String> {
    let [len_field, data_field] = fields else { return None };
    if !len_field.name.eq_ignore_ascii_case("LEN") || !data_field.name.eq_ignore_ascii_case("DATA")
    {
        return None;
    }
    if (len_field.cip_type & 0xFF) != 0xC4 || !data_field.is_array() {
        return None;
    }

    let len_at = len_field.offset as usize;
    let data_at = data_field.offset as usize;
    let raw_len = i32::from_le_bytes([
        *data.get(len_at)?,
        *data.get(len_at + 1)?,
        *data.get(len_at + 2)?,
        *data.get(len_at + 3)?,
    ]);
    let len = usize::try_from(raw_len).ok()?;
    let capacity = data.len().saturating_sub(data_at);
    let text = data.get(data_at..data_at + len.min(capacity))?;
    Some(format!("\"{}\"", String::from_utf8_lossy(text)))
}

/// One decoded leaf value inside a UDT, addressable by its dotted member path.
#[derive(Debug, Clone)]
pub struct StructLeaf {
    /// Member path relative to the tag, e.g. `DIC.EMERGENCY_TM1.PRE`.
    /// Appending this to the tag name gives a CIP-addressable path.
    pub path: String,
    /// Rendered value.
    pub value: String,
    /// CIP type code of the leaf.
    pub cip_type: u16,
    /// Whether a single scalar write to this path is supported.
    pub writable: bool,
}

/// Maximum UDT nesting depth to walk. Deep enough for real programs, bounded so a
/// self-referential template graph cannot recurse forever.
const MAX_STRUCT_DEPTH: usize = 8;

/// Array elements to expand into individual rows before summarising the remainder.
/// A `DATA[82]` char array or a large REAL array would otherwise flood the table.
const MAX_ARRAY_ELEMENTS: usize = 64;

/// Flatten a UDT into individually addressable leaf values.
///
/// Nested UDTs are walked and their members joined with `.`, so each leaf's [`StructLeaf::path`]
/// can be appended to the tag name to read or write that member on its own. Array members are
/// reported as a single non-writable entry (writing one needs an element index).
#[must_use]
pub fn flatten_struct(
    data: &[u8],
    template_id: u16,
    templates: Option<&TemplateMap>,
) -> Vec<StructLeaf> {
    let mut out = Vec::new();
    flatten_into(data, template_id, templates, "", 0, &mut out);
    out
}

fn flatten_into(
    data: &[u8],
    template_id: u16,
    templates: Option<&TemplateMap>,
    prefix: &str,
    depth: usize,
    out: &mut Vec<StructLeaf>,
) {
    if depth >= MAX_STRUCT_DEPTH {
        return;
    }
    let Some(def) = templates.and_then(|m| m.get(&template_id)) else {
        return;
    };

    // A STRING-shaped UDT is text, not a LEN field plus 82 char rows.
    if let Some(text) = decode_logix_string(data, &def.fields) {
        let path = if prefix.is_empty() { "value".to_string() } else { prefix.to_string() };
        out.push(StructLeaf { path, value: text, cip_type: 0x00D0, writable: false });
        return;
    }

    for field in &def.fields {
        let path = if prefix.is_empty() {
            field.name.clone()
        } else {
            format!("{prefix}.{}", field.name)
        };
        let start = field.offset as usize;
        if start >= data.len() {
            continue;
        }
        let raw = &data[start..];

        if field.is_array() {
            flatten_array_member(raw, field, templates, &path, depth, out);
            continue;
        }

        // Nested UDT: recurse so its members become addressable in their own right.
        if field.is_struct() {
            let nested = field.nested_template_id();
            if templates.is_some_and(|m| m.contains_key(&nested)) {
                flatten_into(raw, nested, templates, &path, depth + 1, out);
                continue;
            }
        }

        let (value, writable) = if is_bool_type(field.cip_type) {
            let set = raw[0] & (1u8 << field.bit_pos()) != 0;
            (if set { "true".to_string() } else { "false".to_string() }, true)
        } else {
            let mut synthetic = vec![(field.cip_type & 0xFF) as u8, (field.cip_type >> 8) as u8];
            synthetic.extend_from_slice(raw);
            let rendered = decode_value(field.cip_type, &synthetic, templates);
            (rendered, is_writable_type(field.cip_type))
        };

        out.push(StructLeaf { path, value, cip_type: field.cip_type, writable });
    }
}

/// Emit one leaf per array element, so each is addressable as `Member[i]` and writable alone.
///
/// Declines to expand — emitting a single summary row instead — when the element stride cannot
/// be established: multi-dimensional members (whose per-dimension bounds the template
/// descriptor does not carry), and element types of unknown width. Guessing a stride would
/// produce a path that writes to the wrong element.
fn flatten_array_member(
    raw: &[u8],
    field: &TemplateField,
    templates: Option<&TemplateMap>,
    path: &str,
    depth: usize,
    out: &mut Vec<StructLeaf>,
) {
    let summary = |out: &mut Vec<StructLeaf>, note: &str| {
        out.push(StructLeaf {
            path: path.to_string(),
            value: format!("[{} elements — {note}]", field.array_len()),
            cip_type: field.cip_type,
            writable: false,
        });
    };

    if field.dimensions() > 1 {
        summary(out, "multi-dimensional, index it via the CLI");
        return;
    }

    let total = field.array_len() as usize;
    let shown = total.min(MAX_ARRAY_ELEMENTS);

    // Arrays of nested UDTs: stride by the instance size, then recurse per element.
    if field.is_struct() {
        let nested = field.nested_template_id();
        let Some(stride) = templates
            .and_then(|m| m.get(&nested))
            .and_then(TemplateDef::stride)
            .filter(|&s| s > 0)
        else {
            summary(out, "unknown struct stride");
            return;
        };
        for i in 0..shown {
            let at = i * stride;
            if at + stride > raw.len() {
                break;
            }
            flatten_into(
                &raw[at..],
                nested,
                templates,
                &format!("{path}[{i}]"),
                depth + 1,
                out,
            );
        }
        if total > shown {
            summary(out, &format!("showing {shown} of {total}"));
        }
        return;
    }

    // Logix packs a BOOL array into 32-bit words: element i is bit i%32 of word i/32,
    // not byte i. Writes go out as Member[i] and the controller resolves the bit itself,
    // so this arithmetic only affects what is displayed.
    if is_bool_type(field.cip_type) {
        for i in 0..shown {
            let byte = (i / 32) * 4 + (i % 32) / 8;
            let Some(&b) = raw.get(byte) else { break };
            let set = b & (1u8 << (i % 8)) != 0;
            out.push(StructLeaf {
                path: format!("{path}[{i}]"),
                value: if set { "true".to_string() } else { "false".to_string() },
                cip_type: field.cip_type & 0x1FFF, // drop the array bits for the element
                writable: true,
            });
        }
        if total > shown {
            summary(out, &format!("showing {shown} of {total}"));
        }
        return;
    }

    let elem_type = field.cip_type & 0x1FFF; // element type without the dimension bits
    let Some(stride) = cip_type_size(elem_type) else {
        summary(out, "unknown element width");
        return;
    };

    for i in 0..shown {
        let at = i * stride;
        if at + stride > raw.len() {
            break;
        }
        let mut synthetic = vec![(elem_type & 0xFF) as u8, (elem_type >> 8) as u8];
        synthetic.extend_from_slice(&raw[at..at + stride]);
        out.push(StructLeaf {
            path: format!("{path}[{i}]"),
            value: decode_value(elem_type, &synthetic, templates),
            cip_type: elem_type,
            writable: is_writable_type(elem_type),
        });
    }
    if total > shown {
        summary(out, &format!("showing {shown} of {total}"));
    }
}

/// True for scalar CIP types this driver can encode from user-entered text.
#[must_use]
pub fn is_writable_type(cip_type: u16) -> bool {
    if cip_type & 0x8000 != 0 || symbol_dimensions(cip_type) > 0 {
        return false;
    }
    let code = (cip_type & 0xFF) as u8;
    matches!(code, 0x00..=0x1F | 0xC1..=0xCB)
}

/// Encode user-entered text into CIP value bytes for `cip_type`.
///
/// Accepts `true`/`false`/`on`/`off`/`1`/`0` for BOOL, decimal (or `0x`-prefixed hex) for
/// integers, and decimal for floats. Rejects out-of-range values rather than truncating,
/// so a typo cannot silently write a different number to a controller.
pub fn encode_value_for_type(cip_type: u16, text: &str) -> Result<Vec<u8>> {
    let t = text.trim();
    if t.is_empty() {
        anyhow::bail!("Value is empty");
    }
    let code = (cip_type & 0xFF) as u8;

    // Packed-BOOL type codes (0x00-0x1F) and CIP BOOL both take a single byte.
    if is_bool_type(cip_type) {
        let on = match t.to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" | "set" => true,
            "0" | "false" | "off" | "no" | "clear" => false,
            other => anyhow::bail!("BOOL value must be true/false or 1/0, got '{other}'"),
        };
        return Ok(vec![u8::from(on)]);
    }

    let parse_int = |bits: u32, signed: bool| -> Result<i128> {
        let radix_val = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i128::from_str_radix(hex, 16)
        } else {
            t.parse::<i128>()
        };
        let v = radix_val.map_err(|_| anyhow::anyhow!("'{t}' is not a valid integer"))?;
        let (lo, hi) = if signed {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            (0, (1i128 << bits) - 1)
        };
        if v < lo || v > hi {
            anyhow::bail!("{v} is out of range for this type ({lo}..={hi})");
        }
        Ok(v)
    };

    match code {
        0xC2 => Ok(vec![i8::try_from(parse_int(8, true)?)?.to_le_bytes()[0]]),
        0xC3 => Ok(i16::try_from(parse_int(16, true)?)?.to_le_bytes().to_vec()),
        0xC4 => Ok(i32::try_from(parse_int(32, true)?)?.to_le_bytes().to_vec()),
        0xC5 => Ok(i64::try_from(parse_int(64, true)?)?.to_le_bytes().to_vec()),
        0xC6 => Ok(vec![u8::try_from(parse_int(8, false)?)?]),
        0xC7 => Ok(u16::try_from(parse_int(16, false)?)?.to_le_bytes().to_vec()),
        0xC8 => Ok(u32::try_from(parse_int(32, false)?)?.to_le_bytes().to_vec()),
        0xC9 => Ok(u64::try_from(parse_int(64, false)?)?.to_le_bytes().to_vec()),
        0xCA => {
            let v: f32 = t.parse().map_err(|_| anyhow::anyhow!("'{t}' is not a valid REAL"))?;
            if !v.is_finite() {
                anyhow::bail!("REAL value must be finite");
            }
            Ok(v.to_le_bytes().to_vec())
        }
        0xCB => {
            let v: f64 = t.parse().map_err(|_| anyhow::anyhow!("'{t}' is not a valid LREAL"))?;
            if !v.is_finite() {
                anyhow::bail!("LREAL value must be finite");
            }
            Ok(v.to_le_bytes().to_vec())
        }
        _ => anyhow::bail!("Writing CIP type 0x{code:02X} is not supported"),
    }
}

/// Strip the type prefix from a Read Tag payload, returning just the value bytes.
///
/// A structured reply is `A0 02 <handle:UINT> <data...>` — **4** bytes of type info, not 2.
/// The structure handle is metadata and is *not* the template instance id, so it is skipped
/// rather than used for lookup. Branching on the observed marker keeps this correct for
/// atomic replies (a plain 2-byte type word) and for firmware that omits the marker.
///
/// Template member offsets are relative to the start of the returned slice, so every caller
/// that indexes into struct data must go through this rather than slicing a fixed amount.
#[must_use]
pub fn struct_body(cip_data: &[u8]) -> &[u8] {
    if cip_data.len() >= 4 && cip_data[0] == 0xA0 && cip_data[1] == 0x02 {
        &cip_data[4..]
    } else {
        cip_data.get(2..).unwrap_or(&[])
    }
}

/// Decode a CIP Read Tag response payload into a human-readable value string.
///
/// `cip_data` is the payload returned by `read_tag` / `read_tags_bulk`:
/// first 2 bytes are the type word echo, the rest are the element bytes.
/// Pass `templates` to enable UDT struct decoding; `None` falls back to hex.
#[allow(clippy::too_many_lines)] // single-responsibility type dispatch over the full CIP type table
pub fn decode_value(tag_type: u16, cip_data: &[u8], templates: Option<&TemplateMap>) -> String {
    if cip_data.len() < 2 {
        return "-".to_string();
    }
    // Guard: UDT/struct flag (bit 15) must be checked before any atomic match,
    // because the lower byte of a template_id can collide with an atomic code.
    if tag_type & 0x8000 != 0 {
        let template_id = tag_type & 0x0FFF;
        return decode_struct(struct_body(cip_data), template_id, templates);
    }
    let val = &cip_data[2..]; // skip 2-byte type word echo
    let type_code = (tag_type & 0xFF) as u8;

    match type_code {
        // BOOL: 1 byte; value is 0 or non-zero
        0x00..=0x1F | 0xC1 => {
            if val.is_empty() { return "?".to_string(); }
            if val[0] != 0 { "true  (1)".to_string() } else { "false (0)".to_string() }
        }
        // SINT: 1-byte signed
        0xC2 => {
            if val.is_empty() { return "?".to_string(); }
            i8::from_ne_bytes([val[0]]).to_string()
        }
        // INT: 2-byte signed
        0xC3 => {
            if val.len() < 2 { return "?".to_string(); }
            i16::from_le_bytes([val[0], val[1]]).to_string()
        }
        // DINT: 4-byte signed
        0xC4 => {
            if val.len() < 4 { return "?".to_string(); }
            i32::from_le_bytes([val[0], val[1], val[2], val[3]]).to_string()
        }
        // LINT: 8-byte signed
        0xC5 => {
            if val.len() < 8 { return "?".to_string(); }
            i64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]).to_string()
        }
        // USINT: 1-byte unsigned
        0xC6 => {
            if val.is_empty() { return "?".to_string(); }
            val[0].to_string()
        }
        // UINT: 2-byte unsigned
        0xC7 => {
            if val.len() < 2 { return "?".to_string(); }
            u16::from_le_bytes([val[0], val[1]]).to_string()
        }
        // UDINT: 4-byte unsigned
        0xC8 => {
            if val.len() < 4 { return "?".to_string(); }
            u32::from_le_bytes([val[0], val[1], val[2], val[3]]).to_string()
        }
        // ULINT: 8-byte unsigned
        0xC9 => {
            if val.len() < 8 { return "?".to_string(); }
            u64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]).to_string()
        }
        // REAL: 4-byte IEEE 754 single
        0xCA => {
            if val.len() < 4 { return "?".to_string(); }
            let f = f32::from_le_bytes([val[0], val[1], val[2], val[3]]);
            format!("{f}")
        }
        // LREAL: 8-byte IEEE 754 double
        0xCB => {
            if val.len() < 8 { return "?".to_string(); }
            let f = f64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]);
            format!("{f}")
        }
        // STIME / TIME: 4-byte signed milliseconds
        0xCC | 0xDB => {
            if val.len() < 4 { return "?".to_string(); }
            let ms = i32::from_le_bytes([val[0], val[1], val[2], val[3]]);
            format!("{ms}ms")
        }
        // DATE: 2-byte unsigned days since 1972-01-01
        0xCD => {
            if val.len() < 2 { return "?".to_string(); }
            let days = u16::from_le_bytes([val[0], val[1]]);
            format!("{days}d")
        }
        // TIME_OF_DAY: 4-byte unsigned milliseconds since midnight
        0xCE => {
            if val.len() < 4 { return "?".to_string(); }
            let ms = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
            let h = ms / 3_600_000;
            let m = (ms % 3_600_000) / 60_000;
            let s = (ms % 60_000) / 1_000;
            format!("{h:02}:{m:02}:{s:02}")
        }
        // DATE_AND_TIME: 2 bytes date (days) + 4 bytes time (ms since midnight)
        0xCF => {
            if val.len() < 6 { return "?".to_string(); }
            let days = u16::from_le_bytes([val[0], val[1]]);
            let ms = u32::from_le_bytes([val[2], val[3], val[4], val[5]]);
            let h = ms / 3_600_000;
            let m = (ms % 3_600_000) / 60_000;
            let s = (ms % 60_000) / 1_000;
            format!("{days}d {h:02}:{m:02}:{s:02}")
        }
        // STRING: Logix format: 4-byte length + chars
        0xD0 => {
            if val.len() < 4 { return "\"?\"".to_string(); }
            let len = u32::from_le_bytes([val[0], val[1], val[2], val[3]]) as usize;
            if val.len() >= 4 + len {
                format!("\"{}\"", String::from_utf8_lossy(&val[4..4 + len]))
            } else {
                "\"?\"".to_string()
            }
        }
        // BYTE: 1-byte hex
        0xD1 => {
            if val.is_empty() { return "?".to_string(); }
            format!("0x{:02X}", val[0])
        }
        // WORD: 2-byte hex
        0xD2 => {
            if val.len() < 2 { return "?".to_string(); }
            format!("0x{:04X}", u16::from_le_bytes([val[0], val[1]]))
        }
        // DWORD: 4-byte hex
        0xD3 => {
            if val.len() < 4 { return "?".to_string(); }
            format!("0x{:08X}", u32::from_le_bytes([val[0], val[1], val[2], val[3]]))
        }
        // LWORD: 8-byte hex
        0xD4 => {
            if val.len() < 8 { return "?".to_string(); }
            format!("0x{:016X}", u64::from_le_bytes([val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7]]))
        }
        // Unrecognised type code: likely a UDT on firmware that does not set bit 15
        // in the symbol table (non-standard encoding). Route through decode_struct
        // so at minimum we get STRUCT(0xXXX)[N bytes] instead of a raw hex dump.
        _ => {
            if val.is_empty() { return "-".to_string(); }
            let template_id = tag_type & 0x0FFF;
            if template_id != 0 {
                return decode_struct(val, template_id, templates);
            }
            let mut hex = String::with_capacity(val.len() * 2);
            for b in val { let _ = write!(hex, "{b:02x}"); }
            format!("0x{hex}")
        }
    }
}

/// Write raw bytes to a named tag.
/// Pass `port = 0` for the default EtherNet/IP port (44818).
pub fn write_tag(ip: &str, port: u16, tag_name: &str, type_code: u16, value_bytes: &[u8]) -> Result<()> {
    const CIP_OFF: usize = 40;
    let mut session = EipSession::connect(ip, port)?;

    // Supports UDT member paths such as "Pump.Cmd.SP", not just top-level tag names.
    let path = symbolic_path(tag_name)?;

    let mut cip = vec![0x4d, path_size_words(&path)?]; // Write Tag service
    cip.extend_from_slice(&path);
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
/// Bit 15: UDT/template flag.  Bits 14–13: array dimension count (0–3).  Bit 12: system
/// type.  Bits 7–0: CIP base type code.  Type codes 0x00–0x1F are bit-packed BOOLs: the
/// lower byte is the bit index within a storage DWORD.
pub fn type_name(tag_type: u16) -> String {
    let is_struct = tag_type & 0x8000 != 0;
    let dims = symbol_dimensions(tag_type);

    if is_struct {
        let id = tag_type & 0x0FFF;
        let base = format!("STRUCT({id:#05x})");
        return if dims == 0 { base } else { format!("{base}[{dims}D]") };
    }

    let type_code = (tag_type & 0xFF) as u8;
    if matches!(type_code, 0x00..=0x1F) {
        return if dims == 0 {
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

    if dims == 0 {
        base.to_string()
    } else {
        format!("{base}[{dims}D]")
    }
}

/// Decodes the type word into `(base_type_name, dims_label)`.
///
/// `base_type_name`: e.g. `"BOOL"`, `"DINT"`, `"STRUCT(0x012)"`
/// `dims_label`: `"1D"` / `"2D"` / `"3D"` or `"-"` for scalars
pub fn type_parts(tag_type: u16) -> (String, &'static str) {
    let is_struct = tag_type & 0x8000 != 0;
    let dims = symbol_dimensions(tag_type);

    let dims_label = |dims: u8| match dims {
        1 => "1D",
        2 => "2D",
        3 => "3D",
        _ => "-",
    };

    if is_struct {
        let id = tag_type & 0x0FFF;
        return (format!("STRUCT({id:#05x})"), dims_label(dims));
    }

    let type_code = (tag_type & 0xFF) as u8;
    if matches!(type_code, 0x00..=0x1F) {
        return (format!("BOOL.b{type_code}"), dims_label(dims));
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

    (base.to_string(), dims_label(dims))
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
    use super::{
        cip_status_name, cip_type_size, decode_value, is_user_tag, parse_list_identity_response,
        parse_template_attributes, parse_template_body, type_name, type_parts, TemplateDef,
        TemplateField, TemplateMap,
    };

    // ── Template Object attribute parsing (byte-exact) ───────────────────────

    /// Build a `Get_Attribute_List` reply body for attrs 4 (UDINT), 2 (UINT), 1 (UINT).
    fn attr_reply(def_words: u32, members: u16, handle: u16) -> Vec<u8> {
        let mut d = vec![0x03, 0x00]; // attr_count = 3
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // status OK
        d.extend_from_slice(&def_words.to_le_bytes()); // UDINT
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&members.to_le_bytes()); // UINT
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&handle.to_le_bytes()); // UINT
        d
    }

    #[test]
    fn template_attributes_read_each_field_at_its_own_width() {
        // Attr 4 is a UDINT: a 4-byte read is required. Reading it as a UINT would
        // yield 269 for this input and be mistaken for a member count.
        let info = parse_template_attributes(&attr_reply(269, 5, 0x0FCE)).unwrap();
        assert_eq!(info.object_definition_size, 269);
        assert_eq!(info.member_count, 5);
        assert_eq!(info.handle, 0x0FCE);
    }

    #[test]
    fn template_attributes_reject_zero_member_count() {
        assert!(parse_template_attributes(&attr_reply(269, 0, 1)).is_err());
    }

    #[test]
    fn template_attributes_reject_zero_definition_size() {
        assert!(parse_template_attributes(&attr_reply(0, 5, 1)).is_err());
    }

    #[test]
    fn template_attributes_reject_empty_body() {
        assert!(parse_template_attributes(&[]).is_err());
    }

    #[test]
    fn template_attributes_stop_at_failed_attribute() {
        // A non-zero per-attribute status omits the value, so nothing after it is trustworthy.
        let mut d = vec![0x03, 0x00];
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&0x14u16.to_le_bytes()); // attribute not supported
        assert!(parse_template_attributes(&d).is_err());
    }

    // ── Template body parsing (byte-exact) ───────────────────────────────────

    /// 8-byte member descriptor: `type_info` (UINT) then type word (UINT) then offset (UDINT).
    fn descriptor(type_info: u16, type_word: u16, offset: u32) -> Vec<u8> {
        let mut d = Vec::with_capacity(8);
        d.extend_from_slice(&type_info.to_le_bytes());
        d.extend_from_slice(&type_word.to_le_bytes());
        d.extend_from_slice(&offset.to_le_bytes());
        d
    }

    #[test]
    fn template_body_reads_descriptor_fields_in_the_right_order() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&descriptor(0, 0x00CA, 0)); // REAL @0
        raw.extend_from_slice(&descriptor(0, 0x00C4, 4)); // DINT @4
        raw.extend_from_slice(b"LIT_Type;n0_ABC\0PV\0Mode\0");

        let fields = parse_template_body(&raw, 2);
        assert_eq!(fields.len(), 2);
        // type word lives at bytes 2..4 — if the pair were swapped these would be 0.
        assert_eq!(fields[0].cip_type, 0x00CA);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[1].cip_type, 0x00C4);
        assert_eq!(fields[1].offset, 4);
    }

    #[test]
    fn template_body_skips_the_template_name_so_members_align() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&descriptor(0, 0x00CA, 0));
        raw.extend_from_slice(&descriptor(0, 0x00CA, 4));
        raw.extend_from_slice(&descriptor(0, 0x00CA, 8));
        raw.extend_from_slice(b"LIT_Type;n0_ABC\0PV\0SP\0OUT\0");

        let fields = parse_template_body(&raw, 3);
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        // Without the ';' skip these would be ["LIT_Type;n0_ABC", "PV", "SP"].
        assert_eq!(names, ["PV", "SP", "OUT"]);
    }

    #[test]
    fn template_body_skips_rockwell_internal_members() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&descriptor(0, 0x00CA, 0));
        raw.extend_from_slice(&descriptor(0, 0x00C4, 4));
        raw.extend_from_slice(b"T;x\0PV\0?Internal\0");

        let fields = parse_template_body(&raw, 2);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "PV");
    }

    #[test]
    fn template_body_too_short_for_descriptors_yields_nothing() {
        assert!(parse_template_body(&[0u8; 4], 2).is_empty());
    }

    #[test]
    fn template_body_marks_nested_struct_members() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&descriptor(0, 0x8123, 0)); // bit 15 set → nested UDT
        raw.extend_from_slice(b"Outer;x\0Inner\0");

        let fields = parse_template_body(&raw, 1);
        assert!(fields[0].is_struct());
        assert_eq!(fields[0].nested_template_id(), 0x123);
    }

    #[test]
    fn template_field_array_dimensions_come_from_bits_14_13() {
        // 0x2000 = 1 dimension. Testing bit 0x2000 alone would misread 2D/3D members.
        let one_d = TemplateField {
            name: "A".into(), cip_type: 0x20CA, type_info: 10, offset: 0,
        };
        assert_eq!(one_d.dimensions(), 1);
        assert!(one_d.is_array());
        assert_eq!(one_d.array_len(), 10);

        let three_d = TemplateField {
            name: "B".into(), cip_type: 0x60CA, type_info: 4, offset: 0,
        };
        assert_eq!(three_d.dimensions(), 3);

        let scalar = TemplateField {
            name: "C".into(), cip_type: 0x00CA, type_info: 7, offset: 0,
        };
        assert!(!scalar.is_array());
        assert_eq!(scalar.array_len(), 1, "type_info must be ignored for scalars");
    }

    // ── Structured read reply: the A0 02 handle prefix ───────────────────────

    #[test]
    fn struct_read_skips_the_two_byte_structure_handle() {
        let tag_type: u16 = 0x8ABC;
        let mut map = TemplateMap::new();
        map.insert(
            0xABC,
            TemplateDef::from_fields(vec![
                TemplateField { name: "PV".into(), cip_type: 0xCA, type_info: 0, offset: 0 },
                TemplateField { name: "SP".into(), cip_type: 0xCA, type_info: 0, offset: 4 },
            ]),
        );

        // A0 02 <handle> then the struct body — 4 bytes of type info, not 2.
        let mut cip = vec![0xA0, 0x02, 0xCE, 0x0F];
        cip.extend_from_slice(&2.5f32.to_le_bytes());
        cip.extend_from_slice(&7.5f32.to_le_bytes());

        let out = decode_value(tag_type, &cip, Some(&map));
        assert!(out.contains("PV: 2.5"), "PV misaligned: {out}");
        assert!(out.contains("SP: 7.5"), "SP misaligned: {out}");
    }

    #[test]
    fn struct_body_strips_marker_and_handle() {
        // 4 bytes of type info when the A0 02 marker is present.
        let with_marker = [0xA0, 0x02, 0x34, 0x12, 1, 2, 3, 4];
        assert_eq!(super::struct_body(&with_marker), &[1, 2, 3, 4]);
        // A plain type word echo is only 2 bytes.
        let atomic = [0xC4, 0x00, 1, 2, 3, 4];
        assert_eq!(super::struct_body(&atomic), &[1, 2, 3, 4]);
        // Length must come out 4-aligned for a 4-aligned struct, which the UI relies on.
        assert_eq!(super::struct_body(&with_marker).len() % 4, 0);
        // Short inputs must not panic.
        assert!(super::struct_body(&[]).is_empty());
        assert!(super::struct_body(&[0xA0]).is_empty());
        assert!(super::struct_body(&[0xA0, 0x02]).is_empty());
    }

    #[test]
    fn struct_read_without_the_marker_still_skips_two() {
        let tag_type: u16 = 0x8ABC;
        let mut map = TemplateMap::new();
        map.insert(
            0xABC,
            TemplateDef::from_fields(vec![TemplateField { name: "PV".into(), cip_type: 0xCA, type_info: 0, offset: 0 }]),
        );
        let mut cip = vec![0xBC, 0x8A]; // plain type word echo, no A0 02
        cip.extend_from_slice(&1.25f32.to_le_bytes());

        assert!(decode_value(tag_type, &cip, Some(&map)).contains("PV: 1.25"));
    }

    // ── Packed BOOL members ─────────────────────────────────────────────────

    #[test]
    fn packed_bools_in_one_byte_decode_independently() {
        let tag_type: u16 = 0x8AAA;
        let mut map = TemplateMap::new();
        map.insert(
            0xAAA,
            TemplateDef::from_fields(vec![
                TemplateField { name: "B0".into(), cip_type: 0xC1, type_info: 0, offset: 0 },
                TemplateField { name: "B1".into(), cip_type: 0xC1, type_info: 1, offset: 0 },
                TemplateField { name: "B2".into(), cip_type: 0xC1, type_info: 2, offset: 0 },
                TemplateField { name: "B3".into(), cip_type: 0xC1, type_info: 3, offset: 0 },
            ]),
        );
        // 0b1010 → bits 1 and 3 set, bits 0 and 2 clear.
        let cip = vec![0xA0, 0x02, 0x00, 0x00, 0b1010];

        let out = decode_value(tag_type, &cip, Some(&map));
        assert!(out.contains("B0: false"), "B0 wrong: {out}");
        assert!(out.contains("B1: true"), "B1 wrong: {out}");
        assert!(out.contains("B2: false"), "B2 wrong: {out}");
        assert!(out.contains("B3: true"), "B3 wrong: {out}");
    }

    // ── Logix STRING rendering ──────────────────────────────────────────────

    #[test]
    fn logix_string_struct_renders_as_text() {
        let tag_type: u16 = 0x8FCE;
        let mut map = TemplateMap::new();
        map.insert(
            0xFCE,
            TemplateDef::from_fields(vec![
                TemplateField { name: "LEN".into(), cip_type: 0xC4, type_info: 0, offset: 0 },
                TemplateField { name: "DATA".into(), cip_type: 0x20C2, type_info: 82, offset: 4 },
            ]),
        );
        let mut cip = vec![0xA0, 0x02, 0x00, 0x00];
        cip.extend_from_slice(&5i32.to_le_bytes()); // LEN = 5
        cip.extend_from_slice(b"PUMP1trailing garbage");

        // Truncated to LEN, not the full DATA array.
        assert_eq!(decode_value(tag_type, &cip, Some(&map)), "\"PUMP1\"");
    }

    #[test]
    fn logix_string_with_zero_length_renders_empty() {
        let tag_type: u16 = 0x8FCE;
        let mut map = TemplateMap::new();
        map.insert(
            0xFCE,
            TemplateDef::from_fields(vec![
                TemplateField { name: "LEN".into(), cip_type: 0xC4, type_info: 0, offset: 0 },
                TemplateField { name: "DATA".into(), cip_type: 0x20C2, type_info: 82, offset: 4 },
            ]),
        );
        let mut cip = vec![0xA0, 0x02, 0x00, 0x00];
        cip.extend_from_slice(&0i32.to_le_bytes());
        cip.extend_from_slice(b"ignored");

        assert_eq!(decode_value(tag_type, &cip, Some(&map)), "\"\"");
    }

    // ── Symbol-table filtering ──────────────────────────────────────────────

    #[test]
    fn user_tag_filter_keeps_io_module_tags() {
        // These were being dropped by a blanket ':' rejection.
        assert!(is_user_tag("Local:1:C", 0x00C4));
        assert!(is_user_tag("Local:2:I", 0x00C4));
        assert!(is_user_tag("Local:3:O", 0x00C4));
        assert!(is_user_tag("Rack01:5:S", 0x00C4));
    }

    #[test]
    fn user_tag_filter_drops_controller_bookkeeping() {
        assert!(!is_user_tag("__internal", 0x00C4));
        assert!(!is_user_tag("Program:MainProgram", 0x00C4));
        assert!(!is_user_tag("Routine:Main", 0x00C4));
        assert!(!is_user_tag("Task:MainTask", 0x00C4));
        assert!(!is_user_tag("Local:1:Map:x", 0x00C4));
        assert!(!is_user_tag("Cxn:something", 0x00C4));
    }

    #[test]
    fn user_tag_filter_drops_system_typed_tags() {
        // Bit 12 marks a controller-internal type regardless of the name.
        assert!(!is_user_tag("PlainName", 0x1000));
        assert!(!is_user_tag("SomeStruct", 0x9123));
        assert!(is_user_tag("SomeStruct", 0x8123));
    }

    #[test]
    fn user_tag_filter_keeps_ordinary_names() {
        assert!(is_user_tag("LE_LIT_4002", 0x8F8B));
        assert!(is_user_tag("PUMP_RUN", 0x00C1));
    }

    // ── Symbolic path construction ──────────────────────────────────────────

    #[test]
    fn symbolic_path_single_name() {
        // 0x91, len, "PV", padded to even
        assert_eq!(super::symbolic_path("PV").unwrap(), vec![0x91, 2, b'P', b'V']);
    }

    #[test]
    fn symbolic_path_pads_odd_length_names() {
        let p = super::symbolic_path("ABC").unwrap();
        assert_eq!(p, vec![0x91, 3, b'A', b'B', b'C', 0x00]);
        assert_eq!(p.len() % 2, 0);
    }

    #[test]
    fn symbolic_path_udt_member_emits_one_segment_per_component() {
        // Logix needs three separate 0x91 segments, not one holding "A.B.C".
        let p = super::symbolic_path("A.BB.C").unwrap();
        assert_eq!(
            p,
            vec![0x91, 1, b'A', 0x00, 0x91, 2, b'B', b'B', 0x91, 1, b'C', 0x00]
        );
        assert_eq!(p.split(|&b| b == 0x91).count() - 1, 3, "expected 3 symbolic segments");
    }

    #[test]
    fn symbolic_path_array_index_uses_element_segment() {
        let p = super::symbolic_path("ARR[5]").unwrap();
        assert_eq!(p, vec![0x91, 3, b'A', b'R', b'R', 0x00, 0x28, 5]);
        // Indices past 255 need the 16-bit form.
        let big = super::symbolic_path("ARR[300]").unwrap();
        assert_eq!(&big[6..], &[0x29, 0x00, 0x2C, 0x01]);
    }

    #[test]
    fn symbolic_path_rejects_malformed_input() {
        assert!(super::symbolic_path("").is_err());
        assert!(super::symbolic_path("A..B").is_err());
        assert!(super::symbolic_path("ARR[x]").is_err());
    }

    #[test]
    fn path_size_words_counts_16_bit_words() {
        let p = super::symbolic_path("ABC").unwrap(); // 6 bytes
        assert_eq!(super::path_size_words(&p).unwrap(), 3);
    }

    // ── Value encoding for writes ───────────────────────────────────────────

    #[test]
    fn encode_bool_accepts_words_and_digits() {
        for on in ["true", "TRUE", "1", "on", "yes"] {
            assert_eq!(super::encode_value_for_type(0xC1, on).unwrap(), vec![1]);
        }
        for off in ["false", "0", "off", "no"] {
            assert_eq!(super::encode_value_for_type(0xC1, off).unwrap(), vec![0]);
        }
        assert!(super::encode_value_for_type(0xC1, "maybe").is_err());
    }

    #[test]
    fn encode_integers_little_endian() {
        assert_eq!(super::encode_value_for_type(0xC4, "1337").unwrap(), 1337i32.to_le_bytes());
        assert_eq!(super::encode_value_for_type(0xC3, "-2").unwrap(), (-2i16).to_le_bytes());
        assert_eq!(super::encode_value_for_type(0xC7, "65535").unwrap(), 65535u16.to_le_bytes());
    }

    #[test]
    fn encode_integers_accept_hex() {
        assert_eq!(super::encode_value_for_type(0xC4, "0x100").unwrap(), 256i32.to_le_bytes());
    }

    #[test]
    fn encode_rejects_out_of_range_rather_than_truncating() {
        // Silently wrapping would write a different number to a live controller.
        assert!(super::encode_value_for_type(0xC3, "40000").is_err());
        assert!(super::encode_value_for_type(0xC2, "200").is_err());
        assert!(super::encode_value_for_type(0xC7, "-1").is_err());
    }

    #[test]
    fn encode_real_and_rejects_non_finite() {
        assert_eq!(super::encode_value_for_type(0xCA, "6.4").unwrap(), 6.4f32.to_le_bytes());
        assert!(super::encode_value_for_type(0xCA, "NaN").is_err());
        assert!(super::encode_value_for_type(0xCA, "inf").is_err());
        assert!(super::encode_value_for_type(0xCA, "abc").is_err());
    }

    #[test]
    fn encode_rejects_empty_and_unsupported_types() {
        assert!(super::encode_value_for_type(0xC4, "   ").is_err());
        assert!(super::encode_value_for_type(0xD0, "hello").is_err()); // STRING
    }

    #[test]
    fn writable_types_exclude_structs_and_arrays() {
        assert!(super::is_writable_type(0x00C4)); // DINT
        assert!(super::is_writable_type(0x00CA)); // REAL
        assert!(super::is_writable_type(0x00C1)); // BOOL
        assert!(!super::is_writable_type(0x808B)); // struct
        assert!(!super::is_writable_type(0x20CA)); // REAL array
        assert!(!super::is_writable_type(0x00D0)); // STRING
    }

    // ── Hidden UDT members ──────────────────────────────────────────────────

    #[test]
    fn compiler_generated_members_are_hidden() {
        let mut raw = Vec::new();
        for _ in 0..4 {
            raw.extend_from_slice(&descriptor(0, 0x00C4, 0));
        }
        raw.extend_from_slice(b"T;x\0PV\0ZZZZZZZZZZATS_IBF_UD0\0__BitHost00\0?Internal\0");

        let fields = parse_template_body(&raw, 4);
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["PV"], "only user-authored members should survive");
    }

    // ── Flattening a UDT into addressable leaves ─────────────────────────────

    #[test]
    fn flatten_struct_produces_dotted_paths_for_nested_members() {
        let mut map = TemplateMap::new();
        map.insert(
            0x08B,
            TemplateDef::from_fields(vec![
                TemplateField { name: "PV".into(), cip_type: 0xCA, type_info: 0, offset: 0 },
                TemplateField { name: "Alarm".into(), cip_type: 0xC1, type_info: 2, offset: 4 },
            ]),
        );
        map.insert(
            0x09C,
            TemplateDef::from_fields(vec![
                TemplateField { name: "Hours".into(), cip_type: 0xC4, type_info: 0, offset: 0 },
                TemplateField { name: "Cmd".into(), cip_type: 0x808B, type_info: 0, offset: 4 },
            ]),
        );

        let mut data = Vec::new();
        data.extend_from_slice(&99i32.to_le_bytes()); // Hours
        data.extend_from_slice(&1.5f32.to_le_bytes()); // Cmd.PV
        data.extend_from_slice(&[0x04, 0, 0, 0]); // Cmd.Alarm bit 2 set

        let leaves = super::flatten_struct(&data, 0x09C, Some(&map));
        let paths: Vec<&str> = leaves.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, ["Hours", "Cmd.PV", "Cmd.Alarm"]);
        assert_eq!(leaves[0].value, "99");
        assert_eq!(leaves[2].value, "true");
        assert!(leaves.iter().all(|l| l.writable));
    }

    // ── Array member expansion ───────────────────────────────────────────────

    /// A UDT holding a single array member of `cip_type` with `count` elements.
    fn array_template(cip_type: u16, count: u16) -> TemplateMap {
        let mut map = TemplateMap::new();
        map.insert(
            0x0AA,
            TemplateDef::from_fields(vec![TemplateField {
                name: "Levels".into(), cip_type, type_info: count, offset: 0,
            }]),
        );
        map
    }

    #[test]
    fn real_array_expands_to_one_writable_leaf_per_element() {
        let map = array_template(0x20CA, 4); // REAL[4], 1 dimension
        let mut data = Vec::new();
        for v in [1.5f32, 2.5, 3.5, 4.5] {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let leaves = super::flatten_struct(&data, 0x0AA, Some(&map));
        let paths: Vec<&str> = leaves.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, ["Levels[0]", "Levels[1]", "Levels[2]", "Levels[3]"]);
        // Wrong stride would shift these values.
        assert_eq!(leaves[0].value, "1.5");
        assert_eq!(leaves[2].value, "3.5");
        assert!(leaves.iter().all(|l| l.writable), "each element is writable on its own");
        // The element type must have the dimension bits cleared, or the write is refused.
        assert!(leaves.iter().all(|l| l.cip_type == 0x00CA));
    }

    #[test]
    fn array_expansion_stops_at_the_available_bytes() {
        let map = array_template(0x20CA, 8); // claims 8 elements
        let data = [0u8; 8]; // only 2 REALs of data
        let leaves = super::flatten_struct(&data, 0x0AA, Some(&map));
        let elems = leaves.iter().filter(|l| l.writable).count();
        assert_eq!(elems, 2, "must not read past the end of the struct data");
    }

    #[test]
    fn bool_array_decodes_from_packed_bits_not_bytes() {
        // Logix packs BOOL[n] into 32-bit words: element i is bit i%32 of word i/32.
        // Byte-indexing would read element 33 from data[33] instead of bit 1 of word 1.
        let map = array_template(0x20C1, 40);
        let mut data = [0u8; 8];
        data[0] = 0b0000_0101; // elements 0 and 2 set
        data[4] = 0b0000_0010; // element 33 set (word 1, bit 1)

        let leaves = super::flatten_struct(&data, 0x0AA, Some(&map));
        let val = |i: usize| leaves.iter().find(|l| l.path == format!("Levels[{i}]")).unwrap();
        assert_eq!(val(0).value, "true");
        assert_eq!(val(1).value, "false");
        assert_eq!(val(2).value, "true");
        assert_eq!(val(32).value, "false");
        assert_eq!(val(33).value, "true", "element 33 is bit 1 of the second word");
        assert!(val(33).writable);
    }

    #[test]
    fn array_expansion_caps_and_reports_the_true_total() {
        let total = super::MAX_ARRAY_ELEMENTS + 18;
        let map = array_template(0x20C2, u16::try_from(total).unwrap()); // SINT[82]
        let data = vec![7u8; total];

        let leaves = super::flatten_struct(&data, 0x0AA, Some(&map));
        let elems = leaves.iter().filter(|l| l.path.contains('[')).count();
        assert_eq!(elems, super::MAX_ARRAY_ELEMENTS);
        let note = leaves.last().unwrap();
        assert!(!note.writable);
        assert!(
            note.value.contains(&total.to_string()),
            "the note must state the real total, not hide it: {}",
            note.value
        );
    }

    #[test]
    fn array_of_nested_udts_strides_by_structure_size() {
        let mut map = TemplateMap::new();
        // Inner UDT: two REALs, 8 bytes per instance.
        map.insert(
            0x08B,
            TemplateDef {
                size: Some(8),
                fields: vec![
                    TemplateField { name: "PV".into(), cip_type: 0xCA, type_info: 0, offset: 0 },
                    TemplateField { name: "SP".into(), cip_type: 0xCA, type_info: 0, offset: 4 },
                ],
            },
        );
        map.insert(
            0x0AA,
            TemplateDef::from_fields(vec![TemplateField {
                name: "Pumps".into(), cip_type: 0xA08B, type_info: 3, offset: 0,
            }]),
        );

        let mut data = Vec::new();
        for v in [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0] {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let leaves = super::flatten_struct(&data, 0x0AA, Some(&map));
        let paths: Vec<&str> = leaves.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(
            paths,
            ["Pumps[0].PV", "Pumps[0].SP", "Pumps[1].PV", "Pumps[1].SP",
             "Pumps[2].PV", "Pumps[2].SP"]
        );
        // A wrong stride would put 3.0 somewhere other than Pumps[1].PV.
        assert_eq!(leaves[2].value, "3");
        assert_eq!(leaves[5].value, "6");
    }

    #[test]
    fn struct_array_without_a_known_stride_is_summarised() {
        let mut map = TemplateMap::new();
        // Inner template absent from the map: no stride can be established.
        map.insert(
            0x0AA,
            TemplateDef::from_fields(vec![TemplateField {
                name: "Pumps".into(), cip_type: 0xA0FF, type_info: 3, offset: 0,
            }]),
        );
        let leaves = super::flatten_struct(&[0u8; 24], 0x0AA, Some(&map));
        assert_eq!(leaves.len(), 1);
        assert!(!leaves[0].writable);
        assert_eq!(leaves[0].path, "Pumps", "no index is invented when the stride is unknown");
    }

    #[test]
    fn multi_dimensional_member_is_summarised_not_indexed() {
        // 0x4000 = 2 dimensions. Per-dimension bounds are not in the descriptor, so a
        // fabricated "[i]" would address the wrong element.
        let map = array_template(0x40CA, 6);
        let leaves = super::flatten_struct(&[0u8; 24], 0x0AA, Some(&map));
        assert_eq!(leaves.len(), 1);
        assert!(!leaves[0].writable);
        assert!(!leaves[0].path.contains('['));
    }

    #[test]
    fn array_of_unknown_element_width_is_summarised() {
        let map = array_template(0x2000 | 0x00D0, 4); // STRING array
        let leaves = super::flatten_struct(&[0u8; 32], 0x0AA, Some(&map));
        assert_eq!(leaves.len(), 1);
        assert!(!leaves[0].writable);
    }

    #[test]
    fn flatten_renders_string_structs_as_one_readonly_leaf() {
        let mut map = TemplateMap::new();
        map.insert(
            0xFCE,
            TemplateDef::from_fields(vec![
                TemplateField { name: "LEN".into(), cip_type: 0xC4, type_info: 0, offset: 0 },
                TemplateField { name: "DATA".into(), cip_type: 0x20C2, type_info: 82, offset: 4 },
            ]),
        );
        let mut data = 5i32.to_le_bytes().to_vec();
        data.extend_from_slice(b"PUMP1");
        data.extend_from_slice(&[0u8; 77]);

        let leaves = super::flatten_struct(&data, 0xFCE, Some(&map));
        assert_eq!(leaves.len(), 1, "not LEN plus 82 char rows");
        assert_eq!(leaves[0].value, "\"PUMP1\"");
        assert!(!leaves[0].writable, "a STRING write needs LEN and DATA set together");
    }

    // ── Element widths and struct stride ────────────────────────────────────

    #[test]
    fn cip_type_size_declines_types_it_cannot_stride() {
        assert_eq!(cip_type_size(0x00C1), Some(1));
        assert_eq!(cip_type_size(0x00C3), Some(2));
        assert_eq!(cip_type_size(0x00CA), Some(4));
        assert_eq!(cip_type_size(0x00CB), Some(8));
        // Dimension bits must not change the element width.
        assert_eq!(cip_type_size(0x20CA), Some(4));
        assert_eq!(cip_type_size(0x00D0), None, "STRING has no fixed width");
        assert_eq!(cip_type_size(0x808B), None, "a struct sizes via its own TemplateDef");
    }

    #[test]
    fn template_stride_prefers_reported_size_over_computed_extent() {
        let fields = vec![
            TemplateField { name: "A".into(), cip_type: 0xC1, type_info: 0, offset: 0 },
            TemplateField { name: "B".into(), cip_type: 0xC4, type_info: 0, offset: 4 },
        ];
        // Computed extent is 8; Logix pads this UDT to 12.
        assert_eq!(TemplateDef::from_fields(fields.clone()).stride(), Some(8));
        assert_eq!(TemplateDef { fields, size: Some(12) }.stride(), Some(12));
    }

    #[test]
    fn template_stride_is_none_when_a_member_width_is_unknown() {
        let fields = vec![
            TemplateField { name: "S".into(), cip_type: 0x00D0, type_info: 0, offset: 0 },
        ];
        assert_eq!(TemplateDef::from_fields(fields).stride(), None);
    }

    #[test]
    fn flatten_struct_without_template_is_empty() {
        assert!(super::flatten_struct(&[1, 2, 3, 4], 0x123, None).is_empty());
    }

    #[test]
    fn flatten_struct_survives_self_referential_template() {
        // A template whose member points back at itself must not recurse forever.
        let mut map = TemplateMap::new();
        map.insert(
            0x0BB,
            TemplateDef::from_fields(vec![TemplateField {
                name: "Self".into(), cip_type: 0x80BB, type_info: 0, offset: 0,
            }]),
        );
        let data = [0u8; 64];
        let leaves = super::flatten_struct(&data, 0x0BB, Some(&map));
        assert!(leaves.len() <= super::MAX_STRUCT_DEPTH);
    }

    // ── CIP status names ────────────────────────────────────────────────────

    #[test]
    fn cip_status_names_cover_the_codes_this_module_reports() {
        assert_eq!(cip_status_name(0x00), "success");
        assert_eq!(cip_status_name(0x06), "partial transfer");
        assert_eq!(cip_status_name(0x08), "service not supported");
        assert_eq!(cip_status_name(0x14), "attribute not supported");
        assert_eq!(cip_status_name(0xFE), "unknown");
    }

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
        assert_eq!(decode_value(0xC3, &[0x00], None), "-");
    }

    #[test]
    fn decode_value_bool_true() {
        assert_eq!(decode_value(0xC1, &[0, 0, 1], None), "true  (1)");
    }

    #[test]
    fn decode_value_bool_false() {
        assert_eq!(decode_value(0xC1, &[0, 0, 0], None), "false (0)");
    }

    #[test]
    fn decode_value_bool_empty_val_returns_question() {
        assert_eq!(decode_value(0xC1, &[0, 0], None), "?");
    }

    #[test]
    fn decode_value_sint_neg1() {
        assert_eq!(decode_value(0xC2, &[0, 0, 0xFF], None), "-1");
    }

    #[test]
    fn decode_value_int_1337() {
        // 1337 LE = 0x39, 0x05
        assert_eq!(decode_value(0xC3, &[0, 0, 0x39, 0x05], None), "1337");
    }

    #[test]
    fn decode_value_dint_max() {
        assert_eq!(decode_value(0xC4, &[0, 0, 0xFF, 0xFF, 0xFF, 0x7F], None), "2147483647");
    }

    #[test]
    fn decode_value_lint_neg1() {
        assert_eq!(
            decode_value(0xC5, &[0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], None),
            "-1"
        );
    }

    #[test]
    fn decode_value_usint_255() {
        assert_eq!(decode_value(0xC6, &[0, 0, 255], None), "255");
    }

    #[test]
    fn decode_value_uint_max() {
        assert_eq!(decode_value(0xC7, &[0, 0, 0xFF, 0xFF], None), "65535");
    }

    #[test]
    fn decode_value_udint_max() {
        assert_eq!(decode_value(0xC8, &[0, 0, 0xFF, 0xFF, 0xFF, 0xFF], None), "4294967295");
    }

    #[test]
    fn decode_value_real_one() {
        // 1.0f32 LE = [0x00, 0x00, 0x80, 0x3F]
        assert_eq!(decode_value(0xCA, &[0, 0, 0x00, 0x00, 0x80, 0x3F], None), "1");
    }

    #[test]
    fn decode_value_string_hello() {
        let cip_data: &[u8] = &[0, 0, 5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_value(0xD0, cip_data, None), "\"hello\"");
    }

    #[test]
    fn decode_value_string_truncated_returns_question() {
        // length field says 5 but only 1 byte of data present
        assert_eq!(decode_value(0xD0, &[0, 0, 0x05], None), "\"?\"");
    }

    #[test]
    fn decode_value_unknown_type_shows_struct_fallback() {
        // 0xFF → template_id 0x0FF, no templates → STRUCT fallback (not raw hex)
        assert_eq!(
            decode_value(0xFF, &[0, 0, 0xAB, 0xCD], None),
            "STRUCT(0x0FF)[2 bytes]"
        );
    }

    #[test]
    fn decode_value_unknown_type_empty_val_returns_dash() {
        assert_eq!(decode_value(0xFF, &[0, 0], None), "-");
    }

    #[test]
    fn decode_value_struct_without_templates_shows_byte_count() {
        // tag_type 0x8042 = struct (bit 15 set), template_id = 0x042
        assert_eq!(decode_value(0x8042, &[0, 0, 0xAA, 0xBB, 0xCC], None), "STRUCT(0x042)[3 bytes]");
    }

    #[test]
    fn decode_value_struct_guard_prevents_atomic_misread() {
        // template_id lower byte = 0xC4 (DINT code) but bit 15 is set, so NOT decoded as DINT
        assert_eq!(decode_value(0x80C4, &[0, 0, 0xFF, 0xFF, 0xFF, 0x7F], None), "STRUCT(0x0C4)[4 bytes]");
    }

    #[test]
    fn decode_value_time_ms() {
        // TIME: 1000 ms LE
        assert_eq!(decode_value(0xDB, &[0, 0, 0xE8, 0x03, 0, 0], None), "1000ms");
    }

    #[test]
    fn decode_value_byte_hex() {
        assert_eq!(decode_value(0xD1, &[0, 0, 0xAB], None), "0xAB");
    }

    #[test]
    fn decode_value_word_hex() {
        assert_eq!(decode_value(0xD2, &[0, 0, 0x34, 0x12], None), "0x1234");
    }

    // ── type_name ─────────────────────────────────────────────────────────────

    #[test]
    fn type_name_dint_scalar() {
        assert_eq!(type_name(0xC4), "DINT");
    }

    // Array dimensions live in bits 14-13, so 1D/2D/3D are 0x2000/0x4000/0x6000.
    #[test]
    fn type_name_dint_1d() {
        assert_eq!(type_name(0x20C4), "DINT[1D]");
    }

    #[test]
    fn type_name_dint_2d() {
        assert_eq!(type_name(0x40C4), "DINT[2D]");
    }

    #[test]
    fn type_name_dint_3d() {
        assert_eq!(type_name(0x60C4), "DINT[3D]");
    }

    #[test]
    fn type_name_bit12_is_not_a_dimension() {
        // 0x1000 is the system-type flag. Masking bits 14-12 would report it as "1D".
        assert_eq!(type_name(0x10C4), "DINT");
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
        assert_eq!(type_name(0x2005), "BOOL.b5[1D]");
    }

    #[test]
    fn type_name_struct_scalar() {
        assert_eq!(type_name(0x8042), "STRUCT(0x042)");
    }

    #[test]
    fn type_name_struct_1d() {
        // 0xA042 = struct flag (0x8000) + 1 dimension (0x2000) + template id 0x042
        assert_eq!(type_name(0xA042), "STRUCT(0x042)[1D]");
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
        assert_eq!(type_parts(0x20C4), ("DINT".to_string(), "1D"));
    }

    #[test]
    fn type_parts_struct_scalar() {
        assert_eq!(type_parts(0x8042), ("STRUCT(0x042)".to_string(), "-"));
    }

    #[test]
    fn type_parts_struct_1d() {
        assert_eq!(type_parts(0xA042), ("STRUCT(0x042)".to_string(), "1D"));
    }

    #[test]
    fn symbol_dimensions_reads_bits_14_13_only() {
        assert_eq!(super::symbol_dimensions(0x00C4), 0);
        assert_eq!(super::symbol_dimensions(0x20C4), 1);
        assert_eq!(super::symbol_dimensions(0x40C4), 2);
        assert_eq!(super::symbol_dimensions(0x60C4), 3);
        // Neither the struct flag (bit 15) nor the system flag (bit 12) is a dimension.
        assert_eq!(super::symbol_dimensions(0x8FCE), 0);
        assert_eq!(super::symbol_dimensions(0x10C4), 0);
        assert_eq!(super::symbol_dimensions(0xFFFF), 3);
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
        // data_len = 9999, but buffer is only 4 bytes: triggers "too short"
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
