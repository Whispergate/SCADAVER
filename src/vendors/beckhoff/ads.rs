use crate::core::bytes::reverse_bytes;
use rand::Rng;

pub const DEFAULT_REMOTE_PORT: u16 = 10000;
pub const DEFAULT_LOCAL_PORT: u16 = 31337;

/// Construct a Beckhoff AMS/ADS packet as a hex string.
pub fn construct_ams_packet(
    remote_netid: &str,
    local_netid: &str,
    cmd_id: u16,
    ads_data_list: &AdsParams,
    invoke_id: Option<&str>,
    is_request: bool,
    remote_port: u16,
    local_port: u16,
) -> String {
    let r_port = reverse_bytes(&format!("{remote_port:04x}"));
    let l_port = reverse_bytes(&format!("{local_port:04x}"));
    let s_cmd = reverse_bytes(&format!("{cmd_id:04x}"));
    let state_flag: u16 = if is_request { 4 } else { 5 };
    let s_state = reverse_bytes(&format!("{state_flag:04x}"));

    let ads_data = build_ads_data(cmd_id, ads_data_list);

    let data_len = reverse_bytes(&format!("{:08x}", ads_data.len() / 2));

    let invoke = if let Some(id) = invoke_id {
        // id must be a hex string; zero-left-pad to 8 chars before byte-swapping
        reverse_bytes(&format!("{id:0>8}"))
    } else {
        let mut rng = rand::thread_rng();
        let n: u32 = rng.gen();
        reverse_bytes(&format!("{n:08x}"))
    };

    let ams_data = format!(
        "{remote_netid}{r_port}{local_netid}{l_port}{s_cmd}{s_state}{data_len}{:016}{invoke}{ads_data}",
        0u64
    );

    let ams_len = reverse_bytes(&format!("{:08x}", ams_data.len() / 2));
    format!("{:08}{ams_len}{ams_data}", 0u32)
}

pub enum AdsParams {
    None,
    Read(u32, u32, u32),
    Write(u32, u32, Vec<u8>),
    ReadState,
    WriteControl(u16, u16, Vec<u8>),
    ReadWrite(u32, u32, u32, Vec<u8>),
}

fn build_ads_data(cmd_id: u16, params: &AdsParams) -> String {
    match (cmd_id, params) {
        (2, AdsParams::Read(ig, io, len)) => {
            format!(
                "{}{}{}",
                reverse_bytes(&format!("{ig:08x}")),
                reverse_bytes(&format!("{io:08x}")),
                reverse_bytes(&format!("{len:08x}"))
            )
        }
        (3, AdsParams::Write(ig, io, data)) => {
            let hex_data: String = data.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{}{}{}{}",
                reverse_bytes(&format!("{ig:08x}")),
                reverse_bytes(&format!("{io:08x}")),
                reverse_bytes(&format!("{:08x}", data.len())),
                hex_data
            )
        }
        (4, AdsParams::ReadState) | (4, AdsParams::None) => String::new(),
        (5, AdsParams::WriteControl(ads_state, dev_state, data)) => {
            let hex_data: String = data.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{}{}{}{}",
                reverse_bytes(&format!("{ads_state:04x}")),
                reverse_bytes(&format!("{dev_state:04x}")),
                reverse_bytes(&format!("{:08x}", data.len())),
                hex_data
            )
        }
        (9, AdsParams::ReadWrite(ig, io, read_len, data)) => {
            let hex_data: String = data.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{}{}{}{}{}",
                reverse_bytes(&format!("{ig:08x}")),
                reverse_bytes(&format!("{io:08x}")),
                reverse_bytes(&format!("{read_len:08x}")),
                reverse_bytes(&format!("{:08x}", data.len())),
                hex_data
            )
        }
        _ => String::new(),
    }
}

#[derive(Debug)]
pub struct AmsResponse {
    pub packet_length: u32,
    pub dst_netid: String,
    pub dst_port: u16,
    pub src_netid: String,
    pub src_port: u16,
    pub cmd_id: u16,
    pub state_flags: u16,
    pub error_code: String,
    pub invoke_id: String,
    pub ads_data: String,
}

pub fn parse_ams_response(response: &[u8]) -> Option<AmsResponse> {
    if response.len() < 38 {
        return None;
    }
    let data = hex_encode(response);
    if &data[..4] != "0000" {
        return None;
    }

    let packet_length = u32::from_str_radix(&reverse_bytes(&data[4..12]), 16).ok()?;
    let dst_netid = data[12..24].to_string();
    let dst_port = u16::from_str_radix(&reverse_bytes(&data[24..28]), 16).ok()?;
    let src_netid = data[28..40].to_string();
    let src_port = u16::from_str_radix(&reverse_bytes(&data[40..44]), 16).ok()?;
    let cmd_id = u16::from_str_radix(&reverse_bytes(&data[44..48]), 16).ok()?;
    let state_flags = u16::from_str_radix(&reverse_bytes(&data[48..52]), 16).ok()?;
    let data_len = u32::from_str_radix(&reverse_bytes(&data[52..60]), 16).ok()? as usize;
    let error_code = reverse_bytes(&data[60..68]);
    let invoke_id = reverse_bytes(&data[68..76]);
    let end = 76usize.checked_add(data_len.checked_mul(2)?)?;
    if end > data.len() {
        return None;
    }
    let ads_data = data[76..end].to_string();

    Some(AmsResponse {
        packet_length,
        dst_netid,
        dst_port,
        src_netid,
        src_port,
        cmd_id,
        state_flags,
        error_code,
        invoke_id,
        ads_data,
    })
}

pub fn parse_ads_response(ads_hex: &str) -> Option<(String, String)> {
    if ads_hex.len() < 8 {
        return None;
    }
    let error_code = reverse_bytes(&ads_hex[..8]);
    if ads_hex.len() < 16 {
        return Some((error_code, String::new()));
    }
    let data_len = u32::from_str_radix(&reverse_bytes(&ads_hex[8..16]), 16).ok()? as usize;
    let byte_len = data_len.checked_mul(2)?;
    let end = 16usize.checked_add(byte_len)?;
    if end > ads_hex.len() {
        return None;
    }
    let ads_data = ads_hex[16..end].to_string();
    Some((error_code, ads_data))
}

/// Build a local AMS Net ID from an IPv4 address.
pub fn build_local_netid(local_ip: &str) -> String {
    use crate::core::bytes::ip_to_hex;
    format!("{}0101", ip_to_hex(local_ip))
}

/// Decode raw ADS read response bytes into a human-readable string.
/// type_name is the ADS type string (e.g. "BOOL", "INT", "REAL", "STRING(80)").
pub fn decode_ads_value(type_name: &str, bytes: &[u8]) -> String {
    let t = type_name.trim().to_uppercase();

    if t.starts_with("STRING") {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let s = String::from_utf8_lossy(&bytes[..end]);
        return format!("\"{s}\"");
    }

    match t.as_str() {
        "BOOL" => match bytes.first() {
            Some(0) => "false".to_string(),
            Some(_) => "true".to_string(),
            None => hex_dump(bytes),
        },
        "BYTE" | "USINT" => match bytes.first() {
            Some(&b) => b.to_string(),
            None => hex_dump(bytes),
        },
        "SINT" => match bytes.first() {
            Some(&b) => (b as i8).to_string(),
            None => hex_dump(bytes),
        },
        "WORD" | "UINT" => decode_uint_le(bytes, 2),
        "INT" => decode_int_le(bytes, 2),
        "DWORD" | "UDINT" => decode_uint_le(bytes, 4),
        "DINT" => decode_int_le(bytes, 4),
        "LWORD" | "ULINT" => decode_uint_le(bytes, 8),
        "LINT" => decode_int_le(bytes, 8),
        "REAL" => {
            if bytes.len() >= 4 {
                let v = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                format!("{v}")
            } else {
                hex_dump(bytes)
            }
        }
        "LREAL" => {
            if bytes.len() >= 8 {
                let v = f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                format!("{v}")
            } else {
                hex_dump(bytes)
            }
        }
        _ => hex_dump(bytes),
    }
}

fn hex_dump(bytes: &[u8]) -> String {
    format!("0x{}", hex_encode(bytes))
}

fn decode_uint_le(bytes: &[u8], n: usize) -> String {
    if bytes.len() < n {
        return hex_dump(bytes);
    }
    let mut v: u64 = 0;
    for i in 0..n {
        v |= (bytes[i] as u64) << (8 * i);
    }
    v.to_string()
}

fn decode_int_le(bytes: &[u8], n: usize) -> String {
    if bytes.len() < n {
        return hex_dump(bytes);
    }
    let mut v: u64 = 0;
    for i in 0..n {
        v |= (bytes[i] as u64) << (8 * i);
    }
    let signed: i64 = match n {
        2 => (v as u16 as i16) as i64,
        4 => (v as u32 as i32) as i64,
        _ => v as i64,
    };
    signed.to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
