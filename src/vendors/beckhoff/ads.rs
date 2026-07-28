use crate::core::bytes::reverse_bytes;
use rand::Rng;

/// AMS routing addresses for an ADS packet.
pub struct AmsRoute<'a> {
    pub remote_netid: &'a str,
    pub remote_port: u16,
    pub local_netid: &'a str,
    pub local_port: u16,
}

/// Construct a Beckhoff AMS/ADS packet as a hex string.
pub fn construct_ams_packet(
    route: &AmsRoute<'_>,
    cmd_id: u16,
    ads_data_list: &AdsParams,
    invoke_id: Option<&str>,
    is_request: bool,
) -> String {
    let r_port = reverse_bytes(&format!("{:04x}", route.remote_port));
    let l_port = reverse_bytes(&format!("{:04x}", route.local_port));
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
        "{}{}{}{}{}{}{}{:016}{}{ads_data}",
        route.remote_netid, r_port, route.local_netid, l_port, s_cmd, s_state, data_len, 0u64, invoke
    );

    let ams_len = reverse_bytes(&format!("{:08x}", ams_data.len() / 2));
    format!("{:08}{ams_len}{ams_data}", 0u32)
}

pub enum AdsParams {
    Read(u32, u32, u32),
    Write(u32, u32, Vec<u8>),
    ReadState,
    WriteControl(u16, u16, Vec<u8>),
}

fn build_ads_data(cmd_id: u16, params: &AdsParams) -> String {
    use std::fmt::Write;
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
            let hex_data: String = data.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            format!(
                "{}{}{}{}",
                reverse_bytes(&format!("{ig:08x}")),
                reverse_bytes(&format!("{io:08x}")),
                reverse_bytes(&format!("{:08x}", data.len())),
                hex_data
            )
        }
        (5, AdsParams::WriteControl(ads_state, dev_state, data)) => {
            let hex_data: String = data.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            format!(
                "{}{}{}{}",
                reverse_bytes(&format!("{ads_state:04x}")),
                reverse_bytes(&format!("{dev_state:04x}")),
                reverse_bytes(&format!("{:08x}", data.len())),
                hex_data
            )
        }
        _ => String::new(),
    }
}

// Fields are exercised by unit tests; compiler doesn't count cfg(test) as "read".
#[allow(dead_code)]
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
/// `type_name` is the ADS type string (e.g. "BOOL", "INT", "REAL", "STRING(80)").
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
            Some(&b) => i8::from_ne_bytes([b]).to_string(),
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
    let v: u64 = bytes[..n].iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc | u64::from(b) << (8 * i)
    });
    v.to_string()
}

fn decode_int_le(bytes: &[u8], n: usize) -> String {
    if bytes.len() < n {
        return hex_dump(bytes);
    }
    let signed: i64 = match n {
        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        4 => i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        _ => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    };
    signed.to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ams_response(ads_data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        body.extend_from_slice(&10000u16.to_le_bytes());
        body.extend_from_slice(&[127, 0, 0, 1, 1, 1]);
        body.extend_from_slice(&31337u16.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&u32::try_from(ads_data.len()).unwrap_or(u32::MAX).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0xAABB_CCDD_u32.to_le_bytes());
        body.extend_from_slice(ads_data);

        let mut response = Vec::new();
        response.extend_from_slice(&[0, 0]);
        response.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
        response.extend_from_slice(&body);
        response
    }

    #[test]
    fn parse_ads_response_extracts_error_and_data() {
        let ads = "0000000002000000d204";
        let (error, data) = parse_ads_response(ads).unwrap();
        assert_eq!(error, "00000000");
        assert_eq!(data, "d204");
    }

    #[test]
    fn parse_ams_response_extracts_header_and_payload() {
        let response = ams_response(&[0, 0, 0, 0, 2, 0, 0, 0, 0xD2, 0x04]);
        let ams = parse_ams_response(&response).unwrap();
        assert_eq!(ams.dst_netid, "010203040506");
        assert_eq!(ams.dst_port, 10000);
        assert_eq!(ams.src_netid, "7f0000010101");
        assert_eq!(ams.src_port, 31337);
        assert_eq!(ams.cmd_id, 2);
        assert_eq!(ams.error_code, "00000000");
        assert_eq!(ams.invoke_id, "aabbccdd");
        assert_eq!(ams.ads_data, "0000000002000000d204");
    }

    #[test]
    fn decode_ads_scalar_values() {
        assert_eq!(decode_ads_value("BOOL", &[1]), "true");
        assert_eq!(decode_ads_value("UINT", &1234u16.to_le_bytes()), "1234");
        assert_eq!(decode_ads_value("DINT", &(-42i32).to_le_bytes()), "-42");
        assert_eq!(
            decode_ads_value("STRING(80)", b"hello\0ignored"),
            "\"hello\""
        );
    }
}
