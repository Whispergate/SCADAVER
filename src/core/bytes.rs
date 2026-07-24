/// Reverse the byte order of a hex string (pairs of chars).
/// e.g. "0102" → "0201"
pub fn reverse_bytes(hex: &str) -> String {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    clean
        .as_bytes()
        .chunks(2)
        .rev()
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("00"))
        .collect()
}

/// Convert an IPv4 string to a hex representation of its octets.
/// e.g. "192.168.1.1" → "c0a80101"
pub fn ip_to_hex(ip: &str) -> String {
    ip.split('.')
        .map(|part| {
            let n: u8 = part.parse().unwrap_or(0);
            format!("{n:02x}")
        })
        .collect()
}

/// Format an AMS Net ID hex string as dotted-hex notation.
/// e.g. "c0a80101" (8 chars for 4 bytes) + "0101" → "192.168.1.1.1.1"
pub fn get_netid_as_string(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).unwrap_or("00");
            u8::from_str_radix(s, 16)
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "0".to_string())
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Convert bytes to a little-endian integer. Pass `inverted = true`
/// to read the bytes as big-endian (i.e. reverse first).
pub fn convert_to_int(bytes: &[u8], inverted: bool) -> u32 {
    if inverted {
        let rev: Vec<u8> = bytes.iter().copied().rev().collect();
        bytes_to_u32(&rev)
    } else {
        bytes_to_u32(bytes)
    }
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &b) in bytes.iter().take(4).enumerate() {
        result |= (b as u32) << (i * 8);
    }
    result
}

/// Reverse the pairs of a hex string (for EtherNet/IP little-endian fields).
pub fn invert_hex_string(hex: &str) -> String {
    reverse_bytes(hex)
}

/// Convert a binary string (e.g. "10110000") to a single-byte hex string.
/// The bits are reversed first (LSB-first order).
pub fn bits_to_hex_byte(bits: &str) -> String {
    let padded: String = bits.chars().take(8).collect();
    let padded = format!("{:<8}", padded).replace(' ', "0");
    let reversed: String = padded.chars().rev().collect();
    let val = u8::from_str_radix(&reversed, 2).unwrap_or(0);
    format!("{val:02x}")
}

/// Encode a u32 as a 4-byte little-endian hex string.
pub fn u32_to_le_hex(n: u32) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        n & 0xFF,
        (n >> 8) & 0xFF,
        (n >> 16) & 0xFF,
        (n >> 24) & 0xFF
    )
}

/// Encode a u16 as a 2-byte little-endian hex string.
pub fn u16_to_le_hex(n: u16) -> String {
    format!("{:02x}{:02x}", n & 0xFF, (n >> 8) & 0xFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_bytes() {
        assert_eq!(reverse_bytes("0102"), "0201");
        assert_eq!(reverse_bytes("c0a80101"), "0101a8c0");
    }

    #[test]
    fn test_ip_to_hex() {
        assert_eq!(ip_to_hex("192.168.1.1"), "c0a80101");
    }

    #[test]
    fn test_bits_to_hex_byte() {
        assert_eq!(bits_to_hex_byte("10110000"), "0d");
    }
}
