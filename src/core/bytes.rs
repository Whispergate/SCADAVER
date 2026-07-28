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
    use std::fmt::Write;
    ip.split('.').fold(String::new(), |mut s, part| {
        let n: u8 = part.parse().unwrap_or(0);
        let _ = write!(s, "{n:02x}");
        s
    })
}

/// Format an AMS Net ID hex string as dotted-hex notation.
/// e.g. "c0a80101" (8 chars for 4 bytes) + "0101" → "192.168.1.1.1.1"
pub fn get_netid_as_string(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).unwrap_or("00");
            u8::from_str_radix(s, 16).map_or_else(|_| "0".to_string(), |n| n.to_string())
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Convert a binary string (e.g. "10110000") to a single-byte hex string.
/// The bits are reversed first (LSB-first order).
pub fn bits_to_hex_byte(bits: &str) -> String {
    let padded: String = bits.chars().take(8).collect();
    let padded = format!("{padded:<8}").replace(' ', "0");
    let reversed: String = padded.chars().rev().collect();
    let val = u8::from_str_radix(&reversed, 2).unwrap_or(0);
    format!("{val:02x}")
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
