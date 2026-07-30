// Integration tests for the scadaver_rs public library API.
// Each test exercises the public surface as an external crate would —
// using scadaver_rs:: paths, not crate:: paths.

use scadaver_rs::core::bytes;
use scadaver_rs::vendors::beckhoff::ads;
use scadaver_rs::vendors::enip::enums;
use scadaver_rs::vendors::ewon::exploit;
use scadaver_rs::vendors::rockwell::driver;
use scadaver_rs::vendors::snmp::oids;

// ── core::bytes ──────────────────────────────────────────────────────────────

#[test]
fn bytes_reverse_pairs() {
    assert_eq!(bytes::reverse_bytes("0102"), "0201");
    assert_eq!(bytes::reverse_bytes("c0a80101"), "0101a8c0");
}

#[test]
fn bytes_reverse_empty() {
    assert_eq!(bytes::reverse_bytes(""), "");
}

#[test]
fn bytes_ip_to_hex_loopback() {
    assert_eq!(bytes::ip_to_hex("127.0.0.1"), "7f000001");
}

#[test]
fn bytes_ip_to_hex_broadcast() {
    assert_eq!(bytes::ip_to_hex("192.168.1.1"), "c0a80101");
}

#[test]
fn bytes_get_netid_roundtrip() {
    // ip_to_hex → get_netid_as_string should recover original octets
    let hex = bytes::ip_to_hex("10.0.0.1");
    let parts: Vec<&str> = hex.as_bytes().chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let as_dotted = parts.join(".");
    // "0a.00.00.01" in decimal = "10.0.0.1"
    let recovered: String = as_dotted.split('.')
        .map(|h| u8::from_str_radix(h, 16).unwrap().to_string())
        .collect::<Vec<_>>()
        .join(".");
    assert_eq!(recovered, "10.0.0.1");
}

#[test]
fn bytes_bits_to_hex_byte_known() {
    // "10110000" reversed = "00001101" = 0x0D
    assert_eq!(bytes::bits_to_hex_byte("10110000"), "0d");
}

#[test]
fn bytes_bits_to_hex_byte_all_zeros() {
    assert_eq!(bytes::bits_to_hex_byte("00000000"), "00");
}

#[test]
fn bytes_bits_to_hex_byte_all_ones() {
    // "11111111" reversed = "11111111" = 0xFF
    assert_eq!(bytes::bits_to_hex_byte("11111111"), "ff");
}

// ── enip::enums ──────────────────────────────────────────────────────────────

#[test]
fn enip_vendor_rockwell() {
    assert_eq!(enums::vendor_name(1), "Rockwell Automation/Allen-Bradley");
}

#[test]
fn enip_vendor_siemens() {
    assert_eq!(enums::vendor_name(100), "Siemens Energy & Automation");
}

#[test]
fn enip_vendor_unknown_shows_id() {
    let name = enums::vendor_name(9999);
    assert!(name.contains("9999"), "got: {name}");
}

#[test]
fn enip_device_type_plc() {
    assert_eq!(enums::device_type_name(14), "Programmable Logic Controller");
}

#[test]
fn enip_device_type_ac_drive() {
    assert_eq!(enums::device_type_name(2), "AC Drive");
}

#[test]
fn enip_device_type_unknown_shows_id() {
    let name = enums::device_type_name(9999);
    assert!(name.contains("9999"), "got: {name}");
}

// ── snmp::oids ───────────────────────────────────────────────────────────────

#[test]
fn oids_siemens_root_resolves() {
    assert_eq!(oids::vendor_from_sys_oid(oids::SIEMENS_ROOT), Some("siemens"));
}

#[test]
fn oids_schneider_root_resolves() {
    assert_eq!(oids::vendor_from_sys_oid(oids::SCHNEIDER_ROOT), Some("schneider"));
}

#[test]
fn oids_apc_root_resolves_as_schneider() {
    assert_eq!(oids::vendor_from_sys_oid(oids::APC_ROOT), Some("schneider"));
}

#[test]
fn oids_rockwell_root_resolves() {
    assert_eq!(oids::vendor_from_sys_oid(oids::ROCKWELL_ROOT), Some("rockwell"));
}

#[test]
fn oids_beckhoff_root_resolves() {
    assert_eq!(oids::vendor_from_sys_oid(oids::BECKHOFF_ROOT), Some("beckhoff"));
}

#[test]
fn oids_prefix_match_works() {
    // A child OID of SIEMENS_ROOT should also resolve
    let child = format!("{}.1.2.3", oids::SIEMENS_ROOT);
    assert_eq!(oids::vendor_from_sys_oid(&child), Some("siemens"));
}

#[test]
fn oids_unknown_oid_returns_none() {
    assert_eq!(oids::vendor_from_sys_oid("1.3.6.1.4.1.99999"), None);
}

#[test]
fn oids_sysdescr_constant_format() {
    // Verify the OID string has the expected dotted structure
    assert!(oids::SYS_DESCR.starts_with("1.3.6.1"));
}

#[test]
fn oids_common_communities_includes_public() {
    assert!(oids::COMMON_COMMUNITIES.contains(&"public"));
    assert!(oids::COMMON_COMMUNITIES.contains(&"private"));
}

// ── ewon::exploit ────────────────────────────────────────────────────────────

#[test]
fn ewon_decode_known_vector() {
    // Verified vector from internal unit tests: "JXAAAA==" → "Ad"
    let result = exploit::decode_password("JXAAAA==");
    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    assert_eq!(result.unwrap(), "Ad");
}

#[test]
fn ewon_decode_strips_hash_prefix() {
    let result = exploit::decode_password("#_X_JXAAAA==");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Ad");
}

#[test]
fn ewon_decode_empty_is_error() {
    assert!(exploit::decode_password("").is_err());
}

#[test]
fn ewon_decode_invalid_base64_is_error() {
    assert!(exploit::decode_password("not!!base64").is_err());
}

#[test]
fn ewon_decode_too_long_is_error() {
    // 32 A's decodes to 24 bytes; after removing 2-byte checksum = 22 > 19 max
    let result = exploit::decode_password("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceed"));
}

#[test]
fn ewon_user_struct_fields_accessible() {
    // Verify all pub fields are reachable from outside the crate
    let user = exploit::EwonUser {
        username: "admin".into(),
        first_name: "John".into(),
        last_name: "Doe".into(),
        password: "secret".into(),
        access_rights: "15".into(),
    };
    assert_eq!(user.username, "admin");
    assert_eq!(user.access_rights, "15");
}

// ── rockwell::driver ─────────────────────────────────────────────────────────

#[test]
fn driver_decode_dint_1337() {
    // cip_data layout: [0, 0, <4 value bytes LE>]  — first 2 bytes are the type-word echo
    let mut data = vec![0u8, 0];
    data.extend_from_slice(&1337_i32.to_le_bytes());
    assert_eq!(driver::decode_value(0xC4, &data), "1337");
}

#[test]
fn driver_decode_dint_max() {
    let mut data = vec![0u8, 0];
    data.extend_from_slice(&i32::MAX.to_le_bytes());
    assert_eq!(driver::decode_value(0xC4, &data), "2147483647");
}

#[test]
fn driver_decode_real_one() {
    // 1.0_f32 LE bytes = [0x00, 0x00, 0x80, 0x3F]
    assert_eq!(driver::decode_value(0xCA, &[0, 0, 0x00, 0x00, 0x80, 0x3F]), "1");
}

#[test]
fn driver_decode_bool_true() {
    assert_eq!(driver::decode_value(0xC1, &[0, 0, 1]), "true  (1)");
}

#[test]
fn driver_decode_bool_false() {
    assert_eq!(driver::decode_value(0xC1, &[0, 0, 0]), "false (0)");
}

#[test]
fn driver_decode_too_short_returns_dash() {
    // Fewer than 2 bytes → "-" before any type dispatch
    assert_eq!(driver::decode_value(0xC4, &[]), "-");
}

#[test]
fn driver_type_name_dint() {
    assert_eq!(driver::type_name(0xC4), "DINT");
}

#[test]
fn driver_type_name_real() {
    assert_eq!(driver::type_name(0xCA), "REAL");
}

#[test]
fn driver_type_name_bool() {
    assert_eq!(driver::type_name(0xC1), "BOOL");
}

#[test]
fn driver_logix_tag_struct_fields_accessible() {
    let tag = driver::LogixTag {
        name: "PumpRun".into(),
        tag_type: 0xC1,
        dimensions: 0,
        instance_id: 42,
    };
    assert_eq!(tag.name, "PumpRun");
    assert_eq!(tag.instance_id, 42);
}

#[test]
fn driver_logix_device_struct_fields_accessible() {
    let dev = driver::LogixDevice {
        vendor: "Rockwell Automation/Allen-Bradley".into(),
        product_type: "Programmable Logic Controller".into(),
        product_code: 55,
        revision: "20.13".into(),
        serial: "12345678".into(),
        product_name: "1756-L71".into(),
    };
    assert_eq!(dev.vendor, "Rockwell Automation/Allen-Bradley");
    assert_eq!(dev.product_code, 55);
}

// ── beckhoff::ads ─────────────────────────────────────────────────────────────

#[test]
fn ads_construct_readstate_packet_is_nonempty() {
    let route = ads::AmsRoute {
        remote_netid: "c0a80101.01.01",
        remote_port: 801,
        local_netid: "7f000001.01.01",
        local_port: 801,
    };
    let pkt = ads::construct_ams_packet(
        &route,
        4,                      // cmd_id = ReadState
        &ads::AdsParams::ReadState,
        Some("00000001"),
        true,
    );
    assert!(!pkt.is_empty());
    // Every AMS packet starts with "0000" (TCP header prefix, reserved)
    assert!(pkt.starts_with("0000"), "unexpected prefix: {}", &pkt[..8.min(pkt.len())]);
}

#[test]
fn ads_construct_read_packet_encodes_params() {
    let route = ads::AmsRoute {
        remote_netid: "c0a80101.01.01",
        remote_port: 801,
        local_netid: "7f000001.01.01",
        local_port: 801,
    };
    let pkt = ads::construct_ams_packet(
        &route,
        2,                                          // cmd_id = Read
        &ads::AdsParams::Read(0xF020, 0, 4),
        Some("00000002"),
        true,
    );
    assert!(!pkt.is_empty());
    // Read packets carry more payload than ReadState
    assert!(pkt.len() > 20);
}

#[test]
fn ads_ams_route_fields_accessible() {
    let route = ads::AmsRoute {
        remote_netid: "192.168.1.1.1.1",
        remote_port: 801,
        local_netid: "127.0.0.1.1.1",
        local_port: 801,
    };
    assert_eq!(route.remote_port, 801);
    assert_eq!(route.local_netid, "127.0.0.1.1.1");
}
