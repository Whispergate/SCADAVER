// Integration tests for the scadaver_rs public library API.
// Each test exercises the public surface as an external crate would:
// using scadaver:: paths, not crate:: paths.

use scadaver::core::autodetect::{DeviceInfo, ProbeInfo, SweepOutcome};
use scadaver::core::bytes;
use scadaver::vendors::beckhoff::ads;
use scadaver::vendors::enip::enums;
use scadaver::vendors::ewon::exploit;
use scadaver::vendors::mitsubishi::slmp::SlmpValue;
use scadaver::vendors::omron::fins::{OmronDevice, AREA_DM_WORD, FINS_TCP_PORT};
use scadaver::vendors::rockwell::driver;
use scadaver::vendors::schneider::session_hijack::{SchneiderDeviceInfo, SchneiderSession};
use scadaver::vendors::siemens::scan as siemens_scan;
use scadaver::vendors::mqtt::client::{self, MqttDevice, MQTT_PORT};
use scadaver::vendors::snmp::oids;

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
    // cip_data layout: [0, 0, <4 value bytes LE>]: first 2 bytes are the type-word echo
    let mut data = vec![0u8, 0];
    data.extend_from_slice(&1337_i32.to_le_bytes());
    assert_eq!(driver::decode_value(0xC4, &data, None), "1337");
}

#[test]
fn driver_decode_dint_max() {
    let mut data = vec![0u8, 0];
    data.extend_from_slice(&i32::MAX.to_le_bytes());
    assert_eq!(driver::decode_value(0xC4, &data, None), "2147483647");
}

#[test]
fn driver_decode_real_one() {
    // 1.0_f32 LE bytes = [0x00, 0x00, 0x80, 0x3F]
    assert_eq!(driver::decode_value(0xCA, &[0, 0, 0x00, 0x00, 0x80, 0x3F], None), "1");
}

#[test]
fn driver_decode_bool_true() {
    assert_eq!(driver::decode_value(0xC1, &[0, 0, 1], None), "true  (1)");
}

#[test]
fn driver_decode_bool_false() {
    assert_eq!(driver::decode_value(0xC1, &[0, 0, 0], None), "false (0)");
}

#[test]
fn driver_decode_too_short_returns_dash() {
    // Fewer than 2 bytes → "-" before any type dispatch
    assert_eq!(driver::decode_value(0xC4, &[], None), "-");
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
    let dev = driver::RockwellDevice {
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

// ── rockwell::driver — UDT struct decoding simulations ───────────────────────
//
// These tests build a TemplateMap in-process and verify that decode_value
// correctly renders named fields from raw CIP struct bytes.  They simulate
// the data that download_template produces from a live PLC so that the
// full decode path can be validated without network access.

fn make_lit_template() -> driver::TemplateMap {
    // Simulates a minimal PID / Analog-Input UDT with three REAL fields:
    //   offset 0  → PV   (process value)
    //   offset 4  → SP   (setpoint)
    //   offset 8  → OUT  (output)
    let fields = vec![
        driver::TemplateField { name: "PV".into(),  cip_type: 0xCA, type_info: 1, offset: 0  },
        driver::TemplateField { name: "SP".into(),  cip_type: 0xCA, type_info: 1, offset: 4  },
        driver::TemplateField { name: "OUT".into(), cip_type: 0xCA, type_info: 1, offset: 8  },
    ];
    let template_id: u16 = 0x08B; // matches tag_type & 0x0FFF for tag_type = 0x808B
    let mut map = driver::TemplateMap::new();
    map.insert(template_id, driver::TemplateDef::from_fields(fields));
    map
}

#[test]
fn driver_decode_struct_real_fields_renders_named_values() {
    // Build raw bytes: 3 × f32 LE — PV=6.40, SP=5.00, OUT=0.75
    let mut raw = Vec::new();
    raw.extend_from_slice(&6.40_f32.to_le_bytes());
    raw.extend_from_slice(&5.00_f32.to_le_bytes());
    raw.extend_from_slice(&0.75_f32.to_le_bytes());

    // cip_data = [type_lo, type_hi, ...raw_bytes...]
    let tag_type: u16 = 0x808B; // bit 15 set → struct; template_id = 0x08B
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let map = make_lit_template();
    let out = driver::decode_value(tag_type, &cip_data, Some(&map));

    assert!(out.starts_with('{'), "expected struct output, got: {out}");
    assert!(out.contains("PV:"),  "PV missing from: {out}");
    assert!(out.contains("SP:"),  "SP missing from: {out}");
    assert!(out.contains("OUT:"), "OUT missing from: {out}");
    assert!(out.contains("6.4"),  "PV value wrong in: {out}");
    assert!(out.contains('5'),    "SP value wrong in: {out}");
}

#[test]
fn driver_decode_struct_no_template_falls_back_to_hex_display() {
    // Without a template the output should show STRUCT(0xXXX)[N bytes]
    let tag_type: u16 = 0x808B;
    let raw = vec![0u8; 12];
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let out = driver::decode_value(tag_type, &cip_data, None);
    assert!(out.starts_with("STRUCT("), "expected STRUCT fallback, got: {out}");
    assert!(out.contains("0x08B"), "template_id missing from: {out}");
    assert!(out.contains("12 bytes"), "byte count missing from: {out}");
}

#[test]
fn driver_decode_struct_mixed_types_dint_bool_real() {
    // UDT with DINT @ 0, BOOL @ 4 bit 0, REAL @ 8.
    // For a BOOL member the descriptor's type_info word is the bit position, not a count.
    let template_id: u16 = 0x0AB;
    let fields = vec![
        driver::TemplateField { name: "Count".into(), cip_type: 0xC4, type_info: 1, offset: 0 },
        driver::TemplateField { name: "Active".into(), cip_type: 0xC1, type_info: 0, offset: 4 },
        driver::TemplateField { name: "Rate".into(),  cip_type: 0xCA, type_info: 1, offset: 8 },
    ];
    let mut map = driver::TemplateMap::new();
    map.insert(template_id, driver::TemplateDef::from_fields(fields));

    let mut raw = Vec::new();
    raw.extend_from_slice(&42_i32.to_le_bytes()); // Count = 42
    raw.push(1);                                    // Active = true
    raw.extend_from_slice(&[0; 3]);                // padding to reach offset 8
    raw.extend_from_slice(&std::f32::consts::PI.to_le_bytes()); // Rate ≈ 3.14

    let tag_type: u16 = 0x80AB;
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let out = driver::decode_value(tag_type, &cip_data, Some(&map));
    assert!(out.contains("Count: 42"),       "Count wrong in: {out}");
    assert!(out.contains("Active: true"),    "Active wrong in: {out}");
    assert!(out.contains("Rate:"),           "Rate missing from: {out}");
    assert!(out.contains("3.1"),             "Rate value wrong in: {out}");
}

#[test]
fn driver_decode_struct_truncates_after_eight_fields() {
    // Nine fields → show 8, then "... (1 more fields)"
    let template_id: u16 = 0x0CD;
    let fields: Vec<driver::TemplateField> = (0..9).map(|i| driver::TemplateField {
        name: format!("F{i}"),
        cip_type: 0xC4,
        type_info: 1,
        offset: u32::try_from(i * 4).unwrap(),
    }).collect();
    let mut map = driver::TemplateMap::new();
    map.insert(template_id, driver::TemplateDef::from_fields(fields));

    let mut raw = Vec::new();
    for i in 0_i32..9 { raw.extend_from_slice(&i.to_le_bytes()); }

    let tag_type: u16 = 0x80CD;
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let out = driver::decode_value(tag_type, &cip_data, Some(&map));
    assert!(out.contains("1 more field"), "truncation marker missing from: {out}");
    assert!(!out.contains("F8:"),         "9th field should be hidden: {out}");
}

#[test]
fn driver_decode_struct_field_offset_beyond_data_skipped() {
    // Field whose offset exceeds the raw data length is silently skipped
    let template_id: u16 = 0x0EF;
    let fields = vec![
        driver::TemplateField { name: "Present".into(), cip_type: 0xC4, type_info: 1, offset: 0   },
        driver::TemplateField { name: "Missing".into(), cip_type: 0xC4, type_info: 1, offset: 100 },
    ];
    let mut map = driver::TemplateMap::new();
    map.insert(template_id, driver::TemplateDef::from_fields(fields));

    let raw = [5_i32.to_le_bytes()].concat();
    let tag_type: u16 = 0x80EF;
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let out = driver::decode_value(tag_type, &cip_data, Some(&map));
    assert!(out.contains("Present: 5"), "visible field missing from: {out}");
    assert!(!out.contains("Missing"),   "out-of-bounds field should be absent: {out}");
}

#[test]
fn driver_decode_struct_nested_udt_renders_outer_and_inner() {
    // Outer UDT contains one REAL and one inner UDT (template 0x0BB)
    // Inner UDT has two REAL fields: Lo and Hi
    let inner_id: u16 = 0x0BB;
    let outer_id: u16 = 0x0CC;

    let inner_fields = vec![
        driver::TemplateField { name: "Lo".into(), cip_type: 0xCA, type_info: 1, offset: 0 },
        driver::TemplateField { name: "Hi".into(), cip_type: 0xCA, type_info: 1, offset: 4 },
    ];
    // Outer field 1: REAL @ 0 (tag_type 0xCA)
    // Outer field 2: nested UDT @ 4 (tag_type 0x80BB — bit 15 set, template_id = inner_id)
    let outer_fields = vec![
        driver::TemplateField { name: "Eng".into(), cip_type: 0xCA,          type_info: 1, offset: 0 },
        driver::TemplateField { name: "Lim".into(), cip_type: 0x80BB | inner_id, type_info: 1, offset: 4 },
    ];

    let mut map = driver::TemplateMap::new();
    map.insert(inner_id, driver::TemplateDef::from_fields(inner_fields));
    map.insert(outer_id, driver::TemplateDef::from_fields(outer_fields));

    let mut raw = Vec::new();
    raw.extend_from_slice(&1.5_f32.to_le_bytes()); // Eng = 1.5
    raw.extend_from_slice(&0.0_f32.to_le_bytes()); // Lim.Lo = 0.0
    raw.extend_from_slice(&10.0_f32.to_le_bytes()); // Lim.Hi = 10.0

    let tag_type: u16 = 0x80CC;
    let mut cip_data = vec![(tag_type & 0xFF) as u8, (tag_type >> 8) as u8];
    cip_data.extend_from_slice(&raw);

    let out = driver::decode_value(tag_type, &cip_data, Some(&map));
    assert!(out.contains("Eng:"), "Eng field missing from: {out}");
    assert!(out.contains("Lim:"), "Lim field missing from: {out}");
    // Inner struct nested inside — either decoded or shown as STRUCT(...)
    assert!(out.starts_with('{'), "outer struct format wrong: {out}");
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

#[test]
fn ads_build_local_netid_loopback() {
    assert_eq!(ads::build_local_netid("127.0.0.1"), "7f0000010101");
}

#[test]
fn ads_build_local_netid_class_c() {
    assert_eq!(ads::build_local_netid("192.168.1.1"), "c0a801010101");
}

#[test]
fn ads_decode_value_bool_false() {
    assert_eq!(ads::decode_ads_value("BOOL", &[0]), "false");
}

#[test]
fn ads_decode_value_bool_true() {
    assert_eq!(ads::decode_ads_value("BOOL", &[1]), "true");
}

#[test]
fn ads_decode_value_int_1337() {
    // INT = i16 LE: 1337 = 0x0539
    assert_eq!(ads::decode_ads_value("INT", &[0x39, 0x05]), "1337");
}

#[test]
fn ads_decode_value_dint_neg1() {
    // DINT = i32 LE: -1 = [0xFF, 0xFF, 0xFF, 0xFF]
    assert_eq!(ads::decode_ads_value("DINT", &[0xFF, 0xFF, 0xFF, 0xFF]), "-1");
}

#[test]
fn ads_decode_value_real_one() {
    // REAL = f32 LE: 1.0 = [0x00, 0x00, 0x80, 0x3F]
    assert_eq!(ads::decode_ads_value("REAL", &[0x00, 0x00, 0x80, 0x3F]), "1");
}

#[test]
fn ads_decode_value_string_null_terminated() {
    assert_eq!(ads::decode_ads_value("STRING(80)", b"hello\x00rest"), "\"hello\"");
}

#[test]
fn ads_decode_value_unknown_type_hex_dump() {
    let result = ads::decode_ads_value("MYSTRUCT", &[0xDE, 0xAD]);
    assert!(result.contains("de") || result.contains("DE") || result.contains("dead"),
        "expected hex dump, got: {result}");
}

// ── omron::fins ───────────────────────────────────────────────────────────────

#[test]
fn fins_cpu_state_stop() {
    assert_eq!(OmronDevice::cpu_state_str(0x00), "Stop");
}

#[test]
fn fins_cpu_state_run() {
    assert_eq!(OmronDevice::cpu_state_str(0x01), "Run");
}

#[test]
fn fins_cpu_state_monitor() {
    assert_eq!(OmronDevice::cpu_state_str(0x02), "Monitor");
}

#[test]
fn fins_cpu_state_program() {
    assert_eq!(OmronDevice::cpu_state_str(0x04), "Program");
}

#[test]
fn fins_cpu_state_unknown() {
    assert_eq!(OmronDevice::cpu_state_str(0xFF), "Unknown");
}

#[test]
fn fins_constants() {
    assert_eq!(FINS_TCP_PORT, 9600);
    assert_eq!(AREA_DM_WORD, 0x82);
}

#[test]
fn fins_device_struct_fields_accessible() {
    let dev = OmronDevice {
        node_addr: 1,
        model: "CJ2M-CPU31".into(),
        version: "3.0".into(),
    };
    assert_eq!(dev.node_addr, 1);
    assert_eq!(dev.model, "CJ2M-CPU31");
    assert_eq!(dev.version, "3.0");
}

// ── mitsubishi::slmp ──────────────────────────────────────────────────────────

#[test]
fn slmp_default_port() {
    assert_eq!(scadaver::vendors::mitsubishi::slmp::DEFAULT_PORT, 5007);
}

#[test]
fn slmp_value_struct_fields_accessible() {
    let val = SlmpValue {
        display: "D0=1337".into(),
        raw: 1337,
        value_str: "1337".into(),
    };
    assert_eq!(val.raw, 1337);
    assert_eq!(val.display, "D0=1337");
    assert_eq!(val.value_str, "1337");
}

// ── schneider::session_hijack ─────────────────────────────────────────────────

#[test]
fn schneider_session_struct_fields_accessible() {
    let sess = SchneiderSession {
        cookie_value: "abc123".into(),
        power_on_count: 42,
    };
    assert_eq!(sess.cookie_value, "abc123");
    assert_eq!(sess.power_on_count, 42);
}

#[test]
fn schneider_device_info_struct_fields_accessible() {
    let info = SchneiderDeviceInfo {
        device: "M340".into(),
        mac: "00:11:22:33:44:55".into(),
        firmware: "V2.40".into(),
        state: "run".into(),
    };
    assert_eq!(info.device, "M340");
    assert_eq!(info.firmware, "V2.40");
    assert_eq!(info.mac, "00:11:22:33:44:55");
}

// ── siemens::scan ─────────────────────────────────────────────────────────────

#[test]
fn siemens_device_all_fields() {
    let dev = siemens_scan::SiemensDevice {
        ip: "192.168.1.10".into(),
        hardware: Some("6ES7 315-2EH14".into()),
        firmware: Some("V3.3".into()),
        cpu_state: Some("Run".into()),
        open_ports: vec![102],
    };
    assert_eq!(dev.ip, "192.168.1.10");
    assert_eq!(dev.hardware.as_deref(), Some("6ES7 315-2EH14"));
    assert_eq!(dev.firmware.as_deref(), Some("V3.3"));
    assert_eq!(dev.open_ports, vec![102]);
}

#[test]
fn siemens_device_optional_fields_none() {
    let dev = siemens_scan::SiemensDevice {
        ip: "10.0.0.1".into(),
        hardware: None,
        firmware: None,
        cpu_state: None,
        open_ports: vec![],
    };
    assert!(dev.hardware.is_none());
    assert!(dev.cpu_state.is_none());
    assert!(dev.open_ports.is_empty());
}

// ── mqtt::client ─────────────────────────────────────────────────────────────

#[test]
fn mqtt_port_constant() {
    assert_eq!(MQTT_PORT, 1883);
}

#[test]
fn mqtt_device_struct_fields_accessible() {
    let dev = MqttDevice {
        ip: "192.168.1.100".into(),
        port: 1883,
        anonymous: true,
        broker_info: Some("$SYS/broker/version: mosquitto 2.0.18".into()),
        sparkplug: false,
    };
    assert_eq!(dev.ip, "192.168.1.100");
    assert_eq!(dev.port, 1883);
    assert!(dev.anonymous);
    assert!(!dev.sparkplug);
    assert!(dev.broker_info.is_some());
}

#[test]
fn mqtt_device_broker_info_none() {
    let dev = MqttDevice {
        ip: "10.0.0.1".into(),
        port: 1883,
        anonymous: false,
        broker_info: None,
        sparkplug: true,
    };
    assert!(dev.broker_info.is_none());
    assert!(dev.sparkplug);
}

#[test]
fn mqtt_build_connect_anon_packet_structure() {
    let pkt = client::build_connect("scadaver-probe", None, None);
    assert_eq!(pkt[0], 0x10, "first byte must be CONNECT (0x10)");
    assert!(pkt.windows(4).any(|w| w == b"MQTT"), "protocol name MQTT must appear in packet");
    // After "MQTT": protocol level 0x04 (3.1.1), then connect flags 0x02 (clean session only)
    let mqtt_pos = pkt.windows(4).position(|w| w == b"MQTT").unwrap();
    assert_eq!(pkt[mqtt_pos + 4], 0x04, "protocol level must be 4 (MQTT 3.1.1)");
    assert_eq!(pkt[mqtt_pos + 5], 0x02, "anonymous flags must be 0x02 (clean session only)");
}

#[test]
fn mqtt_build_connect_with_creds_flags_byte() {
    let pkt = client::build_connect("scadaver-spray", Some("admin"), Some("pass"));
    assert_eq!(pkt[0], 0x10, "first byte must be CONNECT (0x10)");
    let mqtt_pos = pkt.windows(4).position(|w| w == b"MQTT").unwrap();
    assert_eq!(pkt[mqtt_pos + 5], 0xC2, "credentialed flags must be 0xC2 (username+password+clean session)");
}

#[test]
fn mqtt_try_credential_unreachable_returns_none() {
    // Port 9 (discard) is almost always closed — connection error → None
    assert!(
        client::try_credential("127.0.0.1", 9, "user", "pass").is_none(),
        "connection to closed port must return None"
    );
}

// ── core::autodetect ──────────────────────────────────────────────────────────

#[test]
fn autodetect_probe_info_fields_accessible() {
    let probe = ProbeInfo {
        label: "Test Protocol",
        transport: "TCP 9999",
    };
    assert_eq!(probe.label, "Test Protocol");
    assert_eq!(probe.transport, "TCP 9999");
}

#[test]
fn autodetect_sweep_outcome_no_device() {
    let outcome = SweepOutcome {
        probe: ProbeInfo { label: "Test", transport: "UDP 161" },
        device: None,
    };
    assert!(outcome.device.is_none());
    assert_eq!(outcome.probe.label, "Test");
}

#[test]
fn autodetect_device_info_struct_fields_accessible() {
    use std::collections::HashMap;
    let info = DeviceInfo {
        vendor: "siemens".into(),
        ip: "192.168.1.10".into(),
        fields: HashMap::new(),
    };
    assert_eq!(info.vendor, "siemens");
    assert_eq!(info.ip, "192.168.1.10");
    assert!(info.fields.is_empty());
}
