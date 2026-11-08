//! eWON `IPCONF` discovery and published-register codec. Typed, no printing.
//!
//! The legacy arm printed the web port (80) as `ipconf_port` while handing the scan no port at
//! all, and the old table claimed 67 (BOOTP), which nothing ever used. Port 0 resolves to
//! casket's `IPCONF` port 1507 through `Protocol::default_port()`.
//!
//! The register codec lives here rather than in a surface because it is wire semantics: Flexy
//! publishes 32-bit values as low word first while Modbus itself stays big-endian on the wire.
//! A surface that owns that rule gets it wrong once per surface.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::ewon::scan::scan_ip_with_port;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default, 1507 (casket's IPCONF port).
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Ewon.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // casket reads with a plain read timeout. Clamp at 1 s: a zero timeout becomes a zero
    // SO_RCVTIMEO, which waits forever rather than not at all.
    let devices = match scan_ip_with_port(ip, timeout.max(1), true, effective_port) {
        Ok(devices) => devices,
        Err(error) => {
            outcome.say(
                Level::Warn,
                format!("eWON discovery failed on {ip}:{effective_port}: {error}"),
            );
            return outcome;
        }
    };

    let Some(device) = devices
        .iter()
        .find(|device| device.response_type == "device_info")
        .or_else(|| devices.first())
    else {
        outcome.say(
            Level::Warn,
            format!("No eWON response from {ip}:{effective_port}."),
        );
        return outcome;
    };

    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("ip", device.ip.as_ref()),
        ("netmask", device.netmask.as_ref()),
        ("mac", device.mac.as_ref()),
        ("serial", device.serial.as_ref()),
        ("product_code", device.product_code.as_ref()),
        ("firmware", device.firmware.as_ref()),
        ("identifier", device.identifier.as_ref()),
    ] {
        if let Some(value) = value {
            fields.insert(key.to_string(), serde_json::json!(value));
        }
    }
    fields.insert(
        "response_type".to_string(),
        serde_json::json!(device.response_type.as_str()),
    );
    fields.insert("responses".to_string(), serde_json::json!(devices.len()));

    // Best human label: the serial number, then the MAC the device announced.
    let identity = device.serial.clone().or_else(|| device.mac.clone());

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Ewon,
        vendor: "ewon".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("eWON device answered on {ip}:{effective_port}."),
    );

    outcome
}

// ---------------------------------------------------------------------------
// Published-register codec.
//
// An eWON Flexy publishes tag values into Modbus holding registers. 16-bit kinds occupy
// one register; 32-bit kinds occupy two, low word then high word, even though each register
// is big-endian on the wire. Nothing here prints or talks to a socket, so the rule is
// testable without a simulator and shared by every surface.
// ---------------------------------------------------------------------------

/// Flexy's published-register default Modbus unit id.
pub const FLEXY_DEFAULT_UNIT_ID: u8 = 100;

/// Smallest and largest legal Modbus TCP unit id (247 is the last addressable slave).
const UNIT_ID_RANGE: std::ops::RangeInclusive<u8> = 1..=247;

/// Data representation for a published eWON Flexy Modbus holding register.
///
/// Flexy publishes 32-bit values as low 16-bit word followed by high 16-bit word.
/// Individual Modbus registers remain big-endian on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterKind {
    U16,
    I16,
    U32,
    I32,
    F32,
}

impl RegisterKind {
    /// Every kind, in the order the CLI documents them. clap's value list is built from this.
    pub const ALL: [Self; 5] = [Self::U16, Self::I16, Self::U32, Self::I32, Self::F32];

    /// Modbus registers one value occupies: 1 for 16-bit, 2 for 32-bit.
    #[must_use]
    pub fn word_count(self) -> u16 {
        match self {
            Self::U16 | Self::I16 => 1,
            Self::U32 | Self::I32 | Self::F32 => 2,
        }
    }
}

/// Resolve a user-supplied port to the one the request will use. Port 0 means Modbus's 502.
#[must_use]
pub fn modbus_port(port: u16) -> u16 {
    casket::core::modbus::effective_port(port)
}

/// Reject unit ids the Modbus wire cannot carry, naming the range and the Flexy default.
pub fn validate_unit_id(unit_id: u8) -> Result<(), String> {
    if UNIT_ID_RANGE.contains(&unit_id) {
        return Ok(());
    }
    Err(format!(
        "eWON Modbus unit id {unit_id} is invalid; use a value from 1 through 247 (Flexy default: {FLEXY_DEFAULT_UNIT_ID})"
    ))
}

/// Turn the words a Modbus read returned into the value Flexy published.
///
/// Extra words beyond `kind.word_count()` are ignored: a 16-bit kind reads one register, and
/// the caller asked for exactly one.
pub fn decode_register(words: &[u16], kind: RegisterKind) -> Result<String, String> {
    let required = usize::from(kind.word_count());
    if words.len() < required {
        return Err(format!(
            "eWON Modbus response returned {} word(s), expected {required}",
            words.len()
        ));
    }
    let value = match kind {
        RegisterKind::U16 => words[0].to_string(),
        RegisterKind::I16 => i16::from_ne_bytes(words[0].to_ne_bytes()).to_string(),
        RegisterKind::U32 => join_words(words).to_string(),
        RegisterKind::I32 => i32::from_ne_bytes(join_words(words).to_ne_bytes()).to_string(),
        RegisterKind::F32 => {
            let value = f32::from_bits(join_words(words));
            if !value.is_finite() {
                return Err("eWON Modbus value is not a finite f32".to_string());
            }
            value.to_string()
        }
    };
    Ok(value)
}

/// Turn a typed value into the words a Modbus write should carry, low word first.
///
/// Parse failures name the kind and the offending text, because the two things a user can
/// get wrong here are the type flag and the number.
pub fn encode_register(value: &str, kind: RegisterKind) -> Result<Vec<u16>, String> {
    let value = value.trim();
    let words = match kind {
        RegisterKind::U16 => vec![value
            .parse::<u16>()
            .map_err(|_| format!("invalid u16 value '{value}'"))?],
        RegisterKind::I16 => vec![u16::from_ne_bytes(
            value
                .parse::<i16>()
                .map_err(|_| format!("invalid i16 value '{value}'"))?
                .to_ne_bytes(),
        )],
        RegisterKind::U32 => split_words(
            value
                .parse::<u32>()
                .map_err(|_| format!("invalid u32 value '{value}'"))?,
        ),
        RegisterKind::I32 => split_words(u32::from_ne_bytes(
            value
                .parse::<i32>()
                .map_err(|_| format!("invalid i32 value '{value}'"))?
                .to_ne_bytes(),
        )),
        RegisterKind::F32 => {
            let parsed = value
                .parse::<f32>()
                .map_err(|_| format!("invalid f32 value '{value}'"))?;
            if !parsed.is_finite() {
                return Err("eWON f32 value must be finite".to_string());
            }
            split_words(parsed.to_bits())
        }
    };
    Ok(words)
}

/// Low word then high word. Both halves are masked before the cast, so each one fits a u16.
fn split_words(bits: u32) -> Vec<u16> {
    vec![(bits & 0xffff) as u16, (bits >> 16) as u16]
}

/// Recombine the two words `decode_register` was handed. Callers guarantee the length.
fn join_words(words: &[u16]) -> u32 {
    u32::from(words[0]) | (u32::from(words[1]) << 16)
}

// ---------------------------------------------------------------------------
// Live reads and writes.
//
// These own the socket call as well as the codec, because the surface that opened the
// client had to repeat the encode/decode dance around it. Errors name the operation and
// the endpoint: "read failed" is useless once three protocols in a session can fail.
// Nothing here prints; the caller renders the typed result.
// ---------------------------------------------------------------------------

/// The result of one holding-register read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRead {
    pub address: u16,
    pub kind: RegisterKind,
    pub unit_id: u8,
    /// Registers requested (the kind's word count), not the ones an answer happened to hold.
    pub words: u16,
    pub value: String,
}

/// The result of one coil read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoilRead {
    pub address: u16,
    pub unit_id: u8,
    pub on: bool,
}

impl CoilRead {
    /// The same text casket gives a coil register, so renders do not fork per surface.
    #[must_use]
    pub fn state(&self) -> &'static str {
        if self.on {
            "ON"
        } else {
            "OFF"
        }
    }
}

/// Read one published holding register and decode it by `kind`.
pub fn read_register(
    ip: &str,
    port: u16,
    unit_id: u8,
    address: u16,
    kind: RegisterKind,
) -> Result<RegisterRead, String> {
    validate_unit_id(unit_id)?;
    let port = modbus_port(port);
    let words = kind.word_count();
    let registers = casket::core::modbus::read_holding_registers_with_unit_id(
        ip, port, unit_id, address, words,
    )
    .map_err(|error| {
        format!("eWON Modbus read of HR{address} from {ip}:{port} (unit {unit_id}) failed: {error}")
    })?;
    let raw: Vec<u16> = registers.iter().map(|register| register.raw).collect();
    let value = decode_register(&raw, kind)?;
    Ok(RegisterRead {
        address,
        kind,
        unit_id,
        words,
        value,
    })
}

/// Read one coil.
pub fn read_coil(ip: &str, port: u16, unit_id: u8, address: u16) -> Result<CoilRead, String> {
    validate_unit_id(unit_id)?;
    let port = modbus_port(port);
    let coils = casket::core::modbus::read_coils_with_unit_id(ip, port, unit_id, address, 1)
        .map_err(|error| {
            format!(
                "eWON Modbus coil read of {address} from {ip}:{port} (unit {unit_id}) failed: {error}"
            )
        })?;
    let coil = coils.first().ok_or_else(|| {
        format!("eWON Modbus coil read of {address} from {ip}:{port} (unit {unit_id}) returned no value")
    })?;
    Ok(CoilRead {
        address,
        unit_id,
        // `raw` is the bit; `value_str` is casket's display rendering ("ON"/"OFF")
        // and must not be the source of truth for a state.
        on: coil.raw == 1,
    })
}

/// Write one published holding register; one word uses FC06, two use FC16.
pub fn write_register(
    ip: &str,
    port: u16,
    unit_id: u8,
    address: u16,
    value: &str,
    kind: RegisterKind,
) -> Result<(), String> {
    validate_unit_id(unit_id)?;
    let port = modbus_port(port);
    let words = encode_register(value, kind)?;
    let write = if words.len() == 1 {
        casket::core::modbus::write_single_register_with_unit_id(
            ip, port, unit_id, address, words[0],
        )
    } else {
        // The multiple-register write reports the count it wrote; one register is all we claim.
        casket::core::modbus::write_multiple_registers_with_unit_id(
            ip, port, unit_id, address, &words,
        )
        .map(|_written| ())
    };
    write.map_err(|error| {
        format!("eWON Modbus write of HR{address} to {ip}:{port} (unit {unit_id}) failed: {error}")
    })
}

/// Write one coil and return whether it was set on.
pub fn write_coil(
    ip: &str,
    port: u16,
    unit_id: u8,
    address: u16,
    state: &str,
) -> Result<bool, String> {
    validate_unit_id(unit_id)?;
    let on = parse_coil_state(state)?;
    let port = modbus_port(port);
    casket::core::modbus::write_single_coil_with_unit_id(ip, port, unit_id, address, on).map_err(
        |error| {
            format!(
                "eWON Modbus coil write of {address} to {ip}:{port} (unit {unit_id}) failed: {error}"
            )
        },
    )?;
    Ok(on)
}

/// Accept exactly the two words the CLI documents, any case, surrounding space allowed.
pub fn parse_coil_state(state: &str) -> Result<bool, String> {
    let state = state.trim();
    if state.eq_ignore_ascii_case("on") {
        return Ok(true);
    }
    if state.eq_ignore_ascii_case("off") {
        return Ok(false);
    }
    Err(format!(
        "invalid eWON coil state '{state}': use 'on' or 'off'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_count_matches_width() {
        assert_eq!(RegisterKind::U16.word_count(), 1);
        assert_eq!(RegisterKind::I16.word_count(), 1);
        assert_eq!(RegisterKind::U32.word_count(), 2);
        assert_eq!(RegisterKind::I32.word_count(), 2);
        assert_eq!(RegisterKind::F32.word_count(), 2);
        assert_eq!(RegisterKind::ALL.len(), 5);
    }

    #[test]
    fn decodes_16_bit_kinds_from_the_first_word() {
        assert_eq!(
            decode_register(&[0], RegisterKind::U16),
            Ok("0".to_string())
        );
        assert_eq!(
            decode_register(&[513], RegisterKind::U16),
            Ok("513".to_string())
        );
        // A 16-bit kind asked for one register; a longer slice must not change the answer.
        assert_eq!(
            decode_register(&[513, 999], RegisterKind::U16),
            Ok("513".to_string())
        );
        assert_eq!(
            decode_register(&[0xffff], RegisterKind::I16),
            Ok("-1".to_string())
        );
        assert_eq!(
            decode_register(&[0x8000], RegisterKind::I16),
            Ok("-32768".to_string())
        );
    }

    #[test]
    fn decodes_32_bit_kinds_low_word_first() {
        // 65538 = 0x0001_0002: low word 2, high word 1.
        assert_eq!(
            decode_register(&[2, 1], RegisterKind::U32),
            Ok("65538".to_string())
        );
        assert_eq!(
            decode_register(&[0xffff, 0xffff], RegisterKind::I32),
            Ok("-1".to_string())
        );
        // 1.5f32 = 0x3FC0_0000: low word 0x0000, high word 0x3FC0.
        assert_eq!(
            decode_register(&[0x0000, 0x3fc0], RegisterKind::F32),
            Ok("1.5".to_string())
        );
    }

    #[test]
    fn decode_names_the_short_word_count() {
        assert_eq!(
            decode_register(&[], RegisterKind::U16),
            Err("eWON Modbus response returned 0 word(s), expected 1".to_string())
        );
        assert_eq!(
            decode_register(&[7], RegisterKind::U32),
            Err("eWON Modbus response returned 1 word(s), expected 2".to_string())
        );
    }

    #[test]
    fn decode_rejects_non_finite_f32() {
        for high in [0x7fc0u16, 0x7f80, 0xff80] {
            assert_eq!(
                decode_register(&[0, high], RegisterKind::F32),
                Err("eWON Modbus value is not a finite f32".to_string())
            );
        }
    }

    #[test]
    fn encode_round_trips_every_kind() {
        for (kind, text) in [
            (RegisterKind::U16, "65535"),
            (RegisterKind::I16, "-32768"),
            (RegisterKind::U32, "4294967295"),
            (RegisterKind::I32, "-2147483648"),
            (RegisterKind::F32, "1.5"),
        ] {
            let words = encode_register(text, kind).expect("value is in range");
            assert_eq!(
                words.len(),
                usize::from(kind.word_count()),
                "{kind:?} word count"
            );
            assert_eq!(
                decode_register(&words, kind),
                Ok(text.to_string()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn encode_writes_low_word_first_and_trims() {
        assert_eq!(encode_register("65538", RegisterKind::U32), Ok(vec![2, 1]));
        // 305419896 = 0x1234_5678, the vector the cli test used to pin.
        assert_eq!(
            encode_register("305419896", RegisterKind::U32),
            Ok(vec![0x5678, 0x1234])
        );
        assert_eq!(encode_register("-1", RegisterKind::I16), Ok(vec![0xffff]));
        assert_eq!(encode_register(" 7 ", RegisterKind::U16), Ok(vec![7]));
        // 73.5f32 = 0x4293_0000.
        assert_eq!(
            decode_register(&[0x0000, 0x4293], RegisterKind::F32),
            Ok("73.5".to_string())
        );
    }

    #[test]
    fn encode_names_the_kind_on_a_bad_value() {
        assert_eq!(
            encode_register("65536", RegisterKind::U16),
            Err("invalid u16 value '65536'".to_string())
        );
        assert_eq!(
            encode_register("32768", RegisterKind::I16),
            Err("invalid i16 value '32768'".to_string())
        );
        assert_eq!(
            encode_register("4294967296", RegisterKind::U32),
            Err("invalid u32 value '4294967296'".to_string())
        );
        assert_eq!(
            encode_register("-2147483649", RegisterKind::I32),
            Err("invalid i32 value '-2147483649'".to_string())
        );
        assert_eq!(
            encode_register("twelve", RegisterKind::F32),
            Err("invalid f32 value 'twelve'".to_string())
        );
        assert_eq!(
            encode_register("inf", RegisterKind::F32),
            Err("eWON f32 value must be finite".to_string())
        );
        assert_eq!(
            encode_register("NaN", RegisterKind::F32),
            Err("eWON f32 value must be finite".to_string())
        );
    }

    #[test]
    fn unit_id_range_is_one_through_247() {
        for good in [1u8, 100, 247] {
            assert_eq!(validate_unit_id(good), Ok(()), "unit id {good}");
        }
        for bad in [0u8, 248, 255] {
            let error = validate_unit_id(bad).expect_err("out of range");
            assert!(
                error.contains(&format!("unit id {bad} is invalid")),
                "{error}"
            );
            assert!(error.contains("Flexy default: 100"), "{error}");
        }
    }

    #[test]
    fn port_zero_is_the_modbus_default() {
        assert_eq!(modbus_port(0), 502);
        assert_eq!(modbus_port(1507), 1507);
        assert_eq!(modbus_port(18082), 18082);
    }

    #[test]
    fn parse_coil_state_accepts_on_off_in_any_case_and_trims() {
        assert_eq!(parse_coil_state("on"), Ok(true));
        assert_eq!(parse_coil_state("ON"), Ok(true));
        assert_eq!(parse_coil_state(" off "), Ok(false));
        assert_eq!(parse_coil_state("Off"), Ok(false));
    }

    #[test]
    fn parse_coil_state_names_the_accepted_words() {
        // "1"/"0" are the tempting wrong guess, so the message has to say what is allowed.
        for bad in ["1", "0", "true", "yes", ""] {
            let error = parse_coil_state(bad).expect_err("not a documented state");
            assert!(error.contains("use 'on' or 'off'"), "{error}");
        }
    }

    #[test]
    fn coil_state_renders_the_same_words_casket_does() {
        let on = CoilRead {
            address: 7,
            unit_id: 100,
            on: true,
        };
        let off = CoilRead {
            address: 7,
            unit_id: 100,
            on: false,
        };
        assert_eq!(on.state(), "ON");
        assert_eq!(off.state(), "OFF");
    }

    #[test]
    fn write_path_rejects_a_bad_unit_id_before_it_opens_a_socket() {
        // 0.0.0.0 and port 1 are unreachable, so a socket attempt would time out. The unit id
        // check has to fire first, which is what keeps the error message about the real mistake.
        let error = write_register("0.0.0.0", 1, 0, 1, "1", RegisterKind::U16)
            .expect_err("unit id 0 is invalid");
        assert!(error.contains("unit id 0 is invalid"), "{error}");
        let error = read_coil("0.0.0.0", 1, 248, 1).expect_err("unit id 248 is invalid");
        assert!(error.contains("unit id 248 is invalid"), "{error}");
        let error = write_coil("0.0.0.0", 1, 100, 1, "maybe").expect_err("state is not on or off");
        assert!(error.contains("use 'on' or 'off'"), "{error}");
    }
}
