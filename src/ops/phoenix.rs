//! Phoenix Contact `ProConOS` device info on 1962: PLC type, firmware, build.
//!
//! The legacy arm repeated the literal `1962` as its fallback instead of asking
//! `Protocol::Phoenix.default_port()`, so the number lived in two places. It passed
//! `silent = true` to casket and then printed the same fields itself.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::phoenix::control;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `get_device_info` owns its own
/// connect and read timing (a five second constant), so `_timeout` is accepted for a uniform
/// dispatch signature and ignored here on purpose.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Phoenix.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // `silent = true`: the library must not write to stdout behind the surface's back.
    let device = match control::get_device_info(ip, effective_port, true) {
        Ok(device) => device,
        Err(error) => {
            outcome.say(
                Level::Warn,
                format!("No Phoenix Contact response from {ip}:{effective_port}: {error}"),
            );
            return outcome;
        }
    };

    // A device that answers with a frame too short to hold the identity yields three empty
    // strings. That is no information, so it is reported the same way as silence.
    if device.plc_type.is_empty() && device.firmware.is_none() && device.build.is_none() {
        outcome.say(
            Level::Warn,
            format!("No Phoenix Contact identity on {ip}:{effective_port}."),
        );
        return outcome;
    }

    let mut fields = BTreeMap::new();
    fields.insert("plc_type".to_string(), serde_json::json!(device.plc_type));
    if let Some(firmware) = device.firmware.as_ref() {
        fields.insert("firmware".to_string(), serde_json::json!(firmware));
    }
    if let Some(build) = device.build.as_ref() {
        fields.insert("build".to_string(), serde_json::json!(build));
    }
    fields.insert(
        "phoenix_info_port".to_string(),
        serde_json::json!(effective_port),
    );

    let identity = Some(device.plc_type.clone()).filter(|plc_type| !plc_type.is_empty());

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Phoenix,
        vendor: "phoenix".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Phoenix Contact device on {ip}:{effective_port}."),
    );

    outcome
}
