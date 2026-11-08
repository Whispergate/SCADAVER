//! Beckhoff `TwinCAT` `ADS`. Typed record, never prints.
//!
//! The legacy arm passed `silent = false`, so casket printed its own discovery lines to stdout
//! behind the report's back, and it kept nothing but a count. This arm reads silently and keeps
//! the `AMS` Net ID, the `TwinCAT` version and the `ADS` state.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::core::network::local_ip_for;
use casket::vendors::beckhoff::ads::build_local_netid;
use casket::vendors::beckhoff::scan;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default ADS port. casket pins UDP discovery to
/// 48899, so `port` selects the ADS/TCP endpoint only.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Beckhoff.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let devices =
        scan::discover_ip_with_port(ip, timeout, true, effective_port).unwrap_or_default();
    let Some(device) = devices.into_iter().next() else {
        outcome.say(Level::Warn, "No Beckhoff TwinCAT response.");
        return outcome;
    };

    // `discover_ip_with_port` can answer from UDP discovery without ever touching the ADS port,
    // so ask the ADS endpoint for its state explicitly. "ERROR" is casket's failure sentinel.
    let local_netid = build_local_netid(&local_ip_for(ip));
    let ads_state = scan::get_state(&device, &local_netid, effective_port);

    let mut fields = BTreeMap::new();
    fields.insert("name".to_string(), serde_json::json!(&device.name));
    fields.insert("netid".to_string(), serde_json::json!(&device.netid_str));
    fields.insert(
        "tc_version".to_string(),
        serde_json::json!(&device.tc_version),
    );
    fields.insert("kernel".to_string(), serde_json::json!(&device.kernel));
    fields.insert("ads_state".to_string(), serde_json::json!(&ads_state));
    fields.insert("ads_port".to_string(), serde_json::json!(effective_port));

    if ads_state != "ERROR" {
        if let Some(info) = scan::get_device_info_full(&device, &local_netid, effective_port) {
            let optional = [
                ("target_type", info.target_type),
                ("hardware_model", info.hardware_model),
                ("serial", info.serial),
                ("os_name", info.os_name),
                ("os_version", info.os_version),
            ];
            for (key, value) in optional.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))) {
                fields.insert(key.to_string(), serde_json::json!(value));
            }
        }
    }

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Beckhoff,
        vendor: "beckhoff".to_string(),
        identity: Some(device.name).filter(|name| !name.is_empty()),
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Beckhoff TwinCAT device on {ip}:{effective_port} ({ads_state})."),
    );

    outcome
}
