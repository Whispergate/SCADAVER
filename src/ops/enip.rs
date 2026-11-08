//! EtherNet/IP identity via List Identity. Typed record, never prints.
//!
//! The legacy arm computed an `effective_port` and then never passed it on: casket's
//! `enip::scan::scan_ip` is fixed to 44818, so the port it reported was decorative. This arm
//! reports the port it really probes and stops labelling every EtherNet/IP peer "rockwell".

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::enip::enums::{device_type_name, vendor_name};
use casket::vendors::enip::scan;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. casket 0.1.1 exposes no port argument
/// on the List Identity probe, so a non-default `port` is reported back and left unused.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = Protocol::Enip.default_port();
    let mut outcome = Outcome::default();
    if port != 0 && port != effective_port {
        outcome.say(
            Level::Info,
            format!(
                "EtherNet/IP List Identity is fixed to {effective_port}; port {port} was not probed."
            ),
        );
    }

    let devices = scan::scan_ip(ip, timeout, true).unwrap_or_default();
    let Some(device) = devices.into_iter().next() else {
        outcome.say(Level::Warn, "No EtherNet/IP response.");
        return outcome;
    };

    let vendor_id = u32::from_str_radix(&device.vendor_id, 16).unwrap_or(0);
    let mut fields = BTreeMap::new();
    fields.insert(
        "product_name".to_string(),
        serde_json::json!(&device.product_name),
    );
    fields.insert(
        "vendor_id".to_string(),
        serde_json::json!(&device.vendor_id),
    );
    fields.insert(
        "vendor_name".to_string(),
        serde_json::json!(vendor_name(vendor_id)),
    );
    fields.insert(
        "device_type".to_string(),
        serde_json::json!(device.device_type),
    );
    fields.insert(
        "device_type_name".to_string(),
        serde_json::json!(device_type_name(device.device_type)),
    );
    fields.insert("revision".to_string(), serde_json::json!(&device.revision));

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Enip,
        vendor: "enip".to_string(),
        identity: Some(device.product_name).filter(|name| !name.is_empty()),
        fields,
    });
    outcome.say(
        Level::Success,
        format!("EtherNet/IP device on {ip}:{effective_port}."),
    );

    outcome
}
