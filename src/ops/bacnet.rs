//! `BACnet/IP`: unicast `Who-Is`, then device-object `ReadProperty`, as typed data.
//!
//! The legacy arm called the right function but printed four of the seven device
//! fields, dropping `max_apdu`, `description` and `firmware_revision`, and it
//! printed an empty vendor name as a blank line instead of falling back.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::bacnet::client;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `scan_ip_with_port`
/// takes whole seconds, not a `Duration`, and owns its own socket timing.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Bacnet.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let Some(device) = client::scan_ip_with_port(ip, effective_port, timeout) else {
        outcome.say(Level::Warn, "No BACnet device responded.");
        return outcome;
    };

    let mut fields = BTreeMap::new();
    fields.insert(
        "instance_id".to_string(),
        serde_json::json!(device.instance_id),
    );
    fields.insert("vendor_id".to_string(), serde_json::json!(device.vendor_id));
    fields.insert("max_apdu".to_string(), serde_json::json!(device.max_apdu));
    fields.insert("name".to_string(), serde_json::json!(&device.object_name));
    fields.insert(
        "vendor_name".to_string(),
        serde_json::json!(&device.vendor_name),
    );
    fields.insert(
        "description".to_string(),
        serde_json::json!(device.description),
    );
    fields.insert(
        "firmware_revision".to_string(),
        serde_json::json!(device.firmware_revision),
    );

    // vendor is the protocol slug on every module so the surfaces can group on it.
    // The device's own vendor name is preserved in fields["vendor_name"].
    let vendor = "bacnet".to_string();
    let identity = if device.object_name.is_empty() {
        Some(format!("device {}", device.instance_id))
    } else {
        Some(device.object_name.clone())
    };

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Bacnet,
        vendor,
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!(
            "BACnet device {} on {ip}:{effective_port}.",
            device.instance_id
        ),
    );

    outcome
}
