//! DNP3: link-status detection plus group 0 device attributes. Typed, never prints.
//!
//! The legacy arm read `device_attributes` off the struct that `detect_with_port` builds, and
//! that field is always empty there, so the attributes were never actually fetched. This module
//! sends the group 0 read itself.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::dnp3::client;
use std::collections::BTreeMap;
use std::time::Duration;

/// Probe one host. `port = 0` means the registered default.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Dnp3.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let Some(device) = client::detect_with_port(ip, effective_port, Duration::from_secs(timeout))
    else {
        outcome.say(Level::Warn, "No DNP3 outstation responded.");
        return outcome;
    };

    let attributes = client::read_device_attributes_with_port(
        ip,
        effective_port,
        Duration::from_secs(timeout),
    );

    let mut fields = BTreeMap::new();
    fields.insert(
        "outstation".to_string(),
        serde_json::json!(format!("0x{:04x}", device.outstation_addr)),
    );
    for (key, value) in &attributes {
        fields.insert(format!("attr.{key}"), serde_json::json!(value));
    }

    // Best available human label: the user assigned name, then the device name, then the vendor.
    let identity = ["user_assigned_name", "device_name", "vendor_name"]
        .iter()
        .find_map(|key| attributes.get(*key).cloned())
        .or_else(|| Some(format!("outstation 0x{:04x}", device.outstation_addr)));

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Dnp3,
        vendor: "dnp3".to_string(),
        identity,
        fields,
    });
    outcome.say(Level::Success, format!("DNP3 outstation on {ip}:{effective_port}."));

    outcome
}
