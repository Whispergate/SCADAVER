//! Rockwell / Logix identity over EtherNet/IP. Typed record, never prints.
//!
//! The legacy arm printed one device and dropped the numeric product code the driver had just
//! parsed for it; its JSON carried only five strings. This arm keeps the whole identity.
//! The vendor column carries the slug like every other module; casket's device vendor name
//! is preserved in `fields["vendor_name"]`.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::rockwell::driver;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `driver::get_device_info` owns its own
/// five second socket timing, so the shared `timeout` argument is accepted for a uniform dispatch
/// signature and ignored here on purpose.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Rockwell.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let Ok(device) = driver::get_device_info(ip, effective_port) else {
        outcome.say(Level::Warn, "No Rockwell EtherNet/IP response.");
        return outcome;
    };

    let mut fields = BTreeMap::new();
    fields.insert("vendor_name".to_string(), serde_json::json!(&device.vendor));
    fields.insert(
        "product_name".to_string(),
        serde_json::json!(&device.product_name),
    );
    fields.insert(
        "product_type".to_string(),
        serde_json::json!(&device.product_type),
    );
    fields.insert(
        "product_code".to_string(),
        serde_json::json!(device.product_code),
    );
    fields.insert("revision".to_string(), serde_json::json!(&device.revision));
    fields.insert("serial".to_string(), serde_json::json!(&device.serial));

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Rockwell,
        vendor: "rockwell".to_string(),
        identity: Some(device.product_name).filter(|name| !name.is_empty()),
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Rockwell EtherNet/IP device on {ip}:{effective_port}."),
    );

    outcome
}
