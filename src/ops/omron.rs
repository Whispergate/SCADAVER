//! Omron FINS/TCP: node address negotiation, then a controller data read (05 01).
//!
//! The legacy arm printed node, model and version and returned `None` on any error, so a
//! surface could not tell a refused connection from a device that answered short. casket
//! still treats a short reply as success and fills `"Unknown"` instead of failing.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::omron::fins;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `get_device_info_tcp` owns its
/// own connect and read timing (a five second constant), so `_timeout` is accepted for a
/// uniform dispatch signature and ignored here on purpose.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Omron.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let device = match fins::get_device_info_tcp(ip, effective_port) {
        Ok(device) => device,
        Err(error) => {
            outcome.say(
                Level::Warn,
                format!("No Omron FINS response from {ip}:{effective_port}: {error}"),
            );
            return outcome;
        }
    };

    let mut fields = BTreeMap::new();
    fields.insert("node".to_string(), serde_json::json!(device.node_addr));
    fields.insert("model".to_string(), serde_json::json!(device.model));
    fields.insert("version".to_string(), serde_json::json!(device.version));
    fields.insert("fins_port".to_string(), serde_json::json!(effective_port));

    let identity = Some(device.model.clone()).filter(|model| !model.is_empty());

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Omron,
        vendor: "omron".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Omron FINS device on {ip}:{effective_port}."),
    );

    outcome
}
