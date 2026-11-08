//! Modbus TCP discovery. Returns typed records; printing is the caller's job.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::schneider::scan::{self, Transport};
use std::collections::BTreeMap;

/// Probe one host on the Modbus TCP port. `port = 0` means the registered default.
///
/// `silent = true` on purpose: the library must not write to stdout behind the surface's
/// back, so every human line is carried in `messages` instead.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let mut outcome = Outcome::default();
    let effective_port = if port == 0 {
        Protocol::Modbus.default_port()
    } else {
        port
    };

    match scan::scan_ip_with_transport(ip, timeout, true, effective_port, Transport::Tcp) {
        Ok(devices) if !devices.is_empty() => {
            for device in devices {
                let mut fields = BTreeMap::new();
                if let Some(name) = device.name.as_ref() {
                    fields.insert("name".to_string(), serde_json::json!(name));
                }
                if let Some(firmware) = device.firmware.as_ref() {
                    fields.insert("firmware".to_string(), serde_json::json!(firmware));
                }
                outcome.records.push(EndpointRecord {
                    ip: ip.to_string(),
                    port: effective_port,
                    protocol: Protocol::Modbus,
                    vendor: "modbus".to_string(),
                    identity: device.name.clone(),
                    fields,
                });
            }
            let count = outcome.records.len();
            outcome.say(Level::Success, format!("Found {count} Modbus device(s)."));
        }
        Ok(_) => outcome.say(Level::Warn, "No Modbus TCP device responded."),
        Err(error) => outcome.say(Level::Error, format!("Modbus scan error: {error}")),
    }

    outcome
}
