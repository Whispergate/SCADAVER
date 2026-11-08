//! Schneider Electric: IPCONF UDP discovery first, then Modbus TCP device identification.
//!
//! The legacy arm collapsed every device to `{vendor, protocol, port, count}` and dropped the
//! name, firmware and unit id the scan had just read. Those become typed fields here.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::schneider::scan::{scan_ip_with_transport, SchneiderDevice, Transport};
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default (Modbus TCP 502).
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Schneider.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // `scan_ip_with_transport` owns its own connect/read timing. Clamp at 1 s because a zero
    // read timeout becomes a zero SO_RCVTIMEO, which waits forever instead of not at all.
    let devices =
        match scan_ip_with_transport(ip, timeout.max(1), true, effective_port, Transport::Both) {
            Ok(devices) => devices,
            Err(error) => {
                outcome.say(
                    Level::Warn,
                    format!("Schneider scan failed on {ip}:{effective_port}: {error}"),
                );
                return outcome;
            }
        };

    // casket reports a "short response" (under 53 bytes) as a device with no name, firmware or
    // Modbus port, and a loopback discovery packet can come back that way. Only devices that
    // identified themselves are real findings.
    let identified: Vec<&SchneiderDevice> = devices
        .iter()
        .filter(|device| {
            device.name.is_some() || device.firmware.is_some() || device.modbus_unit_id.is_some()
        })
        .collect();

    if identified.is_empty() {
        outcome.say(
            Level::Warn,
            format!("No Schneider response from {ip}:{effective_port}."),
        );
        return outcome;
    }

    for device in identified {
        let mut fields = BTreeMap::new();
        for (key, value) in [
            ("name", device.name.as_ref()),
            ("firmware", device.firmware.as_ref()),
            ("protocol", device.protocol.as_ref()),
            ("discovery_transport", device.discovery_transport.as_ref()),
        ] {
            if let Some(value) = value {
                fields.insert(key.to_string(), serde_json::json!(value));
            }
        }
        if let Some(unit_id) = device.modbus_unit_id {
            fields.insert("modbus_unit_id".to_string(), serde_json::json!(unit_id));
        }
        if let Some(modbus_port) = device.port {
            fields.insert("modbus_port".to_string(), serde_json::json!(modbus_port));
        }
        fields.insert(
            "identity_match".to_string(),
            serde_json::json!(device.identity_match),
        );

        // The record's ip is the address the caller asked to scan, not one the device
        // reports; the surfaces group and dedupe on it.
        outcome.records.push(EndpointRecord {
            ip: ip.to_string(),
            port: effective_port,
            protocol: Protocol::Schneider,
            vendor: "schneider".to_string(),
            identity: device.name.clone().or_else(|| device.firmware.clone()),
            fields,
        });
    }

    let found = outcome.records.len();
    outcome.say(
        Level::Success,
        format!("{found} Schneider device(s) on {ip}:{effective_port}."),
    );

    outcome
}
