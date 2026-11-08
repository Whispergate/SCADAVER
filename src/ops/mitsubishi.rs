//! Mitsubishi MELSEC SLMP 3E: one TCP batch read of D0 proves the port speaks SLMP.
//!
//! The legacy arm asked for `Transport::Both`, so a scan of one explicit port still sent GX
//! Works3 discovery to UDP 5561 and SLMP discovery to 5006 first and reported whichever
//! answered, even though neither concerned the port the caller named.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::mitsubishi::scan::{self, Transport};
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `silent = true` on purpose: the
/// library must not write to stdout behind the surface's back. SLMP 3E has no model field in a
/// batch read, so `plc_type` is casket's own synthesis and is the weakest label here.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Mitsubishi.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // `timeout` is forwarded, but casket's TCP path drops it and uses its own five second
    // read timeout instead, so a slow target is bounded by casket, not by this argument.
    let devices =
        match scan::scan_ip_with_transport(ip, timeout, true, effective_port, Transport::Tcp) {
            Ok(devices) => devices,
            Err(error) => {
                outcome.say(
                    Level::Warn,
                    format!("No Mitsubishi MELSEC response from {ip}:{effective_port}: {error}"),
                );
                return outcome;
            }
        };

    if devices.is_empty() {
        outcome.say(
            Level::Warn,
            format!("No Mitsubishi MELSEC response from {ip}:{effective_port}."),
        );
        return outcome;
    }

    let total = devices.len();
    for device in &devices {
        let mut fields = BTreeMap::new();
        fields.insert("plc_type".to_string(), serde_json::json!(device.plc_type));
        fields.insert("slmp_port".to_string(), serde_json::json!(effective_port));
        fields.insert("count".to_string(), serde_json::json!(total));
        if let Some(wire) = device.protocol.as_ref() {
            fields.insert("protocol".to_string(), serde_json::json!(wire));
        }
        if let Some(title) = device.title.as_ref() {
            fields.insert("title".to_string(), serde_json::json!(title));
        }
        if let Some(comment) = device.comment.as_ref() {
            fields.insert("comment".to_string(), serde_json::json!(comment));
        }
        if let Some(transport) = device.discovery_transport.as_ref() {
            fields.insert(
                "discovery_transport".to_string(),
                serde_json::json!(transport),
            );
        }

        let identity = Some(device.plc_type.clone()).filter(|plc_type| !plc_type.is_empty());

        outcome.records.push(EndpointRecord {
            ip: ip.to_string(),
            port: effective_port,
            protocol: Protocol::Mitsubishi,
            vendor: "mitsubishi".to_string(),
            identity,
            fields,
        });
    }
    let count = outcome.records.len();
    outcome.say(
        Level::Success,
        format!("Found {count} Mitsubishi device(s)."),
    );

    outcome
}
