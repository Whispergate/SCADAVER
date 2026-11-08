//! MQTT: anonymous CONNECT, then `$SYS` and Sparkplug B recon, as typed data.
//!
//! `client::probe` has no timeout parameter at all: it hard-codes a 5 s connect
//! and a 1.5 s recon window, so the dispatch timeout cannot reach it. The legacy
//! arm printed the same three facts, so this is a straight port.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::mqtt::client;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default. `_timeout` is unused
/// because `probe` owns its own connect and recon timing.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Mqtt.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    let Some(device) = client::probe(ip, effective_port) else {
        outcome.say(Level::Warn, "No MQTT broker response.");
        return outcome;
    };

    let mut fields = BTreeMap::new();
    fields.insert("anonymous".to_string(), serde_json::json!(device.anonymous));
    fields.insert(
        "broker_info".to_string(),
        serde_json::json!(&device.broker_info),
    );
    fields.insert("sparkplug".to_string(), serde_json::json!(device.sparkplug));

    // MQTT carries no vendor field; the `$SYS/broker` line is the only label a
    // broker volunteers, and `probe` only returns `Some` for an accepted CONNECT.
    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Mqtt,
        vendor: "mqtt".to_string(),
        identity: device.broker_info.clone(),
        fields,
    });
    outcome.say(
        Level::Success,
        format!("MQTT broker on {ip}:{effective_port} accepted an anonymous connect."),
    );

    outcome
}
