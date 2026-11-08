//! OPC UA: `HEL`/`ACK` reachability plus `GetEndpoints` descriptors, as typed data.
//!
//! The legacy arm read `application_name` and `endpoints` off `detect`, which
//! stops after HEL/ACK: both are always empty there, so every live server was
//! reported with a blank application and zero endpoints. This asks for them.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::opcua::client;
use std::collections::BTreeMap;
use std::time::Duration;

/// Probe one host. `port = 0` means the registered default. `detect` and
/// `get_endpoints_checked` both take a `Duration`, so `timeout` is whole seconds.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::OpcUa.default_port()
    } else {
        port
    };
    let budget = Duration::from_secs(timeout);
    let mut outcome = Outcome::default();

    let Some(server) = client::detect(ip, effective_port, budget) else {
        outcome.say(Level::Warn, "No OPC-UA server responded.");
        return outcome;
    };

    // A server that answers HEL/ACK but refuses the secure channel still counts as
    // reachable, so a failed endpoint read is not a failed scan.
    let endpoints = client::get_endpoints_checked(ip, effective_port, budget).unwrap_or_default();

    let endpoint_rows: Vec<serde_json::Value> = endpoints
        .iter()
        .map(|e| {
            serde_json::json!({
                "url": e.url,
                "security_mode": e.security_mode,
                "security_policy": e.security_policy,
                "allows_anonymous": e.allows_anonymous,
            })
        })
        .collect();

    let mut fields = BTreeMap::new();
    fields.insert(
        "application".to_string(),
        serde_json::json!(&server.application_name),
    );
    fields.insert("uri".to_string(), serde_json::json!(server.application_uri));
    fields.insert(
        "product_uri".to_string(),
        serde_json::json!(server.product_uri),
    );
    fields.insert(
        "endpoint_count".to_string(),
        serde_json::json!(endpoints.len()),
    );
    fields.insert("endpoints".to_string(), serde_json::json!(endpoint_rows));

    // Prefer the application name, then the first advertised endpoint URL.
    let identity = if server.application_name.is_empty() {
        endpoints.first().map(|e| e.url.clone())
    } else {
        Some(server.application_name.clone())
    };

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::OpcUa,
        vendor: "opcua".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!(
            "OPC-UA server on {ip}:{effective_port} advertised {} endpoint(s).",
            endpoints.len()
        ),
    );

    outcome
}
