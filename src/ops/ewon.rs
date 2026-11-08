//! eWON `IPCONF` discovery. Typed, no printing.
//!
//! The legacy arm printed the web port (80) as `ipconf_port` while handing the scan no port at
//! all, and the old table claimed 67 (BOOTP), which nothing ever used. Port 0 resolves to
//! casket's `IPCONF` port 1507 through `Protocol::default_port()`.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::ewon::scan::scan_ip_with_port;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default, 1507 (casket's IPCONF port).
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Ewon.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // casket reads with a plain read timeout. Clamp at 1 s: a zero timeout becomes a zero
    // SO_RCVTIMEO, which waits forever rather than not at all.
    let devices = match scan_ip_with_port(ip, timeout.max(1), true, effective_port) {
        Ok(devices) => devices,
        Err(error) => {
            outcome.say(
                Level::Warn,
                format!("eWON discovery failed on {ip}:{effective_port}: {error}"),
            );
            return outcome;
        }
    };

    let Some(device) = devices
        .iter()
        .find(|device| device.response_type == "device_info")
        .or_else(|| devices.first())
    else {
        outcome.say(
            Level::Warn,
            format!("No eWON response from {ip}:{effective_port}."),
        );
        return outcome;
    };

    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("ip", device.ip.as_ref()),
        ("netmask", device.netmask.as_ref()),
        ("mac", device.mac.as_ref()),
        ("serial", device.serial.as_ref()),
        ("product_code", device.product_code.as_ref()),
        ("firmware", device.firmware.as_ref()),
        ("identifier", device.identifier.as_ref()),
    ] {
        if let Some(value) = value {
            fields.insert(key.to_string(), serde_json::json!(value));
        }
    }
    fields.insert(
        "response_type".to_string(),
        serde_json::json!(device.response_type.as_str()),
    );
    fields.insert("responses".to_string(), serde_json::json!(devices.len()));

    // Best human label: the serial number, then the MAC the device announced.
    let identity = device.serial.clone().or_else(|| device.mac.clone());

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Ewon,
        vendor: "ewon".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("eWON device answered on {ip}:{effective_port}."),
    );

    outcome
}
