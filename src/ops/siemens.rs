//! Siemens S7. Typed record, no printing.
//!
//! The legacy arm also ran an SNMP community walk and reported CVEs inline. That belongs to the
//! SNMP vertical, not here, so this module stays single-protocol and a scan of an S7 device does
//! not quietly turn into two network conversations.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::siemens::scan::{self, SiemensDevice};
use casket::vendors::siemens::s7comm;
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default, which keeps the casket sweep
/// (identity plus the well-known port list). An explicit port probes only that port, so the
/// shared `timeout` applies there and is otherwise unused.
pub fn scan_ip(ip: &str, port: u16, timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Siemens.default_port()
    } else {
        port
    };
    // An explicit port means one conversation, with that port. The casket helper also probes
    // 102/502/161 first, so it would silently widen a scan of 1102 into four conversations.
    // That shape is kept for the default-port case only; an explicit port gets the same
    // read-only snapshot the handler used to call directly, with no port sweep in front of it.
    let device = if port == 0 {
        scan::scan_ip_with_port(ip, effective_port)
    } else {
        let (hardware, firmware, cpu_state) =
            s7comm::get_device_snapshot(ip, effective_port, timeout.max(1));
        let cpu_state = if cpu_state == "Unknown" {
            None
        } else {
            Some(cpu_state)
        };
        let found = hardware.is_some() || firmware.is_some() || cpu_state.is_some();
        SiemensDevice {
            ip: ip.to_string(),
            hardware,
            firmware,
            cpu_state,
            open_ports: if found { vec![effective_port] } else { Vec::new() },
        }
    };

    let mut outcome = Outcome::default();
    if device.open_ports.is_empty() && device.hardware.is_none() && device.firmware.is_none() {
        outcome.say(Level::Warn, "No Siemens S7 data retrieved.");
        return outcome;
    }

    let mut fields = BTreeMap::new();
    if let Some(hardware) = device.hardware.as_ref() {
        fields.insert("hardware".to_string(), serde_json::json!(hardware));
    }
    if let Some(firmware) = device.firmware.as_ref() {
        fields.insert("firmware".to_string(), serde_json::json!(firmware));
    }
    if let Some(cpu_state) = device.cpu_state.as_ref() {
        fields.insert("cpu_state".to_string(), serde_json::json!(cpu_state));
    }
    fields.insert(
        "open_ports".to_string(),
        serde_json::json!(device.open_ports),
    );

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Siemens,
        vendor: "siemens".to_string(),
        identity: device.hardware.clone(),
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Siemens S7 device on {ip}:{effective_port}."),
    );

    outcome
}
