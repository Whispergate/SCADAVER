//! IEC 60870-5-104. Link test only, which is all the legacy arm did.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::iec104::client;
use std::collections::BTreeMap;

/// Probe one host for a TESTFR response. `probe` owns its own timing, so `_timeout` is unused.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Iec104.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    if client::probe(ip, effective_port) {
        outcome.records.push(EndpointRecord {
            ip: ip.to_string(),
            port: effective_port,
            protocol: Protocol::Iec104,
            vendor: "iec104".to_string(),
            identity: None,
            fields: BTreeMap::new(),
        });
        outcome.say(Level::Success, "IEC 104 outstation responded to TESTFR.");
    } else {
        outcome.say(Level::Warn, "No IEC 104 outstation responded.");
    }

    outcome
}
