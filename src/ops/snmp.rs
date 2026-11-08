//! SNMP: community discovery plus the MIB-II system group. Typed, never prints.
//!
//! The legacy arm logged `community=<string>` beside sysDescr, which rendered a read-only
//! community next to a credential. The answering community is a typed field here instead.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::snmp::{client, oids};
use std::collections::BTreeMap;

/// Probe one host. `port = 0` means the registered default (161).
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = if port == 0 {
        Protocol::Snmp.default_port()
    } else {
        port
    };
    let mut outcome = Outcome::default();

    // casket's client owns the timing: a fixed 4 s read timeout per request, and
    // `discover_community` may try eleven communities in turn, so the caller's budget is
    // advisory here and not enforced.
    let Some(community) = client::discover_community(ip, effective_port) else {
        outcome.say(
            Level::Warn,
            format!("No SNMP community string answered on {ip}:{effective_port}."),
        );
        return outcome;
    };

    let mut fields = BTreeMap::new();
    fields.insert(
        "community".to_string(),
        serde_json::json!(community.as_str()),
    );
    for (key, oid) in [
        ("descr", oids::SYS_DESCR),
        ("sys_name", oids::SYS_NAME),
        ("sys_object_id", oids::SYS_OBJECT_ID),
        ("sys_location", oids::SYS_LOCATION),
    ] {
        if let Ok(value) = client::get(ip, effective_port, &community, oid) {
            fields.insert(key.to_string(), serde_json::json!(value.display()));
        }
    }

    // Best human label: the configured system name, then the vendor description.
    let identity = ["sys_name", "descr"].iter().find_map(|key| {
        fields
            .get(*key)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    });

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Snmp,
        vendor: "snmp".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("SNMP agent answered on {ip}:{effective_port} with community {community}."),
    );

    outcome
}
