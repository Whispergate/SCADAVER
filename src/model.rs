//! Typed results shared by CLI, TUI and web. No protocol code, no rendering, no casket.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::protocol::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One observable endpoint. `fields` holds protocol specific facts with stable key names
/// (`firmware`, `serial`, `ads_state`, ...), never a per-surface alias.
///
/// `vendor` is the protocol slug on every module (`"bacnet"`, `"schneider"`, ...): surfaces
/// group on it. A device-reported vendor name, when the protocol carries one, goes in
/// `fields["vendor_name"]`, never in `vendor`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

/// One line a human should see. The `[+]`/`[!]`/`[-]` prefixes belong to the CLI renderer,
/// not to the data path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub level: Level,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub records: Vec<EndpointRecord>,
    pub messages: Vec<Message>,
}

impl Outcome {
    #[must_use]
    pub fn with(mut self, record: EndpointRecord) -> Self {
        self.records.push(record);
        self
    }

    pub fn say(&mut self, level: Level, text: impl Into<String>) {
        self.messages.push(Message {
            level,
            text: text.into(),
        });
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
