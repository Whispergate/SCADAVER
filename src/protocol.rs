//! The single vocabulary for protocol names, slugs and default ports.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]
//!
//! Exposed through the library crate so integration tests can import it
//! without pulling in the full CLI module. Numeric defaults come from casket where
//! casket exports a constant, so a port is written down once.

use serde::{Deserialize, Serialize};
use std::fmt;

/// ICS/SCADA protocols supported by scadaver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum Protocol {
    Bacnet,
    Beckhoff,
    Dnp3,
    Enip,
    Ewon,
    Iec104,
    Mitsubishi,
    Modbus,
    Mqtt,
    Omron,
    #[serde(rename = "opcua")]
    #[cfg_attr(feature = "cli", value(alias = "opcua"))]
    OpcUa,
    Phoenix,
    Rockwell,
    Schneider,
    Siemens,
    Snmp,
}

impl Protocol {
    /// The one place a default port is written down. Where casket exports a constant, use
    /// it, so the number has a single source. Literals keep the `ops.rs` line they came from.
    #[must_use]
    pub fn default_port(self) -> u16 {
        use casket::vendors as v;
        match self {
            Self::Modbus => casket::core::modbus::DEFAULT_PORT, // 502
            Self::Schneider => 502,                             // ops.rs:62, no const
            Self::Beckhoff => v::beckhoff::scan::DEFAULT_ADS_PORT, // 48898
            Self::Dnp3 => v::dnp3::client::DNP3_PORT,           // 20000
            Self::Enip | Self::Rockwell => 44_818,              // ops.rs:34 and :459
            // The old table said 67, which is BOOTP: nothing ever used it, and the legacy arm
            // reported it while actually discovering on IPCONF 1507.
            Self::Ewon => v::ewon::scan::IPCONF_DISCOVERY_PORT,
            Self::Iec104 => v::iec104::client::IEC104_PORT,     // 2404
            Self::Mitsubishi => v::mitsubishi::slmp::DEFAULT_PORT, // 5007
            Self::Mqtt => v::mqtt::client::MQTT_PORT,           // 1883
            Self::Omron => v::omron::fins::FINS_TCP_PORT,       // 9600
            Self::OpcUa => v::opcua::client::OPCUA_PORT,        // 4840
            Self::Phoenix => 1_962,                             // ops.rs:443
            Self::Siemens => v::siemens::s7comm::S7_PORT,       // 102
            Self::Snmp => v::snmp::client::SNMP_PORT,           // 161
            Self::Bacnet => v::bacnet::client::BACNET_PORT,     // 47808
        }
    }

    /// The name used in URLs, CLI flags and JSON. One spelling per protocol, everywhere.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Bacnet => "bacnet",
            Self::Beckhoff => "beckhoff",
            Self::Dnp3 => "dnp3",
            Self::Enip => "enip",
            Self::Ewon => "ewon",
            Self::Iec104 => "iec104",
            Self::Mitsubishi => "mitsubishi",
            Self::Modbus => "modbus",
            Self::Mqtt => "mqtt",
            Self::Omron => "fins",
            Self::OpcUa => "opcua",
            Self::Phoenix => "phoenix",
            Self::Rockwell => "rockwell",
            Self::Schneider => "schneider",
            Self::Siemens => "s7",
            Self::Snmp => "snmp",
        }
    }

    /// Accepted alternatives, so old URLs and old scripts keep working.
    #[must_use]
    pub const fn alias_slug(self) -> Option<&'static str> {
        match self {
            Self::Siemens => Some("s7comm"),
            Self::Omron => Some("omron"),
            Self::Enip => Some("ethernet_ip"),
            Self::OpcUa => Some("opc_ua"),
            _ => None,
        }
    }

    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        let wanted = slug.trim().to_ascii_lowercase();
        ALL.into_iter()
            .find(|p| p.slug() == wanted || p.alias_slug() == Some(wanted.as_str()))
    }
}

/// Every variant, in enum order. One list, so `from_slug` cannot silently miss a protocol.
pub const ALL: [Protocol; 16] = [
    Protocol::Bacnet,
    Protocol::Beckhoff,
    Protocol::Dnp3,
    Protocol::Enip,
    Protocol::Ewon,
    Protocol::Iec104,
    Protocol::Mitsubishi,
    Protocol::Modbus,
    Protocol::Mqtt,
    Protocol::Omron,
    Protocol::OpcUa,
    Protocol::Phoenix,
    Protocol::Rockwell,
    Protocol::Schneider,
    Protocol::Siemens,
    Protocol::Snmp,
];

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

#[cfg(test)]
mod tests {
    use super::Protocol;

    #[test]
    fn slugs_round_trip() {
        for protocol in super::ALL {
            assert_eq!(
                Protocol::from_slug(protocol.slug()),
                Some(protocol),
                "{} does not round trip",
                protocol.slug()
            );
        }
    }

    #[test]
    fn ports_match_the_documented_table() {
        assert_eq!(Protocol::Modbus.default_port(), 502);
        assert_eq!(Protocol::Siemens.default_port(), 102);
        assert_eq!(Protocol::Bacnet.default_port(), 47_808);
        assert_eq!(Protocol::Enip.default_port(), 44_818);
        // Corrected from the old table's 67, which no code ever scanned.
        assert_eq!(Protocol::Ewon.default_port(), 1_507);
    }

    #[test]
    fn aliases_still_resolve() {
        assert_eq!(Protocol::from_slug("s7comm"), Some(Protocol::Siemens));
        assert_eq!(Protocol::from_slug("omron"), Some(Protocol::Omron));
        assert_eq!(Protocol::from_slug("nope"), None);
    }
}
