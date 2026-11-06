//! Protocol enum shared between CLI, TUI, Web, and ops dispatch.
//!
//! Exposed through the library crate so integration tests can import it
//! without pulling in the full CLI module.

/// ICS/SCADA protocols supported by scadaver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    #[cfg_attr(feature = "cli", value(alias = "opcua"))]
    OpcUa,
    Phoenix,
    Rockwell,
    Schneider,
    Siemens,
    Snmp,
}
