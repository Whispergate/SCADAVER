//! `scadaver` — ICS/OT red team multi-tool for authorized security research.
//!
//! Provides protocol implementations for EtherNet/IP, Modbus, `S7Comm`, FINS, SLMP,
//! ADS/AMS, IEC 60870-5-104, and SNMP across major PLC vendors. Includes device
//! autodetection, stealth scanning, and a web-based operator interface.
//!
//! **For authorized lab and CTF use only.**

pub mod core;
pub mod prelude;
pub mod references;
pub mod vendors;
