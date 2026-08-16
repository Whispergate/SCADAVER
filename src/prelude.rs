//! Convenience re-exports for the most commonly used scadaver types.
//!
//! `use scadaver::prelude::*` brings in device structs, autodetect utilities,
//! and protocol constants for Beckhoff, Omron, and Siemens. Other vendor types
//! are available directly under `scadaver::vendors`.

pub use crate::core::autodetect::{
    detect_device, probe_all, set_stealth, stealth_enabled, sweep, DeviceInfo, IntoDeviceInfo,
    ProbeInfo, SweepOutcome,
};
pub use crate::vendors::beckhoff::scan::{
    AdsSymbol, BeckhoffDevice, BeckhoffDeviceInfo, DEFAULT_ADS_PORT,
};
pub use crate::vendors::mitsubishi::slmp::SlmpValue;
pub use crate::vendors::mqtt::client::{MqttDevice, MQTT_PORT};
pub use crate::vendors::mqtt::session::{ConnectOptions, MqttMessage, MqttSession, WillConfig};
pub use crate::vendors::omron::fins::{OmronDevice, FINS_TCP_PORT, FINS_UDP_PORT};
pub use crate::vendors::siemens::scan::SiemensDevice;
