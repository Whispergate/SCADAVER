//! Thin wrapper: attempt MQTT probe on the default plaintext port.

use super::client::{self, MqttDevice};

/// Probe for an MQTT broker at the given IP. Tries TCP port 1883.
///
/// Returns `None` if no broker responds or anonymous access is rejected.
/// Port 8883 (TLS) is not attempted here — TLS transport is not yet in the sync lib.
pub fn scan_ip(ip: &str) -> Option<MqttDevice> {
    client::probe(ip, client::MQTT_PORT)
}
