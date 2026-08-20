// BACnet/IP integration tests — require TEST_BACNET_HOST env var.
// In CI, this points at a bacpypes3 simulator (scripts/sim_bacnet.py).
use std::time::Duration;
use scadaver::vendors::bacnet::client::{self, BACNET_PORT, PROP_OBJECT_NAME};

fn bacnet_host() -> Option<String> {
    std::env::var("TEST_BACNET_HOST").ok()
}

#[test]
fn live_bacnet_scan_ip_returns_device() {
    let Some(host) = bacnet_host() else { return };
    let dev = client::scan_ip(&host, 3);
    assert!(
        dev.is_some(),
        "bacpypes3 simulator should respond to unicast Who-Is"
    );
}

#[test]
fn live_bacnet_port_constant() {
    assert_eq!(BACNET_PORT, 0xBAC0, "BACnet port must be 47808 (0xBAC0)");
}

#[test]
fn live_bacnet_read_object_name_succeeds() {
    let Some(host) = bacnet_host() else { return };
    if let Some(dev) = client::scan_ip(&host, 3) {
        let name = client::read_property(
            &host,
            dev.instance_id,
            PROP_OBJECT_NAME,
            Duration::from_secs(3),
        );
        assert!(name.is_some(), "read_property(object-name) should succeed");
    }
}
