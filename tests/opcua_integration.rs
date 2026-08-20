// OPC-UA integration tests — require TEST_OPCUA_HOST env var.
// In CI, this points at an asyncua simulator (scripts/sim_opcua.py).
use std::time::Duration;
use scadaver::vendors::opcua::client::{detect, get_endpoints, OPCUA_PORT};

fn opcua_host() -> Option<String> {
    std::env::var("TEST_OPCUA_HOST").ok()
}

#[test]
fn opcua_port_constant() {
    assert_eq!(OPCUA_PORT, 4840, "OPC-UA default port must be 4840");
}

#[test]
fn live_opcua_detect_returns_server() {
    let Some(host) = opcua_host() else { return };
    let server = detect(&host, OPCUA_PORT, Duration::from_secs(5));
    assert!(server.is_some(), "asyncua simulator should respond to HEL/ACK/OPN");
}

#[test]
fn live_opcua_get_endpoints_has_none_security() {
    let Some(host) = opcua_host() else { return };
    let eps = get_endpoints(&host, OPCUA_PORT, Duration::from_secs(5));
    assert!(
        !eps.is_empty(),
        "GetEndpoints should return at least one endpoint"
    );
    let has_none = eps.iter().any(|e| e.security_mode == "None");
    assert!(
        has_none,
        "asyncua default config should expose a None-security endpoint; got: {:?}",
        eps.iter().map(|e| &e.security_mode).collect::<Vec<_>>()
    );
}
