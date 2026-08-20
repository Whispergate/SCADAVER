// SNMP integration tests.
// Requires TEST_SNMP_HOST and TEST_SNMP_PORT env vars (set in CI via pysnmp simulator).
use scadaver::vendors::snmp::{client, oids};

fn snmp_target() -> Option<(String, u16)> {
    let host = std::env::var("TEST_SNMP_HOST").ok()?;
    let port: u16 = std::env::var("TEST_SNMP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(client::SNMP_PORT);
    Some((host, port))
}

#[test]
fn snmp_port_constant() {
    assert_eq!(client::SNMP_PORT, 161, "SNMP default port must be 161");
}

#[test]
fn live_snmp_discover_community_finds_public() {
    let Some((host, port)) = snmp_target() else { return };
    let community = client::discover_community(&host, port);
    assert!(
        community.is_some(),
        "pysnmp simulator should respond to 'public' community GET"
    );
    assert_eq!(
        community.as_deref(),
        Some("public"),
        "community should be 'public'"
    );
}

#[test]
fn live_snmp_get_sys_descr_returns_value() {
    let Some((host, port)) = snmp_target() else { return };
    let result = client::get(&host, port, "public", oids::SYS_DESCR);
    assert!(
        result.is_ok(),
        "GET sysDescr.0 should succeed: {:?}",
        result.err()
    );
    let val = result.unwrap().display();
    assert!(!val.is_empty(), "sysDescr must not be empty");
}
