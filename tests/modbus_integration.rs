// Modbus TCP integration tests.
// Requires TEST_MODBUS_HOST and TEST_MODBUS_PORT env vars (set in CI via pymodbus simulator).
use scadaver::core::modbus::{ModbusTcpClient, DEFAULT_PORT};

fn modbus_target() -> Option<(String, u16)> {
    let host = std::env::var("TEST_MODBUS_HOST").ok()?;
    let port: u16 = std::env::var("TEST_MODBUS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    Some((host, port))
}

#[test]
fn modbus_default_port_constant() {
    assert_eq!(DEFAULT_PORT, 502, "Modbus default TCP port must be 502");
}

#[test]
fn live_modbus_read_device_id_runs_without_panic() {
    let Some((host, port)) = modbus_target() else { return };
    let client = ModbusTcpClient::new(&host).with_port(port);
    // FC 0x2B/MEI may return a Modbus exception if the server doesn't advertise
    // device identification — that's a valid protocol response, not a test failure.
    let _ = client.read_device_id();
}

#[test]
fn live_modbus_read_holding_registers_succeeds() {
    let Some((host, port)) = modbus_target() else { return };
    let result = scadaver::core::modbus::read_holding_registers(&host, port, 0, 10);
    assert!(
        result.is_ok(),
        "FC 03 holding-register read should succeed: {:?}",
        result.err()
    );
    let regs = result.unwrap();
    assert_eq!(regs.len(), 10, "should read 10 registers");
}

#[test]
fn live_modbus_read_coils_succeeds() {
    let Some((host, port)) = modbus_target() else { return };
    let result = scadaver::core::modbus::read_coils(&host, port, 0, 8);
    assert!(
        result.is_ok(),
        "FC 01 coil read should succeed: {:?}",
        result.err()
    );
}
