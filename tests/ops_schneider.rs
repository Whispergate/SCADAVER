//! Schneider contract test. Spawns the Modbus simulator with its Schneider FC43 identity, so
//! the module's TCP fallback is exercised against real device-identification objects.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

mod common;

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "sim/modbus_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--identity",
                "schneider",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/modbus_sim.py must exist");

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Self(child);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("simulator did not listen on {port} within 10s");
    }
}

impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn schneider_scan_returns_typed_records() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);

    let outcome = scadaver::ops::scan_ip(Protocol::Schneider, "127.0.0.1", port, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected from the simulator on {port}: {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.ip, "127.0.0.1");
    assert_eq!(record.port, port);
    assert_eq!(record.protocol, Protocol::Schneider);
    assert_eq!(record.vendor, "schneider");

    // What sim/modbus_sim.py --identity schneider actually answers over FC43/MEI 0x0E.
    let name = record
        .fields
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert_eq!(name, "TM241CE24T/U");
    assert_eq!(record.identity.as_deref(), Some("TM241CE24T/U"));
    assert_eq!(
        record
            .fields
            .get("firmware")
            .and_then(|value| value.as_str()),
        Some("V1.0.0-sim")
    );
    assert_eq!(
        record
            .fields
            .get("modbus_unit_id")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
}

#[test]
fn schneider_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Schneider, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(
        outcome
            .messages
            .iter()
            .any(|message| message.text.contains("No Schneider response")),
        "expected a warning, got {:?}",
        outcome.messages
    );
}
