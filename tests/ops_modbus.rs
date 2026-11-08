//! The contract test: a scan returns typed records, not strings and not ad hoc JSON.
//!
//! Unlike `tests/ops_integration.rs` these are not `#[ignore]`d: the simulator is spawned by
//! the test and killed by its `Drop`, so `cargo test --test ops_modbus` is a real check with
//! no manual setup.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::model::Outcome;
use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 21502;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/modbus_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/modbus_sim.py must exist");

        // Wait for the listener instead of sleeping a fixed amount: a slow box should not
        // produce a flaky red test.
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
fn modbus_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome: Outcome = scadaver::ops::scan_ip(Protocol::Modbus, "127.0.0.1", PORT, 2);

    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected from the simulator on {PORT}"
    );
    let record = &outcome.records[0];
    assert_eq!(record.ip, "127.0.0.1");
    assert_eq!(record.port, PORT);
    assert_eq!(record.protocol, Protocol::Modbus);
    assert_eq!(record.vendor, "modbus");
    assert!(
        outcome.messages.iter().all(|m| !m.text.is_empty()),
        "every message carries text"
    );
}

#[test]
fn a_scan_that_finds_nothing_is_a_message_not_a_panic() {
    // Nothing listens on port 1, and the call must still return an Outcome.
    let outcome = scadaver::ops::scan_ip(Protocol::Modbus, "127.0.0.1", 1, 1);

    assert!(outcome.records.is_empty());
    assert!(
        outcome
            .messages
            .iter()
            .any(|m| m.text.contains("No Modbus") || m.text.contains("Modbus scan error")),
        "expected a warning or an error message, got {:?}",
        outcome.messages
    );
}
