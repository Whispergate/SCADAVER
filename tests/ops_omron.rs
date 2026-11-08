//! Omron FINS contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 29600;
const CLOSED_PORT: u16 = 29601;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/fins_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/fins_sim.py must exist");

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

fn field_text(fields: &std::collections::BTreeMap<String, serde_json::Value>, key: &str) -> String {
    fields
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn omron_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Omron, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Omron);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "omron");

    // The simulator answers controller data read (05 01) with model "CP1E" and version "V1.0"
    // and assigns server node 1 during address negotiation.
    assert_eq!(field_text(&record.fields, "model"), "CP1E");
    assert_eq!(field_text(&record.fields, "version"), "V1.0");
    assert_eq!(
        record
            .fields
            .get("node")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "server node from the negotiation frame"
    );
    assert_eq!(record.identity.as_deref(), Some("CP1E"));
}

#[test]
fn omron_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Omron, "127.0.0.1", CLOSED_PORT, 1);
    assert!(outcome.records.is_empty());
    assert!(
        outcome
            .messages
            .iter()
            .any(|m| m.text.contains("No Omron FINS response")),
        "got {:?}",
        outcome.messages
    );
    assert_eq!(outcome.messages.len(), 1);
}
