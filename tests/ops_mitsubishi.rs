//! Mitsubishi SLMP contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 25007;
const CLOSED_PORT: u16 = 25008;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/slmp_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/slmp_sim.py must exist");

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
fn mitsubishi_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Mitsubishi, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Mitsubishi);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "mitsubishi");

    // SLMP 3E has no model field in a batch read, so the only label available is casket's
    // synthesis, which names the wire protocol and the port that answered; the simulator
    // answers the D0 batch read with a success end code, which is what produces it.
    let plc_type = field_text(&record.fields, "plc_type");
    assert!(
        plc_type.contains("SLMP") && plc_type.contains(&PORT.to_string()),
        "expected the SLMP TCP label, got {plc_type:?}"
    );
    assert_eq!(field_text(&record.fields, "protocol"), "slmp_tcp");
    assert_eq!(
        record
            .fields
            .get("slmp_port")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(PORT))
    );
    assert_eq!(
        record
            .fields
            .get("count")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(record.identity.as_deref(), Some(plc_type.as_str()));
}

#[test]
fn mitsubishi_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Mitsubishi, "127.0.0.1", CLOSED_PORT, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(
        outcome
            .messages
            .iter()
            .any(|m| m.text.contains("No Mitsubishi MELSEC response")),
        "got {:?}",
        outcome.messages
    );
    assert_eq!(outcome.messages.len(), 1);
}
