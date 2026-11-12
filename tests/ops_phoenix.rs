//! Phoenix Contact contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
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
                "sim/phoenix_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/phoenix_sim.py must exist");

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
fn phoenix_scan_returns_typed_records() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);

    let outcome = scadaver::ops::scan_ip(Protocol::Phoenix, "127.0.0.1", port, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Phoenix);
    assert_eq!(record.port, port);
    assert_eq!(record.vendor, "phoenix");

    // The simulator's info frame carries ILC 150 ETH at bytes 30..50, firmware 3.20 at
    // 66..70 and build 20230101 at 79..100.
    assert_eq!(field_text(&record.fields, "plc_type"), "ILC 150 ETH");
    assert_eq!(field_text(&record.fields, "firmware"), "3.20");
    assert_eq!(field_text(&record.fields, "build"), "20230101");
    assert_eq!(
        record
            .fields
            .get("phoenix_info_port")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(port))
    );
    assert_eq!(record.identity.as_deref(), Some("ILC 150 ETH"));
}

#[test]
fn phoenix_with_nothing_listening_is_a_message_not_a_panic() {
    let port = common::tcp_port();
    let outcome = scadaver::ops::scan_ip(Protocol::Phoenix, "127.0.0.1", port, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(
        outcome
            .messages
            .iter()
            .any(|m| m.text.contains("No Phoenix Contact response")),
        "got {:?}",
        outcome.messages
    );
    assert_eq!(outcome.messages.len(), 1);
}
