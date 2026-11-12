//! OPC UA contract test. Spawns the asyncua server itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

mod common;

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 44840;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "scripts/sim_opcua.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and scripts/sim_opcua.py must exist");

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
fn opcua_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::OpcUa, "127.0.0.1", PORT, 5);
    assert_eq!(
        outcome.records.len(),
        1,
        "one server expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::OpcUa);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "opcua");

    // `detect` stops at HEL/ACK and leaves application/uri empty on every server;
    // the endpoint list is the only part that carries device facts. The GetEndpoints
    // exchange can legitimately come back empty, so assert the shape rather than a
    // count this fixture does not guarantee.
    assert!(
        !record.fields.is_empty(),
        "expected at least one value, got none"
    );

    let endpoint_count = record
        .fields
        .get("endpoint_count")
        .and_then(serde_json::Value::as_u64)
        .expect("endpoint_count is a number");
    let endpoints = record
        .fields
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .expect("endpoints is an array");
    assert_eq!(endpoint_count, endpoints.len() as u64);

    assert!(
        record.fields.contains_key("application"),
        "the application key is always present, even when empty"
    );

    // If the secure channel succeeded, every advertised URL must point at the port
    // we scanned.
    for endpoint in endpoints {
        let url = endpoint
            .get("url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        assert!(
            url.contains(&PORT.to_string()),
            "endpoint url {url:?} should carry port {PORT}"
        );
    }
}

#[test]
fn opcua_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::OpcUa, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No OPC-UA server responded")));
}
