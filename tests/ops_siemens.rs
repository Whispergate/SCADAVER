//! Siemens S7 contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 11202;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/siemens_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/siemens_sim.py must exist");

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
fn siemens_scan_returns_typed_fields() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Siemens, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Siemens);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "siemens");

    let hardware = record
        .fields
        .get("hardware")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        hardware.contains("6ES7"),
        "expected the module order number, got {hardware:?}"
    );
    assert_eq!(record.identity.as_deref(), Some(hardware.as_str()));

    let open_ports = record
        .fields
        .get("open_ports")
        .and_then(serde_json::Value::as_array)
        .expect("open_ports is an array");
    assert!(
        open_ports
            .iter()
            .any(|p| p.as_u64() == Some(u64::from(PORT))),
        "the scanned port should be reported open"
    );
}

#[test]
fn siemens_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Siemens, "127.0.0.1", 1, 1);
    assert!(outcome.records.is_empty());
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No Siemens S7 data")));
}
