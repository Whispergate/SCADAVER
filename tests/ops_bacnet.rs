//! BACnet/IP contract test. Spawns the UDP simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

mod common;

use scadaver::protocol::Protocol;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 47909;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "scripts/sim_bacnet.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and scripts/sim_bacnet.py must exist");

        // BACnet is UDP, so a successful connect means nothing. Readiness here is an
        // I-Am coming back from a unicast Who-Is.
        let probe = UdpSocket::bind("127.0.0.1:0").expect("ephemeral UDP socket");
        let _ = probe.set_read_timeout(Some(Duration::from_millis(200)));
        let who_is: [u8; 8] = [0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08];
        let mut buf = [0u8; 128];

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let _ = probe.send_to(&who_is, ("127.0.0.1", port));
            if probe.recv_from(&mut buf).is_ok() {
                return Self(child);
            }
        }
        panic!("simulator did not answer Who-Is on {port} within 10s");
    }
}

impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn bacnet_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Bacnet, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Bacnet);
    assert_eq!(record.port, PORT);

    // vendor is the slug on every module; the fixture's device vendor name lives in fields.
    assert_eq!(record.vendor, "bacnet");

    let instance = record
        .fields
        .get("instance_id")
        .and_then(serde_json::Value::as_u64)
        .expect("instance_id is a number");
    assert_eq!(instance, 1000);

    let name = record
        .fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert_eq!(name, "ScadaverCI");
    assert_eq!(record.identity.as_deref(), Some("ScadaverCI"));

    let vendor_id = record
        .fields
        .get("vendor_id")
        .and_then(serde_json::Value::as_u64)
        .expect("vendor_id is a number");
    assert_eq!(vendor_id, 999);
}

#[test]
fn bacnet_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Bacnet, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No BACnet device responded")));
}
