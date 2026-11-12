//! EtherNet/IP contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::model::EndpointRecord;
use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;

// The casket List Identity probe is UDP and pinned to 44818, so the simulator's UDP listener is
// the one that answers. The TCP port is only used as the readiness probe, so it comes from the OS:
// a hardcoded value landed inside a Windows reserved range and the bind failed.
const DISCOVERY_PORT: u16 = 44_818;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "sim/eip_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--udp-port",
                &DISCOVERY_PORT.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/eip_sim.py must exist");

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

fn text(record: &EndpointRecord, key: &str) -> String {
    record
        .fields
        .get(key)
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn enip_scan_returns_typed_records() {
    let _sim = Simulator::spawn(common::tcp_port());
    // The simulator's UDP worker is a daemon thread started after the TCP listener check.
    std::thread::sleep(Duration::from_millis(200));

    let outcome = scadaver::ops::enip::scan_ip("127.0.0.1", 0, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Enip);
    assert_eq!(record.port, Protocol::Enip.default_port());
    assert_eq!(record.port, DISCOVERY_PORT);
    assert_eq!(record.vendor, "enip");

    // Values the simulator's List Identity item carries.
    assert_eq!(text(record, "product_name"), "PLC");
    assert_eq!(text(record, "vendor_id"), "0001");
    assert_eq!(text(record, "revision"), "31.3");
    assert_eq!(record.fields["device_type"].as_u64(), Some(14));
    assert_eq!(record.identity.as_deref(), Some("PLC"));
}

#[test]
fn enip_with_nothing_listening_is_a_message_not_a_panic() {
    // The List Identity probe has no port argument, so the silent case has to be an unroutable
    // address (RFC 5737 TEST-NET-1) rather than an unused port.
    let outcome = scadaver::ops::enip::scan_ip("192.0.2.1", 0, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No EtherNet/IP")));
}
