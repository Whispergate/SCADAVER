//! DNP3 contract test. Spawns `sim/dnp3_sim.py` itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 33001;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/dnp3_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/dnp3_sim.py must exist");

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
fn dnp3_scan_reads_the_outstation_and_its_attributes() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Dnp3, "127.0.0.1", PORT, 2);
    assert_eq!(outcome.records.len(), 1, "one outstation expected");
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Dnp3);
    assert_eq!(record.port, PORT);
    assert_eq!(record.ip, "127.0.0.1");
    assert_eq!(record.vendor, "dnp3");

    // The simulator answers group 0 with vendor, device and user assigned names, which the
    // legacy arm never fetched because it read the field instead of sending the read.
    assert!(
        record.fields.keys().any(|k| k.starts_with("attr.")),
        "expected device attributes, got {:?}",
        record.fields
    );
    assert!(record.identity.is_some(), "a human label is expected");
}

#[test]
fn dnp3_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Dnp3, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome.messages.iter().any(|m| m.text.contains("No DNP3")));
}
