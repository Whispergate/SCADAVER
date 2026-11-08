//! IEC 104 contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 22404;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/iec104_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/iec104_sim.py must exist");

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
fn iec104_scan_reports_a_link_test_response() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Iec104, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one outstation expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Iec104);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "iec104");
    assert!(record.fields.is_empty());
}

#[test]
fn iec104_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Iec104, "127.0.0.1", 1, 1);
    assert!(outcome.records.is_empty());
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No IEC 104")));
}
