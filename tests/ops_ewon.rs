//! eWON contract test. The simulator serves HTTP on --port and IPCONF on --udp-port, and the
//! module discovers over UDP, so both are pointed at the same number (TCP and UDP are separate
//! port spaces). Readiness waits for the HTTP listener, which starts after the UDP worker.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 18080;
const MODBUS_PORT: u16 = 18082;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/ewon_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--udp-port",
                &port.to_string(),
                "--modbus-port",
                &MODBUS_PORT.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/ewon_sim.py must exist");

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
fn ewon_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Ewon, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected from the simulator on {PORT}: {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.ip, "127.0.0.1");
    assert_eq!(record.port, PORT);
    assert_eq!(record.protocol, Protocol::Ewon);
    assert_eq!(record.vendor, "ewon");

    // The IPCONF reply sim/ewon_sim.py builds: type 2, 127.0.0.1, /24, MAC de:ad:be:ef:00:01.
    assert_eq!(
        record.fields.get("mac").and_then(|value| value.as_str()),
        Some("de:ad:be:ef:00:01")
    );
    assert_eq!(
        record
            .fields
            .get("netmask")
            .and_then(|value| value.as_str()),
        Some("255.255.255.0")
    );
    assert_eq!(
        record
            .fields
            .get("response_type")
            .and_then(|value| value.as_str()),
        Some("device_info")
    );
    assert!(
        record.identity.is_some(),
        "the serial or MAC labels the device"
    );
}

#[test]
fn ewon_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Ewon, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(
        outcome
            .messages
            .iter()
            .any(|message| message.text.contains("No eWON response")),
        "expected a warning, got {:?}",
        outcome.messages
    );
}
