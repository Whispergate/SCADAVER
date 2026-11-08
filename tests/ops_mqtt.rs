//! MQTT contract test. Spawns the amqtt broker itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PORT: u16 = 21883;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new("python")
            .args([
                "sim/mqtt_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/mqtt_sim.py must exist");

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
fn mqtt_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Mqtt, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one broker expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Mqtt);
    assert_eq!(record.port, PORT);
    assert_eq!(record.vendor, "mqtt");

    // The fixture enables `allow-anonymous`, and `probe` only returns `Some` for
    // CONNACK 0x00, so both of these are facts about the simulator.
    let anonymous = record
        .fields
        .get("anonymous")
        .and_then(serde_json::Value::as_bool)
        .expect("anonymous is a bool");
    assert!(anonymous, "the fixture accepts anonymous connects");

    let sparkplug = record
        .fields
        .get("sparkplug")
        .and_then(serde_json::Value::as_bool)
        .expect("sparkplug is a bool");
    assert!(
        !sparkplug,
        "an amqtt fixture does not advertise Sparkplug B"
    );
}

#[test]
fn mqtt_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Mqtt, "127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No MQTT broker response")));
}
