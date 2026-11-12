//! Rockwell contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::model::EndpointRecord;
use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;

// The EtherNet/IP simulator is shared with the enip test, so this one takes its own TCP port and
// moves the UDP listener off 44818 to keep the two from colliding. Both come from the OS: 34819 and
// 34820 sat inside a Windows reserved range, where bind fails with WinError 10013.

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16, udp_port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "sim/eip_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--udp-port",
                &udp_port.to_string(),
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
fn rockwell_scan_returns_typed_records() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port, common::udp_port());

    let outcome = scadaver::ops::rockwell::scan_ip("127.0.0.1", port, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Rockwell);
    assert_eq!(record.port, port);
    assert_eq!(record.vendor, "rockwell");

    // Values the simulator's List Identity item carries: vendor 1, device type 0x0E, product
    // code 1, revision 31.3, serial 0x12345678, name "PLC".
    // casket spells vendor id 1 two ways: `enip/enums.rs` has no spaces,
    // `rockwell/driver.rs` (the path this record comes from) has them. Pin the driver's
    // spelling here and keep the drift visible instead of normalising it away in ops.
    assert_eq!(
        text(record, "vendor_name"),
        "Rockwell Automation / Allen-Bradley"
    );
    assert_eq!(text(record, "product_name"), "PLC");
    assert_eq!(
        text(record, "product_type"),
        "Programmable Logic Controller"
    );
    assert_eq!(text(record, "revision"), "31.3");
    assert_eq!(text(record, "serial"), "12345678");
    assert_eq!(record.fields["product_code"].as_u64(), Some(1));
    assert_eq!(record.identity.as_deref(), Some("PLC"));
}

#[test]
fn rockwell_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::rockwell::scan_ip("127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No Rockwell")));
}
