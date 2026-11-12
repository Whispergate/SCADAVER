//! Beckhoff contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

mod common;

use scadaver::model::EndpointRecord;
use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// The simulator parses `--ads-port` and `--discovery-port`, not `--port`. Both come from the OS:
// hardcoded values landed inside a Windows reserved range and the bind failed before the sim started.

struct Simulator(Child);

impl Simulator {
    fn spawn(ads_port: u16, discovery_port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "sim/beckhoff_sim.py",
                "--host",
                "127.0.0.1",
                "--ads-port",
                &ads_port.to_string(),
                "--discovery-port",
                &discovery_port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/beckhoff_sim.py must exist");

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", ads_port)).is_ok() {
                return Self(child);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("simulator did not listen on {ads_port} within 10s");
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
fn beckhoff_scan_returns_typed_records() {
    let ads_port = common::tcp_port();
    let _sim = Simulator::spawn(ads_port, common::udp_port());

    // casket's UDP discovery leg is pinned to 48899, which the simulator is not listening on
    // here, so this exercises the ADS/TCP fallback the legacy arm also relied on.
    let outcome = scadaver::ops::beckhoff::scan_ip("127.0.0.1", ads_port, 1);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Beckhoff);
    assert_eq!(record.port, ads_port);
    assert_eq!(record.vendor, "beckhoff");

    // AMS Net ID derived from the target IP, and the ReadState answer the simulator always gives.
    assert_eq!(text(record, "netid"), "127.0.0.1.1.1");
    assert_eq!(text(record, "ads_state"), "RUN");
    assert_eq!(
        record.fields["ads_port"].as_u64(),
        Some(u64::from(ads_port))
    );
    let name = text(record, "name");
    assert!(
        name.contains("Beckhoff"),
        "expected the derived device name, got {name:?}"
    );
    assert_eq!(record.identity.as_deref(), Some(name.as_str()));
}

#[test]
fn beckhoff_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::beckhoff::scan_ip("127.0.0.1", 1, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(outcome
        .messages
        .iter()
        .any(|m| m.text.contains("No Beckhoff")));
}
