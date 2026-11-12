//! Omron FINS contract test. Spawns the simulator itself, so it is not `#[ignore]`d.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;

// Each test asks the OS for its port. Hardcoded values (29600 and friends) sat inside a Windows
// reserved range on this host, where bind fails with WinError 10013 and the simulator never starts.

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let child = Command::new(common::python_exe())
            .args([
                "sim/fins_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/fins_sim.py must exist");

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

fn field_text(fields: &std::collections::BTreeMap<String, serde_json::Value>, key: &str) -> String {
    fields
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn omron_scan_returns_typed_records() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);

    let outcome = scadaver::ops::scan_ip(Protocol::Omron, "127.0.0.1", port, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one device expected, got {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.protocol, Protocol::Omron);
    assert_eq!(record.port, port);
    assert_eq!(record.vendor, "omron");

    // The simulator answers controller data read (05 01) with model "CP1E" and version "V1.0"
    // and assigns server node 1 during address negotiation.
    assert_eq!(field_text(&record.fields, "model"), "CP1E");
    assert_eq!(field_text(&record.fields, "version"), "V1.0");
    assert_eq!(
        record
            .fields
            .get("node")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "server node from the negotiation frame"
    );
    assert_eq!(record.identity.as_deref(), Some("CP1E"));
}

#[test]
fn omron_with_nothing_listening_is_a_message_not_a_panic() {
    let closed_port = common::tcp_port();
    let outcome = scadaver::ops::scan_ip(Protocol::Omron, "127.0.0.1", closed_port, 1);
    assert!(
        outcome.records.is_empty(),
        "expected empty, got {:?}",
        outcome.records
    );
    assert!(
        outcome
            .messages
            .iter()
            .any(|m| m.text.contains("No Omron FINS response")),
        "got {:?}",
        outcome.messages
    );
    assert_eq!(outcome.messages.len(), 1);
}

// Each test below spawns its own simulator on its own port. `cargo test` without
// `--test-threads=1` runs siblings in parallel, and two FINS stubs on one port means one of
// them never listens.

#[test]
fn omron_identity_carries_the_negotiated_node() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);

    let identity = scadaver::ops::omron::identity("127.0.0.1", port)
        .expect("the simulator answers controller data read");
    assert_eq!(identity.model, "CP1E");
    assert_eq!(identity.version, "V1.0");
    assert_eq!(identity.node, 1, "server node from the negotiation frame");
}

#[test]
fn omron_dm_write_then_read_returns_the_same_words() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);
    let written = [11u16, 22, 33, 0xBEEF];

    scadaver::ops::omron::write_dm_words("127.0.0.1", port, 500, &written)
        .expect("the simulator acknowledges memory area write");

    let read = scadaver::ops::omron::read_dm_words("127.0.0.1", port, 500, 4)
        .expect("the simulator answers memory area read");
    assert_eq!(read, written);
}

#[test]
fn omron_port_zero_resolves_to_the_fins_default() {
    // The simulator cannot listen on 9600 here, so only the resolution is under test.
    assert_eq!(scadaver::ops::omron::fins_port(0), 9600);
    assert_eq!(scadaver::ops::omron::fins_port(1234), 1234);
}

#[test]
fn omron_dm_range_past_the_last_word_fails_before_connecting() {
    // Port 1 is not listening; a socket error would name the endpoint. The range error must
    // win, which proves the check runs before any connect.
    let error = scadaver::ops::omron::read_dm_words("127.0.0.1", 1, 65530, 32)
        .expect_err("DM65530 plus 32 words cannot exist");
    assert!(error.contains("DM65530"), "got {error}");
    assert!(error.contains("65535"), "got {error}");
    assert!(
        !error.contains("127.0.0.1"),
        "no socket was opened: {error}"
    );
}

#[test]
fn omron_dm_read_error_names_the_endpoint_and_the_range() {
    let closed_port = common::tcp_port();
    let error = scadaver::ops::omron::read_dm_words("127.0.0.1", closed_port, 100, 4)
        .expect_err("nothing is listening");
    assert!(
        error.contains(&format!("127.0.0.1:{closed_port}")),
        "got {error}"
    );
    assert!(error.contains("DM100..DM103"), "got {error}");
}

#[test]
fn omron_cpu_mode_change_is_reflected_by_cpu_state() {
    let port = common::tcp_port();
    let _sim = Simulator::spawn(port);

    assert_eq!(
        scadaver::ops::omron::cpu_state("127.0.0.1", port).expect("status read"),
        "Run",
        "the simulator starts in Run"
    );

    scadaver::ops::omron::set_cpu_mode("127.0.0.1", port, scadaver::ops::omron::CpuMode::Stop)
        .expect("mode change is acknowledged");
    assert_eq!(
        scadaver::ops::omron::cpu_state("127.0.0.1", port).expect("status read"),
        "Stop"
    );

    // Leave the simulator in Run, the state the other tests assume.
    scadaver::ops::omron::set_cpu_mode("127.0.0.1", port, scadaver::ops::omron::CpuMode::Run)
        .expect("mode change is acknowledged");
}
