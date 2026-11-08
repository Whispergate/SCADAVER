//! SNMP contract test. The simulator is UDP only, so there is no listener to connect to:
//! readiness is the child staying alive after a fixed wait (300 ms) rather than a TCP accept.
// The Simulator guard kills and reaps the child in `Drop`; clippy cannot see through
// the tuple struct, so it reports the spawn as unreaped.
#![allow(clippy::zombie_processes)]

use scadaver::protocol::Protocol;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const PORT: u16 = 21161;

struct Simulator(Child);

impl Simulator {
    fn spawn(port: u16) -> Self {
        let mut child = Command::new("python")
            .args([
                "sim/snmp_sim.py",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python and sim/snmp_sim.py must exist");

        // UDP has no accept queue to poll, so the simulator's own banner is the readiness
        // signal. A fixed sleep is not enough: a cold import of pysnmp (no __pycache__) can take
        // longer than the sleep, and the first scan then loses the race.
        let stdout = child.stdout.take().expect("stdout is piped");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("simulator did not announce itself within 10s on port {port}");
            }
            match rx.recv_timeout(left) {
                Ok(line) if line.contains("listening on UDP") => break,
                Ok(_) => {}
                Err(_) => {
                    let status = child.try_wait().ok().flatten();
                    panic!("simulator exited before it was ready: {status:?}");
                }
            }
        }
        Self(child)
    }
}

impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn snmp_scan_returns_typed_records() {
    let _sim = Simulator::spawn(PORT);

    let outcome = scadaver::ops::scan_ip(Protocol::Snmp, "127.0.0.1", PORT, 2);
    assert_eq!(
        outcome.records.len(),
        1,
        "one agent expected from the simulator on {PORT}: {:?}",
        outcome.messages
    );
    let record = &outcome.records[0];
    assert_eq!(record.ip, "127.0.0.1");
    assert_eq!(record.port, PORT);
    assert_eq!(record.protocol, Protocol::Snmp);
    assert_eq!(record.vendor, "snmp");

    // sim/snmp_sim.py only accepts the "public" community and answers these values.
    assert_eq!(
        record
            .fields
            .get("community")
            .and_then(|value| value.as_str()),
        Some("public")
    );
    let descr = record
        .fields
        .get("descr")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        descr.contains("SCALANCE X200"),
        "expected the simulator's sysDescr, got {descr:?}"
    );
    assert_eq!(
        record
            .fields
            .get("sys_name")
            .and_then(|value| value.as_str()),
        Some("snmp-sim-01")
    );
    assert_eq!(record.identity.as_deref(), Some("snmp-sim-01"));
}

#[test]
fn snmp_with_nothing_listening_is_a_message_not_a_panic() {
    let outcome = scadaver::ops::scan_ip(Protocol::Snmp, "127.0.0.1", 1, 1);
    assert!(outcome.records.is_empty());
    assert!(
        outcome
            .messages
            .iter()
            .any(|message| message.text.contains("No SNMP community")),
        "expected a warning, got {:?}",
        outcome.messages
    );
}
