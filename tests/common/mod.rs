//! Ports for tests that start a simulator.
//!
//! Windows reserves large port blocks for Hyper-V and winnat, and the blocks move between boots: this
//! host currently excludes 123 TCP ranges. A hardcoded port that lands inside one fails to bind with
//! `WinError 10013`, the simulator never comes up, and the test reports a product failure that is really
//! a host reservation. Ask the OS for a port instead, except where the protocol itself fixes the
//! number (EtherNet/IP List Identity is 44818 on the wire).

// Each test binary uses one of these helpers, so the other reads as dead code there.
#![allow(dead_code)]

use std::net::{TcpListener, UdpSocket};

/// A TCP port nobody is listening on right now.
pub fn tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("an ephemeral TCP port")
        .local_addr()
        .expect("a bound address")
        .port()
}

/// A UDP port nobody is bound to right now.
pub fn udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("an ephemeral UDP port")
        .local_addr()
        .expect("a bound address")
        .port()
}

/// The interpreter that runs the simulators.
///
/// The suite used to rely on whatever `python` meant on `PATH`. That is not a stable fact: on this host
/// `python` is a tool-managed 3.14 with no pymodbus, so every simulator spawning through it died on
/// import and the tests reported product failures. Set `SCADAVER_SIM_PYTHON` to override; otherwise prefer
/// a real 3.13 install if one exists, then fall back to `python`.
pub fn python_exe() -> String {
    if let Ok(value) = std::env::var("SCADAVER_SIM_PYTHON") {
        if !value.is_empty() {
            return value;
        }
    }
    let candidates = [
        r"C:/Users/USER/AppData/Local/Programs/Python/Python313/python.exe",
        r"C:/Python313/python.exe",
        r"C:/Program Files/Python313/python.exe",
    ];
    for candidate in candidates {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "python".to_string()
}
