//! Exit codes for a targeted scan and `get info` that find nothing.
//!
//! Both used to print an error and return `Ok(())`, so a caller could not distinguish "no device" from
//! "device answered" without parsing text. These tests spawn the binary and assert on the code, which is
//! the contract a script actually uses.

use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

fn scadaver() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scadaver"))
}

/// A port nothing is listening on: bind, read the assigned port, then release it.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn run(args: &[&str]) -> (i32, String) {
    let output = scadaver()
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn scadaver");
    let code = output.status.code().unwrap_or(-1);
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (code, text)
}

#[test]
fn targeted_scan_of_a_silent_address_exits_nonzero() {
    std::thread::sleep(Duration::from_millis(50));
    let port = closed_port();
    let port_text = port.to_string();
    let (code, text) = run(&[
        "scan",
        "-i",
        "127.0.0.1",
        "-p",
        &port_text,
        "--protocol",
        "beckhoff",
        "--live",
        "--no-cache",
        "--color",
        "never",
    ]);
    assert_ne!(code, 0, "scan exited 0 with nothing listening:\n{text}");
    assert!(
        text.to_lowercase().contains("no") || text.to_lowercase().contains("response"),
        "scan failure said nothing useful:\n{text}"
    );
}

#[test]
fn get_info_on_a_silent_address_exits_nonzero() {
    std::thread::sleep(Duration::from_millis(50));
    let port = closed_port();
    let port_text = port.to_string();
    let (code, text) = run(&[
        "get",
        "info",
        "-i",
        "127.0.0.1",
        "-p",
        &port_text,
        "--protocol",
        "beckhoff",
        "--no-cache",
        "--color",
        "never",
    ]);
    assert_ne!(code, 0, "get info exited 0 with nothing listening:\n{text}");
    assert!(
        text.contains("No Beckhoff device found"),
        "get info failure did not name the reason:\n{text}"
    );
}
