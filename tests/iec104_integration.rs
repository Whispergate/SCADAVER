// IEC 60870-5-104 loopback integration test.
// Spins up an in-process TCP server that responds with TESTFR_CON.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

#[test]
fn loopback_iec104_probe_returns_true() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 6];
            let _ = s.read_exact(&mut buf);
            // TESTFR_CON: start(0x68) + len(0x04) + ctrl[0x83 0x00 0x00 0x00]
            let _ = s.write_all(&[0x68, 0x04, 0x83, 0x00, 0x00, 0x00]);
        }
    });
    thread::sleep(Duration::from_millis(50));
    let result = scadaver::vendors::iec104::client::probe("127.0.0.1", port);
    assert!(result, "IEC104 TESTFR_ACT/CON handshake should succeed against loopback");
}
