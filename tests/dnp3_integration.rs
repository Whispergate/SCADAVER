// DNP3 loopback + live integration tests.
// Loopback: in-process mock that validates the Reset Link States / Request Link Status exchange.
// Live: guarded by TEST_DNP3_HOST env var.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use scadaver::vendors::dnp3::client::{detect, DNP3_PORT};

// Reimplemented here because crc16_dnp is private in client.rs.
fn crc16_dnp(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        let mut b = byte;
        for _ in 0..8 {
            let bit = (crc ^ u16::from(b)) & 1;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xA6BC;
            }
            b >>= 1;
        }
    }
    !crc
}

/// Build a DLL-only Link Status secondary frame (FC=0x0B, DIR=0, PRM=0).
fn link_status_frame(dest: u16, src: u16) -> Vec<u8> {
    let hdr = [
        0x05u8,                    // length (DLL header = ctrl+dest+src = 5 bytes)
        0x0B,                      // ctrl: secondary FC_LINK_STATUS
        (dest & 0xFF) as u8,
        (dest >> 8) as u8,
        (src & 0xFF) as u8,
        (src >> 8) as u8,
    ];
    let crc = crc16_dnp(&hdr);
    let mut frame = vec![0x05u8, 0x64]; // start bytes
    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&crc.to_le_bytes());
    frame
}

fn serve_dnp3(listener: TcpListener) {
    let Ok((mut s, _)) = listener.accept() else { return };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 64];

    // Exchange 1: Reset Link States from master → respond with Link Status (src=outstation=0x0001)
    let _ = s.read(&mut buf);
    let _ = s.write_all(&link_status_frame(0x0001, 0x0001));

    // Exchange 2: Request Link Status from master → respond with Link Status
    let _ = s.read(&mut buf);
    let _ = s.write_all(&link_status_frame(0x0001, 0x0001));
}

#[test]
fn loopback_dnp3_detect_succeeds() {
    // detect() hard-codes port 20000; bind mock there, skip if busy.
    let listener = match TcpListener::bind(format!("127.0.0.1:{DNP3_PORT}")) {
        Ok(l) => l,
        Err(_) => return,
    };
    thread::spawn(move || serve_dnp3(listener));
    thread::sleep(Duration::from_millis(50));

    let result = detect("127.0.0.1", Duration::from_secs(2));
    assert!(result.is_some(), "DNP3 detect should return Some against loopback responder");
    let dev = result.unwrap();
    assert_eq!(dev.ip, "127.0.0.1");
    assert_eq!(dev.outstation_addr, 0x0001);
}

#[test]
fn live_dnp3_detect_returns_device() {
    let Some(host) = std::env::var("TEST_DNP3_HOST").ok() else { return };
    let result = detect(&host, Duration::from_secs(3));
    assert!(result.is_some(), "DNP3 detect should succeed against live outstation");
}
