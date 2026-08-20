// Phoenix Contact ProConOS loopback integration test.
// Implements the 3-exchange handshake required by get_device_info.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn serve_phoenix(listener: TcpListener) {
    let Ok((mut s, _)) = listener.accept() else { return };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));

    let mut buf = [0u8; 4096];
    let mut exchange = 0u32;

    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                exchange += 1;
                match exchange {
                    1 => {
                        // First response: >= 18 bytes, code byte at [17]
                        let mut resp = [0u8; 25];
                        resp[17] = 0x42; // session code
                        let _ = s.write_all(&resp);
                    }
                    2 => {
                        // Second response: let _ = send_recv(...) — any bytes suffice
                        let _ = s.write_all(&[0u8; 8]);
                    }
                    3 => {
                        // Third response: ret for plc_type [30..50] and firmware [66..70]
                        let mut resp = [0u8; 100];
                        resp[30..44].copy_from_slice(b"CI-Phoenix-ILC");
                        resp[66..70].copy_from_slice(b"V1.0");
                        resp[79..92].copy_from_slice(b"Build-2024001");
                        let _ = s.write_all(&resp);
                    }
                    _ => {
                        // Remaining exchanges are all let _ = send_recv(...)
                        let _ = s.write_all(&[0u8; 4]);
                    }
                }
            }
        }
    }
}

#[test]
fn loopback_phoenix_get_device_info() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_phoenix(listener));
    thread::sleep(Duration::from_millis(50));

    let result = scadaver::vendors::phoenix::control::get_device_info("127.0.0.1", port, true);
    assert!(result.is_ok(), "Phoenix get_device_info should succeed: {:?}", result.err());
    let dev = result.unwrap();
    assert!(
        dev.plc_type.contains("CI-Phoenix"),
        "plc_type should contain CI-Phoenix, got: {}", dev.plc_type
    );
    assert!(dev.firmware.is_some(), "firmware should be Some");
}
