// eWON IPCONF UDP loopback integration test.
// Mock listens on port 1507, replies with a device-info response (byte[15]=2).
// Skips gracefully if port 1507 is already in use.
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn build_ewon_device_info_response() -> Vec<u8> {
    // parse_response checks data.len() >= 16 and data[15] == 2 for device_info.
    // parse_device_info reads:
    //   ip  = data[23].data[22].data[21].data[20]  (requires len >= 28)
    //   mac = data[32..38]                          (requires len >= 38)
    //   identifier = data[0..4]
    let mut resp = vec![0u8; 38];
    resp[0..4].copy_from_slice(b"IPCO");   // identifier
    resp[15] = 2;                           // device_info response type
    // IP 127.0.0.1 stored reversed at bytes 20..24
    resp[20] = 1;
    resp[21] = 0;
    resp[22] = 0;
    resp[23] = 127;
    // MAC at bytes 32..38
    resp[32..38].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    resp
}

#[test]
fn loopback_ewon_scan_ip_finds_device() {
    // eWON probe sends to port 1507; mock must be bound there.
    let server_sock = match UdpSocket::bind("0.0.0.0:1507") {
        Ok(s) => s,
        Err(_) => return, // port busy, skip
    };
    server_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let resp = build_ewon_device_info_response();

    thread::spawn(move || {
        let mut buf = [0u8; 256];
        if let Ok((_, peer)) = server_sock.recv_from(&mut buf) {
            let _ = server_sock.send_to(&resp, peer);
        }
    });
    thread::sleep(Duration::from_millis(50));

    // scan_ip sends two discovery packets then listens on port 1506 (or random fallback).
    let result = scadaver::vendors::ewon::scan::scan_ip("127.0.0.1", 2, true);
    assert!(result.is_ok(), "eWON scan_ip should return Ok: {:?}", result.err());
    let devs = result.unwrap();
    // At least one device should be discovered
    assert!(!devs.is_empty(), "should find at least one eWON device");
    let dev = &devs[0];
    assert_eq!(dev.response_type, "device_info");
    assert_eq!(dev.identifier.as_deref(), Some("IPCO"));
    assert_eq!(dev.ip.as_deref(), Some("127.0.0.1"));
}
