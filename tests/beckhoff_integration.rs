// Beckhoff ADS UDP discovery loopback integration test.
// Crafts a valid discovery response and verifies discover_ip parses it.
// Binds to UDP port 48899; skips gracefully if port is busy.
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn build_beckhoff_response() -> Vec<u8> {
    // parse_discovery_frame requires:
    //   hex_encode(data).len() >= 56  →  data.len() >= 28
    //   data[12..18] = AMS Net ID (6 bytes)
    //   data[26..28] = name_len as LE u16 (includes null terminator)
    //   data[28..28+name_len-1] = device name bytes (no null)
    //   data.len() >= 27 + name_len
    let name = b"CI-BeckhoffTwin";
    let name_len: usize = name.len() + 1; // include null
    let mut frame = vec![0u8; 28 + name_len]; // exact minimum
    // AMS Net ID at bytes 12..18 → hex at hexdata[24..36]
    frame[12..18].copy_from_slice(&[0x7F, 0x00, 0x00, 0x01, 0x01, 0x01]);
    // name_len as LE u16 at bytes 26..28
    let nl = u16::try_from(name_len).unwrap_or(u16::MAX).to_le_bytes();
    frame[26] = nl[0];
    frame[27] = nl[1];
    // device name at bytes 28..28+name_len-1
    frame[28..28 + name.len()].copy_from_slice(name);
    frame
}

#[test]
fn loopback_beckhoff_discover_ip_finds_device() {
    let server_sock = match UdpSocket::bind("0.0.0.0:48899") {
        Ok(s) => s,
        Err(_) => return, // port busy on CI, skip
    };
    server_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let resp = build_beckhoff_response();

    thread::spawn(move || {
        let mut buf = [0u8; 256];
        if let Ok((_, peer)) = server_sock.recv_from(&mut buf) {
            let _ = server_sock.send_to(&resp, peer);
        }
    });
    thread::sleep(Duration::from_millis(50));

    let result =
        scadaver::vendors::beckhoff::scan::discover_ip("127.0.0.1", 2, true);
    assert!(result.is_ok(), "discover_ip should return Ok: {:?}", result.err());
    let devs = result.unwrap();
    assert_eq!(devs.len(), 1, "should discover exactly one Beckhoff device");
    assert_eq!(devs[0].name, "CI-BeckhoffTwin");
    assert_eq!(devs[0].netid_str, "127.0.0.1.1.1");
}
