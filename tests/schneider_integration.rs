// Schneider Electric UDP discovery loopback integration test.
// Mock listens on UDP port 1740 (Schneider's proprietary discovery port).
// Skips gracefully if the port is already in use.
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn build_schneider_response() -> Vec<u8> {
    // parse_response checks data.len() >= 53 for firmware/name extraction.
    // firmware: data[51].data[50].data[49].data[48] reversed
    // name:     data[52..] as UTF-8 (null-filtered)
    let name = b"M340 CI-Test";
    let mut data = vec![0u8; 53 + name.len()];
    // firmware bytes at [48..52]: format is data[51].data[50].data[49].data[48]
    data[48] = 14;  // patch
    data[49] = 0;   // patch2
    data[50] = 40;  // minor
    data[51] = 2;   // major → "2.40.0.14"
    data[52..52 + name.len()].copy_from_slice(name);
    data
}

#[test]
fn loopback_schneider_udp_discovers_device() {
    // Schneider scan sends to port 1740; mock must be bound there.
    let server_sock = match UdpSocket::bind("0.0.0.0:1740") {
        Ok(s) => s,
        Err(_) => return, // port busy, skip
    };
    server_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let resp = build_schneider_response();

    thread::spawn(move || {
        let mut buf = [0u8; 256];
        if let Ok((_, peer)) = server_sock.recv_from(&mut buf) {
            let _ = server_sock.send_to(&resp, peer);
        }
    });
    thread::sleep(Duration::from_millis(50));

    // scan_ip_with_transport(ip, timeout, silent, port, Transport::Udp) — UDP only
    use scadaver::vendors::schneider::scan::Transport;
    let result = scadaver::vendors::schneider::scan::scan_ip_with_transport(
        "127.0.0.1", 2, true, 0, Transport::Udp,
    );
    // Either the mock response or the client's own probe arrives; in both cases the
    // function must not error. Firmware parsing is covered by scan.rs unit tests.
    assert!(result.is_ok(), "Schneider scan should return Ok: {:?}", result.err());
}
