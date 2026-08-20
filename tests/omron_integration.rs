// Omron FINS/TCP loopback integration test.
// Implements the 2-stage address negotiation + Controller Data Read exchange.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn serve_fins_tcp(listener: TcpListener) {
    if let Ok((mut s, _)) = listener.accept() {
        // Stage 1: address negotiation
        // Client sends 20-byte hello; we reply with 24 bytes, node=1 at byte 23
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
        let mut hello_resp = [0u8; 24];
        hello_resp[23] = 0x01; // assigned server node
        let _ = s.write_all(&hello_resp);

        // Stage 2: FINS/TCP command response (Controller Data Read 05 01)
        // Client sends a framed FINS command; we reply with header + 52-byte body
        let _ = s.read(&mut buf);

        // Build response header (16 bytes):
        //   [0..4]  = b"FINS"
        //   [4..8]  = resp_len BE (= body_len + 8 = 52 + 8 = 60)
        //   [8..12] = command (2 = execute)
        //   [12..16] = error (0)
        let mut resp_header = [0u8; 16];
        resp_header[..4].copy_from_slice(b"FINS");
        resp_header[4..8].copy_from_slice(&60u32.to_be_bytes());
        resp_header[8..12].copy_from_slice(&2u32.to_be_bytes());

        // Build 52-byte body:
        //   [0..10]  = FINS header (all zeros OK for parsing)
        //   [10..12] = end_code (not checked by get_device_info_tcp)
        //   [12..32] = model string (20 bytes)
        //   [32..52] = version string (20 bytes)
        let mut body = [0u8; 52];
        let model = b"CI-Omron-CJ2M";
        let version = b"V3.1.0";
        body[12..12 + model.len()].copy_from_slice(model);
        body[32..32 + version.len()].copy_from_slice(version);

        let _ = s.write_all(&resp_header);
        let _ = s.write_all(&body);
    }
}

#[test]
fn loopback_omron_fins_device_info() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_fins_tcp(listener));
    thread::sleep(Duration::from_millis(50));

    let result = scadaver::vendors::omron::fins::get_device_info_tcp("127.0.0.1", port);
    assert!(result.is_ok(), "FINS device info should succeed: {:?}", result.err());
    let dev = result.unwrap();
    assert_eq!(dev.node_addr, 1);
    assert!(
        dev.model.contains("CI-Omron"),
        "model should contain CI-Omron, got: {}", dev.model
    );
}
