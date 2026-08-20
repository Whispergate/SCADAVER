// EtherNet/IP UDP loopback integration test.
// Serves a valid List Identity reply on a random port, then calls scan_ip pointing at it.
// Note: scan_ip hard-codes destination port 44818. We bind the mock to 0.0.0.0:44818 and
// skip gracefully if that port is already in use.
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

// Minimal List Identity reply, matching the unit-test fixture in scan.rs
const LIST_ID_RESP: &[u8] = &[
    // EIP header (24 bytes): command=0x0063, data_len=43, rest zeros
    0x63, 0x00,
    0x2b, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // CPF (43 bytes): item_count=1, item_type=0x000C, item_len=37
    0x01, 0x00,
    0x0c, 0x00,
    0x25, 0x00,
    // Identity item (37 bytes)
    0x01, 0x00,                                                        // enc_version
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // socket_addr[0..8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // socket_addr[8..16]
    0x01, 0x00,  // item[18..20] vendor_id=1
    0x0e, 0x00,  // item[20..22] device_type=14
    0x01, 0x00,  // item[22..24] product_code
    0x1f, 0x03,  // item[24..26] rev major=31, minor=3
    0x00, 0x00,  // item[26..28] status
    0x78, 0x56, 0x34, 0x12,  // item[28..32] serial
    0x03,        // item[32] name_len=3
    b'P', b'L', b'C',        // item[33..36] name
    0x03,        // item[36] state
];

#[test]
fn loopback_enip_list_identity_parse() {
    // Try to bind the EtherNet/IP discovery port; skip if busy.
    let server_sock = match UdpSocket::bind("127.0.0.1:44818") {
        Ok(s) => s,
        Err(_) => return,
    };
    server_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 128];
        if let Ok((_, peer)) = server_sock.recv_from(&mut buf) {
            let _ = server_sock.send_to(LIST_ID_RESP, peer);
        }
    });
    thread::sleep(Duration::from_millis(50));

    let result = scadaver::vendors::enip::scan::scan_ip("127.0.0.1", 2, true);
    assert!(result.is_ok(), "EtherNet/IP scan_ip should return Ok");
    let devs = result.unwrap();
    assert_eq!(devs.len(), 1, "should find exactly one device");
    assert_eq!(devs[0].product_name, "PLC");
    assert_eq!(devs[0].vendor_id, "0001");
    assert_eq!(devs[0].device_type, 14);
    assert_eq!(devs[0].revision, "31.3");
}
