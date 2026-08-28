// Rockwell EtherNet/IP TCP loopback integration test.
// Binds a random TCP port, serves a valid List Identity reply, calls
// driver::get_device_info pointing at it, and asserts the parsed device.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

// Identical bytes to tests/enip_integration.rs LIST_ID_RESP — same EIP format
// is used by both the UDP enip scanner and the Rockwell TCP list_identity_tcp path.
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
    0x01, 0x00,  // vendor_id = 1
    0x0e, 0x00,  // device_type = 14
    0x01, 0x00,  // product_code = 1
    0x1f, 0x03,  // revision: major=31, minor=3
    0x00, 0x00,  // status
    0x78, 0x56, 0x34, 0x12,  // serial = 0x12345678
    0x03,        // name_len = 3
    b'P', b'L', b'C',        // product_name
    0x03,        // state
];

fn serve_list_identity(listener: &TcpListener) {
    let Ok((mut s, _)) = listener.accept() else { return };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let mut req = [0u8; 24];
    if s.read_exact(&mut req).is_err() {
        return;
    }
    let _ = s.write_all(LIST_ID_RESP);
}

#[test]
fn rockwell_no_server_returns_err() {
    // Port 1 is reserved and unreachable — get_device_info must return Err.
    let result = casket::vendors::rockwell::driver::get_device_info("127.0.0.1", 1);
    assert!(result.is_err(), "get_device_info with no server must return Err");
}

#[test]
fn loopback_rockwell_list_identity_returns_device() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_list_identity(&listener));
    thread::sleep(Duration::from_millis(50));

    let result = casket::vendors::rockwell::driver::get_device_info("127.0.0.1", port);
    assert!(result.is_ok(), "list_identity_tcp should succeed: {:?}", result.err());
    let dev = result.unwrap();
    assert_eq!(dev.product_name, "PLC");
    assert_eq!(dev.revision, "31.3");
    assert_eq!(dev.vendor, "Rockwell Automation / Allen-Bradley");
}
