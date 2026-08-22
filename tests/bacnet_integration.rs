// BACnet/IP integration tests — in-process UDP loopback on port 47808.
// Binds the BACnet port directly (skip-on-busy, same pattern as dnp3/beckhoff).
// No env vars required.
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use scadaver::vendors::bacnet::client::{self, scan_ip, BACNET_PORT, PROP_OBJECT_NAME};

// Static I-Am response: device instance 1, vendor-id 5, max-APDU 480.
// Bytes verified against parse_i_am_valid_packet unit test in client.rs.
const I_AM_RESPONSE: &[u8] = &[
    0x81, 0x0A, 0x00, 0x14,            // BVLC unicast, length=20
    0x01, 0x00,                        // NPDU version 1, no flags
    0x10, 0x00,                        // UNCONFIRMED_REQ, SVC_I_AM
    0xC4, 0x02, 0x00, 0x00, 0x01,      // ObjectIdentifier: device,instance=1
    0x22, 0x01, 0xE0,                  // max-APDU: 480 (2-byte unsigned)
    0x91, 0x03,                        // segmentation-supported: none(3)
    0x21, 0x05,                        // vendor-id: 5 (1-byte unsigned)
];

// Build a Complex-ACK Read-Property response with CharacterString value "ci".
// invoke_id and prop_id are echoed from the incoming request.
fn build_read_prop_ack(invoke_id: u8, prop_id: u8) -> Vec<u8> {
    let oid: u32 = (8u32 << 22) | 1;
    let oid = oid.to_be_bytes();

    // CharacterString "ci": tag 7, extended-length, len=3 (encoding byte + 2 chars)
    let char_string: &[u8] = &[0x75, 0x03, 0x00, b'c', b'i'];

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x30, invoke_id, 0x0C]);           // COMPLEX_ACK header
    body.extend_from_slice(&[0x0C, oid[0], oid[1], oid[2], oid[3]]); // object-id
    body.extend_from_slice(&[0x19, prop_id]);                    // property-id
    body.push(0x3E);                                             // open tag [3]
    body.extend_from_slice(char_string);
    body.push(0x3F);                                             // close tag [3]

    let npdu: &[u8] = &[0x01, 0x00];
    let payload_len = npdu.len() + body.len();
    let total = 4 + payload_len;
    let mut pkt = vec![0x81, 0x0A, (total >> 8) as u8, (total & 0xFF) as u8];
    pkt.extend_from_slice(npdu);
    pkt.extend_from_slice(&body);
    pkt
}

// Serve one Who-Is + up to N Read-Property requests on the given socket.
fn serve_bacnet(sock: UdpSocket, max_exchanges: usize) {
    let mut buf = [0u8; 512];
    for _ in 0..max_exchanges {
        let Ok((_n, peer)) = sock.recv_from(&mut buf) else { break };
        match buf.get(6) {
            Some(&0x10) => {
                // UNCONFIRMED_REQ → I-Am
                let _ = sock.send_to(I_AM_RESPONSE, peer);
            }
            Some(&0x00) => {
                // CONFIRMED_REQ → Read-Property ACK
                let invoke_id = buf.get(8).copied().unwrap_or(1);
                let prop_id = buf.get(16).copied().unwrap_or(77);
                let ack = build_read_prop_ack(invoke_id, prop_id);
                let _ = sock.send_to(&ack, peer);
            }
            _ => {}
        }
    }
}

#[test]
fn bacnet_port_constant() {
    assert_eq!(BACNET_PORT, 0xBAC0, "BACnet port must be 47808 (0xBAC0)");
    assert_eq!(BACNET_PORT, 47808);
}

#[test]
fn loopback_bacnet_scan_ip_returns_device() {
    // client hardcodes BACNET_PORT — must bind same port; skip if busy
    let sock = match UdpSocket::bind("127.0.0.1:47808") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    // scan_ip sends 1 Who-Is + 4 Read-Property = 5 UDP exchanges
    thread::spawn(move || serve_bacnet(sock, 5));
    thread::sleep(Duration::from_millis(50));

    let result = scan_ip("127.0.0.1", 2);
    assert!(result.is_some(), "loopback BACnet mock should respond to unicast Who-Is");
    let dev = result.unwrap();
    assert_eq!(dev.instance_id, 1);
    assert_eq!(dev.vendor_id, 5);
    assert_eq!(dev.object_name, "ci");
}

#[test]
fn loopback_bacnet_read_object_name() {
    let sock = match UdpSocket::bind("127.0.0.1:47808") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    // scan_ip (5) + one explicit read_property call (1) = 6 exchanges
    thread::spawn(move || serve_bacnet(sock, 6));
    thread::sleep(Duration::from_millis(50));

    let dev = scan_ip("127.0.0.1", 2);
    assert!(dev.is_some());
    let dev = dev.unwrap();
    let name = client::read_property("127.0.0.1", dev.instance_id, PROP_OBJECT_NAME, Duration::from_secs(2));
    assert!(name.is_some(), "read_property(object-name) should return a value");
    assert_eq!(name.unwrap(), "ci");
}
