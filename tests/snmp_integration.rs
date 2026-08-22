// SNMP integration tests — in-process UDP loopback, no env vars required.
// The mock sends a static SNMPv2c GetResponse for OID 1.3.6.1.2.1.1.1.0 = "scadaver CI".
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use scadaver::vendors::snmp::{client, oids};

// Hand-crafted SNMPv2c GetResponse (community "public", req-id 1, error-status 0)
// OID 1.3.6.1.2.1.1.1.0 = OCTET STRING "scadaver CI"
//
// Outer SEQUENCE (0x30) len=49:
//   INTEGER version=1 (v2c):       02 01 01
//   OCTET STRING "public":         04 06 70 75 62 6C 69 63
//   GetResponse-PDU (0xA2) len=36:
//     INTEGER req-id=1:            02 01 01
//     INTEGER error-status=0:      02 01 00
//     INTEGER error-index=0:       02 01 00
//     SEQUENCE VarBindList len=25:
//       SEQUENCE VarBind len=23:
//         OID 1.3.6.1.2.1.1.1.0:  06 08 2B 06 01 02 01 01 01 00
//         OCTET STRING "scadaver CI": 04 0B 73 63 61 64 61 76 65 72 20 43 49
const SNMP_RESPONSE: &[u8] = &[
    0x30, 0x31,
      0x02, 0x01, 0x01,
      0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
      0xA2, 0x24,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x19,
          0x30, 0x17,
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x04, 0x0B,
              b's', b'c', b'a', b'd', b'a', b'v', b'e', b'r', b' ', b'C', b'I',
];

fn serve_snmp_once(sock: UdpSocket) {
    let mut buf = [0u8; 65_535];
    let Ok((_, peer)) = sock.recv_from(&mut buf) else { return };
    let _ = sock.send_to(SNMP_RESPONSE, peer);
}

#[test]
fn snmp_port_constant() {
    assert_eq!(client::SNMP_PORT, 161, "SNMP default port must be 161");
}

#[test]
fn loopback_snmp_discover_community() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || serve_snmp_once(sock));
    thread::sleep(Duration::from_millis(50));

    let community = client::discover_community("127.0.0.1", port);
    assert!(community.is_some(), "mock SNMP server should respond to discover_community");
    assert_eq!(community.as_deref(), Some("public"), "first community tried must be 'public'");
}

#[test]
fn loopback_snmp_get_sys_descr() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || serve_snmp_once(sock));
    thread::sleep(Duration::from_millis(50));

    let result = client::get("127.0.0.1", port, "public", oids::SYS_DESCR);
    assert!(result.is_ok(), "GET sysDescr.0 should succeed: {:?}", result.err());
    assert_eq!(result.unwrap().display(), "scadaver CI");
}
