// Siemens S7comm in-process loopback integration test.
//
// Binds an ephemeral TCP port and serves the three-phase S7 handshake:
//   1. COTP Connection Request → Connection Confirm (byte[5] = 0xd0)
//   2. S7Comm Setup → ACK (byte[9] = 0x00)
//   3. SZL 0x0011 read → response with hardware MLFB + firmware bytes
//   4. SZL 0x0424 read → response with CPU mode byte
//
// Then calls scan::scan_ip_with_port and asserts the parsed SiemensDevice.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

// COTP Connection Confirm — byte[5] must be 0xd0 (checked by setup_connection as
// hex_encode(resp)[10..12] == "d0").
const COTP_CC: &[u8] = &[
    0x03, 0x00, 0x00, 0x0b, // TPKT: total = 11
    0x06, // COTP length field
    0xd0, // PDU type: Connection Confirm ← hex_encode[10..12] = "d0"
    0x00, 0x00, // dst reference
    0x00, 0x01, // src reference
    0x00, // class/options
];

// S7Comm Setup ACK — byte[9] must be 0x00 (checked as hex_encode(resp)[18..20] == "00").
// send_recv reads TPKT total_len from bytes [2..3] big-endian, so 0x0a = 10 total bytes.
const S7_ACK: &[u8] = &[
    0x03, 0x00, 0x00, 0x0a, // TPKT: total = 10
    0x02, 0xf0, 0x80, // COTP DT header
    0x32, 0x03, // S7 protocol (0x32) + msg_type ACK_DATA (0x03)
    0x00, // byte[9] = 0x00 ← hex_encode[18..20] = "00"
];

// SZL 0x0011 response — module info (hardware MLFB + firmware version).
//
// szl_records_start searches from offset 19 for [0xFF, 0x09] marker.
// pos = 19 → szl_id at pos+4..5 = bytes[23..24] = [0x00, 0x11] (big-endian).
// rec_start = pos + 12 = 31.
// hardware: resp[rec_start+2 .. rec_start+22] = bytes[33..53] = "6ES7 315-2EH14      "
// firmware: V{resp[rec_start+26]}.{resp[rec_start+27]} = "V3.1"
const SZL_0011_RESP: &[u8] = &[
    // TPKT header — total = 71 = 0x47
    0x03, 0x00, 0x00, 0x47, // COTP DT
    0x02, 0xf0, 0x80, // S7 UserData response header filler (bytes 7–18, 12 bytes)
    0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [0xFF, 0x09] marker at offset 19
    0xff, 0x09, // data_len (bytes 21–22)
    0x00, 0x24, // szl_id = 0x0011 at pos+4..5 (bytes 23–24, big-endian)
    0x00, 0x11, // szl_index (bytes 25–26)
    0x00, 0x01, // count = 1 (bytes 27–28)
    0x00, 0x01, // reclen = 40 = 0x28 (bytes 29–30)
    0x00, 0x28, // record starts at byte 31 (rec_start = 31)
    0x00, 0x01, // rec[0..1]: record index
    // rec[2..22]: MLFB string (20 bytes) — "6ES7 315-2EH14" + 6 spaces
    b'6', b'E', b'S', b'7', b' ', b'3', b'1', b'5', b'-', b'2', b'E', b'H', b'1', b'4', b' ', b' ',
    b' ', b' ', b' ', b' ', // rec[22..26]: padding
    0x00, 0x00, 0x00, 0x00, // rec[26]: fw_major = 3
    0x03, // rec[27]: fw_minor = 1
    0x01, // rec[28..40]: remaining record padding (12 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// SZL 0x0424 response — CPU operating mode.
//
// Same header structure; szl_id at bytes[23..24] = [0x04, 0x24].
// rec_start = 31; mode_off = rec_start + 2 = 33; resp[33] = 0x01 → "Running".
const SZL_0424_RESP: &[u8] = &[
    // TPKT header — total = 47 = 0x2F
    0x03, 0x00, 0x00, 0x2f, // COTP DT
    0x02, 0xf0, 0x80, // S7 UserData filler (bytes 7–18, 12 bytes)
    0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [0xFF, 0x09] marker at offset 19
    0xff, 0x09, // data_len (bytes 21–22)
    0x00, 0x14, // szl_id = 0x0424 at pos+4..5 (bytes 23–24, big-endian)
    0x04, 0x24, // szl_index (bytes 25–26)
    0x00, 0x01, // count = 1 (bytes 27–28)
    0x00, 0x01, // reclen = 16 = 0x10 (bytes 29–30)
    0x00, 0x10, // record starts at byte 31
    0x00, 0x01, // rec[0..1]: record index
    // rec[2]: mode byte = 0x01 → "Running"
    0x01, // rec[3..16]: padding (13 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Serve one complete S7 session on the given listener.
//
// Loops on accept() to skip the plain TCP probe that scan_ip_with_port uses to
// check port reachability before initiating the real S7 session.
fn serve_s7_session(listener: &TcpListener) {
    for _ in 0..10 {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        let _ = s.set_read_timeout(Some(Duration::from_millis(800)));

        // Phase 1: COTP Connection Request (22 bytes) → Connection Confirm
        let mut cr = [0u8; 22];
        if s.read_exact(&mut cr).is_err() {
            continue; // scan_port probe dropped the connection — skip
        }
        if s.write_all(COTP_CC).is_err() {
            return;
        }

        // Phase 2: S7Comm Setup (25 bytes) → ACK
        let mut setup = [0u8; 25];
        if s.read_exact(&mut setup).is_err() {
            return;
        }
        if s.write_all(S7_ACK).is_err() {
            return;
        }

        // Phase 3a: SZL 0x0011 read (33 bytes) → module info response
        let mut szl_req = [0u8; 33];
        if s.read_exact(&mut szl_req).is_err() {
            return;
        }
        if s.write_all(SZL_0011_RESP).is_err() {
            return;
        }

        // Phase 3b: SZL 0x0424 read (33 bytes) → CPU state response
        if s.read_exact(&mut szl_req).is_err() {
            return;
        }
        let _ = s.write_all(SZL_0424_RESP);
        return;
    }
}

#[test]
fn loopback_s7_scan_returns_device() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_s7_session(&listener));
    thread::sleep(Duration::from_millis(50));

    let dev = casket::vendors::siemens::scan::scan_ip_with_port("127.0.0.1", port);

    assert!(
        dev.hardware.is_some(),
        "hardware should be populated from SZL 0x0011 MLFB: {dev:?}"
    );
    assert_eq!(dev.hardware.as_deref(), Some("6ES7 315-2EH14"));
    assert_eq!(dev.firmware.as_deref(), Some("V3.1"));
    assert_eq!(dev.cpu_state.as_deref(), Some("Running"));
}
