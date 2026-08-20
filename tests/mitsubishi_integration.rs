// Mitsubishi SLMP loopback integration test.
// Implements a minimal SLMP 3E binary response for a 1-word read request.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn serve_slmp(listener: TcpListener) {
    if let Ok((mut s, _)) = listener.accept() {
        let mut buf = [0u8; 64];
        let _ = s.read(&mut buf);

        // SLMP 3E binary response:
        //   Subheader: 0xD0 0x00 (response)
        //   Network no: 0xFF
        //   PC no: 0xFF
        //   Request dest I/O: 0xFF 0x03
        //   Multidrop: 0x00
        //   Data length (2 LE): 4 (end_code 2 + data 2)
        //   End code (2 LE): 0x0000
        //   Word data (2 LE): 0x1234
        let response: &[u8] = &[
            0xD0, 0x00,        // subheader
            0xFF, 0xFF,        // network/PC
            0xFF, 0x03,        // I/O
            0x00,              // multidrop
            0x04, 0x00,        // data_len = 4
            0x00, 0x00,        // end_code = 0
            0x34, 0x12,        // word D0 = 0x1234
        ];
        let _ = s.write_all(response);
    }
}

#[test]
fn loopback_slmp_read_word_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_slmp(listener));
    thread::sleep(Duration::from_millis(50));

    let result =
        scadaver::vendors::mitsubishi::slmp::read_word_devices("127.0.0.1", port, "D", 0, 1);
    assert!(result.is_ok(), "SLMP word read should succeed: {:?}", result.err());
    let words = result.unwrap();
    assert_eq!(words.len(), 1);
    assert_eq!(words[0].raw, 0x1234);
    assert_eq!(words[0].display, "D0");
}
