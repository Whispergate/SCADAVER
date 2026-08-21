// Modbus TCP loopback integration tests.
// In-process mock handles FC 01 (coils) and FC 03 (holding registers).
// No external simulator or env vars required — always runs.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use scadaver::core::modbus::{read_holding_registers, read_coils, DEFAULT_PORT};

// Build a Modbus TCP response frame.
// MBAP length field = unit_id(1) + fc(1) + pdu_data.len()
fn mbap_response(tx_id: [u8; 2], unit_id: u8, fc: u8, pdu_data: &[u8]) -> Vec<u8> {
    let length = (2 + pdu_data.len()) as u16;
    let mut frame = vec![
        tx_id[0], tx_id[1],
        0x00, 0x00,
        (length >> 8) as u8, (length & 0xFF) as u8,
        unit_id,
        fc,
    ];
    frame.extend_from_slice(pdu_data);
    frame
}

fn serve_one_modbus_request(listener: TcpListener) {
    let Ok((mut s, _)) = listener.accept() else { return };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));

    // Read 7-byte MBAP header
    let mut header = [0u8; 7];
    if s.read_exact(&mut header).is_err() { return; }

    let resp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if resp_len < 2 { return; }

    // Read PDU (resp_len - 1 bytes, since unit_id already read in header)
    let mut pdu = vec![0u8; resp_len - 1];
    if s.read_exact(&mut pdu).is_err() { return; }

    let tx_id = [header[0], header[1]];
    let unit_id = header[6];
    let fc = pdu[0];

    // Count is at pdu[3..5] (= request bytes: fc[0], start_hi[1], start_lo[2], count_hi[3], count_lo[4])
    let count = if pdu.len() >= 5 {
        u16::from_be_bytes([pdu[3], pdu[4]])
    } else {
        1
    };

    let response = match fc {
        0x01 | 0x02 => {
            // Coils / discrete inputs: byte_count + packed bits (all ON)
            let byte_count = ((count as usize) + 7) / 8;
            let mut pdu_data = vec![byte_count as u8];
            pdu_data.extend(vec![0xFF_u8; byte_count]);
            mbap_response(tx_id, unit_id, fc, &pdu_data)
        }
        0x03 | 0x04 => {
            // Holding / input registers: byte_count + register values (value = index)
            let byte_count = count as usize * 2;
            let mut pdu_data = vec![byte_count as u8];
            for i in 0..count {
                pdu_data.push((i >> 8) as u8);
                pdu_data.push((i & 0xFF) as u8);
            }
            mbap_response(tx_id, unit_id, fc, &pdu_data)
        }
        _ => return,
    };
    let _ = s.write_all(&response);
}

#[test]
fn modbus_default_port_constant() {
    assert_eq!(DEFAULT_PORT, 502, "Modbus default TCP port must be 502");
}

#[test]
fn loopback_modbus_read_holding_registers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_one_modbus_request(listener));
    thread::sleep(Duration::from_millis(50));

    let result = read_holding_registers("127.0.0.1", port, 0, 10);
    assert!(result.is_ok(), "FC 03 should succeed against loopback: {:?}", result.err());
    let regs = result.unwrap();
    assert_eq!(regs.len(), 10, "should return 10 registers");
    assert_eq!(regs[0].address, 0);
    assert_eq!(regs[1].raw, 1);
}

#[test]
fn loopback_modbus_read_coils() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_one_modbus_request(listener));
    thread::sleep(Duration::from_millis(50));

    let result = read_coils("127.0.0.1", port, 0, 8);
    assert!(result.is_ok(), "FC 01 should succeed against loopback: {:?}", result.err());
    let coils = result.unwrap();
    assert_eq!(coils.len(), 8, "should return 8 coil bits");
    assert_eq!(coils[0].value_str, "ON", "all coils should be ON (0xFF mock data)");
}

#[test]
fn live_modbus_read_device_id_runs_without_panic() {
    let Some(host) = std::env::var("TEST_MODBUS_HOST").ok() else { return };
    let port: u16 = std::env::var("TEST_MODBUS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let client = scadaver::core::modbus::ModbusTcpClient::new(&host).with_port(port);
    // FC 0x2B may return a Modbus exception — that's a valid response, not a test failure.
    let _ = client.read_device_id();
}
