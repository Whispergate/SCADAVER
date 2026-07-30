/// IEC 60870-5-104 (IEC 104) protocol client.
///
/// Implements the Application Protocol Control Interface (APCI) framing used
/// by most ICS SCADA master stations. Port 2404.
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default TCP port for IEC 60870-5-104.
pub const IEC104_PORT: u16 = 2404;
const TIMEOUT: Duration = Duration::from_secs(5);

// U-frame control field values
const STARTDT_ACT: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
const STARTDT_CON: [u8; 4] = [0x0B, 0x00, 0x00, 0x00];
const TESTFR_ACT: [u8; 4] = [0x43, 0x00, 0x00, 0x00];
const TESTFR_CON: [u8; 4] = [0x83, 0x00, 0x00, 0x00];

/// A decoded IEC 104 data object from a General Interrogation response.
#[derive(Debug, Clone)]
pub struct DataObject {
    pub ioa: u32,
    pub type_id: u8,
    pub value: Vec<u8>,
}

/// An active IEC 104 session with sequence number tracking.
pub struct Iec104Session {
    pub asdu_addr: u16,
    stream: TcpStream,
    tx_seq: u16, // send sequence number (increments by 1 per I-frame sent)
    rx_seq: u16, // receive sequence number (increments by 1 per I-frame received)
}

impl Iec104Session {
    fn apdu_uframe(ctrl: [u8; 4]) -> [u8; 6] {
        [0x68, 0x04, ctrl[0], ctrl[1], ctrl[2], ctrl[3]]
    }

    fn apdu_iframe(&self, asdu: &[u8]) -> Vec<u8> {
        let tx = self.tx_seq << 1; // bit 0 = 0 for I-frame
        let rx = self.rx_seq << 1;
        // APDU length field is 1 byte; control fields are 4 bytes.
        // Max payload is 255 - 4 = 251 bytes per IEC 60870-5-104 §5.1.
        let len = u8::try_from(asdu.len() + 4).unwrap_or(u8::MAX);
        let mut frame = vec![
            0x68,
            len,
            (tx & 0xFF) as u8,
            (tx >> 8) as u8,
            (rx & 0xFF) as u8,
            (rx >> 8) as u8,
        ];
        frame.extend_from_slice(asdu);
        frame
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.stream.write_all(frame).context("IEC104: send failed")
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).context("IEC104: recv header")?;
        if header[0] != 0x68 {
            anyhow::bail!("IEC104: unexpected start byte 0x{:02x}", header[0]);
        }
        let len = header[1] as usize;
        let mut rest = vec![0u8; len];
        self.stream.read_exact(&mut rest).context("IEC104: recv body")?;
        // Track incoming sequence numbers for I-frames
        if rest.len() >= 4 && (rest[0] & 0x01) == 0 {
            // I-frame: update rx_seq
            let incoming_tx = u16::from_le_bytes([rest[0], rest[1]]) >> 1;
            self.rx_seq = incoming_tx.wrapping_add(1);
        }
        Ok(rest)
    }

    fn send_iframe(&mut self, asdu: &[u8]) -> Result<Vec<u8>> {
        let frame = self.apdu_iframe(asdu);
        self.send(&frame)?;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        self.recv()
    }
}

/// Connect to an IEC 104 outstation, send STARTDT, and confirm the data transfer phase.
/// Returns a session that can issue commands. Pass `port = 0` to use the default (2404).
pub fn connect(ip: &str, port: u16) -> Result<Iec104Session> {
    let effective_port = if port == 0 { IEC104_PORT } else { port };
    let addr = format!("{ip}:{effective_port}");
    let stream = TcpStream::connect_timeout(&addr.parse()?, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;

    let mut session = Iec104Session {
        asdu_addr: 1,
        stream,
        tx_seq: 0,
        rx_seq: 0,
    };

    // Send STARTDT act, expect STARTDT con
    let startdt = Iec104Session::apdu_uframe(STARTDT_ACT);
    session.send(&startdt)?;
    let resp = session.recv()?;
    if resp.len() < 4 || resp[0..4] != STARTDT_CON {
        anyhow::bail!("IEC104: STARTDT not confirmed (got {:?})", &resp[..resp.len().min(4)]);
    }

    Ok(session)
}

/// Probe an IP for an IEC 104 outstation using TESTFR. Pass `port = 0` for the default (2404).
pub fn probe(ip: &str, port: u16) -> bool {
    let effective_port = if port == 0 { IEC104_PORT } else { port };
    let Ok(addr) = format!("{ip}:{effective_port}").parse() else { return false };
    let Ok(stream) = TcpStream::connect_timeout(&addr, TIMEOUT) else { return false };
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    let mut session = Iec104Session {
        asdu_addr: 0,
        stream,
        tx_seq: 0,
        rx_seq: 0,
    };
    let testfr = Iec104Session::apdu_uframe(TESTFR_ACT);
    if session.send(&testfr).is_err() {
        return false;
    }
    session.recv()
        .is_ok_and(|r| r.len() >= 4 && r[0..4] == TESTFR_CON)
}

/// Build an ASDU for General Interrogation (`C_IC_NA_1`, TypeID=100).
fn gi_asdu(asdu_addr: u16) -> Vec<u8> {
    vec![
        100,                          // TypeID: C_IC_NA_1
        0x01,                         // VSQ: 1 object, not sequence
        0x06, 0x00,                   // COT: Activation (6), P/N=0
        (asdu_addr & 0xFF) as u8,     // ASDU address low
        (asdu_addr >> 8) as u8,       // ASDU address high
        0x00, 0x00, 0x00,             // IOA = 0
        0x14,                         // QOI: station interrogation
    ]
}

/// Build an ASDU for Single Command (`C_SC_NA_1`, TypeID=45).
fn single_cmd_asdu(asdu_addr: u16, ioa: u32, on: bool) -> Vec<u8> {
    let sco: u8 = u8::from(on); // 1=ON, 0=OFF (no qualifier bits)
    vec![
        45,                           // TypeID: C_SC_NA_1
        0x01,                         // VSQ
        0x06, 0x00,                   // COT: Activation
        (asdu_addr & 0xFF) as u8,
        (asdu_addr >> 8) as u8,
        (ioa & 0xFF) as u8,
        ((ioa >> 8) & 0xFF) as u8,
        ((ioa >> 16) & 0xFF) as u8,
        sco,
    ]
}

/// Build an ASDU for Double Command (`C_DC_NA_1`, TypeID=46).
fn double_cmd_asdu(asdu_addr: u16, ioa: u32, state: u8) -> Vec<u8> {
    vec![
        46,                           // TypeID: C_DC_NA_1
        0x01,
        0x06, 0x00,
        (asdu_addr & 0xFF) as u8,
        (asdu_addr >> 8) as u8,
        (ioa & 0xFF) as u8,
        ((ioa >> 8) & 0xFF) as u8,
        ((ioa >> 16) & 0xFF) as u8,
        state & 0x03,                 // 1=off, 2=on, 3=indeterminate
    ]
}

/// Send General Interrogation and collect returned data objects.
pub fn general_interrogation(session: &mut Iec104Session) -> Result<Vec<DataObject>> {
    let asdu = gi_asdu(session.asdu_addr);
    let resp = session.send_iframe(&asdu)?;
    let mut objects = Vec::new();
    parse_response_objects(&resp, &mut objects);
    Ok(objects)
}

/// Send Single Command (`C_SC_NA_1`) to set output IOA on/off.
pub fn single_command(session: &mut Iec104Session, ioa: u32, on: bool) -> Result<bool> {
    let asdu = single_cmd_asdu(session.asdu_addr, ioa, on);
    let resp = session.send_iframe(&asdu)?;
    // recv() returns ctrl(4) + ASDU. ASDU: TypeID[4] VSQ[5] COT_lo[6] COT_hi[7] ...
    // COT bits 0-5 = cause (7 = ActCon = Activation confirmation)
    // COT bit 6 = P/N (0 = positive confirm)
    Ok(resp.len() >= 7 && (resp[6] & 0x3F) == 0x07 && (resp[6] & 0x40) == 0)
}

/// Send Double Command (`C_DC_NA_1`). state: 1=off, 2=on, 3=indeterminate.
pub fn double_command(session: &mut Iec104Session, ioa: u32, state: u8) -> Result<bool> {
    let asdu = double_cmd_asdu(session.asdu_addr, ioa, state);
    let resp = session.send_iframe(&asdu)?;
    Ok(resp.len() >= 7 && (resp[6] & 0x3F) == 0x07 && (resp[6] & 0x40) == 0)
}

fn parse_response_objects(frame: &[u8], out: &mut Vec<DataObject>) {
    // frame starts after APCI: ctrl_hi, ctrl_lo, rx_hi, rx_lo, then ASDU
    if frame.len() < 10 {
        return;
    }
    let asdu = &frame[4..]; // skip 4-byte control field
    if asdu.len() < 6 {
        return;
    }
    let type_id = asdu[0];
    let vsq = asdu[1];
    let sq = (vsq & 0x80) != 0;
    let num = (vsq & 0x7F) as usize;
    // ASDU: type(1) + vsq(1) + cot(2) + addr(2) + objects
    let data = &asdu[6..];
    if sq {
        // Sequence: first object has 3-byte IOA, rest share the base
        if data.len() < 3 {
            return;
        }
        let ioa_base = u32::from_le_bytes([data[0], data[1], data[2], 0]);
        for (offset, i) in (3_usize..).zip(0_usize..num) {
            let ioa = ioa_base + u32::try_from(i).unwrap_or(u32::MAX);
            if offset >= data.len() {
                break;
            }
            out.push(DataObject { ioa, type_id, value: vec![data[offset]] });
        }
    } else {
        // Non-sequence: each object has its own 3-byte IOA
        let mut offset = 0;
        for _ in 0..num {
            if offset + 4 > data.len() {
                break;
            }
            let ioa = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]);
            let value = vec![data[offset + 3]];
            out.push(DataObject { ioa, type_id, value });
            offset += 4;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_objects_empty_frame_yields_nothing() {
        let mut out = vec![];
        parse_response_objects(&[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_response_objects_nine_bytes_yields_nothing() {
        let mut out = vec![];
        parse_response_objects(&[0u8; 9], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_response_objects_num_one_but_empty_data_yields_nothing() {
        // frame.len()=10 passes the guard; vsq=1 means num=1 but data=[] → breaks
        let mut frame = vec![0u8; 10];
        frame[5] = 1; // vsq: num=1, not sequential
        let mut out = vec![];
        parse_response_objects(&frame, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn parse_response_objects_gi_actcon_adds_one_object() {
        // 14-byte payload returned by recv(): ctrl(4) + ASDU(10)
        // ASDU: C_IC_NA_1(0x64), vsq=1, COT=ActCon(7), addr=1, IOA=0, QOI=0x14
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00,  // I-frame control (tx=0, rx=0)
            0x64,                    // type_id = 100 (C_IC_NA_1)
            0x01,                    // vsq: 1 object, not sequential
            0x07, 0x00,              // COT: ActCon (7)
            0x01, 0x00,              // ASDU address = 1
            0x00, 0x00, 0x00,        // IOA = 0
            0x14,                    // QOI = 20 (station interrogation)
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].type_id, 0x64);
        assert_eq!(out[0].ioa, 0);
        assert_eq!(out[0].value, vec![0x14]);
    }

    #[test]
    fn parse_response_objects_sequence_flag_extracts_multi_ioa() {
        // sq=1 (vsq & 0x80), num=3, base IOA=1
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x01,                   // type_id = 1 (M_SP_NA_1)
            0x83,                   // vsq: seq=1, num=3
            0x0b, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x01, 0x00, 0x00,       // IOA base = 1
            0x01,                   // value[0]
            0x00,                   // value[1]
            0x01,                   // value[2]
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].ioa, 1);
        assert_eq!(out[1].ioa, 2);
        assert_eq!(out[2].ioa, 3);
        assert_eq!(out[0].type_id, 1);
    }
}
