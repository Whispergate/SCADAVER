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

// U-frame control field values (IEC 60870-5-104:2006 Table 5, sec 8.3).
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
    pub decoded: String,
}

/// Byte width of the information element for a given `TypeID` (not counting the 3-byte IOA).
fn ie_size(type_id: u8) -> usize {
    match type_id {
        2 => 4,             // M_SP_TA_1: SPI(1) + CP24Time2a(3)
        5 => 2,             // M_ST_NA_1: VTI + QDS
        7 | 13 => 5,        // M_BO_NA_1: BSI(4)+QDS(1) / M_ME_NC_1: R32.23(4)+QDS(1)
        9 | 11 => 3,        // M_ME_NA_1 / M_ME_NB_1: value(2) + QDS(1)
        30 | 31 => 8,       // *_TB_1: IE(1) + CP56Time2a(7)
        34 | 35 => 10,      // M_ME_TD_1 / M_ME_TE_1: value(2) + QDS(1) + CP56Time2a(7)
        36 | 37 => 12,      // M_ME_TF_1: R32.23(4)+QDS(1)+CP56(7) / M_IT_TB_1: BCR(5)+CP56(7)
        _ => 1,             // M_SP_NA_1, M_DP_NA_1, C_SC_NA_1, C_IC_NA_1 and unknowns
    }
}

/// Human-readable value decoded from the information element bytes.
/// Parse a 7-byte `CP56Time2a` timestamp into "YYYY-MM-DDTHH:MM:SS.mmm".
fn decode_cp56time2a(t: &[u8]) -> Option<String> {
    if t.len() < 7 {
        return None;
    }
    let ms_total = u16::from_le_bytes([t[0], t[1]]);
    let secs = ms_total / 1000;
    let ms_rem = ms_total % 1000;
    let minutes = t[2] & 0x3F;
    let hours = t[3] & 0x1F;
    let day = t[4] & 0x1F;
    let month = t[5] & 0x0F;
    let year = u16::from(t[6] & 0x7F) + 2000;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{secs:02}.{ms_rem:03}"
    ))
}

fn decode_ie(type_id: u8, bytes: &[u8]) -> String {
    match type_id {
        1 | 2 => {
            // M_SP_NA_1 / M_SP_TA_1: SPI = bit 0 (no timestamp)
            match bytes.first().map(|b| b & 0x01) {
                Some(1) => "ON".to_string(),
                Some(_) => "OFF".to_string(),
                None => "?".to_string(),
            }
        }
        30 => {
            // M_SP_TB_1: SPI = bit 0, then CP56Time2a (7 bytes)
            let state = match bytes.first().map(|b| b & 0x01) {
                Some(1) => "ON",
                Some(_) => "OFF",
                None => return "?".to_string(),
            };
            let ts = bytes.get(1..).and_then(decode_cp56time2a)
                .map_or_else(String::new, |t| format!(" t={t}"));
            format!("{state}{ts}")
        }
        3 => {
            // M_DP_NA_1: DPI = bits 1-0 (no timestamp)
            match bytes.first().map(|b| b & 0x03) {
                Some(1) => "OFF".to_string(),
                Some(2) => "ON".to_string(),
                _ => "indeterminate".to_string(),
            }
        }
        31 => {
            // M_DP_TB_1: DPI = bits 1-0, then CP56Time2a (7 bytes)
            let state = match bytes.first().map(|b| b & 0x03) {
                Some(1) => "OFF",
                Some(2) => "ON",
                _ => "indeterminate",
            };
            let ts = bytes.get(1..).and_then(decode_cp56time2a)
                .map_or_else(String::new, |t| format!(" t={t}"));
            format!("{state}{ts}")
        }
        5 => {
            // M_ST_NA_1: step position in bits 0-6 (signed 7-bit, -64..+63)
            if bytes.is_empty() { return "?".to_string(); }
            let raw = i32::from(bytes[0] & 0x7F);
            let vti = if raw > 63 { raw - 128 } else { raw };
            format!("{vti}")
        }
        7 => {
            // M_BO_NA_1: 32-bit bitstring
            if bytes.len() < 4 { return "?".to_string(); }
            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("0x{v:08x}")
        }
        9 | 34 => {
            // M_ME_NA_1 / M_ME_TD_1: normalized value: range -1.0..+1.0
            if bytes.len() < 2 { return "?".to_string(); }
            let raw = i16::from_le_bytes([bytes[0], bytes[1]]);
            format!("{:.4}", f64::from(raw) / 32_767.0)
        }
        11 | 35 => {
            // M_ME_NB_1 / M_ME_TE_1: scaled signed 16-bit integer
            if bytes.len() < 2 { return "?".to_string(); }
            format!("{}", i16::from_le_bytes([bytes[0], bytes[1]]))
        }
        37 => {
            // M_IT_TB_1: 32-bit binary counter reading + sequence byte
            if bytes.len() < 4 { return "?".to_string(); }
            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{v}")
        }
        13 => {
            // M_ME_NC_1: IEEE 754 short float (no timestamp)
            if bytes.len() < 4 { return "?".to_string(); }
            let f = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{f:.4}")
        }
        36 => {
            // M_ME_TF_1: IEEE 754 short float + QDS(1) + CP56Time2a(7)
            if bytes.len() < 4 { return "?".to_string(); }
            let f = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let ts = bytes.get(5..).and_then(decode_cp56time2a)
                .map_or_else(String::new, |t| format!(" t={t}"));
            format!("{f:.4}{ts}")
        }
        100 => {
            // C_IC_NA_1: QOI qualifier
            format!("QOI={}", bytes.first().copied().unwrap_or(0))
        }
        45 => {
            // C_SC_NA_1: single command SCO: bit 0
            match bytes.first().map(|b| b & 0x01) {
                Some(1) => "ON".to_string(),
                Some(_) => "OFF".to_string(),
                None => "?".to_string(),
            }
        }
        _ => bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
    }
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

    fn shutdown(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
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
    let confirmed = session.recv()
        .is_ok_and(|r| r.len() >= 4 && r[0..4] == TESTFR_CON);
    session.shutdown();
    confirmed
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

/// Send General Interrogation and collect all returned data objects.
///
/// GI produces a burst: activation confirmation (COT=7, TypeID=100), then N data
/// I-frames, then activation termination (COT=10, TypeID=100). Reading only the
/// first frame yields only the confirmation with no measurements. This loops
/// until the termination frame or a recv timeout.
pub fn general_interrogation(session: &mut Iec104Session) -> Result<Vec<DataObject>> {
    let asdu = gi_asdu(session.asdu_addr);
    let frame = session.apdu_iframe(&asdu);
    session.send(&frame)?;
    session.tx_seq = session.tx_seq.wrapping_add(1);

    let mut objects = Vec::new();
    loop {
        let Ok(resp) = session.recv() else { break }; // timeout or peer closed
        parse_response_objects(&resp, &mut objects);
        // Termination: TypeID=100 (C_IC_NA_1), COT bits 5-0 = 10 (ActivationTermination)
        if resp.len() >= 7 && resp[4] == 100 && (resp[6] & 0x3F) == 10 {
            break;
        }
    }
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
    let sz = ie_size(type_id);
    if sq {
        // Sequence: one base IOA, then N information elements packed back-to-back.
        if data.len() < 3 {
            return;
        }
        let ioa_base = u32::from_le_bytes([data[0], data[1], data[2], 0]);
        let mut offset = 3;
        for i in 0..num {
            let ioa = ioa_base + u32::try_from(i).unwrap_or(u32::MAX);
            if offset + sz > data.len() {
                break;
            }
            let value = data[offset..offset + sz].to_vec();
            let decoded = decode_ie(type_id, &value);
            out.push(DataObject { ioa, type_id, value, decoded });
            offset += sz;
        }
    } else {
        // Non-sequence: each object carries its own 3-byte IOA.
        let mut offset = 0;
        for _ in 0..num {
            if offset + 3 + sz > data.len() {
                break;
            }
            let ioa = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]);
            let value = data[offset + 3..offset + 3 + sz].to_vec();
            let decoded = decode_ie(type_id, &value);
            out.push(DataObject { ioa, type_id, value, decoded });
            offset += 3 + sz;
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
    fn ie_size_timestamped_variants_return_correct_width() {
        assert_eq!(ie_size(2), 4);   // M_SP_TA_1: SPI + CP24Time2a
        assert_eq!(ie_size(34), 10); // M_ME_TD_1: NVA + QDS + CP56Time2a
        assert_eq!(ie_size(35), 10); // M_ME_TE_1: SVA + QDS + CP56Time2a
        assert_eq!(ie_size(37), 12); // M_IT_TB_1: BCR + CP56Time2a
    }

    #[test]
    fn parse_type9_normalized_value_decoded() {
        // Non-sequence M_ME_NA_1 (type 9): IOA=5, value=0x4000 (i16=16384), QDS=0
        // ie_size(9)=3: 2 bytes value + 1 byte QDS
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x09,                   // type_id = 9
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x05, 0x00, 0x00,       // IOA = 5
            0x00, 0x40,             // NVA = 0x4000 = 16384 → 16384/32767 ≈ 0.5000
            0x00,                   // QDS
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 5);
        assert_eq!(out[0].type_id, 9);
        assert!(out[0].decoded.starts_with("0.5"), "got: {}", out[0].decoded);
    }

    #[test]
    fn parse_type11_scaled_value_decoded() {
        // Non-sequence M_ME_NB_1 (type 11): IOA=10, SVA=-100 (0xFF9C little-endian), QDS=0
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x0B,                   // type_id = 11
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x0A, 0x00, 0x00,       // IOA = 10
            0x9C, 0xFF,             // SVA = -100 little-endian
            0x00,                   // QDS
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 10);
        assert_eq!(out[0].decoded, "-100");
    }

    #[test]
    fn parse_type13_float_value_decoded() {
        // Non-sequence M_ME_NC_1 (type 13): IOA=1, f32=1.0 (0x3F800000 LE), QDS=0
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x0D,                   // type_id = 13
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x01, 0x00, 0x00,       // IOA = 1
            0x00, 0x00, 0x80, 0x3F, // f32 = 1.0 little-endian
            0x00,                   // QDS
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 1);
        assert_eq!(out[0].decoded, "1.0000");
    }

    #[test]
    fn parse_type2_timestamped_single_point_decoded() {
        // Non-sequence M_SP_TA_1 (type 2): IOA=3, SPI=1 (ON), 3 bytes CP24Time2a
        // ie_size(2)=4: SPI(1) + CP24Time2a(3)
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x02,                   // type_id = 2
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x03, 0x00, 0x00,       // IOA = 3
            0x01,                   // SPI = 1 (ON)
            0xAA, 0xBB, 0xCC,       // CP24Time2a (ignored for now)
        ];
        let mut out = vec![];
        parse_response_objects(frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 3);
        assert_eq!(out[0].type_id, 2);
        assert_eq!(out[0].decoded, "ON");
    }

    #[test]
    fn parse_type37_counter_decoded() {
        // Non-sequence M_IT_TB_1 (type 37): IOA=7, counter=1000, seqbyte=0, CP56Time2a=7bytes
        // ie_size(37)=12: BCR(5) + CP56Time2a(7)
        let counter: u32 = 1000;
        let mut frame = vec![
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x25,                   // type_id = 37
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x07, 0x00, 0x00,       // IOA = 7
        ];
        frame.extend_from_slice(&counter.to_le_bytes()); // BCR counter bytes
        frame.push(0x00); // BCR sequence byte
        frame.extend_from_slice(&[0x00u8; 7]); // CP56Time2a placeholder
        let mut out = vec![];
        parse_response_objects(&frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 7);
        assert_eq!(out[0].type_id, 37);
        assert_eq!(out[0].decoded, "1000");
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

    // CP56Time2a timestamp: 2026-08-04T14:30:05.500
    // ms_total=5500 → [0x7C, 0x15], minutes=30 → 0x1E, hours=14 → 0x0E,
    // day=4 → 0x04, month=8 → 0x08, year-2000=26 → 0x1A
    const TS: [u8; 7] = [0x7C, 0x15, 0x1E, 0x0E, 0x04, 0x08, 0x1A];
    const TS_STR: &str = "2026-08-04T14:30:05.500";

    #[test]
    fn parse_type30_single_point_with_timestamp() {
        // M_SP_TB_1 (type 30): SPI=1 (ON), then CP56Time2a. ie_size(30)=8.
        let mut frame = vec![
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x1E,                   // type_id = 30
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x01, 0x00, 0x00,       // IOA = 1
            0x01,                   // SPI = ON
        ];
        frame.extend_from_slice(&TS);
        let mut out = vec![];
        parse_response_objects(&frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 1);
        assert_eq!(out[0].decoded, format!("ON t={TS_STR}"));
    }

    #[test]
    fn parse_type31_double_point_with_timestamp() {
        // M_DP_TB_1 (type 31): DPI=2 (ON), then CP56Time2a. ie_size(31)=8.
        let mut frame = vec![
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x1F,                   // type_id = 31
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x02, 0x00, 0x00,       // IOA = 2
            0x02,                   // DPI = ON (state 2)
        ];
        frame.extend_from_slice(&TS);
        let mut out = vec![];
        parse_response_objects(&frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 2);
        assert_eq!(out[0].decoded, format!("ON t={TS_STR}"));
    }

    #[test]
    fn parse_type36_float_with_timestamp() {
        // M_ME_TF_1 (type 36): f32=1.5 LE, QDS=0, then CP56Time2a. ie_size(36)=12.
        let mut frame = vec![
            0x00, 0x00, 0x00, 0x00, // ctrl
            0x24,                   // type_id = 36
            0x01,                   // vsq: 1 object
            0x00, 0x00,             // COT
            0x01, 0x00,             // ASDU addr
            0x03, 0x00, 0x00,       // IOA = 3
            0x00, 0x00, 0xC0, 0x3F, // f32 = 1.5 LE
            0x00,                   // QDS
        ];
        frame.extend_from_slice(&TS);
        let mut out = vec![];
        parse_response_objects(&frame, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ioa, 3);
        assert_eq!(out[0].decoded, format!("1.5000 t={TS_STR}"));
    }
}
