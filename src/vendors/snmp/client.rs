use anyhow::{anyhow, bail, Result};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

pub const SNMP_PORT: u16 = 161;
const TIMEOUT: Duration = Duration::from_secs(4);
const MAX_WALK: usize = 512;
const BUF: usize = 65_535;
const VERSION_V2C: i64 = 1; // SNMPv2c wire version byte

static REQ_ID: AtomicU32 = AtomicU32::new(1);
fn next_id() -> u32 {
    REQ_ID.fetch_add(1, Ordering::Relaxed)
}

// ─── Value type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectId(Vec<u32>),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl SnmpValue {
    pub fn display(&self) -> String {
        match self {
            Self::Integer(n) => n.to_string(),
            Self::OctetString(b) => {
                if b.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
                    String::from_utf8_lossy(b).trim_matches('\0').trim().to_string()
                } else {
                    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
                }
            }
            Self::ObjectId(a) => arcs_to_str(a),
            Self::IpAddress(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Counter32(n) | Self::Gauge32(n) => n.to_string(),
            Self::TimeTicks(n) => format!("{n} ticks ({:.0}s)", f64::from(*n) / 100.0),
            Self::Counter64(n) => n.to_string(),
            Self::Null => "(null)".to_string(),
            Self::NoSuchObject => "(no such object)".to_string(),
            Self::NoSuchInstance => "(no such instance)".to_string(),
            Self::EndOfMibView => "(end of MIB)".to_string(),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            Self::Counter32(n) | Self::Gauge32(n) | Self::TimeTicks(n) => Some(i64::from(*n)),
            Self::Counter64(n) => Some(n.cast_signed()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Self::OctetString(b) = self { Some(b) } else { None }
    }
}

pub fn arcs_to_str(arcs: &[u32]) -> String {
    arcs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(".")
}

fn str_to_arcs(s: &str) -> Result<Vec<u32>> {
    s.trim_start_matches('.')
        .split('.')
        .map(|a| a.parse::<u32>().map_err(|_| anyhow!("bad OID arc: {a}")))
        .collect()
}

// ─── BER encoder ─────────────────────────────────────────────────────────────

fn ber_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![u8::try_from(len).unwrap_or(u8::MAX)]
    } else if len < 256 {
        vec![0x81, u8::try_from(len).unwrap_or(u8::MAX)]
    } else {
        // 2-byte BER length form; handles lengths up to 65535
        vec![0x82, u8::try_from(len >> 8).unwrap_or(u8::MAX), u8::try_from(len & 0xFF).unwrap_or(u8::MAX)]
    }
}

fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&ber_len(val.len()));
    out.extend_from_slice(val);
    out
}

fn enc_int(n: i64) -> Vec<u8> {
    use std::cmp::Ordering;
    let bytes = match n.cmp(&0) {
        Ordering::Equal => {
            vec![0x00u8]
        }
        Ordering::Greater => {
            let mut b = Vec::new();
            let mut v = n.cast_unsigned();
            while v > 0 {
                b.push((v & 0xFF) as u8);
                v >>= 8;
            }
            b.reverse();
            if b[0] & 0x80 != 0 {
                b.insert(0, 0x00);
            }
            b
        }
        Ordering::Less => {
            // n is negative: cast_unsigned gives the two's complement u64 bit pattern
            let mut v = n.cast_unsigned();
            let mut b = Vec::new();
            loop {
                b.push((v & 0xFF) as u8);
                v >>= 8;
                if v == 0 {
                    break;
                }
            }
            b.reverse();
            if b[0] & 0x80 == 0 {
                b.insert(0, 0xFF);
            }
            b
        }
    };
    tlv(0x02, &bytes)
}

fn enc_octet(s: &[u8]) -> Vec<u8> {
    tlv(0x04, s)
}

fn enc_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn enc_oid(arcs: &[u32]) -> Vec<u8> {
    if arcs.len() < 2 {
        return tlv(0x06, &[0]);
    }
    let first_byte = 40_u32.wrapping_mul(arcs[0]).wrapping_add(arcs[1]);
    let mut enc = vec![u8::try_from(first_byte).unwrap_or(u8::MAX)];
    for &arc in &arcs[2..] {
        arc_bytes(arc, &mut enc);
    }
    tlv(0x06, &enc)
}

fn arc_bytes(mut arc: u32, out: &mut Vec<u8>) {
    if arc == 0 {
        out.push(0);
        return;
    }
    let mut b: Vec<u8> = Vec::new();
    b.push((arc & 0x7F) as u8);
    arc >>= 7;
    while arc > 0 {
        b.push(0x80 | (arc & 0x7F) as u8);
        arc >>= 7;
    }
    b.reverse();
    out.extend_from_slice(&b);
}

fn build_pdu(pdu_tag: u8, community: &str, req_id: u32, oids: &[Vec<u32>], f2: i64, f3: i64) -> Vec<u8> {
    let mut vbl = Vec::new();
    for oid in oids {
        let mut vb = enc_oid(oid);
        vb.extend_from_slice(&enc_null());
        vbl.extend_from_slice(&tlv(0x30, &vb));
    }
    let mut pdu = enc_int(i64::from(req_id));
    pdu.extend_from_slice(&enc_int(f2));
    pdu.extend_from_slice(&enc_int(f3));
    pdu.extend_from_slice(&tlv(0x30, &vbl));
    let mut msg = enc_int(VERSION_V2C);
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&tlv(pdu_tag, &pdu));
    tlv(0x30, &msg)
}

fn build_set_pdu(community: &str, req_id: u32, oid: &[u32], value: &SnmpValue) -> Vec<u8> {
    let val_enc = match value {
        SnmpValue::Integer(n) => enc_int(*n),
        SnmpValue::OctetString(b) => enc_octet(b),
        SnmpValue::Counter32(n) => tlv(0x41, &n.to_be_bytes()),
        SnmpValue::Gauge32(n) => tlv(0x42, &n.to_be_bytes()),
        SnmpValue::TimeTicks(n) => tlv(0x43, &n.to_be_bytes()),
        SnmpValue::IpAddress(a) => tlv(0x40, a),
        _ => enc_null(),
    };
    let mut vb = enc_oid(oid);
    vb.extend_from_slice(&val_enc);
    let vbl = tlv(0x30, &tlv(0x30, &vb));
    let mut pdu = enc_int(i64::from(req_id));
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&vbl);
    let mut msg = enc_int(VERSION_V2C);
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&tlv(0xA3, &pdu));
    tlv(0x30, &msg)
}

// ─── BER decoder ─────────────────────────────────────────────────────────────

fn parse_len(buf: &[u8], pos: usize) -> Result<(usize, usize)> {
    let f = *buf.get(pos).ok_or_else(|| anyhow!("truncated length"))? as usize;
    if f < 0x80 {
        Ok((f, pos + 1))
    } else if f == 0x81 {
        Ok((*buf.get(pos + 1).ok_or_else(|| anyhow!("truncated 0x81"))? as usize, pos + 2))
    } else if f == 0x82 {
        let hi = *buf.get(pos + 1).ok_or_else(|| anyhow!("truncated 0x82"))? as usize;
        let lo = *buf.get(pos + 2).ok_or_else(|| anyhow!("truncated 0x82"))? as usize;
        Ok(((hi << 8) | lo, pos + 3))
    } else {
        bail!("unsupported BER length 0x{f:02x}")
    }
}

fn parse_tlv(buf: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
    let tag = *buf.get(pos).ok_or_else(|| anyhow!("buffer underflow at {pos}"))?;
    let (len, data_start) = parse_len(buf, pos + 1)?;
    let data_end = data_start + len;
    if data_end > buf.len() {
        bail!("TLV overflow: need {data_end} have {}", buf.len());
    }
    Ok((tag, data_start, data_end))
}

fn dec_int(buf: &[u8]) -> i64 {
    let mut n: i64 = if buf.first().is_some_and(|&b| b & 0x80 != 0) { -1 } else { 0 };
    for &b in buf {
        n = (n << 8) | i64::from(b);
    }
    n
}

fn dec_u32(buf: &[u8]) -> u32 {
    buf.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b))
}

fn dec_u64(buf: &[u8]) -> u64 {
    buf.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b))
}

fn dec_oid(buf: &[u8]) -> Vec<u32> {
    if buf.is_empty() {
        return vec![];
    }
    let first = u32::from(buf[0]);
    let mut arcs = vec![first / 40, first % 40];
    let mut i = 1;
    while i < buf.len() {
        let mut arc: u32 = 0;
        loop {
            let b = buf[i];
            i += 1;
            arc = (arc << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 || i >= buf.len() {
                break;
            }
        }
        arcs.push(arc);
    }
    arcs
}

fn parse_varbind(buf: &[u8], pos: usize) -> Result<((Vec<u32>, SnmpValue), usize)> {
    let (tag, start, end) = parse_tlv(buf, pos)?;
    if tag != 0x30 {
        bail!("expected VarBind SEQUENCE got 0x{tag:02x}");
    }
    let (oid_tag, os, oe) = parse_tlv(buf, start)?;
    if oid_tag != 0x06 {
        bail!("expected OID got 0x{oid_tag:02x}");
    }
    let oid = dec_oid(&buf[os..oe]);
    let (vt, vs, ve) = parse_tlv(buf, oe)?;
    let vb = &buf[vs..ve];
    let value = match vt {
        0x02 => SnmpValue::Integer(dec_int(vb)),
        0x05 => SnmpValue::Null,
        0x06 => SnmpValue::ObjectId(dec_oid(vb)),
        0x40 => {
            let mut a = [0u8; 4];
            let n = vb.len().min(4);
            a[..n].copy_from_slice(&vb[..n]);
            SnmpValue::IpAddress(a)
        }
        0x41 => SnmpValue::Counter32(dec_u32(vb)),
        0x42 => SnmpValue::Gauge32(dec_u32(vb)),
        0x43 => SnmpValue::TimeTicks(dec_u32(vb)),
        0x46 => SnmpValue::Counter64(dec_u64(vb)),
        0x80 => SnmpValue::NoSuchObject,
        0x81 => SnmpValue::NoSuchInstance,
        0x82 => SnmpValue::EndOfMibView,
        // 0x04 (OCTET STRING) and all unknown types default to OctetString
        _ => SnmpValue::OctetString(vb.to_vec()),
    };
    Ok(((oid, value), end))
}

fn parse_response(buf: &[u8]) -> Result<Vec<(Vec<u32>, SnmpValue)>> {
    let (_tag, outer_start, _) = parse_tlv(buf, 0)?;
    let (_, _, ver_end) = parse_tlv(buf, outer_start)?;
    let (_, _, comm_end) = parse_tlv(buf, ver_end)?;
    let (pdu_tag, pdu_start, _) = parse_tlv(buf, comm_end)?;
    if pdu_tag != 0xA2 {
        bail!("expected GetResponse 0xA2 got 0x{pdu_tag:02x}");
    }
    let (_, _, rid_end) = parse_tlv(buf, pdu_start)?;
    let (_, es, ee) = parse_tlv(buf, rid_end)?;
    let error_status = dec_int(&buf[es..ee]);
    let (_, _, ei_end) = parse_tlv(buf, ee)?;
    let (_, vbl_start, vbl_end) = parse_tlv(buf, ei_end)?;

    if error_status != 0 {
        return Ok(vec![]);
    }
    let mut results = Vec::new();
    let mut pos = vbl_start;
    while pos < vbl_end {
        let ((oid, val), next) = parse_varbind(buf, pos)?;
        results.push((oid, val));
        pos = next;
    }
    Ok(results)
}

// ─── Transport ───────────────────────────────────────────────────────────────

fn open_sock(ip: &str, port: u16) -> Result<UdpSocket> {
    let p = if port == 0 { SNMP_PORT } else { port };
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.connect(format!("{ip}:{p}"))?;
    Ok(sock)
}

fn exchange(sock: &UdpSocket, msg: &[u8]) -> Result<Vec<u8>> {
    sock.send(msg)?;
    let mut buf = vec![0u8; BUF];
    let n = sock.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// GET a single scalar OID.
pub fn get(ip: &str, port: u16, community: &str, oid: &str) -> Result<SnmpValue> {
    let arcs = str_to_arcs(oid)?;
    let sock = open_sock(ip, port)?;
    let pkt = build_pdu(0xA0, community, next_id(), &[arcs], 0, 0);
    let resp = exchange(&sock, &pkt)?;
    parse_response(&resp)?
        .into_iter()
        .next()
        .map(|(_, v)| v)
        .ok_or_else(|| anyhow!("empty GET response"))
}

/// GET multiple OIDs in one request; returns (`oid_string`, value) pairs.
pub fn get_multi(ip: &str, port: u16, community: &str, oids: &[&str]) -> Result<Vec<(String, SnmpValue)>> {
    let arcs_list: Vec<Vec<u32>> = oids.iter().map(|o| str_to_arcs(o)).collect::<Result<_>>()?;
    let sock = open_sock(ip, port)?;
    let pkt = build_pdu(0xA0, community, next_id(), &arcs_list, 0, 0);
    let resp = exchange(&sock, &pkt)?;
    Ok(parse_response(&resp)?
        .into_iter()
        .map(|(oid, v)| (arcs_to_str(&oid), v))
        .collect())
}

/// Walk an OID subtree using repeated GETNEXT.
pub fn walk(ip: &str, port: u16, community: &str, root_oid: &str) -> Result<Vec<(String, SnmpValue)>> {
    let root = str_to_arcs(root_oid)?;
    let sock = open_sock(ip, port)?;
    let mut results = Vec::new();
    let mut cur = root.clone();

    for _ in 0..MAX_WALK {
        let pkt = build_pdu(0xA1, community, next_id(), &[cur.clone()], 0, 0);
        let Ok(resp) = exchange(&sock, &pkt) else { break };
        let Ok(items) = parse_response(&resp) else { break };
        let Some((oid, val)) = items.into_iter().next() else { break };
        if oid.len() < root.len() || oid[..root.len()] != root[..] {
            break;
        }
        if matches!(val, SnmpValue::EndOfMibView | SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance) {
            break;
        }
        if oid <= cur {
            break;
        }
        cur.clone_from(&oid);
        results.push((arcs_to_str(&oid), val));
    }
    Ok(results)
}

/// SET a single OID value. Requires a write community string.
pub fn set(ip: &str, port: u16, community: &str, oid: &str, value: &SnmpValue) -> Result<SnmpValue> {
    let arcs = str_to_arcs(oid)?;
    let sock = open_sock(ip, port)?;
    let pkt = build_set_pdu(community, next_id(), &arcs, value);
    let resp = exchange(&sock, &pkt)?;
    parse_response(&resp)?
        .into_iter()
        .next()
        .map(|(_, v)| v)
        .ok_or_else(|| anyhow!("empty SET response"))
}

/// Try common community strings, return the first that works.
pub fn discover_community(ip: &str, port: u16) -> Option<String> {
    for &c in crate::vendors::snmp::oids::COMMON_COMMUNITIES {
        if get(ip, port, c, crate::vendors::snmp::oids::SYS_DESCR).is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{dec_int, dec_oid, parse_response, SnmpValue};

    // ── dec_int ───────────────────────────────────────────────────────────────

    #[test]
    fn dec_int_empty_is_zero() {
        assert_eq!(dec_int(&[]), 0);
    }

    #[test]
    fn dec_int_zero() {
        assert_eq!(dec_int(&[0x00]), 0);
    }

    #[test]
    fn dec_int_one() {
        assert_eq!(dec_int(&[0x01]), 1);
    }

    #[test]
    fn dec_int_neg1_single_byte() {
        assert_eq!(dec_int(&[0xFF]), -1);
    }

    #[test]
    fn dec_int_pos127() {
        assert_eq!(dec_int(&[0x7F]), 127);
    }

    #[test]
    fn dec_int_pos255_two_bytes() {
        // 0x00 prefix prevents sign extension; value = 255
        assert_eq!(dec_int(&[0x00, 0xFF]), 255);
    }

    #[test]
    fn dec_int_pos256() {
        assert_eq!(dec_int(&[0x01, 0x00]), 256);
    }

    #[test]
    fn dec_int_neg128() {
        // 0xFF sign-extends then 0x80 gives -128
        assert_eq!(dec_int(&[0xFF, 0x80]), -128);
    }

    // ── dec_oid ───────────────────────────────────────────────────────────────

    #[test]
    fn dec_oid_empty_returns_empty() {
        assert_eq!(dec_oid(&[]), Vec::<u32>::new());
    }

    #[test]
    fn dec_oid_iso_org() {
        // 0x2B = 43 = 40*1 + 3 → [1, 3]
        assert_eq!(dec_oid(&[0x2B]), vec![1u32, 3]);
    }

    #[test]
    fn dec_oid_sysdescr_oid() {
        let buf: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        assert_eq!(dec_oid(buf), vec![1u32, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn dec_oid_multi_byte_arc() {
        // [0x00, 0x81, 0x00]: arcs [0,0], then (1<<7)|0 = 128
        assert_eq!(dec_oid(&[0x00, 0x81, 0x00]), vec![0u32, 0, 128]);
    }

    #[test]
    fn dec_oid_enterprises_prefix() {
        // [0x2B, 0x86, 0x48]: [1,3], then (6<<7)|72 = 840
        assert_eq!(dec_oid(&[0x2B, 0x86, 0x48]), vec![1u32, 3, 840]);
    }

    // ── parse_response ────────────────────────────────────────────────────────

    // Hand-crafted 49-byte SNMPv2c GetResponse for sysDescr.0 = "Linux x86".
    // Lengths verified: VarBind=21, VarBindList=23, PDU=34, SEQUENCE=47.
    #[rustfmt::skip]
    const SYSDESCR_RESPONSE: &[u8] = &[
        0x30, 0x2f,                                           // SEQUENCE len=47
        0x02, 0x01, 0x01,                                     // INTEGER 1 (SNMPv2c)
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',      // OCTET_STRING "public"
        0xa2, 0x22,                                           // GetResponse-PDU len=34
        0x02, 0x01, 0x01,                                     // req-id=1
        0x02, 0x01, 0x00,                                     // error-status=0
        0x02, 0x01, 0x00,                                     // error-index=0
        0x30, 0x17,                                           // VarBindList len=23
        0x30, 0x15,                                           // VarBind len=21
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID sysDescr.0
        0x04, 0x09, b'L', b'i', b'n', b'u', b'x', b' ', b'x', b'8', b'6', // "Linux x86"
    ];

    #[test]
    fn parse_response_decodes_sysdescr() {
        let result = parse_response(SYSDESCR_RESPONSE).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, vec![1u32, 3, 6, 1, 2, 1, 1, 1, 0]);
        match &result[0].1 {
            SnmpValue::OctetString(b) => assert_eq!(b, b"Linux x86"),
            other => panic!("expected OctetString, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_error_status_nonzero_returns_empty() {
        // error-status value is at offset 20 (after SEQUENCE+len, INTEGER×3, OCTET_STRING+len+6,
        // PDU+len, req-id tag+len+val, error-status tag+len).
        let mut pkt = SYSDESCR_RESPONSE.to_vec();
        pkt[20] = 0x01;
        let result = parse_response(&pkt).unwrap();
        assert!(result.is_empty());
    }
}
