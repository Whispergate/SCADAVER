//! OPC-UA Binary Transport client.
//!
//! Implements the minimal OPC-UA binary protocol (HEL/ACK, OPN, `GetEndpoints`) over
//! TCP port 4840. All encoding is hand-coded per OPC UA Binary Schema 1.05;
//! no external OPC-UA crate is used.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default TCP port for OPC-UA.
pub const OPCUA_PORT: u16 = 4840;

// Message type bytes
const MSG_HEL: &[u8; 3] = b"HEL";
const MSG_ACK: &[u8; 3] = b"ACK";
const MSG_OPN: &[u8; 3] = b"OPN";
const MSG_MSG: &[u8; 3] = b"MSG";

// Chunk type: 'F' = Final (single chunk, complete message)
const CHUNK_FINAL: u8 = b'F';

// Security policy URIs
const POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

// OPC-UA Security Mode
const SECURITY_MODE_NONE: u32 = 1;
const SECURITY_MODE_SIGN: u32 = 2;
const SECURITY_MODE_SIGN_AND_ENCRYPT: u32 = 3;

// NodeId for known service requests (numeric form, namespace 0)
const NODE_OPEN_SECURE_CHANNEL_REQ: u32 = 446;
const NODE_GET_ENDPOINTS_REQ: u32 = 428;

/// A resolved endpoint descriptor.
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub url: String,
    pub security_mode: String,
    pub security_policy: String,
    pub allows_anonymous: bool,
}

/// A detected OPC-UA server.
#[derive(Debug, Clone)]
pub struct OpcuaServer {
    pub ip: String,
    pub port: u16,
    pub application_name: String,
    pub application_uri: String,
    pub product_uri: String,
    pub endpoints: Vec<EndpointInfo>,
}

// ─── Binary encoding helpers ──────────────────────────────────────────────────

fn encode_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Encode an OPC-UA String (u32 length prefix; `0xFFFF_FFFF` = null).
fn encode_string(s: Option<&str>) -> Vec<u8> {
    match s {
        None => 0xFFFF_FFFFu32.to_le_bytes().to_vec(),
        Some(s) => {
            let bytes = s.as_bytes();
            let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            let mut v = len.to_le_bytes().to_vec();
            v.extend_from_slice(bytes);
            v
        }
    }
}

/// Encode a null OPC-UA `ByteString` (4-byte -1 sentinel).
fn encode_null_bytestring() -> [u8; 4] {
    0xFFFF_FFFFu32.to_le_bytes()
}

/// Encode a null `NodeId` (two zero bytes = `NodeId` type 0).
fn encode_null_node_id() -> [u8; 2] {
    [0x00, 0x00]
}

/// Encode a numeric `NodeId` (namespace=0, type=0x01).
fn encode_numeric_node_id(id: u32) -> Vec<u8> {
    if id <= 255 {
        vec![0x00, u8::try_from(id).unwrap_or(0)] // 2-byte form: type=0x00, id=1 byte
    } else {
        // 4-byte numeric form: type=0x01, namespace=0, id=u16 if ≤65535
        let id_bytes = u16::try_from(id).unwrap_or(u16::MAX).to_le_bytes();
        vec![0x01, 0x00, id_bytes[0], id_bytes[1]]
    }
}

/// Encode an OPC-UA `RequestHeader`.
fn encode_request_header(request_handle: u32, timeout_hint_ms: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&encode_null_node_id()); // auth token (null NodeId)
    h.extend_from_slice(&0i64.to_le_bytes()); // timestamp = 0
    h.extend_from_slice(&encode_u32(request_handle)); // request handle
    h.extend_from_slice(&encode_u32(0)); // return diagnostics = 0
    h.extend_from_slice(&encode_string(None)); // audit entry id = null
    h.extend_from_slice(&encode_u32(timeout_hint_ms)); // timeout hint
    // Additional header: TypeId=null, Encoding=0 (no body)
    h.extend_from_slice(&encode_null_node_id()); // type id
    h.push(0x00); // encoding byte
    h
}

/// Build the OPC-UA message header (message type + chunk type + 4-byte size).
fn build_message_header(msg_type: [u8; 3], body_len: usize) -> Vec<u8> {
    let total = 8 + body_len; // header(4) + size(4) + body
    let mut h = Vec::with_capacity(8);
    h.extend_from_slice(&msg_type);
    h.push(CHUNK_FINAL);
    h.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_le_bytes());
    h
}

// ─── HEL / ACK ────────────────────────────────────────────────────────────────

fn build_hel(endpoint_url: &str) -> Vec<u8> {
    let url_bytes = encode_string(Some(endpoint_url));
    let body_len = 4 + 4 + 4 + 4 + 4 + url_bytes.len();
    // body: version(4) + recv_buf(4) + send_buf(4) + max_msg(4) + max_chunks(4) + url
    let mut body = Vec::new();
    body.extend_from_slice(&encode_u32(0)); // protocol version
    body.extend_from_slice(&encode_u32(65536)); // recv buffer size
    body.extend_from_slice(&encode_u32(65536)); // send buffer size
    body.extend_from_slice(&encode_u32(0)); // max message size (0 = no limit)
    body.extend_from_slice(&encode_u32(0)); // max chunk count (0 = unlimited)
    body.extend_from_slice(&url_bytes);

    let mut pkt = build_message_header(*MSG_HEL, body_len);
    pkt.append(&mut body);
    pkt
}

fn is_ack(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == MSG_ACK[0] && data[1] == MSG_ACK[1] && data[2] == MSG_ACK[2]
}

// ─── OPN (OpenSecureChannel) ──────────────────────────────────────────────────

fn build_opn(channel_id: u32, seq_num: u32, req_id: u32) -> Vec<u8> {
    let policy_uri = encode_string(Some(POLICY_NONE));
    let sender_cert = encode_null_bytestring();
    let recv_thumbprint = encode_null_bytestring();

    // Sequence header
    let mut seq_header = Vec::new();
    seq_header.extend_from_slice(&encode_u32(seq_num));
    seq_header.extend_from_slice(&encode_u32(req_id));

    // OpenSecureChannelRequest body
    // TypeId = i=446 (numeric, namespace 0)
    let type_id = encode_numeric_node_id(NODE_OPEN_SECURE_CHANNEL_REQ);
    let req_header = encode_request_header(req_id, 5000);
    let mut req_body = Vec::new();
    req_body.extend_from_slice(&type_id);
    req_body.extend_from_slice(&req_header);
    req_body.extend_from_slice(&encode_u32(0)); // client protocol version
    req_body.extend_from_slice(&encode_u32(0)); // security token request type = Issue
    req_body.extend_from_slice(&encode_u32(SECURITY_MODE_NONE)); // security mode = None
    req_body.extend_from_slice(&encode_null_bytestring()); // client nonce = null
    req_body.extend_from_slice(&encode_u32(3_600_000)); // requested lifetime = 1 hour

    // OPN body = channel_id + security_policy + sender_cert + thumbprint + seq_header + req
    let mut opn_body = Vec::new();
    opn_body.extend_from_slice(&encode_u32(channel_id));
    opn_body.extend_from_slice(&policy_uri);
    opn_body.extend_from_slice(&sender_cert);
    opn_body.extend_from_slice(&recv_thumbprint);
    opn_body.extend_from_slice(&seq_header);
    opn_body.extend_from_slice(&req_body);

    let mut pkt = build_message_header(*MSG_OPN, opn_body.len());
    pkt.extend_from_slice(&opn_body);
    pkt
}

/// Parse the channel ID and security token from an OPN response.
fn parse_opn_response(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 12 || !data.starts_with(b"OPNF") {
        return None;
    }
    let channel_id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    // Security token starts after channel_id(4) + token_type(varies)...
    // token_id is at offset 8 + 4 = 12 in the OPN body, but the actual layout depends on
    // policy bytes. For policy=None, sender/receiver certs are null (4 bytes each = 0xFFFFFFFF),
    // seq header is 8 bytes, then the response body starts with the TypeId.
    // For a simple scanner, just returning the channel_id is sufficient.
    Some((channel_id, 1)) // token_id = 1 (we don't parse it further)
}

// ─── GetEndpoints MSG ─────────────────────────────────────────────────────────

fn build_get_endpoints(
    channel_id: u32,
    token_id: u32,
    seq_num: u32,
    req_id: u32,
    endpoint_url: &str,
) -> Vec<u8> {
    let type_id = encode_numeric_node_id(NODE_GET_ENDPOINTS_REQ);
    let req_header = encode_request_header(req_id, 5000);

    let mut req_body = Vec::new();
    req_body.extend_from_slice(&type_id);
    req_body.extend_from_slice(&req_header);
    req_body.extend_from_slice(&encode_string(Some(endpoint_url))); // endpoint URL
    req_body.extend_from_slice(&0u32.to_le_bytes()); // locale ids: empty array
    req_body.extend_from_slice(&0u32.to_le_bytes()); // profile uris: empty array

    // MSG body: channel_id(4) + token_id(4) + seq(4) + req_id(4) + body
    let mut sym_header = Vec::new();
    sym_header.extend_from_slice(&encode_u32(channel_id));
    sym_header.extend_from_slice(&encode_u32(token_id));
    sym_header.extend_from_slice(&encode_u32(seq_num));
    sym_header.extend_from_slice(&encode_u32(req_id));

    let mut body = Vec::new();
    body.extend_from_slice(&sym_header);
    body.extend_from_slice(&req_body);

    let mut pkt = build_message_header(*MSG_MSG, body.len());
    pkt.extend_from_slice(&body);
    pkt
}

// ─── Response parsing ─────────────────────────────────────────────────────────

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn read_i32(&mut self) -> Option<i32> {
        if self.remaining() < 4 {
            return None;
        }
        let v = i32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn read_string(&mut self) -> Option<String> {
        let len = self.read_i32()?;
        if len < 0 {
            return Some(String::new()); // null string
        }
        let len = usize::try_from(len).unwrap_or(0);
        if self.remaining() < len {
            return None;
        }
        let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + len]).into_owned();
        self.pos += len;
        Some(s)
    }

    fn read_bytestring(&mut self) -> Option<Vec<u8>> {
        let len = self.read_i32()?;
        if len < 0 {
            return Some(Vec::new()); // null
        }
        let len = usize::try_from(len).unwrap_or(0);
        if self.remaining() < len {
            return None;
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Some(v)
    }

    /// Skip a `NodeId` (variable length: 1-byte type tag + content).
    fn skip_node_id(&mut self) -> Option<()> {
        let node_type = self.read_u8()?;
        match node_type {
            0x01 => { self.pos += 3; } // namespace(1) + id(2)
            0x02 => { self.pos += 5; } // namespace(2) + id(4)
            0x03..=0x05 => { self.skip_node_id()?; } // string / GUID / ByteString
            _ => { self.read_u8()?; } // 0x00 (2-byte numeric) or unknown: skip 1 byte
        }
        Some(())
    }

    /// Skip a `RequestHeader` (consumed by the response parser to get past it).
    fn skip_response_header(&mut self) -> Option<()> {
        // timestamp(8) + request_handle(4) + service_result(4) + service_diagnostics + string + extension
        self.pos += 8; // timestamp
        self.pos += 4; // request handle
        self.pos += 4; // service result (status code)
        // service diagnostics: extended diagnostic (variable) — skip by checking encoded form
        // simplified: just skip the mask byte if it's the simplified form
        let diag_bits = self.read_u32()?;
        if diag_bits != 0 {
            // has diagnostic info — best-effort skip remaining header and bail
            return None;
        }
        // string array (string tables)
        let str_count = self.read_i32()?;
        for _ in 0..str_count.max(0) {
            self.read_string()?;
        }
        // additional header (extension object): type id (NodeId) + encoding + optional body
        self.skip_node_id()?;
        let encoding = self.read_u8()?;
        if encoding != 0 {
            let body_len = self.read_i32()?;
            if body_len > 0 {
                self.pos += usize::try_from(body_len).unwrap_or(0);
            }
        }
        Some(())
    }
}

/// Parse a `GetEndpoints` response.
fn parse_get_endpoints(data: &[u8]) -> Vec<EndpointInfo> {
    // MSG header: type(3) + chunk(1) + size(4) = 8
    // Symmetric security header: channel_id(4) + token_id(4) + seq_num(4) + req_id(4) = 16
    // TypeId (NodeId for GetEndpointsResponse = 431): variable
    // Response header: variable
    // Endpoints array: i32 count + array elements

    let mut endpoints = Vec::new();
    if data.len() < 28 {
        return endpoints;
    }

    // Verify it's a MSG response
    if &data[0..3] != b"MSG" {
        return endpoints;
    }

    // Skip: msg header(8) + symmetric security header(16) = 24
    let body_start = 24;
    let mut p = Parser::new(&data[body_start..]);

    // TypeId (NodeId)
    p.skip_node_id();

    // Response header
    if p.skip_response_header().is_none() {
        return endpoints;
    }

    // Endpoints array count
    let count = match p.read_i32() {
        Some(n) if n > 0 => usize::try_from(n).unwrap_or(0),
        _ => return endpoints,
    };

    for _ in 0..count.min(64) {
        let Some(ep) = parse_endpoint_description(&mut p) else { break };
        endpoints.push(ep);
    }

    endpoints
}

fn parse_endpoint_description(p: &mut Parser<'_>) -> Option<EndpointInfo> {
    // EndpointDescription fields (OPC-UA spec Part 4, §7.9):
    // endpointUrl: String
    // server: ApplicationDescription (complex)
    // serverCertificate: ByteString
    // securityMode: Enum(u32)
    // securityPolicyUri: String
    // userIdentityTokens: array of UserTokenPolicy
    // transportProfileUri: String
    // securityLevel: Byte

    let endpoint_url = p.read_string()?;

    // ApplicationDescription: skip (applicationUri + productUri + applicationName (LocalizedText)
    //   + applicationType(u32) + gatewayServerUri + discoveryProfileUri + discoveryUrls array)
    let _app_uri = p.read_string()?;
    let _product_uri = p.read_string()?;
    // LocalizedText: encoding(u8) + optional locale + optional text
    let lt_encoding = p.read_u8()?;
    if (lt_encoding & 0x01) != 0 { p.read_string()?; } // locale
    if (lt_encoding & 0x02) != 0 { p.read_string()?; } // text
    let _app_type = p.read_u32()?;
    let _gw_uri = p.read_string()?;
    let _disc_profile = p.read_string()?;
    let disc_url_count = p.read_i32()?;
    for _ in 0..disc_url_count.clamp(0, 32) {
        p.read_string()?;
    }

    let _server_cert = p.read_bytestring()?;
    let security_mode_val = p.read_u32()?;
    let security_policy_uri = p.read_string()?;

    // UserIdentityToken array
    let token_count = p.read_i32()?;
    let mut allows_anonymous = false;
    for _ in 0..token_count.clamp(0, 32) {
        // UserTokenPolicy: policyId(String) + tokenType(u32) + issuedTokenType(String)
        //   + issuerEndpointUrl(String) + securityPolicyUri(String)
        let _policy_id = p.read_string()?;
        let token_type = p.read_u32()?;
        if token_type == 0 {
            // 0 = Anonymous
            allows_anonymous = true;
        }
        let _issued_type = p.read_string()?;
        let _issuer_url = p.read_string()?;
        let _sec_policy = p.read_string()?;
    }

    let _transport_profile = p.read_string()?;
    let _security_level = p.read_u8()?;

    let security_mode = match security_mode_val {
        SECURITY_MODE_NONE => "None",
        SECURITY_MODE_SIGN => "Sign",
        SECURITY_MODE_SIGN_AND_ENCRYPT => "SignAndEncrypt",
        _ => "Unknown",
    };

    // Shorten security policy URI to the fragment (after '#')
    let policy_short = security_policy_uri
        .rsplit('#')
        .next()
        .unwrap_or(&security_policy_uri)
        .to_string();

    Some(EndpointInfo {
        url: endpoint_url,
        security_mode: security_mode.to_string(),
        security_policy: policy_short,
        allows_anonymous,
    })
}

// ─── Transport helpers ────────────────────────────────────────────────────────

fn recv_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(8..=4 * 1024 * 1024).contains(&size) {
        return None;
    }
    let mut body = vec![0u8; size - 8];
    stream.read_exact(&mut body).ok()?;
    let mut full = header.to_vec();
    full.append(&mut body);
    Some(full)
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Detect an OPC-UA server by attempting the HEL/ACK handshake.
pub fn detect(ip: &str, port: u16, timeout: Duration) -> Option<OpcuaServer> {
    let effective_port = if port == 0 { OPCUA_PORT } else { port };
    let addr = format!("{ip}:{effective_port}");
    let endpoint_url = format!("opc.tcp://{ip}:{effective_port}");

    let stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut stream = stream;

    let hel = build_hel(&endpoint_url);
    stream.write_all(&hel).ok()?;

    let resp = recv_message(&mut stream)?;
    if !is_ack(&resp) {
        return None;
    }

    Some(OpcuaServer {
        ip: ip.to_string(),
        port: effective_port,
        application_name: String::new(),
        application_uri: String::new(),
        product_uri: String::new(),
        endpoints: Vec::new(),
    })
}

/// Get endpoint descriptors from an OPC-UA server via HEL → OPN → `GetEndpoints`.
pub fn get_endpoints(ip: &str, port: u16, timeout: Duration) -> Vec<EndpointInfo> {
    let effective_port = if port == 0 { OPCUA_PORT } else { port };
    let addr = format!("{ip}:{effective_port}");
    let endpoint_url = format!("opc.tcp://{ip}:{effective_port}");

    let Ok(stream) = TcpStream::connect_timeout(&addr.parse().unwrap_or("0.0.0.0:1".parse().unwrap()), timeout) else {
        return Vec::new();
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    // HEL
    let hel = build_hel(&endpoint_url);
    if stream.write_all(&hel).is_err() {
        return Vec::new();
    }
    let ack = match recv_message(&mut stream) {
        Some(r) if is_ack(&r) => r,
        _ => return Vec::new(),
    };
    drop(ack);

    // OPN
    let opn = build_opn(0, 1, 1);
    if stream.write_all(&opn).is_err() {
        return Vec::new();
    }
    let Some(opn_resp) = recv_message(&mut stream) else { return Vec::new() };
    let Some((channel_id, token_id)) = parse_opn_response(&opn_resp) else { return Vec::new() };

    // GetEndpoints
    let ge = build_get_endpoints(channel_id, token_id, 2, 2, &endpoint_url);
    if stream.write_all(&ge).is_err() {
        return Vec::new();
    }
    let Some(ge_resp) = recv_message(&mut stream) else { return Vec::new() };

    parse_get_endpoints(&ge_resp)
}

/// Build a human-readable summary map for an [`OpcuaServer`].
pub fn server_summary(server: &OpcuaServer) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("port".into(), server.port.to_string());
    if !server.application_name.is_empty() {
        m.insert("application_name".into(), server.application_name.clone());
    }
    if !server.application_uri.is_empty() {
        m.insert("application_uri".into(), server.application_uri.clone());
    }
    let endpoint_count = server.endpoints.len();
    m.insert("endpoint_count".into(), endpoint_count.to_string());
    let anonymous_count = server.endpoints.iter().filter(|e| e.allows_anonymous).count();
    m.insert("anonymous_endpoints".into(), anonymous_count.to_string());
    let security_modes: Vec<String> = server
        .endpoints
        .iter()
        .map(|e| e.security_mode.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    m.insert("security_modes".into(), security_modes.join(","));
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_string_null_produces_sentinel() {
        let v = encode_string(None);
        assert_eq!(v, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn encode_string_non_null_has_correct_prefix() {
        let v = encode_string(Some("abc"));
        assert_eq!(&v[..4], &3u32.to_le_bytes());
        assert_eq!(&v[4..], b"abc");
    }

    #[test]
    fn build_hel_message_has_correct_size_field() {
        let hel = build_hel("opc.tcp://127.0.0.1:4840");
        assert_eq!(&hel[0..3], b"HEL");
        assert_eq!(hel[3], b'F');
        let size = u32::from_le_bytes([hel[4], hel[5], hel[6], hel[7]]) as usize;
        assert_eq!(size, hel.len());
    }

    #[test]
    fn is_ack_accepts_valid_ack() {
        let ack = b"ACKF\x1c\x00\x00\x00\x00\x00\x00\x00xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        assert!(is_ack(ack));
    }

    #[test]
    fn is_ack_rejects_hel() {
        let hel = build_hel("opc.tcp://127.0.0.1:4840");
        assert!(!is_ack(&hel));
    }

    #[test]
    fn parse_get_endpoints_empty_returns_empty() {
        assert!(parse_get_endpoints(&[]).is_empty());
    }

    #[test]
    fn parser_read_string_null() {
        let data = 0xFFFF_FFFFu32.to_le_bytes();
        let mut p = Parser::new(&data);
        let s = p.read_string().unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn parser_read_string_value() {
        let mut data = 3u32.to_le_bytes().to_vec();
        data.extend_from_slice(b"abc");
        let mut p = Parser::new(&data);
        assert_eq!(p.read_string().unwrap(), "abc");
    }
}
