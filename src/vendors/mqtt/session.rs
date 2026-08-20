//! Persistent MQTT 3.1.1 / 5.0 session over raw `TcpStream` or TLS.
//!
//! Complements the single-shot probe in `client.rs` with a keep-alive connection
//! that supports subscribe, unsubscribe, and publish.  A background reader thread
//! drains incoming PUBLISH packets into a shared queue; the main thread handles
//! all writes.

use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ── MQTT version ──────────────────────────────────────────────────────────────

/// Protocol version used in the CONNECT packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MqttVersion {
    /// MQTT 3.1.1 — protocol level 0x04 (default).
    #[default]
    V311,
    /// MQTT 5.0 — protocol level 0x05.
    V5,
}

// ── Stream wrapper ────────────────────────────────────────────────────────────

enum MqttStream {
    Plain(TcpStream),
    #[cfg(feature = "cli")]
    Tls(Box<native_tls::TlsStream<TcpStream>>),
}

impl Read for MqttStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            #[cfg(feature = "cli")]
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for MqttStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            #[cfg(feature = "cli")]
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            #[cfg(feature = "cli")]
            Self::Tls(s) => s.flush(),
        }
    }
}

impl MqttStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.set_read_timeout(dur),
            #[cfg(feature = "cli")]
            Self::Tls(s) => s.get_ref().set_read_timeout(dur),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            #[cfg(feature = "cli")]
            Self::Tls(s) => {
                let _ = s.get_ref().shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Last Will and Testament included in a CONNECT packet.
#[derive(Debug, Clone)]
pub struct WillConfig {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
}

/// Connection parameters for [`MqttSession::connect`].
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub client_id: String,
    /// Keep-alive interval in seconds sent in CONNECT.
    pub keepalive: u16,
    pub clean_session: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub will: Option<WillConfig>,
    /// Wrap the TCP connection in TLS before the MQTT handshake.
    pub tls: bool,
    /// When `false` (default for pentest use), accept self-signed / invalid certs.
    pub tls_verify: bool,
    /// Protocol version to advertise in the CONNECT packet.
    pub protocol_version: MqttVersion,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 1883,
            client_id: "scadaver-shell".into(),
            keepalive: 60,
            clean_session: true,
            username: None,
            password: None,
            will: None,
            tls: false,
            tls_verify: false,
            protocol_version: MqttVersion::V311,
        }
    }
}

/// A single PUBLISH message received from the broker.
#[derive(Debug, Clone)]
pub struct MqttMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
}

impl MqttMessage {
    /// Payload decoded as a UTF-8 string (lossy).
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Live MQTT broker connection with a background packet reader.
///
/// The stream is wrapped in `Arc<Mutex<>>` so the reader thread and main thread
/// can share it without `try_clone()` (which TLS streams do not support).
/// I/O is serialised: the reader locks briefly per packet; writers lock to send.
pub struct MqttSession {
    stream: Arc<Mutex<MqttStream>>,
    messages: Arc<Mutex<VecDeque<MqttMessage>>>,
    suback_codes: Arc<Mutex<VecDeque<u8>>>,
    subscriptions: Vec<String>,
    packet_id: u16,
    _reader: JoinHandle<()>,
    /// True when the broker resumed a stored session (CONNACK session-present bit).
    pub session_present: bool,
}

impl Drop for MqttSession {
    fn drop(&mut self) {
        // Shut down the TCP socket so the reader thread's next read fails and it exits.
        if let Ok(s) = self.stream.try_lock() {
            s.shutdown();
        }
    }
}

impl MqttSession {
    /// Connect to the broker.  Returns `Err` on TCP / TLS failure or a non-zero
    /// CONNACK return code.
    pub fn connect(opts: &ConnectOptions) -> Result<Self> {
        let addr = format!("{}:{}", opts.host, opts.port);
        let sock_addr = addr
            .to_socket_addrs()
            .context("resolve address")?
            .next()
            .context("no addresses for host")?;
        let tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))
            .with_context(|| format!("TCP connect to {addr}"))?;

        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;

        let mut stream = make_stream(opts, tcp)?;

        let pkt = build_connect(opts);
        stream.write_all(&pkt).context("send CONNECT")?;

        let (ack_flags, rc) = parse_connack(&mut stream, opts.protocol_version)?;
        if rc != 0x00 {
            anyhow::bail!(
                "CONNACK refused: 0x{rc:02x} ({}) session_present={}",
                connack_reason(rc, opts.protocol_version),
                ack_flags & 0x01
            );
        }

        // 100 ms read timeout — reader polls in a tight loop to stay non-blocking.
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;

        let stream: Arc<Mutex<MqttStream>> = Arc::new(Mutex::new(stream));
        let messages: Arc<Mutex<VecDeque<MqttMessage>>> = Arc::default();
        let suback_codes: Arc<Mutex<VecDeque<u8>>> = Arc::default();
        let reader_stream = Arc::clone(&stream);
        let reader_q = Arc::clone(&messages);
        let reader_subacks = Arc::clone(&suback_codes);

        let reader = thread::Builder::new()
            .name("mqtt-reader".into())
            .spawn(move || reader_loop(&reader_stream, &reader_q, &reader_subacks))?;

        Ok(Self {
            stream,
            messages,
            suback_codes,
            subscriptions: Vec::new(),
            packet_id: 1,
            _reader: reader,
            session_present: ack_flags & 0x01 != 0,
        })
    }

    /// Subscribe to `topic` at the requested `QoS` (0–2).
    pub fn subscribe(&mut self, topic: &str, qos: u8) -> Result<()> {
        let id = self.next_id();
        self.send_packet(&build_subscribe(id, topic, qos), "SUBSCRIBE")?;
        if !self.subscriptions.iter().any(|s| s == topic) {
            self.subscriptions.push(topic.to_string());
        }
        Ok(())
    }

    /// Unsubscribe from `topic`.
    pub fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        let id = self.next_id();
        self.send_packet(&build_unsubscribe(id, topic), "UNSUBSCRIBE")?;
        self.subscriptions.retain(|s| s != topic);
        Ok(())
    }

    /// Unsubscribe from every currently subscribed topic.
    pub fn unsubscribe_all(&mut self) -> Result<()> {
        for t in self.subscriptions.clone() {
            self.unsubscribe(&t)?;
        }
        Ok(())
    }

    /// Publish `payload` to `topic`.
    pub fn publish(&mut self, topic: &str, payload: &[u8], qos: u8, retain: bool) -> Result<()> {
        let id = if qos > 0 { self.next_id() } else { 0 };
        self.send_packet(&build_publish(id, topic, payload, qos, retain), "PUBLISH")
    }

    /// Send a PINGREQ to keep the connection alive.
    pub fn ping(&mut self) -> Result<()> {
        self.send_packet(&[0xC0, 0x00], "PINGREQ")
    }

    /// Topics currently subscribed on this session.
    pub fn subscriptions(&self) -> &[String] {
        &self.subscriptions
    }

    /// Drain all messages queued by the reader thread.
    pub fn drain_messages(&self) -> Vec<MqttMessage> {
        self.messages.lock().map_or_else(|_| Vec::new(), |mut q| q.drain(..).collect())
    }

    /// Discard any buffered SUBACK codes (call before ACL probe to avoid stale results).
    pub fn flush_subacks(&self) {
        if let Ok(mut q) = self.suback_codes.lock() {
            q.clear();
        }
    }

    /// Poll for the next SUBACK return code from the broker.
    ///
    /// Returns `Some(code)` where `code < 0x80` means granted and `0x80` means refused.
    /// Returns `None` if no SUBACK arrives within `timeout`.
    pub fn poll_suback(&self, timeout: Duration) -> Option<u8> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Ok(mut q) = self.suback_codes.lock() {
                if let Some(code) = q.pop_front() {
                    return Some(code);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    /// Send a DISCONNECT packet and close the session.
    pub fn disconnect(self) -> Result<()> {
        self.send_packet(&[0xE0, 0x00], "DISCONNECT")
    }

    fn send_packet(&self, buf: &[u8], ctx: &'static str) -> Result<()> {
        let mut s = self
            .stream
            .lock()
            .map_err(|_| anyhow::anyhow!("{ctx}: MQTT stream lock poisoned"))?;
        s.write_all(buf).with_context(|| ctx)
    }

    fn next_id(&mut self) -> u16 {
        let id = self.packet_id;
        // Wrap around at 65535 back to 1 (packet ID 0 is reserved for QoS 0 PUBLISH).
        self.packet_id = self.packet_id.wrapping_add(1).max(1);
        id
    }
}

// ── Stream construction ───────────────────────────────────────────────────────

fn make_stream(opts: &ConnectOptions, tcp: TcpStream) -> Result<MqttStream> {
    if !opts.tls {
        return Ok(MqttStream::Plain(tcp));
    }
    #[cfg(feature = "cli")]
    {
        let mut builder = native_tls::TlsConnector::builder();
        if !opts.tls_verify {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        let connector = builder.build().context("TLS connector build")?;
        let tls = connector
            .connect(&opts.host, tcp)
            .map_err(|e| anyhow::anyhow!("TLS handshake with {}: {e}", opts.host))?;
        Ok(MqttStream::Tls(Box::new(tls)))
    }
    #[cfg(not(feature = "cli"))]
    anyhow::bail!("MQTT TLS requires the 'cli' feature")
}

// ── Reader thread ─────────────────────────────────────────────────────────────

fn reader_loop(
    stream: &Arc<Mutex<MqttStream>>,
    q: &Arc<Mutex<VecDeque<MqttMessage>>>,
    subacks: &Arc<Mutex<VecDeque<u8>>>,
) {
    loop {
        let result = {
            let Ok(mut s) = stream.lock() else { break };
            read_packet(&mut s)
        };

        match result {
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Sleep briefly so writer threads can acquire the lock.
                // Without this the reader re-acquires immediately, starving writes
                // on 1-2 core CI runners.
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
            Ok((packet_type, qos, retain, body)) => {
                dispatch_packet(packet_type, qos, retain, &body, q, subacks);
            }
        }
    }
}

fn read_packet(stream: &mut MqttStream) -> std::io::Result<(u8, u8, bool, Vec<u8>)> {
    let mut type_byte = [0u8; 1];
    stream.read_exact(&mut type_byte)?;
    let fixed = type_byte[0];
    let packet_type = (fixed >> 4) & 0x0F;
    let qos = (fixed >> 1) & 0x03;
    let retain = fixed & 0x01 != 0;

    let remaining_len = decode_remaining_length(stream)?;
    if remaining_len > 65_536 {
        // Oversized packet: drain and return a sentinel (packet_type=0 is unused).
        let mut left = remaining_len;
        let mut chunk = [0u8; 4096];
        while left > 0 {
            let n = left.min(4096);
            stream.read_exact(&mut chunk[..n])?;
            left -= n;
        }
        return Ok((0, 0, false, Vec::new()));
    }
    let mut body = vec![0u8; remaining_len];
    stream.read_exact(&mut body)?;
    Ok((packet_type, qos, retain, body))
}

fn dispatch_packet(
    packet_type: u8,
    qos: u8,
    retain: bool,
    body: &[u8],
    q: &Arc<Mutex<VecDeque<MqttMessage>>>,
    subacks: &Arc<Mutex<VecDeque<u8>>>,
) {
    if packet_type == 3 && body.len() >= 2 {
        let topic_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        let payload_start = 2 + topic_len + if qos > 0 { 2 } else { 0 };
        if body.len() >= 2 + topic_len {
            let topic = String::from_utf8_lossy(&body[2..2 + topic_len]).into_owned();
            let payload =
                if body.len() > payload_start { body[payload_start..].to_vec() } else { Vec::new() };
            if let Ok(mut queue) = q.lock() {
                queue.push_back(MqttMessage { topic, payload, qos, retain });
            }
        }
    }
    if packet_type == 9 && body.len() >= 3 {
        // SUBACK: body[0..1]=packet_id, body[2..]=per-topic return codes
        if let Ok(mut sq) = subacks.lock() {
            for &code in &body[2..] {
                sq.push_back(code);
            }
        }
    }
    // UNSUBACK (11), PINGRESP (13): silently discarded.
}

// ── Wire protocol ─────────────────────────────────────────────────────────────

fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        // len % 128 is 0..=127; try_from always succeeds; unwrap_or is a no-op fallback.
        let mut byte = u8::try_from(len % 128).unwrap_or(0);
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

fn decode_remaining_length(stream: &mut impl Read) -> std::io::Result<usize> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for _ in 0..4 {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        let encoded = buf[0];
        value = value.saturating_add(usize::from(encoded & 0x7F) * multiplier);
        multiplier = multiplier.saturating_mul(128);
        if encoded & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

fn utf8_field(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let cap = bytes.len().min(65_535);
    let len = u16::try_from(cap).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(2 + cap);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..cap]);
    out
}

fn build_connect(opts: &ConnectOptions) -> Vec<u8> {
    let proto_level: u8 = match opts.protocol_version {
        MqttVersion::V311 => 0x04,
        MqttVersion::V5 => 0x05,
    };

    let mut flags: u8 = 0;
    if opts.clean_session {
        flags |= 0x02;
    }
    if let Some(w) = &opts.will {
        flags |= 0x04;
        flags |= (w.qos & 0x03) << 3;
        if w.retain {
            flags |= 0x20;
        }
    }
    if opts.username.is_some() {
        flags |= 0x80;
    }
    if opts.password.is_some() && opts.username.is_some() {
        flags |= 0x40;
    }

    let [kh, kl] = opts.keepalive.to_be_bytes();
    let mut var_header = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', proto_level, flags, kh, kl];

    // MQTT 5.0 requires a connect-properties length field (0x00 = no properties).
    if opts.protocol_version == MqttVersion::V5 {
        var_header.push(0x00);
    }

    let mut payload = utf8_field(&opts.client_id);
    if let Some(w) = &opts.will {
        let wt_len = u16::try_from(w.topic.len()).unwrap_or(u16::MAX);
        payload.extend_from_slice(&wt_len.to_be_bytes());
        payload.extend_from_slice(w.topic.as_bytes());
        let wp_len = u16::try_from(w.payload.len()).unwrap_or(u16::MAX);
        payload.extend_from_slice(&wp_len.to_be_bytes());
        payload.extend_from_slice(&w.payload);
    }
    if let Some(u) = &opts.username {
        payload.extend_from_slice(&utf8_field(u));
    }
    if let Some(p) = &opts.password {
        if opts.username.is_some() {
            payload.extend_from_slice(&utf8_field(p));
        }
    }

    let remaining = var_header.len() + payload.len();
    let mut pkt = Vec::with_capacity(2 + remaining);
    pkt.push(0x10);
    pkt.extend_from_slice(&encode_remaining_length(remaining));
    pkt.append(&mut var_header);
    pkt.extend_from_slice(&payload);
    pkt
}

fn build_subscribe(id: u16, topic: &str, qos: u8) -> Vec<u8> {
    let tf = utf8_field(topic);
    let remaining = 2 + tf.len() + 1;
    let mut pkt = Vec::with_capacity(2 + remaining);
    pkt.push(0x82); // SUBSCRIBE type + mandatory reserved bits 0010
    pkt.extend_from_slice(&encode_remaining_length(remaining));
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&tf);
    pkt.push(qos & 0x03);
    pkt
}

fn build_unsubscribe(id: u16, topic: &str) -> Vec<u8> {
    let tf = utf8_field(topic);
    let remaining = 2 + tf.len();
    let mut pkt = Vec::with_capacity(2 + remaining);
    pkt.push(0xA2); // UNSUBSCRIBE type + mandatory reserved bits 0010
    pkt.extend_from_slice(&encode_remaining_length(remaining));
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&tf);
    pkt
}

fn build_publish(id: u16, topic: &str, payload: &[u8], qos: u8, retain: bool) -> Vec<u8> {
    let qos = qos & 0x03;
    let tf = utf8_field(topic);
    let has_id = qos > 0;
    let remaining = tf.len() + if has_id { 2 } else { 0 } + payload.len();
    let mut fixed = 0x30u8;
    if retain {
        fixed |= 0x01;
    }
    fixed |= qos << 1;
    let mut pkt = Vec::with_capacity(2 + remaining);
    pkt.push(fixed);
    pkt.extend_from_slice(&encode_remaining_length(remaining));
    pkt.extend_from_slice(&tf);
    if has_id {
        pkt.extend_from_slice(&id.to_be_bytes());
    }
    pkt.extend_from_slice(payload);
    pkt
}

fn parse_connack(stream: &mut MqttStream, version: MqttVersion) -> Result<(u8, u8)> {
    match version {
        MqttVersion::V311 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).context("CONNACK read")?;
            if buf[0] != 0x20 || buf[1] != 0x02 {
                anyhow::bail!(
                    "expected CONNACK (0x20 0x02), got 0x{:02x} 0x{:02x}",
                    buf[0],
                    buf[1]
                );
            }
            Ok((buf[2], buf[3]))
        }
        MqttVersion::V5 => {
            // v5 CONNACK: 0x20 0x03 ack_flags reason_code properties_length(0x00)
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).context("CONNACK v5 read")?;
            if buf[0] != 0x20 || buf[1] != 0x03 {
                anyhow::bail!(
                    "expected CONNACK v5 (0x20 0x03), got 0x{:02x} 0x{:02x}",
                    buf[0],
                    buf[1]
                );
            }
            Ok((buf[2], buf[3]))
        }
    }
}

fn connack_reason(code: u8, version: MqttVersion) -> &'static str {
    match version {
        MqttVersion::V311 => match code {
            0x00 => "accepted",
            0x01 => "unacceptable protocol version",
            0x02 => "identifier rejected",
            0x03 => "server unavailable",
            0x04 => "bad username or password",
            0x05 => "not authorized",
            _ => "unknown",
        },
        MqttVersion::V5 => match code {
            0x00 => "success",
            0x80 => "unspecified error",
            0x81 => "malformed packet",
            0x82 => "protocol error",
            0x84 => "unsupported protocol version",
            0x85 => "client id not valid",
            0x86 => "bad user name or password",
            0x87 => "not authorized",
            0x88 => "server unavailable",
            0x89 => "server busy",
            0x8A => "banned",
            0x8C => "bad authentication method",
            0x90 => "topic name invalid",
            0x95 => "packet too large",
            0x97 => "quota exceeded",
            0x99 => "payload format invalid",
            0x9A => "retain not supported",
            0x9B => "qos not supported",
            0x9C => "use another server",
            0x9D => "server moved",
            0x9F => "connection rate exceeded",
            _ => "unknown",
        },
    }
}
