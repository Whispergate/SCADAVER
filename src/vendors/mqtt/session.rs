//! Persistent MQTT 3.1.1 session over raw `TcpStream`.
//!
//! Complements the single-shot probe in `client.rs` with a keep-alive connection
//! that supports subscribe, unsubscribe, and publish.  A background reader thread
//! drains incoming PUBLISH packets into a shared queue; the main thread handles
//! all writes.

use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
/// The reader thread owns a `try_clone` of the `TcpStream` and feeds every
/// incoming PUBLISH into the shared message queue.  The main thread owns the
/// write side and serialises all outgoing packets.
pub struct MqttSession {
    write_stream: TcpStream,
    messages: Arc<Mutex<VecDeque<MqttMessage>>>,
    subscriptions: Vec<String>,
    packet_id: u16,
    _reader: JoinHandle<()>,
}

impl MqttSession {
    /// Connect to the broker.  Returns `Err` on TCP failure or a non-zero
    /// CONNACK return code.
    pub fn connect(opts: &ConnectOptions) -> Result<Self> {
        let addr = format!("{}:{}", opts.host, opts.port);
        let mut stream =
            TcpStream::connect_timeout(&addr.parse().context("invalid address")?, Duration::from_secs(10))
                .with_context(|| format!("TCP connect to {addr}"))?;

        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;

        let pkt = build_connect(opts);
        stream.write_all(&pkt).context("send CONNECT")?;

        let (ack_flags, rc) = parse_connack_stream(&mut stream)?;
        if rc != 0x00 {
            anyhow::bail!(
                "CONNACK refused: 0x{rc:02x} ({}) session_present={}",
                connack_reason(rc),
                ack_flags & 0x01
            );
        }

        // Longer timeout after handshake; reader sets its own short one.
        stream.set_read_timeout(Some(Duration::from_mins(1)))?;

        let read_stream = stream.try_clone().context("TcpStream::try_clone")?;
        let messages: Arc<Mutex<VecDeque<MqttMessage>>> = Arc::default();
        let reader_q = Arc::clone(&messages);

        let reader = thread::Builder::new()
            .name("mqtt-reader".into())
            .spawn(move || reader_loop(read_stream, &reader_q))?;

        Ok(Self {
            write_stream: stream,
            messages,
            subscriptions: Vec::new(),
            packet_id: 1,
            _reader: reader,
        })
    }

    /// Subscribe to `topic` at the requested `QoS` (0–2).
    pub fn subscribe(&mut self, topic: &str, qos: u8) -> Result<()> {
        let id = self.next_id();
        self.write_stream.write_all(&build_subscribe(id, topic, qos)).context("SUBSCRIBE")?;
        if !self.subscriptions.iter().any(|s| s == topic) {
            self.subscriptions.push(topic.to_string());
        }
        Ok(())
    }

    /// Unsubscribe from `topic`.
    pub fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        let id = self.next_id();
        self.write_stream.write_all(&build_unsubscribe(id, topic)).context("UNSUBSCRIBE")?;
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
        self.write_stream
            .write_all(&build_publish(id, topic, payload, qos, retain))
            .context("PUBLISH")?;
        Ok(())
    }

    /// Send a PINGREQ to keep the connection alive.
    pub fn ping(&mut self) -> Result<()> {
        self.write_stream.write_all(&[0xC0, 0x00]).context("PINGREQ")?;
        Ok(())
    }

    /// Topics currently subscribed on this session.
    pub fn subscriptions(&self) -> &[String] {
        &self.subscriptions
    }

    /// Drain all messages queued by the reader thread.
    pub fn drain_messages(&self) -> Vec<MqttMessage> {
        self.messages.lock().map_or_else(|_| Vec::new(), |mut q| q.drain(..).collect())
    }

    /// Send a DISCONNECT packet and close the session.
    pub fn disconnect(mut self) -> Result<()> {
        self.write_stream.write_all(&[0xE0, 0x00]).context("DISCONNECT")?;
        Ok(())
    }

    fn next_id(&mut self) -> u16 {
        let id = self.packet_id;
        // Wrap around at 65535 back to 1 (packet ID 0 is reserved for QoS 0 PUBLISH).
        self.packet_id = self.packet_id.wrapping_add(1).max(1);
        id
    }
}

// ── Reader thread ─────────────────────────────────────────────────────────────

fn reader_loop(mut stream: TcpStream, q: &Arc<Mutex<VecDeque<MqttMessage>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    loop {
        let mut type_byte = [0u8; 1];
        match stream.read_exact(&mut type_byte) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
        let fixed = type_byte[0];
        let packet_type = (fixed >> 4) & 0x0F;
        let qos = (fixed >> 1) & 0x03;
        let retain = fixed & 0x01 != 0;

        let Ok(remaining_len) = decode_remaining_length(&mut stream) else { break };
        if remaining_len > 65_536 {
            break;
        }
        let mut body = vec![0u8; remaining_len];
        if stream.read_exact(&mut body).is_err() {
            break;
        }

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
        // SUBACK (9), UNSUBACK (11), PINGRESP (13): silently discarded.
    }
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

fn decode_remaining_length(stream: &mut TcpStream) -> Result<usize> {
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
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(2 + s.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

fn build_connect(opts: &ConnectOptions) -> Vec<u8> {
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
    if opts.password.is_some() {
        flags |= 0x40;
    }

    let [kh, kl] = opts.keepalive.to_be_bytes();
    let mut var_header =
        vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, flags, kh, kl];

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
        payload.extend_from_slice(&utf8_field(p));
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

fn parse_connack_stream(stream: &mut TcpStream) -> Result<(u8, u8)> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).context("CONNACK read")?;
    if buf[0] != 0x20 || buf[1] != 0x02 {
        anyhow::bail!("expected CONNACK (0x20 0x02), got 0x{:02x} 0x{:02x}", buf[0], buf[1]);
    }
    Ok((buf[2], buf[3])) // (ack_flags, return_code)
}

fn connack_reason(code: u8) -> &'static str {
    match code {
        0x00 => "accepted",
        0x01 => "unacceptable protocol version",
        0x02 => "identifier rejected",
        0x03 => "server unavailable",
        0x04 => "bad username or password",
        0x05 => "not authorized",
        _ => "unknown",
    }
}
