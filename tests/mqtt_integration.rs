// Live-broker integration tests for the MQTT session and probe APIs.
//
// Guard: set TEST_MQTT_HOST to the broker IP/hostname to enable.
// Tests return early (pass silently) when the env var is absent.
//
// Run locally:
//   $env:TEST_MQTT_HOST="localhost"; cargo test --test mqtt_integration

use scadaver::vendors::mqtt::client::{self, MQTT_PORT};
use scadaver::vendors::mqtt::session::{ConnectOptions, MqttSession};
use std::thread;
use std::time::Duration;

fn broker_host() -> Option<String> {
    std::env::var("TEST_MQTT_HOST").ok()
}

// ── Probe ─────────────────────────────────────────────────────────────────────

#[test]
fn live_probe_returns_anonymous_device() {
    let Some(host) = broker_host() else { return };
    let dev = client::probe(&host, MQTT_PORT);
    assert!(dev.is_some(), "probe should return a device on an open broker");
    let dev = dev.unwrap();
    assert!(dev.anonymous, "broker should accept anonymous connections");
    assert_eq!(dev.port, MQTT_PORT);
}

#[test]
fn live_sys_topic_recon() {
    let Some(host) = broker_host() else { return };
    let dev = client::probe(&host, MQTT_PORT)
        .expect("probe must succeed against TEST_MQTT_HOST");
    // mosquitto and amqtt both publish $SYS/broker/* as retained topics.
    // If broker_info is Some, verify the topic prefix.
    if let Some(info) = &dev.broker_info {
        assert!(
            info.starts_with("$SYS/broker"),
            "broker_info should start with '$SYS/broker', got: {info}"
        );
    }
}

// ── Session connect / disconnect ──────────────────────────────────────────────

#[test]
fn live_session_connect_and_disconnect() {
    let Some(host) = broker_host() else { return };
    let opts = ConnectOptions {
        host: host.clone(),
        port: MQTT_PORT,
        client_id: "scadaver-test-connect".into(),
        ..ConnectOptions::default()
    };
    let session = MqttSession::connect(&opts).expect("connect should succeed");
    session.disconnect().expect("disconnect should succeed");
}

// ── Subscribe / publish ───────────────────────────────────────────────────────

#[test]
fn live_subscribe_publish_and_receive() {
    const TOPIC: &str = "scadaver/test/subpub";
    const PAYLOAD: &[u8] = b"hello-integration";
    let Some(host) = broker_host() else { return };
    let opts = ConnectOptions {
        host: host.clone(),
        port: MQTT_PORT,
        client_id: "scadaver-test-subpub".into(),
        ..ConnectOptions::default()
    };
    let mut session = MqttSession::connect(&opts).expect("connect should succeed");

    session.subscribe(TOPIC, 0).expect("subscribe should succeed");
    // Brief pause lets the SUBSCRIBE reach the broker before we publish.
    thread::sleep(Duration::from_millis(150));
    session.publish(TOPIC, PAYLOAD, 0, false).expect("publish should succeed");
    // Reader thread polls every 100 ms; give it a full window.
    thread::sleep(Duration::from_millis(500));

    let msgs = session.drain_messages();
    let found = msgs.iter().any(|m| m.topic == TOPIC && m.payload == PAYLOAD);
    assert!(found, "should receive back the published message; got {} message(s)", msgs.len());

    session.disconnect().expect("disconnect should succeed");
}

#[test]
fn live_unsubscribe_stops_delivery() {
    const TOPIC: &str = "scadaver/test/unsub";
    let Some(host) = broker_host() else { return };
    let opts = ConnectOptions {
        host: host.clone(),
        port: MQTT_PORT,
        client_id: "scadaver-test-unsub".into(),
        ..ConnectOptions::default()
    };
    let mut session = MqttSession::connect(&opts).expect("connect should succeed");

    session.subscribe(TOPIC, 0).expect("subscribe should succeed");
    thread::sleep(Duration::from_millis(150));
    session.unsubscribe(TOPIC).expect("unsubscribe should succeed");
    thread::sleep(Duration::from_millis(150));
    session.publish(TOPIC, b"should-not-arrive", 0, false).expect("publish should succeed");
    thread::sleep(Duration::from_millis(500));

    let msgs = session.drain_messages();
    let relevant: Vec<_> = msgs.iter().filter(|m| m.topic == TOPIC).collect();
    assert!(
        relevant.is_empty(),
        "should receive no messages after unsubscribe; got {} relevant message(s)",
        relevant.len()
    );

    session.disconnect().expect("disconnect should succeed");
}

// ── Credential test ───────────────────────────────────────────────────────────

#[test]
fn live_try_credential_anonymous_broker() {
    let Some(host) = broker_host() else { return };
    // An anonymous broker should accept empty credentials (Some(true)).
    let result = client::try_credential(&host, MQTT_PORT, "", "");
    assert_eq!(
        result,
        Some(true),
        "anonymous broker should accept empty credentials"
    );
}
