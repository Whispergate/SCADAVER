use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static STEALTH_MODE: AtomicBool = AtomicBool::new(false);

/// Enable or disable stealth scanning: randomised probe order + inter-probe jitter.
pub fn set_stealth(enabled: bool) {
    STEALTH_MODE.store(enabled, Ordering::Relaxed);
}

/// Returns true when stealth mode is active.
pub fn stealth_enabled() -> bool {
    STEALTH_MODE.load(Ordering::Relaxed)
}

/// The result of vendor autodetection: the identified vendor slug, target IP, and a flattened
/// map of vendor-specific fields (ports, identity strings, capability flags).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub vendor: String,
    pub ip: String,
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

/// Implemented by vendor device structs to convert themselves into the unified [`DeviceInfo`] type.
/// Use `#[derive(scadaver_macros::IntoDeviceInfo)]` (with the `macros` feature) to generate this
/// automatically from struct field annotations.
pub trait IntoDeviceInfo {
    /// The short vendor slug used as `DeviceInfo::vendor` (e.g. `"beckhoff"`, `"siemens"`).
    const VENDOR_SLUG: &'static str;
    /// Consume the vendor struct and produce a [`DeviceInfo`].
    fn into_device_info(self) -> DeviceInfo;
}

/// Vendor detection priority: lower number = higher confidence.
fn vendor_priority(vendor: &str) -> u8 {
    match vendor {
        "modicon" => 0,
        "beckhoff" | "siemens" | "rockwell" | "ewon" | "mitsubishi" | "schneider" | "phoenix"
        | "omron" => 1,
        "enip" | "iec104" => 2,
        "snmp" => 3,
        _ => 99,
    }
}

type ProbeFn = Box<dyn Fn(&str) -> Option<DeviceInfo> + Send + Sync>;

/// Display metadata for one protocol probe in an auto-sweep.
#[derive(Clone, Copy)]
pub struct ProbeInfo {
    pub label: &'static str,
    pub transport: &'static str,
}

/// One protocol's result from `sweep`: what was probed and what (if anything) responded.
pub struct SweepOutcome {
    pub probe: ProbeInfo,
    pub device: Option<DeviceInfo>,
}

fn make_probes() -> Vec<(ProbeInfo, ProbeFn)> {
    vec![
        (
            ProbeInfo { label: "Beckhoff ADS", transport: "UDP 48899 / TCP 48898" },
            Box::new(probe_beckhoff),
        ),
        (
            ProbeInfo { label: "Siemens S7", transport: "TCP 102" },
            Box::new(probe_siemens),
        ),
        (
            ProbeInfo { label: "EtherNet/IP", transport: "TCP 44818" },
            Box::new(probe_enip),
        ),
        (
            ProbeInfo { label: "eWON", transport: "UDP 1507" },
            Box::new(probe_ewon),
        ),
        (
            ProbeInfo { label: "Mitsubishi MELSEC", transport: "UDP 5561 / TCP 5007" },
            Box::new(probe_mitsubishi),
        ),
        (
            ProbeInfo { label: "Schneider Modbus", transport: "TCP 502 / UDP" },
            Box::new(probe_schneider),
        ),
        (
            ProbeInfo { label: "Phoenix Contact", transport: "TCP 1962" },
            Box::new(probe_phoenix),
        ),
        (
            ProbeInfo { label: "Omron FINS", transport: "TCP/UDP 9600" },
            Box::new(probe_omron),
        ),
        (
            ProbeInfo { label: "IEC 60870-5-104", transport: "TCP 2404" },
            Box::new(probe_iec104),
        ),
        (
            ProbeInfo { label: "SNMP", transport: "UDP 161" },
            Box::new(probe_snmp),
        ),
    ]
}

fn probe_beckhoff(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::beckhoff::scan;
    let devices = scan::discover_ip(ip, 2, true).ok()?;
    let d = devices.into_iter().next()?;
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("name".into(), d.name.into());
    fields.insert("netid".into(), d.netid_str.into());
    fields.insert("tc_version".into(), d.tc_version.into());
    fields.insert("kernel".into(), d.kernel.into());
    fields.insert("port".into(), 48898i64.into());
    fields.insert("ads_port".into(), 48898i64.into());
    fields.insert(
        "web_port".into(),
        i64::from(crate::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT).into(),
    );
    fields.insert("discovery_port".into(), 48899i64.into());
    fields.insert("discovery_transport".into(), "udp".into());
    fields.insert("protocol".into(), "ads_tcp".into());
    fields.insert("cap_ads_tcp".into(), true.into());
    fields.insert("cap_ads_udp_discovery".into(), true.into());
    fields.insert("cap_beckhoff_web_candidate".into(), true.into());
    Some(DeviceInfo {
        vendor: "beckhoff".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_siemens(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::siemens::s7comm;
    use std::net::TcpStream;

    // Budget: 3s TCP probe + 2s per S7Comm read ≤ 7s total, within detect_device's 8s window.
    // tcp_scan uses a 1-second timeout that may miss WAN targets; probe directly here.
    TcpStream::connect_timeout(&format!("{ip}:102").parse().ok()?, Duration::from_secs(3)).ok()?;

    // S7-1500 with S7comm+ or access protection: setup_connection succeeds on the first
    // TSAP (c2020101) but SZL reads may return "Unknown": still identify the device.
    let (hardware, firmware, cpu_state) = s7comm::get_device_snapshot(ip, 102, 2);

    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    if let Some(hw) = hardware {
        fields.insert("hardware".into(), hw.into());
    }
    if let Some(fw) = firmware {
        fields.insert("firmware".into(), fw.into());
    }
    fields.insert("cpu_state".into(), cpu_state.into());
    fields.insert("port".into(), 102i64.into());
    fields.insert("s7_port".into(), 102i64.into());
    fields.insert("open_ports".into(), vec![102i64].into());
    fields.insert("cap_s7_tcp".into(), true.into());
    Some(DeviceInfo {
        vendor: "siemens".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_enip(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::enip::scan;
    let devices = scan::scan_ip(ip, 2, true).ok()?;
    let d = devices.into_iter().next()?;

    let vendor_id = u32::from_str_radix(&d.vendor_id, 16).unwrap_or(0);
    let vendor_name = if [1u32, 5, 77].contains(&vendor_id) {
        "rockwell"
    } else {
        "enip"
    };

    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("product_name".into(), d.product_name.into());
    fields.insert("vendor_id".into(), d.vendor_id.into());
    fields.insert("device_type".into(), d.device_type.into());
    fields.insert("revision".into(), d.revision.into());
    fields.insert("port".into(), 44818i64.into());
    fields.insert("enip_port".into(), 44818i64.into());
    fields.insert("cap_enip_tcp_identity".into(), true.into());
    Some(DeviceInfo {
        vendor: vendor_name.into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_ewon(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::ewon::scan;
    let devices = scan::scan_ip(ip, 2, true).ok()?;
    let d = devices.into_iter().next()?;
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    if let Some(mac) = d.mac {
        fields.insert("mac".into(), mac.into());
    }
    if let Some(serial) = d.serial {
        fields.insert("serial".into(), serial.into());
    }
    fields.insert("http_port".into(), 80i64.into());
    fields.insert("cap_ewon_ipconf".into(), true.into());
    fields.insert("cap_ewon_http_candidate".into(), true.into());
    Some(DeviceInfo {
        vendor: "ewon".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_mitsubishi(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::mitsubishi::scan;
    let devices = scan::scan_ip(ip, 2, true).ok()?;
    let d = devices.into_iter().next()?;
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    let protocol = d.protocol.clone().unwrap_or_default();
    let discovery_transport = d.discovery_transport.clone().unwrap_or_default();
    fields.insert("plc_type".into(), d.plc_type.into());
    if let Some(title) = d.title {
        fields.insert("title".into(), title.into());
    }
    if let Some(comment) = d.comment {
        fields.insert("comment".into(), comment.into());
    }
    if let Some(protocol) = d.protocol {
        fields.insert("protocol".into(), protocol.into());
    }
    if let Some(port) = d.port {
        if matches!(d.discovery_transport.as_deref(), Some("tcp")) {
            fields.insert("port".into(), i64::from(port).into());
            fields.insert("slmp_port".into(), i64::from(port).into());
        } else {
            fields.insert("port".into(), 5007i64.into());
            fields.insert("discovery_port".into(), i64::from(port).into());
            fields.insert("slmp_port".into(), 5007i64.into());
        }
    } else {
        fields.insert("port".into(), 5007i64.into());
        fields.insert("slmp_port".into(), 5007i64.into());
    }
    if let Some(transport) = d.discovery_transport {
        fields.insert("discovery_transport".into(), transport.into());
    }
    fields.insert("cap_mitsubishi_identity".into(), true.into());
    fields.insert(
        "cap_gxworks_udp".into(),
        (protocol == "gxworks_udp" || discovery_transport == "udp").into(),
    );
    fields.insert(
        "cap_slmp_tcp".into(),
        (protocol == "slmp_tcp" || discovery_transport == "tcp").into(),
    );
    fields.insert("cap_slmp_udp".into(), (protocol == "slmp_udp").into());
    Some(DeviceInfo {
        vendor: "mitsubishi".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_schneider(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::schneider::scan;
    let devices = scan::scan_ip(ip, 3, true).ok()?;
    let d = devices.into_iter().next()?;
    if !d.identity_match {
        return None;
    }
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    let name_for_family = d.name.clone().unwrap_or_default();
    let identity_confirmed = d.identity_match
        || (matches!(d.discovery_transport.as_deref(), Some("udp"))
            && (d.name.is_some() || d.firmware.is_some()));
    let modbus_tcp_confirmed = d.protocol.as_deref() == Some("modbus_tcp") || d.port.is_some();
    let udp_confirmed =
        matches!(d.discovery_transport.as_deref(), Some("udp")) && identity_confirmed;
    if let Some(name) = d.name {
        fields.insert("name".into(), name.into());
    }
    if let Some(fw) = d.firmware {
        fields.insert("firmware".into(), fw.into());
    }
    if let Some(protocol) = d.protocol {
        fields.insert("protocol".into(), protocol.into());
    }
    if let Some(port) = d.port {
        fields.insert("port".into(), i64::from(port).into());
        fields.insert("modbus_port".into(), i64::from(port).into());
    } else {
        fields.insert("modbus_port".into(), 502i64.into());
    }
    if let Some(transport) = d.discovery_transport {
        fields.insert("discovery_transport".into(), transport.into());
    }
    if let Some(unit_id) = d.modbus_unit_id {
        fields.insert("modbus_unit_id".into(), i64::from(unit_id).into());
    }
    if identity_confirmed {
        fields.insert("web_port".into(), 80i64.into());
    }
    fields.insert("cap_identity_confirmed".into(), identity_confirmed.into());
    fields.insert("cap_schneider_udp".into(), udp_confirmed.into());
    fields.insert("cap_modbus_tcp".into(), modbus_tcp_confirmed.into());
    fields.insert(
        "fc90_family".into(),
        schneider_fc90_family(&name_for_family).into(),
    );
    Some(DeviceInfo {
        vendor: "schneider".into(),
        ip: ip.into(),
        fields,
    })
}

fn schneider_fc90_family(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    if name.contains("tm221") {
        "tm221"
    } else if name.contains("m340")
        || name.contains("quantum")
        || name.contains("premium")
        || name.contains("m580")
    {
        "m340_quantum_premium"
    } else {
        "unknown"
    }
}

fn probe_phoenix(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::phoenix::control;
    let info = control::get_device_info(ip, 0, true).ok()?;
    if info.plc_type.is_empty() {
        return None;
    }
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("plc_type".into(), info.plc_type.into());
    if let Some(fw) = info.firmware {
        fields.insert("firmware".into(), fw.into());
    }
    fields.insert("port".into(), 1962i64.into());
    fields.insert("phoenix_info_port".into(), 1962i64.into());
    fields.insert("webvisit_port".into(), 80i64.into());
    fields.insert("cap_phoenix_info".into(), true.into());
    fields.insert("cap_webvisit_candidate".into(), true.into());
    Some(DeviceInfo {
        vendor: "phoenix".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_omron(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::omron::{fins, scan};
    let (dev, tcp_confirmed) = match fins::get_device_info_tcp(ip, 0) {
        Ok(dev) => (dev, true),
        Err(_) => (scan::scan_ip(ip)?, false),
    };
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("model".into(), dev.model.into());
    fields.insert("version".into(), dev.version.into());
    fields.insert(
        "node".into(),
        serde_json::Value::Number(dev.node_addr.into()),
    );
    fields.insert("port".into(), 9600i64.into());
    fields.insert("fins_port".into(), 9600i64.into());
    fields.insert("cap_fins_tcp".into(), tcp_confirmed.into());
    fields.insert("cap_fins_udp".into(), (!tcp_confirmed).into());
    fields.insert(
        "discovery_transport".into(),
        if tcp_confirmed { "tcp" } else { "udp" }.into(),
    );
    Some(DeviceInfo {
        vendor: "omron".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_iec104(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::iec104::client;
    if !client::probe(ip, 0) {
        return None;
    }
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert(
        "port".into(),
        serde_json::Value::Number(client::IEC104_PORT.into()),
    );
    fields.insert(
        "iec104_port".into(),
        serde_json::Value::Number(client::IEC104_PORT.into()),
    );
    fields.insert("cap_iec104_tcp".into(), true.into());
    Some(DeviceInfo {
        vendor: "iec104".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_snmp(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::snmp::{client, oids};

    // Try common community strings; 4-second UDP timeout per attempt
    let community = client::discover_community(ip, 0)?;

    // Fetch the four most useful scalar OIDs in one round-trip
    let sys_oids = [oids::SYS_DESCR, oids::SYS_OBJECT_ID, oids::SYS_NAME, oids::SYS_LOCATION];
    let results = client::get_multi(ip, 0, &community, &sys_oids).ok()?;
    let at = |i: usize| results.get(i).map(|(_, v)| v.display()).unwrap_or_default();

    let sys_descr = at(0);
    let sys_oid = at(1);
    let sys_name = at(2);
    let sys_location = at(3);

    let is_apc = sys_oid.starts_with(oids::APC_ROOT);

    // If sysObjectID maps to a known ICS vendor, return that vendor slug so the
    // device appears in the correct exploit list; otherwise fall through as "snmp".
    let vendor = oids::vendor_from_sys_oid(&sys_oid).unwrap_or("snmp");

    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("snmp_community".into(), community.clone().into());
    fields.insert("sys_descr".into(), sys_descr.into());
    fields.insert("sys_object_id".into(), sys_oid.into());
    fields.insert("sys_name".into(), sys_name.into());
    fields.insert("sys_location".into(), sys_location.into());
    fields.insert("port".into(), serde_json::Value::Number(client::SNMP_PORT.into()));
    fields.insert("snmp_port".into(), serde_json::Value::Number(client::SNMP_PORT.into()));
    fields.insert("cap_snmp_udp".into(), true.into());
    if is_apc {
        fields.insert("cap_snmp_apc".into(), true.into());
    }

    Some(DeviceInfo { vendor: vendor.into(), ip: ip.into(), fields })
}

/// Probe all protocol families in parallel against a single IP.
///
/// Returns one `SweepOutcome` per protocol in probe order, each carrying the
/// probe metadata and the `DeviceInfo` that responded (or `None` on no response).
/// `timeout_secs` bounds the overall collection window; probes still running when
/// it elapses are reported as non-responding.
pub fn sweep(ip: &str, timeout_secs: u64) -> Vec<SweepOutcome> {
    use rand::Rng;
    use std::sync::mpsc;

    let mut probes = make_probes();
    let stealth = stealth_enabled();
    if stealth {
        probes.shuffle(&mut rand::thread_rng());
    }
    let count = probes.len();
    let metas: Vec<ProbeInfo> = probes.iter().map(|(meta, _)| *meta).collect();
    let (tx, rx) = mpsc::channel::<(usize, Option<DeviceInfo>)>();

    for (idx, (_, probe)) in probes.into_iter().enumerate() {
        // In stealth mode add random jitter between each probe spawn to break up the burst.
        if stealth && idx > 0 {
            thread::sleep(Duration::from_millis(
                rand::thread_rng().gen_range(100..=400),
            ));
        }
        let ip = ip.to_string();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((idx, probe(&ip)));
        });
    }
    drop(tx); // close our copy so the channel drains when all threads finish

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut devices: Vec<Option<DeviceInfo>> = vec![None; count];
    let mut received = 0usize;
    while received < count {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok((idx, device)) => {
                devices[idx] = device;
                received += 1;
            }
            Err(_) => break,
        }
    }

    metas
        .into_iter()
        .zip(devices)
        .map(|(probe, device)| SweepOutcome { probe, device })
        .collect()
}

/// Probe all vendors in parallel. Returns the highest-confidence match.
/// Timeout in seconds applies to the overall collection window.
pub fn detect_device(ip: &str, timeout_secs: u64) -> Option<DeviceInfo> {
    sweep(ip, timeout_secs)
        .into_iter()
        .filter_map(|outcome| outcome.device)
        .min_by_key(|r| vendor_priority(&r.vendor))
}

/// Probe all vendors in parallel. Returns every protocol that responded (one entry per service).
pub fn probe_all(ip: &str, timeout_secs: u64) -> Vec<DeviceInfo> {
    sweep(ip, timeout_secs)
        .into_iter()
        .filter_map(|outcome| outcome.device)
        .collect()
}

