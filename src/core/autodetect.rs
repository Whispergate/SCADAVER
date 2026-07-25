use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub vendor: String,
    pub ip: String,
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

impl DeviceInfo {
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key)?.as_str()
    }
}

/// Vendor detection priority — lower number = higher confidence.
fn vendor_priority(vendor: &str) -> u8 {
    match vendor {
        "modicon" => 0,
        "beckhoff" | "siemens" | "rockwell" | "ewon" | "mitsubishi" | "schneider"
        | "phoenix" | "omron" => 1,
        "enip" | "iec104" => 2,
        _ => 99,
    }
}

type ProbeFn = Box<dyn Fn(&str) -> Option<DeviceInfo> + Send + Sync>;

fn make_probes() -> Vec<ProbeFn> {
    vec![
        Box::new(probe_beckhoff),
        Box::new(probe_siemens),
        Box::new(probe_enip),
        Box::new(probe_ewon),
        Box::new(probe_mitsubishi),
        Box::new(probe_schneider),
        Box::new(probe_modicon),
        Box::new(probe_phoenix),
        Box::new(probe_omron),
        Box::new(probe_iec104),
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
    Some(DeviceInfo {
        vendor: "beckhoff".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_siemens(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::siemens::scan;
    let result = scan::scan_ip(ip).ok()?;
    if !result.open_ports.contains(&102) {
        return None;
    }
    let cpu_state = result.cpu_state?; // None means device didn't respond to S7Comm
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    if let Some(hw) = result.hardware {
        fields.insert("hardware".into(), hw.into());
    }
    if let Some(fw) = result.firmware {
        fields.insert("firmware".into(), fw.into());
    }
    fields.insert("cpu_state".into(), cpu_state.into());
    fields.insert("open_ports".into(), vec![102i64].into());
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
    fields.insert("plc_type".into(), d.plc_type.into());
    if let Some(title) = d.title {
        fields.insert("title".into(), title.into());
    }
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
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    if let Some(name) = d.name {
        fields.insert("name".into(), name.into());
    }
    if let Some(fw) = d.firmware {
        fields.insert("firmware".into(), fw.into());
    }
    Some(DeviceInfo {
        vendor: "schneider".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_modicon(ip: &str) -> Option<DeviceInfo> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect_timeout(
        &format!("{ip}:502").parse().ok()?,
        Duration::from_secs(3),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok()?;

    // Modbus TCP Read Device Identification (FC 0x2B, MEI 0x0E, basic stream)
    let req = hex::decode("000100000006012b0e0100").unwrap_or_default();
    stream.write_all(&req).ok()?;

    // Read MBAP header (6 bytes): txn_id(2) + protocol_id(2) + length(2)
    let mut mbap = [0u8; 6];
    stream.read_exact(&mut mbap).ok()?;
    if mbap[2..4] != [0x00, 0x00] {
        return None; // not Modbus
    }
    let pdu_len = u16::from_be_bytes([mbap[4], mbap[5]]) as usize;
    if pdu_len < 2 {
        return None;
    }
    let mut pdu = vec![0u8; pdu_len];
    stream.read_exact(&mut pdu).ok()?;
    // pdu[0] = unit_id, pdu[1] = function_code
    if pdu.len() < 2 || pdu[1] != 0x2B {
        return None;
    }

    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("protocol".into(), "Modbus TCP".into());

    // pdu: unit_id(1) + fc(1) + mei_type(1) + read_dev_id_code(1) + conformity(1) +
    //      more_follows(1) + next_obj_id(1) + obj_count(1) + objects...
    if pdu.len() > 8 {
        let obj_count = pdu[8] as usize;
        let mut pos = 9usize;
        for _ in 0..obj_count.min(10) {
            if pos + 2 > pdu.len() {
                break;
            }
            let obj_id = pdu[pos];
            let obj_len = pdu[pos + 1] as usize;
            if pos + 2 + obj_len > pdu.len() {
                break;
            }
            let val = String::from_utf8_lossy(&pdu[pos + 2..pos + 2 + obj_len]).to_string();
            pos += 2 + obj_len;
            match obj_id {
                0x00 => { fields.insert("manufacturer".into(), val.into()); }
                0x01 => { fields.insert("product_name".into(), val.into()); }
                0x02 => { fields.insert("version".into(), val.into()); }
                _ => {}
            }
        }
    }

    Some(DeviceInfo {
        vendor: "modicon".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_phoenix(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::phoenix::control;
    let info = control::get_device_info(ip, true).ok()?;
    if info.plc_type.is_empty() {
        return None;
    }
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("plc_type".into(), info.plc_type.into());
    if let Some(fw) = info.firmware {
        fields.insert("firmware".into(), fw.into());
    }
    Some(DeviceInfo {
        vendor: "phoenix".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_omron(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::omron::scan;
    let dev = scan::scan_ip(ip)?;
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("model".into(), dev.model.into());
    fields.insert("version".into(), dev.version.into());
    fields.insert("node".into(), serde_json::Value::Number(dev.node_addr.into()));
    Some(DeviceInfo {
        vendor: "omron".into(),
        ip: ip.into(),
        fields,
    })
}

fn probe_iec104(ip: &str) -> Option<DeviceInfo> {
    use crate::vendors::iec104::client;
    if !client::probe(ip) {
        return None;
    }
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    fields.insert("port".into(), serde_json::Value::Number(client::IEC104_PORT.into()));
    Some(DeviceInfo {
        vendor: "iec104".into(),
        ip: ip.into(),
        fields,
    })
}

/// Probe all vendors in parallel. Returns the highest-confidence match.
/// Timeout in seconds applies to the overall collection window.
pub fn detect_device(ip: &str, timeout_secs: u64) -> Option<DeviceInfo> {
    use std::sync::mpsc;
    let probes = make_probes();
    let (tx, rx) = mpsc::channel::<DeviceInfo>();

    let _handles: Vec<_> = probes
        .into_iter()
        .map(|probe| {
            let ip = ip.to_string();
            let tx = tx.clone();
            thread::spawn(move || {
                if let Some(info) = probe(&ip) {
                    let _ = tx.send(info);
                }
            })
        })
        .collect();
    drop(tx); // close our copy so channel drains when all threads finish

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut results: Vec<DeviceInfo> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(info) => results.push(info),
            Err(_) => break,
        }
    }

    results
        .iter()
        .min_by_key(|r| vendor_priority(&r.vendor))
        .cloned()
}

// Keep hex module available for decode
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
