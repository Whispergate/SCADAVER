# scadaver-rs

Unified ICS red team multi-tool written in Rust. Supports discovery, enumeration, and
exploitation across ten industrial control protocols.

**License:** [PolyForm Noncommercial 1.0.0](LICENSE) — free for non-commercial use  
**Platform:** Linux / Windows / macOS

---

## Build

```
cargo build --release
```

The binary is `target/release/scadaver` (or `scadaver.exe` on Windows).

---

## Usage

### TUI (interactive)

```
scadaver
```

Launches the full-screen terminal UI. Navigate with arrow keys, enter targets in the
prompt, run scans and exploits from the menu.

**Key bindings (Normal mode):**

| Key | Action |
|-----|--------|
| `A` | Add IP — open target entry prompt |
| `S` | Scan menu — auto-detect or broadcast by protocol |
| `E` | Exploit menu — protocol-aware action list for selected device |
| `W` | References — open ICS vulnerability writeup database overlay |
| `R` | Rescan — re-probe selected device |
| `D` | Delete — remove selected device from the session |
| `/` | Search — filter device list |
| `O` | Zoom — full-screen output panel |
| `C` | Clear output |
| `Z` | Toggle stealth mode (see below) |
| `?` | Help overlay |
| `Q` | Quit |

The TUI stores per-protocol capability hints from scans and uses them to keep actions
visible but disabled when the required service has not been confirmed. Read-only actions
run directly; sensitive reads, long-running maps/monitors, and write/control actions
require typing `YES` before execution.

### CLI

```
scadaver [OPTIONS] <COMMAND>
```

Global options:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ip <IP>` | `-i` | — | Target host IP address |
| `--port <N>` | `-p` | `0` | Override port (0 = protocol default) |
| `--timeout <N>` | `-t` | `5` | Timeout in seconds |
| `--protocol <P>` | — | — | Protocol hint (`beckhoff`, `siemens`, `rockwell`, …) |
| `--stealth` | `-z` | off | Stealth mode: randomised probe order + inter-probe jitter |

Commands: `scan`, `get`, `set`, `run`, `db`, `tui`

Examples:

```bash
# Auto-detect vendor and info for an IP
scadaver -i 192.168.1.100 scan

# Stealth scan — randomised probe order with jitter
scadaver --stealth -i 192.168.1.100 scan

# Broadcast scan for all Rockwell devices on the local segment
scadaver --protocol rockwell scan

# Enumerate Rockwell Logix tags
scadaver -i 192.168.1.50 get tags

# Read Siemens S7 CPU state
scadaver -i 192.168.1.10 get cpu-state

# Send IEC 104 General Interrogation
scadaver -i 192.168.1.200 run iec104-gi

# Modbus write coil
scadaver -i 192.168.1.30 run modbus-write-coil

# Browse ICS vulnerability references (all vendors)
scadaver db refs

# Filter references to Rockwell/Allen-Bradley only
scadaver db refs --vendor rockwell
```

### Local simulator suite

The `sim/` directory contains protocol stubs for local smoke and regression testing.
Use `run_all.py` to start them as one supervised test suite:

```bash
python sim/run_all.py --profile high
```

Profiles:
- `high` avoids privileged ports: Modbus TCP 1502, SLMP TCP 15007, Beckhoff ADS TCP
  14898 plus UDP discovery 48899, Siemens TCP 1102, eWON HTTP 8080.
- `canonical` uses normal protocol ports: Modbus TCP 502, SLMP TCP 5007, Beckhoff ADS
  TCP 48898 plus UDP discovery 48899, Siemens TCP 102, eWON HTTP 80. Ports 80, 102,
  and 502 usually require Administrator/root.

The runner preflights bind conflicts before startup, writes per-simulator logs under
`sim/logs/`, and supports `--host`, `--only`, per-protocol port overrides, `--dry-run`,
and `--install-deps`. Existing PowerShell workflows can call:

```powershell
.\sim\start_all.ps1 -Profile high
```

For end-to-end regression checks, build the Rust binary and run the simulator-backed
smoke suite:

```bash
cargo build
python sim/smoke.py --profile high
```

The smoke suite starts the covered simulators, runs read-only `scadaver` commands, and
fails with captured command output if a protocol path regresses. All ten protocol
families have simulator coverage: Schneider/Modbus, Mitsubishi/SLMP, Beckhoff/ADS,
Siemens/S7Comm, eWON, SNMP, Rockwell/EtherNet/IP, Omron/FINS, IEC 104, and
Phoenix Contact WebVisit.

---

## ICS References Database

scadaver embeds a curated database of ~300 publicly disclosed ICS vulnerability writeups
sourced from [awesome-ics-writeups](https://github.com/neutrinoguy/awesome-ics-writeups).
Entries come from Claroty, ZDI, Nozomi Networks, Microsoft, Dragos, and others.

**TUI:** Press `W` in Normal mode to open a scrollable overlay. When a single-vendor
device is selected, only references for that vendor are shown. When a multi-protocol
device is selected (`vendor = multi`), references for every detected protocol are merged.
Scroll with `J`/`K` or `↑`/`↓`; close with `W` or `ESC`.

**CLI:** `scadaver db refs [--vendor <slug>]`

Valid vendor slugs:

| Slug | Matches |
|------|---------|
| `beckhoff` | Beckhoff, TwinCAT, ADS protocol |
| `siemens` | Siemens, SIMATIC, S7, SCALANCE, SINEC, TIA Portal, PROFINET |
| `schneider` | Schneider Electric, Modicon, M340/M580/M221, EcoStruxure, UMAS |
| `rockwell` | Rockwell, Allen-Bradley, FactoryTalk, RSLogix, ControlLogix |
| `mitsubishi` | Mitsubishi, MELSEC, SLMP, GX Works |
| `omron` | Omron, SYSMAC, CX-Programmer, FINS |
| `phoenix` | Phoenix Contact, ProConOS, PLCnext |
| `ewon` | eWON, HMS Networks |
| `modbus` | Modbus protocol generic |
| `iec104` | IEC 60870-5-104, IEC 62351 |
| `enip` | EtherNet/IP, CIP protocol |
| `snmp` | SNMP |
| `malware` | ICS malware (Triton/TRISIS, Industroyer, PIPEDREAM, Havex, …) |
| `ics-general` | General SCADA / OT security research |
| `general` | Everything else |

Update the database at any time by re-running the fetch script from the repo root:

```bash
python scripts/fetch_refs.py
```

This pulls the latest README from the upstream repo, re-parses, and overwrites
`src/data/references.json`. A rebuild embeds the new data into the binary.

---

## Stealth Mode

By default scadaver fires all ten protocol probes simultaneously from a single source IP,
which is detectable in flow logs as an obvious burst of OT-protocol connections. Stealth
mode reduces that fingerprint for authorized engagements where blend-in matters.

**Enable in CLI:** `scadaver --stealth -i <IP> scan` (or short form `-z`)

**Enable in TUI:** Press `Z` to toggle. The title bar shows `[STEALTH]` when active;
a log line confirms the state change. Toggle off with `Z` again.

**What stealth mode does:**

- Shuffles the ten probe functions into a random order each scan, so no protocol is
  always probed first or last.
- Adds a random 100–400 ms delay between each probe thread spawn, breaking up the
  simultaneous-connection burst. All probes still complete within the scan timeout.

**What it does not do:** change packet content, spoof source addresses, or implement
protocol-level camouflage. For that, see the [Protocol Fingerprint Hardening](#protocol-fingerprint-hardening) section.

---

## Protocol Fingerprint Hardening

Several protocol fields in scanners are static and trivially fingerprint the tool in
packet captures or IDS alerts. scadaver randomises these per connection / per request
so traffic blends with legitimate client behavior:

| Protocol | Field | Before | After |
|----------|-------|--------|-------|
| Modbus TCP | MBAP transaction ID | Always `0x0001` | `rand::random::<u16>()` per request |
| Siemens S7Comm | PDU Reference (Setup) | Always `0x722F` | Random per connection |
| Siemens S7Comm | PDU Reference (SZL) | Always `0x0100` | Random per SZL read |
| Omron FINS | SA1 source node | Always `0x63` (99) | Random non-zero per frame |
| Beckhoff ADS | Route hostname fallback | Literal `"scadaver-rs"` | `WINSTATION` (or OS hostname) |
| IEC 60870-5-104 | TCP close after TESTFR | RST (scanner pattern) | Graceful `shutdown(Both)` → FIN |

These changes are always-on; stealth mode (`-z`) adds the timing layer on top.

---

## Multi-Protocol Detection

When multiple protocol probes return a positive result for the same IP (common with
network gateways, protocol converters, and multi-CPU PLCs), scadaver stores the device
with `vendor = "multi"` and embeds per-protocol sub-records under the `protocols` field.

The TUI detail panel expands each sub-vendor with its own capability block. The exploit
menu's `[V] View as protocol` action lets you override the active vendor to access any
one of the detected protocols' exploit lists. The References overlay merges writeups
from all detected vendors.

---

## Supported Protocols

### Rockwell Allen-Bradley — EtherNet/IP + CIP

**Ports:** TCP 44818 (EtherNet/IP), UDP 44818 (List Identity broadcast)

**Discovery:**
- UDP broadcast `ListIdentity` — returns product name, vendor ID, device type, revision,
  and serial number
- TCP `ListIdentity` for single-IP probing

**Enumeration:**
- Tag enumeration via CIP Get Attribute All (class 0x6B, instance 0)
- Tag read by name via CIP Read Tag Service (service 0x4C)
- Controller identity (vendor, firmware, serial) via CIP identity object

**Exploitation:**
- The TUI marks tag enumeration and monitoring as confirmation-gated because they can be
  long-running, and tag writes require explicit `YES` confirmation.
- Tag write via CIP Write Tag Service (service 0x4D) — any data type including BOOL,
  DINT, REAL, STRING
- `scadaver -i <IP> run rockwell-write-tag`

**Auth:** No authentication in standard CIP. CIP Security (TLS) exists on ControlLogix
v33+ but is rarely deployed and not implemented here.

**Notes:** Vendor ID 1, 5, and 77 are Allen-Bradley / Rockwell Automation. All other
EtherNet/IP vendors are reported as `enip`.

---

### Siemens — S7Comm over ISO-on-TCP (COTP/TPKT)

**Ports:** TCP 102

**Discovery:**
- TCP port 102 probe + COTP connection request, iterating TSAPs for all S7 families:
  - `0x0101` — S7-1200/1500 slot 1
  - `0x0102` — S7-300 slot 2
  - `0x0100` — S7-1200/1500 slot 0
  - `0x0300` — S7-400
- PDU Reference randomised per connection to avoid fixed-invoke-ID IDS signatures.

**Enumeration:**
- CPU state (Running / Startup / Stopped / Hold) via SZL read 0x0424
- Hardware order number (MLFB, e.g. "6ES7 315-2EH14-0AB0") via SZL 0x0011
- Firmware version via SZL 0x0011

**Exploitation:**
- Read/write process image inputs, outputs, and merkers
- Read/write arbitrary data blocks (DB read, DB write)
- CPU Run/Stop toggle via S7Plus SubscriptionContainer sequence
- `scadaver -i <IP> run siemens-cpu-flip`
- `scadaver -i <IP> get io`
- `scadaver -i <IP> run siemens-write-db`

**Auth:** S7-300/400 support 4-level password protection. Password is XOR-encoded
(`byte[i] ^ 0xAA` for even indices, `^ 0x55` for odd) padded to 8 bytes. Use
`set_password(stream, password)` from the Rust API. S7-1200/1500 use S7Plus access
levels (different protocol, not currently implemented).

---

### Beckhoff TwinCAT — ADS over AMS/TCP

**Ports:** UDP 48899 (discovery), TCP 48898 (AMS/TCP), TCP 5120 (CX web/UPnP control)

**Discovery:**
- UDP broadcast to 48899 — returns NetID, device name, TwinCAT version, kernel version
- AMS/TCP framing: 6-byte prefix + LE u32 length at bytes [2..6]
- Targeted scans can fall back to ADS/TCP when UDP discovery is blocked:
  `scadaver --protocol beckhoff -i <IP> scan`
- Route-add packets use the OS hostname (env `COMPUTERNAME` / `HOSTNAME`), falling back
  to `WINSTATION` — never embeds tool-identifying strings.

**Enumeration:**
- ADS state (Running / Config / Stop) via ADS ReadState request (command 0x0004)
- Symbol read by name via ADS ReadWrite (command 0x0009) with symbol lookup
- Symbol table enumeration via ADS Read of `/TC_Config/SumReadEx`

**Exploitation:**
- The TUI marks ADS, UDP discovery, and web-control capabilities separately. ADS actions
  require ADS TCP, route injection requires UDP discovery, and web/UPnP actions require
  the web candidate port.
- Write raw bytes to any named ADS symbol: `scadaver -i <IP> run beckhoff-write-symbol`
- TwinCAT state change (Run / Config / Stop): `scadaver -i <IP> run beckhoff-tc-state`
- CVE-2015-4051: Reboot CX9020 via unauthenticated UPnP/SOAP
- Add admin user to CX9020 via UPnP/SOAP

**Auth:** TwinCAT 3.1 Build 4024+ requires TLS with certificate thumbprint pinning.
The tool collects the thumbprint but does not implement the TLS handshake. Earlier
TwinCAT versions have no authentication.

---

### Schneider Electric — Modbus TCP

**Ports:** TCP 502

**Discovery:**
- Modbus Device Identification (FC 0x2B / MEI 0x0E) — returns manufacturer, product
  name, firmware version
- UDP broadcast to port 1740 for Schneider-specific discovery
- Targeted scans can use UDP discovery, Modbus TCP, or both:
  `scadaver --protocol schneider -i <IP> scan`
- Modbus MBAP transaction ID randomised per request (was always `0x0001`).

**Exploitation:**
- TUI Map Modbus Ranges reads holding/input/coils/discrete-input tables to surface
  readable non-zero values when a register map is not known. Presets are `quick`,
  `common`, and `all`; custom specs use `hr:0:500,ir:0:100,co:0:128,di:0:128`.
  Saved map points are namespaced by table (`HR40001`, `IR30001`, `CO1`, `DI10001`)
  so overlapping Modbus display ranges do not collide in the device database.
  Devices that return `illegal function` for unsupported tables are summarized and
  skipped instead of flooding the output.
- The TUI marks Schneider actions by detected capability: Modbus actions require
  confirmed Modbus TCP, FC90 actions require a matching Modicon family hint, and
  write/control actions require an explicit `YES` confirmation.
- FC5 write single coil: `scadaver -i <IP> run modbus-write-coil`
- FC6 write single holding register: `scadaver -i <IP> run modbus-write-register`
- FC16 write multiple holding registers: `scadaver -i <IP> run modbus-write-registers`
- Flash LED (proprietary FC): `scadaver -i <IP> run schneider-flash`

**Auth:** Modbus TCP has no native authentication.

---

### Schneider — FC90 (Function Code 90)

**Ports:** TCP 502 (same socket as Modbus TCP)

FC90 is a Schneider-proprietary function code that allows unauthenticated PLC control
on M340, Quantum, Premium, and TM221 families.

**Exploitation:**
- STOP PLC: `scadaver -i <IP> run fc90-stop`
- START PLC: `scadaver -i <IP> run fc90-start`
- TM221 STOP: `scadaver -i <IP> run fc90-stop-tm221`
- TM221 START: `scadaver -i <IP> run fc90-start-tm221`
- Force physical output bit: `scadaver -i <IP> run fc90-force`

**Auth:** None. FC90 has no authentication mechanism.

---

### Mitsubishi MELSEC — SLMP / MC Protocol 3E Frame

**Ports:** UDP 5561 (SLMP discovery), UDP 5006 (alternate), TCP 5007 (SLMP TCP)

Targeted scans can use UDP discovery, SLMP TCP, or both:
`scadaver --protocol mitsubishi -i <IP> scan`

**Discovery:**
- SLMP UDP broadcast — returns PLC type and title

**Exploitation:**
- TUI Map SLMP reads word devices (`D/W/R`) and bit devices (`M/X/Y/B`) to surface
  readable non-default values when the device memory map is not known. Presets are
  `quick`, `common`, and `all`; custom specs use `d:0:100,m:0:128,w:0:64`.
- Read D (word) registers: `scadaver -i <IP> get slmp-d`
- Read M (bit) devices: `scadaver -i <IP> get slmp-m`
- Write D (word) registers: `scadaver -i <IP> run slmp-write-d`
- Write M (bit) devices: `scadaver -i <IP> run slmp-write-m`

**Auth:** MELSEC-Q Series has an optional password (4 ASCII chars). Not implemented.

---

### Omron — FINS over TCP/UDP

**Ports:** TCP 9600, UDP 9600

**Discovery / Enumeration:**
- UDP FINS broadcast — returns model number, version, node address
- CPU status read (Memory area read of special registers)
- SA1 (client source node) randomised per frame — was always `0x63` (99).

**Exploitation:**
- Read DM area (data memory) words: `scadaver -i <IP> get omron-dm`
- Write DM area words: `scadaver -i <IP> run omron-write-dm`
- CPU Run: `scadaver -i <IP> run omron-cpu-run`
- CPU Stop: `scadaver -i <IP> run omron-cpu-stop`

**Auth:** FINS has no authentication. Network-level access control only.

---

### HMS eWON Flexy — HTTP + UDP IPCONF Discovery

**Ports:** TCP 80 (HTTP management), UDP 1507 (IPCONF discovery, listen on 1506)

**Discovery:**
- UDP IPCONF broadcast (`IPCONF\x00` prefix) to port 1507 — returns device type, IP
  address, netmask, and MAC address:
  `scadaver --protocol ewon scan`

**Exploitation:**
- CVE-2019-9015: Auth bypass — retrieve all credentials via HTTP POST to
  `/wrcgi.bin/wsdReadForm` without authentication:
  `scadaver -i <IP> run ewon-creds`
- Supports up to `--max-users` accounts (default 20)

**Auth:** eWON firmware ≥ 13.2s0 patched CVE-2019-9015. Earlier versions expose
credentials without authentication.

---

### Phoenix Contact — ProConOS + WebVisit HMI

**Ports:** TCP 1962 (ProConOS binary protocol), TCP 80/8080 (HTTP WebVisit)

**Discovery / Enumeration:**
- HTTP GET to WebVisit endpoint — parses PLC type and firmware
- ILC control protocol on TCP 4000

**Exploitation:**
- CVE-2016-8366: Retrieve plaintext passwords from WebVisit HMI:
  `scadaver -i <IP> run phoenix-passwords`
- CVE-2016-8380: Read/write HMI tag values:
  `scadaver -i <IP> get phoenix-tags`
  `scadaver -i <IP> run phoenix-write-tag`
- PLC control (ILC 150 / ILC 390): cold/warm/hot restart, stop, info:
  `scadaver -i <IP> run phoenix-control`

**Auth:** CVE-2016-8366 and CVE-2016-8380 are unauthenticated vulnerabilities. Patched
in firmware ≥ 2.40 (ILC 150) and ≥ 2.30 (ILC 390).

---

### SNMP — Simple Network Management Protocol

**Ports:** UDP 161

**Discovery:**
- Community string brute-force against a list of common strings (`public`, `private`, etc.)
- sysDescr, sysObjectID, sysName, sysLocation, sysContact, sysUptime enumeration:
  `scadaver --protocol snmp -i <IP> scan`
- Full OID subtree walk:
  `scadaver -i <IP> get snmp-walk`
- Community discovery only:
  `scadaver --protocol snmp scan`

**Enumeration:**
- Interface table (IF-MIB): description, speed, MAC, operational status, error counts
- IP address and routing table (IP-MIB)
- ARP table
- Vendor identification via sysObjectID prefix match (Siemens, Schneider, Rockwell,
  Phoenix Contact, Beckhoff)
- CVE check: known vulnerable firmware versions for Siemens SCALANCE and Schneider

**Auth:** SNMPv1/v2c use community strings (no encryption). SNMPv3 is not implemented.

---

### IEC 60870-5-104

**Ports:** TCP 2404

**Discovery:**
- TESTFR (U-frame) probe — confirms an active IEC 104 outstation without initiating
  data transfer. The probe closes the TCP connection with a graceful FIN (not RST),
  matching legitimate client behavior.

**Enumeration / Exploitation:**
- General Interrogation (C_IC_NA_1 / TypeID 100) — enumerate all reported data objects:
  `scadaver -i <IP> run iec104-gi`
- Single Command ON/OFF (C_SC_NA_1 / TypeID 45):
  `scadaver -i <IP> run iec104-sc-on`
  `scadaver -i <IP> run iec104-sc-off`
- Double Command (C_DC_NA_1 / TypeID 46):
  `scadaver -i <IP> run iec104-dc`

**Auth:** IEC 62351-5 defines HMAC-SHA256 challenge-response authentication for IEC 104.
It is rarely deployed in the field. Not implemented.

---

## Authentication Summary

| Protocol | Auth mechanism | Support |
|---|---|---|
| Rockwell EtherNet/IP | None (CIP Security requires TLS — rare) | N/A |
| Siemens S7-300/400 | 4-level password, XOR-encoded | `set_password()` / `connect_authenticated()` |
| Siemens S7-1200/1500 | S7Plus access levels | Not implemented |
| Beckhoff TwinCAT < 4024 | None | N/A |
| Beckhoff TwinCAT ≥ 4024 | TLS + certificate | Not implemented |
| Schneider Modbus / FC90 | None | N/A |
| Mitsubishi SLMP | Optional 4-char password | Not implemented |
| Omron FINS | None | N/A |
| SNMP | Community string (v1/v2c), USM (v3) | v1/v2c only |
| eWON | HTTP Basic Auth (firmware ≥ 13.2s0) | Not implemented |
| Phoenix Contact | HTTP Basic Auth (patched firmware) | Not implemented |
| IEC 60870-5-104 | IEC 62351-5 HMAC (rarely deployed) | Not implemented |

---

## Library Usage

scadaver-rs exposes its protocol engines as a Rust library crate (`scadaver_rs`) alongside
the CLI binary. Add it as a dependency via git URL:

```toml
[dependencies]
scadaver_rs = { git = "https://github.com/SawyersPresent/scadaver-rs" }
```

Example — scan a Rockwell EtherNet/IP device and read a tag:

```rust
use scadaver_rs::vendors::rockwell::driver;

let device = driver::get_device_info("192.168.1.50", 44818)?;
println!("{} — {}", device.product_name, device.revision);

let tags = driver::enumerate_tags("192.168.1.50", 44818)?;
for tag in &tags {
    let value = driver::read_tag("192.168.1.50", 44818, tag)?;
    println!("{} = {}", tag.name, driver::decode_value(tag.tag_type, &value));
}
```

Example — query embedded ICS references for a vendor:

```rust
use scadaver_rs::references;

for r in references::for_vendor("siemens") {
    println!("[{}] {} — {}", r.source, r.title, r.url);
}
```

Example — enable stealth mode before scanning:

```rust
use scadaver_rs::core::autodetect;

autodetect::set_stealth(true);
let results = autodetect::sweep("192.168.1.100", 8);
```

Public namespaces available:

| Namespace | Protocols |
|---|---|
| `scadaver_rs::vendors::schneider` | Modbus TCP, FC90, UDP discovery |
| `scadaver_rs::vendors::siemens` | S7Comm / ISO-on-TCP |
| `scadaver_rs::vendors::beckhoff` | ADS/AMS, TwinCAT, CX webcontrol |
| `scadaver_rs::vendors::mitsubishi` | SLMP / MC Protocol 3E |
| `scadaver_rs::vendors::omron` | FINS TCP/UDP |
| `scadaver_rs::vendors::rockwell` | EtherNet/IP + CIP |
| `scadaver_rs::vendors::enip` | EtherNet/IP enumerations |
| `scadaver_rs::vendors::ewon` | eWON HTTP exploit + IPCONF scan |
| `scadaver_rs::vendors::phoenix` | ProConOS binary, WebVisit HMI |
| `scadaver_rs::vendors::snmp` | SNMPv1/v2c client, OID constants |
| `scadaver_rs::vendors::iec104` | IEC 60870-5-104 client session |
| `scadaver_rs::core::modbus` | Raw Modbus TCP client primitives |
| `scadaver_rs::core::autodetect` | Multi-protocol sweep, stealth mode |
| `scadaver_rs::core::network` | Interface enumeration, broadcast sockets |
| `scadaver_rs::core::bytes` | Hex/IP utility functions |
| `scadaver_rs::references` | Embedded ICS vulnerability reference database |

---

## Legal

This tool is intended for authorized penetration testing, red team exercises, ICS
security research, and CTF competitions only. Unauthorized use against systems you do
not own or have explicit permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse.
