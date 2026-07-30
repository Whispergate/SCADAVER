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

The TUI stores per-protocol capability hints from scans and uses them to keep actions
visible but disabled when the required service has not been confirmed. Read-only actions
run directly; sensitive reads, long-running maps/monitors, and write/control actions
require typing `YES` before execution.

### CLI

```
scadaver <COMMAND> [SUBCOMMAND] [OPTIONS]
```

Top-level commands: `scan`, `control`, `exploit`, `rockwell`, `siemens`, `phoenix`,
`omron`, `iec104`.

Examples:

```bash
# Auto-detect vendor and info for an IP
scadaver scan auto --ip 192.168.1.100

# Enumerate Rockwell Logix tags
scadaver rockwell tags --target 192.168.1.50

# Read Siemens S7 CPU state
scadaver siemens cpu --target 192.168.1.10

# Send IEC 104 General Interrogation
scadaver iec104 gi --target 192.168.1.200

# Modbus write coil
scadaver exploit modbus-write-coil --target 192.168.1.30 --address 0 --state on
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
- `scadaver rockwell write --target <IP> TAG=HEXVALUE [TAG=HEXVALUE ...]`

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

**Enumeration:**
- CPU state (Running / Startup / Stopped / Hold) via SZL read 0x0424
- Hardware order number (MLFB, e.g. "6ES7 315-2EH14-0AB0") via SZL 0x0011
- Firmware version via SZL 0x0011

**Exploitation:**
- Read/write process image inputs, outputs, and merkers
- Read/write arbitrary data blocks (DB read, DB write)
- CPU Run/Stop toggle via S7Plus SubscriptionContainer sequence
- `scadaver siemens cpu --target <IP> [--flip]`
- `scadaver siemens io --target <IP>`
- `scadaver siemens write-db --target <IP> --db <N> --offset <N> <HEXDATA>`

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
  `scadaver scan beckhoff --ip <IP> --port 48898`

**Enumeration:**
- ADS state (Running / Config / Stop) via ADS ReadState request (command 0x0004)
- Symbol read by name via ADS ReadWrite (command 0x0009) with symbol lookup
- Symbol table enumeration via ADS Read of `/TC_Config/SumReadEx`

**Exploitation:**
- The TUI marks ADS, UDP discovery, and web-control capabilities separately. ADS actions
  require ADS TCP, route injection requires UDP discovery, and web/UPnP actions require
  the web candidate port.
- Write raw bytes to any named ADS symbol: `scadaver exploit beckhoff-write-symbol
  --target <IP> MAIN.valve=01`
- TwinCAT state change (Run / Config / Stop): `scadaver control beckhoff-tc
  --target <IP> --state run`
- CVE-2015-4051: Reboot CX9020 via unauthenticated UPnP/SOAP
- Add admin user to CX9020 via UPnP/SOAP
- ADS actions use the ADS port; CX web/UPnP actions use the web-control port.

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
  `scadaver scan schneider --ip <IP> --transport tcp --port 1502`

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
- FC5 write single coil: `scadaver exploit modbus-write-coil`
- FC6 write single holding register: `scadaver exploit modbus-write-register`
- FC16 write multiple holding registers: `scadaver exploit modbus-write-registers`
- Flash LED (proprietary FC): `scadaver exploit schneider-flash`

**Auth:** Modbus TCP has no native authentication.

---

### Schneider — FC90 (Function Code 90)

**Ports:** TCP 502 (same socket as Modbus TCP)

FC90 is a Schneider-proprietary function code that allows unauthenticated PLC control
on M340, Quantum, Premium, and TM221 families.

**Exploitation:**
- STOP PLC: `scadaver exploit fc90-stop --target <IP>`
- START PLC: `scadaver exploit fc90-start --target <IP>`
- TM221 STOP: `scadaver exploit fc90-stop-tm221`
- TM221 START: `scadaver exploit fc90-start-tm221`
- Force physical output bit: `scadaver exploit fc90-force --target <IP>
  --output 0x11 --state on`

**Auth:** None. FC90 has no authentication mechanism.

---

### Mitsubishi MELSEC — SLMP / MC Protocol 3E Frame

**Ports:** UDP 5561 (SLMP discovery), UDP 5006 (alternate), TCP 5007 (SLMP TCP)

Targeted scans can use UDP discovery, SLMP TCP, or both:
`scadaver scan mitsubishi --ip <IP> --transport tcp --port 5007`

**Discovery:**
- SLMP UDP broadcast — returns PLC type and title

**Exploitation:**
- TUI Map SLMP reads word devices (`D/W/R`) and bit devices (`M/X/Y/B`) to surface
  readable non-default values when the device memory map is not known. Presets are
  `quick`, `common`, and `all`; custom specs use `d:0:100,m:0:128,w:0:64`.
- Read D (word) registers: `scadaver exploit slmp-read-d --target <IP>
  --start 0 --count 10`
- Read M (bit) devices: `scadaver exploit slmp-read-m --target <IP>
  --start 0 --count 16`
- Write D (word) registers: `scadaver exploit slmp-write-d --target <IP>
  --start 0 100,200`
- Write M (bit) devices: `scadaver exploit slmp-write-m --target <IP>
  --start 0 0110`

**Auth:** MELSEC-Q Series has an optional password (4 ASCII chars). Not implemented.

---

### Omron — FINS over TCP/UDP

**Ports:** TCP 9600, UDP 9600

**Discovery / Enumeration:**
- UDP FINS broadcast — returns model number, version, node address
- CPU status read (Memory area read of special registers)

**Exploitation:**
- Read DM area (data memory) words: `scadaver omron read-dm --target <IP>`
- Write DM area words: `scadaver omron write-dm --target <IP> --start 0 100,200`
- CPU Run: `scadaver omron cpu-run --target <IP>`
- CPU Stop: `scadaver omron cpu-stop --target <IP>`

**Auth:** FINS has no authentication. Network-level access control only.

**Notes:** The FINS UDP scan reads `SA1` (source node) from the server response at byte
offset 7. The `DA1` field (byte 4) is the client's own node address.

---

### HMS eWON Flexy — HTTP + UDP IPCONF Discovery

**Ports:** TCP 80 (HTTP management), UDP 1507 (IPCONF discovery, listen on 1506)

**Discovery:**
- UDP IPCONF broadcast (`IPCONF\x00` prefix) to port 1507 — returns device type, IP
  address, netmask, and MAC address:
  `scadaver scan ewon -i <IP>`

**Exploitation:**
- CVE-2019-9015: Auth bypass — retrieve all credentials via HTTP POST to
  `/wrcgi.bin/wsdReadForm` without authentication:
  `scadaver exploit ewon-creds --target <IP>`
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
  `scadaver exploit phoenix-passwords --target <IP> [--port 8080]`
- CVE-2016-8380: Read/write HMI tag values:
  `scadaver exploit phoenix-tags --target <IP> [--port 8080] --read`
  `scadaver exploit phoenix-tags --target <IP> [--port 8080] --write TAG=value`
- PLC control (ILC 150 / ILC 390): cold/warm/hot restart, stop, info:
  `scadaver control phoenix --target <IP> --model ilc150 --action stop`

**Auth:** CVE-2016-8366 and CVE-2016-8380 are unauthenticated vulnerabilities. Patched
in firmware ≥ 2.40 (ILC 150) and ≥ 2.30 (ILC 390).

---

### SNMP — Simple Network Management Protocol

**Ports:** UDP 161

**Discovery:**
- Community string brute-force against a list of common strings (`public`, `private`, etc.)
- sysDescr, sysObjectID, sysName, sysLocation, sysContact, sysUptime enumeration:
  `scadaver snmp enum --target <IP>`
- Full OID subtree walk:
  `scadaver snmp walk --target <IP> --oid 1.3.6.1.2.1.1`
- Community discovery only:
  `scadaver snmp scan --target <IP>`

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
  data transfer

**Enumeration / Exploitation:**
- General Interrogation (C_IC_NA_1 / TypeID 100) — enumerate all reported data objects:
  `scadaver iec104 gi --target <IP>`
- Single Command ON/OFF (C_SC_NA_1 / TypeID 45):
  `scadaver iec104 sc-on --target <IP> --ioa 1001`
  `scadaver iec104 sc-off --target <IP> --ioa 1001`
- Double Command (C_DC_NA_1 / TypeID 46):
  `scadaver iec104 dc --target <IP> --ioa 1001 --state 2`

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
| `scadaver_rs::core::network` | Interface enumeration, broadcast sockets |
| `scadaver_rs::core::bytes` | Hex/IP utility functions |

---

## Legal

This tool is intended for authorized penetration testing, red team exercises, ICS
security research, and CTF competitions only. Unauthorized use against systems you do
not own or have explicit permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse.
