# scadaver-rs

Unified ICS red team multi-tool written in Rust. Discovers, enumerates, and exploits
devices across ten industrial control protocols from a single binary with both a
terminal UI and a bloodyAD-style CLI.

**License:** [PolyForm Noncommercial 1.0.0](LICENSE): free for non-commercial use  
**Platform:** Linux / Windows / macOS

---

## Background

Industrial Control Systems (ICS) are networks of hardware and software that run physical
infrastructure - water treatment, power grids, manufacturing lines, oil pipelines. The
devices on these networks were designed decades ago when networking meant a serial cable
between two machines in the same room. Most protocols have no authentication, no
encryption, and no audit logging.

```
  Physical world           Field level           Supervisory level
  ──────────────           ───────────           ─────────────────
  Sensors / actuators ──▶  PLC / RTU  ◀──────▶  SCADA / HMI
  (temp, flow, valves)     (the brain)           (operator screens)
                                │
                         Industrial Ethernet
                         (often flat, no VLAN)
                                │
                         Corporate network ──▶ (sometimes) Internet
```

A **PLC** (Programmable Logic Controller) is the embedded computer that actually closes
relays, reads sensors, and runs the control logic. It communicates over a protocol like
Modbus or S7Comm. A **SCADA** system polls the PLCs, logs values, and lets operators send
commands. An **HMI** is the screen operators look at. An **Engineering Workstation (EWS)**
is where engineers load new PLC programs - usually the highest-value target on the network.

The threat model scadaver-rs addresses: an attacker with access to the industrial network
segment (via VPN, phishing the EWS, or a misconfigured DMZ) who wants to understand what
is running and what can be affected.

### Recommended viewing

Microsoft ICS/OT defense - how defenders use forensics tools to detect exactly the kind
of activity this tool performs:  
[https://www.youtube.com/watch?v=g3KLq_IHId4](https://www.youtube.com/watch?v=g3KLq_IHId4)

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
| `A` | Add IP, open target entry prompt |
| `S` | Scan menu - auto-detect or broadcast by protocol |
| `E` | Exploit menu - protocol-aware action list for selected device |
| `W` | References - open ICS vulnerability writeup database overlay |
| `R` | Rescan - re-probe selected device |
| `D` | Delete - remove selected device from the session |
| `V` | View as protocol - override active vendor on a MULTI device |
| `/` | Search - filter device list |
| `O` | Zoom - full-screen output panel |
| `C` | Clear output |
| `Z` | Toggle stealth mode |
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
| `--ip <IP>` | `-i` | (required) | Target host IP address |
| `--port <N>` | `-p` | `0` | Override port (0 = protocol default) |
| `--timeout <N>` | `-t` | `5` | Timeout in seconds |
| `--protocol <P>` | | | Protocol hint (`beckhoff`, `siemens`, `rockwell`, ...) |
| `--stealth` | `-z` | off | Randomised probe order + inter-probe jitter |

Commands: `scan`, `get`, `set`, `run`, `db`, `tui`, `web`

Examples:

### Web UI

```
scadaver web                            # bind on 127.0.0.1:7443 (defaults)
scadaver web --host 0.0.0.0 --port 8080
```

Launches a browser-based control panel. Authentication:

- A random 32-character hex token is generated at startup and printed to the terminal.
- The browser opens automatically at `http://host:port/?key=<token>` — no manual copy needed.
- REST clients must include `X-API-Key: <token>` on protected endpoints
  (scan, device tags, tag write, and all exploit routes).
- The health check, device list, and device history endpoints do not require the key.
- The token is ephemeral — a new one is generated every run.

```bash
# Auto-detect vendor and enumerate
scadaver -i 192.168.1.100 scan

# Stealth scan - randomised probe order with jitter
scadaver --stealth -i 192.168.1.100 scan

# Broadcast scan for all Rockwell devices on the local segment
scadaver --protocol rockwell scan

# Enumerate all Rockwell Logix tags (scalars + array element [0])
scadaver -i 192.168.1.50 get tags

# Read Siemens S7 CPU state and hardware info
scadaver -i 192.168.1.10 get cpu-state

# IEC 104 General Interrogation - dump all data objects
scadaver -i 192.168.1.200 run iec104-gi

# Modbus write single coil
scadaver -i 192.168.1.30 run modbus-write-coil

# Browse embedded ICS vulnerability references
scadaver db refs
scadaver db refs --vendor rockwell
```

---

## Stealth Mode

By default scadaver fires all ten protocol probes simultaneously, which appears in flow
logs as an obvious burst of OT-protocol connections from a single source. Stealth mode
reduces that timing fingerprint.

**Enable in CLI:** `scadaver --stealth -i <IP> scan` (short: `-z`)  
**Enable in TUI:** Press `Z`. The title bar shows `[STEALTH]` when active.

**What it does:**

1. Shuffles the ten probe functions into a random order each scan - no protocol is
   always probed first or last.
2. Adds a random 100–400 ms delay between each probe spawn - breaks up the
   simultaneous-connection burst. All probes still finish within the scan timeout.

**What it does not do:** change packet content, spoof source addresses, or add protocol-
level camouflage. For that, see [Protocol Fingerprint Hardening](#protocol-fingerprint-hardening).

---

## Protocol Fingerprint Hardening

Several protocol fields were static and trivially fingerprinted the tool in packet
captures or IDS signatures. These are now randomised per connection or per request:

| Protocol | Field | Before | After |
|----------|-------|--------|-------|
| Modbus TCP | MBAP transaction ID | Always `0x0001` | Random per request |
| Siemens S7Comm | PDU Reference (Setup) | Always `0x722F` | Random per connection |
| Siemens S7Comm | PDU Reference (SZL) | Always `0x0100` | Random per SZL read |
| Omron FINS | SA1 source node | Always `0x63` (99) | Random non-zero per frame |
| Beckhoff ADS | Route hostname | Literal `"scadaver-rs"` | `WINSTATION` (or OS hostname) |
| IEC 60870-5-104 | TCP teardown after TESTFR | RST (scanner pattern) | Graceful FIN |

These are always-on. Stealth mode (`-z`) adds the timing layer on top.

---

## Multi-Protocol Detection

When multiple protocol probes succeed for the same IP (common with network gateways,
protocol converters, and multi-CPU racks), scadaver stores the device with
`vendor = "multi"` and embeds per-protocol sub-records.

The TUI detail panel expands each sub-vendor with its own capability block. Press `[V]`
to open the VendorPicker and switch which protocol's exploit list is active. The
References overlay merges writeups from all detected vendors.

---

## ICS References Database

scadaver embeds a curated database of ~300 publicly disclosed ICS vulnerability writeups
sourced from [awesome-ics-writeups](https://github.com/neutrinoguy/awesome-ics-writeups).
Entries come from Claroty, ZDI, Nozomi Networks, Microsoft, Dragos, and others.

**TUI:** Press `W` to open a scrollable overlay. When a single-vendor device is selected,
only that vendor's references are shown. For MULTI devices, all detected vendors are merged.
Scroll with `J`/`K` or arrow keys; close with `W` or `ESC`.

**CLI:** `scadaver db refs [--vendor <slug>]`

| Slug | Covers |
|------|--------|
| `beckhoff` | Beckhoff, TwinCAT, ADS |
| `siemens` | Siemens, SIMATIC, S7, SCALANCE, SINEC, TIA Portal, PROFINET |
| `schneider` | Schneider Electric, Modicon, M340/M580/M221, EcoStruxure, UMAS |
| `rockwell` | Rockwell, Allen-Bradley, FactoryTalk, RSLogix, ControlLogix |
| `mitsubishi` | Mitsubishi, MELSEC, SLMP, GX Works |
| `omron` | Omron, SYSMAC, CX-Programmer, FINS |
| `phoenix` | Phoenix Contact, ProConOS, PLCnext |
| `ewon` | eWON, HMS Networks |
| `modbus` | Modbus protocol (generic) |
| `iec104` | IEC 60870-5-104, IEC 62351 |
| `enip` | EtherNet/IP, CIP |
| `snmp` | SNMP |
| `malware` | ICS malware - Triton/TRISIS, Industroyer, PIPEDREAM, Havoc |
| `ics-general` | General OT/SCADA security research |

Refresh the database from the upstream repo:

```bash
python scripts/fetch_refs.py
```

---

## Test Environments

Two open-source simulation environments are useful for building a realistic test lab:

- **PyScada** - Django-based SCADA platform with Modbus, OPC-UA, VISA, and GPIB I/O.
  Full SCADA stack (historian, HMI, alarms) for exercising scan and enumeration paths:
  <https://pyscada.readthedocs.io/en/main/>

- **Pump Station Simulator** - Python simulation of a real pump-station control program
  (two pumps, level sensor, alarm ladder logic). Emits live Modbus TCP registers at
  realistic process values. Ideal for tag-write and monitor testing without hardware:
  <https://github.com/dscioli/pump-station-simulator>

### Local simulator suite

The `sim/` directory contains lightweight protocol stubs for offline smoke and regression
testing. Start all stubs at once:

```bash
python sim/run_all.py --profile high
```

Profiles:

- `high` - avoids privileged ports: Modbus TCP 1502, SLMP TCP 15007, Beckhoff ADS TCP
  14898 + UDP 48899, Siemens TCP 1102, eWON HTTP 8080.
- `canonical` - standard protocol ports: Modbus 502, SLMP 5007, Beckhoff 48898/48899,
  Siemens 102, eWON 80. Ports 80, 102, and 502 require Administrator/root.

Run simulator-backed smoke tests after building the binary:

```bash
cargo build
python sim/smoke.py --profile high
```

---

## Supported Protocols

---

### Rockwell Allen-Bradley - EtherNet/IP + CIP

**Ports:** TCP 44818, UDP 44818

EtherNet/IP is an ODVA-standard protocol layered on top of TCP/UDP. CIP (Common Industrial
Protocol) is the application layer. Rockwell PLCs - ControlLogix, CompactLogix, MicroLogix -
store all I/O and program data as named tags accessible by any device on the network.

**Discovery:**
1. UDP broadcast `ListIdentity` - returns product name, vendor ID, device type, revision, serial number.
2. TCP `ListIdentity` for single-IP probing.

**Enumeration:**
1. Tag enumeration via CIP service 0x55 on class 0x6B - dumps every tag name, type, and dimension.
2. Tag read by name via CIP Read Tag (service 0x4C). Scalar tags return decoded values;
   1D arrays read element `[0]` and display as `[val, ...]`; struct/UDT tags show `[struct]`.
3. Controller identity - vendor, product name, firmware revision, serial number.

**Exploitation:**
1. Tag write via CIP Write Tag (service 0x4D) - any data type: BOOL, DINT, REAL, STRING.
2. `scadaver -i <IP> run rockwell-write-tag`

**Auth:** No authentication in standard CIP. CIP Security (TLS) exists on ControlLogix
v33+ but is rarely deployed.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| UDP `ListIdentity` broadcast | Low | Firewall/flow logs - normal SCADA startup behavior |
| TCP `ListIdentity` (single IP) | Low | Same as above |
| Tag read (known tag names) | Low | Indistinguishable from SCADA polling |
| Full tag enumeration (service 0x55) | Medium | Long CIP session; Studio 5000 does this on connect but SCADA masters don't |
| Tag write from non-SCADA IP | High | PLC does not log writes, but historian shows value jump; IDS on flow |
| Repeated connection/disconnect | Medium | Netflow shows session bursts from new IP |

---

### Siemens - S7Comm over ISO-on-TCP (COTP/TPKT)

**Ports:** TCP 102

S7Comm is Siemens' proprietary protocol used by S7-300, S7-400, S7-1200, and S7-1500 PLCs.
It runs inside COTP (ISO transport) inside TPKT, all over TCP port 102. The protocol is
layered - you must complete the TCP, COTP, and S7 handshakes before reading any data.
A TSAP (Transport Service Access Point) identifies the rack and slot of the target CPU.

**Discovery:**
1. TCP port 102 probe + COTP connection request, iterating TSAPs for all S7 families:
   `0x0101` (S7-1200/1500 slot 1), `0x0102` (S7-300 slot 2), `0x0100`, `0x0300` (S7-400).
2. PDU Reference randomised per connection.

**Enumeration:**
1. CPU state (Running / Startup / Stopped / Hold) via SZL read 0x0424.
2. Hardware order number (MLFB, e.g. `6ES7 315-2EH14-0AB0`) via SZL 0x0011.
3. Firmware version via SZL 0x0011.

**Exploitation:**
1. Read/write process image inputs, outputs, and merkers.
2. Read/write arbitrary data blocks (DB read, DB write).
3. CPU Run/Stop toggle.
4. `scadaver -i <IP> run siemens-cpu-flip`
5. `scadaver -i <IP> get io`
6. `scadaver -i <IP> run siemens-write-db`

**Auth:** S7-300/400 support 4-level password protection (XOR-encoded, 8 bytes). S7-1200/1500
use S7Plus access levels (different protocol, not currently implemented).

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| COTP connection + S7 Setup | Low | Normal EWS connect sequence |
| SZL reads (identity/firmware) | Low–Medium | Happens at EWS startup; rarely from SCADA masters |
| Read Var (I/O, DB) | Low | Indistinguishable from SCADA polling |
| Write Var from non-EWS IP | High | No PLC audit log on S7-300/400; historian value jump; IDS |
| CPU Stop command | Critical | SCADA loses comms immediately; operator alarm; TIA Portal event log |
| CPU Start command | High | Historian gap + restart event |
| Hardcoded PDU reference (fixed invoke ID) | Medium | IDS signatures for specific tools; now randomised |

---

### Beckhoff TwinCAT - ADS over AMS/TCP

**Ports:** UDP 48899 (discovery), TCP 48898 (AMS/TCP)

ADS (Automation Device Specification) is Beckhoff's proprietary protocol. Every TwinCAT
device has an AMS Net ID - a 6-byte address that looks like an IP but isn't
(e.g. `192.168.1.100.1.1`). Devices exchange data using Index Group and Index Offset
addressing into the PLC's symbol table. No authentication on older TwinCAT versions.

**Discovery:**
1. UDP broadcast to port 48899 - returns NetID, device name, TwinCAT version, kernel version.
2. AMS/TCP fallback when UDP is blocked: `scadaver --protocol beckhoff -i <IP> scan`
3. Route-add packets identify the client by hostname - uses the OS hostname or `WINSTATION`,
   never embeds tool-identifying strings.

**Enumeration:**
1. ADS state (Running / Config / Stop) via ADS ReadState (command 0x0004).
2. Symbol read by name via ADS ReadWrite (command 0x0009).
3. Symbol table enumeration via ADS Read of `/TC_Config/SumReadEx`.

**Exploitation:**
1. Write raw bytes to any named ADS symbol: `scadaver -i <IP> run beckhoff-write-symbol`
2. TwinCAT state change (Run / Config / Stop): `scadaver -i <IP> run beckhoff-tc-state`
3. CVE-2015-4051: Reboot CX9020 via unauthenticated UPnP/SOAP.
4. Add admin user to CX9020 via UPnP/SOAP.

**Auth:** TwinCAT 3.1 Build 4024+ requires TLS with certificate thumbprint pinning.
Earlier versions have no authentication.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| UDP discovery broadcast | Low | Normal when TwinCAT Engineering connects |
| ADS ReadState | Low | Common health-check |
| Symbol table enumeration | Medium | Not routine from production SCADA; TwinCAT event viewer |
| ADS write to symbol | High | TwinCAT event log; historian value jump |
| TwinCAT Stop/Config state | Critical | Runtime halts; all I/O freezes; TwinCAT event log; SCADA alarm |
| Hostname `"scadaver-rs"` in route-add | High | Appears in AMS routing table - obvious tool identifier; now `WINSTATION` |

---

### Schneider Electric - Modbus TCP

**Ports:** TCP 502

Modbus TCP is the oldest and most widely deployed ICS protocol. It wraps the original
serial Modbus protocol in a thin TCP header (MBAP - Modbus Application Protocol). There
are four memory areas: Coils (1-bit R/W), Discrete Inputs (1-bit R), Holding Registers
(16-bit R/W), and Input Registers (16-bit R). There is no authentication, no encryption,
and no concept of authorisation.

**Discovery:**
1. Modbus Device Identification (FC 0x2B / MEI 0x0E) - returns manufacturer, product name, firmware.
2. UDP broadcast to port 1740 for Schneider-specific discovery.

**Exploitation:**
1. FC5 write single coil: `scadaver -i <IP> run modbus-write-coil`
2. FC6 write single holding register: `scadaver -i <IP> run modbus-write-register`
3. FC16 write multiple holding registers: `scadaver -i <IP> run modbus-write-registers`
4. Flash LED (proprietary FC): `scadaver -i <IP> run schneider-flash`

TUI Map Modbus Ranges reads all four table types to surface non-zero values when a
register map is not known. Presets: `quick`, `common`, `all`. Custom:
`hr:0:500,ir:0:100,co:0:128,di:0:128`.

**Auth:** None. Modbus TCP has no authentication mechanism.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| FC01/02/03/04 reads (known ranges) | Low | Indistinguishable from SCADA polling |
| FC43 Device Identification read | Low–Medium | Normal at commissioning; SCADA masters rarely send this in production |
| Full register sweep (all ranges) | Medium | Netflow: long session with many requests; IDS pattern match |
| FC05/06/16 write from non-SCADA IP | High | Historian value jump; no PLC audit log; IDS |
| MBAP transaction ID = `0x0001` always | Medium | Tool fingerprint in PCAP; now randomised |
| Unit ID 0xFF (broadcast) | Medium | Not normal in production; most PLCs respond anyway |

---

### Schneider - FC90 (Function Code 90)

**Ports:** TCP 502 (same socket as Modbus TCP)

FC90 is a Schneider-proprietary function code that provides unauthenticated PLC control
on M340, Quantum, Premium, and TM221 families. It is carried inside a standard Modbus
frame, so it is invisible to firewalls that only block non-502 ports.

**Exploitation:**
1. STOP PLC: `scadaver -i <IP> run fc90-stop`
2. START PLC: `scadaver -i <IP> run fc90-start`
3. TM221 STOP: `scadaver -i <IP> run fc90-stop-tm221`
4. TM221 START: `scadaver -i <IP> run fc90-start-tm221`
5. Force physical output bit: `scadaver -i <IP> run fc90-force`

**Auth:** None. FC90 has no authentication.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| FC90 STOP/START | Critical | PLC stops; SCADA loses comms immediately; operator alarm |
| FC90 on port 502 | Medium | Looks like a Modbus packet to port-level firewalls; FC90 is unusual on DPI |
| Force output bit | High | Physical effect visible; historian records the value change |

---

### Mitsubishi MELSEC - SLMP / MC Protocol 3E Frame

**Ports:** UDP 5561 (discovery), UDP 5006, TCP 5007

SLMP (Seamless Message Protocol) is Mitsubishi's Ethernet protocol for iQ-R, Q-series,
and FX-series PLCs. Data is addressed by device type and offset: `D` (data registers),
`M` (internal relays), `X`/`Y` (inputs/outputs), `W` (link registers), `R` (file registers).
The 3E frame format is the most common: subheader `0x5000` (binary) or `QnA` (ASCII).

**Discovery:**
1. SLMP UDP broadcast - returns PLC type and title.

**Exploitation:**
1. Read D (word) registers: `scadaver -i <IP> get slmp-d`
2. Read M (bit) devices: `scadaver -i <IP> get slmp-m`
3. Write D registers: `scadaver -i <IP> run slmp-write-d`
4. Write M devices: `scadaver -i <IP> run slmp-write-m`

TUI Map SLMP reads word and bit devices to surface non-default values. Presets: `quick`,
`common`, `all`. Custom: `d:0:100,m:0:128,w:0:64`.

**Auth:** MELSEC-Q Series has an optional 4-character ASCII password. Not implemented.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| UDP discovery broadcast | Low | Normal for GX Works on startup |
| Batch Read (0x0401) D/W registers | Low | Indistinguishable from SCADA polling |
| Full device memory sweep | Medium | Netflow: large number of reads; unusual device count |
| Batch Write (0x1401) from non-SCADA IP | High | Historian; physical effect |
| Remote Stop/Run (0x1003/0x1001) | Critical | PLC halts; SCADA alarm; GX Works event log |

---

### Omron - FINS over TCP/UDP

**Ports:** TCP 9600, UDP 9600

FINS (Factory Interface Network Service) is Omron's proprietary protocol for SYSMAC PLCs.
It uses node addressing rather than IP addressing - each device has a node number (1–254)
on the network. Commands identify source (SA1) and destination (DA1) node addresses.
No authentication.

**Discovery/Enumeration:**
1. UDP FINS broadcast - returns model number, firmware version, node address.
2. CPU status read via special register read.
3. SA1 (source node) randomised per frame - was always `0x63`.

**Exploitation:**
1. Read DM area words: `scadaver -i <IP> get omron-dm`
2. Write DM area words: `scadaver -i <IP> run omron-write-dm`
3. CPU Run: `scadaver -i <IP> run omron-cpu-run`
4. CPU Stop: `scadaver -i <IP> run omron-cpu-stop`

**Auth:** No authentication. Network-level access control only.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| Memory Area Read (0101) | Low | Indistinguishable from SCADA |
| Model info read | Low–Medium | CX-Programmer does this on connect |
| SA1 = 0x63 (hardcoded) | Medium | FINS node table; known tool fingerprint; now randomised |
| SA1 = even number | Medium | Invalid - Omron nodes are odd-numbered |
| Memory Area Write (0102) | High | Historian; physical effect |
| CPU Stop (0402) | Critical | PLC halts; SCADA alarm; Omron event log |

---

### HMS eWON Flexy - HTTP + IPCONF Discovery

**Ports:** TCP 80 (HTTP), UDP 1507 (IPCONF discovery)

eWON Flexy is an industrial VPN gateway made by HMS Networks. It bridges OT networks
to cloud services (Talk2M) and is often internet-facing by design. The IPCONF protocol
allows unauthenticated device discovery by UDP broadcast.

**Discovery:**
1. UDP IPCONF broadcast (`IPCONF\x00` prefix) to port 1507 - returns device type, IP, netmask, MAC.

**Exploitation:**
1. CVE-2019-9015: Auth bypass - retrieve all stored credentials via HTTP POST to
   `/wrcgi.bin/wsdReadForm` without authentication.
   `scadaver -i <IP> run ewon-creds`

**Auth:** eWON firmware >= 13.2s0 patched CVE-2019-9015. Older versions expose credentials
unauthenticated.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| IPCONF UDP broadcast | Low | Not logged by the eWON itself |
| HTTP GET to management interface | Low | Web server access log |
| CVE-2019-9015 POST to `/wrcgi.bin/wsdReadForm` | High | Web server access log; unusual endpoint; WAF if present |
| Successful credential extract | High | No eWON-side alert on unpatched firmware |

---

### Phoenix Contact - ProConOS + WebVisit HMI

**Ports:** TCP 1962 (ProConOS), TCP 80/8080 (WebVisit HMI)

Phoenix Contact ILC/RFC PLCs run ProConOS as the runtime. WebVisit is the browser-based
HMI that exposes tag values and alarms. Older firmware exposed credentials and tag writes
without authentication.

**Discovery/Enumeration:**
1. HTTP GET to WebVisit endpoint - parses PLC type and firmware version.
2. ILC control protocol on TCP 4000.

**Exploitation:**
1. CVE-2016-8366: Retrieve plaintext credentials from WebVisit.
   `scadaver -i <IP> run phoenix-passwords`
2. CVE-2016-8380: Read/write HMI tag values.
   `scadaver -i <IP> get phoenix-tags`
   `scadaver -i <IP> run phoenix-write-tag`
3. PLC control (cold/warm/hot restart, stop, info):
   `scadaver -i <IP> run phoenix-control`

**Auth:** CVE-2016-8366 and CVE-2016-8380 are unauthenticated. Patched in firmware >= 2.40
(ILC 150) and >= 2.30 (ILC 390).

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| HTTP GET to WebVisit index | Low | Web server access log |
| CVE-2016-8366 password endpoint | High | Unusual URL; web server log; IDS |
| Tag write via CVE-2016-8380 | High | HMI audit log (if enabled); historian |
| PLC restart via ProConOS | Critical | PLC halts; SCADA alarm; restart logged |

---

### SNMP - Simple Network Management Protocol

**Ports:** UDP 161

SNMP is a network management protocol present on almost every managed network device,
many PLCs, and most industrial switches. Version 1 and 2c use community strings
(effectively plaintext passwords) for access. v3 adds authentication and encryption but
is rarely deployed on OT devices.

**Discovery:**
1. Community string probe against common strings (`public`, `private`, etc.).
2. sysDescr, sysObjectID, sysName, sysLocation, sysContact, sysUptime enumeration.
3. Full OID subtree walk: `scadaver -i <IP> get snmp-walk`
4. Broadcast community discovery: `scadaver --protocol snmp scan`

**Enumeration:**
1. Interface table (IF-MIB): description, speed, MAC, operational status, error counts.
2. IP address and routing table (IP-MIB).
3. ARP table.
4. Vendor identification via sysObjectID prefix.
5. Known vulnerable firmware version check for Siemens SCALANCE and Schneider.

**Auth:** SNMPv1/v2c use community strings. SNMPv3 not implemented.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| Read with correct community string | Low | Indistinguishable from NMS polling |
| Community string brute-force | High | SNMP auth failure log; IDS |
| Full OID walk (many GETs) | Medium | Netflow: sustained UDP 161 from new IP |
| SNMP write (SetRequest) | High | Device may log; physical config change |

---

### IEC 60870-5-104

**Ports:** TCP 2404

IEC 60870-5-104 (IEC 104) is the standard protocol for power grid SCADA - substations,
RTUs, protection relays. Data objects are identified by Information Object Addresses (IOA).
A STARTDT frame begins the data transfer phase; a General Interrogation request dumps all
current values. Control commands trip breakers, open valves, and set setpoints.

**Discovery:**
1. TESTFR (U-frame) probe confirms an active outstation without initiating data transfer.
   The probe closes with a graceful FIN (was RST - a scanner fingerprint, now fixed).

**Enumeration/Exploitation:**
1. General Interrogation (C_IC_NA_1 / TypeID 100) - all reported data objects:
   `scadaver -i <IP> run iec104-gi`
2. Single Command ON/OFF (C_SC_NA_1 / TypeID 45):
   `scadaver -i <IP> run iec104-sc-on` / `iec104-sc-off`
3. Double Command (C_DC_NA_1 / TypeID 46):
   `scadaver -i <IP> run iec104-dc`

**Auth:** IEC 62351-5 defines HMAC-SHA256 challenge-response. Rarely deployed. Not implemented.

**OPSEC:**

| Operation | Noise level | Where traces appear |
|-----------|-------------|---------------------|
| TESTFR probe (graceful FIN) | Low | Firewall log - matches legitimate keepalive |
| TESTFR probe (RST close) | Medium | Scanner pattern in PCAP; now fixed |
| STARTDT from unknown IP | Medium | SCADA masters are fixed IPs; new source is unusual |
| General Interrogation (TypeID 100) | Medium | Normal at connection start; suspicious mid-session from new IP |
| Single/Double Command from non-SCADA IP | Critical | Physical effect (breaker trip); RTU sequence number log; SCADA alarm |

---

## Authentication Summary

| Protocol | Auth mechanism | Status |
|----------|---------------|--------|
| Rockwell EtherNet/IP | None (CIP Security/TLS exists but rarely deployed) | N/A |
| Siemens S7-300/400 | 4-level password, XOR-encoded | `set_password()` / `connect_authenticated()` |
| Siemens S7-1200/1500 | S7Plus access levels | Not implemented |
| Beckhoff TwinCAT < 4024 | None | N/A |
| Beckhoff TwinCAT >= 4024 | TLS + certificate | Not implemented |
| Schneider Modbus / FC90 | None | N/A |
| Mitsubishi SLMP | Optional 4-char password | Not implemented |
| Omron FINS | None | N/A |
| SNMP | Community string (v1/v2c) | Implemented |
| eWON | HTTP Basic Auth (>= firmware 13.2s0) | Not implemented |
| Phoenix Contact | HTTP Basic Auth (patched firmware) | Not implemented |
| IEC 60870-5-104 | IEC 62351-5 HMAC (rarely deployed) | Not implemented |

---

## Library Usage

scadaver-rs exposes its protocol engines as a Rust library crate. Add as a dependency:

```toml
[dependencies]
scadaver_rs = { git = "https://github.com/SawyersPresent/scadaver-rs" }
```

Example - scan a Rockwell device and read tags:

```rust
use scadaver_rs::vendors::rockwell::driver;

let device = driver::get_device_info("192.168.1.50", 44818)?;
println!("{}: {}", device.product_name, device.revision);

let tags = driver::enumerate_tags("192.168.1.50", 44818)?;
for tag in &tags {
    let value = driver::read_tag("192.168.1.50", 44818, &tag.name)?;
    println!("{} = {}", tag.name, driver::decode_value(tag.tag_type, &value, None));
}
```

Example - query the embedded ICS reference database:

```rust
use scadaver_rs::references;

for r in references::for_vendor("siemens") {
    println!("[{}] {} | {}", r.source, r.title, r.url);
}
```

Example - enable stealth mode before sweeping:

```rust
use scadaver_rs::core::autodetect;

autodetect::set_stealth(true);
let results = autodetect::sweep("192.168.1.100", 8);
```

Public namespaces:

| Namespace | Protocols |
|-----------|-----------|
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

This tool is for authorized penetration testing, red team exercises, ICS security
research, and CTF competitions only. Unauthorized use against systems you do not own
or have explicit written permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse.
