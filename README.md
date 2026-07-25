# scadaver-rs

Unified ICS red team multi-tool written in Rust. Supports discovery, enumeration, and
exploitation across ten industrial control protocols.

**License:** GPL-3.0-or-later  
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

**Ports:** UDP 48899 (discovery), TCP 48898 (AMS/TCP)

**Discovery:**
- UDP broadcast to 48899 — returns NetID, device name, TwinCAT version, kernel version
- AMS/TCP framing: 6-byte prefix + LE u32 length at bytes [2..6]

**Enumeration:**
- ADS state (Running / Config / Stop) via ADS ReadState request (command 0x0004)
- Symbol read by name via ADS ReadWrite (command 0x0009) with symbol lookup
- Symbol table enumeration via ADS Read of `/TC_Config/SumReadEx`

**Exploitation:**
- Write raw bytes to any named ADS symbol: `scadaver exploit beckhoff-write-symbol
  --target <IP> MAIN.valve=01`
- TwinCAT state change (Run / Config / Stop): `scadaver control beckhoff-tc
  --target <IP> --state run`
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

**Exploitation:**
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

**Discovery:**
- SLMP UDP broadcast — returns PLC type and title

**Exploitation:**
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

### HMS eWON Flexy — Proprietary UDP Discovery

**Ports:** UDP broadcast on standard interfaces

**Discovery:**
- Broadcasts a proprietary discovery datagram — returns device name, MAC address, serial
  number

**Exploitation:**
- CVE-2019-9015: Auth bypass — retrieve all credentials from `/ExportAccount`:
  `scadaver exploit ewon-creds --target <IP>`
- Supports up to `--max-users` accounts (default 20)

**Auth:** eWON firmware ≥ 13.2s0 patched CVE-2019-9015. Earlier versions expose
credentials without authentication.

---

### Phoenix Contact — ILC WebVisit HMI

**Ports:** TCP 80 (HTTP WebVisit), TCP 4000 (ILC proprietary)

**Discovery / Enumeration:**
- HTTP GET to WebVisit endpoint — parses PLC type and firmware
- ILC control protocol on TCP 4000

**Exploitation:**
- CVE-2016-8366: Retrieve plaintext passwords from WebVisit HMI:
  `scadaver exploit phoenix-passwords --target <IP>`
- CVE-2016-8380: Read/write HMI tag values:
  `scadaver exploit phoenix-tags --target <IP> --read`
  `scadaver exploit phoenix-tags --target <IP> --write TAG=value`
- PLC control (ILC 150 / ILC 390): cold/warm/hot restart, stop, info:
  `scadaver control phoenix --target <IP> --model ilc150 --action stop`

**Auth:** CVE-2016-8366 and CVE-2016-8380 are unauthenticated vulnerabilities. Patched
in firmware ≥ 2.40 (ILC 150) and ≥ 2.30 (ILC 390).

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
| eWON | HTTP Basic Auth (firmware ≥ 13.2s0) | Not implemented |
| Phoenix Contact | HTTP Basic Auth (patched firmware) | Not implemented |
| IEC 60870-5-104 | IEC 62351-5 HMAC (rarely deployed) | Not implemented |

---

## Legal

This tool is intended for authorized penetration testing, red team exercises, ICS
security research, and CTF competitions only. Unauthorized use against systems you do
not own or have explicit permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse.
