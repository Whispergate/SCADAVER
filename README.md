# scadaver

> Unified ICS red team multi-tool - Rust edition.

[![License: PolyForm Noncommercial 1.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

**Experimental.** This tool is built from publicly available ICS protocol documentation, CVE advisories, and open-source security research. Direct access to hardware for testing is limited, so behavior on specific device models or firmware versions may differ from what is documented here. If you have access to ICS test equipment and can verify, correct, or extend any module, contributions are very welcome please open an issue or pull request.

Discovers, enumerates, and exploits devices across twelve industrial control protocols.
Single binary with a terminal UI, bloodyAD-style CLI, and REST web interface.


---

## Features

- Active fingerprint and passive scan across 12 ICS protocols
- TUI, CLI, and REST web interface in one binary
- Authenticated and unauthenticated exploitation paths
- Protocol fingerprint randomisation - always-on, no flags needed
- Ephemeral-token web API - no credential file, no config
- ~300-entry ICS CVE reference database built in
- Local simulator suite (`sim/`) for safe offline testing
- Usable as a Rust library (`scadaver` crate)

---

## Install

**From crates.io (recommended):**
```sh
cargo install scadaver
```

**From source:**
```sh
git clone https://github.com/Whispergate/SCADAVER
cd scadaver
cargo build --release
# binary: target/release/scadaver
```

---

## Quick Start

```sh
scadaver scan                                       # sweep local network, all protocols
scadaver scan --protocol siemens -i 10.0.0.50       # targeted S7 fingerprint
scadaver get io -i 10.0.0.50 --protocol siemens     # read digital I/O state
scadaver run fc90-stop -i 192.168.1.10              # unauthenticated Schneider stop
scadaver tui                                        # interactive terminal UI
scadaver web --host 0.0.0.0 --port 8080             # REST API + browser UI
```

---

## Supported Protocols

| Protocol | Vendor | Port(s) | Discovery | Exploitation | Auth |
|---|---|---|---|---|---|
| S7Comm / ISO-TCP | Siemens | TCP 102 | COTP fingerprint, PDU info | I/O and DB r/w, CPU start/stop, password spray | optional password |
| ADS/AMS | Beckhoff TwinCAT | UDP 48899, TCP 48898 | broadcast NetID | run/config state, symbol r/w, add route | none (pre-4024) |
| Modbus TCP | Schneider / generic | TCP 502 | FC43 Device ID, UDP 1740 | FC1/3/4/5/6/16, false-data injection, rogue server | none |
| FC90 | Schneider M340/TM221 | TCP 502 | function-code probe | stop, start, force output bit | none |
| EtherNet/IP + CIP | Rockwell Allen-Bradley | TCP/UDP 44818 | ListIdentity broadcast | tag enumeration, tag r/w | none |
| SLMP / MC 3E | Mitsubishi MELSEC | UDP 5561, TCP 5007 | UDP broadcast | D/M register r/w | none |
| FINS | Omron SYSMAC | TCP/UDP 9600 | UDP broadcast | DM area r/w, CPU state | none |
| HTTP + IPCONF | HMS eWON Flexy | TCP 80, UDP 1507 | IPCONF UDP broadcast | auth-bypass credential extract (CVE-2019-9015) | HTTP Basic |
| ProConOS + WebVisit | Phoenix Contact | TCP 1962, 80/8080 | HTTP probe | password retrieval (CVE-2016-8366), tag r/w | HTTP Basic |
| SNMPv2c | generic | UDP 161 | community scan | GET, GETNEXT, walk, SET | community string |
| IEC 60870-5-104 | generic RTU/relay | TCP 2404 | TESTFR probe | GI dump, single command, double command | none |
| HTTP Basic | generic | TCP 80/443/8080 | TCP connect | default-cred spray, Shellshock (CVE-2014-6271) | configurable |

### Protocol Fingerprint Hardening

Six fields that previously fingerprinted the tool are randomised per-connection: Modbus MBAP
transaction ID, two Siemens S7Comm PDU references, Omron FINS SA1 source node, Beckhoff ADS
route hostname (OS hostname, never the tool name), and IEC 104 teardown (graceful FIN instead
of RST). These are always-on. Stealth mode (`-z`) adds probe-order shuffle and 100-400 ms
inter-probe jitter on top.

---

## Interfaces

### TUI

```sh
scadaver tui
```

| Key | Action |
|-----|--------|
| `A` | Add IP |
| `S` | Scan menu |
| `E` | Exploit menu |
| `W` | References overlay |
| `R` | Rescan selected device |
| `D` | Delete selected device |
| `V` | VendorPicker (for multi-protocol devices) |
| `/` | Search / filter device list |
| `O` | Zoom output panel |
| `C` | Clear output |
| `Z` | Toggle stealth mode |
| `?` | Help overlay |
| `Q` | Quit |

Sensitive and write actions require typing `YES` before execution. When multiple protocols
respond for the same IP, the device is stored as `multi` and `V` switches which protocol's
exploit list is active.

---

### CLI

```sh
scadaver [OPTIONS] <COMMAND>
```

**Global flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ip <IP>` | `-i` | | Target host IP |
| `--port <N>` | `-p` | `0` | Override port (0 = protocol default) |
| `--timeout <N>` | `-t` | `5` | Timeout in seconds |
| `--protocol <P>` | | | Protocol hint (`siemens`, `rockwell`, `beckhoff`, ...) |
| `--stealth` | `-z` | off | Randomised probe order + inter-probe jitter |

**`scan`** - probe for ICS devices on the local segment or a single IP

**`get` nouns:**

| Noun | Description |
|------|-------------|
| `info` | Device identity and firmware (`--protocol` required) |
| `state` | CPU run/stop/monitor state |
| `io` | Siemens S7 digital inputs, outputs, merkers |
| `tags` | Tag or symbol list |
| `tag <name>` | Read one named tag |
| `register [start] [count]` | Modbus holding registers (FC3) |
| `input-register [start] [count]` | Modbus input registers (FC4) |
| `coil [start] [count]` | Modbus coils (FC1) |
| `dm [start] [count]` | Omron FINS DM area words |
| `db <db> [offset] [len]` | Siemens S7 data block bytes |
| `d [start] [count]` | Mitsubishi SLMP D word registers |
| `m [start] [count]` | Mitsubishi SLMP M bit devices |
| `community` | SNMP community string probe |
| `oid <oid> [-c community]` | SNMP GET single OID |
| `walk <oid> [-c community]` | SNMP GETNEXT walk |
| `enum` | SNMP system info, interfaces, topology |
| `gi` | IEC 104 General Interrogation |
| `creds` | eWON auth-bypass credential extract |
| `session` | Schneider legacy web-session compatibility check |

**`set` nouns:**

| Noun | Description |
|------|-------------|
| `state <state>` | CPU state: run/stop/monitor/config/flip (`--protocol` required) |
| `tag <NAME=HEXBYTES>` | Write one tag |
| `register <address> <value>` | Modbus holding register (FC6) |
| `registers <start> <values>` | Multiple Modbus holding registers (FC16) |
| `coil <address> <on\|off>` | Modbus coil (FC5) |
| `output <bits>` | Siemens S7 digital outputs (binary string) |
| `merkers <bits> <offset>` | Siemens S7 merkers |
| `dm <start> <values>` | Omron FINS DM area words |
| `db <db> [offset] <data>` | Siemens S7 data block bytes |
| `d <start> <values>` | Mitsubishi SLMP D word registers |
| `m <start> <bits>` | Mitsubishi SLMP M bit devices |
| `oid <oid> <value> --community --type` | SNMP SET (`--confirm` required) |
| `sc <ioa> <on\|off>` | IEC 104 Single Command |
| `dc <ioa> [state]` | IEC 104 Double Command |

**`run` exploits:**

| Command | Description |
|---------|-------------|
| `reboot` | Beckhoff CX9020 reboot via UPnP/SOAP (CVE-2015-4051) |
| `add-user <credentials>` | Add admin user to CX9020 via UPnP/SOAP (default password: `Sc4d4v3r!`) |
| `write-symbol <NAME=hexbytes>` | Write raw bytes to ADS symbol |
| `flash-led` | Schneider identification LED flash |
| `session-stop` | Schneider PLC stop via recovered legacy web session |
| `session-run` | Schneider PLC start via recovered legacy web session |
| `fc90-stop [--model m340\|tm221]` | Unauthenticated Schneider FC90 stop |
| `fc90-start [--model m340\|tm221]` | Unauthenticated Schneider FC90 start |
| `fc90-force [--output] [--state]` | Force physical output bit on M340 |
| `passwords` | Retrieve Phoenix Contact WebVisit passwords (CVE-2016-8366) |
| `ewon-creds` | eWON auth-bypass credential extract |
| `portscan [--ports]` | TCP connect scan for common ICS ports |
| `shellshock [--http-port]` | Shellshock scanner on PLC/HMI web CGI (CVE-2014-6271) |
| `default-creds [--path]` | HTTP Basic Auth default-credential spray |
| `fdi` | False Data Injection - continuous Modbus write loop |
| `modbus-server` | Rogue Modbus TCP server (no `-i` needed) |

**`db` commands:**

| Command | Description |
|---------|-------------|
| `db add --ip <IP> [--vendor]` | Add a device to the database |
| `db remove --id <id>` | Remove a device by ID |
| `db refs [--vendor <slug>]` | List embedded ICS research references |

---

### Web API

```sh
scadaver web                            # 127.0.0.1:8888
scadaver web --host 0.0.0.0 --port 9000
```

A 32-character hex token is generated at startup and printed to the terminal. The browser
opens automatically at `http://host:port/?key=<token>`. REST clients send `X-API-Key: <token>`
on protected endpoints (scan, device tags, tag write, all exploit routes). The token is
ephemeral - a new one is generated each run.

Endpoints that do not require authentication: `GET /health`, `GET /api/devices`,
`GET /api/devices/:ip/history`.

---

## ICS References Database

~300 publicly disclosed ICS vulnerability writeups embedded in the binary, sourced from
[awesome-ics-writeups](https://github.com/neutrinoguy/awesome-ics-writeups). Entries from
Claroty, ZDI, Nozomi Networks, Microsoft, Dragos, and others.

**TUI:** press `W`. **CLI:** `scadaver db refs [--vendor <slug>]`

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
| `modbus` | Modbus protocol |
| `iec104` | IEC 60870-5-104, IEC 62351 |
| `enip` | EtherNet/IP, CIP |
| `snmp` | SNMP |
| `malware` | ICS malware: Triton/TRISIS, Industroyer, PIPEDREAM, Havoc |
| `ics-general` | General OT/SCADA security research |

Refresh from upstream:

```bash
python scripts/fetch_refs.py
```

---

## Test Environments

- **PyScada** - Django-based SCADA with Modbus, OPC-UA, historian, and HMI: <https://pyscada.readthedocs.io/en/main/>
- **Pump Station Simulator** - live Modbus TCP registers from a pump-station ladder logic sim: <https://github.com/dscioli/pump-station-simulator>

Local protocol stubs for offline regression testing (`sim/` directory):

```sh
python sim/run_all.py --profile high    # start all simulators on unprivileged ports
python sim/smoke.py                     # smoke test against them
```

Use `--profile canonical` for standard protocol ports (requires Administrator/root for ports 80, 102, 502).

---

## Library Usage

`scadaver` is both a binary and a library crate. When used as a dependency, all
CLI and TUI deps (ratatui, clap, rusqlite, axum, etc.) are automatically excluded
only the pure protocol stack is compiled.

```toml
[dependencies]
# library only zero CLI/TUI overhead
scadaver = { version = "1", default-features = false }

# library + derive macro
scadaver = { version = "1", default-features = false, features = ["macros"] }
scadaver-macros = "1"
```

Scan a Rockwell device and read tags:

```rust
use scadaver::vendors::rockwell::driver;

let device = driver::get_device_info("192.168.1.50", 44818)?;
println!("{}: {}", device.product_name, device.revision);

let tags = driver::enumerate_tags("192.168.1.50", 44818)?;
for tag in &tags {
    let value = driver::read_tag("192.168.1.50", 44818, &tag.name)?;
    println!("{} = {}", tag.name, driver::decode_value(tag.tag_type, &value, None));
}
```

Multi-protocol sweep using the prelude:

```rust
use scadaver::prelude::*;

set_stealth(true);
for outcome in sweep("192.168.1.100", 8) {
    if let Some(info) = outcome.device {
        println!("[{}] {} — {:?}", info.vendor, info.ip, info.fields);
    }
}
```

Query the embedded ICS reference database:

```rust
use scadaver::references;

for r in references::for_vendor("siemens") {
    println!("[{}] {} | {}", r.source, r.title, r.url);
}
```

### `#[derive(IntoDeviceInfo)]`

The companion `scadaver-macros` crate provides a derive macro that converts any
vendor device struct into the unified `DeviceInfo` type used by the sweep engine:

```rust
use scadaver_macros::IntoDeviceInfo;
use scadaver::core::autodetect::IntoDeviceInfo as _;

#[derive(IntoDeviceInfo)]
#[vendor(slug = "acme")]
pub struct AcmeDevice {
    #[device_info(ip)]          // becomes DeviceInfo::ip
    pub ip: String,
    pub firmware: String,
    #[device_info(rename = "hw_rev")]
    pub hardware_revision: String,
    #[device_info(optional)]    // Option<T> — only inserted when Some
    pub serial: Option<String>,
    #[device_info(skip)]        // excluded from DeviceInfo::fields
    pub _socket: std::net::TcpStream,
}

// Generated:
// impl IntoDeviceInfo for AcmeDevice {
//     const VENDOR_SLUG: &'static str = "acme";
//     fn into_device_info(self) -> DeviceInfo { ... }
// }

let info: DeviceInfo = my_device.into_device_info();
```

Field attributes: `ip`, `skip`, `rename = "key"`, `optional`.
Struct attribute: `#[vendor(slug = "...")]`.

### Public namespaces

| Namespace | Protocols |
|-----------|-----------|
| `scadaver::vendors::schneider` | Modbus TCP, FC90, UDP discovery |
| `scadaver::vendors::siemens` | S7Comm / ISO-on-TCP |
| `scadaver::vendors::beckhoff` | ADS/AMS, TwinCAT, CX webcontrol |
| `scadaver::vendors::mitsubishi` | SLMP / MC Protocol 3E |
| `scadaver::vendors::omron` | FINS TCP/UDP |
| `scadaver::vendors::rockwell` | EtherNet/IP + CIP |
| `scadaver::vendors::enip` | EtherNet/IP enumerations |
| `scadaver::vendors::ewon` | eWON HTTP exploit + IPCONF scan |
| `scadaver::vendors::phoenix` | ProConOS binary, WebVisit HMI |
| `scadaver::vendors::snmp` | SNMPv1/v2c client, OID constants |
| `scadaver::vendors::iec104` | IEC 60870-5-104 client session |
| `scadaver::core::modbus` | Raw Modbus TCP client primitives |
| `scadaver::core::autodetect` | Multi-protocol sweep, stealth mode |
| `scadaver::core::network` | Interface enumeration, broadcast sockets |
| `scadaver::core::bytes` | Hex/IP utility functions |
| `scadaver::references` | Embedded ICS vulnerability reference database |
| `scadaver::prelude` | Common re-exports (`DeviceInfo`, `sweep`, vendor result types) |

---

## Legal

This tool is for authorized penetration testing, red team exercises, ICS security
research, and CTF competitions only. Unauthorized use against systems you do not own
or have explicit written permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse.


# Authors:
- [Sawyer (Saif Yaseen)](https://github.com/SawyersPresent)
