# Changelog

All notable changes to this project will be documented in this file.

## [1.5.4] - 2026-08-28

### Fixed
- `--timeout` flag now propagates to all S7Comm call sites (`get_io`, `get state`, `get db`,
  `set output`, `set merkers`, `set db`) instead of being hardcoded to 5 seconds
- `--timeout` propagates to Beckhoff ADS discovery in `get state` and `get tags` (was hardcoded to 3)
- `get tags --protocol mqtt` subscribe window now respects `--timeout` instead of always waiting 2 s

### Added
- `db list` subcommand: prints all stored devices with id, IP, vendor, and last-seen age

### Fixed (CSV)
- `export --format csv` now strips embedded newlines and carriage returns from JSON field blobs
  so rows are never split across multiple CSV lines

## [1.5.3] - 2026-08-28

### Fixed
- `set tag --protocol mqtt` now publishes decoded bytes instead of the ASCII encoding of the hex
  string (`set tag TOPIC=01` now sends `[0x01]`, not `[0x30, 0x31]`); invalid hex input now
  returns a clear error
- `set state --protocol siemens` help text removed "monitor" and "config" states that were never
  implemented; valid states are `run`, `stop`, and `flip`
- `GET /health` web endpoint now returns the real binary version via `CARGO_PKG_VERSION` instead
  of the hardcoded string `"1.0.0"`
- Stale comment in `tests/library_api.rs` updated from `scadaver::` to `casket::` paths

### Changed
- CI workflow now runs `rockwell_integration`, `s7_integration`, `library_api`, and
  `macros_derive` in the explicit per-test integration step (they were already covered by
  `cargo test --verbose` but were absent from the named step)

## [1.5.2] - 2026-08-28

### Fixed
- BACnet (3 entries), DNP3 (2 entries), and OPC-UA (3 entries) exploit entries in the TUI were
  always shown as enabled regardless of whether the protocol was actually detected; added
  `BacnetIp`, `Dnp3Tcp`, and `OpcuaTcp` capability keys with port-based and field-based
  detection, matching the existing pattern used for MQTT

## [1.5.1] - 2026-08-28

### Fixed
- MQTT was absent from the TUI vendor picker (`ALL_VENDORS`) — it now appears alongside all other vendors
- MQTT exploit entries ("Publish", "List Topics") were missing capability keys, causing them to always appear disabled; added `MqttTcp` capability key with port and field-based detection
- Added `MqttTcp` to `check_capability` and `capability_missing_reason` to complete the gating logic

## [1.4.0] - 2026-08-28

### Added
- Write and read support for IEC-104, Siemens S7, MQTT, and eWON devices (`set tag`, `get tag`)
- Beckhoff `get tag` via ADS; Rockwell `set tag --type` flag for typed CIP writes
- EIP sender context watermark for traffic fingerprinting; Snort and YARA detection rules
- TUI: persistent struct members, auto-display on device select, Beckhoff I-key, access labels, legend

### Fixed
- TUI panic guard on empty device list
- Web API auth gaps in ephemeral key validation

### Changed
- Pre-commit strict clippy gate; Rust 1.87 pinned as minimum version

## [1.3.0] - 2026-08-26

### Added
- PCAP passive discovery (`capture` feature flag): listen on a network interface and fingerprint ICS devices from traffic without sending any probes
- Regression test suite covering all protocol parsers

### Fixed
- 7 security and correctness fixes across MQTT, EIP, and Modbus parsers
- Reader thread lock starvation in MQTT persistent session
- CI: replaced Python-based simulators (pysnmp, bacpypes3, pymodbus) with in-process UDP/TCP loopbacks for reliable test runs

## [1.2.1] - 2026-08-20

### Added
- Integration tests for all 10 remaining ICS protocol scanners (BACnet, DNP3, OPC-UA, SNMP, IEC-104, SLMP, FINS, EIP, Modbus, Beckhoff)

### Fixed
- MQTT shell `ConnectOptions` missing `tls` and `protocol_version` fields at construction
- musl CI build: vendor native-tls OpenSSL so the static binary links cleanly

## [1.2.0] - 2026-08-20

### Added
- CIDR network sweep: `scadaver --network 192.168.1.0/24 scan` probes every host in a range
- Nmap XML import: `scadaver import --nmap scan.xml` seeds the device database from existing scans
- Config file support (`~/.config/scadaver/config.toml`): persist default timeout, interface, and stealth settings
- BACnet/IP, DNP3 TCP, and OPC-UA protocol support (scan, read, exploits)
- MQTT TLS and MQTT v5 support in the interactive shell
- Web UI: live device push over WebSocket — browser updates without polling
- MQTT: ACL enumeration, session persistence attack, and retain flooding commands
- Sparkplug B fuzzer with safety hardening and configurable payload gates
- TUI: live MQTT topic browser panel (press `m`)

## [1.1.3] - 2026-08-16

### Added
- Siemens and SNMP device info enrichment: CPU state, firmware, and hardware fields now populate the device record
- `IntoDeviceInfo` derive macro wired into all vendor structs so autodetect results are fully typed

## [1.1.2] - 2026-08-16

### Added
- MQTT broker scanner: anonymous detection, `$SYS/#` recon, Sparkplug B passive detection, credential spraying
- `MqttSession`: persistent MQTT connection with background reader thread (subscribe, publish, drain, disconnect)
- `scadaver mqtt` interactive shell: 3-level client (configure → connect → pub/sub/attack)

### Fixed
- Renamed `FinsDevice` to `OmronDevice` to match the prelude re-export
- Renamed `LogixDevice` and `PhoenixDeviceInfo` to match prelude export names

## [1.5.0] - 2026-08-28

### Changed
- All ICS/OT protocol implementations moved to [casket](https://crates.io/crates/casket), a standalone library published on crates.io; scadaver now depends on `casket = "0.1"` instead of compiling the vendor code directly
- Network interface selection (`select_interface`) kept in scadaver as CLI-specific tooling in `src/net.rs`
- `scadaver-macros` workspace crate removed; the `IntoDeviceInfo` derive macro now lives in `casket-macros`

### Added
- `capture` feature flag to opt into pcap-based capture via `casket/capture`

### Removed
- `src/core/`, `src/vendors/`, `src/prelude.rs`, `src/references.rs` — all protocol logic is now in casket
- `scadaver-macros/` workspace crate

## [1.1.1] - 2026-08-16

### Fixed

- `session.rs`: oversized PUBLISH packet (`remaining_len > 65536`) now drains the body and
  continues instead of killing the reader thread permanently
- `session.rs`: password CONNECT flag no longer set when username is absent (MQTT 3.1.1 §3.1.2.8)
- `client.rs`: `read_sys_publish` and `probe_sparkplug` now drain oversized packets before
  returning to keep the TCP stream in sync for subsequent reads
- `mqtt_shell.rs`: `exit`/`quit` in the messaging console now returns normally instead of
  calling `process::exit(0)` which skipped all Drop impls
- `mqtt_shell.rs`: connecting with an empty host now shows a clear message instead of an OS error

### Added

- `sim/mqtt_sim.py`: Python MQTT 3.1.1 broker simulator (amqtt) matching the `sim/` pattern
- `sim/run_all.py` / `sim/smoke.py`: MQTT wired into the simulator suite (`--only mqtt`)
- `tests/mqtt_integration.rs`: 5 live-broker integration tests (guarded by `TEST_MQTT_HOST`)
- `Protocol::Mqtt` in CLI: `scadaver -i <host> --protocol mqtt scan` probes MQTT brokers
- CI: Mosquitto service + `MQTT integration tests` step
- `Cargo.toml`: declared `rust-version = "1.87"` (required for `Duration::from_mins`)

## [1.1.0] - 2026-08-16

### Added

- MQTT broker support: raw MQTT 3.1.1 wire protocol over `TcpStream` (no async dep)
- Anonymous broker detection (`CONNACK` return code 0x00) on port 1883
- `$SYS/#` recon: captures broker version/uptime from retained system topics
- Sparkplug B passive detection: flags ICS/SCADA brokers publishing `spBv1.0/` topics
- `try_credential`: per-attempt connection for MQTT credential spraying
- `MqttDevice` struct re-exported via `scadaver::prelude`
- `probe_mqtt` wired into the autodetect engine alongside all other protocol probes
- 6 new library API integration tests covering MQTT packet structure and struct fields
- `MqttSession`: persistent MQTT connection with background reader thread (subscribe, unsubscribe,
  publish, unsubscribe_all, ping, drain_messages, disconnect)
- `ConnectOptions`, `MqttMessage`, `WillConfig` re-exported via `scadaver::prelude`
- `scadaver mqtt` CLI subcommand: interactive 3-level MQTT client shell (configure, connect,
  pub/sub); based on python-mqtt-client-shell by Barry Powell

## [1.0.0] - 2026-08-15

Initial public release.

### Added

- Multi-protocol ICS scanner: EtherNet/IP/CIP, Modbus TCP, S7Comm, FINS (Omron),
  SLMP (Mitsubishi), ADS/AMS (Beckhoff), IEC 60870-5-104, SNMP
- Vendor coverage: Rockwell, Siemens, Schneider Electric, Beckhoff, Omron,
  Mitsubishi, Phoenix Contact, eWON, generic Modbus/ENIP targets
- `scan`: auto-detect ICS devices on a host or sweep a range across all protocols
- `get` / `set`: read and write PLC data (registers, tags, DM words)
- `run`: execute vendor-specific exploits and actions (unauthenticated stop/start, LED flash, user add, credential spray)
- Stealth mode: randomised probe order and inter-probe jitter (`-z`)
- Device database: persist scan results, tag devices, query by protocol or vendor
- Terminal UI (`tui`): interactive device browser and action runner
- Web UI (`web`): browser-based operator interface with ephemeral API key auth
- Library API (`scadaver` crate): all protocol implementations re-exported for
  use in external Rust tools
- Autodetect engine (`probe_all`, `sweep`, `detect_device`) with `IntoDeviceInfo` trait
- 117 integration tests covering protocol parsers and library API surface
- Startup disclaimer on every invocation
- Research references database (`references` module): ICS CVEs, advisories, and write-ups
