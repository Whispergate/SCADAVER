# Changelog

All notable changes to this project will be documented in this file.

## [1.8.0] - 2026-11-08

This release is the protocol layer. Every protocol now has one place that owns its codec and its
socket call, and the three surfaces (CLI, TUI, web) render typed results instead of talking to the
`casket` dependency themselves.

### Added

- `src/ops/`: one module per protocol (bacnet, beckhoff, dnp3, enip, ewon, iec104, mitsubishi,
  modbus, mqtt, omron, opcua, phoenix, rockwell, schneider, siemens, snmp). Each returns a typed
  `Outcome` plus errors that name the operation, and none of them print.
- `src/ops/ranges.rs`: Modbus and SLMP address tables, range parsers and chunkers, with unit
  coverage, so map operations take a validated range rather than two loose integers.
- `src/protocol.rs`: one registry of protocol names, display names and default ports. It replaces
  three private copies; the CLI's copy had eWON on port 80 while the registry said 1507.
- `src/model.rs`: shared record types (`EndpointRecord`, `Outcome`, `ValueChange`) used by the
  surfaces and by the import/database layer.
- `src/safety.rs` and `docs/safe-mode.md`: safe mode, fragile-host refusal that states its reason,
  and a mutating-verb table so writes need an explicit opt-in.
- Web UI: rebuilt routes and static app, with per-protocol panels, an exploit runner and a live
  tag reader.
- `sim/`: Python simulators for thirteen protocols (beckhoff, dnp3, enip, ewon, fins, iec104,
  modbus, mqtt, opcua, phoenix, siemens, slmp, snmp) plus a conformance writer that checks the
  Rust client against an independent library rather than against itself.
- `scripts/golden.sh` with `tests/golden/`: output fixtures per case, in a "simulators down" and a
  "simulators up" mode, so CLI output cannot drift silently.
- `scripts/check-parity.sh`: fails when a surface calls `casket` directly instead of going through
  `ops`. The remaining count per file is the backlog, not a pass.
- `docs/build.md`: build steps, which Python carries the simulator dependencies, the simulator
  matrix, and the parity rule.

### Changed

- The TUI is 2,343 lines lighter (876 added, 3,219 removed) because its per-protocol socket code
  moved into `ops`. `cli.rs` keeps the rendering and the cache writes.
- eWON register and coil verbs keep port 0 when no port is given, so the Modbus codec chooses 502
  instead of inheriting the IPCONF discovery port 1507 from the registry.
- Web `omron/cpu_run` sends Run (0x01), which matches both its name and `set-cpu-mode run`. It used
  to send Monitor (0x02), so a browser click and a CLI command left the controller in different
  states.
- `omron/read_dm` rejects a word count outside 1..=100 with a message naming the value and the
  range, instead of clamping to 100 and reporting success.
- FINS DM reads treat a short reply as an error that states how many words came back; a
  non-numeric set token and a non-zero end code are errors rather than quiet successes.
- `src/main.rs` is a thin consumer of the library, so each module compiles once and its unit tests
  run once. 46 duplicate test runs are gone from a suite that otherwise stayed at the same count.

### Fixed

- eWON coil read takes the bit from the raw value instead of comparing the display string to `ON`.
- Modbus and SLMP map chunking refuse an address range the parsers cannot produce instead of
  clamping the address to `u16::MAX`.
- Golden harness strips CR from case lines and from both diff sides, so `core.autocrlf=true` no
  longer turns every case into a clap usage error.
- Golden harness refuses to run in the wrong simulator state and names the closed or listening
  port, instead of reporting code drift.
- 35 emptiness assertions print the value on failure, which is what clippy 1.99's
  `assert_is_empty` requires and what makes a CI failure say which records were present.
- CI: the Mosquitto broker config lives in `conf.d` because AppArmor blocks `/tmp`; clippy runs on
  all targets; formatting is a gate.

## [1.7.2] - 2026-08-29

### Added

- TUI broadcast scan: Modbus TCP is now its own dedicated menu entry ("Modbus TCP port 502 /24 sweep"), separate from Schneider UDP; sweeps the local /24 in 32-host batches using TCP pre-connect + FC3 confirmation
- CLI `scan_network` (CIDR sweep): after `autodetect::sweep` finishes, any host with no modbus/schneider result is probed directly on port 502 — fixes Modbus TCP devices being silently dropped from CIDR scans
- TUI `spawn_ip_scan` (single-IP scan): after `probe_all` returns 0 results, falls back to TCP connect + FC3 read on the Modbus port — fixes Modbus TCP devices going undetected in the TUI device scanner
- Web `broadcast_scan`: Modbus vendor is now handled by a dedicated TCP /24 sweep (32-host batches, TCP pre-connect + FC3 confirmation) instead of being incorrectly routed through the Schneider UDP broadcast path
- CLI `get tag --protocol iec104 <name>` — resolves IOA number from name (e.g. `100` or `IOA:100`), performs general interrogation, and prints the matching data object value
- CLI `get tag --protocol ewon <name>` — reads all eWON tag values and looks up the named tag, with a clear "not found" message listing how many tags were returned
- CLI `get tag --protocol mqtt <topic>` — subscribes to the named topic, drains messages within the timeout, and prints the payload
- CLI `get tag --protocol modbus <name>` — resolves `hr:N`/`coil:N`/`ir:N`/`di:N` address and reads the individual register

### Fixed

- eWON `get tag` lookup corrected from HashMap `.get()` to tuple-vector `.find()` — the return type of `read_tag_values` is `Vec<(String, String)>`, not a map

## [1.7.1] - 2026-08-29

### Added

- TUI broadcast scan: new "Modbus TCP (/24 sweep)" entry probes port 502 across the local /24
  in batches of 32 concurrent threads; any host that answers a FC3 read is registered as
  vendor=modbus
- TUI Phoenix "List Tags" (exploit index 1) and "Read Tag Values" (exploit index 2) now emit
  `ScanEvent::TagLeaves` after completion, populating the tag browser so `[W]` write is
  available for Phoenix tags
- CLI `get tags --protocol modbus` — reads FC3 holding registers, FC1 coils, and FC4 input
  registers (first 32 each) and prints them with display addresses
- CLI `get tags --protocol bacnet` — reads BACnet device properties (instance_id, vendor_name,
  object_name, description, firmware_revision) via `bacnet::client::scan_ip`
- CLI `get tags --protocol dnp3` — reads DNP3 device attributes via
  `dnp3::client::read_device_attributes`
- CLI `get tags --protocol opcua` — enumerates OPC-UA server endpoints (URL, security mode,
  security policy) via `opcua::client::get_endpoints`
- CLI `get discrete-input [start] [count]` subcommand — reads Modbus FC2 discrete inputs
- Web `POST /api/exploit/modbus/map-quick` — sweeps FC1/FC2/FC3/FC4 (first 125 registers each)
  and returns a formatted register map
- Web `POST /api/exploit/modbus/map-common` — same as map-quick but reads up to 512 registers
  per function code
- Web `POST /api/device/tags {"vendor":"s7"}` — `"s7"` is now a recognised alias for
  `"siemens"` in `read_tags_for_vendor`, matching the existing write-side behaviour

### Fixed

- Web `POST /api/device/write` for `vendor=modbus|schneider|modicon` with a bare tag name
  (no `hr:` or `coil:` prefix) now returns a clear format hint instead of the generic
  "Unknown tag format" Modbus fallback message
- CLI `get tags` catch-all `Some(p) => bail!` arm removed — all 16 Protocol variants are
  now explicitly handled, matching the existing `get info` completeness

## [1.7.0] - 2026-08-29

### Added

- `get tags --password` and `get tag --password` CLI flags for Siemens S7 — threads the password
  directly into `list_data_blocks` and `read_data_block` instead of ignoring it
- `get tags --username` / `--password` CLI flags for eWON — credentials are passed to the REST
  API call instead of being ignored
- `get tags --username` / `--password` CLI flags for MQTT — broker credentials are included in
  the `ConnectOptions` when subscribing for topic enumeration
- Web `POST /api/device/tags` now accepts `username` and `password` JSON fields; both are
  optional (`#[serde(default)]`) — existing callers are unaffected
- Web `POST /api/device/write` now accepts `username` and `password` JSON fields (same pattern)
- `read_tags_for_vendor`: Siemens arm now prefers the request-body password over the DB-stored
  value, falling back to DB if none is provided in the request
- `read_tags_for_vendor`: eWON arm now prefers request-body credentials over DB-stored values
- `read_tags_for_vendor`: added `"mqtt"` arm — connects with optional credentials, subscribes
  to `#`, drains up to 50 messages, and returns topic → payload as UTF-8 strings
- `read_tags_for_vendor`: added `"bacnet"` arm — reads device properties via
  `bacnet::scan_ip` (vendor\_name, object\_name, description, firmware\_revision, instance\_id)
- `read_tags_for_vendor`: added `"dnp3"` arm — reads device attributes via
  `dnp3::read_device_attributes`; previously the arm was absent and requests silently returned
  an empty tag map
- `read_tags_for_vendor`: added `"opcua"` arm — enumerates server endpoints via
  `opcua::get_endpoints`, returning each endpoint's URL, security mode, and security policy
  as `ep<n>.*` tags
- `write_tag_for_vendor`: added `"iec104"` arm — sends a `single_command` to the specified
  IOA; tag format is `IOA:<number>`, value is `1`/`on` or `0`/`off`
- `write_tag_for_vendor`: added informative bail responses for `"bacnet"`, `"dnp3"`, and
  `"opcua"` — previously these fell through to the generic Modbus error message
- `write_tag_for_vendor`: Siemens arm now prefers request-body password over DB-stored value
- `broadcast_scan` (`POST /api/scan`): added `"bacnet"` discovery via
  `bacnet::who_is_broadcast`; responds to any of `vendor=bacnet`, `all`, or empty string

### Changed

- `write_tag_for_vendor` IEC-104, BACnet, DNP3, and OPC-UA arms are checked before the
  generic Modbus tag-prefix fallback, so a clear protocol-specific error is returned instead of
  the misleading "Unknown tag format … Use hr:<addr> or coil:<addr>" message

### Notes

- **Casket `change_cpu_state` password gap**: `F:\git\casket` has been updated to add
  `password: Option<&str>` to `change_cpu_state`; that change will wire into the three
  scadaver call sites (`cli.rs`, `tui.rs`, `routes.rs`) once casket v0.1.1 is published to
  crates.io

## [1.6.0] - 2026-08-28

### Added

- Web exploit routes for BACnet (`bacnet/0-2`), DNP3 (`dnp3/0-1`), and OPC-UA (`opcua/0-2`) —
  previously these IDs were silently unreachable in `POST /api/exploit/:id`
- `GET /api/info` for Enip, Schneider, Mitsubishi, and SNMP — all four now return real device
  data instead of bailing with "not supported"
- `get tags --protocol siemens` — lists S7 data blocks (DB number and byte length) via
  `s7comm::list_data_blocks`
- `get tags --protocol mitsubishi` — reads SLMP D-word registers D0–D31
- `get tags --protocol omron` — reads FINS DM words DM0–DM31
- `get tags --protocol schneider` — reads 32 Modbus holding registers (40001–40032)
- `get tags --protocol snmp` — discovers community string, prints sysInfo and interface table
- `get tags --protocol enip` — informative bail directing user to `--protocol rockwell`
- `get tag --protocol siemens NAME` — reads a single S7 data block byte range; name format
  `DB<num>` (reads 4 bytes) or `DB<num>:<offset>:<len>`
- `get tag --protocol mitsubishi NAME` — reads one SLMP word device; name format `D<addr>`,
  `M<addr>`, `W<addr>`, etc.
- `get tag --protocol omron NAME` — reads one FINS DM word; name format `DM<addr>` or bare
  number
- `get tag --protocol schneider NAME` — reads one Modbus holding register; accepts display
  address (40001) or raw address (0)
- `get tag --protocol snmp OID` — reads one SNMP OID with auto-discovered community; accepts
  dotted OID or shorthand names (`sysDescr`, `sysName`, `sysLocation`, `sysContact`)
- `get tag --protocol enip NAME` — informative bail directing user to `--protocol rockwell`

### Fixed

- Removed unreachable `Some(p) => bail!` fallthrough in `get_info` — all 16 protocol variants
  are now handled explicitly
- `get tag --protocol mitsubishi DM100` now fails at parse time with a clear error listing valid
  SLMP device codes (D, M, X, Y, B, W, R); previously "DM" silently reached casket and returned
  an opaque "unknown device" error
- `get tag --protocol siemens DB0` now fails at parse time; DB0 is a reserved S7 internal block
- `get tags --protocol siemens` now prints an upfront warning about worst-case probe duration
  before starting the DB1–DB200 sweep
- Web: `POST /api/portscan` now returns `401 Unauthorized` on auth failure; previously it
  returned `200 OK` with `{"error": "..."}` due to an incorrect response construction
- Web: `/ws/monitor/:ip` and `/ws/events` WebSocket endpoints now require the `X-API-Key`
  header; previously they only checked the `Origin` header, allowing any non-browser client to
  connect without a key
- Web: task panics in `spawn_blocking` handlers now return `"internal error"` instead of the
  raw `JoinError` string, which included source file paths
- `scan --network` CIDR sweep now excludes the network address (.0) and IPv4 broadcast (.255)
  from the host list, preventing noise and spurious IDS alerts on those addresses
- `scan --network` with `-z` stealth flag now randomizes the host sweep order instead of
  always scanning in ascending IP order (which creates a textbook ascending-scan signature)
- `scan --network` now hard-limits sweeps to 65,536 hosts (/16 max); larger ranges bail with
  a clear error instead of silently allocating hundreds of MB and running for hours
- Mutex poisoning in `scan_network` semaphore and TUI MQTT threads now recovers the inner
  value via `unwrap_or_else(PoisonError::into_inner)` instead of propagating a secondary panic
- Dead `in_hostname_element` tracking variable removed from `src/import.rs` (was set but
  never read; Nmap XML hostname capture was already correct without it)

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
