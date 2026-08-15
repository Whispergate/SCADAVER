# Changelog

All notable changes to this project will be documented in this file.

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
