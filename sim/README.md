# Simulator fidelity and provenance

These fixtures are safe, local protocol-operation test doubles.  They are not
claims of hardware, firmware, safety, performance, or certification
conformance.  Each simulator header names its precise implemented surface and
its primary source.

| Fixture | Evidence level | Primary source |
| --- | --- | --- |
| Modbus TCP | Standards-backed; raw MBAP vectors cover FC3 and FC6. | [Modbus Application Protocol v1.1b3](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf) |
| Mitsubishi SLMP | Source-traced 3E-frame fixture; CLI read/write/read-back smoke coverage. | [Mitsubishi SLMP Reference Manual](https://www.mitsubishielectric.com/dl/fa/document/manual/plc/sh080956eng/sh080956engl.pdf) |
| Beckhoff ADS/AMS | Source-traced limited ADS fixture; CLI smoke coverage. | [Beckhoff ADS documentation](https://infosys.beckhoff.com/content/1033/tcadscommon/12440276875.html) |
| Siemens S7Comm | Source-traced limited frame fixture; no public full S7Comm wire specification. | [RFC 1006](https://www.rfc-editor.org/rfc/rfc1006), [Siemens communication manual](https://cache.industry.siemens.com/dl/files/925/59192925/att_61992/v1/s71500_communication_function_manual_en-US_en-US.pdf) |
| eWON Flexy | Source-traced unit-id 100 publication fixture; raw Modbus and HTTP agreement test. | [HMS Flexy Modbus TCP guide](https://support.hms-networks.com/hc/en-us/articles/11964515209234-How-to-publish-Ewon-Flexy-tags-through-Modbus-TCP) |
| Omron FINS/TCP | Source-traced limited FINS fixture; CLI smoke coverage. | [Omron Sysmac NJ FINS Technical Guide](https://assets.omron.com/m/7b1f867d19635636/original/Sysmac-NJ-FINS-Technical-Guide.pdf) |
| IEC 60870-5-104 | Source-traced limited telecontrol fixture; CLI smoke coverage. | [IEC 60870-5-104](https://webstore.iec.ch/en/publication/3746) |
| MQTT | Standards-backed broker fixture; independent Paho publish/subscribe test. | [OASIS MQTT v3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html) |
| Phoenix ProConOS/WebVisit | Fixture-only limited compatibility stub; no public vendor wire specification. | [Phoenix Contact advisory](https://assets.phoenixcontact.com/file/0b82d360-83fb-4cd5-965a-1b7cb89712fd/media/original?Security_Advisory_OEM_CVE-2014-9195.pdf=) |
| SNMPv2c | Standards-backed limited system-MIB fixture; CLI smoke coverage. | [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html), [RFC 3418](https://www.rfc-editor.org/rfc/rfc3418.html) |
| EtherNet/IP/CIP | Source-traced limited fixture; not an ODVA or ControlLogix conformance emulator. | [ODVA specifications catalogue](https://www.odva.org/subscriptions-services/specifications/), [pycomm3](https://github.com/ottowayi/pycomm3) |
| BACnet/IP CI fixture | Standards-backed limited Who-Is/I-Am/ReadProperty fixture. | [BACnet developer aids](https://bacnet.org/developer-aids/) |
| DNP3 | Standards-backed limited IEEE 1815 fixture; raw link-status and Group-0 attribute vectors. | [DNP Users Group standards information](https://www.dnp.org/) |
| OPC UA CI fixture | Standards-backed no-security endpoint; independent asyncua read-only node and endpoint checks. | [OPC UA Part 4](https://reference.opcfoundation.org/specs/OPC-10000-4/full), [Part 6](https://reference.opcfoundation.org/Core/Part6/v105/docs/) |

## Simulator inventory

Two generations exist. `scripts/sim_*.py` predate the `sim/` tree and are kept because tests and CI
point at those exact paths. New simulators belong in `sim/` as `<protocol>_sim.py`, accept `--host`
and `--port`, and are added to this table on the day they land.

| Script | Default port | Emulates | Started by |
| --- | --- | --- | --- |
| `scripts/sim_bacnet.py` | 47808 | BACnet/IP device, Who-Is/I-Am and ReadProperty | `tests/ops_bacnet.rs`, `tests/ops_integration.rs` (ignored case), a test in `src/web/routes.rs` |
| `scripts/sim_modbus.py` | 5020 | Modbus TCP, CI-only fixture, FC3 and FC6 | `sim/run_all.py`, `sim/test_protocol_conformance.py` |
| `scripts/sim_opcua.py` | 4840 | OPC UA no-security endpoint | `tests/ops_opcua.rs`, `.github/workflows/ci.yml` |
| `scripts/sim_snmp.py` | 16100 | SNMPv2c system-MIB agent | `sim/test_protocol_conformance.py` |
| `sim/modbus_sim.py` | 502 | Modbus TCP with the richer data model | `scripts/golden.sh sim` (on 21502) |
| `sim/dnp3_sim.py` | 20000 | DNP3 outstation | `scripts/golden.sh sim` (on 33001) |
| `sim/siemens_sim.py` | 102 | Siemens S7 PLC | `scripts/golden.sh sim` (on 11202) |
| `sim/beckhoff_sim.py` | 48898 ADS, 48899 discovery | Beckhoff ADS/AMS | `sim/run_all.py`, the ADS tests |
| `sim/eip_sim.py` | 44818 | EtherNet/IP CIP | `sim/run_all.py`, the EtherNet/IP tests |
| `sim/ewon_sim.py` | 80 HTTP, 502 Modbus | eWON Flexy publication | `sim/run_all.py`, the eWON tests |
| `sim/fins_sim.py` | 9600 | Omron FINS/TCP | `sim/run_all.py`, the FINS tests |
| `sim/iec104_sim.py` | 2404 | IEC 60870-5-104 | `sim/run_all.py`, the IEC-104 tests |
| `sim/mqtt_sim.py` | 1883 | MQTT 3.1.1 broker | `sim/run_all.py`, the MQTT tests |
| `sim/opcua_sim.py` | 4840 | OPC UA, second generation | `sim/run_all.py` |
| `sim/phoenix_sim.py` | 1962 | Phoenix ProConOS/WebVisit stub | `sim/run_all.py` |
| `sim/slmp_sim.py` | 5007 | Mitsubishi SLMP 3E | `sim/run_all.py` |
| `sim/snmp_sim.py` | 1161 | SNMPv2c, second generation | `sim/run_all.py` |

Ports above are the `argparse` defaults, and most honour a `SCADAVER_<PROTOCOL>_PORT` variable. The
golden harness deliberately starts its three simulators on unprivileged ports (21502, 33001,
11202) so the run works without elevation; see `docs/build.md`.

`sim/start_all.ps1` is the PowerShell launcher for a Windows lab box. `sim/run_all.py` is the
portable one used by CI and by the golden harness notes in `docs/build.md`.

## Run the audit

```powershell
py -3 -m pip install -r sim\requirements-test.txt
py -3 -m unittest sim.test_run_all sim.test_protocol_conformance -v
py -3 sim\smoke.py --profile high --scadaver .\target\release\scadaver.exe
py -3 sim\write_smoke.py --profile high --scadaver .\target\release\scadaver.exe
```

The last two commands prove SCADAver interoperability with these local
fixtures.  The independent suite is intentionally separate: it catches cases
where a client and fixture accidentally share the same incorrect assumption.
