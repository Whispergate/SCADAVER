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
