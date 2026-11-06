"""Stateful, loopback-only CLI write smoke tests.

Every change is made to a fresh in-memory simulator and restored before the
test moves on.  This intentionally covers only standard ``scadaver set``
commands—never the ``run`` action/exploit command family.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

try:
    from . import run_all, smoke
except ImportError:
    import run_all
    import smoke


REPO_ROOT = Path(__file__).resolve().parents[1]
WRITE_FAMILIES = [
    "modbus", "slmp", "ewon", "beckhoff", "siemens", "snmp", "rockwell",
    "fins", "iec104", "phoenix", "mqtt",
]


def command(
    exe: Path,
    name: str,
    args: list[str],
    expected: str,
    *,
    force_live_get: bool = True,
) -> None:
    # Read-backs must query the simulator rather than render the cache that
    # the preceding live operation created.
    command_args = ["--live", *args] if force_live_get and "get" in args else args
    proc = subprocess.run(
        [str(exe), *command_args], cwd=REPO_ROOT, text=True, encoding="utf-8",
        errors="replace", capture_output=True, timeout=30,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode != 0 or expected not in output:
        raise RuntimeError(
            f"{name} failed (rc={proc.returncode}; expected {expected!r})\n{output.strip()}"
        )
    print(f"[+] {name}")


def rejected_command(exe: Path, name: str, args: list[str], expected: str) -> None:
    proc = subprocess.run(
        [str(exe), *args], cwd=REPO_ROOT, text=True, encoding="utf-8",
        errors="replace", capture_output=True, timeout=15,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode == 0 or expected not in output:
        raise RuntimeError(
            f"{name} did not fail explicitly (rc={proc.returncode}; expected {expected!r})\n{output.strip()}"
        )
    print(f"[+] {name}")


def common(target: str, port: int, protocol: str) -> list[str]:
    return ["-i", target, "-p", str(port), "--protocol", protocol]


def prime_inventory(exe: Path, target: str, ports: run_all.PortProfile) -> None:
    """Create fresh protocol records so the write-safety guard is exercised."""
    scans = [
        ("modbus", [*common(target, ports.modbus, "modbus"), "scan"]),
        ("mitsubishi", [*common(target, ports.slmp, "mitsubishi"), "scan"]),
        ("ewon", ["-i", target, "--protocol", "ewon", "scan"]),
        ("beckhoff", [*common(target, ports.beckhoff_ads, "beckhoff"), "scan"]),
        ("siemens", [*common(target, ports.siemens, "siemens"), "scan"]),
        ("snmp", [*common(target, ports.snmp, "snmp"), "scan"]),
        ("rockwell", [*common(target, ports.rockwell, "rockwell"), "scan"]),
        ("omron", [*common(target, ports.fins, "omron"), "scan"]),
        ("iec104", [*common(target, ports.iec104, "iec104"), "scan"]),
        ("phoenix", [*common(target, ports.phoenix, "phoenix"), "scan"]),
        ("mqtt", [*common(target, ports.mqtt, "mqtt"), "scan"]),
    ]
    for protocol, args in scans:
        proc = subprocess.run(
            [str(exe), *args], cwd=REPO_ROOT, text=True, encoding="utf-8",
            errors="replace", capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            output = f"{proc.stdout}\n{proc.stderr}".strip()
            raise RuntimeError(f"{protocol} inventory scan failed (rc={proc.returncode})\n{output}")
        print(f"[+] {protocol} fresh inventory")


def mqtt_round_trip(exe: Path, target: str, port: int) -> None:
    topic = "scadaver/write-smoke"
    received: list[bytes] = []
    ready = threading.Event()
    got_message = threading.Event()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="scadaver-write-smoke")

    def on_connect(client: mqtt.Client, _userdata: object, _flags: object, reason_code: object, _properties: object = None) -> None:
        if str(reason_code) == "Success":
            client.subscribe(topic, qos=0)
            ready.set()

    def on_message(_client: mqtt.Client, _userdata: object, message: mqtt.MQTTMessage) -> None:
        received.append(message.payload)
        got_message.set()

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(target, port, keepalive=10)
    client.loop_start()
    try:
        if not ready.wait(5):
            raise RuntimeError("MQTT write subscriber did not become ready")
        command(
            exe,
            "mqtt publish",
            [*common(target, port, "mqtt"), "set", "tag", f"{topic}=a1b2"],
            "Published 2 byte(s)",
        )
        if not got_message.wait(5) or received[-1] != bytes.fromhex("a1b2"):
            raise RuntimeError(f"MQTT subscriber did not receive a1b2; got {received!r}")
        print("[+] mqtt publish read-back")

        retained_topic = "scadaver/write-smoke-retained"
        command(
            exe,
            "mqtt retained text publish",
            [
                *common(target, port, "mqtt"),
                "set",
                "tag",
                f"{retained_topic}=running",
                "--type",
                "text",
                "--retain",
            ],
            "broker delivery echo confirmed",
        )
        command(
            exe,
            "mqtt retained text read-back",
            [*common(target, port, "mqtt"), "get", "tag", retained_topic],
            "= running",
        )
        # MQTT clears a retained value by publishing an empty retained payload.
        command(
            exe,
            "mqtt retained topic cleanup",
            [
                *common(target, port, "mqtt"),
                "set",
                "tag",
                f"{retained_topic}=",
                "--type",
                "text",
                "--retain",
            ],
            "broker delivery echo confirmed",
        )
    finally:
        client.loop_stop()
        client.disconnect()


def run_writes(exe: Path, target: str, ports: run_all.PortProfile) -> None:
    command(exe, "modbus register write", [*common(target, ports.modbus, "modbus"), "set", "register", "7", "49321"], "Register written")
    command(exe, "modbus register read-back", [*common(target, ports.modbus, "modbus"), "get", "register", "7", "1"], "49321")
    command(exe, "modbus register restore", [*common(target, ports.modbus, "modbus"), "set", "register", "7", "70"], "Register written")
    command(exe, "modbus coil write", [*common(target, ports.modbus, "modbus"), "set", "coil", "8", "on"], "Coil written")
    command(exe, "modbus coil read-back", [*common(target, ports.modbus, "modbus"), "get", "coil", "8", "1"], "ON")
    command(exe, "modbus coil restore", [*common(target, ports.modbus, "modbus"), "set", "coil", "8", "off"], "Coil written")

    command(exe, "slmp D write", [*common(target, ports.slmp, "mitsubishi"), "set", "d", "7", "49321"], "D register(s) written")
    command(exe, "slmp D read-back", [*common(target, ports.slmp, "mitsubishi"), "get", "d", "7", "1"], "49321")
    command(exe, "slmp D restore", [*common(target, ports.slmp, "mitsubishi"), "set", "d", "7", "70"], "D register(s) written")

    # Published Flexy variables use standard Modbus TCP at unit 100.  The
    # eWON simulator's Web/API port is intentionally separate from this port.
    command(exe, "ewon coil write", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-coil", "500", "off"], "set OFF")
    command(exe, "ewon coil read-back", ["-i", target, "-p", str(ports.ewon_modbus), "get", "ewon-coil", "500"], "coil 500 = OFF")
    command(exe, "ewon coil restore", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-coil", "500", "on"], "set ON")
    command(exe, "ewon word write", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-register", "501", "555"], "written")
    command(exe, "ewon word read-back", ["-i", target, "-p", str(ports.ewon_modbus), "get", "ewon-register", "501"], "= 555")
    command(exe, "ewon word restore", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-register", "501", "70"], "written")
    command(exe, "ewon f32 write", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-register", "502", "12.5", "--type", "f32"], "written")
    command(exe, "ewon f32 read-back", ["-i", target, "-p", str(ports.ewon_modbus), "get", "ewon-register", "502", "--type", "f32"], "= 12.5")
    command(exe, "ewon f32 restore", ["-i", target, "-p", str(ports.ewon_modbus), "set", "ewon-register", "502", "73.5", "--type", "f32"], "written")

    command(exe, "beckhoff symbol write", [*common(target, ports.beckhoff_ads, "beckhoff"), "set", "tag", "MAIN.counter=2b02"], "written")
    command(exe, "beckhoff symbol read-back", [*common(target, ports.beckhoff_ads, "beckhoff"), "get", "tag", "MAIN.counter"], "= 555")
    command(exe, "beckhoff symbol restore", [*common(target, ports.beckhoff_ads, "beckhoff"), "set", "tag", "MAIN.counter=d204"], "written")
    command(exe, "beckhoff stop", [*common(target, ports.beckhoff_ads, "beckhoff"), "set", "state", "stop"], "State command sent")
    command(exe, "beckhoff stopped read-back", [*common(target, ports.beckhoff_ads, "beckhoff"), "get", "state"], "STOP")
    command(exe, "beckhoff run restore", [*common(target, ports.beckhoff_ads, "beckhoff"), "set", "state", "run"], "State command sent")

    command(exe, "siemens DB cache seed", [*common(target, ports.siemens, "siemens"), "get", "db", "1", "4", "2"], "aa aa")
    command(exe, "siemens DB no-cache write", ["--no-cache", *common(target, ports.siemens, "siemens"), "set", "db", "1", "4", "1234"], "DB write acknowledged")
    command(exe, "siemens no-cache retains cache", [*common(target, ports.siemens, "siemens"), "get", "db", "1", "4", "2"], "db:1:4:2 = aaaa", force_live_get=False)
    command(exe, "siemens DB read-back", [*common(target, ports.siemens, "siemens"), "get", "db", "1", "4", "2"], "12 34")
    command(exe, "siemens DB restore", [*common(target, ports.siemens, "siemens"), "set", "db", "1", "4", "aaaa"], "DB write acknowledged")
    rejected_command(exe, "siemens DB write invalidates cache", [*common(target, ports.siemens, "siemens"), "get", "db", "1", "4", "2"], "No cached value")
    command(exe, "siemens DB restore read-back", [*common(target, ports.siemens, "siemens"), "get", "db", "1", "4", "2"], "aa aa")
    command(exe, "siemens output write", [*common(target, ports.siemens, "siemens"), "set", "output", "11110000"], "Outputs written")
    command(exe, "siemens output read-back", [*common(target, ports.siemens, "siemens"), "get", "io"], "outputs:\n    0.0: 1")
    command(exe, "siemens output restore", [*common(target, ports.siemens, "siemens"), "set", "output", "01010101"], "Outputs written")
    command(exe, "siemens merker write", [*common(target, ports.siemens, "siemens"), "set", "merkers", "11110000,0"], "Merkers written")
    command(exe, "siemens merker read-back", [*common(target, ports.siemens, "siemens"), "get", "io"], "merkers:\n    0.0: 1")
    command(exe, "siemens merker restore", [*common(target, ports.siemens, "siemens"), "set", "merkers", "01010101,0"], "Merkers written")
    command(exe, "siemens merker restore read-back", [*common(target, ports.siemens, "siemens"), "get", "io"], "merkers:\n    0.0: 0")
    command(exe, "siemens CPU stop", [*common(target, ports.siemens, "siemens"), "set", "state", "stop"], "New state: Stopped")
    command(exe, "siemens stopped read-back", [*common(target, ports.siemens, "siemens"), "get", "state"], "Stopped")
    command(exe, "siemens CPU run restore", [*common(target, ports.siemens, "siemens"), "set", "state", "run"], "New state: Running")

    command(exe, "snmp location write", [*common(target, ports.snmp, "snmp"), "set", "oid", "1.3.6.1.2.1.1.6.0", "LabWrite", "--community", "public", "--confirm"], "SET accepted")
    command(exe, "snmp location read-back", [*common(target, ports.snmp, "snmp"), "get", "oid", "1.3.6.1.2.1.1.6.0", "--community", "public"], "LabWrite")
    command(exe, "snmp location restore", [*common(target, ports.snmp, "snmp"), "set", "oid", "1.3.6.1.2.1.1.6.0", "Lab", "--community", "public", "--confirm"], "SET accepted")

    command(exe, "rockwell tag write", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "PUMP_RUN=false", "--type", "bool"], "written")
    command(exe, "rockwell tag read-back", [*common(target, ports.rockwell, "rockwell"), "get", "tag", "PUMP_RUN"], "false")
    command(exe, "rockwell tag restore", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "PUMP_RUN=true", "--type", "bool"], "written")
    # `--live` must resolve a UDT leaf's atomic CIP type using a read-only
    # Read Tag request even when no leaf inventory exists yet.
    command(exe, "rockwell UDT leaf live-type write", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "LE_LIT_4002.PV=7.5", "--live"], "written")
    command(exe, "rockwell UDT leaf live-type read-back", [*common(target, ports.rockwell, "rockwell"), "get", "tag", "LE_LIT_4002.PV", "--live"], "7.5")
    command(exe, "rockwell UDT leaf live-type restore", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "LE_LIT_4002.PV=6.4", "--live"], "written")
    # A live tag inventory also expands scalar UDTs and saves per-leaf types,
    # so a later write can operate normally without --live or --type real.
    command(exe, "rockwell UDT leaf inventory", [*common(target, ports.rockwell, "rockwell"), "get", "tags", "--live"], "LE_LIT_4002.PV")
    command(exe, "rockwell UDT leaf cached-type write", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "LE_LIT_4002.PV=7.5"], "written")
    command(exe, "rockwell UDT leaf cached-type read-back", [*common(target, ports.rockwell, "rockwell"), "get", "tag", "LE_LIT_4002.PV", "--live"], "7.5")
    command(exe, "rockwell UDT leaf cached-type restore", [*common(target, ports.rockwell, "rockwell"), "set", "tag", "LE_LIT_4002.PV=6.4"], "written")

    command(exe, "fins DM baseline", [*common(target, ports.fins, "omron"), "get", "dm", "7", "1"], "DM7       0")
    command(exe, "fins DM write", [*common(target, ports.fins, "omron"), "set", "dm", "7", "49321"], "DM word(s) written")
    command(exe, "fins DM read-back", [*common(target, ports.fins, "omron"), "get", "dm", "7", "1"], "49321")
    command(exe, "fins DM restore", [*common(target, ports.fins, "omron"), "set", "dm", "7", "0"], "DM word(s) written")
    command(exe, "fins DM restore read-back", [*common(target, ports.fins, "omron"), "get", "dm", "7", "1"], "DM7       0")
    command(exe, "fins CPU stop", [*common(target, ports.fins, "omron"), "set", "state", "stop"], "CPU set to stop")
    command(exe, "fins CPU stopped read-back", [*common(target, ports.fins, "omron"), "get", "state"], "CPU state: Stop")
    command(exe, "fins CPU run restore", [*common(target, ports.fins, "omron"), "set", "state", "run"], "CPU set to run")
    command(exe, "fins CPU run read-back", [*common(target, ports.fins, "omron"), "get", "state"], "CPU state: Run")

    command(exe, "iec104 single command", [*common(target, ports.iec104, "iec104"), "set", "sc", "100", "on"], "confirmed")
    command(exe, "iec104 single read-back", [*common(target, ports.iec104, "iec104"), "get", "gi"], "value=ON")
    command(exe, "iec104 double restore", [*common(target, ports.iec104, "iec104"), "set", "dc", "100", "1"], "confirmed")
    command(exe, "iec104 double read-back", [*common(target, ports.iec104, "iec104"), "get", "gi"], "value=OFF")

    command(exe, "phoenix tag write", [*common(target, ports.phoenix_http, "phoenix"), "set", "tag", "PUMP_RUN=00"], "Wrote PUMP_RUN")
    command(exe, "phoenix tag read-back", [*common(target, ports.phoenix_http, "phoenix"), "get", "tag", "PUMP_RUN"], "00")
    command(exe, "phoenix tag restore", [*common(target, ports.phoenix_http, "phoenix"), "set", "tag", "PUMP_RUN=01"], "Wrote PUMP_RUN")

    mqtt_round_trip(exe, target, ports.mqtt)

    # These protocols deliberately have no standard ``set tag`` operation.
    # Verify CLI callers receive an actionable non-zero error rather than a
    # misleading success when they select an unsupported write path.
    for protocol in ("bacnet", "dnp3", "opc-ua", "schneider"):
        rejected_command(
            exe,
            f"{protocol} unsupported tag write",
            [*common(target, 1, protocol), "set", "tag", "TEST=01"],
            "does not support 'set tag'",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run loopback-only SCADAver CLI write smoke tests")
    parser.add_argument("--profile", choices=sorted(run_all.PROFILES), default="high")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--scadaver", default=str(smoke.default_scadaver_path()))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--logs-dir", default=str(run_all.SIM_DIR / "logs"))
    args = parser.parse_args()

    exe = Path(args.scadaver)
    if not exe.exists():
        print(f"[!] scadaver binary not found: {exe}", file=sys.stderr)
        return 2
    ports = run_all.PROFILES[args.profile]
    db_fd, db_file = tempfile.mkstemp(prefix="scadaver-write-smoke-", suffix=".db")
    os.close(db_fd)
    previous_db = os.environ.get("SCADAVER_DB_PATH")
    os.environ["SCADAVER_DB_PATH"] = db_file
    specs = run_all.filter_specs(run_all.build_specs(args.host, ports), WRITE_FAMILIES)
    run_all.preflight(args.host, specs)
    children = smoke.start_simulators(specs, args.python, Path(args.logs_dir))
    try:
        for spec in specs:
            for port in spec.tcp_ports:
                if not smoke.wait_for_tcp(args.target, port, 8):
                    raise RuntimeError(f"{spec.name} did not open TCP {port}")
            for port in spec.udp_ports:
                if not smoke.wait_for_udp(args.target, port, 8):
                    raise RuntimeError(f"{spec.name} did not respond on UDP {port}")
        prime_inventory(exe, args.target, ports)
        run_writes(exe, args.target, ports)
        print("[+] all loopback write/read-back/restore checks passed")
        return 0
    except Exception as exc:
        print(f"[!] write smoke failed: {exc}", file=sys.stderr)
        return 1
    finally:
        smoke.stop_simulators(children)
        if previous_db is None:
            os.environ.pop("SCADAVER_DB_PATH", None)
        else:
            os.environ["SCADAVER_DB_PATH"] = previous_db
        for suffix in ("", "-wal", "-shm"):
            try:
                Path(f"{db_file}{suffix}").unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
