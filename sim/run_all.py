"""Start all SCADAver protocol simulators for local mass testing."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SIM_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class PortProfile:
    modbus: int
    slmp: int
    beckhoff_ads: int
    beckhoff_discovery: int
    siemens: int
    ewon: int
    snmp: int


PROFILES = {
    "canonical": PortProfile(
        modbus=502,
        slmp=5007,
        beckhoff_ads=48898,
        beckhoff_discovery=48899,
        siemens=102,
        ewon=80,
        snmp=161,
    ),
    "high": PortProfile(
        modbus=1502,
        slmp=15007,
        beckhoff_ads=14898,
        beckhoff_discovery=48899,
        siemens=1102,
        ewon=8080,
        snmp=1161,
    ),
}


@dataclass(frozen=True)
class SimSpec:
    name: str
    script: str
    args: tuple[str, ...]
    tcp_ports: tuple[int, ...] = ()
    udp_ports: tuple[int, ...] = ()

    def command(self, python: str) -> list[str]:
        return [python, str(SIM_DIR / self.script), *self.args]


def valid_port(value: int, name: str) -> int:
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def selected_ports(args: argparse.Namespace) -> PortProfile:
    profile = PROFILES[args.profile]
    return PortProfile(
        modbus=valid_port(args.modbus_port or profile.modbus, "modbus port"),
        slmp=valid_port(args.slmp_port or profile.slmp, "slmp port"),
        beckhoff_ads=valid_port(
            args.beckhoff_ads_port or profile.beckhoff_ads,
            "beckhoff ads port",
        ),
        beckhoff_discovery=valid_port(
            args.beckhoff_discovery_port or profile.beckhoff_discovery,
            "beckhoff discovery port",
        ),
        siemens=valid_port(args.siemens_port or profile.siemens, "siemens port"),
        ewon=valid_port(args.ewon_port or profile.ewon, "ewon port"),
        snmp=valid_port(args.snmp_port or profile.snmp, "snmp port"),
    )


def build_specs(host: str, ports: PortProfile) -> list[SimSpec]:
    return [
        SimSpec(
            "modbus",
            "modbus_sim.py",
            ("--host", host, "--port", str(ports.modbus)),
            tcp_ports=(ports.modbus,),
        ),
        SimSpec(
            "slmp",
            "slmp_sim.py",
            ("--host", host, "--port", str(ports.slmp)),
            tcp_ports=(ports.slmp,),
        ),
        SimSpec(
            "beckhoff",
            "beckhoff_sim.py",
            (
                "--host",
                host,
                "--ads-port",
                str(ports.beckhoff_ads),
                "--discovery-port",
                str(ports.beckhoff_discovery),
            ),
            tcp_ports=(ports.beckhoff_ads,),
            udp_ports=(ports.beckhoff_discovery,),
        ),
        SimSpec(
            "siemens",
            "siemens_sim.py",
            ("--host", host, "--port", str(ports.siemens)),
            tcp_ports=(ports.siemens,),
        ),
        SimSpec(
            "ewon",
            "ewon_sim.py",
            ("--host", host, "--port", str(ports.ewon)),
            tcp_ports=(ports.ewon,),
        ),
        SimSpec(
            "snmp",
            "snmp_sim.py",
            ("--host", host, "--port", str(ports.snmp)),
            udp_ports=(ports.snmp,),
        ),
    ]


def endpoint_conflicts(specs: Iterable[SimSpec]) -> list[str]:
    seen: dict[tuple[str, int], str] = {}
    conflicts = []
    for spec in specs:
        for port in spec.tcp_ports:
            key = ("tcp", port)
            if key in seen:
                conflicts.append(f"TCP {port}: {seen[key]} and {spec.name}")
            seen[key] = spec.name
        for port in spec.udp_ports:
            key = ("udp", port)
            if key in seen:
                conflicts.append(f"UDP {port}: {seen[key]} and {spec.name}")
            seen[key] = spec.name
    return conflicts


def check_bind(host: str, port: int, proto: str) -> None:
    sock_type = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        if proto == "tcp":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))


def preflight(host: str, specs: list[SimSpec]) -> None:
    conflicts = endpoint_conflicts(specs)
    if conflicts:
        raise RuntimeError("profile has conflicting endpoints: " + "; ".join(conflicts))
    for spec in specs:
        for port in spec.tcp_ports:
            check_bind(host, port, "tcp")
        for port in spec.udp_ports:
            check_bind(host, port, "udp")


def print_summary(specs: list[SimSpec], python: str, as_json: bool) -> None:
    rows = [
        {
            "name": spec.name,
            "tcp_ports": list(spec.tcp_ports),
            "udp_ports": list(spec.udp_ports),
            "command": spec.command(python),
        }
        for spec in specs
    ]
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    for row in rows:
        endpoints = []
        endpoints.extend(f"TCP {p}" for p in row["tcp_ports"])
        endpoints.extend(f"UDP {p}" for p in row["udp_ports"])
        print(f"{row['name']:<9} {', '.join(endpoints):<24} {' '.join(row['command'])}")


def print_scadaver_hints(host: str, ports: PortProfile) -> None:
    target = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print("")
    print("Example SCADAver commands:")
    print(f"  scadaver scan schneider -i {target} --port {ports.modbus}")
    print(f"  scadaver scan mitsubishi -i {target} --port {ports.slmp}")
    print(f"  scadaver scan beckhoff -i {target} --port {ports.beckhoff_ads}")
    print(f"  scadaver scan siemens -i {target} --port {ports.siemens}")
    print(f"  scadaver scan ewon -i {target} --port {ports.ewon}")
    print(f"  scadaver snmp enum -t {target} --port {ports.snmp}")


def install_dependencies() -> None:
    req = SIM_DIR / "requirements.txt"
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req)])


def spawn(specs: list[SimSpec], python: str, logs_dir: Path) -> int:
    logs_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    children: list[tuple[SimSpec, subprocess.Popen[bytes], object]] = []
    try:
        for spec in specs:
            log_path = logs_dir / f"{spec.name}.log"
            log_file = log_path.open("ab")
            proc = subprocess.Popen(
                spec.command(python),
                cwd=str(SIM_DIR),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
            )
            children.append((spec, proc, log_file))
            print(f"[+] {spec.name} started pid={proc.pid} log={log_path}")

        print("")
        print("Simulators are running. Press Ctrl+C to stop all.")
        while True:
            for spec, proc, _ in children:
                rc = proc.poll()
                if rc is not None:
                    print(f"[!] {spec.name} exited with code {rc}")
                    return rc or 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("")
        print("[*] stopping simulators...")
        return 0
    finally:
        for _, proc, _ in children:
            if proc.poll() is None:
                proc.terminate()
        deadline = time.time() + 5
        for _, proc, _ in children:
            remaining = max(0.0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
        for _, _, log_file in children:
            log_file.close()


def filter_specs(specs: list[SimSpec], only: list[str] | None) -> list[SimSpec]:
    if not only:
        return specs
    wanted = set(only)
    return [spec for spec in specs if spec.name in wanted]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start SCADAver simulator suite")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=os.environ.get("SCADAVER_SIM_PROFILE", "high"),
        help="port profile to use (default: high)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind all simulators (default: 0.0.0.0)",
    )
    parser.add_argument("--modbus-port", type=int)
    parser.add_argument("--slmp-port", type=int)
    parser.add_argument("--beckhoff-ads-port", type=int)
    parser.add_argument("--beckhoff-discovery-port", type=int)
    parser.add_argument("--siemens-port", type=int)
    parser.add_argument("--ewon-port", type=int)
    parser.add_argument("--snmp-port", type=int)
    parser.add_argument(
        "--only",
        nargs="+",
        choices=["modbus", "slmp", "beckhoff", "siemens", "ewon", "snmp"],
        help="start only selected simulators",
    )
    parser.add_argument(
        "--logs-dir",
        default=str(SIM_DIR / "logs"),
        help="directory for simulator stdout/stderr logs",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="python executable used for child simulators",
    )
    parser.add_argument("--install-deps", action="store_true", help="install sim requirements first")
    parser.add_argument("--skip-preflight", action="store_true", help="skip bind checks")
    parser.add_argument("--dry-run", action="store_true", help="print commands without starting")
    parser.add_argument("--json", action="store_true", help="print dry-run/list output as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ports = selected_ports(args)
    specs = filter_specs(build_specs(args.host, ports), args.only)
    if not specs:
        print("No simulators selected", file=sys.stderr)
        return 2

    if args.install_deps:
        install_dependencies()

    if args.dry_run:
        print_summary(specs, args.python, args.json)
        if not args.json:
            print_scadaver_hints(args.host, ports)
        return 0

    if not args.skip_preflight:
        try:
            preflight(args.host, specs)
        except OSError as exc:
            print(f"[!] port preflight failed: {exc}", file=sys.stderr)
            return 1
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1

    print_summary(specs, args.python, False)
    print_scadaver_hints(args.host, ports)
    return spawn(specs, args.python, Path(args.logs_dir))


if __name__ == "__main__":
    raise SystemExit(main())
