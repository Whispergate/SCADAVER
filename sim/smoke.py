"""End-to-end smoke tests for SCADAver simulators.

Starts the local simulator suite, runs read-only scadaver CLI commands against
the high-port profile, and reports command output on failure.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from . import run_all
except ImportError:
    import run_all


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = "127.0.0.1"


@dataclass(frozen=True)
class SmokeCase:
    name: str
    simulator: str
    args: tuple[str, ...]
    expect: tuple[str, ...]


def default_scadaver_path() -> Path:
    exe = "scadaver.exe" if os.name == "nt" else "scadaver"
    return REPO_ROOT / "target" / "debug" / exe


def build_cases(target: str, ports: run_all.PortProfile) -> list[SmokeCase]:
    return [
        SmokeCase(
            "schneider-scan-tcp",
            "modbus",
            ("scan", "schneider", "-i", target, "--transport", "tcp", "--port", str(ports.modbus)),
            ("Modbus TCP",),
        ),
        SmokeCase(
            "modbus-read-hr",
            "modbus",
            (
                "exploit",
                "modbus-read-registers",
                "--target",
                target,
                "--port",
                str(ports.modbus),
                "--start",
                "0",
                "--count",
                "3",
            ),
            ("40001", "register(s) read"),
        ),
        SmokeCase(
            "modbus-read-coils",
            "modbus",
            (
                "exploit",
                "modbus-read-coils",
                "--target",
                target,
                "--port",
                str(ports.modbus),
                "--start",
                "0",
                "--count",
                "4",
            ),
            ("coil(s) read",),
        ),
        SmokeCase(
            "mitsubishi-scan-tcp",
            "slmp",
            ("scan", "mitsubishi", "-i", target, "--transport", "tcp", "--port", str(ports.slmp)),
            ("SLMP TCP",),
        ),
        SmokeCase(
            "slmp-read-d",
            "slmp",
            (
                "exploit",
                "slmp-read-d",
                "--target",
                target,
                "--port",
                str(ports.slmp),
                "--start",
                "0",
                "--count",
                "3",
            ),
            ("D0", "D register(s) read"),
        ),
        SmokeCase(
            "slmp-read-m",
            "slmp",
            (
                "exploit",
                "slmp-read-m",
                "--target",
                target,
                "--port",
                str(ports.slmp),
                "--start",
                "0",
                "--count",
                "4",
            ),
            ("M0", "M bit(s) read"),
        ),
        SmokeCase(
            "beckhoff-scan-ads",
            "beckhoff",
            ("scan", "beckhoff", "-i", target, "--port", str(ports.beckhoff_ads)),
            ("Beckhoff",),
        ),
        SmokeCase(
            "siemens-scan",
            "siemens",
            ("scan", "siemens", "-i", target, "--port", str(ports.siemens)),
            ("Hardware", "CPU"),
        ),
        SmokeCase(
            "siemens-cpu",
            "siemens",
            ("siemens", "cpu", "--target", target, "--port", str(ports.siemens)),
            ("CPU state",),
        ),
        SmokeCase(
            "ewon-creds",
            "ewon",
            ("exploit", "ewon-creds", "--target", target, "--port", str(ports.ewon), "--max-users", "2"),
            ("admin", "credential"),
        ),
        SmokeCase(
            "ewon-scan",
            "ewon",
            ("scan", "ewon", "-i", target),
            ("IPCO",),
        ),
        SmokeCase(
            "snmp-enum",
            "snmp",
            ("snmp", "enum", "--target", target, "--port", str(ports.snmp)),
            ("sysDescr", "SCALANCE", "community"),
        ),
        SmokeCase(
            "snmp-walk",
            "snmp",
            ("snmp", "walk", "--target", target, "--oid", "1.3.6.1.2.1.1", "--port", str(ports.snmp)),
            ("1.3.6.1.2.1.1.1.0",),
        ),
        SmokeCase(
            "snmp-scan",
            "snmp",
            ("snmp", "scan", "--target", target, "--port", str(ports.snmp)),
            ("public",),
        ),
        SmokeCase(
            "siemens-io",
            "siemens",
            ("siemens", "io", "--target", target, "--port", str(ports.siemens)),
            ("inputs",),
        ),
        SmokeCase(
            "slmp-write-d",
            "slmp",
            (
                "exploit",
                "slmp-write-d",
                "--target",
                target,
                "--start",
                "0",
                "--port",
                str(ports.slmp),
                "100,200",
            ),
            ("D register(s) written",),
        ),
        SmokeCase(
            "rockwell-info",
            "rockwell",
            ("rockwell", "info", "--target", target, "--port", str(ports.rockwell)),
            ("Vendor:",),
        ),
        SmokeCase(
            "rockwell-tags",
            "rockwell",
            ("rockwell", "tags", "--target", target, "--port", str(ports.rockwell)),
            ("tag",),
        ),
        SmokeCase(
            "enip-scan",
            "rockwell",
            ("scan", "enip", "-i", target),
            ("PLC",),
        ),
        SmokeCase(
            "fins-info",
            "fins",
            ("omron", "info", "--target", target, "--port", str(ports.fins)),
            ("Model:",),
        ),
        SmokeCase(
            "fins-read-dm",
            "fins",
            (
                "omron",
                "read-dm",
                "--target",
                target,
                "--port",
                str(ports.fins),
                "--start",
                "0",
                "--count",
                "10",
            ),
            ("DM0",),
        ),
        SmokeCase(
            "iec104-gi",
            "iec104",
            ("iec104", "gi", "--target", target, "--port", str(ports.iec104)),
            ("STARTDT confirmed",),
        ),
        SmokeCase(
            "phoenix-info",
            "phoenix",
            ("phoenix", "info", "--target", target, "--port", str(ports.phoenix)),
            ("PLC Type:",),
        ),
        SmokeCase(
            "phoenix-tags",
            "phoenix",
            ("phoenix", "tags", "--target", target, "--port", str(ports.phoenix_http)),
            ("PUMP_RUN",),
        ),
    ]


def wait_for_tcp(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


# Minimal SNMPv2c GET for sysDescr.0 with community "public"
_SNMP_PROBE = bytes([
    0x30, 0x26,
    0x02, 0x01, 0x01,                                # version = 1 (v2c)
    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, # community = "public"
    0xa0, 0x19,
    0x02, 0x01, 0x01,                                # request-id = 1
    0x02, 0x01, 0x00,                                # error-status = 0
    0x02, 0x01, 0x00,                                # error-index = 0
    0x30, 0x0e,
    0x30, 0x0c,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # sysDescr.0
    0x05, 0x00,                                      # NULL
])


def wait_for_udp(host: str, port: int, timeout: float) -> bool:
    """Wait until a UDP SNMP agent responds to a sysDescr probe."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.sendto(_SNMP_PROBE, (host, port))
                sock.recv(1024)
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def start_simulators(
    specs: list[run_all.SimSpec],
    python: str,
    logs_dir: Path,
) -> list[tuple[run_all.SimSpec, subprocess.Popen[bytes], object]]:
    logs_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    children = []
    for spec in specs:
        log_path = logs_dir / f"{spec.name}.smoke.log"
        log_file = log_path.open("ab")
        proc = subprocess.Popen(
            spec.command(python),
            cwd=str(run_all.SIM_DIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
        )
        children.append((spec, proc, log_file))
        print(f"[+] started {spec.name:<9} pid={proc.pid} log={log_path}")
    return children


def stop_simulators(children: list[tuple[run_all.SimSpec, subprocess.Popen[bytes], object]]) -> None:
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


def run_case(scadaver: Path, case: SmokeCase, timeout: float) -> bool:
    command = [str(scadaver), *case.args]
    print(f"[*] {case.name}: {' '.join(command)}")
    proc = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    missing = [needle for needle in case.expect if needle not in output]
    if proc.returncode == 0 and not missing:
        print(f"[+] {case.name} passed")
        return True

    print(f"[!] {case.name} failed rc={proc.returncode}")
    if missing:
        print(f"[!] missing expected text: {', '.join(missing)}")
    print(output.strip())
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run simulator-backed SCADAver smoke tests")
    parser.add_argument("--profile", choices=sorted(run_all.PROFILES), default="high")
    parser.add_argument("--host", default="127.0.0.1", help="simulator bind host")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="target IP for scadaver commands")
    parser.add_argument("--scadaver", default=str(default_scadaver_path()))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--logs-dir", default=str(run_all.SIM_DIR / "logs"))
    parser.add_argument(
        "--only",
        nargs="+",
        choices=["modbus", "slmp", "beckhoff", "siemens", "ewon", "snmp",
                 "rockwell", "fins", "iec104", "phoenix"],
        help="run only cases for selected simulator families",
    )
    parser.add_argument("--no-start", action="store_true", help="use already-running simulators")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print planned commands only")
    parser.add_argument("--startup-timeout", type=float, default=8.0)
    parser.add_argument("--case-timeout", type=float, default=50.0)
    parser.add_argument(
        "--repeat", type=int, default=1, metavar="N",
        help="repeat the full suite N times (stress / flakiness detection)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ports = run_all.PROFILES[args.profile]
    specs = run_all.filter_specs(run_all.build_specs(args.host, ports), args.only)
    cases = build_cases(args.target, ports)
    if args.only:
        wanted = set(args.only)
        cases = [case for case in cases if case.simulator in wanted]

    scadaver = Path(args.scadaver)
    if not scadaver.exists() and not args.dry_run:
        print(f"[!] scadaver binary not found: {scadaver}", file=sys.stderr)
        print("    Run `cargo build` or pass --scadaver <path>.", file=sys.stderr)
        return 2

    if args.dry_run:
        for case in cases:
            print(f"{case.name:<22} {scadaver} {' '.join(case.args)}")
        return 0

    if not args.no_start and not args.skip_preflight:
        try:
            run_all.preflight(args.host, specs)
        except Exception as exc:
            print(f"[!] preflight failed: {exc}", file=sys.stderr)
            return 1

    children = []
    try:
        if not args.no_start:
            children = start_simulators(specs, args.python, Path(args.logs_dir))
            for spec in specs:
                for port in spec.tcp_ports:
                    if not wait_for_tcp(args.target, port, args.startup_timeout):
                        print(f"[!] {spec.name} did not open TCP {port}", file=sys.stderr)
                        return 1
                for port in spec.udp_ports:
                    if not wait_for_udp(args.target, port, args.startup_timeout):
                        print(f"[!] {spec.name} did not respond on UDP {port}", file=sys.stderr)
                        return 1

        total_failed = 0
        for round_num in range(args.repeat):
            if args.repeat > 1:
                print(f"[*] Round {round_num + 1}/{args.repeat}")
            failed = 0
            for case in cases:
                if not run_case(scadaver, case, args.case_timeout):
                    failed += 1
            total_failed += failed
            if args.repeat > 1 and failed:
                print(f"[!] Round {round_num + 1}: {failed} failure(s)")
        if total_failed:
            print(f"[!] {total_failed} total failure(s) across {args.repeat} round(s)")
            return 1
        print(f"[+] {len(cases) * args.repeat} run(s) across {args.repeat} round(s), all passed")
        return 0
    finally:
        stop_simulators(children)


if __name__ == "__main__":
    raise SystemExit(main())
