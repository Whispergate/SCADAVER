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
        choices=["modbus", "slmp", "beckhoff", "siemens", "ewon"],
        help="run only cases for selected simulator families",
    )
    parser.add_argument("--no-start", action="store_true", help="use already-running simulators")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print planned commands only")
    parser.add_argument("--startup-timeout", type=float, default=8.0)
    parser.add_argument("--case-timeout", type=float, default=20.0)
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

        failed = 0
        for case in cases:
            if not run_case(scadaver, case, args.case_timeout):
                failed += 1
        if failed:
            print(f"[!] {failed} smoke case(s) failed")
            return 1
        print(f"[+] {len(cases)} smoke case(s) passed")
        return 0
    finally:
        stop_simulators(children)


if __name__ == "__main__":
    raise SystemExit(main())
