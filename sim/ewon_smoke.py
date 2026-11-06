"""Stateful loopback-only eWON Flexy published-Modbus CLI smoke test.

The test starts an isolated simulator, verifies HTTP tag reading and standard
Modbus coil/register reads, performs write/read-back checks, then restores all
modified values before it stops the child process.  It never invokes ``run``
actions or HTTP configuration/credential endpoints.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent


def default_scadaver_path() -> Path:
    executable = "scadaver.exe" if os.name == "nt" else "scadaver"
    return REPO_ROOT / "target" / "debug" / executable


def require_available(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))


def wait_for_tcp(host: str, port: int, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"simulator did not open TCP {host}:{port}")


def command(exe: Path, name: str, arguments: list[str], expected: str) -> None:
    command_args = ["--live", *arguments] if "get" in arguments else arguments
    proc = subprocess.run(
        [str(exe), *command_args],
        cwd=REPO_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=20,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode != 0 or expected not in output:
        raise RuntimeError(
            f"{name} failed (rc={proc.returncode}; expected {expected!r})\n{output.strip()}"
        )
    print(f"[+] {name}")


def rejected_command(exe: Path, name: str, arguments: list[str], expected: str) -> None:
    command_args = ["--live", *arguments] if "get" in arguments else arguments
    proc = subprocess.run(
        [str(exe), *command_args],
        cwd=REPO_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=20,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode == 0 or expected not in output:
        raise RuntimeError(
            f"{name} did not fail as expected (rc={proc.returncode}; expected {expected!r})\n{output.strip()}"
        )
    print(f"[+] {name}")


def cli(target: str, modbus_port: int, *tail: str) -> list[str]:
    return ["-i", target, "-p", str(modbus_port), *tail]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated eWON Flexy Modbus CLI smoke tests")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--target", default="127.0.0.1")
    # Deliberately separate from the high simulator profile (8080/18002), so
    # this stateful test cannot attach to an operator's running lab suite.
    parser.add_argument("--http-port", type=int, default=28080)
    parser.add_argument("--modbus-port", type=int, default=28002)
    parser.add_argument("--udp-port", type=int, default=21507)
    parser.add_argument("--scadaver", default=str(default_scadaver_path()))
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    exe = Path(args.scadaver)
    if not exe.exists():
        print(f"[!] scadaver binary not found: {exe}", file=sys.stderr)
        return 2
    for port in (args.http_port, args.modbus_port):
        if not 1 <= port <= 65535:
            print(f"[!] invalid TCP port {port}", file=sys.stderr)
            return 2

    try:
        require_available(args.host, args.http_port)
        require_available(args.host, args.modbus_port)
    except OSError as exc:
        print(f"[!] isolated eWON smoke port unavailable: {exc}", file=sys.stderr)
        return 2

    db_fd, db_file = tempfile.mkstemp(prefix="scadaver-ewon-smoke-", suffix=".db")
    os.close(db_fd)
    previous_db = os.environ.get("SCADAVER_DB_PATH")
    os.environ["SCADAVER_DB_PATH"] = db_file
    child = subprocess.Popen(
        [
            args.python,
            str(SIM_DIR / "ewon_sim.py"),
            "--host", args.host,
            "--port", str(args.http_port),
            "--modbus-port", str(args.modbus_port),
            "--udp-port", str(args.udp_port),
        ],
        cwd=SIM_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_tcp(args.target, args.http_port)
        wait_for_tcp(args.target, args.modbus_port)
        command(
            exe,
            "eWON HTTP tag read",
            ["-i", args.target, "-p", str(args.http_port), "--protocol", "ewon", "get", "tags"],
            "TANK_LEVEL",
        )
        command(exe, "eWON coil initial read", cli(args.target, args.modbus_port, "get", "ewon-coil", "500"), "coil 500 = ON")
        command(exe, "eWON coil write", cli(args.target, args.modbus_port, "set", "ewon-coil", "500", "off"), "set OFF")
        command(exe, "eWON coil read-back", cli(args.target, args.modbus_port, "get", "ewon-coil", "500"), "coil 500 = OFF")

        command(exe, "eWON u16 initial read", cli(args.target, args.modbus_port, "get", "ewon-register", "501"), "= 70")
        command(exe, "eWON u16 write", cli(args.target, args.modbus_port, "set", "ewon-register", "501", "555"), "written")
        command(exe, "eWON u16 read-back", cli(args.target, args.modbus_port, "get", "ewon-register", "501"), "= 555")

        command(exe, "eWON i16 write", cli(args.target, args.modbus_port, "set", "ewon-register", "504", "-123", "--type", "i16"), "written")
        command(exe, "eWON i16 read-back", cli(args.target, args.modbus_port, "get", "ewon-register", "504", "--type", "i16"), "= -123")

        command(exe, "eWON f32 initial read", cli(args.target, args.modbus_port, "get", "ewon-register", "502", "--type", "f32"), "= 73.5")
        command(exe, "eWON f32 write", cli(args.target, args.modbus_port, "set", "ewon-register", "502", "12.5", "--type", "f32"), "written")
        command(exe, "eWON f32 read-back", cli(args.target, args.modbus_port, "get", "ewon-register", "502", "--type", "f32"), "= 12.5")

        command(exe, "eWON u32 write", cli(args.target, args.modbus_port, "set", "ewon-register", "510", "305419896", "--type", "u32"), "written")
        command(exe, "eWON u32 read-back", cli(args.target, args.modbus_port, "get", "ewon-register", "510", "--type", "u32"), "= 305419896")
        command(exe, "eWON i32 write", cli(args.target, args.modbus_port, "set", "ewon-register", "512", "-123456", "--type", "i32"), "written")
        command(exe, "eWON i32 read-back", cli(args.target, args.modbus_port, "get", "ewon-register", "512", "--type", "i32"), "= -123456")

        rejected_command(exe, "eWON rejects non-finite f32", cli(args.target, args.modbus_port, "set", "ewon-register", "501", "NaN", "--type", "f32"), "must be finite")
        rejected_command(exe, "eWON rejects unit zero", cli(args.target, args.modbus_port, "get", "ewon-coil", "500", "--unit-id", "0"), "unit id 0 is invalid")
        print("[+] all eWON read/write/read-back/restore checks passed")
        return 0
    except Exception as exc:
        print(f"[!] eWON smoke failed: {exc}", file=sys.stderr)
        return 1
    finally:
        # Each write above targets only this new child and its known fixture.
        for restore in (
            ("set", "ewon-coil", "500", "on"),
            ("set", "ewon-register", "501", "70"),
            ("set", "ewon-register", "504", "0", "--type", "i16"),
            ("set", "ewon-register", "502", "73.5", "--type", "f32"),
            ("set", "ewon-register", "510", "0", "--type", "u32"),
            ("set", "ewon-register", "512", "0", "--type", "i32"),
        ):
            subprocess.run(
                [str(exe), *cli(args.target, args.modbus_port, *restore)],
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
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
