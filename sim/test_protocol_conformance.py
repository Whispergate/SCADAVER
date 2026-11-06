"""Independent protocol checks for the local simulator fixtures.

These checks deliberately use raw standard frames or a client library that is
not SCADAver/Casket.  They prove only the bounded surfaces documented in the
simulator headers; they do not certify vendor-product or safety conformance.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable

SIMULATOR_SOURCES = (
    "sim/modbus_sim.py",
    "sim/slmp_sim.py",
    "sim/beckhoff_sim.py",
    "sim/siemens_sim.py",
    "sim/ewon_sim.py",
    "sim/fins_sim.py",
    "sim/iec104_sim.py",
    "sim/mqtt_sim.py",
    "sim/phoenix_sim.py",
    "sim/snmp_sim.py",
    "sim/eip_sim.py",
    "sim/dnp3_sim.py",
    "sim/opcua_sim.py",
    "scripts/sim_bacnet.py",
    "scripts/sim_modbus.py",
    "scripts/sim_opcua.py",
    "scripts/sim_snmp.py",
)


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(f"connection closed with {remaining} byte(s) pending")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def load_siemens_fixture_module():
    """Load the standalone fixture without starting its TCP server."""
    source = REPO_ROOT / "sim" / "siemens_sim.py"
    spec = importlib.util.spec_from_file_location("scadaver_siemens_fixture", source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {source}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def s7_byte_write_packet(area: int, byte_offset: int, value: int) -> bytes:
    """One-byte S7 WriteVar vector used to test the bounded fixture surface."""
    return bytes.fromhex(
        "0300002402f08032010000732f000e0005"
        f"0501120a100200010000{area:02x}{byte_offset * 8:06x}"
        f"00040008{value:02x}"
    )


def s7_io_read_packet(area: int) -> bytes:
    """Casket's one-byte I/O map ReadVar vector (transport size 0x06)."""
    return bytes.fromhex(
        "0300001f02f08032010000732f000e0000"
        f"0401120a100600010000{area:02x}000000"
    )


def s7_cpu_control_packet(command: int) -> bytes:
    """Minimal complete shape of Casket's supported OMS+ control vector."""
    packet = bytearray(0x78)
    header = bytes.fromhex("0300007802f08072020069310000054200000003000003")
    packet[:len(header)] = header
    packet[23] = 0x80  # server-assigned session byte
    packet[24:28] = b"\x34\x00\x00\x03"
    packet[28] = command
    packet[29:33] = b"\x01\x01\x82\x32"
    packet[-4:] = b"\x72\x02\x00\x00"
    return bytes(packet)


def dnp_crc16(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def dnp_link_frame(function: int, destination: int = 10, source: int = 1) -> bytes:
    header = bytes((5, 0xC0 | function, destination & 0xff, destination >> 8, source & 0xff, source >> 8))
    return b"\x05\x64" + header + struct.pack("<H", dnp_crc16(header))


def dnp_data_frame(apdu: bytes, destination: int = 10, source: int = 1) -> bytes:
    data = b"\xc0" + apdu
    header = bytes((5 + len(data), 0xC3, destination & 0xff, destination >> 8, source & 0xff, source >> 8))
    frame = bytearray(b"\x05\x64" + header + struct.pack("<H", dnp_crc16(header)))
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        frame.extend(block)
        frame.extend(struct.pack("<H", dnp_crc16(block)))
    return bytes(frame)


def recv_dnp_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 10)
    if header[:2] != b"\x05\x64" or dnp_crc16(header[2:8]) != struct.unpack_from("<H", header, 8)[0]:
        raise AssertionError("response was not a valid DNP3 data-link frame")
    data_size = header[2] - 5
    payload = bytearray()
    while data_size:
        block_size = min(16, data_size)
        block = recv_exact(sock, block_size)
        if dnp_crc16(block) != struct.unpack("<H", recv_exact(sock, 2))[0]:
            raise AssertionError("DNP3 data-block CRC mismatch")
        payload.extend(block)
        data_size -= block_size
    return header + bytes(payload)


def modbus_tcp_request(port: int, unit_id: int, pdu: bytes, transaction_id: int = 1) -> bytes:
    """Send one Modbus/TCP ADU without using SCADAver or pymodbus."""
    header = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(header + pdu)
        response_header = recv_exact(sock, 7)
        response_tid, protocol_id, length, response_unit = struct.unpack(
            ">HHHB", response_header
        )
        if response_tid != transaction_id or protocol_id != 0 or response_unit != unit_id:
            raise AssertionError("response MBAP header did not match request")
        return recv_exact(sock, length - 1)


def slmp_tcp_request(
    port: int,
    command: int,
    subcommand: int,
    device_code: int,
    address: int,
    count: int,
    values: bytes = b"",
) -> bytes:
    """Send one SLMP 3E request without using SCADAver or Casket."""
    body = (
        b"\x00\x00"  # monitoring timer
        + struct.pack("<HH", command, subcommand)
        + bytes([device_code])
        + address.to_bytes(3, "little")
        + struct.pack("<H", count)
        + values
    )
    request = b"\x50\x00\xff\xff\xff\x03\x00" + struct.pack("<H", len(body)) + body
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(request)
        header = recv_exact(sock, 9)
        response_len = struct.unpack_from("<H", header, 7)[0]
        return recv_exact(sock, response_len)


def fins_tcp_request(port: int, command: bytes, payload: bytes) -> bytes:
    """Perform FINS/TCP node negotiation plus one request using standard frames."""
    fins_header = bytes([0x80, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
    body = fins_header + command + payload
    frame = (
        b"FINS"
        + struct.pack(">I", len(body) + 8)
        + b"\x00\x00\x00\x02\x00\x00\x00\x00"
        + body
    )
    hello = b"FINS" + struct.pack(">I", 12) + b"\x00" * 12
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(hello)
        negotiation = recv_exact(sock, 24)
        if negotiation[:4] != b"FINS" or negotiation[23] != 1:
            raise AssertionError("FINS/TCP node negotiation was invalid")
        sock.sendall(frame)
        header = recv_exact(sock, 16)
        if header[:4] != b"FINS":
            raise AssertionError("response was not a FINS/TCP frame")
        return recv_exact(sock, struct.unpack_from(">I", header, 4)[0] - 8)


def recv_iec104_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 2)
    if header[0] != 0x68:
        raise AssertionError("response was not an IEC 104 APDU")
    return header + recv_exact(sock, header[1])


def wait_for_tcp(port: int, process: subprocess.Popen[str], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"simulator exited early: {output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"simulator did not accept TCP on 127.0.0.1:{port}")


@contextmanager
def simulator(script: str, *args: str):
    process = subprocess.Popen(
        [PYTHON, str(REPO_ROOT / script), *args],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


class SimulatorProvenanceTests(unittest.TestCase):
    def test_every_simulator_declares_scope_and_source(self) -> None:
        for relative_path in SIMULATOR_SOURCES:
            with self.subTest(simulator=relative_path):
                source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("Accuracy audit", source)
                self.assertIn("http", source)
                self.assertIn("Surface:", source)

    def test_scope_notes_do_not_claim_vendor_device_emulation(self) -> None:
        for relative_path in (
            "sim/eip_sim.py",
            "sim/siemens_sim.py",
            "sim/phoenix_sim.py",
            "sim/beckhoff_sim.py",
            "sim/fins_sim.py",
        ):
            with self.subTest(simulator=relative_path):
                source = (REPO_ROOT / relative_path).read_text(encoding="utf-8").lower()
                self.assertIn("not a", source)
                self.assertIn("emulator", source)

    def test_independent_client_requirements_are_fully_pinned(self) -> None:
        requirements = REPO_ROOT / "sim" / "requirements-test.txt"
        lines = [
            line.strip()
            for line in requirements.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertGreaterEqual(len(lines), 6)
        self.assertTrue(all("==" in line for line in lines), lines)


class IndependentWireTests(unittest.TestCase):
    def test_modbus_fc3_and_fc6_match_standard_mbap_vectors(self) -> None:
        port = free_tcp_port()
        with simulator(
            "sim/modbus_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            self.assertEqual(
                b"\x03\x06\x00\x00\x00\x0a\x00\x14",
                modbus_tcp_request(port, 1, b"\x03\x00\x00\x00\x03"),
            )
            self.assertEqual(
                b"\x06\x00\x07\x12\x34",
                modbus_tcp_request(port, 1, b"\x06\x00\x07\x12\x34", 2),
            )
            self.assertEqual(
                b"\x03\x02\x12\x34",
                modbus_tcp_request(port, 1, b"\x03\x00\x07\x00\x01", 3),
            )

    def test_ewon_http_and_unit_100_modbus_tag_publication_agree(self) -> None:
        http_port = free_tcp_port()
        modbus_port = free_tcp_port()
        udp_port = free_udp_port()
        with simulator(
            "sim/ewon_sim.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(http_port),
            "--modbus-port",
            str(modbus_port),
            "--udp-port",
            str(udp_port),
        ) as process:
            wait_for_tcp(http_port, process)
            wait_for_tcp(modbus_port, process)
            self.assertEqual(
                b"\x01\x01\x01",
                modbus_tcp_request(modbus_port, 100, b"\x01\x01\xf4\x00\x01"),
            )
            self.assertEqual(
                b"\x03\x04\x00\x00\x42\x93",
                modbus_tcp_request(modbus_port, 100, b"\x03\x01\xf6\x00\x02", 2),
            )
            # FC16 changes TANK_LEVEL from 73.5 to 80.0.  eWON's documented
            # publication order is low 16-bit word first, then high word.
            self.assertEqual(
                b"\x10\x01\xf6\x00\x02",
                modbus_tcp_request(
                    modbus_port,
                    100,
                    b"\x10\x01\xf6\x00\x02\x04\x00\x00\x42\xa0",
                    3,
                ),
            )
            with urlopen(f"http://127.0.0.1:{http_port}/api/tags/", timeout=2) as response:
                payload = json.load(response)
            tags = {tag["name"]: tag["value"] for tag in payload["body"]}
            self.assertTrue(tags["PUMP_RUN"])
            self.assertEqual(80.0, tags["TANK_LEVEL"])

    def test_slmp_3e_batch_read_write_readback_vectors(self) -> None:
        port = free_tcp_port()
        with simulator(
            "sim/slmp_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            # 0x0401 batch-read D7..D8 returns the deterministic initial words.
            self.assertEqual(
                b"\x00\x00\x07\x00\x08\x00",
                slmp_tcp_request(port, 0x0401, 0x0000, 0xA8, 7, 2),
            )
            # 0x1401 batch-write D7 then the independent raw read sees it.
            self.assertEqual(
                b"\x00\x00",
                slmp_tcp_request(
                    port, 0x1401, 0x0000, 0xA8, 7, 1, struct.pack("<H", 0x1234)
                ),
            )
            self.assertEqual(
                b"\x00\x00\x34\x12",
                slmp_tcp_request(port, 0x0401, 0x0000, 0xA8, 7, 1),
            )

    def test_fins_tcp_node_negotiation_and_dm_write_readback(self) -> None:
        port = free_tcp_port()
        address = b"\x82\x00\x07\x00"  # DM, word 7, bit 0
        count = b"\x00\x01"
        with simulator(
            "sim/fins_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00\x00\x00",
                fins_tcp_request(port, b"\x01\x01", address + count),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00",
                fins_tcp_request(port, b"\x01\x02", address + count + b"\x12\x34"),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00\x12\x34",
                fins_tcp_request(port, b"\x01\x01", address + count),
            )

    def test_fins_cpu_mode_control_changes_the_reported_mode(self) -> None:
        port = free_tcp_port()
        with simulator(
            "sim/fins_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00\x01",
                fins_tcp_request(port, b"\x06\x01", b""),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00",
                fins_tcp_request(port, b"\x04\x01", b"\x00"),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00\x00",
                fins_tcp_request(port, b"\x06\x01", b""),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00",
                fins_tcp_request(port, b"\x04\x01", b"\x01"),
            )
            self.assertEqual(
                b"\xc0\x00\x02\x00\x00\x01\x00\x63\x00\x01\x00\x00\x01",
                fins_tcp_request(port, b"\x06\x01", b""),
            )

    def test_dnp3_link_status_and_group_zero_attributes(self) -> None:
        """Check the fixture with independently built IEEE 1815 frames."""
        port = free_tcp_port()
        with simulator(
            "sim/dnp3_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(dnp_link_frame(0x00))
                self.assertEqual(0x00, recv_dnp_frame(sock)[3] & 0x0f)
                sock.sendall(dnp_link_frame(0x09))
                self.assertEqual(0x0b, recv_dnp_frame(sock)[3] & 0x0f)

            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(dnp_link_frame(0x00))
                recv_dnp_frame(sock)
                # Application read, invoke 1, group 0, variation 0, no-range.
                sock.sendall(dnp_data_frame(b"\x01\x01\x00\x00\x06"))
                response = recv_dnp_frame(sock)
                self.assertEqual(b"\xc0\x81\x00\x00", response[10:14])
                self.assertIn(b"SCADAver Labs", response)
                self.assertIn(b"DNP3 Test Outstation", response)

    def test_iec104_startdt_gi_and_single_command_confirmation(self) -> None:
        port = free_tcp_port()
        startdt = b"\x68\x04\x07\x00\x00\x00"
        # A C_SC_NA_1 single command for IOA 100, value ON.
        command = b"\x68\x0e\x00\x00\x00\x00" + bytes(
            [45, 1, 6, 0, 1, 0, 100, 0, 0, 1]
        )
        # C_IC_NA_1 general interrogation activation.
        gi = b"\x68\x0e\x00\x00\x00\x00" + bytes(
            [100, 1, 6, 0, 1, 0, 0, 0, 0, 20]
        )
        with simulator(
            "sim/iec104_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(startdt)
                self.assertEqual(b"\x68\x04\x0b\x00\x00\x00", recv_iec104_frame(sock))
                sock.sendall(command)
                self.assertEqual(45, recv_iec104_frame(sock)[6])

            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(startdt)
                self.assertEqual(b"\x68\x04\x0b\x00\x00\x00", recv_iec104_frame(sock))
                sock.sendall(gi)
                data = recv_iec104_frame(sock)
                termination = recv_iec104_frame(sock)
                self.assertEqual(1, data[6])  # M_SP_NA_1
                self.assertEqual(1, data[-1])  # command state persisted
                self.assertEqual(100, termination[6])  # C_IC_NA_1 termination

    def test_phoenix_binary_and_webvisit_limited_surface(self) -> None:
        port = free_tcp_port()
        http_port = free_tcp_port()
        with simulator(
            "sim/phoenix_sim.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--http-port",
            str(http_port),
        ) as process:
            wait_for_tcp(port, process)
            wait_for_tcp(http_port, process)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(b"\x00" * 26)
                self.assertEqual(b"\x00" * 18, recv_exact(sock, 18))
                sock.sendall(b"\x00" * 22)
                self.assertEqual(b"\x00", recv_exact(sock, 1))
                sock.sendall(b"\x00" * 14)
                info = recv_exact(sock, 100)
                self.assertEqual(b"ILC 150 ETH", info[30:41])
                self.assertEqual(b"3.20", info[66:70])

            with urlopen(f"http://127.0.0.1:{http_port}/app.tcr", timeout=2) as response:
                self.assertIn(b"PUMP_RUN", response.read())

    def test_enip_list_identity_encapsulation_vector(self) -> None:
        port = free_tcp_port()
        udp_port = free_udp_port()
        request = b"\x63\x00" + b"\x00\x00" + b"\x00" * 20
        with simulator(
            "sim/eip_sim.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--udp-port",
            str(udp_port),
        ) as process:
            wait_for_tcp(port, process)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(request)
                header = recv_exact(sock, 24)
                self.assertEqual(0x0063, struct.unpack_from("<H", header)[0])
                payload = recv_exact(sock, struct.unpack_from("<H", header, 2)[0])
                self.assertEqual(1, struct.unpack_from("<H", payload)[0])  # CPF item count
                self.assertEqual(0x000C, struct.unpack_from("<H", payload, 2)[0])
                self.assertEqual(b"\x01\x00", payload[24:26])  # Rockwell vendor ID
                self.assertIn(b"PLC", payload)

    def test_ads_ams_read_state_frame_reports_run(self) -> None:
        ads_port = free_tcp_port()
        discovery_port = free_udp_port()
        destination = bytes([127, 0, 0, 1, 1, 1])
        source = bytes([127, 0, 0, 1, 1, 2])
        # Minimal AMS ReadState request.  This is deliberately built here,
        # outside both Rust implementations, to lock the fixture's wire surface.
        ams = (
            destination
            + struct.pack("<H", 851)
            + source
            + struct.pack("<H", 32905)
            + struct.pack("<H", 4)  # ADS ReadState command
            + struct.pack("<I", 4)
            + struct.pack("<I", 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 1)
        )
        request = b"\x00\x00" + struct.pack("<I", len(ams)) + ams
        with simulator(
            "sim/beckhoff_sim.py",
            "--host",
            "127.0.0.1",
            "--ads-port",
            str(ads_port),
            "--discovery-port",
            str(discovery_port),
        ) as process:
            wait_for_tcp(ads_port, process)
            with socket.create_connection(("127.0.0.1", ads_port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(request)
                tcp_header = recv_exact(sock, 6)
                response = recv_exact(sock, struct.unpack_from("<I", tcp_header, 2)[0])
                self.assertTrue(response.endswith(b"\x00\x00\x05\x00\x00\x00"))

    def test_siemens_cotp_connection_confirm_vector(self) -> None:
        port = free_tcp_port()
        cotp_connection_request = bytes.fromhex(
            "0300001611e00000000100c0010ac1020100c2020102"
        )
        expected_confirm = bytes.fromhex(
            "0300001611d00000000100c0010ac1020100c2020102"
        )
        with simulator(
            "sim/siemens_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(cotp_connection_request)
                self.assertEqual(expected_confirm, recv_exact(sock, len(expected_confirm)))

    def test_siemens_writevar_rejects_malformed_lengths_before_state_change(self) -> None:
        fixture = load_siemens_fixture_module()
        packet = s7_byte_write_packet(0x83, 0, 0xaa)
        parsed = fixture.parse_s7any_request(packet, 0x05)
        self.assertEqual((0x83, 0, 0, 1, b"\xaa"), parsed)
        self.assertEqual(
            (0x82, 0, 0, 1, b""),
            fixture.parse_s7any_request(s7_io_read_packet(0x82), 0x04),
        )

        malformed = bytearray(packet)
        malformed[15:17] = b"\x00\x06"  # declares one byte too many
        self.assertIsNone(fixture.parse_s7any_request(bytes(malformed), 0x05))

    def test_siemens_cpu_control_requires_the_supported_complete_vector(self) -> None:
        fixture = load_siemens_fixture_module()
        original_mode = fixture._cpu_mode
        try:
            fixture._cpu_mode = 0x03
            malformed = bytearray(s7_cpu_control_packet(0xce))
            malformed[29] = 0x00
            self.assertFalse(fixture.apply_cpu_control(bytes(malformed)))
            self.assertEqual(0x03, fixture._cpu_mode)

            self.assertTrue(fixture.apply_cpu_control(s7_cpu_control_packet(0xce)))
            self.assertEqual(0x01, fixture._cpu_mode)
            self.assertTrue(fixture.apply_cpu_control(s7_cpu_control_packet(0x88)))
            self.assertEqual(0x03, fixture._cpu_mode)
        finally:
            fixture._cpu_mode = original_mode

    def test_snmpv2c_get_set_get_uses_external_pysnmp_client(self) -> None:
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                get_cmd,
                set_cmd,
            )
            from pysnmp.proto.rfc1902 import OctetString
        except ModuleNotFoundError:
            self.skipTest("install sim/requirements-test.txt to run the pysnmp check")

        async def request(port: int) -> None:
            target = await UdpTransportTarget.create(
                ("127.0.0.1", port), timeout=1, retries=0
            )
            common = (
                SnmpEngine(),
                CommunityData("public", mpModel=1),
                target,
                ContextData(),
            )
            error, status, _, var_binds = await get_cmd(
                *common,
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )
            self.assertIsNone(error)
            self.assertEqual(0, int(status))
            self.assertIn("SCALANCE X200", var_binds[0][1].prettyPrint())

            error, status, _, var_binds = await set_cmd(
                *common,
                ObjectType(
                    ObjectIdentity("1.3.6.1.2.1.1.6.0"), OctetString("AuditLab")
                ),
            )
            self.assertIsNone(error)
            self.assertEqual(0, int(status))
            self.assertEqual("AuditLab", var_binds[0][1].prettyPrint())

            error, status, _, var_binds = await get_cmd(
                *common,
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.6.0")),
            )
            self.assertIsNone(error)
            self.assertEqual(0, int(status))
            self.assertEqual("AuditLab", var_binds[0][1].prettyPrint())

        port = free_udp_port()
        with simulator(
            "sim/snmp_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ):
            # UDP has no listener handshake; let the process bind before Pysnmp sends.
            time.sleep(0.2)
            asyncio.run(request(port))

    def test_mqtt_publish_subscribe_works_with_external_paho_client(self) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ModuleNotFoundError:
            self.skipTest("install sim/requirements-test.txt to run the Paho check")

        port = free_tcp_port()
        connected = threading.Event()
        subscribed = threading.Event()
        received = threading.Event()
        messages: list[bytes] = []
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="scadaver-sim-audit",
            protocol=mqtt.MQTTv311,
        )

        def on_connect(client, userdata, flags, reason_code, properties) -> None:
            if reason_code == 0:
                client.subscribe("scadaver/audit/vector", qos=1)
                connected.set()

        def on_subscribe(client, userdata, mid, reason_codes, properties) -> None:
            subscribed.set()

        def on_message(client, userdata, message) -> None:
            messages.append(message.payload)
            received.set()

        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.on_message = on_message
        with simulator(
            "sim/mqtt_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process)
            try:
                client.connect("127.0.0.1", port, keepalive=5)
                client.loop_start()
                self.assertTrue(connected.wait(5), "Paho client did not connect")
                self.assertTrue(subscribed.wait(5), "Paho client did not subscribe")
                publication = client.publish("scadaver/audit/vector", b"mqtt-3.1.1", qos=1)
                publication.wait_for_publish(timeout=5)
                self.assertTrue(received.wait(5), "Paho client did not receive publication")
                self.assertEqual([b"mqtt-3.1.1"], messages)
            finally:
                client.disconnect()
                client.loop_stop()

    def test_opcua_fixture_exposes_a_read_only_temperature_with_external_client(self) -> None:
        try:
            from asyncua import Client
        except ModuleNotFoundError:
            self.skipTest("install sim/requirements-test.txt to run the asyncua check")

        async def exercise(port: int) -> None:
            async with Client(f"opc.tcp://127.0.0.1:{port}/freeopcua/server/") as client:
                objects = await client.nodes.objects.get_children()
                device = None
                for node in objects:
                    if (await node.read_browse_name()).Name == "SimDevice":
                        device = node
                        break
                self.assertIsNotNone(device)
                temperature = None
                for node in await device.get_children():
                    if (await node.read_browse_name()).Name == "Temperature":
                        temperature = node
                        break
                self.assertIsNotNone(temperature)
                self.assertEqual(21.5, await temperature.read_value())

        port = free_tcp_port()
        with simulator(
            "sim/opcua_sim.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process, timeout=20)
            asyncio.run(exercise(port))

    def test_opcua_read_write_restore_works_with_external_asyncua_client(self) -> None:
        try:
            from asyncua import Client
        except ModuleNotFoundError:
            self.skipTest("install sim/requirements-test.txt to run the asyncua check")

        async def exercise(port: int) -> None:
            async with Client(f"opc.tcp://127.0.0.1:{port}/freeopcua/server/") as client:
                objects = await client.nodes.objects.get_children()
                device = None
                for node in objects:
                    if (await node.read_browse_name()).Name == "CIDevice":
                        device = node
                        break
                self.assertIsNotNone(device)
                tag = None
                for node in await device.get_children():
                    if (await node.read_browse_name()).Name == "Tag1":
                        tag = node
                        break
                self.assertIsNotNone(tag)
                original = await tag.read_value()
                self.assertEqual(42.0, original)
                await tag.write_value(43.5)
                self.assertEqual(43.5, await tag.read_value())
                await tag.write_value(original)
                self.assertEqual(original, await tag.read_value())

        port = free_tcp_port()
        with simulator(
            "scripts/sim_opcua.py", "--host", "127.0.0.1", "--port", str(port)
        ) as process:
            wait_for_tcp(port, process, timeout=20)
            asyncio.run(exercise(port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
