"""eWON HTTP stub — port 80.

Exposes only ``GET /api/tags/`` over HTTP plus the UDP IPCONF discovery
response. It deliberately does not emulate credentials, configuration, or
write endpoints.
"""
# Accuracy audit (2026-08): source-traced eWON Flexy tag-publication fixture,
# not an eWON appliance emulator. Source: HMS Networks' Flexy Modbus TCP guide
# (https://support.hms-networks.com/hc/en-us/articles/11964515209234-How-to-publish-Ewon-Flexy-tags-through-Modbus-TCP).
# Surface: IPCONF discovery, GET tag values, and unit-id 100 Modbus publication;
# it deliberately omits authentication, configuration, and administration APIs.
import argparse
import asyncio
import http.server
import json
import os
import struct
import threading

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

PORT = 80
MODBUS_PORT = 502
MODBUS_UNIT_ID = 100
# Published Flexy tags use zero-based Modbus addresses.  32-bit values are
# low 16-bit word first, then high 16-bit word.  TANK_LEVEL=73.5 is IEEE754
# 0x42930000, therefore HR502=0x0000 and HR503=0x4293.
ewon_store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(504, [0]),
    co=ModbusSequentialDataBlock(500, [1]),
    hr=ModbusSequentialDataBlock(501, [70, 0x0000, 0x4293, *([0] * 18)]),
    zero_mode=True,
)
ewon_context = ModbusServerContext(slaves={MODBUS_UNIT_ID: ewon_store}, single=False)


def current_tags() -> dict[str, list[dict[str, object]]]:
    """Keep the legacy HTTP read view aligned with the published Modbus map."""
    pump_run = bool(ewon_store.getValues(1, 500, 1)[0])
    low_word, high_word = ewon_store.getValues(3, 502, 2)
    tank_bits = low_word | (high_word << 16)
    tank_level = struct.unpack("<f", struct.pack("<I", tank_bits))[0]
    return {
        "body": [
            {"name": "PUMP_RUN", "value": str(pump_run).lower()},
            {"name": "TANK_LEVEL", "value": tank_level},
            {"name": "ALARM_ACTIVE", "value": "false"},
        ]
    }


def _build_ipconf_response() -> bytes:
    resp = bytearray(38)
    resp[0:4] = b"IPCO"            # identifier → data[0..4]
    resp[15] = 2                    # response_type = device_info
    resp[16] = 1                    # product_code
    # IP 127.0.0.1 stored in reversed-octet order (data[23].data[22].data[21].data[20])
    resp[20] = 1; resp[21] = 0; resp[22] = 0; resp[23] = 127
    # netmask 255.255.255.0 reversed
    resp[24] = 0; resp[25] = 0xFF; resp[26] = 0xFF; resp[27] = 0xFF
    # MAC
    resp[32] = 0xDE; resp[33] = 0xAD; resp[34] = 0xBE
    resp[35] = 0xEF; resp[36] = 0x00; resp[37] = 0x01
    return bytes(resp)


def _udp_ipconf_worker(host: str, port: int) -> None:
    import socket as _socket
    resp = _build_ipconf_response()
    with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        # Bind the host the caller asked for; see eip_sim.py for why 0.0.0.0 is wrong here.
        sock.bind((host, port))
        sock.settimeout(1.0)
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 7 and data[:7] == b"IPCONF\x00":
                    sock.sendto(resp, addr)
            except _socket.timeout:
                continue


# Split on '","': 19 separators -> 20 parts
EWON_RESPONSE = (
    '"filler",'    # [0] starts with '"'
    '"John",'      # [1] first_name
    '"Doe",'       # [2] last_name
    '"admin",'     # [3] username
    '"!invalid!",' # [4] password (fails base64 -> <decode failed>)
    '"",'          # [5] information
    '"15",'        # [6] access_rights
    '"",'          # [7]
    '"",'          # [8]
    '"",'          # [9]
    '"",'          # [10]
    '"",'          # [11]
    '"",'          # [12]
    '"",'          # [13]
    '"",'          # [14]
    '"",'          # [15]
    '"",'          # [16]
    '"",'          # [17]
    '"",'          # [18]
    '"filler"'     # [19] ends with '"'
)


class EwonHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # silence access log
        pass

    def do_POST(self) -> None:
        # The lab simulator intentionally does not emulate credential or
        # configuration endpoints. SCADaver's web rollout validates only the
        # safe read-only tag endpoint below.
        self.send_response(405)
        self.end_headers()

    def do_GET(self) -> None:
        if self.path != '/api/tags/':
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(current_tags()).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="eWON HTTP simulator")
    parser.add_argument(
        "legacy_port",
        nargs="?",
        type=int,
        help="legacy positional TCP port",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="TCP port to listen on (default: 80 or EWON_SIM_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=1507,
        help="UDP port for IPCONF discovery responses (default: 1507)",
    )
    parser.add_argument(
        "--modbus-port",
        type=int,
        default=int(os.environ.get("EWON_MODBUS_PORT", str(MODBUS_PORT))),
        help="published-tag Modbus TCP port (default: 502 or EWON_MODBUS_PORT)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    port = args.port or args.legacy_port or int(os.environ.get("EWON_SIM_PORT", str(PORT)))
    if not 1 <= port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    if not 1 <= args.modbus_port <= 65535:
        raise ValueError("--modbus-port must be between 1 and 65535")

    threading.Thread(
        target=_udp_ipconf_worker, args=(args.host, args.udp_port), daemon=True
    ).start()

    srv = http.server.ThreadingHTTPServer((args.host, port), EwonHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"eWON HTTP stub listening on {args.host}:{port}")
    print("  GET /api/tags/ -> three read-only process values")
    print(f"eWON Flexy Modbus TCP listening on {args.host}:{args.modbus_port} (unit {MODBUS_UNIT_ID})")
    print("  coil 500 PUMP_RUN=true; HR501 SPEED_SETPOINT=70; HR502/503 TANK_LEVEL=73.5 f32")
    await StartAsyncTcpServer(
        context=ewon_context,
        address=(args.host, args.modbus_port),
    )


if __name__ == '__main__':
    asyncio.run(main())
