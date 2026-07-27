"""Minimal Beckhoff TwinCAT ADS/AMS simulator.

Provides UDP discovery on 48899 and ADS/TCP responses for state, info,
symbol upload, scalar reads, and writes. This is for local SCADAver smoke tests.
"""

import argparse
import os
import socket
import socketserver
import struct
import threading

DISCOVERY_PORT = 48899
DEFAULT_ADS_PORT = 48898
NETID = bytes([127, 0, 0, 1, 1, 1])
NAME = b"SCADAVER-CX"
SYMBOLS = [
    {
        "name": "MAIN.counter",
        "type": "UINT",
        "index_group": 0x4020,
        "index_offset": 0,
        "size": 2,
        "value": struct.pack("<H", 1234),
    },
    {
        "name": "MAIN.running",
        "type": "BOOL",
        "index_group": 0x4020,
        "index_offset": 2,
        "size": 1,
        "value": b"\x01",
    },
]

ADSIGRP_SYM_UPLOADINFO = 0xF00F
ADSIGRP_SYM_UPLOAD = 0xF00B


def discovery_frame() -> bytes:
    name_len = len(NAME) + 1
    frame = bytearray(340)
    frame[12:18] = NETID
    frame[26:28] = struct.pack("<H", name_len)
    frame[28 : 28 + len(NAME)] = NAME
    frame[28 + len(NAME)] = 0

    kernel_offset = 27 + name_len + 9
    frame[kernel_offset : kernel_offset + 12] = (
        struct.pack("<I", 3) + struct.pack("<I", 1) + struct.pack("<I", 4024)
    )

    tc_offset = kernel_offset + 12 + 264
    frame[tc_offset] = 3
    frame[tc_offset + 1] = 1
    frame[tc_offset + 2 : tc_offset + 4] = struct.pack("<H", 4024)
    return bytes(frame)


def symbol_blob() -> bytes:
    blob = bytearray()
    for sym in SYMBOLS:
        name = sym["name"].encode()
        type_name = sym["type"].encode()
        comment = b""
        entry_len = 30 + len(name) + 1 + len(type_name) + 1 + len(comment) + 1
        entry = bytearray(entry_len)
        struct.pack_into("<I", entry, 0, entry_len)
        struct.pack_into("<I", entry, 4, sym["index_group"])
        struct.pack_into("<I", entry, 8, sym["index_offset"])
        struct.pack_into("<I", entry, 12, sym["size"])
        struct.pack_into("<H", entry, 24, len(name))
        struct.pack_into("<H", entry, 26, len(type_name))
        struct.pack_into("<H", entry, 28, len(comment))
        pos = 30
        entry[pos : pos + len(name)] = name
        pos += len(name) + 1
        entry[pos : pos + len(type_name)] = type_name
        blob.extend(entry)
    return bytes(blob)


SYMBOL_BLOB = symbol_blob()
INFO_XML = (
    "<TreeItem><TargetType>TC3</TargetType><HardwareModel>CX-SIM</HardwareModel>"
    "<SerialNo>SIM-001</SerialNo><ImageOsName>Windows CE</ImageOsName>"
    "<ImageVersion>1.0</ImageVersion></TreeItem>"
).encode("utf-16le")


def ads_read_response(payload: bytes) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack("<I", len(payload)) + payload


def split_ams_request(request: bytes) -> bytes:
    """Return the AMS body from standard or SCADAver-style AMS/TCP packets."""
    if len(request) >= 8 and request[:4] == b"\x00\x00\x00\x00":
        length = struct.unpack_from("<I", request, 4)[0]
        if length <= len(request) - 8:
            return request[8 : 8 + length]
    if len(request) >= 6:
        length = struct.unpack_from("<I", request, 2)[0]
        if length <= len(request) - 6:
            return request[6 : 6 + length]
    return b""


def ams_response(request: bytes, ads_data: bytes, error: int = 0) -> bytes:
    body = split_ams_request(request)
    if len(body) < 36:
        return b""
    dst_netid = body[8:14]
    dst_port = body[14:16]
    src_netid = body[0:6]
    src_port = body[6:8]
    cmd = body[16:18]
    invoke = body[32:36]

    response_body = bytearray()
    response_body.extend(dst_netid)
    response_body.extend(dst_port)
    response_body.extend(src_netid)
    response_body.extend(src_port)
    response_body.extend(cmd)
    response_body.extend(struct.pack("<H", 5))
    response_body.extend(struct.pack("<I", len(ads_data)))
    response_body.extend(struct.pack("<I", error))
    response_body.extend(invoke)
    response_body.extend(ads_data)

    return b"\x00\x00" + struct.pack("<I", len(response_body)) + bytes(response_body)


def handle_ads(request: bytes) -> bytes:
    body = split_ams_request(request)
    if len(body) < 36:
        return b""

    cmd = struct.unpack_from("<H", body, 16)[0]
    ads_data = body[36:]

    if cmd == 4:
        return ams_response(request, b"\x00\x00\x00\x00" + struct.pack("<H", 5) + b"\x00\x00")

    if cmd == 5:
        return ams_response(request, b"\x00\x00\x00\x00")

    if cmd == 3 and len(ads_data) >= 12:
        index_group, index_offset, write_len = struct.unpack_from("<III", ads_data, 0)
        data = ads_data[12 : 12 + write_len]
        for sym in SYMBOLS:
            if (
                index_group == sym["index_group"]
                and index_offset == sym["index_offset"]
            ):
                sym["value"] = data[: sym["size"]].ljust(sym["size"], b"\x00")
                break
        return ams_response(request, b"\x00\x00\x00\x00")

    if cmd == 2 and len(ads_data) >= 12:
        index_group, index_offset, read_len = struct.unpack_from("<III", ads_data, 0)
        if index_group == 700 and index_offset == 1 and read_len == 4:
            return ams_response(request, ads_read_response(struct.pack("<I", len(INFO_XML))))
        if index_group == 700 and index_offset == 1:
            return ams_response(request, ads_read_response(INFO_XML[:read_len]))
        if index_group == ADSIGRP_SYM_UPLOADINFO:
            return ams_response(
                request,
                ads_read_response(struct.pack("<II", len(SYMBOLS), len(SYMBOL_BLOB))),
            )
        if index_group == ADSIGRP_SYM_UPLOAD:
            return ams_response(request, ads_read_response(SYMBOL_BLOB[:read_len]))
        for sym in SYMBOLS:
            if (
                index_group == sym["index_group"]
                and index_offset == sym["index_offset"]
            ):
                return ams_response(request, ads_read_response(sym["value"][:read_len]))

    return ams_response(request, b"\x01\x00\x00\x00")


class AdsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        while True:
            header = sock.recv(6)
            if not header:
                return
            while len(header) < 6:
                chunk = sock.recv(6 - len(header))
                if not chunk:
                    return
                header += chunk
            prefix = header
            length = struct.unpack_from("<I", header, 2)[0]
            if length > 1024 * 1024 and header[:4] == b"\x00\x00\x00\x00":
                extra = sock.recv(2)
                if len(extra) < 2:
                    return
                prefix += extra
                length = struct.unpack_from("<I", prefix, 4)[0]
            body = b""
            while len(body) < length:
                chunk = sock.recv(length - len(body))
                if not chunk:
                    return
                body += chunk
            response = handle_ads(prefix + body)
            if response:
                sock.sendall(response)


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_discovery(stop: threading.Event, host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    frame = discovery_frame()
    while not stop.is_set():
        try:
            _, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        sock.sendto(frame, addr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal Beckhoff ADS simulator")
    parser.add_argument(
        "--ads-port",
        type=int,
        default=int(os.environ.get("SCADAVER_BECKHOFF_ADS_PORT", str(DEFAULT_ADS_PORT))),
        help="ADS TCP port to listen on (default: 48898 or SCADAVER_BECKHOFF_ADS_PORT)",
    )
    parser.add_argument(
        "--discovery-port",
        type=int,
        default=int(os.environ.get("SCADAVER_BECKHOFF_DISCOVERY_PORT", str(DISCOVERY_PORT))),
        help="UDP discovery port to listen on (default: 48899 or SCADAVER_BECKHOFF_DISCOVERY_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not 1 <= args.ads_port <= 65535:
        raise ValueError("--ads-port must be between 1 and 65535")
    if not 1 <= args.discovery_port <= 65535:
        raise ValueError("--discovery-port must be between 1 and 65535")

    stop_event = threading.Event()
    threading.Thread(
        target=udp_discovery,
        args=(stop_event, args.host, args.discovery_port),
        daemon=True,
    ).start()
    server = ReusableThreadingTCPServer((args.host, args.ads_port), AdsHandler)
    print(f"Beckhoff UDP discovery listening on {args.host}:{args.discovery_port}")
    print(f"Beckhoff ADS simulator listening on {args.host}:{args.ads_port}")
    try:
        server.serve_forever()
    finally:
        stop_event.set()
