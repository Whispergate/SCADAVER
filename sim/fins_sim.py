"""Omron FINS/TCP stub — TCP port 9600.

Two-phase per connection:
  Phase 1 — address negotiation: 20-byte hello → 24-byte response (server_node=1 at byte 23)
  Phase 2 — FINS command: 16-byte header + body → dispatch on command code:
    05 01  Controller Data Read  → device info (model "CP1E", version "V1.0")
    01 01  Memory Area Read      → count DM words of zero
"""
# Accuracy audit (2026-08): source-traced FINS/TCP fixture, not an Omron PLC
# emulator. Source: Omron Sysmac NJ FINS Technical Guide
# (https://assets.omron.com/m/7b1f867d19635636/original/Sysmac-NJ-FINS-Technical-Guide.pdf).
# Surface: FINS/TCP negotiation, controller-data read, selected DM read/write,
# and run/program state for local CLI regression tests.
import argparse
import os
import socketserver
import struct
import threading

PORT = 9600

_FINS_HDR = bytes([0xC0, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x63, 0x00, 0x01])
_dm_words: dict[int, int] = {}
_cpu_mode = 0x01  # Run
_state_lock = threading.Lock()


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def _fins_tcp_frame(body: bytes) -> bytes:
    length = len(body) + 8
    return (
        b'FINS'
        + struct.pack('>I', length)
        + b'\x00\x00\x00\x02'  # command = 2 (send FINS command)
        + b'\x00\x00\x00\x00'  # error = 0
        + body
    )


def _device_info_resp() -> bytes:
    model = b'CP1E' + b'\x00' * 16   # 20 bytes
    version = b'V1.0' + b'\x00' * 16 # 20 bytes
    body = _FINS_HDR + b'\x00\x00' + model + version  # 52 bytes
    return _fins_tcp_frame(body)


def _dm_read_resp(start: int, count: int) -> bytes:
    with _state_lock:
        data = b''.join(
            _dm_words.get(start + index, 0).to_bytes(2, 'big')
            for index in range(count)
        )
    body = _FINS_HDR + b'\x00\x00' + data
    return _fins_tcp_frame(body)


def _ok_resp(extra: bytes = b'') -> bytes:
    return _fins_tcp_frame(_FINS_HDR + b'\x00\x00' + extra)


_DEVICE_INFO_RESP = _device_info_resp()


class FinsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        global _cpu_mode
        sock = self.request
        sock.settimeout(10)
        try:
            # Phase 1: address negotiation
            recv_exact(sock, 20)  # client hello (auto-assign, node=0)
            neg_resp = (
                b'FINS'
                + struct.pack('>I', 16)    # length = 16
                + b'\x00\x00\x00\x01'     # command = 1 (server node assign response)
                + b'\x00\x00\x00\x00'     # error = 0
                + b'\x00\x00\x00\x00'     # client node assigned = 0
                + b'\x00\x00\x00\x01'     # server node = 1 (at byte 23)
            )  # 24 bytes
            sock.sendall(neg_resp)

            # Phase 2: FINS command
            tcp_hdr = recv_exact(sock, 16)
            length = struct.unpack_from('>I', tcp_hdr, 4)[0]
            body = recv_exact(sock, length - 8)

            cmd = body[10:12]
            if cmd == b'\x05\x01':
                sock.sendall(_DEVICE_INFO_RESP)
            elif cmd == b'\x01\x01':
                start = struct.unpack_from('>H', body, 13)[0]
                count = struct.unpack_from('>H', body, 16)[0]
                sock.sendall(_dm_read_resp(start, count))
            elif cmd == b'\x01\x02':
                start = struct.unpack_from('>H', body, 13)[0]
                count = struct.unpack_from('>H', body, 16)[0]
                values = body[18:]
                with _state_lock:
                    for index in range(count):
                        offset = index * 2
                        if offset + 2 > len(values):
                            break
                        _dm_words[start + index] = int.from_bytes(
                            values[offset : offset + 2], 'big'
                        )
                sock.sendall(_ok_resp())
            elif cmd == b'\x06\x01':
                with _state_lock:
                    mode = _cpu_mode
                sock.sendall(_ok_resp(bytes([mode])))
            elif cmd == b'\x04\x01' and len(body) >= 13:
                with _state_lock:
                    _cpu_mode = body[12]
                sock.sendall(_ok_resp())
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Omron FINS/TCP simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_FINS_PORT", str(PORT))),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socketserver.ThreadingTCPServer((args.host, args.port), FinsHandler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
