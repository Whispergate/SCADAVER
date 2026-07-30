"""Omron FINS/TCP stub — TCP port 9600.

Two-phase per connection:
  Phase 1 — address negotiation: 20-byte hello → 24-byte response (server_node=1 at byte 23)
  Phase 2 — FINS command: 16-byte header + body → dispatch on command code:
    05 01  Controller Data Read  → device info (model "CP1E", version "V1.0")
    01 01  Memory Area Read      → count DM words of zero
"""
import argparse
import os
import socketserver
import struct

PORT = 9600

_FINS_HDR = bytes([0xC0, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x63, 0x00, 0x01])


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


def _dm_read_resp(count: int) -> bytes:
    body = _FINS_HDR + b'\x00\x00' + b'\x00' * (count * 2)
    return _fins_tcp_frame(body)


_DEVICE_INFO_RESP = _device_info_resp()


class FinsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
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
                count = struct.unpack_from('>H', body, 16)[0]
                sock.sendall(_dm_read_resp(count))
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
