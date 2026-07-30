"""IEC 60870-5-104 stub — TCP port 2404.

Two exchanges per connection:
  1. STARTDT_ACT (68 04 07 00 00 00) → STARTDT_CON (68 04 0b 00 00 00)
  2. GI I-frame (any) → GI ActCon with 0 objects
"""
import argparse
import os
import socketserver

PORT = 2404

# C_IC_NA_1 ActCon: type=100, vsq=0 objects, COT=ActCon(7), addr=1
_GI_ACTCON = bytes.fromhex('68 0a 00 00 00 00 64 00 07 00 01 00'.replace(' ', ''))
_STARTDT_CON = b'\x68\x04\x0b\x00\x00\x00'
_STARTDT_ACT_CTRL = b'\x07\x00\x00\x00'


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


class IEC104Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        try:
            # Exchange 1: STARTDT
            frame = recv_exact(sock, 6)  # start(1) + len(1) + ctrl(4)
            if frame[2:6] == _STARTDT_ACT_CTRL:
                sock.sendall(_STARTDT_CON)

            # Exchange 2: GI I-frame
            header = recv_exact(sock, 2)  # start byte + length byte
            if header[0] == 0x68:
                recv_exact(sock, header[1])  # discard control field + ASDU
                sock.sendall(_GI_ACTCON)
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IEC 60870-5-104 simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_IEC104_PORT", str(PORT))),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socketserver.ThreadingTCPServer((args.host, args.port), IEC104Handler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
