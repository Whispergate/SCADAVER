"""Mitsubishi SLMP 3E TCP simulator.

Handles batch read/write:
  command 0x0401: batch read
  command 0x1401: batch write
  subcommand 0x0000 (word): word[i] = start + i
  subcommand 0x0001 (bit): alternating OFF/ON pattern (byte 0x10 per pair)

Expected output with 'Read D Registers 0:10':  D0=0, D1=1, D2=2, ...
Expected output with 'Read M Bits 0:8':        M0=OFF, M1=ON, M2=OFF, M3=ON, ...
"""

import argparse
import os
import socketserver
import struct

CMD_BATCH_READ = 0x0401
CMD_BATCH_WRITE = 0x1401
SUBCMD_WORD = 0x0000
SUBCMD_BIT = 0x0001


def slmp_response(payload: bytes) -> bytes:
    data_len = 2 + len(payload)
    header = bytes(
        [
            0xD0,
            0x00,
            0xFF,
            0xFF,
            0xFF,
            0x03,
            0x00,
            data_len & 0xFF,
            (data_len >> 8) & 0xFF,
        ]
    )
    return header + b"\x00\x00" + payload


def slmp_error(code: int) -> bytes:
    header = bytes([0xD0, 0x00, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x02, 0x00])
    return header + struct.pack("<H", code)


class SlmpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        try:
            while True:
                raw = b""
                while len(raw) < 9:
                    chunk = sock.recv(9 - len(raw))
                    if not chunk:
                        return
                    raw += chunk

                if raw[0] != 0x50:
                    return

                data_len = struct.unpack_from("<H", raw, 7)[0]
                body = b""
                while len(body) < data_len:
                    chunk = sock.recv(data_len - len(body))
                    if not chunk:
                        return
                    body += chunk

                if len(body) < 12:
                    sock.sendall(slmp_error(0x0001))
                    continue

                cmd = struct.unpack_from("<H", body, 2)[0]
                subcmd = struct.unpack_from("<H", body, 4)[0]
                start = int.from_bytes(body[7:10], "little")
                count = struct.unpack_from("<H", body, 10)[0]

                if cmd == CMD_BATCH_READ and subcmd == SUBCMD_WORD:
                    payload = b"".join(
                        struct.pack("<H", (start + i) & 0xFFFF) for i in range(count)
                    )
                    sock.sendall(slmp_response(payload))
                elif cmd == CMD_BATCH_READ and subcmd == SUBCMD_BIT:
                    n_bytes = (count + 1) // 2
                    sock.sendall(slmp_response(bytes([0x10] * n_bytes)))
                elif cmd == CMD_BATCH_WRITE and subcmd in (SUBCMD_WORD, SUBCMD_BIT):
                    sock.sendall(slmp_response(b""))
                else:
                    sock.sendall(slmp_error(0x0001))
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mitsubishi SLMP 3E TCP simulator")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_SLMP_PORT", "5007")),
        help="TCP port to listen on (default: 5007 or SCADAVER_SLMP_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    srv = socketserver.ThreadingTCPServer((args.host, args.port), SlmpHandler)
    srv.allow_reuse_address = True
    print(f"SLMP 3E simulator listening on {args.host}:{args.port}")
    print("  Word read: device[i] = start + i")
    print("  Bit  read: OFF, ON, OFF, ON, ...  (0x10 nibble pattern)")
    print("  Writes: ACK success")
    srv.serve_forever()
