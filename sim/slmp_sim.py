"""Mitsubishi SLMP 3E TCP simulator — port 5007.

Handles batch read (command 0x0401):
  subcommand 0x0000 (word): word[i] = start + i
  subcommand 0x0001 (bit): alternating OFF/ON pattern (byte 0x10 per pair)

Expected output with 'Read D Registers 0:10':  D0=0, D1=1, D2=2, ...
Expected output with 'Read M Bits 0:8':        M0=OFF, M1=ON, M2=OFF, M3=ON, ...
"""
import socketserver
import struct
import sys

PORT = 5007
CMD_BATCH_READ = 0x0401
SUBCMD_WORD = 0x0000
SUBCMD_BIT = 0x0001


def slmp_response(payload: bytes) -> bytes:
    data_len = 2 + len(payload)
    header = bytes([0xD0, 0x00, 0xFF, 0xFF, 0xFF, 0x03, 0x00,
                    data_len & 0xFF, (data_len >> 8) & 0xFF])
    return header + b'\x00\x00' + payload


def slmp_error(code: int) -> bytes:
    header = bytes([0xD0, 0x00, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x02, 0x00])
    return header + struct.pack('<H', code)


class SlmpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        try:
            while True:
                # Read 9-byte SLMP 3E request header
                raw = b''
                while len(raw) < 9:
                    chunk = sock.recv(9 - len(raw))
                    if not chunk:
                        return
                    raw += chunk

                if raw[0] != 0x50:
                    return

                data_len = struct.unpack_from('<H', raw, 7)[0]
                body = b''
                while len(body) < data_len:
                    chunk = sock.recv(data_len - len(body))
                    if not chunk:
                        return
                    body += chunk

                if len(body) < 12:
                    sock.sendall(slmp_error(0x0001))
                    continue

                # timer(2) cmd(2) subcmd(2) device(1) start(3) count(2)
                cmd = struct.unpack_from('<H', body, 2)[0]
                subcmd = struct.unpack_from('<H', body, 4)[0]
                start = int.from_bytes(body[7:10], 'little')
                count = struct.unpack_from('<H', body, 10)[0]

                if cmd != CMD_BATCH_READ:
                    sock.sendall(slmp_error(0x0001))
                    continue

                if subcmd == SUBCMD_WORD:
                    payload = b''.join(
                        struct.pack('<H', (start + i) & 0xFFFF)
                        for i in range(count)
                    )
                    sock.sendall(slmp_response(payload))
                elif subcmd == SUBCMD_BIT:
                    # Each byte holds two bits: low nibble = even index, high nibble = odd index.
                    # 0x10 → low=0 (OFF), high=1 (ON) → pattern: OFF, ON, OFF, ON, ...
                    n_bytes = (count + 1) // 2
                    sock.sendall(slmp_response(bytes([0x10] * n_bytes)))
                else:
                    sock.sendall(slmp_error(0x0001))
        except Exception:
            pass


if __name__ == '__main__':
    srv = socketserver.ThreadingTCPServer(('0.0.0.0', PORT), SlmpHandler)
    srv.allow_reuse_address = True
    print(f"SLMP 3E simulator listening on 0.0.0.0:{PORT}")
    print("  Word read: device[i] = start + i")
    print("  Bit  read: OFF, ON, OFF, ON, ...  (0x10 nibble pattern)")
    srv.serve_forever()
