"""IEC 60870-5-104 stub — TCP port 2404.

Two exchanges per connection:
  1. STARTDT_ACT (68 04 07 00 00 00) → STARTDT_CON (68 04 0b 00 00 00)
  2. GI I-frame (any) → GI ActCon with 0 objects
"""
# Accuracy audit (2026-08): source-traced IEC 60870-5-104 test fixture, not an
# RTU or SCADA-server emulator. Primary standard: IEC 60870-5-104
# (https://webstore.iec.ch/en/publication/3746); interoperability reference:
# lib60870 (https://github.com/mz-automation/lib60870).
# Surface: STARTDT/TESTFR, GI confirmation, and one controlled single/double point.
import argparse
import os
import socketserver
import threading

PORT = 2404

# C_IC_NA_1 ActCon: type=100, vsq=0 objects, COT=ActCon(7), addr=1
_GI_ACTCON = bytes.fromhex('68 0a 00 00 00 00 64 00 07 00 01 00'.replace(' ', ''))
_STARTDT_CON = b'\x68\x04\x0b\x00\x00\x00'
_STARTDT_ACT_CTRL = b'\x07\x00\x00\x00'
_TESTFR_ACT_CTRL = b'\x43\x00\x00\x00'
_TESTFR_CON = b'\x68\x04\x83\x00\x00\x00'
_OUTPUT_IOA = 100
_points = {_OUTPUT_IOA: 0}
_state_lock = threading.Lock()


def _iframe(asdu: bytes, tx_seq: int = 0, rx_seq: int = 1) -> bytes:
    ctrl = bytes([(tx_seq << 1) & 0xFF, (tx_seq >> 7) & 0xFF,
                  (rx_seq << 1) & 0xFF, (rx_seq >> 7) & 0xFF])
    return b'\x68' + bytes([len(ctrl) + len(asdu)]) + ctrl + asdu


def _gi_frames() -> bytes:
    with _state_lock:
        value = _points[_OUTPUT_IOA]
    data_asdu = bytes([
        1, 1, 20, 0, 1, 0,  # M_SP_NA_1, one object, interrogation response
        _OUTPUT_IOA & 0xFF, (_OUTPUT_IOA >> 8) & 0xFF, (_OUTPUT_IOA >> 16) & 0xFF,
        value,
    ])
    term_asdu = bytes([100, 0, 10, 0, 1, 0])  # GI activation termination
    return _iframe(data_asdu, 0, 1) + _iframe(term_asdu, 1, 1)


def _command_confirmation(asdu: bytes) -> bytes:
    type_id = asdu[0]
    ioa = int.from_bytes(asdu[6:9], 'little')
    value = asdu[9] & (0x03 if type_id == 46 else 0x01)
    observed = int(value == 2) if type_id == 46 else value
    with _state_lock:
        _points[ioa] = observed
    confirm = bytes([
        type_id, 1, 7, 0, asdu[4], asdu[5],
        *asdu[6:9], value,
    ])
    return _iframe(confirm, 0, 1)


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
            if frame[2:6] == _TESTFR_ACT_CTRL:
                sock.sendall(_TESTFR_CON)
                return
            if frame[2:6] == _STARTDT_ACT_CTRL:
                sock.sendall(_STARTDT_CON)
            else:
                return

            # Exchange 2: GI or a confirmed command I-frame.
            header = recv_exact(sock, 2)  # start byte + length byte
            if header[0] == 0x68:
                body = recv_exact(sock, header[1])
                asdu = body[4:]
                if asdu and asdu[0] == 100:
                    sock.sendall(_gi_frames())
                elif len(asdu) >= 10 and asdu[0] in (45, 46):
                    sock.sendall(_command_confirmation(asdu))
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
