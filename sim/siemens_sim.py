"""Siemens S7Comm stub — port 102.

Handles the three-step COTP + S7Comm handshake:
  1. COTP CR (byte 5 == 0xE0) -> CC
  2. S7Comm Setup Comm (Job func 0xF0) -> Ack-Data
  3. S7Comm Read Variable (Job func 0x04) -> Ack-Data with 4 bytes 0xAA

0xAA = 10101010 binary -> bit pattern: 0,1,0,1,0,1,0,1 per byte
Expected output with 'Read I/O': I0.0=0 I0.1=1 I0.2=0 I0.3=1 ...

CPU state check (UserData msg type 0x07) -> 50-byte response, byte[44]=0x08 -> "Running"
"""
# Accuracy audit (2026-08): source-traced TPKT/COTP/S7Comm fixture, not a
# Siemens CPU emulator. Sources: RFC 1006 (https://www.rfc-editor.org/rfc/rfc1006)
# and Siemens communication-function documentation
# (https://cache.industry.siemens.com/dl/files/925/59192925/att_61992/v1/s71500_communication_function_manual_en-US_en-US.pdf).
# Surface: COTP setup, selected S7Comm state/read/write frames, and SZL state
# reads. The full S7Comm wire specification is not public; vectors are implementation-tested only.
import argparse
from collections import defaultdict
import os
import socketserver
import struct
import threading

PORT = 102

# COTP Connection Confirm (CC): TPKT(22 bytes), byte[5]=0xD0
COTP_CC = bytes.fromhex('0300001611d000000001' '00c0010ac1020100c2020102')

# S7Comm Ack-Data for Setup Comm: 27 bytes, byte[9]=0x00, param_len=8
S7_SETUP_ACK = bytes.fromhex(
    '0300001b'  # TPKT (27)
    '02f080'    # COTP DT
    '3203'      # S7 proto, Ack-Data
    '0000'      # reserved (byte 9 = 0x00)
    '0000'      # PDU ref
    '0008'      # param_len = 8
    '0000'      # data_len = 0
    '0000'      # error class + error code
    'f000'      # SetupComm func + reserved
    '0001'      # max AMQ caller = 1
    '0001'      # max AMQ callee = 1
    '01e0'      # PDU size = 480
)

# State is deliberately in-memory and reset for every simulator process.
_outputs = bytearray([0xAA] * 256)
_merkers = bytearray([0xAA] * 256)
_dbs: dict[int, bytearray] = defaultdict(lambda: bytearray([0xAA] * 256))
_cpu_mode = 0x01  # Running
_state_lock = threading.Lock()


def tpkt(payload: bytes) -> bytes:
    return b'\x03\x00' + (len(payload) + 4).to_bytes(2, 'big') + payload


def s7_read_ack(data: bytes) -> bytes:
    """Return an Ack-Data ReadVar response with a valid one-item payload."""
    item = b'\xff\x04' + (len(data) * 8).to_bytes(2, 'big') + data
    s7 = (
        b'\x32\x03\x00\x00\x00\x00'
        + b'\x00\x02'
        + len(item).to_bytes(2, 'big')
        + b'\x00\x00\x04\x01'
        + item
    )
    return tpkt(b'\x02\xf0\x80' + s7)


S7_WRITE_ACK = s7_read_ack(b'\xff')

def szl_ack(szl_id: int, record: bytes) -> bytes:
    data = (
        b'\xff\x09'
        + len(record).to_bytes(2, 'big')
        + szl_id.to_bytes(2, 'big')
        + b'\x00\x01'  # SZL index
        + b'\x00\x01'  # record count
        + len(record).to_bytes(2, 'big')
        + record
    )
    body = (
        b'\x02\xf0\x80'
        b'\x32\x07'
        b'\x00\x00'
        b'\x00\x01'
        b'\x00\x08'
        + len(data).to_bytes(2, 'big')
        + b'\x00\x00'
        + data
    )
    return b'\x03\x00' + (len(body) + 4).to_bytes(2, 'big') + body


module_record = bytearray(28)
module_record[0:2] = b'\x00\x01'
module_record[2:22] = b'6ES7 315-2EH14-0AB0'.ljust(20)[:20]
module_record[26] = 3
module_record[27] = 2
MODULE_INFO_ACK = szl_ack(0x0011, bytes(module_record))



def cpu_state_ack() -> bytes:
    with _state_lock:
        mode = _cpu_mode
    return szl_ack(0x0424, b'\x00\x01' + bytes([mode, 0x00]))


def read_area(area: int, db_num: int, byte_offset: int, count: int) -> bytes:
    count = max(count, 1)
    with _state_lock:
        if area == 0x82:  # outputs (Q)
            source = _outputs
        elif area == 0x83:  # merkers (M)
            source = _merkers
        elif area == 0x84:  # data block
            source = _dbs[db_num]
        else:  # inputs and unsupported areas remain deterministic read-only bytes
            source = bytearray([0xAA] * 256)
        end = byte_offset + count
        if end > len(source):
            source.extend(b'\x00' * (end - len(source)))
        return bytes(source[byte_offset:end])


def write_area(area: int, db_num: int, byte_offset: int, data: bytes) -> None:
    if not data:
        return
    with _state_lock:
        if area == 0x82:
            target = _outputs
        elif area == 0x83:
            target = _merkers
        elif area == 0x84:
            target = _dbs[db_num]
        else:
            return
        end = byte_offset + len(data)
        if end > len(target):
            target.extend(b'\x00' * (end - len(target)))
        target[byte_offset:end] = data


def parse_s7any_request(pkt: bytes, expected_function: int) -> tuple[int, int, int, int, bytes] | None:
    """Validate the bounded byte-oriented ReadVar/WriteVar surface we model.

    This is deliberately stricter than the old fixed-offset fixture parser:
    a frame must declare its own TPKT, parameter, and data lengths correctly
    before it can read or change in-memory state.
    """
    if (
        len(pkt) < 31
        or pkt[:2] != b'\x03\x00'
        or int.from_bytes(pkt[2:4], 'big') != len(pkt)
        or pkt[4:7] != b'\x02\xf0\x80'
        or pkt[7:9] != b'\x32\x01'
    ):
        return None

    param_len = int.from_bytes(pkt[13:15], 'big')
    data_len = int.from_bytes(pkt[15:17], 'big')
    if param_len != 14 or len(pkt) != 17 + param_len + data_len:
        return None

    parameter = pkt[17:17 + param_len]
    if (
        parameter[0] != expected_function
        or parameter[1] != 0x01
        or parameter[2:5] != b'\x12\x0a\x10'
    ):
        return None

    transport_size = parameter[5]
    if expected_function == 0x04:
        # Casket uses 0x06 for its I/O bit-map read and 0x02 for byte reads.
        if transport_size not in (0x02, 0x06):
            return None
    elif transport_size != 0x02:
        # Writes in this fixture are always complete bytes, never bit writes.
        return None

    count = int.from_bytes(parameter[6:8], 'big')
    db_num = int.from_bytes(parameter[8:10], 'big')
    area = parameter[10]
    bit_addr = int.from_bytes(parameter[11:14], 'big')
    if count == 0 or bit_addr % 8:
        return None

    data = pkt[17 + param_len:]
    if expected_function == 0x04:
        if data:
            return None
        return area, db_num, bit_addr // 8, count, b''

    if (
        data_len != 4 + count
        or len(data) != data_len
        or data[:2] != b'\x00\x04'
        or int.from_bytes(data[2:4], 'big') != count * 8
    ):
        return None
    return area, db_num, bit_addr // 8, count, data[4:]


def parse_cpu_control_mode(pkt: bytes) -> int | None:
    """Recognise only the bounded OMS+ control vector emitted by Casket.

    The simulator is not a CPU controller.  Requiring the full control-frame
    shape prevents arbitrary UserData frames (or a coincidental marker byte)
    from changing its test state.
    """
    header = bytes.fromhex('0300007802f08072020069310000054200000003000003')
    if (
        len(pkt) != 0x78
        or pkt[:len(header)] != header
        or pkt[24:28] != b'\x34\x00\x00\x03'
        or pkt[29:33] != b'\x01\x01\x82\x32'
        or pkt[-4:] != b'\x72\x02\x00\x00'
    ):
        return None
    if pkt[28] == 0xce:
        return 0x01  # Running
    if pkt[28] == 0x88:
        return 0x03  # Stopped
    return None


def apply_cpu_control(pkt: bytes) -> bool:
    """Apply a recognised simulator-only control vector and report success."""
    global _cpu_mode
    mode = parse_cpu_control_mode(pkt)
    if mode is None:
        return False
    with _state_lock:
        _cpu_mode = mode
    return True


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


class SiemensHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        global _cpu_mode
        sock = self.request
        sock.settimeout(10)
        try:
            while True:
                tpkt_hdr = recv_exact(sock, 4)
                total_len = struct.unpack('>H', tpkt_hdr[2:4])[0]
                body = recv_exact(sock, total_len - 4)
                pkt = tpkt_hdr + body

                cotp_type = pkt[5] if len(pkt) > 5 else 0

                if cotp_type == 0xE0:
                    # COTP Connection Request -> Connection Confirm
                    sock.sendall(COTP_CC)

                elif cotp_type == 0xF0 and len(pkt) > 8 and pkt[7] == 0x32:
                    msg_type = pkt[8]
                    if msg_type == 0x01 and len(pkt) > 17:
                        func = pkt[17]
                        if func == 0xF0:
                            sock.sendall(S7_SETUP_ACK)
                        elif func == 0x04:
                            parsed = parse_s7any_request(pkt, 0x04)
                            if parsed is not None:
                                area, db_num, byte_offset, count, _ = parsed
                                sock.sendall(s7_read_ack(read_area(
                                    area, db_num, byte_offset, count
                                )))
                        elif func == 0x05:
                            parsed = parse_s7any_request(pkt, 0x05)
                            if parsed is not None:
                                area, db_num, byte_offset, count, payload = parsed
                                write_area(area, db_num, byte_offset, payload[:count])
                                sock.sendall(S7_WRITE_ACK)
                    elif msg_type == 0x07:
                        szl_id = struct.unpack('>H', pkt[-4:-2])[0] if len(pkt) >= 4 else 0
                        if szl_id == 0x0011:
                            sock.sendall(MODULE_INFO_ACK)
                        else:
                            sock.sendall(cpu_state_ack())

                elif cotp_type == 0xF0 and len(pkt) > 8 and pkt[7] == 0x72:
                    # The control client uses OMS+ UserData frames. It only
                    # requires valid responses, while CPU state is observed via
                    # a subsequent SZL read.  Only the exact bounded state
                    # vector may affect simulator state.
                    apply_cpu_control(pkt)
                    sock.sendall(cpu_state_ack())
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Siemens S7Comm simulator")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_SIEMENS_PORT", str(PORT))),
        help="TCP port to listen on (default: 102 or SCADAVER_SIEMENS_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    srv = socketserver.ThreadingTCPServer((args.host, args.port), SiemensHandler)
    srv.allow_reuse_address = True
    print(f"Siemens S7Comm stub listening on {args.host}:{args.port}")
    print("  COTP CR  -> CC")
    print("  S7 Setup -> Ack-Data (param_len=8, PDU=480)")
    print("  S7 Read/Write -> stateful Q, M, and DB values (in memory only)")
    print("  CPU state -> OMS+ toggle with SZL read-back")
    print("  list_data_blocks: DB1..DB200 respond with deterministic in-memory bytes")
    srv.serve_forever()
