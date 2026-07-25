"""Siemens S7Comm stub — port 102.

Handles the three-step COTP + S7Comm handshake:
  1. COTP CR (byte 5 == 0xE0) -> CC
  2. S7Comm Setup Comm (Job func 0xF0) -> Ack-Data
  3. S7Comm Read Variable (Job func 0x04) -> Ack-Data with 4 bytes 0xAA

0xAA = 10101010 binary -> bit pattern: 0,1,0,1,0,1,0,1 per byte
Expected output with 'Read I/O': I0.0=0 I0.1=1 I0.2=0 I0.3=1 ...

CPU state check (UserData msg type 0x07) -> 50-byte response, byte[44]=0x08 -> "Running"
"""
import socketserver
import struct

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

# S7Comm Ack-Data for Read Variable: 29 bytes, 4 bytes 0xAA, byte[9]=0x00
# Data item: return_code=0xFF, transport_size=BIT(0x04), length=32bits, data=0xAA*4
S7_READ_ACK = bytes.fromhex(
    '0300001d'      # TPKT (29)
    '02f080'        # COTP DT
    '3203'          # S7 proto, Ack-Data
    '0000'          # reserved (byte 9 = 0x00)
    '0000'          # PDU ref
    '0002'          # param_len = 2
    '0008'          # data_len = 8
    '0000'          # error class + error code
    '0401'          # params: Read func (0x04), item count = 1
    'ff04'          # data item: return_code=0xFF, transport_size=BIT(0x04)
    '0020'          # bit length = 32
    'aaaaaaaa'      # 4 bytes of 0xAA = 10101010
)

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

CPU_STATE_ACK = szl_ack(0x0424, b'\x00\x01\x01\x00')


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
                            sock.sendall(S7_READ_ACK)
                    elif msg_type == 0x07:
                        szl_id = struct.unpack('>H', pkt[-4:-2])[0] if len(pkt) >= 4 else 0
                        if szl_id == 0x0011:
                            sock.sendall(MODULE_INFO_ACK)
                        else:
                            sock.sendall(CPU_STATE_ACK)
        except Exception:
            pass


if __name__ == '__main__':
    srv = socketserver.ThreadingTCPServer(('0.0.0.0', PORT), SiemensHandler)
    srv.allow_reuse_address = True
    print(f"Siemens S7Comm stub listening on 0.0.0.0:{PORT}")
    print("  COTP CR  -> CC")
    print("  S7 Setup -> Ack-Data (param_len=8, PDU=480)")
    print("  S7 Read  -> 4x0xAA (bit pattern: 0,1,0,1,...) per area")
    print("  CPU state -> Running (byte[44]=0x08)")
    print("  list_data_blocks: all 200 DBs appear responsive (returns fake 4-byte block)")
    srv.serve_forever()
