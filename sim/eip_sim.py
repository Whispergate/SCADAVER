"""Rockwell EtherNet/IP stub — TCP port 44818.

Handles List Identity (0x0063), Register Session (0x0065), and SendRRData (0x006F).
Each connection may carry multiple requests; dispatches on the EIP command word.
"""
import argparse
import os
import socketserver
import struct
import threading

PORT = 44818


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def _build_list_identity_resp() -> bytes:
    item = (
        b'\x01\x00'           # enc_version
        + b'\x00' * 16        # socket_addr (all zeros)
        + b'\x01\x00'         # vendor_id = 1 (Rockwell Automation)
        + b'\x0e\x00'         # device_type = 0x000E
        + b'\x01\x00'         # product_code
        + b'\x1f\x03'         # revision: major=31, minor=3
        + b'\x00\x00'         # status
        + b'\x78\x56\x34\x12' # serial LE = 0x12345678
        + b'\x03'             # name_len = 3
        + b'PLC'              # product_name
        + b'\x03'             # state = 0x03 (Operational); required by ODVA spec
    )  # 37 bytes
    cpf = (
        b'\x01\x00'           # item_count = 1
        + b'\x0c\x00'         # item type = Identity (0x000C)
        + struct.pack('<H', len(item))
        + item
    )  # 43 bytes
    hdr = (
        b'\x63\x00'           # command = List Identity
        + struct.pack('<H', len(cpf))
        + b'\x00\x00\x00\x00' # session_handle = 0
        + b'\x00\x00\x00\x00' # status = 0
        + b'\x00' * 8         # sender_context
        + b'\x00' * 4         # options
    )  # 24 bytes
    return hdr + cpf


def _build_reg_session_resp() -> bytes:
    return (
        b'\x65\x00'           # command = Register Session
        + b'\x04\x00'         # length = 4 (bytes after header)
        + b'\x01\x00\x00\x00' # session_handle = 1
        + b'\x00\x00\x00\x00' # status = 0
        + b'\x00' * 8         # sender_context
        + b'\x00' * 4         # options
        + b'\x01\x00\x00\x00' # protocol version=1, option flags=0
    )  # 28 bytes


def _build_rr_data_resp(session_handle: int) -> bytes:
    cip = b'\xd5\x00\x00\x00'  # service=0xD5, reserved=0, status=0, ext_size=0
    body = (
        b'\x00\x00\x00\x00'   # interface_handle
        + b'\x00\x00'          # timeout
        + b'\x02\x00'          # item_count = 2
        + b'\x00\x00\x00\x00'  # null address item (type=0, len=0)
        + b'\xb2\x00'          # unconnected data item type = 0x00B2
        + struct.pack('<H', len(cip))
        + cip
    )  # 20 bytes
    hdr = (
        b'\x6f\x00'            # command = SendRRData
        + struct.pack('<H', len(body))
        + struct.pack('<I', session_handle)
        + b'\x00\x00\x00\x00'  # status = 0
        + b'\x00' * 8          # sender_context
        + b'\x00' * 4          # options
    )  # 24 bytes
    return hdr + body


LIST_IDENTITY_RESP = _build_list_identity_resp()
REG_SESSION_RESP = _build_reg_session_resp()


def _udp_list_identity_worker(port: int) -> None:
    import socket as _socket
    resp = _build_list_identity_resp()
    with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1.0)
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 2 and data[0] == 0x63 and data[1] == 0x00:
                    sock.sendto(resp, addr)
            except _socket.timeout:
                continue


class EipHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        session_handle = 1
        try:
            while True:
                hdr = recv_exact(sock, 24)
                cmd = struct.unpack_from('<H', hdr, 0)[0]
                body_len = struct.unpack_from('<H', hdr, 2)[0]
                if body_len:
                    recv_exact(sock, body_len)
                if cmd == 0x0063:
                    sock.sendall(LIST_IDENTITY_RESP)
                elif cmd == 0x0065:
                    sock.sendall(REG_SESSION_RESP)
                elif cmd == 0x006F:
                    sock.sendall(_build_rr_data_resp(session_handle))
                else:
                    break
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rockwell EtherNet/IP simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_ROCKWELL_PORT", str(PORT))),
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=44818,
        help="UDP port for List Identity responses (default: 44818)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    threading.Thread(
        target=_udp_list_identity_worker, args=(args.udp_port,), daemon=True
    ).start()
    with socketserver.ThreadingTCPServer((args.host, args.port), EipHandler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
