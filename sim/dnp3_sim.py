"""DNP3 (IEEE 1815) outstation simulator — TCP port 20000.

Responds to Data Link Layer frames:
  FC_RESET_LINK     (0x00) → FC_ACK (0x00)
  FC_REQUEST_LINK_STATUS (0x09) → FC_LINK_STATUS (0x0B)
"""
# Accuracy audit (2026-08): IEEE 1815-2012 (DNP3) test fixture.
# Reference: DNP Users Group standards information (https://www.dnp.org/).
# CRC covers len+ctrl+dst+src (bytes 2-7 of the 10-byte header after start bytes).
# Surface: DLL link-layer handshake plus Group 0 device-attribute reads.
import argparse
import os
import socketserver
import struct

PORT = 20000
START_HI = 0x05
START_LO = 0x64
OUTSTATION_ADDR = 10


def crc16_dnp(data: bytes) -> int:
    """CRC-16/DNP: poly=0xA6BC reflected, init=0x0000, finalXor=0xFFFF."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def build_dll_response(ctrl: int, dst: int, src: int) -> bytes:
    """Build a 10-byte DLL-only response frame (no payload).

    Frame layout (casket compatible):
      [0x05, 0x64, len, ctrl, dst_lo, dst_hi, src_lo, src_hi, crc_lo, crc_hi]
    CRC covers bytes 2-7 (len through src_hi).
    """
    length = 5  # DLL-only: ctrl(1)+dst(2)+src(2)
    header_for_crc = bytes([
        length, ctrl,
        dst & 0xFF, (dst >> 8) & 0xFF,
        src & 0xFF, (src >> 8) & 0xFF,
    ])
    crc = crc16_dnp(header_for_crc)
    return bytes([START_HI, START_LO]) + header_for_crc + struct.pack('<H', crc)


def build_data_response(dst: int, src: int, apdu: bytes) -> bytes:
    """Build an unfragmented solicited DNP3 response with block CRCs."""
    data = bytes([0xC0]) + apdu
    header_for_crc = bytes([
        5 + len(data), 0x03,
        dst & 0xFF, (dst >> 8) & 0xFF,
        src & 0xFF, (src >> 8) & 0xFF,
    ])
    frame = bytearray([START_HI, START_LO])
    frame.extend(header_for_crc)
    frame.extend(struct.pack('<H', crc16_dnp(header_for_crc)))
    for index in range(0, len(data), 16):
        block = data[index:index + 16]
        frame.extend(block)
        frame.extend(struct.pack('<H', crc16_dnp(block)))
    return bytes(frame)


def device_attributes_response() -> bytes:
    """Return a small Group 0 character-string attribute response."""
    attributes = (
        (250, b"SCADAver Labs"),
        (252, b"DNP3 Test Outstation"),
        (16, b"dnp3-sim-01"),
    )
    objects = bytearray()
    for variation, value in attributes:
        objects.extend((0x00, variation, 0x07, 0x01, len(value)))
        objects.extend(value)
    return bytes([0x81, 0x00, 0x00]) + bytes(objects)


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('closed')
        buf += chunk
    return buf


def recv_data_blocks(sock, data_octets: int) -> bytes:
    """Receive and validate DNP3 data blocks, returning the payload bytes."""
    data = bytearray()
    remaining = data_octets
    while remaining:
        block_len = min(16, remaining)
        block = recv_exact(sock, block_len)
        supplied_crc = struct.unpack('<H', recv_exact(sock, 2))[0]
        if crc16_dnp(block) != supplied_crc:
            raise ValueError("bad DNP3 data-block CRC")
        data.extend(block)
        remaining -= block_len
    return bytes(data)


class DNP3Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(5)
        try:
            while True:
                header = recv_exact(sock, 10)
                if header[0] != START_HI or header[1] != START_LO:
                    return
                frame_len = header[2]
                ctrl = header[3]
                dst = struct.unpack_from('<H', header, 4)[0]
                src = struct.unpack_from('<H', header, 6)[0]
                fc = ctrl & 0x0F

                # Broadcast traffic must not receive a DNP3 response.  This
                # fixture models the documented lab pairing: master 1 to
                # outstation 10.
                if dst != OUTSTATION_ADDR:
                    return

                payload = b""
                data_octets = max(0, frame_len - 5)
                if data_octets > 0:
                    payload = recv_data_blocks(sock, data_octets)

                if fc == 0x00:  # FC_RESET_LINK → ACK
                    sock.sendall(build_dll_response(0x00, src, OUTSTATION_ADDR))
                elif fc == 0x09:  # FC_REQUEST_LINK_STATUS → FC_LINK_STATUS
                    sock.sendall(build_dll_response(0x0B, src, OUTSTATION_ADDR))
                elif fc == 0x03 and len(payload) >= 6 and payload[1] == 0x01:
                    # Group 0 attribute read; the response reverses DLL addresses.
                    sock.sendall(build_data_response(src, OUTSTATION_ADDR, device_attributes_response()))
                else:
                    sock.sendall(build_dll_response(0x00, src, OUTSTATION_ADDR))
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DNP3 outstation simulator")
    parser.add_argument("--host", default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_DNP3_PORT", str(PORT))),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socketserver.ThreadingTCPServer((args.host, args.port), DNP3Handler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
