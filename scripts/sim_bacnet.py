"""Bounded BACnet/IP fixture for SCADAver's local simulator suite.

It implements only the standard, read-only exchanges exercised by the CLI:
unicast Who-Is/I-Am discovery and device-object ReadProperty acknowledgements.
This is a protocol fixture, not a B-BC or vendor controller emulator.
"""
# Accuracy audit (2026-08): BACnet/IP protocol fixture, not a vendor-device
# emulator. Sources: ASHRAE BACnet developer aids
# (https://bacnet.org/developer-aids/) and the official standard catalogue
# (https://bacnet.org/buy/). Surface: unicast Who-Is/I-Am and device-object
# ReadProperty of name, vendor name, description, and firmware revision.

from __future__ import annotations

import argparse
import os
import socketserver
import struct


DEVICE_INSTANCE = 1000
DEVICE_OBJECT = (8 << 22) | DEVICE_INSTANCE
VENDOR_ID = 999

# BACnet Device-object property identifiers used by the CLI's Casket client.
PROPERTIES = {
    77: "ScadaverCI",                 # object-name
    121: "SCADAver Labs",             # vendor-name
    28: "Loopback BACnet/IP fixture", # description
    44: "1.0",                        # firmware-revision
}


def bvlc(payload: bytes) -> bytes:
    return b"\x81\x0a" + struct.pack(">H", 4 + len(payload)) + payload


def i_am() -> bytes:
    """Return an ANSI/ASHRAE 135 I-Am for device instance 1000."""
    apdu = (
        b"\x10\x00"  # unconfirmed request, I-Am service
        + b"\xc4" + struct.pack(">I", DEVICE_OBJECT)
        + b"\x22\x05\xc4"  # max APDU 1476
        + b"\x91\x03"        # no segmentation
        + b"\x22" + struct.pack(">H", VENDOR_ID)
    )
    return bvlc(b"\x01\x00" + apdu)


def character_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    # Application tag 7: CharacterString. Its length includes the encoding
    # octet; use extended length only for the deliberately short fixture data.
    length = len(encoded) + 1
    if length <= 4:
        return bytes([(7 << 4) | length, 0]) + encoded
    return bytes([(7 << 4) | 5, length, 0]) + encoded


def read_property_ack(invoke_id: int, property_id: int) -> bytes:
    """Return a standard ComplexACK carrying an application string value."""
    value = PROPERTIES.get(property_id, "")
    # ReadPropertyACK: object identifier, property identifier, opening tag
    # [3], application value, closing tag [3].
    result = (
        b"\x0c" + struct.pack(">I", DEVICE_OBJECT)
        + bytes([0x19, property_id])
        + b"\x3e" + character_string(value) + b"\x3f"
    )
    return bvlc(b"\x01\x00" + bytes([0x30, invoke_id, 0x0c]) + result)


class BacnetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if os.environ.get("SCADAVER_SIM_DEBUG") == "1":
            print(f"BACnet UDP request {data.hex()}", flush=True)
        # BVLC Original-Unicast-NPDU, then NPDU v1/no-routing.
        if len(data) < 8 or data[:2] != b"\x81\x0a" or data[4] != 0x01:
            return
        apdu = data[6:]
        if apdu[:2] == b"\x10\x08":  # unconfirmed Who-Is
            sock.sendto(i_am(), self.client_address)
            return
        # Confirmed ReadProperty request: invoke-id then service 0x0c; the
        # request encodes property-id as context tag 1 (0x19) + one byte.
        if len(apdu) >= 11 and apdu[0] == 0x00 and apdu[3] == 0x0c:
            try:
                property_tag = apdu.index(0x19, 4)
                property_id = apdu[property_tag + 1]
            except (ValueError, IndexError):
                return
            sock.sendto(read_property_ack(apdu[2], property_id), self.client_address)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SCADAver BACnet/IP fixture")
    parser.add_argument("--host", default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_BACNET_PORT", "47808")),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socketserver.ThreadingUDPServer((args.host, args.port), BacnetHandler) as server:
        server.daemon_threads = True
        server.serve_forever()


if __name__ == "__main__":
    main()
