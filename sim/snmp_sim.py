"""Minimal SNMPv2c UDP simulator for smoke tests.

Responds to GET and GETNEXT for six sysGroup OIDs, pretending to be a
Siemens SCALANCE X200.  Only the "public" community is accepted.

Uses stdlib only — no third-party deps required.
"""
from __future__ import annotations

import argparse
import socketserver
import time

_START = time.monotonic()

COMMUNITY = "public"

# OIDs for the system group (1.3.6.1.2.1.1)
SYS_DESCR    = (1,3,6,1,2,1,1,1,0)
SYS_OBJ_ID   = (1,3,6,1,2,1,1,2,0)
SYS_UPTIME   = (1,3,6,1,2,1,1,3,0)
SYS_CONTACT  = (1,3,6,1,2,1,1,4,0)
SYS_NAME     = (1,3,6,1,2,1,1,5,0)
SYS_LOCATION = (1,3,6,1,2,1,1,6,0)

ENTERPRISE_OID = (1,3,6,1,4,1,4329,20,1,2,0,2)  # Siemens SCALANCE

MIB_ORDER = [SYS_DESCR, SYS_OBJ_ID, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION]

# ─── BER helpers ─────────────────────────────────────────────────────────────

def _ber_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _enc_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    out: list[int] = []
    while n > 0:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    if out[0] & 0x80:
        out.insert(0, 0)
    return _tlv(0x02, bytes(out))


def _enc_oid(arcs: tuple[int, ...]) -> bytes:
    if len(arcs) < 2:
        return _tlv(0x06, b"\x00")
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        if arc == 0:
            body.append(0)
        else:
            parts: list[int] = []
            while arc:
                parts.append(arc & 0x7F)
                arc >>= 7
            parts.reverse()
            for i, part in enumerate(parts):
                body.append(part | (0x80 if i < len(parts) - 1 else 0))
    return _tlv(0x06, bytes(body))


def _octet(s: bytes) -> bytes:
    return _tlv(0x04, s)


def _timeticks(n: int) -> bytes:
    n = n & 0xFFFFFFFF
    b = n.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
    return bytes([0x43]) + _ber_len(len(b)) + b


def _no_such_object() -> bytes:
    return _tlv(0x80, b"")


def _end_of_mib() -> bytes:
    return _tlv(0x82, b"")


# ─── BER parser ──────────────────────────────────────────────────────────────

def _parse_len(data: bytes, pos: int) -> tuple[int, int]:
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n = b & 0x7F
    return int.from_bytes(data[pos + 1 : pos + 1 + n], "big"), pos + 1 + n


def _parse_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = data[pos]
    length, start = _parse_len(data, pos + 1)
    end = start + length
    return tag, data[start:end], end


def _decode_oid(data: bytes) -> tuple[int, ...]:
    if not data:
        return ()
    first = data[0]
    arcs = [first // 40, first % 40]
    i = 1
    while i < len(data):
        arc = 0
        while i < len(data):
            b = data[i]
            i += 1
            arc = (arc << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        arcs.append(arc)
    return tuple(arcs)


def _parse_message(
    data: bytes,
) -> tuple[str, int, int, list[tuple[int, ...]]]:
    """Return (community, pdu_tag, req_id, oid_list)."""
    _, msg, _ = _parse_tlv(data, 0)
    pos = 0
    _, _, pos = _parse_tlv(msg, pos)            # version
    _, comm_bytes, pos = _parse_tlv(msg, pos)   # community
    community = comm_bytes.decode("ascii", errors="replace")
    pdu_tag, pdu_body, _ = _parse_tlv(msg, pos)
    pos2 = 0
    _, rid_bytes, pos2 = _parse_tlv(pdu_body, pos2)
    req_id = int.from_bytes(rid_bytes, "big") if rid_bytes else 0
    _, _, pos2 = _parse_tlv(pdu_body, pos2)     # error-status
    _, _, pos2 = _parse_tlv(pdu_body, pos2)     # error-index
    _, vbl_body, _ = _parse_tlv(pdu_body, pos2) # VarBindList
    oids: list[tuple[int, ...]] = []
    vpos = 0
    while vpos < len(vbl_body):
        _, vb_body, vpos = _parse_tlv(vbl_body, vpos)
        _, oid_bytes, _ = _parse_tlv(vb_body, 0)
        oids.append(_decode_oid(oid_bytes))
    return community, pdu_tag, req_id, oids


# ─── MIB lookup ──────────────────────────────────────────────────────────────

def _value_for(oid: tuple[int, ...]) -> bytes | None:
    if oid == SYS_DESCR:
        return _octet(b"SCALANCE X200 simulated")
    if oid == SYS_OBJ_ID:
        return _enc_oid(ENTERPRISE_OID)
    if oid == SYS_UPTIME:
        return _timeticks(int((time.monotonic() - _START) * 100))
    if oid == SYS_CONTACT:
        return _octet(b"")
    if oid == SYS_NAME:
        return _octet(b"snmp-sim-01")
    if oid == SYS_LOCATION:
        return _octet(b"Lab")
    return None


def _next_oid(oid: tuple[int, ...]) -> tuple[int, ...] | None:
    for key in MIB_ORDER:
        if key > oid:
            return key
    return None


# ─── Response builder ────────────────────────────────────────────────────────

def _build_response(
    community: str,
    req_id: int,
    varbinds: list[tuple[tuple[int, ...], bytes]],
) -> bytes:
    vbl_body = b""
    for oid, val_tlv in varbinds:
        vb = _enc_oid(oid) + val_tlv
        vbl_body += _tlv(0x30, vb)
    pdu_body = _enc_int(req_id) + _enc_int(0) + _enc_int(0) + _tlv(0x30, vbl_body)
    pdu = _tlv(0xA2, pdu_body)
    msg = _enc_int(1) + _octet(community.encode()) + pdu
    return _tlv(0x30, msg)


# ─── Request handler ─────────────────────────────────────────────────────────

class SnmpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            community, pdu_tag, req_id, oids = _parse_message(data)
        except Exception:
            return  # malformed — drop silently

        if community != COMMUNITY:
            return  # wrong community — drop silently

        varbinds: list[tuple[tuple[int, ...], bytes]] = []

        if pdu_tag == 0xA0:  # GetRequest
            for oid in oids:
                val = _value_for(oid)
                varbinds.append((oid, val if val is not None else _no_such_object()))

        elif pdu_tag == 0xA1:  # GetNextRequest
            for oid in oids:
                nxt = _next_oid(oid)
                if nxt is None:
                    varbinds.append((oid, _end_of_mib()))
                else:
                    val = _value_for(nxt)
                    varbinds.append((nxt, val if val is not None else _no_such_object()))

        else:
            return  # unsupported PDU type — drop

        sock.sendto(_build_response(community, req_id, varbinds), self.client_address)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal SNMPv2c simulator")
    parser.add_argument("--host", default="127.0.0.1", help="bind host")
    parser.add_argument("--port", type=int, default=1161, help="UDP port (default 1161)")
    args = parser.parse_args()

    with socketserver.UDPServer((args.host, args.port), SnmpHandler) as srv:
        print(f"[snmp_sim] listening on UDP {args.host}:{args.port}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
