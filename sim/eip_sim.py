"""Rockwell EtherNet/IP + ControlLogix simulator — TCP port 44818.

Handles List Identity (0x0063), Register Session (0x0065) and SendRRData (0x006F),
dispatching the encapsulated CIP request to a small in-memory controller model:

  class 0x6B (Symbol Object)    service 0x55  Get_Instance_Attribute_List
  class 0x6C (Template Object)  service 0x03  Get_Attribute_List
  class 0x6C (Template Object)  service 0x4C  Template Read
  class 0x01 (Identity Object)  service 0x01  Get_Attribute_All
  ANSI symbolic path            service 0x4C  Read Tag
  ANSI symbolic path            service 0x52  Read Tag Fragmented

The byte layouts here are written from the protocol definitions rather than by mirroring
the Rust parser, so a passing run is independent evidence that the parser is correct.
Symbol enumeration and Template Read both chunk their replies and report CIP status 0x06
(Partial Transfer) so the client's multi-packet paths are always exercised.
"""
import argparse
import os
import socketserver
import struct
import threading

PORT = 44818

# ── CIP type codes ───────────────────────────────────────────────────────────
BOOL, SINT, DINT, REAL = 0x00C1, 0x00C2, 0x00C4, 0x00CA
ARRAY_1D = 0x2000  # bits 14-13 = dimension count
STRUCT = 0x8000  # bit 15
SYSTEM = 0x1000  # bit 12

# Force the client through its partial-transfer loops.
SYMBOLS_PER_REPLY = 4
TEMPLATE_CHUNK = 40

# Byte width of each atomic CIP type, used to stride array elements.
ATOMIC_WIDTHS = {
    0xC1: 1, 0xC2: 1, 0xC6: 1,
    0xC3: 2, 0xC7: 2, 0xCD: 2,
    0xC4: 4, 0xC8: 4, 0xCA: 4, 0xDB: 4,
    0xC5: 8, 0xC9: 8, 0xCB: 8,
}


def _real(v):
    return struct.pack("<f", v)


def _dint(v):
    return struct.pack("<i", v)


# ── UDT definitions ──────────────────────────────────────────────────────────
# Each member is (name, type_info, type_word, offset). `type_info` is an array
# element count for array members and a bit position for packed BOOLs.
TEMPLATES = {
    0x08B: {
        "name": "LIT_Type",
        "handle": 0x1234,
        "size": 44,
        "members": [
            ("PV", 0, REAL, 0),
            ("SP", 0, REAL, 4),
            ("OUT", 0, REAL, 8),
            ("Alarm", 2, BOOL, 12),  # bit 2 of the byte at offset 12
            ("Mode", 0, DINT, 16),
            # REAL[4]: exercises per-element expansion and indexed writes.
            ("Trend", 4, ARRAY_1D | REAL, 20),
            # BOOL[40]: packed into 32-bit words, so element 33 is bit 1 of word 1.
            ("Flags", 40, ARRAY_1D | BOOL, 36),
        ],
    },
    0x09C: {
        "name": "Pump_Type",
        "handle": 0x5678,
        "size": 52,
        "members": [
            ("Run", 0, BOOL, 0),  # bit 0
            ("Hours", 0, DINT, 4),
            ("Cmd", 0, STRUCT | 0x08B, 8),  # nested LIT_Type (44 bytes)
        ],
    },
    0xFCE: {
        "name": "STRING",
        "handle": 0x0FCE,
        "size": 86,
        "members": [
            ("LEN", 0, DINT, 0),
            ("DATA", 82, ARRAY_1D | SINT, 4),
        ],
    },
}


def _lit_bytes(pv, sp, out, alarm_bit2, mode, trend=(0.0, 0.0, 0.0, 0.0), flag_bits=()):
    """40-byte LIT_Type instance.

    `flag_bits` is a set of BOOL[40] indices to set; Logix packs those into 32-bit words,
    so index i lives in bit i%32 of word i/32.
    """
    flags = bytearray(8)  # BOOL[40] spans two 32-bit words
    for i in flag_bits:
        flags[(i // 32) * 4 + (i % 32) // 8] |= 1 << (i % 8)
    return (
        _real(pv)
        + _real(sp)
        + _real(out)
        + bytes([0x04 if alarm_bit2 else 0x00])
        + b"\x00" * 3
        + _dint(mode)
        + b"".join(_real(v) for v in trend)  # Trend[4] @20
        + bytes(flags)                       # Flags[40] @36
    )


def _string_bytes(text, capacity=82):
    raw = text.encode("ascii")[:capacity]
    return _dint(len(raw)) + raw + b"\x00" * (capacity - len(raw))


# ── Symbol table ─────────────────────────────────────────────────────────────
# (instance_id, name, symbol_type, value_bytes)
# value_bytes is the payload after the type prefix; structs get an A0 02 header.
SYMBOLS = [
    (1, "PUMP_RUN", BOOL, bytes([1])),
    (2, "FLOW_RATE", REAL, _real(12.5)),
    (3, "TOTAL_COUNT", DINT, _dint(4242)),
    (
        4,
        "LE_LIT_4002",
        STRUCT | 0x08B,
        _lit_bytes(6.40, 5.00, 3.25, True, 3,
                   trend=(1.0, 2.0, 3.0, 4.0), flag_bits=(0, 2, 33)),
    ),
    (
        5,
        "PUMP_01",
        STRUCT | 0x09C,
        bytes([1]) + b"\x00" * 3 + _dint(1234)
        + _lit_bytes(1.5, 2.5, 3.5, False, 7, trend=(9.0, 8.0, 7.0, 6.0)),
    ),
    (6, "STATION_NAME", STRUCT | 0xFCE, _string_bytes("PUMP_STN")),
    # I/O module tag: must survive the client's name filter.
    (7, "Local:1:C", DINT, _dint(7)),
    # Odd-length name (11 chars) with no padding before the type word.
    (8, "ODD_LEN_TAG", DINT, _dint(99)),
    # 1-dimensional REAL array: dimension count lives in bits 14-13.
    (9, "LEVEL_ARRAY", ARRAY_1D | REAL, b"".join(_real(v) for v in (1.0, 2.0, 3.0))),
    # The following three must all be filtered out by the client.
    (10, "Program:MainProgram", DINT, _dint(0)),
    (11, "__internal_thing", DINT, _dint(0)),
    (12, "SYS_TIMER", SYSTEM | DINT, _dint(0)),
]

SYMBOL_BY_NAME = {name: (stype, value) for _, name, stype, value in SYMBOLS}


def build_template_definition(template_id):
    """Serialise a Template Object definition body.

    Layout: `member_count` 8-byte descriptors, then NUL-terminated strings. The first
    string is the template's own name and carries a ';' separator; member names follow.
    Each descriptor is type_info(UINT) | type word(UINT) | offset(UDINT).
    """
    tpl = TEMPLATES[template_id]
    body = b""
    for _, type_info, type_word, offset in tpl["members"]:
        body += struct.pack("<HHI", type_info, type_word, offset)
    body += f"{tpl['name']};n0_SIM\x00".encode("ascii")
    for name, _, _, _ in tpl["members"]:
        body += name.encode("ascii") + b"\x00"
    return body


def template_definition_words(template_id):
    """Attribute 4: definition size in 32-bit words, such that words*4 - 23 covers the body."""
    return (len(build_template_definition(template_id)) + 23 + 3) // 4


# ── CIP reply helpers ────────────────────────────────────────────────────────
def cip_reply(service, status, data=b""):
    """service|0x80, reserved, general status, ext-status word count, then data."""
    return bytes([service | 0x80, 0x00, status, 0x00]) + data


def cip_error(service, status):
    return cip_reply(service, status)


# ── CIP service handlers ─────────────────────────────────────────────────────
def handle_symbol_list(start_instance):
    """Service 0x55 on class 0x6B: instance_id(UDINT) name_len(UINT) name symbol_type(UINT).

    No padding follows the name — the type word comes immediately after the bytes.
    """
    pending = [s for s in SYMBOLS if s[0] >= start_instance]
    chunk = pending[:SYMBOLS_PER_REPLY]
    more = len(pending) > len(chunk)

    data = b""
    for instance_id, name, symbol_type, _ in chunk:
        raw = name.encode("ascii")
        data += struct.pack("<IH", instance_id, len(raw)) + raw
        data += struct.pack("<H", symbol_type)
    return cip_reply(0x55, 0x06 if more else 0x00, data)


def handle_template_attributes(template_id, request_data):
    """Service 0x03 on class 0x6C. Replies with each requested attribute at its own width.

    Attr 4 = object definition size (UDINT), 5 = structure size (UDINT),
    attr 2 = member count (UINT), attr 1 = structure handle (UINT).
    """
    if template_id not in TEMPLATES:
        return cip_error(0x03, 0x05)  # path destination unknown
    if len(request_data) < 2:
        return cip_error(0x03, 0x13)  # not enough data

    count = struct.unpack_from("<H", request_data, 0)[0]
    wanted = [
        struct.unpack_from("<H", request_data, 2 + i * 2)[0]
        for i in range(count)
        if 2 + i * 2 + 2 <= len(request_data)
    ]

    tpl = TEMPLATES[template_id]
    values = {
        4: ("<I", template_definition_words(template_id)),
        5: ("<I", tpl["size"]),
        2: ("<H", len(tpl["members"])),
        1: ("<H", tpl["handle"]),
    }

    data = struct.pack("<H", len(wanted))
    for attr in wanted:
        if attr in values:
            fmt, val = values[attr]
            data += struct.pack("<HH", attr, 0x00) + struct.pack(fmt, val)
        else:
            data += struct.pack("<HH", attr, 0x14)  # attribute not supported, no value
    return cip_reply(0x03, 0x00, data)


def handle_template_read(template_id, request_data):
    """Service 0x4C on class 0x6C. Request data is offset(UDINT) then byte count(UINT).

    Rejects the reversed field order rather than silently returning nothing, so a client
    that sends count-first gets a diagnosable error instead of an empty body.
    """
    if template_id not in TEMPLATES:
        return cip_error(0x4C, 0x05)
    if len(request_data) < 6:
        return cip_error(0x4C, 0x13)

    offset, count = struct.unpack_from("<IH", request_data, 0)
    body = build_template_definition(template_id)

    if offset > len(body):
        return cip_error(0x4C, 0x03)  # invalid parameter value
    if count == 0:
        return cip_error(0x4C, 0x03)

    end = min(offset + min(count, TEMPLATE_CHUNK), len(body))
    chunk = body[offset:end]
    more = end < len(body)
    return cip_reply(0x4C, 0x06 if more else 0x00, chunk)


def tag_payload(dotted):
    """Read Tag reply payload: structs get `A0 02 <handle>`, atomics a plain type word.

    Accepts a dotted member path, in which case only that member's bytes are returned
    with the member's own type word.
    """
    resolved = resolve_member(dotted)
    if resolved is None:
        return None
    tag, offset, member = resolved
    stype, value = SYMBOL_BY_NAME[tag]

    if member is None:
        if stype & STRUCT:
            handle = TEMPLATES.get(stype & 0x0FFF, {}).get("handle", 0)
            return struct.pack("<HH", 0x02A0, handle) + value
        return struct.pack("<H", stype & 0x0FFF) + value

    _, type_info, member_type, _ = member
    if member_type & STRUCT:
        handle = TEMPLATES.get(member_type & 0x0FFF, {}).get("handle", 0)
        size = TEMPLATES.get(member_type & 0x0FFF, {}).get("size", 0)
        return struct.pack("<HH", 0x02A0, handle) + value[offset:offset + size]

    code = member_type & 0xFF
    if code <= 0x1F or code == 0xC1:
        # Packed BOOL: report just this member's bit.
        bit = (value[offset] >> (type_info & 0x07)) & 1 if offset < len(value) else 0
        return struct.pack("<H", code if code <= 0x1F else 0xC1) + bytes([bit])
    width = ATOMIC_WIDTHS.get(code, 4)
    return struct.pack("<H", code) + value[offset:offset + width]


def handle_read_tag(name, fragmented, request_data):
    payload = tag_payload(name)
    if payload is None:
        return cip_error(0x52 if fragmented else 0x4C, 0x04)  # path segment error
    if not fragmented:
        return cip_reply(0x4C, 0x00, payload)

    # Fragmented: element count (UINT) then byte offset (UDINT) — the reverse of
    # the Template Read layout.
    offset = 0
    if len(request_data) >= 6:
        offset = struct.unpack_from("<I", request_data, 2)[0]
    prefix = payload[:4] if payload[:2] == b"\xa0\x02" else payload[:2]
    body = payload[len(prefix):]
    if offset > len(body):
        return cip_error(0x52, 0x03)
    end = min(offset + 64, len(body))
    more = end < len(body)
    return cip_reply(0x52, 0x06 if more else 0x00, prefix + body[offset:end])


def handle_identity_get_all():
    name = b"PLC"
    data = (
        struct.pack("<HHH", 1, 0x000E, 1)  # vendor, device type, product code
        + bytes([31, 3])  # revision
        + struct.pack("<H", 0)  # status
        + struct.pack("<I", 0x12345678)  # serial
        + bytes([len(name)])
        + name
    )
    return cip_reply(0x01, 0x00, data)


def parse_symbolic_path(path):
    """Decode a chain of ANSI symbolic segments into a dotted name.

    Logix addresses a UDT member as one 0x91 segment per component, so
    `Pump.Cmd.SP` arrives as three segments. Array subscripts (0x28/0x29/0x2A)
    are appended as `[n]`. Returns None if this is not a symbolic path.
    """
    if len(path) < 2 or path[0] != 0x91:
        return None
    parts = []
    pos = 0
    while pos < len(path):
        seg = path[pos]
        if seg == 0x91:
            if pos + 2 > len(path):
                return None
            name_len = path[pos + 1]
            name = path[pos + 2:pos + 2 + name_len].decode("ascii", errors="replace")
            pos += 2 + name_len + (name_len % 2)  # segments pad to even length
            parts.append(name)
        elif seg == 0x28:
            if not parts or pos + 2 > len(path):
                return None
            parts[-1] += f"[{path[pos + 1]}]"
            pos += 2
        elif seg == 0x29:
            if not parts or pos + 4 > len(path):
                return None
            parts[-1] += f"[{struct.unpack_from('<H', path, pos + 2)[0]}]"
            pos += 4
        elif seg == 0x2A:
            if not parts or pos + 6 > len(path):
                return None
            parts[-1] += f"[{struct.unpack_from('<I', path, pos + 2)[0]}]"
            pos += 6
        else:
            return None
    return ".".join(parts) if parts else None


def resolve_member(dotted):
    """Walk a dotted path to the owning struct value and the leaf template member.

    Returns (tag_name, byte_offset, member_tuple) or None. Only scalar leaves resolve;
    this is what lets the simulator verify a member write landed at the right offset.
    """
    parts = dotted.split(".")
    tag = parts[0]
    if tag not in SYMBOL_BY_NAME:
        return None
    stype, _ = SYMBOL_BY_NAME[tag]
    if len(parts) == 1:
        return (tag, 0, None)
    if not stype & STRUCT:
        return None

    tid = stype & 0x0FFF
    offset = 0
    member = None
    for part in parts[1:]:
        if tid is None or tid not in TEMPLATES:
            return None
        # "Trend[2]" -> member "Trend", element 2
        name, _, idx = part.partition("[")
        index = int(idx.rstrip("]")) if idx else None

        found = None
        for m in TEMPLATES[tid]["members"]:
            if m[0] == name:
                found = m
                break
        if found is None:
            return None

        m_name, m_info, m_type, m_off = found
        offset += m_off
        is_array = ((m_type >> 13) & 0x03) > 0

        if index is not None:
            if not is_array:
                return None
            if m_type & STRUCT:
                stride = TEMPLATES.get(m_type & 0x0FFF, {}).get("size")
                if stride is None:
                    return None
                offset += index * stride
            elif (m_type & 0xFF) == (BOOL & 0xFF) or (m_type & 0xFF) <= 0x1F:
                # Packed BOOL array: advance to the containing word, keep the bit in type_info.
                offset += (index // 32) * 4 + (index % 32) // 8
                found = (m_name, index % 8, m_type & 0x1FFF, m_off)
            else:
                width = ATOMIC_WIDTHS.get(m_type & 0xFF)
                if width is None:
                    return None
                offset += index * width
                found = (m_name, 0, m_type & 0x1FFF, m_off)
        elif is_array:
            return None  # a whole-array read/write is not supported

        member = found
        tid = (found[2] & 0x0FFF) if (found[2] & STRUCT) else None
    return (tag, offset, member)


def handle_write_tag(dotted, request_data):
    """Service 0x4D: apply a scalar write to the in-memory symbol table."""
    resolved = resolve_member(dotted)
    if resolved is None:
        return cip_error(0x4D, 0x04)  # path segment error
    if len(request_data) < 4:
        return cip_error(0x4D, 0x13)

    tag, offset, member = resolved
    type_code, count = struct.unpack_from("<HH", request_data, 0)
    payload = request_data[4:]
    if count != 1 or not payload:
        return cip_error(0x4D, 0x03)

    stype, value = SYMBOL_BY_NAME[tag]

    if member is None:
        # Whole-tag scalar write.
        if type_code != (stype & 0x0FFF):
            return cip_error(0x4D, 0x07)  # type mismatch
        SYMBOL_BY_NAME[tag] = (stype, bytes(payload))
        return cip_reply(0x4D, 0x00)

    name, type_info, member_type, _ = member
    if type_code != (member_type & 0x0FFF):
        return cip_error(0x4D, 0x07)

    buf = bytearray(value)
    if member_type & 0x00FF == BOOL & 0x00FF or (member_type & 0xFF) <= 0x1F:
        # Packed BOOL: set or clear just this member's bit.
        if offset >= len(buf):
            return cip_error(0x4D, 0x03)
        mask = 1 << (type_info & 0x07)
        if payload[0]:
            buf[offset] |= mask
        else:
            buf[offset] &= 0xFF ^ mask
    else:
        if offset + len(payload) > len(buf):
            return cip_error(0x4D, 0x03)
        buf[offset:offset + len(payload)] = payload

    SYMBOL_BY_NAME[tag] = (stype, bytes(buf))
    return cip_reply(0x4D, 0x00)


def dispatch_cip(cip):
    """Route a CIP request by service code and path type."""
    if len(cip) < 2:
        return cip_error(0x00, 0x13)

    service = cip[0]
    path_words = cip[1]
    path = cip[2:2 + path_words * 2]
    request_data = cip[2 + path_words * 2:]

    # ANSI Extended Symbolic path (0x91): a named tag or UDT member.
    dotted = parse_symbolic_path(path)
    if dotted is not None:
        if service in (0x4C, 0x52):
            return handle_read_tag(dotted, service == 0x52, request_data)
        if service == 0x4D:
            return handle_write_tag(dotted, request_data)
        return cip_error(service, 0x08)

    # Logical segment: 0x20 <class> 0x25 0x00 <instance:2>, or 0x24 <instance:1>.
    if len(path) >= 2 and path[0] == 0x20:
        class_id = path[1]
        instance = 0
        if len(path) >= 6 and path[2] == 0x25:
            instance = struct.unpack_from("<H", path, 4)[0]
        elif len(path) >= 4 and path[2] == 0x24:
            instance = path[3]

        if class_id == 0x6B and service == 0x55:
            return handle_symbol_list(instance)
        if class_id == 0x6C and service == 0x03:
            return handle_template_attributes(instance, request_data)
        if class_id == 0x6C and service == 0x4C:
            return handle_template_read(instance, request_data)
        if class_id == 0x01 and service == 0x01:
            return handle_identity_get_all()
        return cip_error(service, 0x08)  # service not supported

    return cip_error(service, 0x04)  # path segment error


# ── EtherNet/IP encapsulation ────────────────────────────────────────────────
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


def _build_rr_data_resp(session_handle: int, cip: bytes, sender_context: bytes) -> bytes:
    """Wrap a CIP reply in SendRRData. CIP starts at byte 40 of the returned buffer."""
    body = (
        b'\x00\x00\x00\x00'   # interface_handle
        + b'\x00\x00'          # timeout
        + b'\x02\x00'          # item_count = 2
        + b'\x00\x00\x00\x00'  # null address item (type=0, len=0)
        + b'\xb2\x00'          # unconnected data item type = 0x00B2
        + struct.pack('<H', len(cip))
        + cip
    )  # 16 bytes + cip
    hdr = (
        b'\x6f\x00'            # command = SendRRData
        + struct.pack('<H', len(body))
        + struct.pack('<I', session_handle)
        + b'\x00\x00\x00\x00'  # status = 0
        + sender_context[:8].ljust(8, b'\x00')
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


def extract_cip(body: bytes) -> bytes:
    """Pull the CIP request out of a SendRRData body (after the 24-byte EIP header)."""
    if len(body) < 16:
        return b""
    item_count = struct.unpack_from("<H", body, 6)[0]
    pos = 8
    cip = b""
    for _ in range(item_count):
        if pos + 4 > len(body):
            break
        item_type, item_len = struct.unpack_from("<HH", body, pos)
        pos += 4
        if item_type == 0x00B2:  # unconnected data
            cip = body[pos:pos + item_len]
        pos += item_len
    return cip


class EipHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(30)
        session_handle = 1
        try:
            while True:
                hdr = recv_exact(sock, 24)
                cmd = struct.unpack_from('<H', hdr, 0)[0]
                body_len = struct.unpack_from('<H', hdr, 2)[0]
                body = recv_exact(sock, body_len) if body_len else b""
                sender_context = hdr[12:20]

                if cmd == 0x0063:
                    sock.sendall(LIST_IDENTITY_RESP)
                elif cmd == 0x0065:
                    sock.sendall(REG_SESSION_RESP)
                elif cmd == 0x006F:
                    cip = extract_cip(body)
                    reply = dispatch_cip(cip) if cip else cip_error(0x00, 0x13)
                    sock.sendall(_build_rr_data_resp(session_handle, reply, sender_context))
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
