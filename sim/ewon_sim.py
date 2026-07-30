"""eWON HTTP stub — port 80.

POST /wrcgi.bin/wsdReadForm -> 20-field CSV response (split on '","').

Field layout after split:
  [0] opening filler (starts with '"')
  [1] first_name  = "John"
  [2] last_name   = "Doe"
  [3] username    = "admin"  (non-empty -> user returned)
  [4] password    = "!invalid!"  (base64 decode fails -> "<decode failed>")
  [5] information = ""
  [6] access_rights = "15"
  [7..18] filler fields
  [19] closing filler (ends with '"')

Expected TUI output with 'Extract Credentials adm:5':
  username=admin  first_name=John  last_name=Doe
  password=<decode failed>  Access: 15
"""
import argparse
import http.server
import os
import threading

PORT = 80


def _build_ipconf_response() -> bytes:
    resp = bytearray(38)
    resp[0:4] = b"IPCO"            # identifier → data[0..4]
    resp[15] = 2                    # response_type = device_info
    resp[16] = 1                    # product_code
    # IP 127.0.0.1 stored in reversed-octet order (data[23].data[22].data[21].data[20])
    resp[20] = 1; resp[21] = 0; resp[22] = 0; resp[23] = 127
    # netmask 255.255.255.0 reversed
    resp[24] = 0; resp[25] = 0xFF; resp[26] = 0xFF; resp[27] = 0xFF
    # MAC
    resp[32] = 0xDE; resp[33] = 0xAD; resp[34] = 0xBE
    resp[35] = 0xEF; resp[36] = 0x00; resp[37] = 0x01
    return bytes(resp)


def _udp_ipconf_worker(port: int) -> None:
    import socket as _socket
    resp = _build_ipconf_response()
    with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1.0)
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 7 and data[:7] == b"IPCONF\x00":
                    sock.sendto(resp, addr)
            except _socket.timeout:
                continue


# Split on '","': 19 separators -> 20 parts
EWON_RESPONSE = (
    '"filler",'    # [0] starts with '"'
    '"John",'      # [1] first_name
    '"Doe",'       # [2] last_name
    '"admin",'     # [3] username
    '"!invalid!",' # [4] password (fails base64 -> <decode failed>)
    '"",'          # [5] information
    '"15",'        # [6] access_rights
    '"",'          # [7]
    '"",'          # [8]
    '"",'          # [9]
    '"",'          # [10]
    '"",'          # [11]
    '"",'          # [12]
    '"",'          # [13]
    '"",'          # [14]
    '"",'          # [15]
    '"",'          # [16]
    '"",'          # [17]
    '"",'          # [18]
    '"filler"'     # [19] ends with '"'
)


class EwonHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # silence access log
        pass

    def do_POST(self) -> None:
        if self.path == '/wrcgi.bin/wsdReadForm':
            body = EWON_RESPONSE.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        self.send_response(404)
        self.end_headers()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="eWON HTTP simulator")
    parser.add_argument(
        "legacy_port",
        nargs="?",
        type=int,
        help="legacy positional TCP port",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="TCP port to listen on (default: 80 or EWON_SIM_PORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SCADAVER_SIM_HOST", "0.0.0.0"),
        help="IP address to bind (default: 0.0.0.0 or SCADAVER_SIM_HOST)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=1507,
        help="UDP port for IPCONF discovery responses (default: 1507)",
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    port = args.port or args.legacy_port or int(os.environ.get("EWON_SIM_PORT", str(PORT)))
    if not 1 <= port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    threading.Thread(
        target=_udp_ipconf_worker, args=(args.udp_port,), daemon=True
    ).start()

    srv = http.server.HTTPServer((args.host, port), EwonHandler)
    print(f"eWON HTTP stub listening on {args.host}:{port}")
    print("  POST /wrcgi.bin/wsdReadForm -> 20-field CSV")
    print("  username=admin  access_rights=15  password=<decode failed>")
    srv.serve_forever()
