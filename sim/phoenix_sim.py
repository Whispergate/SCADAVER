"""Phoenix Contact ProConOS binary TCP stub — port 1962.

Three mandatory exchanges matching the get_device_info() probe sequence, then drain.

Exchange 1 (probe):   read 26 bytes → send 18-byte response (byte[17]=0x00 → code="00")
Exchange 2 (session): read 22 bytes → send 1 byte (0x00)
Exchange 3 (info):    read 14 bytes → send 100-byte response with PLC identity:
                         ret[30:50] = "ILC 150 ETH" (PLC type)
                         ret[66:70] = "3.20"         (firmware)
                         ret[79:87] = "20230101"     (build)
Drain:                read remaining bytes from optional follow-up packets.
"""
import argparse
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 1962

_SPLIT_MARKER = b"userLevel\x05\x06\x03\x00\x01"
_CLEAR_MARKER = bytes([0x00, 0x03, 0x00, 0x03, 0x01, 0x03, 0x01, 0x06, 0x83, 0x00])


def _build_teq() -> bytes:
    pw = b"admin"
    return b"hdr\x00" + _SPLIT_MARKER + _CLEAR_MARKER + bytes([len(pw)]) + pw + b"\x00" * 5


_TCR = b"#!-- N = 2\nPUMP_RUN;0;1;\nPUMP_SPEED;0;2;\n"

_ROOT_HTML = (
    b"<html><body>\n"
    b'<input type="hidden" name="MainTEQName" VALUE="app.teq">\n'
    b'<input type="hidden" name="ProjectName" VALUE="app">\n'
    b"</body></html>"
)

_RR_XML = (
    b"<body>"
    b"<i><n>PUMP_RUN</n><v>1</v></i>"
    b"<i><n>PUMP_SPEED</n><v>1500</v></i>"
    b"</body>"
)


class WebVisitHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", ""):
            self._send(200, "text/html", _ROOT_HTML)
        elif path == "/app.tcr":
            self._send(200, "text/plain", _TCR)
        elif path == "/app.teq":
            self._send(200, "application/octet-stream", _build_teq())
        elif path == "/cgi-bin/writeVal.exe":
            self._send(200, "text/plain", b"")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/cgi-bin/ILRReadValues.exe":
            self._send(200, "text/xml", _RR_XML)
        else:
            self.send_response(404)
            self.end_headers()

    def _send(self, code: int, ct: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # type: ignore[override]
        pass


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def _build_info_resp() -> bytes:
    resp = bytearray(100)
    resp[30:41] = b'ILC 150 ETH'
    resp[66:70] = b'3.20'
    resp[79:87] = b'20230101'
    return bytes(resp)


_INFO_RESP = _build_info_resp()


class PhoenixHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        try:
            recv_exact(sock, 26)          # Exchange 1: probe
            sock.sendall(b'\x00' * 18)    # byte[17]=0x00 → code hex = "00"

            recv_exact(sock, 22)          # Exchange 2: session init
            sock.sendall(b'\x00')

            recv_exact(sock, 14)          # Exchange 3: info request
            sock.sendall(_INFO_RESP)

            # Drain follow-up packets (5 additional send_recv calls in the client).
            # Reply with one byte each so the client doesn't time out.
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                sock.sendall(b'\x00')
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phoenix Contact ProConOS simulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SCADAVER_PHOENIX_PORT", str(PORT))),
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=0,
        help="TCP port for WebVisit HTTP server (0 = disabled)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.http_port > 0:
        http_srv = HTTPServer((args.host, args.http_port), WebVisitHandler)
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    with socketserver.ThreadingTCPServer((args.host, args.port), PhoenixHandler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
