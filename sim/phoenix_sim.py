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
# Accuracy audit (2026-08): fixture-only ProConOS/WebVisit compatibility stub,
# not a Phoenix Contact controller emulator. Phoenix's public advisory
# (https://assets.phoenixcontact.com/file/0b82d360-83fb-4cd5-965a-1b7cb89712fd/media/original?Security_Advisory_OEM_CVE-2014-9195.pdf=)
# and Redpoint research (https://github.com/digitalbond/Redpoint) informed its
# Surface: only SCADAver's info and local tag test paths. No public vendor wire
# specification was available to verify full conformance.
import argparse
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

PORT = 1962

_TCR = b"#!-- N = 2\nPUMP_RUN;0;1;\nPUMP_SPEED;0;2;\n"

_ROOT_HTML = (
    b"<html><body>\n"
    b'<input type="hidden" name="ProjectName" VALUE="app">\n'
    b"</body></html>"
)

_webvisit_values = {"PUMP_RUN": "1", "PUMP_SPEED": "1500"}
_webvisit_lock = threading.Lock()


def _read_values_xml() -> bytes:
    with _webvisit_lock:
        rows = b"".join(
            f"<i><n>{name}</n><v>{value}</v></i>".encode()
            for name, value in _webvisit_values.items()
        )
    return b"<body>" + rows + b"</body>"


class WebVisitHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", ""):
            self._send(200, "text/html", _ROOT_HTML)
        elif path == "/app.tcr":
            self._send(200, "text/plain", _TCR)
        elif path == "/cgi-bin/writeVal.exe":
            raw_query = self.path.split("?", 1)[1] if "?" in self.path else ""
            try:
                name, value = unquote(raw_query).split("+", 1)
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            with _webvisit_lock:
                if name not in _webvisit_values:
                    self.send_response(404)
                    self.end_headers()
                    return
                _webvisit_values[name] = value
            self._send(200, "text/plain", b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/cgi-bin/ILRReadValues.exe":
            self._send(200, "text/xml", _read_values_xml())
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
