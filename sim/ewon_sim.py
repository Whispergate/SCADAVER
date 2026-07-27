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

PORT = 80

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
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    port = args.port or args.legacy_port or int(os.environ.get("EWON_SIM_PORT", str(PORT)))
    if not 1 <= port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    srv = http.server.HTTPServer((args.host, port), EwonHandler)
    print(f"eWON HTTP stub listening on {args.host}:{port}")
    print("  POST /wrcgi.bin/wsdReadForm -> 20-field CSV")
    print("  username=admin  access_rights=15  password=<decode failed>")
    srv.serve_forever()
