#!/usr/bin/env python3
"""Business origin for the Nginx WAF e2e fixture.

Echoes the request line, every received header and the body length as JSON so
the checks can assert what survived the Nginx -> Rooster -> origin hop.

usage: backend.py <port> <name> [--tls <cert> <key>]
"""
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    origin = "origin"

    def _respond(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps(
            {
                "origin": self.origin,
                "method": self.command,
                "path": self.path,
                "version": self.request_version,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                # Same-name directives survive as separate pairs; the dict above
                # collapses them, which is exactly what the Host-inheritance
                # checks need to see.
                "header_pairs": [[k.lower(), v] for k, v in self.headers.items()],
                "body_bytes": len(body),
                "body_head": body[:64].decode("utf-8", "replace"),
            },
            sort_keys=True,
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("x-origin", self.origin)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_HEAD = _respond

    def log_message(self, format, *args):  # noqa: A002 - base class name
        sys.stderr.write("%s %s\n" % (self.origin, format % args))


def main() -> int:
    port, name = int(sys.argv[1]), sys.argv[2]
    Handler.origin = name
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if len(sys.argv) > 3 and sys.argv[3] == "--tls":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[4], sys.argv[5])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"serving {name} on {port}", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
