#!/usr/bin/env python3
"""Mock Integrations gateway for the PCE Kafka tests (python3 stdlib plus the openssl CLI).

Serves GET /integrations/api/v1/config/flowlink-kafka over HTTPS with a self-signed certificate
generated at start-up (FlowPilot runs with verify_pce_cert: false against it).

Usage: mock_gateway.py [--listen 127.0.0.1] [--port 8444] [--status 200|404|<n>]
                       [--body-file FILE] [--once] [--requests FILE]
  --status     response status (default 200)
  --body-file  response body; with status 200 the Integrations JSON. The body comes from a file so a
               connection string never appears in an argv. Default: `{}` for 200, `404 page not found`
               otherwise.
  --once       exit after the first config request
  --requests   append one JSON line per request: method, path, query, basic_auth (true/false). The
               credentials themselves are never written.
Prints `mock gateway listening on <host>:<port>` once ready.
"""
import argparse
import json
import os
import ssl
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

CONFIG_PATH = "/integrations/api/v1/config/flowlink-kafka"


def self_signed_context(workdir):
    key = os.path.join(workdir, "gw.key")
    cert = os.path.join(workdir, "gw.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=mock-gateway", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-keyout", key, "-out", cert],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--status", type=int, default=200)
    ap.add_argument("--body-file")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--requests")
    a = ap.parse_args()

    if a.body_file:
        with open(a.body_file, "rb") as f:
            body = f.read()
    else:
        body = b"{}" if a.status == 200 else b"404 page not found"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        served = False

        def do_GET(self):
            u = urlsplit(self.path)
            if a.requests:
                rec = {
                    "method": "GET",
                    "path": u.path,
                    "query": u.query,
                    "basic_auth": self.headers.get("Authorization", "").startswith("Basic "),
                }
                with open(a.requests, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            if u.path != CONFIG_PATH:
                self.reply(404, b"404 page not found")
                return
            self.reply(a.status, body)
            if a.once:
                Handler.served = True

        def reply(self, status, data):
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if status == 200 else "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            sys.stderr.write("mock gateway: %s\n" % (fmt % args))

    with tempfile.TemporaryDirectory() as d:
        srv = HTTPServer((a.listen, a.port), Handler)
        srv.socket = self_signed_context(d).wrap_socket(srv.socket, server_side=True)
        print("mock gateway listening on %s:%d" % (a.listen, a.port), flush=True)
        try:
            while not Handler.served:
                srv.handle_request()
        except KeyboardInterrupt:
            pass
        srv.server_close()


if __name__ == "__main__":
    main()
