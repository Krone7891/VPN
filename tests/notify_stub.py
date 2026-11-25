#!/usr/bin/env python3
"""nimmt Benachrichtigungen an (wie ntfy/Telegram) und schreibt sie in eine Datei: notify_stub.py <port> <datei>"""
import http.server, sys, urllib.parse

port, out = int(sys.argv[1]), sys.argv[2]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(out, "a", encoding="utf-8") as f:
            auth = self.headers.get("Authorization") or "-"
            f.write(urllib.parse.unquote(self.path) + " | " + urllib.parse.unquote_plus(body).replace("\n", " ") + " | " + auth + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
