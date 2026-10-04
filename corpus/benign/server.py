"""Tiny status server used in the widgetlib examples (synthetic)."""
import base64
import hashlib
import http.server
import json

# A 1x1 transparent PNG, embedded so the demo needs no static files.
PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
EXPECTED_DIGEST = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
ROUTE_TEMPLATE = "https://api.example.com/{owner}/{repo}/status"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/pixel.png":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(PIXEL)
            return
        body = json.dumps({"status": "ok", "digest": hashlib.sha256(b"hello").hexdigest() == EXPECTED_DIGEST})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
