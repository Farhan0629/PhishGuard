"""Tiny Flask server exposing the phishing detector as a JSON API.

Single endpoint: POST /api/check   body: {"url": "..."}
Also serves the static frontend from ./static/
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Flask-free: stdlib http.server to keep dependencies to zero. (Flask is fine too,
# but the user asked for simplest approach with limited deps.)


HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")

sys.path.insert(0, HERE)
from detector import analyze  # noqa: E402


# Indicator -> (label shown to user, hex color).
INDICATOR_META = {
    "safe":        ("Safe",          "#16a34a"),
    "likely_safe": ("Likely Safe",   "#0ea5e9"),
    "suspicious":  ("Suspicious",    "#f59e0b"),
    "fake":        ("Likely Fake",   "#dc2626"),
}


def _json(handler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _serve_file(handler, path: str) -> None:
    if not os.path.isfile(path):
        handler.send_response(404)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.end_headers()
        handler.wfile.write(b"Not found")
        return

    ext = os.path.splitext(path)[1].lower()
    ctype = {
        ".html": "text/html; charset=utf-8",
        ".css":  "text/css; charset=utf-8",
        ".js":   "application/javascript; charset=utf-8",
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".ico":  "image/x-icon",
        ".svg":  "image/svg+xml",
    }.get(ext, "application/octet-stream")

    with open(path, "rb") as f:
        data = f.read()
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    # Quieter logs.
    def log_message(self, fmt, *args):  # noqa: N802
        sys.stderr.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            _serve_file(self, os.path.join(STATIC_DIR, "index.html"))
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            rel = os.path.normpath(rel).lstrip(os.sep)
            # prevent path traversal
            full = os.path.normpath(os.path.join(STATIC_DIR, rel))
            if not full.startswith(STATIC_DIR):
                self.send_response(403); self.end_headers(); return
            _serve_file(self, full)
            return
        if path == "/api/health":
            _json(self, 200, {"ok": True})
            return
        self.send_response(404); self.end_headers()

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/api/check":
            _json(self, 404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            _json(self, 400, {"error": "invalid_json"})
            return

        url = (data.get("url") or "").strip()
        if not url:
            _json(self, 400, {"error": "missing_url"})
            return

        report = analyze(url)
        label, color = INDICATOR_META[report.indicator]
        _json(self, 200, {
            "url":       url,
            "score":     report.score,
            "indicator": report.indicator,
            "label":     label,
            "color":     color,
            "reason":    report.reason,
            "flags":     report.flags,
        })


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Phishing detector running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
