from __future__ import annotations

import json
import mimetypes
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from moda.core.engine import AnalyzerEngine


STATIC_DIR = Path(__file__).resolve().parent / "static"


class MODAUIHandler(SimpleHTTPRequestHandler):
    """Small stdlib HTTP handler for the local MODA web UI."""

    server_version = "MODAUI/0.1"

    def __init__(self, *args: object, directory: str | None = None, **kwargs: object) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/analyze":
            self.send_error(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json({"error": "No file content received"}, status=400)
            return

        max_size_mb = getattr(self.server, "max_size_mb", 100)
        max_bytes = max_size_mb * 1024 * 1024
        if length > max_bytes:
            self._send_json({"error": f"File exceeds {max_size_mb} MB limit"}, status=413)
            return

        query = parse_qs(parsed.query)
        request_skip_yara = query.get("yara", ["1"])[0] == "0"
        original_name = unquote(self.headers.get("X-Filename", "upload.bin"))
        suffix = Path(original_name).suffix[:16]
        temp_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                temp_file.write(self.rfile.read(length))
                temp_path = Path(temp_file.name)

            engine = AnalyzerEngine(
                skip_yara=getattr(self.server, "skip_yara", False) or request_skip_yara,
                max_file_size_mb=max_size_mb,
            )
            result = engine.analyze_file(temp_path)
            payload = result.to_dict()
            payload["file_info"]["file_name"] = Path(original_name).name
            self._send_json(payload)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def guess_type(self, path: str) -> str:
        if path.endswith(".js"):
            return "text/javascript"
        if path.endswith(".css"):
            return "text/css"
        return mimetypes.guess_type(path)[0] or "application/octet-stream"

    def log_message(self, format: str, *args: object) -> None:
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)

    def _send_json(self, payload: dict[str, object], status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_ui(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    skip_yara: bool = False,
    max_size_mb: int = 100,
    verbose: bool = False,
) -> None:
    """Start the local MODA browser UI."""
    server = ThreadingHTTPServer((host, port), MODAUIHandler)
    server.skip_yara = skip_yara
    server.max_size_mb = max_size_mb
    server.verbose = verbose

    url = f"http://{host}:{port}"
    print(f"MODA UI running at {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MODA UI.")
    finally:
        server.server_close()
