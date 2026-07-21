from __future__ import annotations

import json
import logging
import mimetypes
import secrets
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import replace
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from moda.core.engine import AnalyzerEngine
from moda.core.models import AnalysisResult
from moda.reporting.pdf_report import PDFReporter


STATIC_DIR = Path(__file__).resolve().parent / "static"
logger = logging.getLogger(__name__)


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
        if parsed.path not in {"/api/analyze", "/api/report"}:
            self.send_error(404, "Not found")
            return

        if not self._is_authorized() or not self._is_same_origin():
            self._send_json({"error": "Request is not authorized"}, status=403)
            return

        query = parse_qs(parsed.query)
        if parsed.path == "/api/report" and query.get("analysis_id"):
            cached = self._get_cached_result(query["analysis_id"][0])
            if cached is None:
                self._send_json({"error": "Analysis result expired or was not found"}, status=404)
                return
            language = query.get("lang", ["en"])[0]
            self._send_pdf(cached, cached.file_name, language=language if language in {"en", "tr"} else "en")
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json({"error": "Invalid Content-Length header"}, status=400)
            return
        if length <= 0:
            self._send_json({"error": "No file content received"}, status=400)
            return

        max_size_mb = getattr(self.server, "max_size_mb", 100)
        max_bytes = max_size_mb * 1024 * 1024
        if length > max_bytes:
            self._send_json({"error": f"File exceeds {max_size_mb} MB limit"}, status=413)
            return

        request_skip_yara = query.get("yara", ["1"])[0] == "0"
        report_language = query.get("lang", ["en"])[0]
        if report_language not in {"en", "tr"}:
            report_language = "en"
        original_name = Path(unquote(self.headers.get("X-Filename", "upload.bin"))).name
        suffix = Path(original_name).suffix[:16]
        temp_path: Path | None = None
        acquired = False

        try:
            semaphore = getattr(self.server, "analysis_semaphore", None)
            if semaphore is not None and not semaphore.acquire(blocking=False):
                self._send_json({"error": "Analysis capacity is busy; retry shortly"}, status=429)
                return
            acquired = semaphore is not None
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                body = self.rfile.read(length)
                if len(body) != length:
                    self._send_json({"error": "Incomplete request body"}, status=400)
                    return
                temp_file.write(body)
                temp_path = Path(temp_file.name)

            engine = AnalyzerEngine(
                skip_yara=getattr(self.server, "skip_yara", False) or request_skip_yara,
                max_file_size_mb=max_size_mb,
            )
            result = engine.analyze_file(temp_path)
            display_name = Path(original_name).name
            cache_id = f"{result.file_hash_sha256[:24]}-{'y0' if request_skip_yara else 'y1'}"
            extra = dict(result.extra)
            extra["analysis_id"] = cache_id
            result = replace(result, file_name=display_name, file_path=display_name, extra=extra)
            self._cache_result(cache_id, result)
            if parsed.path == "/api/report":
                self._send_pdf(result, display_name, language=report_language)
                return
            payload = result.to_dict()
            self._send_json(payload)
        except Exception as exc:
            logger.exception("UI request failed")
            message = str(exc) if getattr(self.server, "verbose", False) else "Analysis failed"
            self._send_json({"error": message}, status=500)
        finally:
            if acquired:
                semaphore.release()
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'",
        )
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

    def _is_authorized(self) -> bool:
        token = getattr(self.server, "access_token", "")
        return not token or secrets.compare_digest(self.headers.get("X-MODA-Token", ""), token)

    def _is_same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.scheme in {"http", "https"} and parsed.netloc == self.headers.get("Host", "")

    def _cache_result(self, analysis_id: str, result: AnalysisResult) -> None:
        cache = getattr(self.server, "result_cache", None)
        lock = getattr(self.server, "cache_lock", None)
        if cache is None or lock is None:
            return
        with lock:
            cache[analysis_id] = (time.monotonic(), result)
            cache.move_to_end(analysis_id)
            while len(cache) > 32:
                cache.popitem(last=False)

    def _get_cached_result(self, analysis_id: str) -> AnalysisResult | None:
        cache = getattr(self.server, "result_cache", None)
        lock = getattr(self.server, "cache_lock", None)
        if cache is None or lock is None:
            return None
        with lock:
            cached = cache.get(analysis_id)
            if cached is None:
                return None
            created, result = cached
            if time.monotonic() - created > 15 * 60:
                cache.pop(analysis_id, None)
                return None
            return result

    def _send_pdf(
        self,
        result: AnalysisResult,
        original_name: str,
        *,
        language: str = "en",
    ) -> None:
        body = PDFReporter(language=language).generate(result)
        safe_stem = "".join(
            character for character in (Path(original_name).stem or "moda")
            if character.isalnum() or character in {"-", "_", "."}
        )[:80] or "moda"
        report_name = f"{safe_stem}-moda-report.pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{report_name}"')
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
    allow_remote: bool = False,
    access_token: str | None = None,
    max_concurrent_analyses: int = 2,
) -> None:
    """Start the local MODA browser UI."""
    if host not in {"127.0.0.1", "localhost", "::1"} and not allow_remote:
        raise ValueError("Remote UI binding requires --allow-remote and an access token")
    if allow_remote and not access_token:
        access_token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer((host, port), MODAUIHandler)
    server.skip_yara = skip_yara
    server.max_size_mb = max_size_mb
    server.verbose = verbose
    server.access_token = access_token or ""
    server.max_concurrent_analyses = max(1, max_concurrent_analyses)
    server.analysis_semaphore = threading.BoundedSemaphore(server.max_concurrent_analyses)
    server.result_cache = OrderedDict()
    server.cache_lock = threading.Lock()

    url = f"http://{host}:{port}"
    print(f"MODA UI running at {url}")
    if server.access_token:
        print(f"Remote access token: {server.access_token}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MODA UI.")
    finally:
        server.server_close()
