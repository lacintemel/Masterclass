"""Local health and server-rendered quarantine administration UI."""

from __future__ import annotations

import html
import json
import secrets
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .processor import GatewayProcessor


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_health_server(
    host: str,
    port: int,
    processor: GatewayProcessor,
    smtp_status: Callable[[], bool],
) -> GatewayHTTPServer:
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if urlparse(self.path).path != "/health":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            payload = json.dumps(processor.health(smtp_running=smtp_status())).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return GatewayHTTPServer((host, port), HealthHandler)


def build_admin_server(host: str, port: int, processor: GatewayProcessor) -> GatewayHTTPServer:
    csrf_token = secrets.token_urlsafe(32)

    class AdminHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(_dashboard(processor.stats.snapshot()))
                return
            if parsed.path == "/quarantine":
                self._send_html(_quarantine_list(processor.quarantine.list_records()))
                return
            route = _quarantine_route(parsed.path)
            if route is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            quarantine_id, action = route
            try:
                if action == "download":
                    self._download(quarantine_id)
                elif action == "detail":
                    record = processor.quarantine.get(quarantine_id)
                    if record is None:
                        self.send_error(HTTPStatus.NOT_FOUND)
                    else:
                        self._send_html(_quarantine_detail(record, csrf_token))
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)

        def do_POST(self) -> None:
            route = _quarantine_route(urlparse(self.path).path)
            if route is None or route[1] != "delete":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not self._same_origin():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            if length > 4096:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            values = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            if not secrets.compare_digest(values.get("csrf_token", [""])[0], csrf_token):
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                deleted = processor.quarantine.delete(route[0])
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            if not deleted:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/quarantine")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _download(self, quarantine_id: str) -> None:
            path = processor.quarantine.eml_path(quarantine_id)
            if path is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            body = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", "message/rfc822")
            self.send_header("Content-Disposition", f'attachment; filename="{quarantine_id}.eml"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, body: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            )

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            parsed = urlparse(origin)
            return parsed.netloc == self.headers.get("Host") and parsed.scheme in {"http", "https"}

        def log_message(self, format: str, *args: Any) -> None:
            return

    return GatewayHTTPServer((host, port), AdminHandler)


def _quarantine_route(path: str) -> tuple[str, str] | None:
    parts = [part for part in path.split("/") if part]
    if len(parts) == 2 and parts[0] == "quarantine":
        return parts[1], "detail"
    if (
        len(parts) == 3
        and parts[0] == "quarantine"
        and parts[2]
        in {
            "download",
            "delete",
        }
    ):
        return parts[1], parts[2]
    return None


def _layout(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(title)} · MODA Gateway</title><style>
:root{{--bg:#0d1117;--panel:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--safe:#3fb950;--suspicious:#d29922;--malicious:#f85149}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}}
nav,main{{max-width:1180px;margin:auto;padding:20px}}nav{{display:flex;gap:24px;border-bottom:1px solid var(--line)}}a{{color:#58a6ff;text-decoration:none}}h1{{font-size:25px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}}
.card,table,.detail{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px}}.metric{{font-size:30px;font-weight:700}}table{{width:100%;border-collapse:collapse;padding:0}}th,td{{padding:11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th,.muted{{color:var(--muted)}}
.safe{{color:var(--safe)}}.suspicious{{color:var(--suspicious)}}.malicious,.error{{color:var(--malicious)}}code{{overflow-wrap:anywhere}}button{{background:#da3633;color:white;border:0;border-radius:6px;padding:9px 14px;cursor:pointer}}ul{{padding-left:20px}}
</style></head><body><nav><strong>MODA Mail Gateway</strong><a href="/">Dashboard</a><a href="/quarantine">Quarantine</a></nav><main><h1>{html.escape(title)}</h1>{content}</main></body></html>"""


def _dashboard(stats: dict[str, Any]) -> str:
    cards = "".join(
        f'<div class="card"><div class="muted">{html.escape(label)}</div><div class="metric">{int(stats[key])}</div></div>'
        for key, label in (
            ("total", "Scanned"),
            ("safe", "Safe"),
            ("suspicious", "Suspicious"),
            ("malicious", "Malicious"),
            ("analyzer_errors", "Analyzer errors"),
        )
    )
    rows = (
        "".join(
            "<tr>"
            f"<td>{html.escape(str(item.get('timestamp', '')))}</td>"
            f"<td>{html.escape(str(item.get('sender', '')))}</td>"
            f"<td>{html.escape(str(item.get('event', '')))}</td>"
            f'<td class="{html.escape(str(item.get("verdict", "")))}">{html.escape(str(item.get("verdict", "")))}</td>'
            "</tr>"
            for item in stats.get("recent", [])[:20]
        )
        or '<tr><td colspan="4" class="muted">No messages processed yet.</td></tr>'
    )
    return _layout(
        "Dashboard",
        f'<div class="grid">{cards}</div><h2>Recent activity</h2><table><tr><th>Time</th><th>Sender</th><th>Event</th><th>Verdict</th></tr>{rows}</table>',
    )


def _quarantine_list(records: list[dict[str, Any]]) -> str:
    rows = (
        "".join(
            "<tr>"
            f"<td>{html.escape(str(item.get('created_at', '')))}</td>"
            f"<td>{html.escape(str(item.get('mail_from', '')))}</td>"
            f"<td>{html.escape(', '.join(str(value) for value in item.get('recipients', [])))}</td>"
            f"<td>{html.escape(str(item.get('subject', '')))}</td>"
            f'<td class="{html.escape(str(item.get("message_verdict", "")))}">{html.escape(str(item.get("message_verdict", "")))}</td>'
            f"<td>{float(item.get('risk_score', 0)):.1f}</td>"
            f'<td><a href="/quarantine/{html.escape(str(item.get("quarantine_id", "")))}">Details</a></td>'
            "</tr>"
            for item in records
        )
        or '<tr><td colspan="7" class="muted">Quarantine is empty.</td></tr>'
    )
    return _layout(
        "Quarantine",
        f"<table><tr><th>Date</th><th>Sender</th><th>Recipients</th><th>Subject</th><th>Verdict</th><th>Score</th><th></th></tr>{rows}</table>",
    )


def _quarantine_detail(record: dict[str, Any], csrf_token: str) -> str:
    quarantine_id = html.escape(str(record.get("quarantine_id", "")))
    attachments = "".join(_attachment_card(item) for item in record.get("attachments", []))
    metadata = (
        '<div class="detail">'
        f"<p><strong>Sender:</strong> {html.escape(str(record.get('mail_from', '')))}</p>"
        f"<p><strong>Recipients:</strong> {html.escape(', '.join(str(item) for item in record.get('recipients', [])))}</p>"
        f"<p><strong>Subject:</strong> {html.escape(str(record.get('subject', '')))}</p>"
        f"<p><strong>Verdict:</strong> {html.escape(str(record.get('message_verdict', '')))}</p>"
        f'<p><a href="/quarantine/{quarantine_id}/download">Download raw .eml</a></p>'
        '<p class="muted">Attachments are never previewed or opened in the browser.</p>'
        f'<form method="post" action="/quarantine/{quarantine_id}/delete"><input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}"><button type="submit">Delete quarantine record</button></form>'
        "</div>"
    )
    return _layout("Quarantine detail", metadata + "<h2>Attachments</h2>" + attachments)


def _attachment_card(item: dict[str, Any]) -> str:
    reasons = "".join(f"<li>{html.escape(str(reason))}</li>" for reason in item.get("reasons", []))
    return (
        '<div class="card">'
        f"<h3>{html.escape(str(item.get('filename', '')))}</h3>"
        f"<p><strong>Type:</strong> {html.escape(str(item.get('content_type', '')))}</p>"
        f"<p><strong>SHA-256:</strong> <code>{html.escape(str(item.get('sha256', '')))}</code></p>"
        f"<p><strong>Verdict / score:</strong> {html.escape(str(item.get('verdict', '')))} / {float(item.get('score', 0)):.1f}</p>"
        f"<p><strong>Analysis status:</strong> {html.escape(str(item.get('analysis_status', '')))}</p>"
        f"<ul>{reasons}</ul></div>"
    )
