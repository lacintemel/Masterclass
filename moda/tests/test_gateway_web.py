from __future__ import annotations

import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from test_mail_gateway import FakeAnalyzer, FakeRelay, make_mail

from moda.gateway.config import GatewayConfig
from moda.gateway.models import AttachmentResult, MessageResult, Verdict
from moda.gateway.processor import GatewayProcessor
from moda.gateway.web import build_admin_server, build_health_server


@pytest.fixture
def gateway(tmp_path: Path) -> GatewayProcessor:
    config = GatewayConfig(
        quarantine_path=tmp_path / "quarantine",
        accepted_recipient_domains=("example.test",),
    )
    return GatewayProcessor(config, analyzer=FakeAnalyzer(), relay=FakeRelay())


def run_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def fetch(url: str) -> tuple[bytes, object]:
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read(), response.headers


def test_admin_dashboard_quarantine_detail_download_and_delete(
    gateway: GatewayProcessor,
) -> None:
    raw = make_mail(("malicious.docm", b"harmless marker"), subject="Admin test")
    outcome = gateway.process(
        raw,
        "sender@example.test",
        ["recipient@example.test"],
    )
    assert outcome.quarantine_id

    server = build_admin_server("127.0.0.1", 0, gateway)
    thread = run_server(server)
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        dashboard, headers = fetch(base_url + "/")
        assert b"Dashboard" in dashboard
        assert b"malicious" in dashboard
        assert headers["X-Frame-Options"] == "DENY"

        listing, _ = fetch(base_url + "/quarantine")
        assert b"Admin test" in listing
        assert outcome.quarantine_id.encode() in listing

        detail, _ = fetch(base_url + f"/quarantine/{outcome.quarantine_id}")
        assert b"Attachments are never previewed" in detail
        token_match = re.search(rb'name="csrf_token" value="([^"]+)"', detail)
        assert token_match

        downloaded, download_headers = fetch(
            base_url + f"/quarantine/{outcome.quarantine_id}/download"
        )
        assert downloaded == raw
        assert download_headers["Content-Disposition"].startswith("attachment;")

        payload = urllib.parse.urlencode({"csrf_token": token_match.group(1).decode()}).encode()
        request = urllib.request.Request(
            base_url + f"/quarantine/{outcome.quarantine_id}/delete",
            data=payload,
            method="POST",
            headers={"Origin": base_url},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            assert response.status == 200
        assert gateway.quarantine.get(outcome.quarantine_id) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_admin_rejects_invalid_id_and_csrf(gateway: GatewayProcessor) -> None:
    server = build_admin_server("127.0.0.1", 0, gateway)
    thread = run_server(server)
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as invalid_id:
            fetch(base_url + "/quarantine/not-an-id")
        assert invalid_id.value.code == 400

        request = urllib.request.Request(
            base_url + "/quarantine/" + ("a" * 32) + "/delete",
            data=b"csrf_token=wrong",
            method="POST",
            headers={"Origin": "http://outside.test"},
        )
        with pytest.raises(urllib.error.HTTPError) as csrf_error:
            urllib.request.urlopen(request, timeout=3)
        assert csrf_error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_health_endpoint_reports_component_state(gateway: GatewayProcessor) -> None:
    server = build_health_server("127.0.0.1", 0, gateway, lambda: True)
    thread = run_server(server)
    try:
        body, headers = fetch(f"http://127.0.0.1:{server.server_address[1]}/health")
        assert b'"smtp": true' in body
        assert b'"relay": false' in body
        assert headers["Cache-Control"] == "no-store"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_detail_escapes_untrusted_metadata(gateway: GatewayProcessor) -> None:
    result = MessageResult(
        "<script>alert(1)</script>",
        Verdict.MALICIOUS,
        (
            AttachmentResult(
                "<img src=x>.docm",
                "application/msword",
                1,
                "a" * 64,
                Verdict.MALICIOUS,
                90,
                ("<script>reason</script>",),
            ),
        ),
    )
    quarantine_id = gateway.quarantine.save(
        b"Subject: escaped\r\n\r\nbody",
        mail_from="<sender@example.test>",
        recipients=["recipient@example.test"],
        result=result,
    )
    server = build_admin_server("127.0.0.1", 0, gateway)
    thread = run_server(server)
    try:
        body, _ = fetch(f"http://127.0.0.1:{server.server_address[1]}/quarantine/{quarantine_id}")
        assert b"<script>" not in body
        assert b"&lt;script&gt;" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
