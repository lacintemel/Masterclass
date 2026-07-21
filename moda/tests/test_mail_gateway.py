from __future__ import annotations

import asyncio
import hashlib
import json
import smtplib
import socket
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import pytest

from moda.gateway.analyzer import normalize_verdict
from moda.gateway.config import GatewayConfig
from moda.gateway.errors import AnalyzerScanError, RelayError
from moda.gateway.models import AttachmentResult, Verdict
from moda.gateway.processor import GatewayProcessor
from moda.gateway.smtp import GatewaySmtpHandler, build_smtp_controller


class FakeAnalyzer:
    def __init__(self, *, fail: str | None = None):
        self.fail = fail

    def analyze(self, filename: str, content_type: str, content: bytes) -> AttachmentResult:
        if self.fail:
            raise AnalyzerScanError(self.fail)
        if "malicious" in filename:
            verdict, score = Verdict.MALICIOUS, 95.0
        elif "suspicious" in filename:
            verdict, score = Verdict.SUSPICIOUS, 50.0
        else:
            verdict, score = Verdict.SAFE, 0.0
        return AttachmentResult(
            filename,
            content_type,
            len(content),
            hashlib.sha256(content).hexdigest(),
            verdict,
            score,
            (f"{verdict.value} test result",),
        )

    def close(self) -> None:
        return

    @property
    def healthy(self) -> bool:
        return True


class FakeRelay:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.deliveries: list[tuple[bytes, str, list[str]]] = []

    def deliver(self, raw_message: bytes, mail_from: str, recipients: list[str]) -> None:
        if self.fail:
            raise RelayError("relay unavailable")
        self.deliveries.append((raw_message, mail_from, recipients))


@pytest.fixture
def config(tmp_path: Path) -> GatewayConfig:
    return GatewayConfig(
        accepted_recipient_domains=("example.test",),
        quarantine_path=tmp_path / "quarantine",
        max_message_bytes=100_000,
        max_attachment_bytes=50_000,
        max_attachments=5,
    )


def make_mail(*attachments: tuple[str, bytes], subject: str = "Gateway test") -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = subject
    message.set_content("Harmless unit test message")
    for filename, content in attachments:
        message.add_attachment(
            content,
            maintype="application",
            subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
        )
    return message.as_bytes(policy=policy.SMTP)


def processor(
    config: GatewayConfig,
    *,
    analyzer: FakeAnalyzer | None = None,
    relay: FakeRelay | None = None,
) -> tuple[GatewayProcessor, FakeRelay]:
    actual_relay = relay or FakeRelay()
    return (
        GatewayProcessor(
            config,
            analyzer=analyzer or FakeAnalyzer(),
            relay=actual_relay,
        ),
        actual_relay,
    )


def process(gateway: GatewayProcessor, raw: bytes):
    return gateway.process(raw, "sender@example.test", ["recipient@example.test"])


def test_message_without_attachment_is_delivered(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    outcome = process(gateway, make_mail())
    assert outcome.response == "250 2.0.0 Message accepted for delivery"
    assert len(relay.deliveries) == 1
    assert not list(config.quarantine_path.glob("*"))


def test_safe_office_attachment_is_delivered_raw(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    raw = make_mail(("safe.docx", b"safe"))
    outcome = process(gateway, raw)
    assert outcome.code == 250
    assert outcome.result and outcome.result.verdict is Verdict.SAFE
    assert relay.deliveries[0][0] == raw


def test_suspicious_attachment_is_silently_quarantined(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    outcome = process(gateway, make_mail(("suspicious.docx", b"safe marker")))
    assert outcome.response == "250 2.0.0 Message accepted into quarantine"
    assert outcome.quarantine_id
    assert not relay.deliveries


def test_malicious_attachment_is_quarantined_and_rejected(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    outcome = process(gateway, make_mail(("malicious.docm", b"safe marker")))
    assert outcome.response == "550 5.7.1 Message rejected by security policy"
    assert outcome.quarantine_id
    assert not relay.deliveries


def test_multiple_attachments_use_highest_verdict(config: GatewayConfig) -> None:
    gateway, _ = processor(config)
    suspicious = process(
        gateway,
        make_mail(("safe.docx", b"a"), ("suspicious.xlsx", b"b")),
    )
    malicious = process(
        gateway,
        make_mail(("safe.docx", b"a"), ("malicious.pptm", b"b")),
    )
    assert suspicious.result and suspicious.result.verdict is Verdict.SUSPICIOUS
    assert malicious.result and malicious.result.verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("failure", ["Analyzer timed out", "Invalid analyzer response"])
def test_analyzer_failures_are_fail_closed(config: GatewayConfig, failure: str) -> None:
    gateway, relay = processor(config, analyzer=FakeAnalyzer(fail=failure))
    outcome = process(gateway, make_mail(("safe.docx", b"safe")))
    assert outcome.response == "451 4.7.0 Temporary scanning failure; please retry later"
    assert not relay.deliveries


def test_mailpit_relay_failure_returns_temporary_error(config: GatewayConfig) -> None:
    gateway, _ = processor(config, relay=FakeRelay(fail=True))
    outcome = process(gateway, make_mail(("safe.docx", b"safe")))
    assert outcome.response == "451 4.4.1 Downstream mail server unavailable"


def test_unaccepted_recipient_domain_is_not_relayed(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    outcome = gateway.process(
        make_mail(),
        "sender@example.test",
        ["recipient@outside.test"],
    )
    assert outcome.response == "550 5.7.1 Relaying denied"
    assert not relay.deliveries


def test_large_attachment_is_rejected(config: GatewayConfig) -> None:
    gateway, relay = processor(replace(config, max_attachment_bytes=3))
    outcome = process(gateway, make_mail(("safe.docx", b"four")))
    assert outcome.code == 552
    assert not relay.deliveries


def test_large_raw_message_is_rejected(config: GatewayConfig) -> None:
    gateway, relay = processor(replace(config, max_message_bytes=10))
    outcome = process(gateway, make_mail())
    assert outcome.response.startswith("552 5.3.4")
    assert not relay.deliveries


def test_broken_mime_and_invalid_base64_fail_closed(config: GatewayConfig) -> None:
    gateway, relay = processor(config)
    broken_mime = b'Content-Type: multipart/mixed; boundary="missing"\r\n\r\nplain text'
    invalid_base64 = (
        b"Content-Type: application/msword\r\n"
        b"Content-Disposition: attachment; filename=test.doc\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n%%%INVALID%%%"
    )
    assert process(gateway, broken_mime).code == 451
    assert process(gateway, invalid_base64).code == 451
    assert not relay.deliveries


def test_quarantine_files_contain_required_metadata(config: GatewayConfig) -> None:
    gateway, _ = processor(config)
    raw = make_mail(("../../malicious.docm", b"harmless"), subject="Quarantine me")
    outcome = process(gateway, raw)
    assert outcome.quarantine_id
    eml_path = config.quarantine_path / f"{outcome.quarantine_id}.eml"
    json_path = config.quarantine_path / f"{outcome.quarantine_id}.json"
    assert eml_path.read_bytes() == raw
    report = json.loads(json_path.read_text())
    assert report["quarantine_id"] == outcome.quarantine_id
    assert report["mail_from"] == "sender@example.test"
    assert report["recipients"] == ["recipient@example.test"]
    assert report["subject"] == "Quarantine me"
    assert report["message_verdict"] == "malicious"
    assert report["attachments"][0]["filename"] == "malicious.docm"
    assert len(report["attachments"][0]["sha256"]) == 64


def test_attachment_count_limit(config: GatewayConfig) -> None:
    gateway, _ = processor(replace(config, max_attachments=1))
    outcome = process(
        gateway,
        make_mail(("safe.docx", b"a"), ("another.docx", b"b")),
    )
    assert outcome.code == 552


def test_smtp_handler_returns_processor_status(config: GatewayConfig) -> None:
    gateway, _ = processor(config)
    handler = GatewaySmtpHandler(gateway)
    envelope = SimpleNamespace(
        original_content=make_mail(("malicious.docm", b"marker")),
        mail_from="sender@example.test",
        rcpt_tos=["recipient@example.test"],
    )
    response = asyncio.run(handler.handle_DATA(None, None, envelope))
    assert response == "550 5.7.1 Message rejected by security policy"


def test_smtp_handler_enforces_recipient_allowlist(config: GatewayConfig) -> None:
    gateway, _ = processor(config)
    handler = GatewaySmtpHandler(gateway)
    envelope = SimpleNamespace(mail_from="sender@example.test", rcpt_tos=[])
    denied = asyncio.run(handler.handle_RCPT(None, None, envelope, "target@outside.test", []))
    accepted = asyncio.run(handler.handle_RCPT(None, None, envelope, "target@example.test", []))
    assert denied == "550 5.7.1 Relaying denied"
    assert accepted == "250 2.1.5 Recipient OK"
    assert envelope.rcpt_tos == ["target@example.test"]


def test_verdict_alias_normalization_and_unknown_rejection() -> None:
    assert normalize_verdict("clean") is Verdict.SAFE
    assert normalize_verdict("unknown") is Verdict.SUSPICIOUS
    assert normalize_verdict("infected") is Verdict.MALICIOUS
    with pytest.raises(AnalyzerScanError):
        normalize_verdict("unexpected")


def test_real_smtp_session_returns_policy_response(config: GatewayConfig) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    smtp_config = replace(
        config,
        smtp_listen_host="127.0.0.1",
        smtp_listen_port=port,
    )
    gateway, _ = processor(smtp_config)
    controller = build_smtp_controller(smtp_config, gateway)
    controller.start()
    try:
        with (
            smtplib.SMTP("127.0.0.1", port, timeout=3) as client,
            pytest.raises(smtplib.SMTPDataError) as rejected,
        ):
            client.sendmail(
                "sender@example.test",
                ["recipient@example.test"],
                make_mail(("malicious.docm", b"marker")),
            )
        assert rejected.value.smtp_code == 550
        assert b"Message rejected by security policy" in rejected.value.smtp_error
    finally:
        controller.stop()
