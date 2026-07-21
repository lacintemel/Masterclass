from __future__ import annotations

import smtplib
from pathlib import Path
from types import SimpleNamespace

import pytest

import moda.gateway.analyzer as analyzer_module
import moda.gateway.app as app_module
from moda.gateway.analyzer import DirectModaAnalyzer, SimulatedAnalyzer
from moda.gateway.app import GatewayApplication
from moda.gateway.config import GatewayConfig
from moda.gateway.models import Verdict
from moda.gateway.quarantine import QuarantineStore
from moda.gateway.relay import SmtpRelay


def test_environment_configuration(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SMTP_LISTEN_PORT", "2626")
    monkeypatch.setenv("SIMULATE_ANALYZER", "false")
    monkeypatch.setenv("ACCEPTED_RECIPIENT_DOMAINS", "Example.Test, company.test")
    monkeypatch.setenv("QUARANTINE_PATH", str(tmp_path / "mail"))
    config = GatewayConfig.from_env()
    assert config.smtp_listen_port == 2626
    assert config.simulate_analyzer is False
    assert config.accepted_recipient_domains == ("company.test", "example.test")
    assert config.quarantine_path == (tmp_path / "mail").resolve()


def test_environment_rejects_empty_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACCEPTED_RECIPIENT_DOMAINS", " , ")
    with pytest.raises(ValueError):
        GatewayConfig.from_env()


def test_simulation_marker_and_filename_verdicts() -> None:
    analyzer = SimulatedAnalyzer()
    assert analyzer.analyze("normal.docx", "application/msword", b"x").verdict is Verdict.SAFE
    assert (
        analyzer.analyze("suspicious.docx", "application/msword", b"x").verdict
        is Verdict.SUSPICIOUS
    )
    assert (
        analyzer.analyze("normal.docx", "application/msword", b"MDOA_TEST_MALICIOUS").verdict
        is Verdict.MALICIOUS
    )
    analyzer.close()


def test_direct_analyzer_adapts_moda_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_result = SimpleNamespace(
        risk_level="medium",
        risk_score=42.0,
        file_hash_sha256="b" * 64,
        findings=(SimpleNamespace(title="Suspicious macro"),),
        score_breakdown={},
        extra={"analysis_status": "complete"},
    )

    class FakeEngine:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def analyze_file(self, path: str):
            assert Path(path).read_bytes() == b"document"
            return fake_result

    monkeypatch.setattr(analyzer_module, "AnalyzerEngine", FakeEngine)
    adapter = DirectModaAnalyzer(timeout_seconds=2, max_attachment_bytes=100)
    try:
        result = adapter.analyze("sample.docm", "application/msword", b"document")
    finally:
        adapter.close()
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == 42
    assert result.reasons == ("Suspicious macro",)


def test_quarantine_crud_and_id_validation(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "quarantine")
    from moda.gateway.models import MessageResult

    quarantine_id = store.save(
        b"Subject: test\r\n\r\nbody",
        mail_from="sender@example.test",
        recipients=["recipient@example.test"],
        result=MessageResult("test", Verdict.SUSPICIOUS),
    )
    assert store.get(quarantine_id)
    assert store.list_records()[0]["quarantine_id"] == quarantine_id
    assert store.eml_path(quarantine_id)
    assert store.delete(quarantine_id)
    assert not store.delete(quarantine_id)
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")


def test_smtp_relay_preserves_envelope_and_raw_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[tuple[str, list[str], bytes]] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float):
            assert (host, port, timeout) == ("mailpit", 1025, 3)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def sendmail(self, sender: str, recipients: list[str], raw: bytes):
            sent.append((sender, recipients, raw))
            return {}

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    SmtpRelay("mailpit", 1025, timeout=3).deliver(
        b"raw-message", "sender@example.test", ["recipient@example.test"]
    )
    assert sent == [("sender@example.test", ["recipient@example.test"], b"raw-message")]


class DummyController:
    def __init__(self):
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


class DummyServer:
    def __init__(self):
        self.shutdown_called = False

    def serve_forever(self) -> None:
        return

    def shutdown(self) -> None:
        self.shutdown_called = True

    def server_close(self) -> None:
        return


def test_gateway_application_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    controller = DummyController()
    health_server = DummyServer()
    admin_server = DummyServer()
    monkeypatch.setattr(app_module, "build_smtp_controller", lambda config, processor: controller)
    monkeypatch.setattr(
        app_module,
        "build_health_server",
        lambda host, port, processor, status: health_server,
    )
    monkeypatch.setattr(
        app_module,
        "build_admin_server",
        lambda host, port, processor: admin_server,
    )
    application = GatewayApplication(GatewayConfig(quarantine_path=tmp_path / "quarantine"))
    application.start()
    assert controller.started
    assert application.smtp_running
    application.stop()
    assert controller.stopped
    assert health_server.shutdown_called
    assert admin_server.shutdown_called


def test_gateway_admin_refuses_non_loopback_outside_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(app_module, "_running_in_container", lambda: False)
    monkeypatch.setattr(
        app_module,
        "build_smtp_controller",
        lambda config, processor: DummyController(),
    )
    application = GatewayApplication(
        GatewayConfig(
            web_ui_host="0.0.0.0",  # noqa: S104 - verifies rejection of unsafe bind
            quarantine_path=tmp_path / "quarantine",
        )
    )
    with pytest.raises(ValueError, match="only permits"):
        application.start()
