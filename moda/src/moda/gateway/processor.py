"""Policy engine for SMTP messages."""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any

from .analyzer import AttachmentAnalyzer, DirectModaAnalyzer, SimulatedAnalyzer
from .config import GatewayConfig
from .errors import AnalyzerScanError, MessageLimitError, MessageParseError, RelayError
from .logging import configure_gateway_logging, log_event
from .mime import parse_message
from .models import AttachmentResult, GatewayStats, MessageResult, SmtpOutcome, Verdict
from .quarantine import QuarantineStore
from .relay import MailRelay, SmtpRelay


class GatewayProcessor:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        analyzer: AttachmentAnalyzer | None = None,
        relay: MailRelay | None = None,
        quarantine: QuarantineStore | None = None,
    ):
        self.config = config
        self.analyzer = analyzer or self._default_analyzer()
        self.relay = relay or SmtpRelay(config.relay_host, config.relay_port)
        self.quarantine = quarantine or QuarantineStore(config.quarantine_path)
        self.stats = GatewayStats()
        self._stats_lock = threading.Lock()
        self.logger = configure_gateway_logging()

    def recipient_allowed(self, recipient: str) -> bool:
        address = parseaddr(recipient)[1]
        if "@" not in address:
            return False
        domain = address.rsplit("@", 1)[1].lower().rstrip(".")
        return domain in self.config.accepted_recipient_domains

    def process(self, raw_message: bytes, mail_from: str, recipients: list[str]) -> SmtpOutcome:
        message_id = uuid.uuid4().hex
        started = time.monotonic()
        recipient_domains = sorted(
            {
                parseaddr(item)[1].rsplit("@", 1)[-1].lower()
                for item in recipients
                if "@" in parseaddr(item)[1]
            }
        )
        log_event(
            self.logger,
            "message_received",
            message_id=message_id,
            sender=mail_from,
            recipient_domains=recipient_domains,
            message_size=len(raw_message),
        )
        if not recipients or any(not self.recipient_allowed(item) for item in recipients):
            log_event(
                self.logger,
                "invalid_recipient",
                message_id=message_id,
                recipient_domains=recipient_domains,
            )
            return SmtpOutcome(550, "5.7.1", "Relaying denied")
        if len(raw_message) > self.config.max_message_bytes:
            return SmtpOutcome(552, "5.3.4", "Message exceeds fixed maximum message size")

        try:
            result = self._analyze_message(raw_message)
        except MessageLimitError as exc:
            log_event(self.logger, "analysis_failed", message_id=message_id, error=str(exc))
            self._record_error(message_id, mail_from, "limit_exceeded", started)
            return SmtpOutcome(552, "5.3.4", str(exc))
        except (AnalyzerScanError, MessageParseError) as exc:
            log_event(self.logger, "analysis_failed", message_id=message_id, error=str(exc))
            self._record_error(message_id, mail_from, "analysis_failed", started)
            return SmtpOutcome(
                451,
                "4.7.0",
                "Temporary scanning failure; please retry later",
            )

        if result.verdict is Verdict.SAFE:
            try:
                self.relay.deliver(raw_message, mail_from, recipients)
            except RelayError as exc:
                log_event(self.logger, "relay_failed", message_id=message_id, error=str(exc))
                self._record_recent(message_id, mail_from, "relay_failed", result, started)
                return SmtpOutcome(451, "4.4.1", "Downstream mail server unavailable", result)
            log_event(
                self.logger,
                "message_delivered",
                message_id=message_id,
                verdict=result.verdict.value,
                attachment_count=len(result.attachments),
                duration_ms=_duration_ms(started),
            )
            self._record_recent(message_id, mail_from, "delivered", result, started)
            return SmtpOutcome(250, "2.0.0", "Message accepted for delivery", result)

        try:
            quarantine_id = self.quarantine.save(
                raw_message,
                mail_from=mail_from,
                recipients=recipients,
                result=result,
            )
        except OSError as exc:
            log_event(self.logger, "analysis_failed", message_id=message_id, error=str(exc))
            self._record_error(message_id, mail_from, "quarantine_failed", started)
            return SmtpOutcome(
                451,
                "4.7.0",
                "Temporary scanning failure; please retry later",
                result,
            )

        if result.verdict is Verdict.SUSPICIOUS:
            event = "message_quarantined"
            outcome = SmtpOutcome(
                250,
                "2.0.0",
                "Message accepted into quarantine",
                result,
                quarantine_id,
            )
        else:
            event = "message_rejected"
            outcome = SmtpOutcome(
                550,
                "5.7.1",
                "Message rejected by security policy",
                result,
                quarantine_id,
            )
        log_event(
            self.logger,
            event,
            message_id=message_id,
            verdict=result.verdict.value,
            attachment_count=len(result.attachments),
            quarantine_id=quarantine_id,
            duration_ms=_duration_ms(started),
        )
        self._record_recent(message_id, mail_from, event, result, started, quarantine_id)
        return outcome

    def health(self, *, smtp_running: bool) -> dict[str, Any]:
        import socket

        try:
            with socket.create_connection(
                (self.config.relay_host, self.config.relay_port), timeout=1.0
            ):
                relay_ready = True
        except OSError:
            relay_ready = False
        analyzer_ready = self.analyzer.healthy
        return {
            "status": (
                "healthy" if smtp_running and analyzer_ready and relay_ready else "degraded"
            ),
            "smtp": smtp_running,
            "analyzer": analyzer_ready,
            "relay": relay_ready,
        }

    def close(self) -> None:
        self.analyzer.close()

    def _analyze_message(self, raw_message: bytes) -> MessageResult:
        parsed = parse_message(raw_message, self.config)
        results: list[AttachmentResult] = []
        for attachment in parsed.attachments:
            if attachment.is_office:
                results.append(
                    self.analyzer.analyze(
                        attachment.filename,
                        attachment.content_type,
                        attachment.content,
                    )
                )
            else:
                results.append(
                    AttachmentResult(
                        filename=attachment.filename,
                        content_type=attachment.content_type,
                        size=attachment.size,
                        sha256=attachment.sha256,
                        verdict=Verdict.SAFE,
                        score=0.0,
                        reasons=("Outside the Office attachment analysis scope",),
                        analysis_status="not_applicable",
                    )
                )
        verdict = max(
            (item.verdict for item in results if item.analysis_status != "not_applicable"),
            key=lambda item: item.priority,
            default=Verdict.SAFE,
        )
        return MessageResult(parsed.subject, verdict, tuple(results))

    def _default_analyzer(self) -> AttachmentAnalyzer:
        if self.config.simulate_analyzer:
            return SimulatedAnalyzer()
        return DirectModaAnalyzer(
            timeout_seconds=self.config.analyzer_timeout_seconds,
            max_attachment_bytes=self.config.max_attachment_bytes,
            skip_yara=self.config.skip_yara,
        )

    def _record_error(self, message_id: str, sender: str, event: str, started: float) -> None:
        with self._stats_lock:
            self.stats.analyzer_errors += 1
        self._record_recent(message_id, sender, event, None, started)

    def _record_recent(
        self,
        message_id: str,
        sender: str,
        event: str,
        result: MessageResult | None,
        started: float,
        quarantine_id: str | None = None,
    ) -> None:
        item = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_id": message_id,
            "sender": sender,
            "event": event,
            "verdict": result.verdict.value if result else "error",
            "attachment_count": len(result.attachments) if result else 0,
            "duration_ms": _duration_ms(started),
            "quarantine_id": quarantine_id,
        }
        with self._stats_lock:
            self.stats.total += 1
            if result:
                if result.verdict is Verdict.SAFE:
                    self.stats.safe += 1
                elif result.verdict is Verdict.SUSPICIOUS:
                    self.stats.suspicious += 1
                else:
                    self.stats.malicious += 1
            self.stats.recent.insert(0, item)
            del self.stats.recent[50:]


def _duration_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)
