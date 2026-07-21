"""aiosmtpd integration for the gateway policy processor."""

from __future__ import annotations

import uuid
from email.utils import parseaddr
from typing import Any

from aiosmtpd.controller import Controller

from .config import GatewayConfig
from .logging import log_event
from .processor import GatewayProcessor


class GatewaySmtpHandler:
    def __init__(self, processor: GatewayProcessor):
        self.processor = processor

    async def handle_RCPT(  # noqa: N802 - aiosmtpd hook name
        self,
        server: Any,
        session: Any,
        envelope: Any,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        del server, session, rcpt_options
        if not self.processor.recipient_allowed(address):
            parsed_address = parseaddr(address)[1]
            recipient_domain = (
                parsed_address.rsplit("@", 1)[1].lower() if "@" in parsed_address else "invalid"
            )
            log_event(
                self.processor.logger,
                "invalid_recipient",
                message_id=uuid.uuid4().hex,
                sender=str(envelope.mail_from),
                recipient_domain=recipient_domain,
            )
            return "550 5.7.1 Relaying denied"
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 Recipient OK"

    async def handle_DATA(  # noqa: N802 - aiosmtpd hook name
        self,
        server: Any,
        session: Any,
        envelope: Any,
    ) -> str:
        del server, session
        raw_message = envelope.original_content
        if not isinstance(raw_message, bytes):
            return "451 4.7.0 Temporary scanning failure; please retry later"
        outcome = self.processor.process(
            raw_message,
            str(envelope.mail_from),
            [str(recipient) for recipient in envelope.rcpt_tos],
        )
        return outcome.response


def build_smtp_controller(config: GatewayConfig, processor: GatewayProcessor) -> Controller:
    return Controller(
        GatewaySmtpHandler(processor),
        hostname=config.smtp_listen_host,
        port=config.smtp_listen_port,
        data_size_limit=config.max_message_bytes,
        enable_SMTPUTF8=True,
        decode_data=False,
    )
