"""Downstream SMTP relay client."""

from __future__ import annotations

import smtplib
from typing import Protocol

from .errors import RelayError


class MailRelay(Protocol):
    def deliver(self, raw_message: bytes, mail_from: str, recipients: list[str]) -> None: ...


class SmtpRelay:
    def __init__(self, host: str, port: int, *, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def deliver(self, raw_message: bytes, mail_from: str, recipients: list[str]) -> None:
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as client:
                refused = client.sendmail(mail_from, recipients, raw_message)
        except (OSError, smtplib.SMTPException) as exc:
            raise RelayError("Downstream mail server unavailable") from exc
        if refused:
            raise RelayError("Downstream mail server refused one or more recipients")
