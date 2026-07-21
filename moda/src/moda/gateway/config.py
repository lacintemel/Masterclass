"""Environment-backed gateway configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    value = default if raw is None else int(raw)
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    smtp_listen_host: str = "127.0.0.1"
    smtp_listen_port: int = 2525
    relay_host: str = "127.0.0.1"
    relay_port: int = 1025
    health_host: str = "127.0.0.1"
    health_port: int = 8080
    web_ui_host: str = "127.0.0.1"
    web_ui_port: int = 8081
    simulate_analyzer: bool = True
    analyzer_timeout_seconds: int = 30
    max_message_bytes: int = 25 * 1024 * 1024
    max_attachment_bytes: int = 20 * 1024 * 1024
    max_attachments: int = 20
    accepted_recipient_domains: tuple[str, ...] = ("example.test",)
    quarantine_path: Path = Path("quarantine")
    skip_yara: bool = False

    @classmethod
    def from_env(cls) -> GatewayConfig:
        domains = tuple(
            sorted(
                {
                    domain.strip().lower().rstrip(".")
                    for domain in os.environ.get(
                        "ACCEPTED_RECIPIENT_DOMAINS", "example.test"
                    ).split(",")
                    if domain.strip()
                }
            )
        )
        if not domains:
            raise ValueError("ACCEPTED_RECIPIENT_DOMAINS must contain at least one domain")
        return cls(
            smtp_listen_host=os.environ.get("SMTP_LISTEN_HOST", "127.0.0.1"),
            smtp_listen_port=_env_int("SMTP_LISTEN_PORT", 2525),
            relay_host=os.environ.get("RELAY_HOST", "127.0.0.1"),
            relay_port=_env_int("RELAY_PORT", 1025),
            health_host=os.environ.get("HEALTH_HOST", "127.0.0.1"),
            health_port=_env_int("HEALTH_PORT", 8080),
            web_ui_host=os.environ.get("WEB_UI_HOST", "127.0.0.1"),
            web_ui_port=_env_int("WEB_UI_PORT", 8081),
            simulate_analyzer=_env_bool("SIMULATE_ANALYZER", True),
            analyzer_timeout_seconds=_env_int("ANALYZER_TIMEOUT_SECONDS", 30),
            max_message_bytes=_env_int("MAX_MESSAGE_BYTES", 25 * 1024 * 1024),
            max_attachment_bytes=_env_int("MAX_ATTACHMENT_BYTES", 20 * 1024 * 1024),
            max_attachments=_env_int("MAX_ATTACHMENTS", 20),
            accepted_recipient_domains=domains,
            quarantine_path=Path(os.environ.get("QUARANTINE_PATH", "quarantine")).resolve(),
            skip_yara=_env_bool("SKIP_YARA", False),
        )
