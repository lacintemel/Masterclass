"""Minimal JSON logging without message or attachment content."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


def configure_gateway_logging() -> logging.Logger:
    logger = logging.getLogger("moda.gateway")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **{key: value for key, value in fields.items() if value is not None},
    }
    logger.info(json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str))
