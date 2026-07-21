"""Local SMTP security gateway for MODA."""

from .config import GatewayConfig
from .models import AttachmentResult, MessageResult, SmtpOutcome, Verdict
from .processor import GatewayProcessor

__all__ = [
    "AttachmentResult",
    "GatewayConfig",
    "GatewayProcessor",
    "MessageResult",
    "SmtpOutcome",
    "Verdict",
]
