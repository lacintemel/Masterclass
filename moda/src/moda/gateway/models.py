"""Data contracts shared by the SMTP gateway components."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def priority(self) -> int:
        return {
            Verdict.SAFE: 0,
            Verdict.SUSPICIOUS: 1,
            Verdict.MALICIOUS: 2,
        }[self]


@dataclass(frozen=True, slots=True)
class AttachmentResult:
    filename: str
    content_type: str
    size: int
    sha256: str
    verdict: Verdict
    score: float
    reasons: tuple[str, ...] = ()
    analysis_status: str = "complete"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["verdict"] = self.verdict.value
        result["reasons"] = list(self.reasons)
        return result


@dataclass(frozen=True, slots=True)
class MessageResult:
    subject: str
    verdict: Verdict
    attachments: tuple[AttachmentResult, ...] = ()

    @property
    def max_score(self) -> float:
        return max((item.score for item in self.attachments), default=0.0)


@dataclass(frozen=True, slots=True)
class SmtpOutcome:
    code: int
    enhanced_status: str
    message: str
    result: MessageResult | None = None
    quarantine_id: str | None = None

    @property
    def response(self) -> str:
        return f"{self.code} {self.enhanced_status} {self.message}"


@dataclass(slots=True)
class GatewayStats:
    total: int = 0
    safe: int = 0
    suspicious: int = 0
    malicious: int = 0
    analyzer_errors: int = 0
    recent: list[dict[str, Any]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "safe": self.safe,
            "suspicious": self.suspicious,
            "malicious": self.malicious,
            "analyzer_errors": self.analyzer_errors,
            "recent": list(self.recent),
        }
