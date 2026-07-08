"""Data models for MODA analysis results.

This module defines the immutable data containers used to represent
analysis findings, indicators of compromise, and YARA matches.
All models use ``dataclasses`` with ``frozen=True`` for thread-safety
and predictable hashing behaviour.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from moda.core.enums import FindingSeverity, IOCType


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Finding:
    """A single actionable finding produced by an analyzer.

    Attributes:
        title: Short, human-readable title (e.g. "Macro Detected").
        description: Detailed explanation of what was found.
        severity: How severe/suspicious this finding is.
        analyzer: Fully-qualified name of the analyzer that produced it.
        details: Arbitrary structured data supporting the finding.
        finding_id: Unique identifier (auto-generated UUID4).
        timestamp: When the finding was created (UTC).
    """

    title: str
    description: str
    severity: FindingSeverity
    analyzer: str
    details: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a plain dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name.lower(),
            "analyzer": self.analyzer,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class IOC:
    """An Indicator of Compromise extracted from document content.

    Attributes:
        ioc_type: Category of the IOC (URL, IP, etc.).
        value: The raw IOC string (URL, domain, IP, etc.).
        source: Which analyzer/stage extracted this IOC.
        context: Surrounding text or metadata giving provenance.
        confidence: Confidence score in range [0.0, 1.0].
        defanged: Whether the original value was defanged notation.
    """

    ioc_type: IOCType
    value: str
    source: str
    context: str = ""
    confidence: float = 0.5
    defanged: bool = False

    def __hash__(self) -> int:
        return hash((self.ioc_type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IOC):
            return NotImplemented
        return (
            self.ioc_type == other.ioc_type
            and self.value.lower() == other.value.lower()
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the IOC to a plain dictionary."""
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "source": self.source,
            "context": self.context,
            "confidence": self.confidence,
            "defanged": self.defanged,
        }


# ---------------------------------------------------------------------------
# YaraMatch
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class YaraMatch:
    """A single YARA rule match against file content.

    Attributes:
        rule_name: Name of the matching YARA rule.
        rule_namespace: Namespace/file the rule came from.
        tags: Tags attached to the YARA rule.
        meta: Metadata dictionary from the rule definition.
        strings_matched: List of (offset, identifier, data) tuples.
        match_hash: Deterministic hash for deduplication.
    """

    rule_name: str
    rule_namespace: str = "default"
    tags: tuple[str, ...] = field(default_factory=tuple)
    meta: dict[str, Any] = field(default_factory=dict)
    strings_matched: tuple[tuple[int, str, bytes], ...] = field(
        default_factory=tuple,
    )
    match_hash: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        # Compute a deterministic hash if not provided.
        if not self.match_hash:
            raw = f"{self.rule_namespace}:{self.rule_name}"
            digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
            # frozen dataclass → must use object.__setattr__
            object.__setattr__(self, "match_hash", digest)

    @property
    def severity_hint(self) -> FindingSeverity:
        """Derive a severity from rule metadata if available."""
        sev_raw = self.meta.get("severity", "medium")
        try:
            return FindingSeverity[str(sev_raw).upper()]
        except KeyError:
            return FindingSeverity.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        """Serialize the match to a plain dictionary."""
        return {
            "rule_name": self.rule_name,
            "rule_namespace": self.rule_namespace,
            "tags": list(self.tags),
            "meta": self.meta,
            "strings_matched_count": len(self.strings_matched),
            "match_hash": self.match_hash,
        }


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Immutable snapshot of a completed analysis.

    This is the primary data container consumed by reporters.  It is
    typically constructed from a mutable :class:`AnalysisContext` after
    all analyzers have executed.

    Attributes:
        file_name: Original file name.
        file_path: Absolute path to the analysed file.
        file_size: File size in bytes.
        file_type: Detected :class:`FileType` string value.
        mime_type: MIME type string.
        file_hash_md5: MD5 hex digest.
        file_hash_sha1: SHA-1 hex digest.
        file_hash_sha256: SHA-256 hex digest.
        metadata: Extracted document metadata.
        findings: Ordered list of findings.
        iocs: Deduplicated IOCs.
        yara_matches: YARA rule matches.
        macro_code: Extracted VBA / macro source code blocks.
        risk_level: Final risk level string.
        risk_score: Numeric risk score (0–100).
        score_breakdown: Per-category scoring details.
        recommendations: List of security recommendations.
        analysis_timestamp: When the analysis was performed (UTC).
        analysis_duration: Wall-clock seconds the analysis took.
        moda_version: Version of MODA that produced the result.
        extra: Free-form extension data.
    """

    file_name: str
    file_path: str
    file_size: int
    file_type: str = "unknown"
    mime_type: str = "application/octet-stream"

    # Hashes
    file_hash_md5: str = ""
    file_hash_sha1: str = ""
    file_hash_sha256: str = ""

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    # Findings & IOCs
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    iocs: tuple[IOC, ...] = field(default_factory=tuple)
    yara_matches: tuple[YaraMatch, ...] = field(default_factory=tuple)

    # Macro code
    macro_code: tuple[str, ...] = field(default_factory=tuple)

    # Risk
    risk_level: str = "clean"
    risk_score: float = 0.0
    score_breakdown: dict[str, Any] = field(default_factory=dict)

    # Recommendations
    recommendations: tuple[str, ...] = field(default_factory=tuple)

    # Meta
    analysis_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    analysis_duration: float = 0.0
    moda_version: str = "0.1.0"

    # Extra
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_context(
        cls,
        ctx: Any,  # AnalysisContext (avoid circular import)
        *,
        duration: float = 0.0,
        recommendations: tuple[str, ...] | list[str] = (),
    ) -> "AnalysisResult":
        """Build an immutable result snapshot from a mutable AnalysisContext."""
        import hashlib as _hl

        md5 = _hl.md5(ctx.file_bytes).hexdigest()
        sha1 = _hl.sha1(ctx.file_bytes).hexdigest()

        extra = dict(ctx.extra)
        extra["errors"] = list(ctx.errors)

        return cls(
            file_name=ctx.file_path.name,
            file_path=str(ctx.file_path),
            file_size=len(ctx.file_bytes),
            file_type=ctx.file_type.value,
            mime_type=ctx.mime_type,
            file_hash_md5=ctx.hashes.get("MD5", md5),
            file_hash_sha1=ctx.hashes.get("SHA1", sha1),
            file_hash_sha256=ctx.hashes.get("SHA256", ctx.file_hash),
            metadata=dict(ctx.metadata),
            findings=tuple(ctx.findings),
            iocs=tuple(ctx.iocs),
            yara_matches=tuple(ctx.yara_matches),
            macro_code=tuple(ctx.macro_code),
            risk_level=ctx.risk_level.name.lower(),
            risk_score=ctx.risk_score,
            score_breakdown=dict(ctx.score_breakdown),
            recommendations=tuple(recommendations),
            analysis_duration=duration,
            extra=extra,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity value."""
        groups: dict[str, list[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity.name.lower(), []).append(f)
        return groups

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.name.lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.name.lower() == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.name.lower() == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.name.lower() == "low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.name.lower() == "info")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Produce a fully JSON-serializable dictionary."""
        return {
            "file_info": {
                "file_name": self.file_name,
                "file_path": self.file_path,
                "file_size": self.file_size,
                "file_type": self.file_type,
                "mime_type": self.mime_type,
            },
            "hashes": {
                "md5": self.file_hash_md5,
                "sha1": self.file_hash_sha1,
                "sha256": self.file_hash_sha256,
            },
            "metadata": self.metadata,
            "risk": {
                "level": self.risk_level,
                "score": self.risk_score,
                "breakdown": self.score_breakdown,
            },
            "findings": [f.to_dict() for f in self.findings],
            "iocs": [i.to_dict() for i in self.iocs],
            "yara_matches": [m.to_dict() for m in self.yara_matches],
            "macro_code": list(self.macro_code),
            "recommendations": list(self.recommendations),
            "extra": self.extra,
            "analysis": {
                "timestamp": self.analysis_timestamp.isoformat(),
                "duration_seconds": self.analysis_duration,
                "moda_version": self.moda_version,
            },
            "errors": list(self.extra.get("errors", ())),
        }
