"""Analysis context — the shared data bus for MODA analyzers.

``AnalysisContext`` acts as the single communication channel between all
analyzers in the pipeline.  Each analyzer reads from *and* writes to the
context rather than passing data directly to other analyzers, enforcing
loose coupling and deterministic ordering.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

from moda.core.enums import FileType, RiskLevel
from moda.core.limits import AnalysisLimits
from moda.core.models import AnalysisResult, Finding, IOC, YaraMatch
from moda.utils.file_utils import extract_strings

logger = logging.getLogger(__name__)


class AnalysisContext:
    """Shared state container threaded through every analyzer.

    Attributes:
        file_path: Absolute path to the file under analysis.
        file_bytes: Raw bytes of the file (read once, shared by all).
        file_type: Detected file type.
        file_hash: SHA-256 hex digest of ``file_bytes``.
        metadata: Dictionary of document metadata (author, dates, …).
        findings: Ordered list of findings from all analyzers.
        iocs: Set of deduplicated IOCs.
        yara_matches: List of YARA rule matches.
        macro_code: Extracted VBA / macro source code.
        embedded_strings: Raw strings extracted from the binary.
        raw_strings: Additional decoded/extracted strings.
        risk_level: Final computed risk level.
        risk_score: Numeric risk score (0–100).
        score_breakdown: Per-category scoring details.
        extra: Free-form bag for analyzer-specific data.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        file_path: str | Path,
        file_bytes: bytes,
        limits: AnalysisLimits | None = None,
    ) -> None:
        # File identity
        self.file_path: Path = Path(file_path).resolve()
        self.file_bytes: bytes = file_bytes
        self.file_size: int = len(file_bytes)
        self.extension: str = self.file_path.suffix.lower().lstrip(".")
        self.mime_type: str = "application/octet-stream"
        self.file_type: FileType = FileType.UNKNOWN
        self.file_hash: str = hashlib.sha256(file_bytes).hexdigest()
        self.hashes: dict[str, str] = {"SHA256": self.file_hash}
        self.limits = limits or AnalysisLimits()

        # Metadata & textual content
        self.metadata: dict[str, Any] = {}
        self.macro_code: list[str] = []
        self.embedded_strings: list[str] = []
        self.raw_strings: list[str] = []

        # Results
        self.findings: list[Finding] = []
        self.iocs: set[IOC] = set()
        self.yara_matches: list[YaraMatch] = []

        # Scoring
        self.risk_level: RiskLevel = RiskLevel.LOW
        self.risk_score: float = 0.0
        self.score_breakdown: dict[str, Any] = {}

        # Timing
        self.analysis_start: float = time.time()
        self.analysis_end: float | None = None

        # Errors encountered during analysis (non-fatal)
        self.errors: list[str] = []

        # Free-form extension point
        self.extra: dict[str, Any] = {}

        logger.debug(
            "AnalysisContext created for %s (%d bytes, SHA-256=%s)",
            self.file_path.name,
            len(file_bytes),
            self.file_hash[:16],
        )

    # ------------------------------------------------------------------
    # Convenience mutators
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Append a finding to the results list."""
        self.findings.append(finding)
        logger.debug("Finding added: [%s] %s", finding.severity.value, finding.title)

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC (set-based deduplication by type+value)."""
        self.iocs.add(ioc)

    def add_yara_match(self, match: YaraMatch) -> None:
        """Record a YARA match."""
        self.yara_matches.append(match)
        logger.debug("YARA match: %s::%s", match.rule_namespace, match.rule_name)

    def set_risk(
        self,
        score: float,
        risk_level: RiskLevel,
        breakdown: dict[str, Any] | None = None,
    ) -> None:
        """Set the final risk assessment for this analysis."""
        self.risk_score = score
        self.risk_level = risk_level
        if breakdown is not None:
            self.score_breakdown = breakdown

    # ------------------------------------------------------------------
    # Convenience queries
    # ------------------------------------------------------------------

    def has_macros(self) -> bool:
        """Return True if any macro code was extracted."""
        return bool(self.macro_code)

    def max_severity(self) -> str:
        """Return the string value of the highest finding severity."""
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: f.severity).severity.name.lower()

    def get_findings_by_severity(
        self,
        severity: str,
    ) -> list[Finding]:
        """Filter findings to those matching the given severity string."""
        return [f for f in self.findings if f.severity.name.lower() == severity.lower()]

    def get_all_text(self) -> str:
        """Aggregate text-like analysis artifacts for IOC extraction."""
        parts: list[str] = []
        parts.extend(str(value) for value in self.metadata.values() if value is not None)
        parts.extend(self.macro_code)
        parts.extend(self.embedded_strings)
        parts.extend(self.raw_strings)
        for finding in self.findings:
            parts.append(finding.title)
            parts.append(finding.description)
            parts.extend(str(value) for value in finding.details.values())

        if not self.raw_strings:
            self.raw_strings = extract_strings(
                self.file_bytes,
                max_strings=self.limits.max_extracted_strings,
                max_string_length=self.limits.max_string_length,
            )
        if not parts or parts[-len(self.raw_strings):] != self.raw_strings:
            parts.extend(self.raw_strings)
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Produce a JSON-serializable summary of the analysis."""
        return {
            "file_path": str(self.file_path),
            "file_hash": self.file_hash,
            "file_type": self.file_type.value,
            "mime_type": self.mime_type,
            "risk_level": self.risk_level.name.lower(),
            "risk_score": self.risk_score,
            "score_breakdown": self.score_breakdown,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "iocs_count": len(self.iocs),
            "iocs": [i.to_dict() for i in self.iocs],
            "yara_matches_count": len(self.yara_matches),
            "yara_matches": [m.to_dict() for m in self.yara_matches],
            "errors": list(self.errors),
        }

    def to_result(self) -> AnalysisResult:
        """Freeze the mutable context into an AnalysisResult."""
        duration = 0.0
        if self.analysis_end is not None:
            duration = self.analysis_end - self.analysis_start
        return AnalysisResult.from_context(
            self,
            duration=duration,
            recommendations=self._build_recommendations(),
        )

    def _build_recommendations(self) -> tuple[str, ...]:
        """Generate concise analyst guidance from the final risk level."""
        if self.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return (
                "Do not open the document on a workstation.",
                "Review findings and extracted IOCs in a sandboxed analysis workflow.",
                "Hunt for extracted hashes, URLs, and IP addresses in telemetry.",
            )
        if self.risk_level is RiskLevel.MEDIUM:
            return (
                "Manually review suspicious findings before releasing the document.",
                "Correlate extracted IOCs with mail and endpoint telemetry.",
            )
        return ("No high-risk indicators were detected by the configured static checks.",)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AnalysisContext file={self.file_path.name!r} "
            f"type={self.file_type.value} "
            f"findings={len(self.findings)} "
            f"risk={self.risk_level.value}>"
        )
