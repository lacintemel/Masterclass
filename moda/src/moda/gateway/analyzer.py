"""Adapters between mail attachments and MODA analysis results."""

from __future__ import annotations

import math
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Protocol

from moda.core.engine import AnalyzerEngine

from .errors import AnalyzerScanError
from .models import AttachmentResult, Verdict


class AttachmentAnalyzer(Protocol):
    def analyze(self, filename: str, content_type: str, content: bytes) -> AttachmentResult: ...

    def close(self) -> None: ...

    @property
    def healthy(self) -> bool: ...


def normalize_verdict(value: str) -> Verdict:
    normalized = value.strip().lower()
    aliases = {
        "safe": Verdict.SAFE,
        "clean": Verdict.SAFE,
        "benign": Verdict.SAFE,
        "suspicious": Verdict.SUSPICIOUS,
        "unknown": Verdict.SUSPICIOUS,
        "malicious": Verdict.MALICIOUS,
        "dangerous": Verdict.MALICIOUS,
        "infected": Verdict.MALICIOUS,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise AnalyzerScanError(f"Unknown analyzer verdict: {value!r}") from exc


class SimulatedAnalyzer:
    """Harmless deterministic analyzer used by the local SMTP demo."""

    def __init__(self) -> None:
        self.closed = False

    @property
    def healthy(self) -> bool:
        return not self.closed

    def analyze(self, filename: str, content_type: str, content: bytes) -> AttachmentResult:
        if self.closed:
            raise AnalyzerScanError("Analyzer is closed")
        lowered_name = filename.lower()
        if "malicious" in lowered_name or b"MDOA_TEST_MALICIOUS" in content:
            verdict = Verdict.MALICIOUS
            score = 95.0
            reasons = ("Safe simulation marker for a malicious verdict",)
        elif "suspicious" in lowered_name:
            verdict = Verdict.SUSPICIOUS
            score = 50.0
            reasons = ("Safe simulation filename for a suspicious verdict",)
        else:
            verdict = Verdict.SAFE
            score = 0.0
            reasons = ("No simulated threat marker was present",)
        return AttachmentResult(
            filename=filename,
            content_type=content_type,
            size=len(content),
            sha256=_sha256(content),
            verdict=verdict,
            score=score,
            reasons=reasons,
        )

    def close(self) -> None:
        self.closed = True


class DirectModaAnalyzer:
    """Run the existing MODA engine in-process with a hard caller timeout."""

    def __init__(
        self,
        *,
        timeout_seconds: int,
        max_attachment_bytes: int,
        skip_yara: bool = False,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_attachment_bytes = max_attachment_bytes
        self.skip_yara = skip_yara
        self.closed = False
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="moda-scan")

    @property
    def healthy(self) -> bool:
        return not self.closed

    def analyze(self, filename: str, content_type: str, content: bytes) -> AttachmentResult:
        if self.closed:
            raise AnalyzerScanError("Analyzer is closed")
        if len(content) > self.max_attachment_bytes:
            raise AnalyzerScanError("Attachment exceeds analyzer size limit")
        future = self._executor.submit(self._analyze_bytes, filename, content_type, content)
        try:
            return future.result(timeout=self.timeout_seconds)
        except TimeoutError as exc:
            future.cancel()
            raise AnalyzerScanError("Analyzer timed out") from exc
        except AnalyzerScanError:
            raise
        except Exception as exc:
            raise AnalyzerScanError("Analyzer failed while scanning the attachment") from exc

    def _analyze_bytes(self, filename: str, content_type: str, content: bytes) -> AttachmentResult:
        suffix = Path(filename).suffix.lower()
        if len(suffix) > 12 or not suffix.replace(".", "").isalnum():
            suffix = ".bin"
        fd, temp_name = tempfile.mkstemp(prefix="moda-mail-", suffix=suffix)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
            max_size_mb = max(1, math.ceil(self.max_attachment_bytes / (1024 * 1024)))
            result = AnalyzerEngine(
                skip_yara=self.skip_yara,
                max_file_size_mb=max_size_mb,
            ).analyze_file(temp_name)
            verdict = _result_verdict(result.risk_level, result.extra.get("analysis_status"))
            reasons = tuple(finding.title for finding in result.findings[:10])
            if not reasons:
                reasons = (str(result.score_breakdown.get("risk_summary", "No findings")),)
            return AttachmentResult(
                filename=filename,
                content_type=content_type,
                size=len(content),
                sha256=result.file_hash_sha256 or _sha256(content),
                verdict=verdict,
                score=float(result.risk_score),
                reasons=reasons,
                analysis_status=str(result.extra.get("analysis_status", "complete")),
            )
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def close(self) -> None:
        self.closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)


def _result_verdict(risk_level: str, analysis_status: object) -> Verdict:
    risk = risk_level.lower()
    if risk in {"high", "critical"}:
        return Verdict.MALICIOUS
    if risk == "medium" or analysis_status != "complete":
        return Verdict.SUSPICIOUS
    if risk == "low":
        return Verdict.SAFE
    return normalize_verdict(risk)


def _sha256(content: bytes) -> str:
    import hashlib

    return hashlib.sha256(content).hexdigest()
