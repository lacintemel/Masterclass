from __future__ import annotations

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import extract_strings

class PDFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "PDFAnalyzer"
    @property
    def description(self) -> str: return "Analyzes PDF files."
    def can_run(self, context: AnalysisContext) -> bool: return context.file_type == FileType.PDF

    SUSPICIOUS_KEYWORDS = {
        b"/JavaScript": ("PDF JavaScript", FindingSeverity.HIGH),
        b"/JS": ("PDF JavaScript Shortcut", FindingSeverity.HIGH),
        b"/OpenAction": ("PDF OpenAction", FindingSeverity.HIGH),
        b"/AA": ("PDF Additional Actions", FindingSeverity.MEDIUM),
        b"/Launch": ("PDF Launch Action", FindingSeverity.CRITICAL),
        b"/EmbeddedFile": ("PDF Embedded File", FindingSeverity.HIGH),
        b"/URI": ("PDF URI Action", FindingSeverity.MEDIUM),
        b"/AcroForm": ("PDF Interactive Form", FindingSeverity.LOW),
        b"/XFA": ("PDF XFA Form", FindingSeverity.MEDIUM),
        b"/ObjStm": ("PDF Object Streams", FindingSeverity.LOW),
    }

    def analyze(self, context: AnalysisContext) -> None:
        data = context.file_bytes
        context.raw_strings.extend(extract_strings(data, min_length=5))

        for keyword, (title, severity) in self.SUSPICIOUS_KEYWORDS.items():
            count = data.count(keyword)
            if count:
                self._add_finding(
                    context,
                    title=title,
                    description=f"PDF contains {count} occurrence(s) of {keyword.decode()}",
                    severity=severity,
                    details={"keyword": keyword.decode(), "count": count},
                )

        if data.count(b" obj") > 500:
            self._add_finding(
                context,
                title="Large PDF Object Count",
                description="PDF contains an unusually high number of objects.",
                severity=FindingSeverity.LOW,
                details={"object_markers": data.count(b" obj")},
            )

        eof_count = data.count(b"%%EOF")
        if eof_count > 1:
            self._add_finding(
                context,
                title="Multiple PDF EOF Markers",
                description="PDF contains multiple EOF markers, which can indicate appended content.",
                severity=FindingSeverity.LOW,
                details={"eof_markers": eof_count},
            )
