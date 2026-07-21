from __future__ import annotations

import io
from importlib import import_module
from typing import Any

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import extract_strings

try:
    PdfReader: Any = import_module("pypdf").PdfReader
except ImportError:  # pragma: no cover - optional analyzer dependency
    PdfReader = None


class PDFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "PDFAnalyzer"

    @property
    def description(self) -> str:
        return "Analyzes PDF files."

    def can_run(self, context: AnalysisContext) -> bool:
        return context.file_type == FileType.PDF

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
        context.raw_strings.extend(
            extract_strings(
                data,
                min_length=5,
                max_strings=context.limits.max_extracted_strings,
                max_string_length=context.limits.max_string_length,
            )
        )

        structurally_parsed = self._inspect_pdf_structure(context)
        if not structurally_parsed:
            self._inspect_raw_keywords(context, data)

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

    def _inspect_pdf_structure(self, context: AnalysisContext) -> bool:
        if PdfReader is None or len(context.file_bytes) > context.limits.max_archive_entry_bytes:
            context.extra["pdf_analysis_mode"] = "raw_fallback"
            return False
        try:
            reader = PdfReader(io.BytesIO(context.file_bytes), strict=False)
            if reader.is_encrypted:
                self._add_finding(
                    context,
                    title="Encrypted PDF",
                    description="PDF content is encrypted; structural static analysis may be incomplete.",
                    severity=FindingSeverity.MEDIUM,
                )
                context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
                context.extra["pdf_analysis_mode"] = "encrypted"
                return True

            found: dict[str, int] = {}
            visited: set[tuple[int, int] | int] = set()
            self._walk_pdf_object(reader.trailer, found, visited, depth=0)
            for page in reader.pages:
                self._walk_pdf_object(page, found, visited, depth=0)

            for keyword, count in sorted(found.items()):
                encoded = keyword.encode("ascii")
                title, severity = self.SUSPICIOUS_KEYWORDS[encoded]
                self._add_finding(
                    context,
                    title=title,
                    description=f"PDF structure contains {count} {keyword} action or object reference(s).",
                    severity=severity,
                    details={"keyword": keyword, "count": count, "source": "parsed_object_graph"},
                )
            context.extra["pdf_analysis_mode"] = "structural"
            return True
        except Exception as exc:
            context.errors.append(f"PDF structural parsing unavailable; raw fallback used: {exc}")
            context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
            context.extra["pdf_analysis_mode"] = "raw_fallback"
            return False

    def _walk_pdf_object(
        self,
        value: object,
        found: dict[str, int],
        visited: set[tuple[int, int] | int],
        *,
        depth: int,
    ) -> None:
        if depth > 20 or len(visited) >= 10_000:
            return
        indirect_id = getattr(value, "idnum", None)
        generation = getattr(value, "generation", 0)
        key: tuple[int, int] | int = (
            (int(indirect_id), int(generation)) if indirect_id is not None else id(value)
        )
        if key in visited:
            return
        visited.add(key)

        get_object = getattr(value, "get_object", None)
        if callable(get_object):
            resolved = get_object()
            if resolved is not value:
                self._walk_pdf_object(resolved, found, visited, depth=depth + 1)
                return
        if isinstance(value, dict):
            for raw_key, child in value.items():
                name = str(raw_key)
                encoded = name.encode("ascii", errors="ignore")
                if encoded in self.SUSPICIOUS_KEYWORDS:
                    found[name] = found.get(name, 0) + 1
                self._walk_pdf_object(child, found, visited, depth=depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._walk_pdf_object(child, found, visited, depth=depth + 1)

    def _inspect_raw_keywords(self, context: AnalysisContext, data: bytes) -> None:

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
