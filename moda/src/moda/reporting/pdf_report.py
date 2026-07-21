from __future__ import annotations

import json
import math
import unicodedata
from datetime import datetime
from typing import Any

from ..core.models import AnalysisResult, Finding, IOC, YaraMatch
from .base import BaseReporter


class _PDFDocument:
    """Small A4 PDF drawing helper with automatic pagination.

    MODA intentionally keeps PDF generation self-contained.  This helper uses
    the PDF built-in fonts and emits uncompressed content streams so reports do
    not require a browser, office suite, or optional rendering dependency.
    """

    width = 595.0
    height = 842.0
    margin = 42.0
    content_width = width - (2 * margin)
    bottom = 48.0

    ink = (0.11, 0.12, 0.14)
    muted = (0.36, 0.39, 0.43)
    line_color = (0.82, 0.84, 0.86)
    panel = (0.96, 0.97, 0.98)
    accent = (0.12, 0.39, 0.49)
    critical = (0.70, 0.16, 0.13)
    high = (0.82, 0.31, 0.20)
    medium = (0.82, 0.55, 0.12)
    low = (0.20, 0.52, 0.37)

    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self.page: list[str] = []
        self.y = 0.0
        self.new_page()

    def new_page(self) -> None:
        self.page = []
        self.pages.append(self.page)
        self.y = self.height - self.margin
        if len(self.pages) > 1:
            self._text("MODA / STATIC ANALYSIS REPORT", self.margin, self.y, 8, "bold", self.accent)
            self._line(self.margin, self.y - 9, self.width - self.margin, self.y - 9, self.line_color)
            self.y -= 30

    def ensure_space(self, required: float) -> None:
        if self.y - required < self.bottom:
            self.new_page()

    def spacer(self, amount: float = 8) -> None:
        self.ensure_space(amount)
        self.y -= amount

    def title(self, text: str, subtitle: str | None = None) -> None:
        self.ensure_space(76)
        self._rect(self.margin, self.y - 43, 7, 54, self.accent, fill=True)
        title_size = self._fit(text, self.content_width - 20, 24, "bold", minimum=14)
        self._text(text, self.margin + 20, self.y - 1, title_size, "bold", self.ink)
        if subtitle:
            self._wrapped_text(
                subtitle,
                self.margin + 20,
                self.y - 24,
                self.content_width - 20,
                10,
                "regular",
                self.muted,
                14,
            )
        self.y -= 70

    def section(self, title: str, description: str | None = None) -> None:
        self.ensure_space(58 if description else 36)
        self.spacer(8)
        self._rect(self.margin, self.y - 2, 4, 18, self.accent, fill=True)
        self._text(title.upper(), self.margin + 12, self.y, 13, "bold", self.ink)
        self.y -= 21
        if description:
            self.paragraph(description, size=8.5, color=self.muted, leading=12)
        self._line(self.margin, self.y, self.width - self.margin, self.y, self.line_color)
        self.y -= 11

    def paragraph(
        self,
        text: str,
        *,
        size: float = 9.5,
        color: tuple[float, float, float] | None = None,
        leading: float = 14,
        font: str = "regular",
        indent: float = 0,
    ) -> None:
        lines = self._wrap(text, self.content_width - indent, size, font)
        for line in lines or [""]:
            self.ensure_space(leading)
            self._text(line, self.margin + indent, self.y, size, font, color or self.ink)
            self.y -= leading

    def label(self, text: str) -> None:
        self.ensure_space(16)
        self._text(text.upper(), self.margin, self.y, 7.5, "bold", self.accent)
        self.y -= 13

    def key_value(self, key: str, value: object, *, mono: bool = False) -> None:
        label_width = 116.0
        value_x = self.margin + label_width
        value_width = self.content_width - label_width
        value_text = self._display(value)
        lines = self._wrap(value_text, value_width, 8.5, "mono" if mono else "regular") or [""]
        row_height = max(20.0, (len(lines) * 11.0) + 7)
        self.ensure_space(row_height)
        self._rect(self.margin, self.y - row_height + 5, self.content_width, row_height, self.panel, fill=True)
        self._text(key, self.margin + 8, self.y - 8, 8, "bold", self.muted)
        line_y = self.y - 8
        for line in lines:
            self._text(line, value_x, line_y, 8.5, "mono" if mono else "regular", self.ink)
            line_y -= 11
        self.y -= row_height + 2

    def metric_row(self, metrics: list[tuple[str, str]], color: tuple[float, float, float]) -> None:
        self.ensure_space(72)
        gap = 8.0
        card_width = (self.content_width - (gap * (len(metrics) - 1))) / max(len(metrics), 1)
        for index, (label, value) in enumerate(metrics):
            x = self.margin + index * (card_width + gap)
            self._rect(x, self.y - 56, card_width, 56, self.panel, fill=True)
            self._rect(x, self.y - 56, 4, 56, color, fill=True)
            self._text(label.upper(), x + 12, self.y - 17, 7, "bold", self.muted)
            fitted = self._fit(value, card_width - 22, 17, "bold", minimum=9)
            self._text(value, x + 12, self.y - 41, fitted, "bold", self.ink)
        self.y -= 68

    def bullet(self, text: str, *, color: tuple[float, float, float] | None = None) -> None:
        lines = self._wrap(text, self.content_width - 19, 9, "regular") or [""]
        for index, line in enumerate(lines):
            self.ensure_space(13)
            if index == 0:
                self._rect(self.margin + 2, self.y + 2, 5, 5, color or self.accent, fill=True)
            self._text(line, self.margin + 18, self.y, 9, "regular", self.ink)
            self.y -= 13
        self.y -= 2

    def finding(self, number: int, finding: Finding, explanation: str, evidence: list[str]) -> None:
        severity = finding.severity.name.lower()
        color = self.severity_color(severity)
        self.ensure_space(78)
        self._rect(self.margin, self.y - 20, 58, 20, color, fill=True)
        self._text(severity.upper(), self.margin + 8, self.y - 14, 8, "bold", (1, 1, 1))
        self._text(f"{number:02d}  {finding.title}", self.margin + 70, self.y - 14, 11, "bold", self.ink)
        self.y -= 32
        self._text(f"SOURCE  {finding.analyzer}", self.margin, self.y, 7, "bold", self.muted)
        self.y -= 14
        self._text("ANALYST INTERPRETATION", self.margin, self.y, 7, "bold", self.accent)
        self.y -= 13
        self.paragraph(explanation, size=9, leading=13)
        if evidence:
            self._text("RECORDED EVIDENCE", self.margin, self.y, 7, "bold", self.accent)
            self.y -= 13
            for item in evidence:
                self.bullet(item, color=color)
        self._text(f"Finding ID: {finding.finding_id}", self.margin, self.y, 6.8, "mono", self.muted)
        self.y -= 13
        self._line(self.margin, self.y, self.width - self.margin, self.y, self.line_color)
        self.y -= 13

    def component(self, label: str, points: float, description: str, reasons: list[str]) -> None:
        self.ensure_space(60)
        self._text(label, self.margin, self.y, 9, "bold", self.ink)
        self._text(f"{points:g} / 100", self.width - self.margin - 62, self.y, 8, "bold", self.muted)
        self.y -= 11
        bar_width = self.content_width
        self._rect(self.margin, self.y - 5, bar_width, 6, self.line_color, fill=True)
        self._rect(self.margin, self.y - 5, bar_width * min(max(points, 0), 100) / 100, 6, self.accent, fill=True)
        self.y -= 14
        if description:
            self.paragraph(description, size=8, leading=11, color=self.muted)
        if reasons:
            self.paragraph("Evidence: " + ", ".join(reasons), size=8, leading=11)
        self.y -= 5

    def code_block(self, title: str, lines: list[str], omitted: int = 0) -> None:
        self.ensure_space(48)
        self._text(title, self.margin, self.y, 9, "bold", self.ink)
        self.y -= 16
        for line_number, line in enumerate(lines, start=1):
            wrapped = self._wrap(line, self.content_width - 42, 7.2, "mono") or [""]
            for index, part in enumerate(wrapped):
                self.ensure_space(10)
                if index == 0:
                    self._text(f"{line_number:>4}", self.margin, self.y, 7, "mono", self.muted)
                self._text(part, self.margin + 38, self.y, 7.2, "mono", self.ink)
                self.y -= 10
        if omitted:
            self.paragraph(f"[{omitted} additional source lines omitted from the PDF appendix.]", size=8, color=self.muted)
        self.y -= 8

    def severity_color(self, severity: str) -> tuple[float, float, float]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.accent,
        }.get(severity, self.accent)

    def build(self) -> bytes:
        page_count = len(self.pages)
        page_start = 3
        normal_font_id = page_start + page_count
        bold_font_id = normal_font_id + 1
        mono_font_id = normal_font_id + 2
        content_start = mono_font_id + 1

        objects: list[bytes] = []
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        kids = " ".join(f"{page_start + index} 0 R" for index in range(page_count))
        objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode("ascii"))

        for index in range(page_count):
            content_id = content_start + index
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width:g} {self.height:g}] "
                    f"/Resources << /Font << /F1 {normal_font_id} 0 R /F2 {bold_font_id} 0 R "
                    f"/F3 {mono_font_id} 0 R >> >> /Contents {content_id} 0 R >>"
                ).encode("ascii")
            )

        objects.extend(
            [
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
            ]
        )

        for index, commands in enumerate(self.pages, start=1):
            stream_commands = list(commands)
            stream_commands.extend(self._footer(index, page_count))
            content = "\n".join(stream_commands).encode("cp1252", errors="replace")
            objects.append(
                b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream"
            )

        pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for object_id, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{object_id} 0 obj\n".encode("ascii"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_start = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        pdf.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_start}\n%%EOF\n"
            ).encode("ascii")
        )
        return bytes(pdf)

    def _footer(self, page_number: int, page_count: int) -> list[str]:
        y = 25
        return [
            self._line_command(self.margin, y + 12, self.width - self.margin, y + 12, self.line_color),
            self._text_command("MODA  |  Static analysis only - no document content was executed", self.margin, y, 6.8, "regular", self.muted),
            self._text_command(f"PAGE {page_number} / {page_count}", self.width - self.margin - 48, y, 6.8, "bold", self.muted),
        ]

    def _wrapped_text(
        self,
        text: str,
        x: float,
        y: float,
        width: float,
        size: float,
        font: str,
        color: tuple[float, float, float],
        leading: float,
    ) -> None:
        for line in self._wrap(text, width, size, font):
            self._text(line, x, y, size, font, color)
            y -= leading

    def _wrap(self, text: object, width: float, size: float, font: str) -> list[str]:
        safe = self._safe_text(self._display(text))
        if not safe:
            return []
        lines: list[str] = []
        for paragraph in safe.replace("\t", "    ").splitlines() or [""]:
            if not paragraph:
                lines.append("")
                continue
            current = ""
            for word in paragraph.split(" "):
                candidate = word if not current else f"{current} {word}"
                if self._text_width(candidate, size, font) <= width:
                    current = candidate
                    continue
                if current:
                    lines.append(current)
                    current = ""
                while self._text_width(word, size, font) > width and len(word) > 1:
                    ratio = width / max(self._text_width(word, size, font), 1)
                    split_at = max(1, int(len(word) * ratio) - 1)
                    lines.append(word[:split_at])
                    word = word[split_at:]
                current = word
            if current:
                lines.append(current)
        return lines

    def _fit(self, text: str, width: float, size: float, font: str, minimum: float) -> float:
        fitted = size
        while fitted > minimum and self._text_width(text, fitted, font) > width:
            fitted -= 0.5
        return fitted

    def _text_width(self, text: str, size: float, font: str) -> float:
        factor = 0.60 if font == "mono" else 0.54 if font == "bold" else 0.50
        return len(self._safe_text(text)) * size * factor

    def _text(
        self,
        text: str,
        x: float,
        y: float,
        size: float,
        font: str = "regular",
        color: tuple[float, float, float] | None = None,
    ) -> None:
        self.page.append(self._text_command(text, x, y, size, font, color or self.ink))

    def _text_command(
        self,
        text: str,
        x: float,
        y: float,
        size: float,
        font: str,
        color: tuple[float, float, float],
    ) -> str:
        font_name = {"regular": "F1", "bold": "F2", "mono": "F3"}.get(font, "F1")
        r, g, b = color
        escaped = self._escape(self._safe_text(text))
        return f"BT /{font_name} {size:g} Tf {r:g} {g:g} {b:g} rg 1 0 0 1 {x:g} {y:g} Tm ({escaped}) Tj ET"

    def _line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float],
    ) -> None:
        self.page.append(self._line_command(x1, y1, x2, y2, color))

    def _line_command(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float],
    ) -> str:
        r, g, b = color
        return f"q {r:g} {g:g} {b:g} RG 0.7 w {x1:g} {y1:g} m {x2:g} {y2:g} l S Q"

    def _rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        color: tuple[float, float, float],
        *,
        fill: bool,
    ) -> None:
        r, g, b = color
        operator = "f" if fill else "S"
        paint = "rg" if fill else "RG"
        self.page.append(f"q {r:g} {g:g} {b:g} {paint} {x:g} {y:g} {width:g} {height:g} re {operator} Q")

    def _display(self, value: object) -> str:
        if value is None:
            return "Not available"
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, float):
            return f"{value:.2f}".rstrip("0").rstrip(".")
        return str(value)

    def _safe_text(self, text: str) -> str:
        replacements = str.maketrans(
            {
                "\u2013": "-",
                "\u2014": "-",
                "\u2018": "'",
                "\u2019": "'",
                "\u201c": '"',
                "\u201d": '"',
                "\u2026": "...",
                "\u2022": "-",
                "\u011e": "G",
                "\u011f": "g",
                "\u0130": "I",
                "\u0131": "i",
                "\u015e": "S",
                "\u015f": "s",
            }
        )
        normalized = unicodedata.normalize("NFKD", str(text).translate(replacements))
        safe = "".join(char for char in normalized if not unicodedata.combining(char))
        return safe.encode("cp1252", errors="replace").decode("cp1252")

    def _escape(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class PDFReporter(BaseReporter):
    """Render a detailed, analyst-oriented, multi-page PDF report."""

    format_name = "pdf"
    file_extension = ".pdf"

    _MAX_IOCS = 500
    _MAX_YARA_MATCHES = 200
    _MAX_TECHNICAL_ROWS = 300
    _MAX_MACRO_LINES = 400

    def generate(self, result: AnalysisResult) -> bytes:
        document = _PDFDocument()
        self._render_cover(document, result)
        document.new_page()
        self._render_file_identity(document, result)
        self._render_risk_assessment(document, result)
        self._render_findings(document, result)
        self._render_iocs(document, result)
        self._render_yara(document, result)
        self._render_metadata(document, result)
        self._render_macro_code(document, result)
        self._render_technical_evidence(document, result)
        self._render_limitations(document, result)
        return document.build()

    def _render_cover(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.label("MODA / Malicious Office Document Analyzer")
        document.spacer(14)
        document.title(result.file_name, "Comprehensive static document analysis report")
        document.metric_row(
            [
                ("Risk level", result.risk_level.upper()),
                ("Risk score", f"{result.risk_score:g}/100"),
                ("Findings", str(len(result.findings))),
                ("Indicators", str(len(result.iocs))),
            ],
            document.severity_color(result.risk_level.lower()),
        )
        document.section("Executive Summary")
        document.paragraph(self._executive_summary(result), size=10.5, leading=16)

        top_findings = sorted(result.findings, key=lambda finding: finding.severity, reverse=True)[:5]
        if top_findings:
            document.label("Priority observations")
            for finding in top_findings:
                document.bullet(
                    f"{finding.severity.name}: {finding.title} - {finding.description}",
                    color=document.severity_color(finding.severity.name.lower()),
                )
        else:
            document.label("Priority observations")
            document.paragraph(
                "The configured static checks did not produce a suspicious finding. This does not prove that the file is safe; it records only what this analysis could observe.",
                color=document.muted,
            )

        document.spacer(6)
        document.label("Report context")
        document.key_value("Generated", self._format_timestamp(result.analysis_timestamp))
        document.key_value("Analysis duration", f"{result.analysis_duration:.3f} seconds")
        document.key_value("MODA version", result.moda_version)

    def _render_file_identity(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "File Identity",
            "Identity fields and cryptographic hashes make the analyzed artifact traceable across reports and security systems.",
        )
        document.key_value("File name", result.file_name)
        document.key_value("Reported path", result.file_path)
        document.key_value("Detected type", result.file_type)
        document.key_value("MIME type", result.mime_type)
        document.key_value("Size", self._format_size(result.file_size))
        document.key_value("MD5", result.file_hash_md5 or "Not calculated", mono=True)
        document.key_value("SHA-1", result.file_hash_sha1 or "Not calculated", mono=True)
        document.key_value("SHA-256", result.file_hash_sha256 or "Not calculated", mono=True)

    def _render_risk_assessment(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Risk Assessment",
            "The risk score is calculated by MODA's deterministic rules. Narrative text explains the recorded evidence and does not alter the score.",
        )
        summary = str(result.score_breakdown.get("risk_summary") or self._risk_narrative(result))
        document.paragraph(summary, size=10, leading=15)

        components = result.score_breakdown.get("components", [])
        if isinstance(components, list) and components:
            document.label("Score contributors")
            for component in components:
                if not isinstance(component, dict):
                    continue
                reasons = component.get("reasons", [])
                document.component(
                    str(component.get("label", "Risk component")),
                    self._number(component.get("points")),
                    str(component.get("description", "")),
                    [str(item) for item in reasons] if isinstance(reasons, list) else [],
                )
        else:
            document.paragraph("No score-contributing component was recorded.", color=document.muted)

        self._render_list_section(
            document,
            "Potential impact",
            result.score_breakdown.get("potential_impacts", []),
            "No concrete impact path was identified by the static analysis.",
        )
        self._render_list_section(
            document,
            "Response and recovery",
            result.score_breakdown.get("recovery_steps", []),
            "Keep the file quarantined until the findings have been reviewed.",
        )
        self._render_list_section(
            document,
            "Recommendations",
            list(result.recommendations),
            "No additional recommendation was recorded.",
        )

    def _render_findings(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Detailed Findings",
            "Each entry preserves the analyzer output and adds a plain-language interpretation grounded in the recorded evidence.",
        )
        if not result.findings:
            document.paragraph("No findings were produced by the configured analyzers.", color=document.muted)
            return
        findings = sorted(result.findings, key=lambda finding: finding.severity, reverse=True)
        for number, finding in enumerate(findings, start=1):
            document.finding(
                number,
                finding,
                self._finding_explanation(finding),
                self._finding_evidence(finding),
            )

    def _render_iocs(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Indicators of Compromise",
            "Indicators are investigation pivots extracted from the document. Their presence alone is not proof of malicious activity.",
        )
        if not result.iocs:
            document.paragraph("No indicators of compromise were extracted.", color=document.muted)
            return
        for index, ioc in enumerate(result.iocs[: self._MAX_IOCS], start=1):
            document.ensure_space(62)
            document.label(f"Indicator {index:03d} / {ioc.ioc_type.value}")
            document.key_value("Value", ioc.value, mono=True)
            document.key_value("Source", ioc.source)
            document.key_value("Confidence", f"{ioc.confidence:.0%}")
            if ioc.context:
                document.key_value("Context", ioc.context)
            document.paragraph(self._ioc_explanation(ioc), size=8.5, color=document.muted, leading=12)
            document.spacer(5)
        omitted = len(result.iocs) - self._MAX_IOCS
        if omitted > 0:
            document.paragraph(f"{omitted} additional indicators were omitted to keep the PDF bounded.", color=document.muted)

    def _render_yara(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "YARA Matches",
            "A YARA match means that byte or string patterns defined by a rule were observed. It should be correlated with the rule metadata and other findings.",
        )
        if not result.yara_matches:
            document.paragraph("No YARA rules matched, or YARA scanning was unavailable or disabled.", color=document.muted)
            return
        for index, match in enumerate(result.yara_matches[: self._MAX_YARA_MATCHES], start=1):
            self._render_yara_match(document, index, match)
        omitted = len(result.yara_matches) - self._MAX_YARA_MATCHES
        if omitted > 0:
            document.paragraph(f"{omitted} additional YARA matches were omitted from the PDF.", color=document.muted)

    def _render_yara_match(self, document: _PDFDocument, index: int, match: YaraMatch) -> None:
        document.ensure_space(76)
        document.label(f"YARA match {index:03d}")
        document.key_value("Rule", match.rule_name, mono=True)
        document.key_value("Namespace", match.rule_namespace)
        document.key_value("Severity hint", match.severity_hint.name)
        document.key_value("Matched strings", len(match.strings_matched))
        if match.tags:
            document.key_value("Tags", ", ".join(match.tags))
        for key, value in self._flatten(match.meta, max_rows=20):
            document.key_value(f"Meta / {key}", value)
        document.paragraph(
            "Analyst interpretation: this signature match supports triage, but the rule logic and surrounding findings should be reviewed before assigning a final verdict.",
            size=8.5,
            color=document.muted,
            leading=12,
        )
        document.spacer(6)

    def _render_metadata(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Document Metadata",
            "Metadata describes document provenance and editing history. These values can be missing, forged, or altered and should not be treated as identity proof.",
        )
        if not result.metadata:
            document.paragraph("No document metadata was extracted.", color=document.muted)
            return
        for key, value in self._flatten(result.metadata, max_rows=100):
            document.key_value(key, value)

    def _render_macro_code(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Macro Code Appendix",
            "Extracted macro text is evidence only. MODA did not execute the code. Long source listings are bounded to keep the report usable.",
        )
        if not result.macro_code:
            document.paragraph("No extractable macro source code was recorded.", color=document.muted)
            return

        remaining = self._MAX_MACRO_LINES
        for module_index, source in enumerate(result.macro_code, start=1):
            source_lines = str(source).splitlines() or [str(source)]
            visible = source_lines[:remaining]
            if not visible:
                break
            remaining -= len(visible)
            module_omitted = max(0, len(source_lines) - len(visible))
            document.code_block(f"Macro module / block {module_index}", visible, module_omitted)
            if remaining <= 0:
                break

        total_lines = sum(len(str(source).splitlines() or [str(source)]) for source in result.macro_code)
        if total_lines > self._MAX_MACRO_LINES:
            document.paragraph(
                f"The appendix shows the first {self._MAX_MACRO_LINES} of {total_lines} extracted source lines. The complete macro_code value remains available in the JSON result.",
                color=document.muted,
            )

    def _render_technical_evidence(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            "Technical Evidence",
            "Analyzer-specific structured output is included here for reproducibility and deeper manual review.",
        )
        extra = {key: value for key, value in result.extra.items() if key != "errors"}
        if not extra:
            document.paragraph("No additional analyzer-specific evidence was recorded.", color=document.muted)
            return
        rows = self._flatten(extra, max_rows=self._MAX_TECHNICAL_ROWS)
        for key, value in rows:
            document.key_value(key, value, mono=self._looks_technical(value))
        if len(rows) >= self._MAX_TECHNICAL_ROWS:
            document.paragraph(
                "The technical evidence appendix reached its PDF row limit. The complete structured output remains available in JSON.",
                color=document.muted,
            )

    def _render_limitations(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section("Analysis Notes and Limitations")
        errors = result.extra.get("errors", [])
        if isinstance(errors, list) and errors:
            document.label("Non-fatal analysis errors")
            for error in errors:
                document.bullet(str(error), color=document.high)
        else:
            document.paragraph("No non-fatal analyzer errors were recorded.", color=document.muted)

        document.label("Interpretation boundary")
        for note in (
            "This report describes static evidence and does not certify that a file is safe or malicious.",
            "MODA did not open, render, or execute the submitted document, macros, scripts, or embedded payloads.",
            "A low score can still require manual review when the source is untrusted or the file type is unsupported.",
            "IOC reputation and behavioral impact should be validated with current threat intelligence, endpoint telemetry, or an isolated sandbox.",
        ):
            document.bullet(note)

    def _render_list_section(
        self,
        document: _PDFDocument,
        title: str,
        values: object,
        fallback: str,
    ) -> None:
        document.label(title)
        items = values if isinstance(values, (list, tuple)) else []
        if items:
            for item in items:
                document.bullet(str(item))
        else:
            document.paragraph(fallback, color=document.muted)
        document.spacer(4)

    def _executive_summary(self, result: AnalysisResult) -> str:
        counts = {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        }
        severity_text = ", ".join(f"{count} {name}" for name, count in counts.items() if count)
        if not severity_text:
            severity_text = "no severity-rated findings"
        narrative = self._risk_narrative(result)
        return (
            f"MODA completed a non-executing static analysis of {result.file_name}. "
            f"The deterministic engine assigned a {result.risk_level.upper()} risk level with a score of "
            f"{result.risk_score:g}/100 and recorded {severity_text}. {narrative} "
            f"The analysis extracted {len(result.iocs)} indicator(s) and {len(result.yara_matches)} YARA match(es)."
        )

    def _risk_narrative(self, result: AnalysisResult) -> str:
        narratives = {
            "critical": "The recorded evidence includes indicators associated with code execution, exploitation, or payload loading. The file should remain quarantined.",
            "high": "The analysis found strong suspicious-document behavior. The file should not be opened on a normal workstation.",
            "medium": "The file contains suspicious traits that require analyst review before it can be released or trusted.",
            "low": "The configured checks did not identify high-risk static behavior, but static analysis cannot prove that the file is benign.",
            "clean": "No suspicious static behavior was recorded, but the result remains limited to the checks that were available and enabled.",
        }
        return narratives.get(result.risk_level.lower(), "The result should be interpreted together with the detailed evidence below.")

    def _finding_explanation(self, finding: Finding) -> str:
        lowered = f"{finding.title} {finding.description} {finding.analyzer}".lower()
        why = "This characteristic can increase document risk and should be reviewed together with the recorded evidence and surrounding findings."
        patterns = [
            (("unsupported file",), "The file is outside MODA's supported document scope, so the result is inconclusive rather than clean."),
            (("auto-execution", "auto execution"), "An automatic entry point can activate macro behavior when a document event occurs, reducing the amount of explicit user action required."),
            (("process execution", "powershell", "cmd.exe", "shell"), "Process-launch capability can allow a document to start operating-system tools or scripts outside the document application."),
            (("download", "xmlhttp", "winhttp"), "Downloader-related behavior can retrieve a second-stage payload or remote script after delivery."),
            (("obfuscat", "encoded"), "Obfuscation makes manual inspection harder and can conceal commands, URLs, or payload material from simple scanners."),
            (("native api", "virtualalloc", "writeprocessmemory"), "Native memory and process APIs are frequently associated with in-memory loaders and code-injection techniques."),
            (("remote", "external relationship", "template"), "External relationships can cause a document to retrieve content from another location and change behavior after delivery."),
            (("embedded", "activex", "objectpool", "ole object", "package"), "Embedded content can hide secondary files, active controls, or payloads inside an otherwise ordinary-looking document."),
            (("pdf", "javascript", "openaction", "launch action"), "Active PDF actions can run script or launch behavior when the document is opened or interacted with."),
            (("rtf", "equation", "exploit"), "RTF objects and legacy component markers may expose exploit paths in vulnerable document-processing software."),
            (("macro", "vba"), "Macro code can automate legitimate tasks, but it can also execute commands, modify files, or retrieve remote content when enabled."),
            (("dde",), "Dynamic Data Exchange can invoke external applications or commands through document fields and links."),
            (("yara",), "A signature matched content in the file. The rule metadata and other findings should be reviewed before treating the match as a verdict."),
        ]
        for tokens, explanation in patterns:
            if any(token in lowered for token in tokens):
                why = explanation
                break
        return (
            f"MODA reported: {finding.description} This item was classified as {finding.severity.name.lower()} severity. "
            f"Why it matters: {why}"
        )

    def _finding_evidence(self, finding: Finding) -> list[str]:
        if not finding.details:
            return ["The analyzer recorded the finding without additional structured detail."]
        return [f"{key}: {value}" for key, value in self._flatten(finding.details, max_rows=30)]

    def _ioc_explanation(self, ioc: IOC) -> str:
        ioc_type = ioc.ioc_type.value.lower()
        if "url" in ioc_type or "domain" in ioc_type:
            meaning = "This network destination can be searched in proxy, DNS, email, and endpoint telemetry."
        elif "ip" in ioc_type:
            meaning = "This address can be correlated with network connections, DNS resolutions, and threat-intelligence records."
        elif "hash" in ioc_type:
            meaning = "This hash can identify matching files without relying on their names."
        elif "path" in ioc_type or "file" in ioc_type:
            meaning = "This path or filename can be used to search endpoint and file-system telemetry."
        elif "command" in ioc_type:
            meaning = "This command text can be searched in process-creation, script, and command-line telemetry."
        else:
            meaning = "This value can be used as a pivot during threat hunting and manual review."
        defanged = " The value was originally recorded in defanged notation." if ioc.defanged else ""
        return f"Analyst interpretation: {meaning}{defanged} Validate context and reputation before blocking."

    def _flatten(
        self,
        value: Any,
        prefix: str = "",
        *,
        max_rows: int,
        depth: int = 0,
    ) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []

        def visit(current: Any, path: str, level: int) -> None:
            if len(rows) >= max_rows:
                return
            if level >= 4:
                rows.append((path or "value", self._compact(current)))
                return
            if isinstance(current, dict):
                if not current:
                    rows.append((path or "value", "{}"))
                for key, item in current.items():
                    child = f"{path} / {key}" if path else str(key)
                    visit(item, child, level + 1)
                return
            if isinstance(current, (list, tuple, set)):
                sequence = list(current)
                if not sequence:
                    rows.append((path or "value", "[]"))
                for index, item in enumerate(sequence):
                    child = f"{path} [{index + 1}]" if path else f"item {index + 1}"
                    visit(item, child, level + 1)
                return
            rows.append((path or "value", self._compact(current)))

        visit(value, prefix, depth)
        return rows

    def _compact(self, value: Any, limit: int = 800) -> str:
        if isinstance(value, bytes):
            text = value.hex()
        elif isinstance(value, (dict, list, tuple, set)):
            try:
                text = json.dumps(value, sort_keys=True, default=str)
            except (TypeError, ValueError):
                text = str(value)
        else:
            text = str(value)
        text = " ".join(text.split())
        return text if len(text) <= limit else text[: limit - 24] + " ... [value truncated]"

    def _looks_technical(self, value: str) -> bool:
        return any(token in value.lower() for token in ("http://", "https://", "\\", "sha", "0x"))

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} bytes"
        units = ["KB", "MB", "GB"]
        value = float(size)
        for unit in units:
            value /= 1024
            if value < 1024 or unit == units[-1]:
                return f"{value:.2f} {unit} ({size:,} bytes)"
        return f"{size:,} bytes"

    def _format_timestamp(self, value: datetime) -> str:
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    def _number(self, value: object) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        return number if math.isfinite(number) else 0.0
