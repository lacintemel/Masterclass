from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Any

from ..core.models import IOC, AnalysisResult, Finding, YaraMatch
from .base import BaseReporter
from .view_model import build_report_view


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

    def __init__(self, language: str = "en") -> None:
        self.language = "tr" if language == "tr" else "en"
        self.pages: list[list[str]] = []
        self.page: list[str] = []
        self.y = 0.0
        self.new_page()

    def new_page(self) -> None:
        self.page = []
        self.pages.append(self.page)
        self.y = self.height - self.margin
        if len(self.pages) > 1:
            self._text(
                self._l("MODA / STATIC ANALYSIS REPORT", "MODA / STATİK ANALİZ RAPORU"),
                self.margin,
                self.y,
                8,
                "bold",
                self.accent,
            )
            self._line(
                self.margin, self.y - 9, self.width - self.margin, self.y - 9, self.line_color
            )
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
        self._text(self._upper(title), self.margin + 12, self.y, 13, "bold", self.ink)
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
        self._text(self._upper(text), self.margin, self.y, 7.5, "bold", self.accent)
        self.y -= 13

    def key_value(self, key: str, value: object, *, mono: bool = False) -> None:
        label_width = 116.0
        value_x = self.margin + label_width
        value_width = self.content_width - label_width
        value_text = self._display(value)
        lines = self._wrap(value_text, value_width, 8.5, "mono" if mono else "regular") or [""]
        row_height = max(20.0, (len(lines) * 11.0) + 7)
        self.ensure_space(row_height)
        self._rect(
            self.margin,
            self.y - row_height + 5,
            self.content_width,
            row_height,
            self.panel,
            fill=True,
        )
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
            self._text(self._upper(label), x + 12, self.y - 17, 7, "bold", self.muted)
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

    def finding(
        self,
        number: int,
        finding: Finding,
        display_title: str,
        explanation: str,
        evidence: list[str],
    ) -> None:
        severity = finding.severity.name.lower()
        color = self.severity_color(severity)
        severity_label = {
            "critical": self._l("CRITICAL", "KRİTİK"),
            "high": self._l("HIGH", "YÜKSEK"),
            "medium": self._l("MEDIUM", "ORTA"),
            "low": self._l("LOW", "DÜŞÜK"),
            "info": self._l("INFO", "BİLGİ"),
        }.get(severity, severity.upper())
        self.ensure_space(78)
        self._rect(self.margin, self.y - 20, 58, 20, color, fill=True)
        self._text(severity_label, self.margin + 8, self.y - 14, 8, "bold", (1, 1, 1))
        self._text(
            f"{number:02d}  {display_title}", self.margin + 70, self.y - 14, 11, "bold", self.ink
        )
        self.y -= 32
        self._text(
            f"{self._l('SOURCE', 'KAYNAK')}  {finding.analyzer}",
            self.margin,
            self.y,
            7,
            "bold",
            self.muted,
        )
        self.y -= 14
        self._text(
            self._l("ANALYST INTERPRETATION", "ANALİST YORUMU"),
            self.margin,
            self.y,
            7,
            "bold",
            self.accent,
        )
        self.y -= 13
        self.paragraph(explanation, size=9, leading=13)
        if evidence:
            self._text(
                self._l("RECORDED EVIDENCE", "KAYDEDİLEN KANIT"),
                self.margin,
                self.y,
                7,
                "bold",
                self.accent,
            )
            self.y -= 13
            for item in evidence:
                self.bullet(item, color=color)
        self._text(
            f"{self._l('Finding ID', 'Bulgu kimliği')}: {finding.finding_id}",
            self.margin,
            self.y,
            6.8,
            "mono",
            self.muted,
        )
        self.y -= 13
        self._line(self.margin, self.y, self.width - self.margin, self.y, self.line_color)
        self.y -= 13

    def component(self, label: str, points: float, description: str, reasons: list[str]) -> None:
        self.ensure_space(60)
        self._text(label, self.margin, self.y, 9, "bold", self.ink)
        self._text(
            f"{points:g} / 100", self.width - self.margin - 62, self.y, 8, "bold", self.muted
        )
        self.y -= 11
        bar_width = self.content_width
        self._rect(self.margin, self.y - 5, bar_width, 6, self.line_color, fill=True)
        self._rect(
            self.margin,
            self.y - 5,
            bar_width * min(max(points, 0), 100) / 100,
            6,
            self.accent,
            fill=True,
        )
        self.y -= 14
        if description:
            self.paragraph(description, size=8, leading=11, color=self.muted)
        if reasons:
            self.paragraph(
                self._l("Evidence", "Kanıt") + ": " + ", ".join(reasons),
                size=8,
                leading=11,
            )
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
            self.paragraph(
                self._l(
                    f"[{omitted} additional source lines omitted from the PDF appendix.]",
                    f"[{omitted} ek kaynak satırı PDF ekinden çıkarıldı.]",
                ),
                size=8,
                color=self.muted,
            )
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
                self._font_object("Helvetica"),
                self._font_object("Helvetica-Bold"),
                self._font_object("Courier"),
            ]
        )

        for index, commands in enumerate(self.pages, start=1):
            stream_commands = list(commands)
            stream_commands.extend(self._footer(index, page_count))
            content = "\n".join(stream_commands).encode("cp1254", errors="replace")
            objects.append(
                b"<< /Length "
                + str(len(content)).encode("ascii")
                + b" >>\nstream\n"
                + content
                + b"\nendstream"
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
            self._line_command(
                self.margin, y + 12, self.width - self.margin, y + 12, self.line_color
            ),
            self._text_command(
                self._l(
                    "MODA  |  Static analysis only - no document content was executed",
                    "MODA  |  Yalnızca statik analiz - hiçbir belge içeriği çalıştırılmadı",
                ),
                self.margin,
                y,
                6.8,
                "regular",
                self.muted,
            ),
            self._text_command(
                f"{self._l('PAGE', 'SAYFA')} {page_number} / {page_count}",
                self.width - self.margin - 48,
                y,
                6.8,
                "bold",
                self.muted,
            ),
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
        self.page.append(
            f"q {r:g} {g:g} {b:g} {paint} {x:g} {y:g} {width:g} {height:g} re {operator} Q"
        )

    def _display(self, value: object) -> str:
        if value is None:
            return self._l("Not available", "Mevcut değil")
        if isinstance(value, bool):
            return self._l("Yes", "Evet") if value else self._l("No", "Hayır")
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
            }
        )
        return str(text).translate(replacements).encode("cp1254", errors="replace").decode("cp1254")

    def _escape(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _font_object(self, base_font: str) -> bytes:
        encoding = (
            "<< /Type /Encoding /BaseEncoding /WinAnsiEncoding "
            "/Differences [208 /Gbreve 221 /Idotaccent /Scedilla "
            "240 /gbreve 253 /dotlessi /scedilla] >>"
        )
        return (
            f"<< /Type /Font /Subtype /Type1 /BaseFont /{base_font} /Encoding {encoding} >>"
        ).encode("ascii")

    def _l(self, english: str, turkish: str) -> str:
        return turkish if self.language == "tr" else english

    def _upper(self, text: str) -> str:
        if self.language == "tr":
            replacements: dict[str, str | int | None] = {"i": "İ", "ı": "I"}
            return text.translate(str.maketrans(replacements)).upper()
        return text.upper()


class PDFReporter(BaseReporter):
    """Render a detailed, analyst-oriented, multi-page PDF report."""

    format_name = "pdf"
    file_extension = ".pdf"

    _MAX_IOCS = 500
    _MAX_YARA_MATCHES = 200
    _MAX_TECHNICAL_ROWS = 300
    _MAX_MACRO_LINES = 400

    def __init__(self, language: str = "en", **config: Any) -> None:
        super().__init__(**config)
        self.language = "tr" if language == "tr" else "en"

    def generate(self, result: AnalysisResult) -> bytes:
        document = _PDFDocument(self.language)
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
        document.label(
            self._l(
                "MODA / Malicious Office Document Analyzer",
                "MODA / Zararlı Office Belgesi Analiz Aracı",
            )
        )
        document.spacer(14)
        document.title(
            result.file_name,
            self._l(
                "Comprehensive static document analysis report",
                "Kapsamlı statik belge analiz raporu",
            ),
        )
        document.metric_row(
            [
                (self._l("Risk level", "Risk seviyesi"), self._risk_level(result.risk_level)),
                (self._l("Risk score", "Risk puanı"), f"{result.risk_score:g}/100"),
                (self._l("Findings", "Bulgular"), str(len(result.findings))),
                (self._l("Indicators", "Göstergeler"), str(len(result.iocs))),
            ],
            document.severity_color(result.risk_level.lower()),
        )
        document.section(self._l("Executive Summary", "Yönetici Özeti"))
        document.paragraph(self._executive_summary(result), size=10.5, leading=16)
        document.key_value(
            self._l("Analysis completeness", "Analiz bütünlüğü"),
            self._analysis_status(str(result.extra.get("analysis_status", "complete"))),
        )

        top_findings = sorted(result.findings, key=lambda finding: finding.severity, reverse=True)[
            :5
        ]
        if top_findings:
            document.label(self._l("Priority observations", "Öncelikli gözlemler"))
            for finding in top_findings:
                document.bullet(
                    f"{self._severity(finding.severity.name)}: "
                    f"{self._finding_title(finding.title)} - {self._finding_description(finding)}",
                    color=document.severity_color(finding.severity.name.lower()),
                )
        else:
            document.label(self._l("Priority observations", "Öncelikli gözlemler"))
            document.paragraph(
                self._l(
                    "The configured static checks did not produce a suspicious finding. This does not prove that the file is safe; it records only what this analysis could observe.",
                    "Yapılandırılmış statik kontroller şüpheli bir bulgu üretmedi. Bu durum dosyanın güvenli olduğunu kanıtlamaz; yalnızca bu analizin gözlemleyebildiklerini kaydeder.",
                ),
                color=document.muted,
            )

        document.spacer(6)
        document.label(self._l("Report context", "Rapor bilgileri"))
        document.key_value(
            self._l("Generated", "Oluşturulma zamanı"),
            self._format_timestamp(result.analysis_timestamp),
        )
        document.key_value(
            self._l("Analysis duration", "Analiz süresi"),
            self._l(
                f"{result.analysis_duration:.3f} seconds",
                f"{result.analysis_duration:.3f} saniye",
            ),
        )
        document.key_value(self._l("MODA version", "MODA sürümü"), result.moda_version)

    def _render_file_identity(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("File Identity", "Dosya Kimliği"),
            self._l(
                "Identity fields and cryptographic hashes make the analyzed artifact traceable across reports and security systems.",
                "Kimlik alanları ve kriptografik özetler, analiz edilen dosyanın raporlar ve güvenlik sistemleri arasında izlenebilmesini sağlar.",
            ),
        )
        document.key_value(self._l("File name", "Dosya adı"), result.file_name)
        document.key_value(self._l("Reported path", "Bildirilen yol"), result.file_path)
        document.key_value(self._l("Detected type", "Algılanan tür"), result.file_type)
        document.key_value("MIME", result.mime_type)
        document.key_value(self._l("Size", "Boyut"), self._format_size(result.file_size))
        not_calculated = self._l("Not calculated", "Hesaplanmadı")
        document.key_value("MD5", result.file_hash_md5 or not_calculated, mono=True)
        document.key_value("SHA-1", result.file_hash_sha1 or not_calculated, mono=True)
        document.key_value("SHA-256", result.file_hash_sha256 or not_calculated, mono=True)

    def _render_risk_assessment(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Risk Assessment", "Risk Değerlendirmesi"),
            self._l(
                "The risk score is calculated by MODA's deterministic rules. Narrative text explains the recorded evidence and does not alter the score.",
                "Risk puanı MODA'nın deterministik kurallarıyla hesaplanır. Doğal dil açıklamaları kaydedilen kanıtları yorumlar ve puanı değiştirmez.",
            ),
        )
        summary = (
            self._risk_narrative(result)
            if self.language == "tr"
            else str(result.score_breakdown.get("risk_summary") or self._risk_narrative(result))
        )
        document.paragraph(summary, size=10, leading=15)

        components = result.score_breakdown.get("components", [])
        if isinstance(components, list) and components:
            document.label(self._l("Score contributors", "Puan bileşenleri"))
            for component in components:
                if not isinstance(component, dict):
                    continue
                reasons = component.get("reasons", [])
                document.component(
                    self._component_label(component),
                    self._number(component.get("points")),
                    self._component_description(component),
                    [self._finding_title(str(item)) for item in reasons]
                    if isinstance(reasons, list)
                    else [],
                )
        else:
            document.paragraph(
                self._l(
                    "No score-contributing component was recorded.",
                    "Puana katkıda bulunan bir bileşen kaydedilmedi.",
                ),
                color=document.muted,
            )

        self._render_list_section(
            document,
            self._l("Potential impact", "Olası etkiler"),
            self._localized_list(result.score_breakdown.get("potential_impacts", [])),
            self._l(
                "No concrete impact path was identified by the static analysis.",
                "Statik analiz somut bir etki yolu belirlemedi.",
            ),
        )
        self._render_list_section(
            document,
            self._l("Response and recovery", "Müdahale ve kurtarma"),
            self._localized_list(result.score_breakdown.get("recovery_steps", [])),
            self._l(
                "Keep the file quarantined until the findings have been reviewed.",
                "Bulgular incelenene kadar dosyayı karantinada tutun.",
            ),
        )
        self._render_list_section(
            document,
            self._l("Recommendations", "Öneriler"),
            self._localized_list(list(result.recommendations)),
            self._l(
                "No additional recommendation was recorded.",
                "Ek bir öneri kaydedilmedi.",
            ),
        )

    def _render_findings(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Detailed Findings", "Ayrıntılı Bulgular"),
            self._l(
                "Each entry preserves the analyzer output and adds a plain-language interpretation grounded in the recorded evidence.",
                "Her kayıt analiz çıktısını korur ve kaydedilen kanıta dayalı, anlaşılır bir analist yorumu ekler.",
            ),
        )
        if not result.findings:
            document.paragraph(
                self._l(
                    "No findings were produced by the configured analyzers.",
                    "Yapılandırılmış analiz araçları herhangi bir bulgu üretmedi.",
                ),
                color=document.muted,
            )
            return
        findings = sorted(result.findings, key=lambda finding: finding.severity, reverse=True)
        for number, finding in enumerate(findings, start=1):
            document.finding(
                number,
                finding,
                self._finding_title(finding.title),
                self._finding_explanation(finding),
                self._finding_evidence(finding),
            )

    def _render_iocs(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Indicators of Compromise", "İhlal Göstergeleri"),
            self._l(
                "Indicators are investigation pivots extracted from the document. Their presence alone is not proof of malicious activity.",
                "Göstergeler belgeden çıkarılan inceleme başlangıç noktalarıdır. Tek başlarına bulunmaları kötü amaçlı etkinliğin kanıtı değildir.",
            ),
        )
        if not result.iocs:
            document.paragraph(
                self._l(
                    "No indicators of compromise were extracted.",
                    "Herhangi bir ihlal göstergesi çıkarılmadı.",
                ),
                color=document.muted,
            )
            return
        for index, ioc in enumerate(result.iocs[: self._MAX_IOCS], start=1):
            document.ensure_space(62)
            document.label(f"{self._l('Indicator', 'Gösterge')} {index:03d} / {ioc.ioc_type.value}")
            document.key_value(self._l("Value", "Değer"), ioc.value, mono=True)
            document.key_value(self._l("Source", "Kaynak"), ioc.source)
            document.key_value(self._l("Confidence", "Güven"), f"{ioc.confidence:.0%}")
            if ioc.context:
                document.key_value(self._l("Context", "Bağlam"), ioc.context)
            document.paragraph(
                self._ioc_explanation(ioc), size=8.5, color=document.muted, leading=12
            )
            document.spacer(5)
        omitted = len(result.iocs) - self._MAX_IOCS
        if omitted > 0:
            document.paragraph(
                self._l(
                    f"{omitted} additional indicators were omitted to keep the PDF bounded.",
                    f"PDF boyutunu sınırlamak için {omitted} ek gösterge rapora alınmadı.",
                ),
                color=document.muted,
            )

    def _render_yara(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("YARA Matches", "YARA Eşleşmeleri"),
            self._l(
                "A YARA match means that byte or string patterns defined by a rule were observed. It should be correlated with the rule metadata and other findings.",
                "YARA eşleşmesi, bir kuralda tanımlanan bayt veya metin örüntülerinin gözlemlendiğini gösterir. Kural metadatası ve diğer bulgularla birlikte değerlendirilmelidir.",
            ),
        )
        if not result.yara_matches:
            document.paragraph(
                self._l(
                    "No YARA rules matched, or YARA scanning was unavailable or disabled.",
                    "Hiçbir YARA kuralı eşleşmedi ya da YARA taraması kullanılamadı veya devre dışıydı.",
                ),
                color=document.muted,
            )
            return
        for index, match in enumerate(result.yara_matches[: self._MAX_YARA_MATCHES], start=1):
            self._render_yara_match(document, index, match)
        omitted = len(result.yara_matches) - self._MAX_YARA_MATCHES
        if omitted > 0:
            document.paragraph(
                self._l(
                    f"{omitted} additional YARA matches were omitted from the PDF.",
                    f"{omitted} ek YARA eşleşmesi PDF raporuna alınmadı.",
                ),
                color=document.muted,
            )

    def _render_yara_match(self, document: _PDFDocument, index: int, match: YaraMatch) -> None:
        document.ensure_space(76)
        document.label(f"YARA {self._l('match', 'eşleşmesi')} {index:03d}")
        document.key_value(self._l("Rule", "Kural"), match.rule_name, mono=True)
        document.key_value(self._l("Namespace", "Ad alanı"), match.rule_namespace)
        document.key_value(
            self._l("Severity hint", "Önem derecesi"),
            self._severity(match.severity_hint.name),
        )
        document.key_value(
            self._l("Matched strings", "Eşleşen metinler"),
            len(match.strings_matched),
        )
        if match.tags:
            document.key_value(self._l("Tags", "Etiketler"), ", ".join(match.tags))
        for key, value in self._flatten(match.meta, max_rows=20):
            document.key_value(f"Meta / {key}", value)
        document.paragraph(
            self._l(
                "Analyst interpretation: this signature match supports triage, but the rule logic and surrounding findings should be reviewed before assigning a final verdict.",
                "Analist yorumu: Bu imza eşleşmesi ön incelemeyi destekler; ancak kesin bir karar vermeden önce kural mantığı ve ilişkili bulgular incelenmelidir.",
            ),
            size=8.5,
            color=document.muted,
            leading=12,
        )
        document.spacer(6)

    def _render_metadata(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Document Metadata", "Belge Metadatası"),
            self._l(
                "Metadata describes document provenance and editing history. These values can be missing, forged, or altered and should not be treated as identity proof.",
                "Metadata, belgenin kaynağını ve düzenleme geçmişini açıklar. Bu değerler eksik, sahte veya değiştirilmiş olabilir; kimlik kanıtı olarak değerlendirilmemelidir.",
            ),
        )
        if not result.metadata:
            document.paragraph(
                self._l("No document metadata was extracted.", "Belge metadatası çıkarılmadı."),
                color=document.muted,
            )
            return
        for key, value in self._flatten(result.metadata, max_rows=100):
            document.key_value(self._metadata_key(key), value)

    def _render_macro_code(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Macro Code Appendix", "Makro Kodu Eki"),
            self._l(
                "Extracted macro text is evidence only. MODA did not execute the code. Long source listings are bounded to keep the report usable.",
                "Çıkarılan makro metni yalnızca kanıttır. MODA kodu çalıştırmamıştır. Raporun kullanılabilir kalması için uzun kaynak listeleri sınırlandırılır.",
            ),
        )
        if not result.macro_code:
            document.paragraph(
                self._l(
                    "No extractable macro source code was recorded.",
                    "Çıkarılabilir makro kaynak kodu kaydedilmedi.",
                ),
                color=document.muted,
            )
            return

        remaining = self._MAX_MACRO_LINES
        for module_index, source in enumerate(result.macro_code, start=1):
            source_lines = str(source).splitlines() or [str(source)]
            visible = source_lines[:remaining]
            if not visible:
                break
            remaining -= len(visible)
            module_omitted = max(0, len(source_lines) - len(visible))
            document.code_block(
                self._l(
                    f"Macro module / block {module_index}",
                    f"Makro modülü / blok {module_index}",
                ),
                visible,
                module_omitted,
            )
            if remaining <= 0:
                break

        total_lines = sum(
            len(str(source).splitlines() or [str(source)]) for source in result.macro_code
        )
        if total_lines > self._MAX_MACRO_LINES:
            document.paragraph(
                self._l(
                    f"The appendix shows the first {self._MAX_MACRO_LINES} of {total_lines} extracted source lines. The complete macro_code value remains available in the JSON result.",
                    f"Ek bölüm, çıkarılan {total_lines} kaynak satırının ilk {self._MAX_MACRO_LINES} satırını gösterir. macro_code değerinin tamamı JSON sonucunda bulunur.",
                ),
                color=document.muted,
            )

    def _render_technical_evidence(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(
            self._l("Technical Evidence", "Teknik Kanıtlar"),
            self._l(
                "Analyzer-specific structured output is included here for reproducibility and deeper manual review.",
                "Yeniden üretilebilirlik ve ayrıntılı manuel inceleme için analiz aracına özgü yapılandırılmış çıktılar bu bölümde sunulur.",
            ),
        )
        extra = {key: value for key, value in result.extra.items() if key != "errors"}
        if not extra:
            document.paragraph(
                self._l(
                    "No additional analyzer-specific evidence was recorded.",
                    "Analiz aracına özgü ek bir kanıt kaydedilmedi.",
                ),
                color=document.muted,
            )
            return
        rows = self._flatten(extra, max_rows=self._MAX_TECHNICAL_ROWS)
        for key, value in rows:
            document.key_value(key, value, mono=self._looks_technical(value))
        if len(rows) >= self._MAX_TECHNICAL_ROWS:
            document.paragraph(
                self._l(
                    "The technical evidence appendix reached its PDF row limit. The complete structured output remains available in JSON.",
                    "Teknik kanıt eki PDF satır sınırına ulaştı. Yapılandırılmış çıktının tamamı JSON sonucunda bulunur.",
                ),
                color=document.muted,
            )

    def _render_limitations(self, document: _PDFDocument, result: AnalysisResult) -> None:
        document.section(self._l("Analysis Notes and Limitations", "Analiz Notları ve Kısıtlar"))
        view = build_report_view(result)
        document.key_value(
            self._l("Analysis completeness", "Analiz bütünlüğü"),
            self._analysis_status(view["analysis_status"]),
        )
        if view["analyzer_statuses"]:
            document.label(self._l("Analyzer execution", "Analizör çalıştırma durumu"))
            for name, details in view["analyzer_statuses"].items():
                status = details.get("status", "unknown") if isinstance(details, dict) else details
                document.bullet(f"{name}: {status}")
        errors = result.extra.get("errors", [])
        if isinstance(errors, list) and errors:
            document.label(self._l("Non-fatal analysis errors", "Kritik olmayan analiz hataları"))
            for error in errors:
                document.bullet(str(error), color=document.high)
        else:
            document.paragraph(
                self._l(
                    "No non-fatal analyzer errors were recorded.",
                    "Kritik olmayan bir analiz hatası kaydedilmedi.",
                ),
                color=document.muted,
            )

        document.label(self._l("Interpretation boundary", "Yorumlama sınırı"))
        notes = (
            (
                "This report describes static evidence and does not certify that a file is safe or malicious.",
                "Bu rapor statik kanıtları açıklar; bir dosyanın güvenli veya kötü amaçlı olduğunu kesin olarak onaylamaz.",
            ),
            (
                "MODA did not open, render, or execute the submitted document, macros, scripts, or embedded payloads.",
                "MODA gönderilen belgeyi, makroları, betikleri veya gömülü yükleri açmamış, görüntülememiş ya da çalıştırmamıştır.",
            ),
            (
                "A low score can still require manual review when the source is untrusted or the file type is unsupported.",
                "Kaynak güvenilir değilse veya dosya türü desteklenmiyorsa düşük puanlı bir sonuç yine de manuel inceleme gerektirebilir.",
            ),
            (
                "IOC reputation and behavioral impact should be validated with current threat intelligence, endpoint telemetry, or an isolated sandbox.",
                "IOC itibarı ve davranışsal etki; güncel tehdit istihbaratı, uç nokta telemetrisi veya izole bir sandbox ile doğrulanmalıdır.",
            ),
        )
        for english, turkish in notes:
            note = self._l(english, turkish)
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
        severity_text = ", ".join(
            f"{count} {self._severity(name).lower()}" for name, count in counts.items() if count
        )
        if not severity_text:
            severity_text = self._l("no severity-rated findings", "önem dereceli bulgu yok")
        narrative = self._risk_narrative(result)
        status = self._analysis_status(str(result.extra.get("analysis_status", "complete")))
        if self.language == "tr":
            return (
                f"MODA, {result.file_name} dosyasını içeriğini çalıştırmadan statik olarak inceledi. Analiz bütünlüğü: {status}. "
                f"Deterministik analiz motoru {result.risk_score:g}/100 puanla {self._risk_level(result.risk_level)} "
                f"risk seviyesi belirledi ve {severity_text} kaydetti. {narrative} Analiz sonucunda "
                f"{len(result.iocs)} gösterge ve {len(result.yara_matches)} YARA eşleşmesi çıkarıldı."
            )
        return (
            f"MODA performed a non-executing static analysis of {result.file_name}. Analysis completeness: {status}. "
            f"The deterministic engine assigned a {result.risk_level.upper()} risk level with a score of "
            f"{result.risk_score:g}/100 and recorded {severity_text}. {narrative} "
            f"The analysis extracted {len(result.iocs)} indicator(s) and {len(result.yara_matches)} YARA match(es)."
        )

    def _risk_narrative(self, result: AnalysisResult) -> str:
        if self.language == "tr":
            narratives = {
                "critical": "Kaydedilen kanıtlar; kod çalıştırma, istismar veya zararlı yük çalıştırma ile ilişkili göstergeler içeriyor. Dosya karantinada tutulmalıdır.",
                "high": "Analiz, güçlü şüpheli belge davranışları belirledi. Dosya normal bir iş istasyonunda açılmamalıdır.",
                "medium": "Dosya, serbest bırakılmadan veya güvenilir kabul edilmeden önce analist incelemesi gerektiren şüpheli özellikler içeriyor.",
                "low": "Yapılandırılmış kontroller yüksek riskli statik davranış belirlemedi; ancak statik analiz dosyanın zararsız olduğunu kanıtlayamaz.",
                "clean": "Şüpheli bir statik davranış kaydedilmedi; ancak sonuç kullanılabilen ve etkinleştirilmiş kontrollerle sınırlıdır.",
            }
            return narratives.get(
                result.risk_level.lower(),
                "Sonuç aşağıdaki ayrıntılı kanıtlarla birlikte değerlendirilmelidir.",
            )
        narratives = {
            "critical": "The recorded evidence includes indicators associated with code execution, exploitation, or payload loading. The file should remain quarantined.",
            "high": "The analysis found strong suspicious-document behavior. The file should not be opened on a normal workstation.",
            "medium": "The file contains suspicious traits that require analyst review before it can be released or trusted.",
            "low": "The configured checks did not identify high-risk static behavior, but static analysis cannot prove that the file is benign.",
            "clean": "No suspicious static behavior was recorded, but the result remains limited to the checks that were available and enabled.",
        }
        return narratives.get(
            result.risk_level.lower(),
            "The result should be interpreted together with the detailed evidence below.",
        )

    def _analysis_status(self, status: str) -> str:
        labels = {
            "complete": self._l("Complete", "Tamamlandı"),
            "partial": self._l("Partial", "Kısmi"),
            "inconclusive": self._l("Inconclusive", "Sonuçlandırılamadı"),
        }
        return labels.get(status, status)

    def _finding_explanation(self, finding: Finding) -> str:
        lowered = f"{finding.title} {finding.description} {finding.analyzer}".lower()
        if self.language == "tr":
            why = "Bu özellik belge riskini artırabilir; kaydedilen kanıtlar ve ilişkili bulgularla birlikte incelenmelidir."
            patterns = [
                (
                    ("unsupported file",),
                    "Dosya MODA'nın desteklediği belge kapsamının dışındadır; bu nedenle sonuç temiz değil, belirsizdir.",
                ),
                (
                    ("auto-execution", "auto execution"),
                    "Otomatik bir giriş noktası belge olayı gerçekleştiğinde makro davranışını etkinleştirebilir ve açık kullanıcı etkileşimi ihtiyacını azaltabilir.",
                ),
                (
                    ("process execution", "powershell", "cmd.exe", "shell"),
                    "İşlem başlatma yeteneği, belgenin belge uygulaması dışında işletim sistemi araçlarını veya betikleri çalıştırmasına imkân verebilir.",
                ),
                (
                    ("download", "xmlhttp", "winhttp"),
                    "İndirme davranışı, teslimattan sonra ikinci aşama bir zararlı yükün veya uzak betiğin alınmasını sağlayabilir.",
                ),
                (
                    ("obfuscat", "encoded"),
                    "Gizleme teknikleri manuel incelemeyi zorlaştırır; komutları, URL'leri veya zararlı yük içeriğini basit tarayıcılardan saklayabilir.",
                ),
                (
                    ("native api", "virtualalloc", "writeprocessmemory"),
                    "Yerel bellek ve işlem API'leri sıklıkla bellek içi yükleyiciler ve kod enjeksiyonu teknikleriyle ilişkilidir.",
                ),
                (
                    ("remote", "external relationship", "template"),
                    "Harici ilişkiler belgenin başka bir konumdan içerik almasına ve teslimattan sonra davranışını değiştirmesine neden olabilir.",
                ),
                (
                    ("embedded", "activex", "objectpool", "ole object", "package"),
                    "Gömülü içerik, sıradan görünen bir belgenin içinde ikincil dosyaları, etkin denetimleri veya zararlı yükleri gizleyebilir.",
                ),
                (
                    ("pdf", "javascript", "openaction", "launch action"),
                    "Etkin PDF eylemleri belge açıldığında veya belgeyle etkileşime girildiğinde betik ya da başlatma davranışı çalıştırabilir.",
                ),
                (
                    ("rtf", "equation", "exploit"),
                    "RTF nesneleri ve eski bileşen işaretleri, güvenlik açığı bulunan belge işleme yazılımlarında istismar yolları oluşturabilir.",
                ),
                (
                    ("macro", "vba"),
                    "Makro kodu meşru görevleri otomatikleştirebilir; ancak etkinleştirildiğinde komut çalıştırabilir, dosyaları değiştirebilir veya uzak içerik alabilir.",
                ),
                (
                    ("dde",),
                    "Dinamik Veri Alışverişi, belge alanları ve bağlantıları üzerinden harici uygulamaları veya komutları çağırabilir.",
                ),
                (
                    ("yara",),
                    "Dosya içeriği bir imzayla eşleşti. Eşleşme kesin karar olarak değerlendirilmeden önce kural metadatası ve diğer bulgular incelenmelidir.",
                ),
            ]
            for tokens, explanation in patterns:
                if any(token in lowered for token in tokens):
                    why = explanation
                    break
            return (
                f"MODA çıktısı: {self._finding_description(finding)} Bu bulgu "
                f"{self._severity(finding.severity.name).lower()} önem derecesinde sınıflandırıldı. "
                f"Neden önemli: {why}"
            )

        why = "This characteristic can increase document risk and should be reviewed together with the recorded evidence and surrounding findings."
        patterns = [
            (
                ("unsupported file",),
                "The file is outside MODA's supported document scope, so the result is inconclusive rather than clean.",
            ),
            (
                ("auto-execution", "auto execution"),
                "An automatic entry point can activate macro behavior when a document event occurs, reducing the amount of explicit user action required.",
            ),
            (
                ("process execution", "powershell", "cmd.exe", "shell"),
                "Process-launch capability can allow a document to start operating-system tools or scripts outside the document application.",
            ),
            (
                ("download", "xmlhttp", "winhttp"),
                "Downloader-related behavior can retrieve a second-stage payload or remote script after delivery.",
            ),
            (
                ("obfuscat", "encoded"),
                "Obfuscation makes manual inspection harder and can conceal commands, URLs, or payload material from simple scanners.",
            ),
            (
                ("native api", "virtualalloc", "writeprocessmemory"),
                "Native memory and process APIs are frequently associated with in-memory loaders and code-injection techniques.",
            ),
            (
                ("remote", "external relationship", "template"),
                "External relationships can cause a document to retrieve content from another location and change behavior after delivery.",
            ),
            (
                ("embedded", "activex", "objectpool", "ole object", "package"),
                "Embedded content can hide secondary files, active controls, or payloads inside an otherwise ordinary-looking document.",
            ),
            (
                ("pdf", "javascript", "openaction", "launch action"),
                "Active PDF actions can run script or launch behavior when the document is opened or interacted with.",
            ),
            (
                ("rtf", "equation", "exploit"),
                "RTF objects and legacy component markers may expose exploit paths in vulnerable document-processing software.",
            ),
            (
                ("macro", "vba"),
                "Macro code can automate legitimate tasks, but it can also execute commands, modify files, or retrieve remote content when enabled.",
            ),
            (
                ("dde",),
                "Dynamic Data Exchange can invoke external applications or commands through document fields and links.",
            ),
            (
                ("yara",),
                "A signature matched content in the file. The rule metadata and other findings should be reviewed before treating the match as a verdict.",
            ),
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
            return [
                self._l(
                    "The analyzer recorded the finding without additional structured detail.",
                    "Analiz aracı bulguyu ek yapılandırılmış ayrıntı olmadan kaydetti.",
                )
            ]
        return [f"{key}: {value}" for key, value in self._flatten(finding.details, max_rows=30)]

    def _ioc_explanation(self, ioc: IOC) -> str:
        ioc_type = ioc.ioc_type.value.lower()
        if self.language == "tr":
            if "url" in ioc_type or "domain" in ioc_type:
                meaning = "Bu ağ hedefi proxy, DNS, e-posta ve uç nokta telemetrisinde aranabilir."
            elif "ip" in ioc_type:
                meaning = "Bu adres ağ bağlantıları, DNS çözümlemeleri ve tehdit istihbaratı kayıtlarıyla ilişkilendirilebilir."
            elif "hash" in ioc_type:
                meaning = "Bu özet değer, dosya adlarına bağlı kalmadan eşleşen dosyaları belirlemek için kullanılabilir."
            elif "path" in ioc_type or "file" in ioc_type:
                meaning = (
                    "Bu yol veya dosya adı uç nokta ve dosya sistemi telemetrisinde aranabilir."
                )
            elif "command" in ioc_type:
                meaning = "Bu komut metni işlem oluşturma, betik ve komut satırı telemetrisinde aranabilir."
            else:
                meaning = "Bu değer tehdit avcılığı ve manuel inceleme sırasında başlangıç noktası olarak kullanılabilir."
            defanged = (
                " Değer başlangıçta etkisizleştirilmiş gösterimle kaydedildi."
                if ioc.defanged
                else ""
            )
            return f"Analist yorumu: {meaning}{defanged} Engelleme uygulamadan önce bağlamı ve itibarı doğrulayın."
        if "url" in ioc_type or "domain" in ioc_type:
            meaning = "This network destination can be searched in proxy, DNS, email, and endpoint telemetry."
        elif "ip" in ioc_type:
            meaning = "This address can be correlated with network connections, DNS resolutions, and threat-intelligence records."
        elif "hash" in ioc_type:
            meaning = "This hash can identify matching files without relying on their names."
        elif "path" in ioc_type or "file" in ioc_type:
            meaning = (
                "This path or filename can be used to search endpoint and file-system telemetry."
            )
        elif "command" in ioc_type:
            meaning = "This command text can be searched in process-creation, script, and command-line telemetry."
        else:
            meaning = "This value can be used as a pivot during threat hunting and manual review."
        defanged = (
            " The value was originally recorded in defanged notation." if ioc.defanged else ""
        )
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
        suffix = self._l(" ... [value truncated]", " ... [değer kısaltıldı]")
        return text if len(text) <= limit else text[: limit - len(suffix)] + suffix

    def _looks_technical(self, value: str) -> bool:
        return any(token in value.lower() for token in ("http://", "https://", "\\", "sha", "0x"))

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return self._l(f"{size} bytes", f"{size} bayt")
        units = ["KB", "MB", "GB"]
        value = float(size)
        for unit in units:
            value /= 1024
            if value < 1024 or unit == units[-1]:
                return self._l(
                    f"{value:.2f} {unit} ({size:,} bytes)",
                    f"{value:.2f} {unit} ({size:,} bayt)",
                )
        return self._l(f"{size:,} bytes", f"{size:,} bayt")

    def _format_timestamp(self, value: datetime) -> str:
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    def _l(self, english: str, turkish: str) -> str:
        return turkish if self.language == "tr" else english

    def _risk_level(self, level: str) -> str:
        if self.language != "tr":
            return level.upper()
        return {
            "critical": "KRİTİK",
            "high": "YÜKSEK",
            "medium": "ORTA",
            "low": "DÜŞÜK",
            "clean": "TEMİZ",
        }.get(level.lower(), level.upper())

    def _severity(self, severity: str) -> str:
        if self.language != "tr":
            return severity.upper()
        return {
            "critical": "KRİTİK",
            "high": "YÜKSEK",
            "medium": "ORTA",
            "low": "DÜŞÜK",
            "info": "BİLGİ",
        }.get(severity.lower(), severity.upper())

    def _finding_title(self, title: str) -> str:
        if self.language != "tr":
            return title
        titles = {
            "Unsupported File Type": "Desteklenmeyen Dosya Türü",
            "File Extension Mismatch": "Dosya Uzantısı Uyumsuzluğu",
            "VBA Macros Present": "VBA Makroları Mevcut",
            "Macro Project In Non-Macro OOXML": "Makro İçermemesi Gereken OOXML İçinde Makro Projesi",
            "Embedded Objects": "Gömülü Nesneler",
            "Macro Auto-Execution Trigger": "Makro Otomatik Çalıştırma Tetikleyicisi",
            "Macro Process Execution": "Makro İşlem Çalıştırma Davranışı",
            "Macro Download Capability": "Makro İndirme Yeteneği",
            "Macro Obfuscation Indicators": "Makro Gizleme Göstergeleri",
            "Macro Native API Abuse": "Makro Yerel API Kötüye Kullanımı",
            "Suspicious Document Author": "Şüpheli Belge Yazarı",
            "Office Exploit Protocol Relationship": "Office İstismar Protokolü İlişkisi",
            "High-Risk External OOXML Relationship": "Yüksek Riskli Harici OOXML İlişkisi",
            "Remote Document Relationships": "Uzak Belge İlişkileri",
            "OOXML Office Exploit Protocol": "OOXML Office İstismar Protokolü",
            "OOXML MSHTML/ActiveX Exploit Markers": "OOXML MSHTML/ActiveX İstismar İşaretleri",
            "OOXML DDE Field": "OOXML DDE Alanı",
            "OOXML OLE Link Or Object": "OOXML OLE Bağlantısı veya Nesnesi",
            "OOXML Active Content Markers": "OOXML Etkin İçerik İşaretleri",
            "Suspicious Command Text In OOXML": "OOXML İçinde Şüpheli Komut Metni",
            "OOXML Auto Field Update": "OOXML Otomatik Alan Güncellemesi",
            "Excel External Links": "Excel Harici Bağlantıları",
            "Excel Data Connections": "Excel Veri Bağlantıları",
            "Suspicious Excel Formula": "Şüpheli Excel Formülü",
            "Excel Very Hidden Sheet": "Excel Çok Gizli Sayfası",
            "RTF Embedded Object Data": "RTF Gömülü Nesne Verisi",
            "RTF Exploit Indicator": "RTF İstismar Göstergesi",
            "RTF DDE Reference": "RTF DDE Referansı",
            "Large RTF Hex Blob": "Büyük RTF Hex Veri Bloğu",
            "PDF JavaScript": "PDF JavaScript",
            "PDF JavaScript Shortcut": "PDF JavaScript Kısayolu",
            "PDF OpenAction": "PDF Açılış Eylemi",
            "PDF Additional Actions": "PDF Ek Eylemleri",
            "PDF Launch Action": "PDF Başlatma Eylemi",
            "PDF Embedded File": "PDF Gömülü Dosyası",
            "PDF URI Action": "PDF URI Eylemi",
            "PDF Interactive Form": "PDF Etkileşimli Formu",
            "PDF XFA Form": "PDF XFA Formu",
            "PDF Object Streams": "PDF Nesne Akışları",
            "Large PDF Object Count": "Yüksek PDF Nesne Sayısı",
            "Multiple PDF EOF Markers": "Birden Fazla PDF EOF İşareti",
            "OLE Stream Inventory": "OLE Akış Envanteri",
            "Encrypted Office Package": "Şifrelenmiş Office Paketi",
            "OLE Object Pool": "OLE Nesne Havuzu",
            "OLE Embedded Package Stream": "OLE Gömülü Paket Akışı",
            "OLE Exploit-Or-DDE Hint": "OLE İstismar veya DDE İşareti",
            "Large OLE Directory Tree": "Büyük OLE Dizin Ağacı",
            "ActiveX Controls Present": "ActiveX Denetimleri Mevcut",
            "High Entropy VBA Stream": "Yüksek Entropili VBA Akışı",
            "PowerPoint Office Exploit Protocol": "PowerPoint Office İstismar Protokolü",
            "PowerPoint External Link": "PowerPoint Harici Bağlantısı",
            "Suspicious Command Text In PowerPoint": "PowerPoint İçinde Şüpheli Komut Metni",
            "PowerPoint OLE Or Active Content Markers": "PowerPoint OLE veya Etkin İçerik İşaretleri",
        }
        if title.startswith("Embedded "):
            return "Gömülü " + title.removeprefix("Embedded ")
        return titles.get(title, title)

    def _finding_description(self, finding: Finding) -> str:
        if self.language != "tr":
            return finding.description
        descriptions = {
            "Document contains extractable VBA macro code.": "Belge, çıkarılabilir VBA makro kodu içeriyor.",
            "Macro code contains automatic execution entry points.": "Makro kodu otomatik çalıştırma giriş noktaları içeriyor.",
            "Macro code references process execution or living-off-the-land tools.": "Makro kodu işlem çalıştırma veya sistemde yerleşik araçların kötüye kullanımına ilişkin ifadeler içeriyor.",
            "Macro code contains downloader-related APIs or commands.": "Makro kodu indirme işleviyle ilişkili API'ler veya komutlar içeriyor.",
            "Macro code contains patterns commonly used for string obfuscation.": "Makro kodu metin gizlemede yaygın kullanılan örüntüler içeriyor.",
            "Macro code references native APIs often used by shellcode loaders.": "Makro kodu, shellcode yükleyicilerinin sıklıkla kullandığı yerel API'lere başvuruyor.",
            "Document relationships reference protocol handlers used by Office exploit chains.": "Belge ilişkileri Office istismar zincirlerinde kullanılan protokol işleyicilerine başvuruyor.",
            "Document uses external relationships commonly abused for template injection, OLE loading, or payload retrieval.": "Belge; şablon enjeksiyonu, OLE yükleme veya zararlı yük alma amacıyla kötüye kullanılabilen harici ilişkiler içeriyor.",
            "Document references external or remote resources.": "Belge harici veya uzak kaynaklara başvuruyor.",
            "RTF contains embedded object control words.": "RTF gömülü nesne kontrol sözcükleri içeriyor.",
            "RTF contains DDE-related control words.": "RTF, DDE ile ilişkili kontrol sözcükleri içeriyor.",
            "RTF contains large hex-encoded data blocks.": "RTF büyük, hex kodlu veri blokları içeriyor.",
            "PDF contains an unusually high number of objects.": "PDF olağan dışı sayıda nesne içeriyor.",
            "PDF contains multiple EOF markers, which can indicate appended content.": "PDF, sonradan eklenmiş içeriğe işaret edebilen birden fazla EOF işareti içeriyor.",
            "OOXML document contains a vbaProject.bin macro project.": "OOXML belgesi bir vbaProject.bin makro projesi içeriyor.",
            "Document XML references protocol handlers associated with Office vulnerability exploitation.": "Belge XML'i Office güvenlik açıklarının istismarıyla ilişkili protokol işleyicilerine başvuruyor.",
            "Document XML contains MSHTML, ActiveX, classid, or OLE markers seen in Office exploit chains.": "Belge XML'i Office istismar zincirlerinde görülen MSHTML, ActiveX, classid veya OLE işaretleri içeriyor.",
            "Document XML contains DDE field instructions that can launch commands.": "Belge XML'i komut başlatabilen DDE alan talimatları içeriyor.",
            "Document XML references OLE linked or embedded object behavior.": "Belge XML'i OLE bağlantılı veya gömülü nesne davranışına başvuruyor.",
            "Document XML contains active content markers such as ActiveX or custom UI callbacks.": "Belge XML'i ActiveX veya özel arayüz geri çağrıları gibi etkin içerik işaretleri içeriyor.",
            "Text-bearing OOXML parts reference commands often used by malicious documents.": "Metin içeren OOXML parçaları kötü amaçlı belgelerde sıklıkla kullanılan komutlara başvuruyor.",
            "Document settings request field updates, which can combine with links or DDE fields.": "Belge ayarları, bağlantılar veya DDE alanlarıyla birleşebilen alan güncellemeleri istiyor.",
            "Workbook contains external link parts that can reference remote or local content.": "Çalışma kitabı uzak veya yerel içeriğe başvurabilen harici bağlantı parçaları içeriyor.",
            "Workbook contains connection or query table parts that can retrieve external data.": "Çalışma kitabı harici veri alabilen bağlantı veya sorgu tablosu parçaları içeriyor.",
            "Workbook formulas reference functions or command-like patterns abused in malicious spreadsheets.": "Çalışma kitabı formülleri, kötü amaçlı elektronik tablolarda kötüye kullanılan işlevlere veya komut benzeri örüntülere başvuruyor.",
            "Workbook contains veryHidden sheets, often used to conceal staging data or formulas.": "Çalışma kitabı, hazırlık verilerini veya formülleri gizlemek için kullanılabilen veryHidden sayfalar içeriyor.",
            "Document contains a VBA project storage.": "Belge bir VBA proje depolama alanı içeriyor.",
            "OLE document references ActiveX-related storages or streams.": "OLE belgesi ActiveX ile ilişkili depolama alanlarına veya akışlara başvuruyor.",
            "Contains an ObjectPool storage often used for embedded objects.": "Gömülü nesneler için sıklıkla kullanılan bir ObjectPool depolama alanı içeriyor.",
            "Contains stream names associated with embedded packages or OLE objects.": "Gömülü paketler veya OLE nesneleriyle ilişkili akış adları içeriyor.",
            "OLE document contains an unusually large number of streams/storages.": "OLE belgesi olağan dışı sayıda akış veya depolama alanı içeriyor.",
            "A VBA-related stream has high entropy and may be compressed or obfuscated.": "VBA ile ilişkili bir akış yüksek entropiye sahip; sıkıştırılmış veya gizlenmiş olabilir.",
            "Legacy PowerPoint binary content references external or remote resources.": "Eski PowerPoint ikili içeriği harici veya uzak kaynaklara başvuruyor.",
            "Legacy PowerPoint binary content contains OLE, ActiveX, DDE, or package markers.": "Eski PowerPoint ikili içeriği OLE, ActiveX, DDE veya paket işaretleri içeriyor.",
        }
        if finding.description.startswith("Detected embedded "):
            embedded = finding.description.removeprefix("Detected embedded ").removesuffix(
                " content."
            )
            return f"Gömülü {embedded} içeriği algılandı."
        if (
            finding.description.startswith("PDF contains ")
            and " occurrence(s) of " in finding.description
        ):
            count_and_keyword = finding.description.removeprefix("PDF contains ")
            count, keyword = count_and_keyword.split(" occurrence(s) of ", 1)
            return f"PDF, {keyword} ifadesinden {count} adet içeriyor."
        if finding.description.startswith("Found ") and finding.description.endswith(
            " embedded objects"
        ):
            count = finding.description.removeprefix("Found ").removesuffix(" embedded objects")
            return f"{count} gömülü nesne bulundu."
        if finding.description.startswith("File extension '"):
            return "Dosya uzantısı algılanan dosya biçimiyle eşleşmiyor."
        if finding.description.startswith("The document author '"):
            return "Belge yazarı genel bir değer kullanıyor ve bu değer kötü amaçlı belge oluşturucularında sık görülüyor."
        if finding.description.startswith("RTF references suspicious object/class marker '"):
            return "RTF şüpheli bir nesne veya sınıf işaretine başvuruyor."
        if finding.description.startswith("OLE container exposes "):
            return "OLE kapsayıcısı statik inceleme için birden fazla veri akışı sunuyor."
        if finding.description.startswith(
            "OLE container includes encrypted Office package streams"
        ):
            return "OLE kapsayıcısı şifrelenmiş Office paket akışları içeriyor; statik içerik incelemesi sınırlı olabilir."
        if finding.description.startswith("Stream names reference Equation Editor"):
            return "Akış adları, kötü amaçlı belgelerde kötüye kullanılan Equation Editor veya DDE davranışına başvuruyor."
        if finding.description.startswith(
            "Legacy PowerPoint binary content references protocol handlers"
        ):
            return "Eski PowerPoint ikili içeriği Office istismar zincirleriyle ilişkili protokol işleyicilerine başvuruyor."
        if finding.description.startswith("Legacy PowerPoint binary content references commands"):
            return "Eski PowerPoint ikili içeriği kötü amaçlı belgelerde sıklıkla kullanılan komutlara başvuruyor."
        return descriptions.get(finding.description, finding.description)

    def _component_label(self, component: dict[str, object]) -> str:
        label = str(component.get("label", "Risk component"))
        if self.language != "tr":
            return label
        return {
            "macro": "Makro davranışı",
            "embedded": "Gömülü içerik",
            "relationship": "Harici ilişkiler",
            "pdf": "PDF eylemleri",
            "rtf": "RTF istismarları",
            "metadata": "Metadata sinyalleri",
            "yara": "YARA eşleşmeleri",
            "other": "Diğer bulgular",
        }.get(str(component.get("key", "")), self._translate_known(label))

    def _component_description(self, component: dict[str, object]) -> str:
        description = str(component.get("description", ""))
        if self.language != "tr":
            return description
        return {
            "macro": "VBA makrosu, otomatik çalıştırma, komut yürütme, indirme veya yerel API davranışı.",
            "embedded": "Gömülü betikler, OLE nesneleri, ActiveX denetimleri, çalıştırılabilir dosyalar veya iç içe belgeler.",
            "relationship": "Uzak şablonlar, harici OLE bağlantıları, UNC/dosya bağlantıları veya ağdan yüklenen kaynaklar.",
            "pdf": "PDF JavaScript, başlatma/açılış eylemleri, gömülü dosyalar, formlar veya şüpheli yapı.",
            "rtf": "RTF nesne verisi, istismar sınıfı işaretleri, DDE veya olağan dışı büyük kodlanmış bloklar.",
            "metadata": "Şüpheli metadata veya belge özellikleri.",
            "yara": "Yapılandırılmış YARA imzalarından gelen kural eşleşmeleri.",
            "other": "Toplam riske katkıda bulunan diğer analiz bulguları.",
        }.get(str(component.get("key", "")), self._translate_known(description))

    def _localized_list(self, values: object) -> list[str]:
        if not isinstance(values, (list, tuple)):
            return []
        return [self._translate_known(str(value)) for value in values]

    def _translate_known(self, text: str) -> str:
        if self.language != "tr":
            return text
        translations = {
            "No concrete impact path was identified from static indicators alone.": "Yalnızca statik göstergelerden somut bir etki yolu belirlenmedi.",
            "User interaction can trigger command execution, script launch, or second-stage payload download.": "Kullanıcı etkileşimi komut yürütmeyi, betik başlatmayı veya ikinci aşama zararlı yük indirmeyi tetikleyebilir.",
            "The document may load remote templates or resources that change behavior after delivery.": "Belge, teslimattan sonra davranışı değiştiren uzak şablonları veya kaynakları yükleyebilir.",
            "Embedded objects may drop files, exploit Office components, or hide secondary content.": "Gömülü nesneler dosya bırakabilir, Office bileşenlerini istismar edebilir veya ikincil içeriği gizleyebilir.",
            "Extracted URLs, domains, IPs, or file paths can indicate network callbacks or persistence artifacts.": "Çıkarılan URL, alan adı, IP veya dosya yolları ağ geri çağrılarına ya da kalıcılık izlerine işaret edebilir.",
            "Disconnect the affected machine from the network if the file was opened.": "Dosya açıldıysa etkilenen cihazın ağ bağlantısını kesin.",
            "Preserve the document, email, and endpoint logs for investigation.": "İnceleme için belgeyi, e-postayı ve uç nokta günlüklerini koruyun.",
            "Run a full endpoint security scan and collect process, startup, scheduled task, and PowerShell history artifacts.": "Tam uç nokta güvenlik taraması çalıştırın; işlem, başlangıç, zamanlanmış görev ve PowerShell geçmişi kayıtlarını toplayın.",
            "Block or investigate extracted IOCs in proxy, DNS, mail, and EDR telemetry.": "Çıkarılan IOC'leri proxy, DNS, e-posta ve EDR telemetrisinde araştırın veya engelleyin.",
            "Rotate credentials used on the affected machine if code execution or credential theft is suspected.": "Kod çalıştırma veya kimlik bilgisi hırsızlığından şüpheleniliyorsa etkilenen cihazda kullanılan kimlik bilgilerini yenileyin.",
            "Restore from a known-good backup if persistence, encryption, or system modification is confirmed.": "Kalıcılık, şifreleme veya sistem değişikliği doğrulanırsa bilinen güvenli bir yedekten geri yükleyin.",
            "Keep the file quarantined until an analyst reviews the suspicious indicators.": "Bir analist şüpheli göstergeleri inceleyene kadar dosyayı karantinada tutun.",
            "Open only in an isolated VM or sandbox if manual inspection is required.": "Manuel inceleme gerekiyorsa dosyayı yalnızca izole bir sanal makinede veya sandbox ortamında açın.",
            "Check mail and endpoint logs for extracted IOCs before releasing the document.": "Belgeyi serbest bırakmadan önce çıkarılan IOC'leri e-posta ve uç nokta günlüklerinde arayın.",
            "Keep standard endpoint protection enabled.": "Standart uç nokta korumasını etkin tutun.",
            "Treat the result as static-analysis-only and rescan if the file source is untrusted.": "Sonucu yalnızca statik analiz olarak değerlendirin; dosya kaynağı güvenilir değilse yeniden tarayın.",
            "Do not open the document on a workstation.": "Belgeyi bir iş istasyonunda açmayın.",
            "Review findings and extracted IOCs in a sandboxed analysis workflow.": "Bulguları ve çıkarılan IOC'leri sandbox tabanlı bir analiz sürecinde inceleyin.",
            "Hunt for extracted hashes, URLs, and IP addresses in telemetry.": "Çıkarılan özet, URL ve IP adreslerini telemetride arayın.",
            "Manually review suspicious findings before releasing the document.": "Belgeyi serbest bırakmadan önce şüpheli bulguları manuel olarak inceleyin.",
            "Correlate extracted IOCs with mail and endpoint telemetry.": "Çıkarılan IOC'leri e-posta ve uç nokta telemetrisiyle ilişkilendirin.",
            "No high-risk indicators were detected by the configured static checks.": "Yapılandırılmış statik kontroller yüksek riskli bir gösterge belirlemedi.",
            "Macro Process Execution": "Makro İşlem Çalıştırma Davranışı",
            "VBA Macros Present": "VBA Makroları Mevcut",
            "Macro Auto-Execution Trigger": "Makro Otomatik Çalıştırma Tetikleyicisi",
            "Macro Download Capability": "Makro İndirme Yeteneği",
            "Macro Obfuscation Indicators": "Makro Gizleme Göstergeleri",
            "Macro Native API Abuse": "Makro Yerel API Kötüye Kullanımı",
        }
        return translations.get(text, text)

    def _metadata_key(self, key: str) -> str:
        if self.language != "tr":
            return key
        return {
            "Author": "Yazar",
            "Last Modified By": "Son Değiştiren",
            "Created": "Oluşturulma",
            "Modified": "Değiştirilme",
            "Title": "Başlık",
            "Subject": "Konu",
            "Description": "Açıklama",
            "Keywords": "Anahtar kelimeler",
            "Creator": "Oluşturan",
            "Producer": "Üretici",
        }.get(key, key)

    def _number(self, value: object) -> float:
        if not isinstance(value, (str, bytes, int, float)):
            return 0.0
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        return number if math.isfinite(number) else 0.0
