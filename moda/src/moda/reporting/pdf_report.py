from __future__ import annotations

from textwrap import wrap

from .base import BaseReporter
from ..core.models import AnalysisResult


class PDFReporter(BaseReporter):
    """Render a compact, dependency-free PDF report."""

    format_name = "pdf"
    file_extension = ".pdf"

    def generate(self, result: AnalysisResult) -> bytes:
        lines = self._build_lines(result)
        return self._minimal_pdf(lines)

    def _build_lines(self, result: AnalysisResult) -> list[str]:
        lines = [
            "MODA - Malicious Office Document Analyzer",
            f"File: {result.file_name}",
            f"Risk: {result.risk_level.upper()} ({result.risk_score}/100)",
            f"Type: {result.file_type}",
            f"MIME: {result.mime_type}",
            f"Size: {result.file_size} bytes",
            f"MD5: {result.file_hash_md5}",
            f"SHA1: {result.file_hash_sha1}",
            f"SHA256: {result.file_hash_sha256}",
            "",
            "Findings:",
        ]
        if result.findings:
            for finding in result.findings[:40]:
                lines.extend(
                    wrap(
                        f"- {finding.severity.name}: {finding.title} - {finding.description}",
                        width=92,
                    )
                )
        else:
            lines.append("- No findings")

        lines.append("")
        lines.append("Indicators:")
        if result.iocs:
            for ioc in result.iocs[:60]:
                lines.extend(wrap(f"- {ioc.ioc_type.value}: {ioc.value}", width=92))
        else:
            lines.append("- No indicators")

        lines.append("")
        lines.append("Recommendations:")
        for recommendation in result.recommendations:
            lines.extend(wrap(f"- {recommendation}", width=92))
        return lines[:95]

    def _minimal_pdf(self, lines: list[str]) -> bytes:
        y = 780
        stream_lines = ["BT", "/F1 10 Tf", "50 800 Td"]
        for line in lines:
            escaped = self._escape_pdf_text(line)
            stream_lines.append(f"0 {y - 800} Td ({escaped}) Tj")
            y -= 14
        stream_lines.append("ET")
        content = "\n".join(stream_lines).encode("latin-1", errors="replace")

        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        ]

        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode())
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_start = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode())
        pdf.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_start}\n%%EOF\n"
            ).encode()
        )
        return bytes(pdf)

    def _escape_pdf_text(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
