from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.cli import build_reporter, emit_report
from moda.core.enums import FindingSeverity, IOCType
from moda.core.engine import AnalyzerEngine
from moda.core.models import Finding, IOC, YaraMatch
from moda.reporting.pdf_report import PDFReporter


def build_docx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
        )


class ReportingTests(unittest.TestCase):
    def make_result(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        sample = Path(temp_dir.name) / "report.docx"
        build_docx(sample)
        return AnalyzerEngine(skip_yara=True).analyze_file(sample)

    def test_html_reporter_generates_self_contained_html(self) -> None:
        result = self.make_result()
        reporter = build_reporter("html")

        payload = reporter.generate(result)

        self.assertIn("<!doctype html>", payload)
        self.assertIn("MODA - Malicious Office Document Analyzer", payload)
        self.assertIn("report.docx", payload)

    def test_pdf_reporter_generates_pdf_bytes(self) -> None:
        result = self.make_result()
        reporter = build_reporter("pdf")

        payload = reporter.generate(result)

        self.assertIsInstance(payload, bytes)
        self.assertTrue(payload.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", payload)
        self.assertIn(b"EXECUTIVE SUMMARY", payload)
        self.assertIn(b"FILE IDENTITY", payload)
        self.assertIn(b"PAGE 1 /", payload)

    def test_pdf_report_includes_narrative_findings_and_structured_evidence(self) -> None:
        result = self.make_result()
        finding = Finding(
            title="Macro Process Execution",
            description="Macro code references PowerShell and process execution.",
            severity=FindingSeverity.HIGH,
            analyzer="MacroAnalyzer",
            details={"keywords": ["powershell", "wscript.shell"]},
        )
        enriched = replace(
            result,
            findings=(finding,),
            iocs=(
                IOC(
                    ioc_type=IOCType.URL,
                    value="https://example.invalid/payload",
                    source="IOCExtractor",
                    confidence=0.9,
                ),
            ),
            yara_matches=(
                YaraMatch(
                    rule_name="unit_test_maldoc",
                    tags=("document", "macro"),
                    meta={"description": "Test malicious document rule", "severity": "high"},
                ),
            ),
            macro_code=("Sub AutoOpen()\n  Shell \"powershell.exe\"\nEnd Sub",),
            risk_level="high",
            risk_score=65,
            score_breakdown={
                "risk_summary": "Strong malicious-document indicators were recorded.",
                "components": [
                    {
                        "label": "Macro behavior",
                        "points": 65,
                        "description": "Macro execution behavior.",
                        "reasons": ["Macro Process Execution"],
                    }
                ],
                "potential_impacts": ["The macro may launch a process."],
                "recovery_steps": ["Keep the file quarantined."],
            },
            extra={"remote_relationships": ["https://example.invalid/payload"], "errors": []},
        )

        payload = build_reporter("pdf").generate(enriched)

        for expected in (
            b"DETAILED FINDINGS",
            b"ANALYST INTERPRETATION",
            b"Macro Process Execution",
            b"powershell",
            b"INDICATORS OF COMPROMISE",
            b"unit_test_maldoc",
            b"MACRO CODE APPENDIX",
            b"TECHNICAL EVIDENCE",
        ):
            self.assertIn(expected, payload)

    def test_pdf_reporter_generates_turkish_report_with_turkish_characters(self) -> None:
        result = self.make_result()
        payload = PDFReporter(language="tr").generate(result)

        for expected in (
            "YÖNETİCİ ÖZETİ",
            "DOSYA KİMLİĞİ",
            "RİSK DEĞERLENDİRMESİ",
            "AYRINTILI BULGULAR",
            "SAYFA 1 /",
            "hiçbir belge içeriği çalıştırılmadı",
        ):
            self.assertIn(expected.encode("cp1254"), payload)

    def test_pdf_report_automatically_paginates_long_content(self) -> None:
        result = self.make_result()
        findings = tuple(
            Finding(
                title=f"Repeated Finding {index}",
                description="A detailed suspicious behavior was recorded for pagination testing.",
                severity=FindingSeverity.MEDIUM,
                analyzer="UnitTestAnalyzer",
                details={"index": index, "evidence": "x" * 120},
            )
            for index in range(24)
        )
        payload = build_reporter("pdf").generate(replace(result, findings=findings))

        match = re.search(rb"/Type /Pages /Kids \[[^]]+\] /Count (\d+)", payload)
        self.assertIsNotNone(match)
        self.assertGreater(int(match.group(1)), 2)
        self.assertIn(b"Repeated Finding 23", payload)

    def test_emit_report_saves_binary_and_text_outputs(self) -> None:
        result = self.make_result()
        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "report.html"
            pdf_path = Path(temp_dir) / "report.pdf"

            with contextlib.redirect_stdout(io.StringIO()):
                emit_report(result, build_reporter("html"), output=str(html_path))
                emit_report(result, build_reporter("pdf"), output=str(pdf_path))

            self.assertIn("<!doctype html>", html_path.read_text(encoding="utf-8"))
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-1.4"))

    def test_json_reporter_prints_to_stdout(self) -> None:
        result = self.make_result()
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            emit_report(result, build_reporter("json"), output=None)

        self.assertIn('"file_info"', stdout.getvalue())
        self.assertIn('"risk"', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
