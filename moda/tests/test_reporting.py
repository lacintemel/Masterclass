from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.cli import build_reporter, emit_report
from moda.core.engine import AnalyzerEngine


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
