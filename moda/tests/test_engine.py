from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.core.engine import AnalyzerEngine


def build_docx(path: Path, extra_files: dict[str, str | bytes] | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "docProps/core.xml",
            (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<cp:coreProperties '
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                'xmlns:dcterms="http://purl.org/dc/terms/">'
                "<dc:creator>Alice Analyst</dc:creator>"
                "<cp:lastModifiedBy>Alice Analyst</cp:lastModifiedBy>"
                "<dcterms:created>2026-07-06T12:00:00Z</dcterms:created>"
                "</cp:coreProperties>"
            ),
        )
        archive.writestr(
            "word/document.xml",
            (
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>"
                "</w:document>"
            ),
        )
        for name, data in (extra_files or {}).items():
            archive.writestr(name, data)


class AnalyzerEngineTests(unittest.TestCase):
    def test_analyzes_minimal_docx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "benign.docx"
            build_docx(sample)

            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        self.assertEqual(result.file_type, "ooxml_docx")
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.metadata["Author"], "Alice Analyst")
        self.assertEqual(result.findings, ())
        self.assertTrue(result.file_hash_md5)
        self.assertTrue(result.file_hash_sha1)
        self.assertTrue(result.file_hash_sha256)

    def test_ooxml_macro_project_adds_finding_and_score(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "macro.docm"
            build_docx(sample, {"word/vbaProject.bin": b"fake static macro project"})

            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        self.assertEqual(result.file_type, "ooxml_docm")
        self.assertEqual(result.risk_level, "medium")
        self.assertGreater(result.risk_score, 0)
        self.assertEqual(result.findings[0].title, "VBA Macros Present")

    def test_context_errors_are_in_result_dict(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "benign.docx"
            build_docx(sample)

            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)
            payload = result.to_dict()

        self.assertIn("errors", payload)
        self.assertEqual(payload["errors"], [])
        self.assertIn("extra", payload)


if __name__ == "__main__":
    unittest.main()
