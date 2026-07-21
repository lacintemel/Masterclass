from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from moda.core.context import AnalysisContext
from moda.core.engine import AnalyzerEngine
from moda.core.enums import FindingSeverity, IOCType
from moda.core.limits import AnalysisLimits
from moda.core.models import IOC, Finding, YaraMatch
from moda.intelligence.ioc_extractor import IOCExtractor
from moda.scoring.risk_scorer import RiskScorer


class SecurityRegressionTests(unittest.TestCase):
    def test_yara_match_is_scored_once(self) -> None:
        context = AnalysisContext("sample.doc", b"unit")
        context.add_finding(
            Finding(
                title="YARA Rule Match: unit_rule",
                description="unit",
                severity=FindingSeverity.MEDIUM,
                analyzer="YaraScanner",
            )
        )
        context.add_yara_match(YaraMatch(rule_name="unit_rule"))

        RiskScorer().analyze(context)

        self.assertEqual(context.risk_score, 24)
        self.assertEqual(context.score_breakdown["finding_score"], 24)
        self.assertNotIn("yara_score", context.score_breakdown)

    def test_risk_threshold_25_is_medium(self) -> None:
        context = AnalysisContext("sample.doc", b"unit")
        for index in range(5):
            context.add_finding(
                Finding(
                    title=f"Low signal {index}",
                    description="unit",
                    severity=FindingSeverity.LOW,
                    analyzer="UnitAnalyzer",
                )
            )

        RiskScorer().analyze(context)

        self.assertEqual(context.risk_score, 25)
        self.assertEqual(context.risk_level.name, "MEDIUM")

    def test_benign_docx_schema_urls_and_hashes_are_not_iocs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "benign.docx"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr(
                    "[Content_Types].xml",
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
                )
                archive.writestr(
                    "word/document.xml",
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
                )
            result = AnalyzerEngine(skip_yara=True).analyze_file(sample)

        self.assertEqual(result.iocs, ())
        self.assertTrue(result.file_hash_sha256)

    def test_ioc_extraction_refangs_and_filters_private_values(self) -> None:
        context = AnalysisContext("sample.doc", b"unit")
        context.raw_strings = ["hxxp://evil[.]com/payload 8.8.8.8 10.0.0.1 cmd.exe /c calc"]

        IOCExtractor().analyze(context)

        values = {ioc.value for ioc in context.iocs}
        self.assertIn("http://evil.com/payload", values)
        self.assertIn("8.8.8.8", values)
        self.assertNotIn("10.0.0.1", values)

    def test_archive_budget_marks_analysis_inconclusive(self) -> None:
        limits = AnalysisLimits(
            max_file_bytes=2 * 1024 * 1024,
            max_archive_uncompressed_bytes=1_024,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "oversized.docx"
            with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("[Content_Types].xml", "<Types/>" + "A" * 2_000)
                archive.writestr("word/document.xml", "<document/>")
            result = AnalyzerEngine(skip_yara=True, limits=limits).analyze_file(sample)

        self.assertEqual(result.extra["analysis_status"], "inconclusive")
        self.assertTrue(result.extra["resource_limit_exceeded"])
        self.assertTrue(any("safety limit" in item for item in result.extra["errors"]))

    def test_ioc_serialization_order_is_deterministic(self) -> None:
        context = AnalysisContext("sample.doc", b"unit")
        context.add_ioc(IOC(IOCType.URL, "https://z.example", "unit"))
        context.add_ioc(IOC(IOCType.DOMAIN, "a.example", "unit"))

        result = context.to_result()

        self.assertEqual(
            [(ioc.ioc_type.value, ioc.value) for ioc in result.iocs],
            [("domain", "a.example"), ("url", "https://z.example")],
        )

    def test_skip_yara_does_not_construct_scanner(self) -> None:
        engine = AnalyzerEngine(skip_yara=True)

        self.assertNotIn("YaraScanner", {analyzer.name for analyzer in engine.analyzers})
        self.assertEqual(engine.disabled_analyzers["YaraScanner"], "disabled_by_user")


if __name__ == "__main__":
    unittest.main()
