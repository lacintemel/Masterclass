from __future__ import annotations

import logging
import time
from pathlib import Path

from ..utils.file_utils import safe_read_file
from .base import BaseAnalyzer
from .context import AnalysisContext
from .exceptions import AnalyzerError, FileTooLargeError, ResourceLimitError
from .limits import AnalysisLimits
from .models import AnalysisResult

logger = logging.getLogger(__name__)


class AnalyzerEngine:
    """
    Pipeline orchestrator for MODA.
    Manages the analysis lifecycle: file input -> context -> analyzers -> result.
    """

    def __init__(
        self,
        skip_yara: bool = False,
        max_file_size_mb: int = 100,
        *,
        limits: AnalysisLimits | None = None,
        rules_dir: str | Path | None = None,
        scoring_config: str | Path | None = None,
    ):
        self.analyzers: list[BaseAnalyzer] = []
        self.skip_yara = skip_yara
        self.max_file_size_mb = max_file_size_mb
        self.limits = limits or AnalysisLimits.for_file_size_mb(max_file_size_mb)
        self.rules_dir = Path(rules_dir).resolve() if rules_dir else None
        self.scoring_config = Path(scoring_config).resolve() if scoring_config else None
        self.disabled_analyzers: dict[str, str] = {}
        self._build_default_pipeline()

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Register an analyzer to the pipeline."""
        self.analyzers.append(analyzer)
        logger.debug(f"Registered analyzer: {analyzer.name}")

    def _build_default_pipeline(self) -> None:
        """Build the default analysis pipeline in correct order."""
        from ..analyzers import (
            EmbeddedObjectAnalyzer,
            FileTypeDetector,
            HashGenerator,
            MacroAnalyzer,
            MetadataAnalyzer,
            OLEAnalyzer,
            OOXMLAnalyzer,
            PDFAnalyzer,
            RelationshipAnalyzer,
            RTFAnalyzer,
        )
        from ..intelligence import IOCExtractor, YaraScanner
        from ..scoring import RiskScorer

        # Stage 1-2: Triage
        self.register_analyzer(FileTypeDetector())
        self.register_analyzer(HashGenerator())

        # Stage 3-4: Structure
        self.register_analyzer(MetadataAnalyzer())
        self.register_analyzer(OLEAnalyzer())
        self.register_analyzer(OOXMLAnalyzer())
        self.register_analyzer(RTFAnalyzer())
        self.register_analyzer(PDFAnalyzer())

        # Stage 5-7: Content
        self.register_analyzer(MacroAnalyzer())
        self.register_analyzer(EmbeddedObjectAnalyzer())
        self.register_analyzer(RelationshipAnalyzer())

        # Stage 8-9: Intelligence
        self.register_analyzer(IOCExtractor())
        if self.skip_yara:
            self.disabled_analyzers["YaraScanner"] = "disabled_by_user"
        else:
            self.register_analyzer(YaraScanner(rules_dir=self.rules_dir))

        # Stage 10: Output
        self.register_analyzer(RiskScorer(config_path=self.scoring_config))

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """Run the full analysis pipeline on a file."""
        file_path = Path(file_path).resolve()
        logger.info(f"Starting analysis of file: {file_path}")
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise FileNotFoundError(f"Not a regular file: {file_path}")
        max_bytes = self.limits.max_file_bytes
        file_size = file_path.stat().st_size
        if file_size > max_bytes:
            raise FileTooLargeError(file_path, file_size, max_bytes)

        start_time = time.time()
        file_bytes = safe_read_file(file_path, max_size_bytes=max_bytes)

        # 1. Create context
        context = AnalysisContext(
            file_path=file_path,
            file_bytes=file_bytes,
            limits=self.limits,
        )
        context.extra["analysis_id"] = context.file_hash[:24]

        # 2. Run pipeline
        self._run_pipeline(context)

        self._finalize_analysis_status(context)

        # 3. Finalize and return
        context.analysis_end = time.time()
        logger.info(f"Analysis complete in {context.analysis_end - start_time:.2f}s")

        return context.to_result()

    def _run_pipeline(self, context: AnalysisContext) -> None:
        """Execute all registered analyzers in sequence."""
        statuses: dict[str, dict[str, object]] = {
            name: {"status": status, "duration_seconds": 0.0}
            for name, status in self.disabled_analyzers.items()
        }
        context.extra["analyzer_statuses"] = statuses
        for analyzer in self.analyzers:
            if not analyzer.can_run(context):
                statuses[analyzer.name] = {
                    "status": "not_applicable",
                    "duration_seconds": 0.0,
                }
                continue

            started = time.perf_counter()
            try:
                logger.debug(f"Running analyzer: {analyzer.name}")
                analyzer.run(context)
                override = context.extra.get("capability_overrides", {}).get(analyzer.name)
                statuses[analyzer.name] = {
                    "status": override or "success",
                    "duration_seconds": round(time.perf_counter() - started, 6),
                }
            except ResourceLimitError as e:
                error_msg = f"{analyzer.name} stopped by a safety limit: {e}"
                logger.warning(error_msg)
                context.errors.append(error_msg)
                context.extra["resource_limit_exceeded"] = True
                statuses[analyzer.name] = {
                    "status": "resource_limit",
                    "duration_seconds": round(time.perf_counter() - started, 6),
                    "error": str(e),
                }
            except AnalyzerError as e:
                # Expected analyzer failure, log and continue
                error_msg = f"{analyzer.name} failed: {str(e)}"
                logger.error(error_msg)
                context.errors.append(error_msg)
                statuses[analyzer.name] = {
                    "status": "failed",
                    "duration_seconds": round(time.perf_counter() - started, 6),
                    "error": str(e),
                }
            except Exception as e:
                # Unexpected failure, log and continue to not crash the whole pipeline
                error_msg = f"{analyzer.name} encountered unexpected error: {str(e)}"
                logger.exception(error_msg)
                context.errors.append(error_msg)
                statuses[analyzer.name] = {
                    "status": "failed",
                    "duration_seconds": round(time.perf_counter() - started, 6),
                    "error": str(e),
                }

    def _finalize_analysis_status(self, context: AnalysisContext) -> None:
        statuses = context.extra.get("analyzer_statuses", {})
        status_values = {
            str(item.get("status")) for item in statuses.values() if isinstance(item, dict)
        }
        if context.extra.get("unsupported_file_type") or context.extra.get(
            "resource_limit_exceeded"
        ):
            status = "inconclusive"
        elif status_values.intersection({"failed", "disabled_by_user", "unavailable", "partial"}):
            status = "partial"
        else:
            status = "complete"
        context.extra["analysis_status"] = status
