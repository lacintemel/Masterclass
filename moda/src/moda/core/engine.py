from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import List

from .context import AnalysisContext
from .models import AnalysisResult
from .base import BaseAnalyzer
from .exceptions import AnalyzerError, FileTooLargeError

logger = logging.getLogger(__name__)

class AnalyzerEngine:
    """
    Pipeline orchestrator for MODA.
    Manages the analysis lifecycle: file input -> context -> analyzers -> result.
    """
    def __init__(self, skip_yara: bool = False, max_file_size_mb: int = 100):
        self.analyzers: List[BaseAnalyzer] = []
        self.skip_yara = skip_yara
        self.max_file_size_mb = max_file_size_mb
        self._build_default_pipeline()

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Register an analyzer to the pipeline."""
        self.analyzers.append(analyzer)
        logger.debug(f"Registered analyzer: {analyzer.name}")

    def _build_default_pipeline(self) -> None:
        """Build the default analysis pipeline in correct order."""
        from ..analyzers import (
            FileTypeDetector, HashGenerator, MetadataAnalyzer, 
            OLEAnalyzer, OOXMLAnalyzer, RTFAnalyzer, PDFAnalyzer,
            MacroAnalyzer, EmbeddedObjectAnalyzer, RelationshipAnalyzer
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
        self.register_analyzer(YaraScanner())
        
        # Stage 10: Output
        self.register_analyzer(RiskScorer())

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """Run the full analysis pipeline on a file."""
        file_path = Path(file_path).resolve()
        logger.info(f"Starting analysis of file: {file_path}")
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise FileNotFoundError(f"Not a regular file: {file_path}")
        max_bytes = self.max_file_size_mb * 1024 * 1024
        file_size = file_path.stat().st_size
        if file_size > max_bytes:
            raise FileTooLargeError(file_path, file_size, max_bytes)
        
        start_time = time.time()
        file_bytes = file_path.read_bytes()
        
        # 1. Create context
        context = AnalysisContext(
            file_path=file_path,
            file_bytes=file_bytes,
        )
        
        # 2. Run pipeline
        self._run_pipeline(context)
        
        # 3. Finalize and return
        context.analysis_end = time.time()
        logger.info(f"Analysis complete in {context.analysis_end - start_time:.2f}s")
        
        return context.to_result()

    def _run_pipeline(self, context: AnalysisContext) -> None:
        """Execute all registered analyzers in sequence."""
        for analyzer in self.analyzers:
            if self.skip_yara and analyzer.name.lower() == "yarascanner":
                logger.info(f"Skipping {analyzer.name} (YARA scanning disabled)")
                continue
                
            try:
                if analyzer.can_run(context):
                    logger.debug(f"Running analyzer: {analyzer.name}")
                    analyzer.analyze(context)
                else:
                    logger.debug(f"Skipping analyzer: {analyzer.name} (can_run returned False)")
            except AnalyzerError as e:
                # Expected analyzer failure, log and continue
                error_msg = f"{analyzer.name} failed: {str(e)}"
                logger.error(error_msg)
                context.errors.append(error_msg)
            except Exception as e:
                # Unexpected failure, log and continue to not crash the whole pipeline
                error_msg = f"{analyzer.name} encountered unexpected error: {str(e)}"
                logger.exception(error_msg)
                context.errors.append(error_msg)
