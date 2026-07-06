from __future__ import annotations
from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType

class PDFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "PDFAnalyzer"
    @property
    def description(self) -> str: return "Analyzes PDF files."
    def can_run(self, context: AnalysisContext) -> bool: return context.file_type == FileType.PDF
    def analyze(self, context: AnalysisContext) -> None: pass
