from __future__ import annotations
from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType

class RTFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "RTFAnalyzer"
    @property
    def description(self) -> str: return "Analyzes RTF files."
    def can_run(self, context: AnalysisContext) -> bool: return context.file_type == FileType.RTF
    def analyze(self, context: AnalysisContext) -> None: pass
