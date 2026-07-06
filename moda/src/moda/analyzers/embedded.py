from __future__ import annotations
from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext

class EmbeddedObjectAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "EmbeddedObjectAnalyzer"
    @property
    def description(self) -> str: return "Analyzes embedded objects."
    def analyze(self, context: AnalysisContext) -> None: pass
