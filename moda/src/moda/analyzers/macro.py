from __future__ import annotations

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext

class MacroAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "MacroAnalyzer"
        
    @property
    def description(self) -> str:
        return "Extracts and statically analyzes VBA macros."

    def analyze(self, context: AnalysisContext) -> None:
        pass # Full oletools extraction would be here
