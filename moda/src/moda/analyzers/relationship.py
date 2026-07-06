from __future__ import annotations
from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext

class RelationshipAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "RelationshipAnalyzer"
    @property
    def description(self) -> str: return "Analyzes document relationships."
    def analyze(self, context: AnalysisContext) -> None: pass
