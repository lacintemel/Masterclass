from __future__ import annotations

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import RiskLevel, FindingSeverity
from ..utils.config_loader import load_scoring_config

class RiskScorer(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.config = load_scoring_config()
        self.weights = self.config.get('severity_weights', {})
        self.levels = self.config.get('risk_levels', {})
        self.max_score = self.config.get('max_score', 100)

    @property
    def name(self) -> str:
        return "RiskScorer"
        
    @property
    def description(self) -> str:
        return "Calculates final risk score based on findings."

    def analyze(self, context: AnalysisContext) -> None:
        score = 0
        
        severity_weights = {
            FindingSeverity.INFO: self.weights.get("info", 0),
            FindingSeverity.LOW: self.weights.get("low", 5),
            FindingSeverity.MEDIUM: self.weights.get("medium", 15),
            FindingSeverity.HIGH: self.weights.get("high", 30),
            FindingSeverity.CRITICAL: self.weights.get("critical", 50),
        }
        
        for finding in context.findings:
            score += severity_weights.get(finding.severity, 0)
            
        for ym in context.yara_matches:
            score += self.config.get("category_caps", {}).get("yara", 30)
            
        score = min(score, self.max_score)
        
        # Determine risk level
        risk_level = RiskLevel.LOW
        for level_name, thresholds in self.levels.items():
            min_score = thresholds.get("min_score", thresholds.get("min", 0))
            max_score = thresholds.get("max_score", thresholds.get("max", self.max_score))
            if min_score <= score <= max_score:
                risk_level = RiskLevel[level_name.upper()]
                break
                
        context.set_risk(
            score,
            risk_level,
            {
                "finding_score": score,
                "findings_count": len(context.findings),
                "yara_matches_count": len(context.yara_matches),
            },
        )
