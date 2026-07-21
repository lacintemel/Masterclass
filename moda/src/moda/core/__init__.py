"""Core module for MODA - contains base classes, models, enums, and context."""

from moda.core.base import BaseAnalyzer
from moda.core.context import AnalysisContext
from moda.core.enums import FileType, FindingSeverity, IOCType, RiskLevel
from moda.core.exceptions import AnalyzerError, MODAError
from moda.core.models import IOC, AnalysisResult, Finding, YaraMatch

__all__ = [
    "AnalysisResult",
    "BaseAnalyzer",
    "AnalysisContext",
    "FileType",
    "FindingSeverity",
    "IOCType",
    "RiskLevel",
    "AnalyzerError",
    "MODAError",
    "Finding",
    "IOC",
    "YaraMatch",
]
