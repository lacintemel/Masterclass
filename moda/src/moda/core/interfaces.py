from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from .context import AnalysisContext
from .models import AnalysisResult


@runtime_checkable
class IAnalyzer(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    def analyze(self, context: AnalysisContext) -> None: ...

    def can_run(self, context: AnalysisContext) -> bool: ...


@runtime_checkable
class IReporter(Protocol):
    @property
    def format_name(self) -> str: ...

    def generate(self, result: AnalysisResult) -> str | bytes: ...

    def save(self, result: AnalysisResult, output_path: Path) -> None: ...


@runtime_checkable
class IScorer(Protocol):
    def analyze(self, context: AnalysisContext) -> None: ...
