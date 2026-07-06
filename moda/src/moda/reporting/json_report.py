from __future__ import annotations

import json

from .base import BaseReporter
from ..core.models import AnalysisResult


class JSONReporter(BaseReporter):
    """Render MODA analysis results as JSON."""

    format_name = "json"
    file_extension = ".json"

    def generate(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
