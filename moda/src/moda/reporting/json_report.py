from __future__ import annotations

import json

from ..core.models import AnalysisResult
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """Render MODA analysis results as JSON."""

    format_name = "json"
    file_extension = ".json"

    def generate(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
