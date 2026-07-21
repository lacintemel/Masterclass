"""Shared presentation model used by human-readable reporters."""

from __future__ import annotations

from typing import Any

from ..core.models import AnalysisResult


def build_report_view(result: AnalysisResult) -> dict[str, Any]:
    breakdown = result.score_breakdown or {}
    return {
        "analysis_status": str(result.extra.get("analysis_status", "complete")),
        "analysis_id": str(result.extra.get("analysis_id", "")),
        "summary": str(breakdown.get("risk_summary", "")),
        "components": list(breakdown.get("components", [])),
        "potential_impacts": list(breakdown.get("potential_impacts", [])),
        "recovery_steps": list(breakdown.get("recovery_steps", [])),
        "errors": list(result.extra.get("errors", [])),
        "analyzer_statuses": dict(result.extra.get("analyzer_statuses", {})),
    }
