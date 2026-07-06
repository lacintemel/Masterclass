from __future__ import annotations

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import RiskLevel, FindingSeverity
from ..utils.config_loader import load_scoring_config


class RiskScorer(BaseAnalyzer):
    CATEGORY_META = {
        "macro": {
            "label": "Macro behavior",
            "color": "#e05a47",
            "description": "VBA macro, auto-execution, command execution, downloader, or native API behavior.",
        },
        "embedded": {
            "label": "Embedded content",
            "color": "#bd6b44",
            "description": "Embedded scripts, OLE objects, ActiveX controls, executables, or nested documents.",
        },
        "relationship": {
            "label": "External relationships",
            "color": "#d6b46a",
            "description": "Remote templates, external OLE links, UNC/file links, or network-loaded resources.",
        },
        "pdf": {
            "label": "PDF actions",
            "color": "#e05a47",
            "description": "PDF JavaScript, launch/open actions, embedded files, forms, or suspicious structure.",
        },
        "rtf": {
            "label": "RTF exploits",
            "color": "#bd6b44",
            "description": "RTF object data, exploit class hints, DDE, or unusually large encoded blobs.",
        },
        "metadata": {
            "label": "Metadata signals",
            "color": "#6aa7b8",
            "description": "Suspicious metadata or document properties.",
        },
        "yara": {
            "label": "YARA matches",
            "color": "#9b7cf6",
            "description": "Rule matches from configured YARA signatures.",
        },
        "other": {
            "label": "Other findings",
            "color": "#6fcf97",
            "description": "Other analyzer findings that contribute to the total risk.",
        },
    }

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
        severity_weights = {
            FindingSeverity.INFO: self.weights.get("info", 0),
            FindingSeverity.LOW: self.weights.get("low", 5),
            FindingSeverity.MEDIUM: self.weights.get("medium", 15),
            FindingSeverity.HIGH: self.weights.get("high", 30),
            FindingSeverity.CRITICAL: self.weights.get("critical", 50),
        }

        finding_score = 0
        components: dict[str, dict[str, object]] = {}
        finding_details: list[dict[str, object]] = []

        for finding in context.findings:
            points = severity_weights.get(finding.severity, 0)
            category = self._category_for_finding(finding.analyzer, finding.title)
            self._add_component_points(components, category, points, finding.title)
            finding_score += points
            finding_details.append(
                {
                    "title": finding.title,
                    "severity": finding.severity.name.lower(),
                    "analyzer": finding.analyzer,
                    "category": category,
                    "points": points,
                }
            )

        yara_points_per_match = self.config.get("category_caps", {}).get("yara", 30)
        yara_score = 0
        for match in context.yara_matches:
            yara_score += yara_points_per_match
            self._add_component_points(components, "yara", yara_points_per_match, match.rule_name)

        raw_score = finding_score + yara_score
        score = min(raw_score, self.max_score)
        self._normalize_components(components, score)

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
                "finding_score": min(finding_score, self.max_score),
                "raw_score": raw_score,
                "max_score": self.max_score,
                "findings_count": len(context.findings),
                "yara_matches_count": len(context.yara_matches),
                "components": list(components.values()),
                "finding_details": finding_details,
                "risk_summary": self._risk_summary(risk_level, score),
                "potential_impacts": self._potential_impacts(context),
                "recovery_steps": self._recovery_steps(context, risk_level),
            },
        )

    def _add_component_points(
        self,
        components: dict[str, dict[str, object]],
        category: str,
        points: int,
        reason: str,
    ) -> None:
        meta = self.CATEGORY_META.get(category, self.CATEGORY_META["other"])
        component = components.setdefault(
            category,
            {
                "key": category,
                "label": meta["label"],
                "color": meta["color"],
                "description": meta["description"],
                "points": 0,
                "percentage": 0,
                "reasons": [],
            },
        )
        component["points"] = int(component["points"]) + points
        reasons = component["reasons"]
        if isinstance(reasons, list) and reason not in reasons:
            reasons.append(reason)

    def _normalize_components(
        self,
        components: dict[str, dict[str, object]],
        score: int,
    ) -> None:
        total_points = sum(int(component["points"]) for component in components.values())
        for component in components.values():
            raw_points = int(component["points"])
            if total_points > self.max_score and total_points:
                display_points = round((raw_points / total_points) * score, 2)
            else:
                display_points = raw_points
            component["points"] = display_points
            component["percentage"] = round((display_points / self.max_score) * 100, 2)

    def _category_for_finding(self, analyzer: str, title: str) -> str:
        lowered = f"{analyzer} {title}".lower()
        if any(token in lowered for token in ("macro", "vba")):
            return "macro"
        if any(token in lowered for token in ("dde", "customui", "command text")):
            return "macro"
        if any(token in lowered for token in ("embedded", "ole", "activex", "object pool", "package")):
            return "embedded"
        if any(token in lowered for token in ("relationship", "template", "external", "remote")):
            return "relationship"
        if "pdf" in lowered:
            return "pdf"
        if "rtf" in lowered:
            return "rtf"
        if "metadata" in lowered:
            return "metadata"
        return "other"

    def _risk_summary(self, risk_level: RiskLevel, score: int) -> str:
        summaries = {
            RiskLevel.LOW: "No high-risk static indicators were found by the configured checks.",
            RiskLevel.MEDIUM: "The file contains suspicious traits and should be reviewed before use.",
            RiskLevel.HIGH: "The file contains strong malicious-document indicators and should not be opened on a workstation.",
            RiskLevel.CRITICAL: "The file contains critical indicators associated with code execution or payload loading.",
        }
        return f"{summaries[risk_level]} Score: {score}/{self.max_score}."

    def _potential_impacts(self, context: AnalysisContext) -> list[str]:
        impacts: list[str] = []
        titles = " ".join(finding.title.lower() for finding in context.findings)
        text = context.get_all_text().lower()
        combined = f"{titles} {text}"
        if any(token in combined for token in ("macro", "auto-execution", "process execution", "powershell", "cmd.exe")):
            impacts.append("User interaction can trigger command execution, script launch, or second-stage payload download.")
        if any(token in combined for token in ("remote relationship", "external", "attachedtemplate", "template")):
            impacts.append("The document may load remote templates or resources that change behavior after delivery.")
        if any(token in combined for token in ("embedded", "ole", "activex", "object")):
            impacts.append("Embedded objects may drop files, exploit Office components, or hide secondary content.")
        if context.iocs:
            impacts.append("Extracted URLs, domains, IPs, or file paths can indicate network callbacks or persistence artifacts.")
        if not impacts:
            impacts.append("No concrete impact path was identified from static indicators alone.")
        return impacts

    def _recovery_steps(self, context: AnalysisContext, risk_level: RiskLevel) -> list[str]:
        if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} or any(
            finding.severity >= FindingSeverity.HIGH for finding in context.findings
        ):
            return [
                "Disconnect the affected machine from the network if the file was opened.",
                "Preserve the document, email, and endpoint logs for investigation.",
                "Run a full endpoint security scan and collect process, startup, scheduled task, and PowerShell history artifacts.",
                "Block or investigate extracted IOCs in proxy, DNS, mail, and EDR telemetry.",
                "Rotate credentials used on the affected machine if code execution or credential theft is suspected.",
                "Restore from a known-good backup if persistence, encryption, or system modification is confirmed.",
            ]
        if risk_level is RiskLevel.MEDIUM:
            return [
                "Keep the file quarantined until an analyst reviews the suspicious indicators.",
                "Open only in an isolated VM or sandbox if manual inspection is required.",
                "Check mail and endpoint logs for extracted IOCs before releasing the document.",
            ]
        return [
            "Keep standard endpoint protection enabled.",
            "Treat the result as static-analysis-only and rescan if the file source is untrusted.",
        ]
