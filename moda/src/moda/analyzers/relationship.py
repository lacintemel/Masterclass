from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FindingSeverity
from ..utils.regex_patterns import URL_PATTERN

class RelationshipAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "RelationshipAnalyzer"
    @property
    def description(self) -> str: return "Analyzes document relationships."

    def analyze(self, context: AnalysisContext) -> None:
        remote_targets = []
        if context.file_type.is_ooxml:
            remote_targets.extend(self._extract_ooxml_relationships(context.file_bytes))

        if not context.file_type.is_ooxml:
            remote_targets.extend(self._extract_remote_urls_from_text(context.get_all_text()))
        deduped = sorted(set(remote_targets))
        context.extra["remote_relationships"] = deduped

        if deduped:
            self._add_finding(
                context,
                title="Remote Document Relationships",
                description="Document references external or remote resources.",
                severity=FindingSeverity.MEDIUM,
                details={"targets": deduped[:25], "target_count": len(deduped)},
            )

    def _extract_ooxml_relationships(self, data: bytes) -> list[str]:
        targets: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    if not name.lower().endswith(".rels"):
                        continue
                    targets.extend(self._parse_rels(archive.read(name)))
        except zipfile.BadZipFile:
            return []
        return targets

    def _parse_rels(self, data: bytes) -> list[str]:
        targets: list[str] = []
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            return targets
        for element in root.iter():
            target = element.attrib.get("Target", "")
            target_mode = element.attrib.get("TargetMode", "")
            rel_type = element.attrib.get("Type", "")
            if self._is_remote_target(target) or target_mode.lower() == "external":
                targets.append(target)
            elif "attachedtemplate" in rel_type.lower() and target:
                targets.append(target)
        return targets

    def _extract_remote_urls_from_text(self, text: str) -> list[str]:
        return [match.group() for match in URL_PATTERN.finditer(text)]

    def _is_remote_target(self, target: str) -> bool:
        return bool(re.match(r"(?i)^(?:https?|ftp|file|\\\\)", target))
