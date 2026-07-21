from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import unquote

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FindingSeverity
from ..utils.archive_utils import read_zip_member, validate_zip_archive
from ..utils.regex_patterns import URL_PATTERN


class RelationshipAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "RelationshipAnalyzer"

    @property
    def description(self) -> str:
        return "Analyzes document relationships."

    def analyze(self, context: AnalysisContext) -> None:
        remote_relationships: list[dict[str, str]] = []
        if context.file_type.is_ooxml:
            remote_relationships.extend(self._extract_ooxml_relationships(context))

        if not context.file_type.is_ooxml:
            remote_relationships.extend(
                {
                    "target": target,
                    "type": "text-url",
                    "mode": "",
                    "source": "text",
                }
                for target in self._extract_remote_urls_from_text(context.get_all_text())
            )

        deduped = self._dedupe_relationships(remote_relationships)
        targets = [item["target"] for item in deduped]
        context.extra["remote_relationships"] = targets
        context.extra["remote_relationship_details"] = deduped

        if deduped:
            exploit_protocol = [
                item for item in deduped if self._uses_office_exploit_protocol(item["target"])
            ]
            if exploit_protocol:
                self._add_finding(
                    context,
                    title="Office Exploit Protocol Relationship",
                    description="Document relationships reference protocol handlers used by Office exploit chains.",
                    severity=FindingSeverity.CRITICAL,
                    details={
                        "relationships": exploit_protocol[:25],
                        "relationship_count": len(exploit_protocol),
                    },
                )
            high_risk = [
                item
                for item in deduped
                if self._is_high_risk_relationship(item["type"], item["target"])
            ]
            if high_risk:
                self._add_finding(
                    context,
                    title="High-Risk External OOXML Relationship",
                    description="Document uses external relationships commonly abused for template injection, OLE loading, or payload retrieval.",
                    severity=FindingSeverity.HIGH,
                    details={
                        "relationships": high_risk[:25],
                        "relationship_count": len(high_risk),
                    },
                )
            self._add_finding(
                context,
                title="Remote Document Relationships",
                description="Document references external or remote resources.",
                severity=FindingSeverity.MEDIUM,
                details={"targets": targets[:25], "target_count": len(targets)},
            )

    def _extract_ooxml_relationships(self, context: AnalysisContext) -> list[dict[str, str]]:
        relationships: list[dict[str, str]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as archive:
                validate_zip_archive(archive, context.limits)
                for name in archive.namelist():
                    if not name.lower().endswith(".rels"):
                        continue
                    relationships.extend(
                        self._parse_rels(
                            name,
                            read_zip_member(
                                archive,
                                name,
                                context.limits,
                                max_bytes=context.limits.max_text_part_bytes,
                            ),
                        )
                    )
        except zipfile.BadZipFile:
            return []
        return relationships

    def _parse_rels(self, source: str, data: bytes) -> list[dict[str, str]]:
        relationships: list[dict[str, str]] = []
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            return relationships
        for element in root.iter():
            target = element.attrib.get("Target", "")
            target_mode = element.attrib.get("TargetMode", "")
            rel_type = element.attrib.get("Type", "")
            if (
                (
                    self._is_remote_target(target)
                    or self._uses_office_exploit_protocol(target)
                    or target_mode.lower() == "external"
                )
                or "attachedtemplate" in rel_type.lower()
                and target
            ):
                relationships.append(
                    {
                        "target": target,
                        "type": rel_type,
                        "mode": target_mode,
                        "source": source,
                    }
                )
        return relationships

    def _extract_remote_urls_from_text(self, text: str) -> list[str]:
        return [match.group() for match in URL_PATTERN.finditer(text)]

    def _is_remote_target(self, target: str) -> bool:
        normalized = self._normalize_target(target)
        return bool(
            re.match(
                r"(?i)^(?:https?|ftp|file|mhtml|ms-msdt|search-ms|ms-officecmd|\\\\)", normalized
            )
        )

    def _is_high_risk_relationship(self, rel_type: str, target: str) -> bool:
        lowered_type = rel_type.lower()
        lowered_target = self._normalize_target(target)
        return (
            "attachedtemplate" in lowered_type
            or "oleobject" in lowered_type
            or "package" in lowered_type
            or "activex" in lowered_type
            or self._uses_office_exploit_protocol(target)
            or lowered_target.startswith(("file:", "\\\\"))
            or lowered_target.endswith(
                (".dotm", ".dot", ".xlam", ".hta", ".vbs", ".js", ".exe", ".dll", ".html", ".hta")
            )
        )

    def _uses_office_exploit_protocol(self, target: str) -> bool:
        normalized = self._normalize_target(target)
        return any(
            token in normalized
            for token in (
                "ms-msdt:",
                "mhtml:",
                "search-ms:",
                "ms-officecmd:",
                "ms-excel:",
                "ms-word:",
                "ms-powerpoint:",
                "hcp:",
                "script:",
                "javascript:",
            )
        )

    def _normalize_target(self, target: str) -> str:
        current = target
        for _ in range(2):
            decoded = unquote(current)
            if decoded == current:
                break
            current = decoded
        return current.lower().replace("&amp;", "&")

    def _dedupe_relationships(self, relationships: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, str]] = []
        for item in relationships:
            key = (item.get("target", ""), item.get("type", ""), item.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return sorted(deduped, key=lambda item: item.get("target", ""))
