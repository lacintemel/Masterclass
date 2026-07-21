"""Static inspection for Microsoft Office 2003 XML documents."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..core.exceptions import ResourceLimitError
from ..utils.file_utils import extract_strings
from ..utils.regex_patterns import URL_PATTERN


class OfficeXMLAnalyzer(BaseAnalyzer):
    COMMAND_RE = re.compile(
        r"\b(?:powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\b",
        re.IGNORECASE,
    )
    EXPLOIT_PROTOCOLS = (
        "ms-msdt:",
        "mhtml:",
        "search-ms:",
        "ms-officecmd:",
        "script:",
        "javascript:",
    )
    SAFE_SCHEMA_DOMAINS = ("schemas.microsoft.com", "www.w3.org")

    @property
    def name(self) -> str:
        return "OfficeXMLAnalyzer"

    @property
    def description(self) -> str:
        return "Inspects Microsoft Office 2003 XML documents and SpreadsheetML content."

    def can_run(self, context: AnalysisContext) -> bool:
        return context.file_type is FileType.OFFICE_XML

    def analyze(self, context: AnalysisContext) -> None:
        if len(context.file_bytes) > context.limits.max_text_part_bytes:
            raise ResourceLimitError(
                f"Office XML exceeds {context.limits.max_text_part_bytes} byte text limit"
            )
        text = self._decode(context.file_bytes)
        lowered = text.lower()
        context.extra["office_xml"] = {
            "format": self._format_name(lowered),
            "decoded_characters": len(text),
        }

        has_dtd = "<!doctype" in lowered or "<!entity" in lowered
        if has_dtd:
            self._add_finding(
                context,
                "Office XML DTD Or Entity Declaration",
                "The document declares a DTD or entity and was not expanded during analysis.",
                FindingSeverity.HIGH,
                {"dtd": "<!doctype" in lowered, "entity": "<!entity" in lowered},
            )
            context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
            visible_text = text
        else:
            visible_text = self._parse_visible_text(context, text)

        extracted = extract_strings(
            context.file_bytes,
            min_length=5,
            max_strings=context.limits.max_extracted_strings,
            max_string_length=context.limits.max_string_length,
        )
        context.raw_strings.extend(extracted)
        if visible_text:
            context.raw_strings.append(visible_text[: context.limits.max_text_part_bytes])

        if not has_dtd:
            self._extract_metadata(context, text)
        self._scan_external_targets(context, text)
        self._scan_active_content(context, text)
        self._scan_embedded_data(context, text)

    def _decode(self, data: bytes) -> str:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="replace")
        return data.decode("utf-8-sig", errors="replace")

    def _parse_visible_text(self, context: AnalysisContext, text: str) -> str:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            context.errors.append(f"Office XML parsing error: {exc}")
            context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
            return text
        return " ".join(value.strip() for value in root.itertext() if value.strip())

    def _format_name(self, lowered: str) -> str:
        if "office:spreadsheet" in lowered or "<workbook" in lowered:
            return "spreadsheetml"
        if "office:word" in lowered or "wordml" in lowered:
            return "wordml"
        return "office_xml"

    def _extract_metadata(self, context: AnalysisContext, text: str) -> None:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return
        wanted = {
            "author": "Author",
            "lastauthor": "LastSavedBy",
            "created": "CreateTime",
            "lastsaved": "LastSavedTime",
            "company": "Company",
            "version": "Version",
        }
        for element in root.iter():
            local_name = element.tag.rsplit("}", 1)[-1].lower()
            key = wanted.get(local_name)
            if key and element.text and element.text.strip():
                context.metadata.setdefault(key, element.text.strip()[:500])

    def _scan_external_targets(self, context: AnalysisContext, text: str) -> None:
        targets = []
        for match in URL_PATTERN.finditer(text):
            value = match.group().rstrip("\"'<>),.;")
            lowered = value.lower()
            if any(domain in lowered for domain in self.SAFE_SCHEMA_DOMAINS):
                continue
            if value not in targets:
                targets.append(value)
        lowered_text = text.lower()
        protocols = sorted(
            protocol for protocol in self.EXPLOIT_PROTOCOLS if protocol in lowered_text
        )
        if protocols:
            self._add_finding(
                context,
                "Office XML Exploit Protocol",
                "The Office XML document references protocol handlers associated with exploit chains.",
                FindingSeverity.CRITICAL,
                {"protocols": protocols, "targets": targets[:25]},
            )
        elif targets:
            self._add_finding(
                context,
                "Office XML External Link",
                "The Office XML document references external network resources.",
                FindingSeverity.MEDIUM,
                {"targets": targets[:25], "target_count": len(targets)},
            )

    def _scan_active_content(self, context: AnalysisContext, text: str) -> None:
        lowered = text.lower()
        commands = sorted({match.group().lower() for match in self.COMMAND_RE.finditer(text)})
        if commands:
            self._add_finding(
                context,
                "Suspicious Command Text In Office XML",
                "The Office XML document contains command-line tools frequently abused by malware.",
                FindingSeverity.HIGH,
                {"commands": commands},
            )
        dde_markers = sorted(
            marker for marker in ("ddeauto", "dde ", "ddeexec") if marker in lowered
        )
        if dde_markers:
            self._add_finding(
                context,
                "Office XML DDE Field",
                "The document contains Dynamic Data Exchange markers capable of launching external actions.",
                FindingSeverity.HIGH,
                {"markers": dde_markers},
            )
        macro_markers = sorted(
            marker
            for marker in ("auto_open", "autoopen", "workbook_open", "createobject")
            if marker in lowered
        )
        if macro_markers:
            self._add_finding(
                context,
                "Office XML Macro Or Auto-Execution Marker",
                "The XML content references macro or automatic execution primitives.",
                FindingSeverity.HIGH,
                {"markers": macro_markers},
            )

    def _scan_embedded_data(self, context: AnalysisContext, text: str) -> None:
        lowered = text.lower()
        encoded_blobs = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{256,}={0,2}", text)
        if "bindata" in lowered or encoded_blobs:
            self._add_finding(
                context,
                "Office XML Embedded Binary Data",
                "The XML document contains embedded or long encoded binary data requiring review.",
                FindingSeverity.MEDIUM,
                {
                    "bin_data_marker": "bindata" in lowered,
                    "encoded_blob_count": len(encoded_blobs),
                },
            )
