from __future__ import annotations

import html
import io
import re
import zipfile
from urllib.parse import unquote

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..core.exceptions import ResourceLimitError
from ..utils.archive_utils import read_zip_member, validate_zip_archive

class OOXMLAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "OOXMLAnalyzer"
        
    @property
    def description(self) -> str:
        return "Inspects OOXML structures (DOCX, XLSX, PPTX)."

    def can_run(self, context: AnalysisContext) -> bool:
        return context.file_type in (
            FileType.OOXML_DOCX, FileType.OOXML_DOCM, 
            FileType.OOXML_XLSX, FileType.OOXML_XLSM, 
            FileType.OOXML_PPTX, FileType.OOXML_PPTM
        )

    def analyze(self, context: AnalysisContext) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as z:
                validate_zip_archive(z, context.limits)
                files = z.namelist()
                lowered_files = {name.lower(): name for name in files}
                context.extra["ooxml_package"] = self._package_profile(files)
                vba_projects = [
                    original
                    for lowered, original in lowered_files.items()
                    if lowered.endswith("vbaproject.bin")
                ]
                if vba_projects:
                    severity = (
                        FindingSeverity.CRITICAL
                        if context.file_type in {FileType.OOXML_DOCX, FileType.OOXML_XLSX, FileType.OOXML_PPTX}
                        else FindingSeverity.HIGH
                    )
                    title = (
                        "Macro Project In Non-Macro OOXML"
                        if severity is FindingSeverity.CRITICAL
                        else "VBA Macros Present"
                    )
                    self._add_finding(
                        context,
                        title,
                        "OOXML document contains a vbaProject.bin macro project.",
                        severity,
                        {"projects": vba_projects},
                    )

                embeddings = [f for f in files if 'embeddings/' in f.lower()]
                if embeddings:
                    self._add_finding(context, "Embedded Objects", f"Found {len(embeddings)} embedded objects", FindingSeverity.MEDIUM, {"files": embeddings})

                self._inspect_xml_parts(context, z)
                self._inspect_excel_parts(context, z)
        except zipfile.BadZipFile as e:
            context.errors.append(f"OOXML parsing error: {e}")

    def _package_profile(self, files: list[str]) -> dict[str, object]:
        lowered = [name.lower() for name in files]
        return {
            "part_count": len(files),
            "has_macros": any(name.endswith("vbaproject.bin") for name in lowered),
            "embedded_count": sum(1 for name in lowered if "/embeddings/" in name),
            "activex_count": sum(1 for name in lowered if "/activex/" in name),
            "external_link_parts": sum(1 for name in lowered if "externallinks/" in name),
            "connection_parts": sum(1 for name in lowered if "connections" in name or "querytables/" in name),
        }

    def _inspect_xml_parts(self, context: AnalysisContext, archive: zipfile.ZipFile) -> None:
        dde_hits: list[str] = []
        ole_hits: list[str] = []
        active_content: list[str] = []
        suspicious_text: list[str] = []
        update_fields: list[str] = []
        exploit_protocols: list[str] = []
        mshtml_activex: list[str] = []

        for name in archive.namelist():
            lowered_name = name.lower()
            if not lowered_name.endswith((".xml", ".rels")):
                continue
            try:
                text = read_zip_member(
                    archive, name, context.limits, max_bytes=context.limits.max_text_part_bytes
                ).decode("utf-8", errors="ignore")
            except ResourceLimitError:
                raise
            except Exception:
                continue
            lowered = self._normalize_text(text)

            if any(token in lowered for token in ("ddeauto", "dde ", "ddeexec")):
                dde_hits.append(name)
            if any(token in lowered for token in ("<o:oleobject", "oleobject", "olelink", "objectembed")):
                ole_hits.append(name)
            if any(token in lowered for token in ("activex", "customui", "onaction=", "xlink:href")):
                active_content.append(name)
            if self._contains_suspicious_command_text(lowered):
                suspicious_text.append(name)
            if "updatefields" in lowered and 'val="true"' in lowered:
                update_fields.append(name)
            if self._contains_office_exploit_protocol(lowered):
                exploit_protocols.append(name)
            if self._contains_mshtml_activex_chain(lowered):
                mshtml_activex.append(name)

        if exploit_protocols:
            self._add_finding(
                context,
                title="OOXML Office Exploit Protocol",
                description="Document XML references protocol handlers associated with Office vulnerability exploitation.",
                severity=FindingSeverity.CRITICAL,
                details={"parts": sorted(set(exploit_protocols))[:20]},
            )
        if mshtml_activex:
            self._add_finding(
                context,
                title="OOXML MSHTML/ActiveX Exploit Markers",
                description="Document XML contains MSHTML, ActiveX, classid, or OLE markers seen in Office exploit chains.",
                severity=FindingSeverity.CRITICAL,
                details={"parts": sorted(set(mshtml_activex))[:20]},
            )
        if dde_hits:
            self._add_finding(
                context,
                title="OOXML DDE Field",
                description="Document XML contains DDE field instructions that can launch commands.",
                severity=FindingSeverity.HIGH,
                details={"parts": sorted(set(dde_hits))[:20]},
            )
        if ole_hits:
            self._add_finding(
                context,
                title="OOXML OLE Link Or Object",
                description="Document XML references OLE linked or embedded object behavior.",
                severity=FindingSeverity.HIGH,
                details={"parts": sorted(set(ole_hits))[:20]},
            )
        if active_content:
            self._add_finding(
                context,
                title="OOXML Active Content Markers",
                description="Document XML contains active content markers such as ActiveX or custom UI callbacks.",
                severity=FindingSeverity.MEDIUM,
                details={"parts": sorted(set(active_content))[:20]},
            )
        if suspicious_text:
            self._add_finding(
                context,
                title="Suspicious Command Text In OOXML",
                description="Text-bearing OOXML parts reference commands often used by malicious documents.",
                severity=FindingSeverity.MEDIUM,
                details={"parts": sorted(set(suspicious_text))[:20]},
            )
        if update_fields:
            self._add_finding(
                context,
                title="OOXML Auto Field Update",
                description="Document settings request field updates, which can combine with links or DDE fields.",
                severity=FindingSeverity.MEDIUM,
                details={"parts": sorted(set(update_fields))[:20]},
            )

    def _inspect_excel_parts(self, context: AnalysisContext, archive: zipfile.ZipFile) -> None:
        external_link_parts: list[str] = []
        connection_parts: list[str] = []
        suspicious_formulas: list[str] = []
        very_hidden_sheets: list[str] = []

        for name in archive.namelist():
            lowered_name = name.lower()
            if not lowered_name.startswith("xl/"):
                continue
            if "externallinks/" in lowered_name:
                external_link_parts.append(name)
            if "connections" in lowered_name or "querytables/" in lowered_name:
                connection_parts.append(name)
            if not lowered_name.endswith((".xml", ".rels")):
                continue
            try:
                text = read_zip_member(
                    archive, name, context.limits, max_bytes=context.limits.max_text_part_bytes
                ).decode("utf-8", errors="ignore")
            except ResourceLimitError:
                raise
            except Exception:
                continue
            lowered = self._normalize_text(text)
            if self._contains_suspicious_formula(lowered):
                suspicious_formulas.append(name)
            if 'state="veryhidden"' in lowered:
                very_hidden_sheets.append(name)

        if external_link_parts:
            self._add_finding(
                context,
                title="Excel External Links",
                description="Workbook contains external link parts that can reference remote or local content.",
                severity=FindingSeverity.MEDIUM,
                details={"parts": sorted(set(external_link_parts))[:25]},
            )
        if connection_parts:
            self._add_finding(
                context,
                title="Excel Data Connections",
                description="Workbook contains connection or query table parts that can retrieve external data.",
                severity=FindingSeverity.MEDIUM,
                details={"parts": sorted(set(connection_parts))[:25]},
            )
        if suspicious_formulas:
            self._add_finding(
                context,
                title="Suspicious Excel Formula",
                description="Workbook formulas reference functions or command-like patterns abused in malicious spreadsheets.",
                severity=FindingSeverity.HIGH,
                details={"parts": sorted(set(suspicious_formulas))[:25]},
            )
        if very_hidden_sheets:
            self._add_finding(
                context,
                title="Excel Very Hidden Sheet",
                description="Workbook contains veryHidden sheets, often used to conceal staging data or formulas.",
                severity=FindingSeverity.LOW,
                details={"parts": sorted(set(very_hidden_sheets))[:25]},
            )

    def _contains_suspicious_command_text(self, lowered: str) -> bool:
        return bool(
            re.search(
                r"\b(?:powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\b",
                lowered,
            )
        )

    def _contains_office_exploit_protocol(self, lowered: str) -> bool:
        return any(
            token in lowered
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

    def _contains_mshtml_activex_chain(self, lowered: str) -> bool:
        has_mshtml_or_html = any(token in lowered for token in ("mshtml", "htmlfile", ".html", "mhtml:"))
        has_activex_or_class = any(token in lowered for token in ("activex", "classid", "clsid:", "oleobject"))
        return has_mshtml_or_html and has_activex_or_class

    def _normalize_text(self, text: str) -> str:
        current = html.unescape(text)
        for _ in range(2):
            decoded = unquote(current)
            if decoded == current:
                break
            current = decoded
        return current.lower().replace("\x00", "")

    def _contains_suspicious_formula(self, lowered: str) -> bool:
        formula_markers = (
            "hyperlink(",
            "webservice(",
            "filterxml(",
            "cmd|",
            "powershell",
            "mshta",
            "dde",
            "rundll32",
            "regsvr32",
        )
        return any(marker in lowered for marker in formula_markers)
