from __future__ import annotations

import zipfile
import io
import re

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity

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
                files = z.namelist()
                lowered_files = {name.lower(): name for name in files}
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
        except Exception as e:
            context.errors.append(f"OOXML parsing error: {e}")

    def _inspect_xml_parts(self, context: AnalysisContext, archive: zipfile.ZipFile) -> None:
        dde_hits: list[str] = []
        ole_hits: list[str] = []
        active_content: list[str] = []
        suspicious_text: list[str] = []

        for name in archive.namelist():
            lowered_name = name.lower()
            if not lowered_name.endswith((".xml", ".rels")):
                continue
            try:
                text = archive.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue
            lowered = text.lower()

            if any(token in lowered for token in ("ddeauto", "dde ", "ddeexec")):
                dde_hits.append(name)
            if any(token in lowered for token in ("<o:oleobject", "oleobject", "olelink", "objectembed")):
                ole_hits.append(name)
            if any(token in lowered for token in ("activex", "customui", "onaction=", "xlink:href")):
                active_content.append(name)
            if self._contains_suspicious_command_text(lowered):
                suspicious_text.append(name)

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

    def _contains_suspicious_command_text(self, lowered: str) -> bool:
        return bool(
            re.search(
                r"\b(?:powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\b",
                lowered,
            )
        )
