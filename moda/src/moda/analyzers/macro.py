from __future__ import annotations

import io
import re
import zipfile

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import extract_strings

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

class MacroAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "MacroAnalyzer"
        
    @property
    def description(self) -> str:
        return "Extracts and statically analyzes VBA macros."

    def analyze(self, context: AnalysisContext) -> None:
        macro_strings = self._collect_macro_strings(context)
        if not macro_strings:
            return

        context.macro_code.extend(macro_strings)
        macro_text = "\n".join(macro_strings)
        lowered = macro_text.lower()

        self._scan_auto_execution(context, lowered)
        self._scan_process_execution(context, lowered)
        self._scan_downloaders(context, lowered)
        self._scan_obfuscation(context, macro_text, lowered)
        self._scan_api_abuse(context, lowered)

    def _collect_macro_strings(self, context: AnalysisContext) -> list[str]:
        chunks: list[str] = []
        if context.file_type.is_ooxml:
            chunks.extend(self._extract_ooxml_vba_strings(context.file_bytes))
        elif context.file_type.is_ole:
            chunks.extend(self._extract_ole_vba_strings(context.file_bytes))

        if context.file_type.is_macro_enabled and not chunks:
            chunks.extend(
                text
                for text in extract_strings(context.file_bytes, min_length=5)
                if self._looks_like_macro_text(text)
            )
        return list(dict.fromkeys(chunks))

    def _extract_ooxml_vba_strings(self, data: bytes) -> list[str]:
        strings: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    if name.lower().endswith("vbaproject.bin"):
                        strings.extend(extract_strings(archive.read(name), min_length=4))
        except zipfile.BadZipFile:
            return []
        return strings

    def _extract_ole_vba_strings(self, data: bytes) -> list[str]:
        if olefile is None:
            return []
        strings: list[str] = []
        try:
            with olefile.OleFileIO(data) as ole:
                for stream in ole.listdir(streams=True, storages=False):
                    stream_name = "/".join(stream).lower()
                    if "vba" in stream_name or stream_name.endswith(("/dir", "/project")):
                        try:
                            strings.extend(extract_strings(ole.openstream(stream).read(), min_length=4))
                        except Exception:
                            continue
        except Exception:
            return []
        return strings

    def _looks_like_macro_text(self, text: str) -> bool:
        lowered = text.lower()
        return any(
            marker in lowered
            for marker in (
                "sub ",
                "function ",
                "autoopen",
                "document_open",
                "workbook_open",
                "createobject",
                "wscript.shell",
                "powershell",
            )
        )

    def _scan_auto_execution(self, context: AnalysisContext, lowered: str) -> None:
        triggers = [
            "autoopen",
            "auto_open",
            "autoexec",
            "document_open",
            "workbook_open",
            "presentation_open",
            "autoclose",
        ]
        found = [trigger for trigger in triggers if trigger in lowered]
        if found:
            self._add_finding(
                context,
                title="Macro Auto-Execution Trigger",
                description="Macro code contains automatic execution entry points.",
                severity=FindingSeverity.HIGH,
                details={"triggers": found},
            )

    def _scan_process_execution(self, context: AnalysisContext, lowered: str) -> None:
        keywords = [
            "shell",
            "createobject",
            "wscript.shell",
            "cmd.exe",
            "powershell",
            "mshta",
            "rundll32",
            "regsvr32",
            "certutil",
            "bitsadmin",
        ]
        found = [keyword for keyword in keywords if keyword in lowered]
        if found:
            self._add_finding(
                context,
                title="Macro Process Execution",
                description="Macro code references process execution or living-off-the-land tools.",
                severity=FindingSeverity.HIGH,
                details={"keywords": found},
            )

    def _scan_downloaders(self, context: AnalysisContext, lowered: str) -> None:
        keywords = [
            "urldownloadtofile",
            "downloadstring",
            "invoke-webrequest",
            "invoke-expression",
            "xmlhttp",
            "winhttprequest",
            "adodb.stream",
        ]
        found = [keyword for keyword in keywords if keyword in lowered]
        if found:
            self._add_finding(
                context,
                title="Macro Download Capability",
                description="Macro code contains downloader-related APIs or commands.",
                severity=FindingSeverity.HIGH,
                details={"keywords": found},
            )

    def _scan_obfuscation(self, context: AnalysisContext, macro_text: str, lowered: str) -> None:
        chr_calls = len(re.findall(r"\bchrw?\s*\(", lowered))
        concat_count = macro_text.count("&")
        base64_like = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", macro_text)
        hex_literals = len(re.findall(r"&H[0-9A-Fa-f]{2,}", macro_text))

        indicators: dict[str, int] = {}
        if chr_calls >= 5:
            indicators["chr_calls"] = chr_calls
        if concat_count >= 20:
            indicators["string_concatenations"] = concat_count
        if base64_like:
            indicators["base64_like_strings"] = len(base64_like)
        if hex_literals >= 8:
            indicators["hex_literals"] = hex_literals

        if indicators:
            self._add_finding(
                context,
                title="Macro Obfuscation Indicators",
                description="Macro code contains patterns commonly used for string obfuscation.",
                severity=FindingSeverity.MEDIUM,
                details=indicators,
            )

    def _scan_api_abuse(self, context: AnalysisContext, lowered: str) -> None:
        keywords = ["virtualalloc", "rtlmovememory", "writeprocessmemory", "createthread", "callbyname"]
        found = [keyword for keyword in keywords if keyword in lowered]
        if found:
            self._add_finding(
                context,
                title="Macro Native API Abuse",
                description="Macro code references native APIs often used by shellcode loaders.",
                severity=FindingSeverity.CRITICAL,
                details={"keywords": found},
            )
