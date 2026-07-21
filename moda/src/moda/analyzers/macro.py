from __future__ import annotations

import io
import re
import zipfile

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import extract_strings
from ..utils.archive_utils import read_zip_member, validate_zip_archive

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:  # pragma: no cover - optional analyzer dependency
    VBA_Parser = None

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

        if not self._has_macro_presence_finding(context):
            self._add_finding(
                context,
                title="VBA Macros Present",
                description="Document contains extractable VBA macro code.",
                severity=FindingSeverity.HIGH,
                details={"source": "macro extraction"},
            )

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
        chunks.extend(self._extract_vba_with_oletools(context))
        if context.file_type.is_ooxml and not chunks:
            chunks.extend(self._extract_ooxml_vba_strings(context))
        elif context.file_type.is_ole and not chunks:
            chunks.extend(self._extract_ole_vba_strings(context.file_bytes))

        if context.file_type.is_macro_enabled and not chunks:
            chunks.extend(
                text
                for text in extract_strings(
                    context.file_bytes,
                    min_length=5,
                    max_strings=context.limits.max_extracted_strings,
                    max_string_length=context.limits.max_string_length,
                )
                if self._looks_like_macro_text(text)
            )
        return list(dict.fromkeys(chunks))

    def _extract_vba_with_oletools(self, context: AnalysisContext) -> list[str]:
        if VBA_Parser is None or not (context.file_type.is_ole or context.file_type.is_ooxml):
            return []

        parser = None
        try:
            parser = VBA_Parser(str(context.file_path), data=context.file_bytes)
            if not parser.detect_vba_macros():
                return []
            modules: list[str] = []
            for _, stream_path, vba_filename, vba_code in parser.extract_macros():
                if not vba_code:
                    continue
                modules.append(f"' {stream_path or vba_filename}\n{vba_code}")
            return modules
        except Exception as exc:
            context.errors.append(f"VBA parser could not inspect the document: {exc}")
            context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
            return []
        finally:
            if parser is not None:
                try:
                    parser.close()
                except Exception:
                    pass

    def _extract_ooxml_vba_strings(self, context: AnalysisContext) -> list[str]:
        strings: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as archive:
                validate_zip_archive(archive, context.limits)
                for name in archive.namelist():
                    if name.lower().endswith("vbaproject.bin"):
                        strings.extend(
                            extract_strings(
                                read_zip_member(archive, name, context.limits),
                                min_length=4,
                                max_strings=context.limits.max_extracted_strings,
                                max_string_length=context.limits.max_string_length,
                            )
                        )
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
                            size = ole.get_size(stream)
                            if size > context.limits.max_archive_entry_bytes:
                                context.errors.append(
                                    f"VBA stream skipped because it exceeds {context.limits.max_archive_entry_bytes} bytes"
                                )
                                context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
                                continue
                            data = ole.openstream(stream).read(context.limits.max_archive_entry_bytes + 1)
                            strings.extend(
                                extract_strings(
                                    data,
                                    min_length=4,
                                    max_strings=context.limits.max_extracted_strings,
                                    max_string_length=context.limits.max_string_length,
                                )
                            )
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

    def _has_macro_presence_finding(self, context: AnalysisContext) -> bool:
        return any(
            finding.title in {"VBA Macros Present", "Macro Project In Non-Macro OOXML"}
            for finding in context.findings
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
        keywords = [
            "virtualalloc",
            "rtlmovememory",
            "writeprocessmemory",
            "createthread",
            "callbyname",
        ]
        found = [keyword for keyword in keywords if keyword in lowered]
        if found:
            self._add_finding(
                context,
                title="Macro Native API Abuse",
                description="Macro code references native APIs often used by shellcode loaders.",
                severity=FindingSeverity.CRITICAL,
                details={"keywords": found},
            )
