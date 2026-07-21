from __future__ import annotations

import re
from typing import Any

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import calculate_entropy, extract_strings
from ..utils.regex_patterns import URL_PATTERN


class OLEAnalyzer(BaseAnalyzer):
    POWERPOINT_STREAM_NAMES = {
        "powerpoint document",
        "current user",
        "pictures",
        "document summary information",
        "summary information",
    }
    OFFICE_EXPLOIT_PROTOCOLS = (
        "ms-msdt:",
        "mhtml:",
        "search-ms:",
        "ms-officecmd:",
        "ms-powerpoint:",
        "hcp:",
        "script:",
        "javascript:",
    )
    COMMAND_RE = re.compile(
        r"\b(?:powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\b",
        re.IGNORECASE,
    )
    EXTERNAL_TARGET_RE = re.compile(
        r"(?i)(?:\b(?:file|mhtml|ms-msdt|search-ms|ms-officecmd|"
        r"ms-powerpoint|script|javascript):[^\s\"'<>)]{3,}|"
        r"\\\\[a-z0-9._$-]+\\[^\s\"'<>]+)"
    )
    OLE_MARKERS = (
        "activex",
        "classid",
        "clsid:",
        "dde ",
        "ddeauto",
        "ddeexec",
        "ole10native",
        "olelink",
        "oleobject",
        "objectpool",
        "packager",
    )

    @property
    def name(self) -> str:
        return "OLEAnalyzer"
        
    @property
    def description(self) -> str:
        return "Inspects OLE compound document structures."

    def can_run(self, context: AnalysisContext) -> bool:
        return context.file_type in (FileType.OLE_DOC, FileType.OLE_XLS, FileType.OLE_PPT)

    def analyze(self, context: AnalysisContext) -> None:
        if olefile is None:
            context.errors.append("OLE parsing skipped: olefile is not installed")
            context.extra.setdefault("capability_overrides", {})[self.name] = "unavailable"
            return
        if not olefile.isOleFile(context.file_bytes):
            return
            
        try:
            with olefile.OleFileIO(context.file_bytes) as ole:
                self._inspect_streams(context, ole)
                self._check_vba_storage(context, ole)
                self._check_activex(context, ole)
                self._inspect_powerpoint_streams(context, ole)
                self._record_directory_tree(context, ole)
        except Exception as e:
            context.errors.append(f"OLE parsing error: {e}")
            context.extra.setdefault("capability_overrides", {})[self.name] = "failed"

    def _inspect_streams(self, context: AnalysisContext, ole: Any) -> None:
        streams = ole.listdir(streams=True, storages=False)
        stream_names = ["/".join(stream) for stream in streams]
        stream_entries = self._build_stream_entries(ole, streams)
        context.extra["ole_streams"] = stream_names
        context.extra["ole_stream_count"] = len(stream_entries)
        context.extra["ole_stream_inventory"] = stream_entries

        self._add_finding(
            context,
            "OLE Stream Inventory",
            f"OLE container exposes {len(stream_entries)} streams for static inspection.",
            FindingSeverity.INFO,
            {
                "stream_count": len(stream_entries),
                "streams": stream_entries[:50],
            },
        )

        for stream in streams:
            stream_name = "/".join(stream)
            lowered = stream_name.lower()
            if "encryptedpackage" in lowered or "encryptioninfo" in lowered:
                self._add_finding(
                    context,
                    "Encrypted Office Package",
                    (
                        "OLE container includes encrypted Office package streams; "
                        "static content inspection may be limited."
                    ),
                    FindingSeverity.MEDIUM,
                    {"stream": stream_name},
                )
                context.extra.setdefault("capability_overrides", {})[self.name] = "partial"
            if "objectpool" in lowered:
                self._add_finding(
                    context,
                    "OLE Object Pool",
                    "Contains an ObjectPool storage often used for embedded objects.",
                    FindingSeverity.MEDIUM,
                    {"stream": stream_name},
                )
            if any(marker in lowered for marker in ("package", "ole10native", "equation native")):
                self._add_finding(
                    context,
                    "OLE Embedded Package Stream",
                    "Contains stream names associated with embedded packages or OLE objects.",
                    FindingSeverity.MEDIUM,
                    {"stream": stream_name},
                )
            if any(marker in lowered for marker in ("equation", "eqnedt32", "dde")):
                self._add_finding(
                    context,
                    "OLE Exploit-Or-DDE Hint",
                    (
                        "Stream names reference Equation Editor or DDE-related behavior "
                        "abused by malicious documents."
                    ),
                    FindingSeverity.HIGH,
                    {"stream": stream_name},
                )
            if any(marker in lowered for marker in ("vba", "macros")):
                self._inspect_macro_stream_content(context, ole, stream, stream_name)

        if len(stream_names) > 100:
            self._add_finding(
                context,
                "Large OLE Directory Tree",
                "OLE document contains an unusually large number of streams/storages.",
                FindingSeverity.LOW,
                {"stream_count": len(stream_names)},
            )

    def _check_vba_storage(self, context: AnalysisContext, ole: Any) -> None:
        vba_paths = ("Macros/VBA", "_VBA_PROJECT_CUR", "VBA", "VBA/dir")
        existing = [path for path in vba_paths if self._ole_exists(ole, path)]
        if existing:
            self._add_finding(
                context,
                "VBA Macros Present",
                "Document contains a VBA project storage.",
                FindingSeverity.HIGH,
                {"paths": existing},
            )

    def _check_activex(self, context: AnalysisContext, ole: Any) -> None:
        stream_names = [
            "/".join(stream).lower()
            for stream in ole.listdir(streams=True, storages=False)
        ]
        activex = [name for name in stream_names if "activex" in name or "ocx" in name]
        if activex:
            self._add_finding(
                context,
                "ActiveX Controls Present",
                "OLE document references ActiveX-related storages or streams.",
                FindingSeverity.HIGH,
                {"streams": activex[:25], "count": len(activex)},
            )

    def _record_directory_tree(self, context: AnalysisContext, ole: Any) -> None:
        streams = ole.listdir(streams=True, storages=False)
        storages = ole.listdir(streams=False, storages=True)
        context.extra["ole_stream_count"] = len(streams)
        context.extra["ole_storage_count"] = len(storages)
        context.extra["ole_directory_count"] = len(streams) + len(storages)

    def _inspect_macro_stream_content(
        self,
        context: AnalysisContext,
        ole: Any,
        stream: list[str],
        stream_name: str,
    ) -> None:
        try:
            data = self._read_ole_stream(context, ole, stream)
        except Exception:
            return

        strings = extract_strings(
            data,
            min_length=4,
            max_strings=context.limits.max_extracted_strings,
            max_string_length=context.limits.max_string_length,
        )
        context.macro_code.extend(strings)
        entropy = calculate_entropy(data)
        if entropy >= 7.2 and len(data) > 1024:
            self._add_finding(
                context,
                "High Entropy VBA Stream",
                "A VBA-related stream has high entropy and may be compressed or obfuscated.",
                FindingSeverity.MEDIUM,
                {"stream": stream_name, "entropy": round(entropy, 3), "size": len(data)},
            )

    def _ole_exists(self, ole: Any, path: str) -> bool:
        try:
            return bool(ole.exists(path))
        except Exception:
            return False

    def _build_stream_entries(self, ole: Any, streams: list[list[str]]) -> list[dict[str, object]]:
        entries: list[dict[str, object]] = []
        for index, stream in enumerate(streams, start=1):
            name = "/".join(stream)
            try:
                size = int(ole.get_size(stream))
            except Exception:
                size = None
            entries.append(
                {
                    "index": index,
                    "name": name,
                    "display_name": self._escape_control_chars(name),
                    "size": size,
                }
            )
        return entries

    def _escape_control_chars(self, value: str) -> str:
        return "".join(
            f"\\x{ord(char):02x}" if ord(char) < 32 else char
            for char in value
        )

    def _inspect_powerpoint_streams(self, context: AnalysisContext, ole: Any) -> None:
        if context.file_type is not FileType.OLE_PPT:
            return

        candidates = self._powerpoint_stream_candidates(ole)
        if not candidates:
            return

        stream_strings: list[str] = []
        stream_names: list[str] = []
        for stream in candidates:
            stream_name = "/".join(stream)
            try:
                data = self._read_ole_stream(context, ole, stream)
            except Exception:
                continue
            strings = extract_strings(
                data,
                min_length=5,
                max_strings=context.limits.max_extracted_strings,
                max_string_length=context.limits.max_string_length,
            )
            if not strings:
                continue
            stream_names.append(stream_name)
            stream_strings.extend(strings)
            if len(stream_strings) >= context.limits.max_extracted_strings:
                stream_strings = stream_strings[: context.limits.max_extracted_strings]
                break

        if not stream_strings:
            return

        context.extra["powerpoint_ole_streams"] = stream_names
        context.embedded_strings.extend(stream_strings[:200])

        combined = "\n".join(stream_strings)
        lowered = combined.lower()
        external_targets = self._extract_external_targets(stream_strings)
        exploit_protocols = sorted(
            protocol for protocol in self.OFFICE_EXPLOIT_PROTOCOLS if protocol in lowered
        )
        command_hits = sorted(
            set(match.group().lower() for match in self.COMMAND_RE.finditer(combined))
        )
        ole_hits = sorted(marker for marker in self.OLE_MARKERS if marker in lowered)

        if exploit_protocols:
            self._add_finding(
                context,
                "PowerPoint Office Exploit Protocol",
                (
                    "Legacy PowerPoint binary content references protocol handlers "
                    "associated with Office exploit chains."
                ),
                FindingSeverity.CRITICAL,
                {"protocols": exploit_protocols, "streams": stream_names[:10]},
            )
        if external_targets:
            self._add_finding(
                context,
                "PowerPoint External Link",
                "Legacy PowerPoint binary content references external or remote resources.",
                FindingSeverity.MEDIUM,
                {
                    "targets": external_targets[:25],
                    "target_count": len(external_targets),
                    "streams": stream_names[:10],
                },
            )
        if command_hits:
            self._add_finding(
                context,
                "Suspicious Command Text In PowerPoint",
                (
                    "Legacy PowerPoint binary content references commands often used "
                    "by malicious documents."
                ),
                FindingSeverity.HIGH,
                {"keywords": command_hits, "streams": stream_names[:10]},
            )
        if ole_hits:
            self._add_finding(
                context,
                "PowerPoint OLE Or Active Content Markers",
                "Legacy PowerPoint binary content contains OLE, ActiveX, DDE, or package markers.",
                FindingSeverity.HIGH,
                {"markers": ole_hits, "streams": stream_names[:10]},
            )

    def _read_ole_stream(
        self,
        context: AnalysisContext,
        ole: Any,
        stream: list[str],
    ) -> bytes:
        size = int(ole.get_size(stream))
        if size > context.limits.max_archive_entry_bytes:
            raise ValueError(
                f"OLE stream exceeds {context.limits.max_archive_entry_bytes} byte safety limit"
            )
        handle = ole.openstream(stream)
        try:
            return handle.read(context.limits.max_archive_entry_bytes + 1)
        except TypeError:  # simple file-like test doubles
            return handle.read()

    def _powerpoint_stream_candidates(self, ole: Any) -> list[list[str]]:
        candidates: list[list[str]] = []
        for stream in ole.listdir(streams=True, storages=False):
            lowered = "/".join(stream).lower()
            leaf = stream[-1].lower() if stream else ""
            if leaf in self.POWERPOINT_STREAM_NAMES or "powerpoint document" in lowered:
                candidates.append(stream)
        return candidates

    def _extract_external_targets(self, strings: list[str]) -> list[str]:
        targets: list[str] = []
        seen: set[str] = set()
        for text in strings:
            for match in URL_PATTERN.finditer(text):
                value = match.group().strip()
                if value not in seen:
                    seen.add(value)
                    targets.append(value)
            for match in self.EXTERNAL_TARGET_RE.finditer(text):
                value = match.group().strip()
                if value not in seen:
                    seen.add(value)
                    targets.append(value)
        return targets
