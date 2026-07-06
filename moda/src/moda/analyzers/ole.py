from __future__ import annotations

from typing import Any

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import calculate_entropy, extract_strings

class OLEAnalyzer(BaseAnalyzer):
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
            return
        if not olefile.isOleFile(context.file_bytes):
            return
            
        try:
            with olefile.OleFileIO(context.file_bytes) as ole:
                self._inspect_streams(context, ole)
                self._check_vba_storage(context, ole)
                self._check_activex(context, ole)
                self._record_directory_tree(context, ole)
        except Exception as e:
            context.errors.append(f"OLE parsing error: {e}")

    def _inspect_streams(self, context: AnalysisContext, ole: Any) -> None:
        streams = ole.listdir()
        stream_names = ["/".join(stream) for stream in streams]
        context.extra["ole_streams"] = stream_names

        for stream in streams:
            stream_name = "/".join(stream)
            lowered = stream_name.lower()
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
        stream_names = ["/".join(stream).lower() for stream in ole.listdir()]
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
        context.extra["ole_directory_count"] = len(ole.listdir())

    def _inspect_macro_stream_content(
        self,
        context: AnalysisContext,
        ole: Any,
        stream: list[str],
        stream_name: str,
    ) -> None:
        try:
            data = ole.openstream(stream).read()
        except Exception:
            return

        strings = extract_strings(data, min_length=4)
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
