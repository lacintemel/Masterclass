from __future__ import annotations

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity

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
        except Exception as e:
            context.errors.append(f"OLE parsing error: {e}")

    def _inspect_streams(self, context: AnalysisContext, ole: olefile.OleFileIO) -> None:
        streams = ole.listdir()
        for stream in streams:
            stream_name = '/'.join(stream)
            if 'ObjectPool' in stream_name:
                self._add_finding(context, "OLE Object Pool", "Contains an Object Pool (often used for embedded objects)", FindingSeverity.LOW)

    def _check_vba_storage(self, context: AnalysisContext, ole: olefile.OleFileIO) -> None:
        if ole.exists('Macros/VBA') or ole.exists('_VBA_PROJECT_CUR'):
            self._add_finding(context, "VBA Macros Present", "Document contains a VBA project", FindingSeverity.HIGH)
