from __future__ import annotations

import zipfile
from pathlib import Path

try:
    import magic
except ImportError:  # pragma: no cover - depends on optional system package
    magic = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..core.exceptions import UnsupportedFileTypeError
from ..utils.file_utils import get_file_extension

class FileTypeDetector(BaseAnalyzer):
    """Detects the file type using magic bytes, MIME, and structural inspection."""
    
    @property
    def name(self) -> str:
        return "FileTypeDetector"
        
    @property
    def description(self) -> str:
        return "Detects real file type and checks for extension mismatches."

    MAGIC_BYTES = {
        b'\xD0\xCF\x11\xE0': 'OLE',
        b'\x50\x4B\x03\x04': 'OOXML',
        b'\x25\x50\x44\x46': 'PDF',
        b'\x7B\x5C\x72\x74\x36': 'RTF', # {\rtf
        b'\x7B\x5C\x72\x74\x66': 'RTF', # {\rtf
    }

    def analyze(self, context: AnalysisContext) -> None:
        data = context.file_bytes
        
        # 1. Detect magic bytes
        base_type = self._check_magic_bytes(data)
        
        # 2. Get MIME type
        if magic is not None:
            try:
                mime = magic.from_buffer(data, mime=True)
                context.mime_type = mime
            except Exception:
                context.mime_type = "application/octet-stream"
        else:
            context.mime_type = self._fallback_mime(base_type)
            
        # 3. Determine exact file type
        file_type = FileType.UNKNOWN
        if base_type == 'OLE':
            file_type = self._detect_ole_subtype(context.file_path)
        elif base_type == 'OOXML':
            file_type = self._detect_ooxml_subtype(context.file_path, data)
        elif base_type == 'PDF':
            file_type = FileType.PDF
        elif base_type == 'RTF':
            file_type = FileType.RTF
            
        context.file_type = file_type
        
        if file_type == FileType.UNKNOWN:
            raise UnsupportedFileTypeError(context.file_path, context.mime_type)
            
        # 4. Check for extension mismatch
        self._check_extension_mismatch(context)

    def _check_magic_bytes(self, data: bytes) -> str | None:
        for magic_sig, ftype in self.MAGIC_BYTES.items():
            if data.startswith(magic_sig):
                return ftype
        return None

    def _detect_ole_subtype(self, file_path: Path) -> FileType:
        # Simplistic detection based on extension since OLE streams are complex to map perfectly without full parsing
        # Real implementation would look at streams (e.g. WordDocument stream -> DOC)
        ext = get_file_extension(file_path)
        if ext in ('xls', 'xla'):
            return FileType.OLE_XLS
        elif ext in ('ppt', 'pps'):
            return FileType.OLE_PPT
        return FileType.OLE_DOC # Default OLE

    def _detect_ooxml_subtype(self, file_path: Path, data: bytes) -> FileType:
        # OOXML type is usually defined in [Content_Types].xml or by extension
        ext = get_file_extension(file_path)
        if ext in ('xlsx', 'xlst'):
            return FileType.OOXML_XLSX
        elif ext in ('xlsm', 'xlsb'):
            return FileType.OOXML_XLSM
        elif ext in ('pptx', 'ppsx'):
            return FileType.OOXML_PPTX
        elif ext in ('pptm', 'ppsm'):
            return FileType.OOXML_PPTM
        elif ext == 'docm':
            return FileType.OOXML_DOCM
        return FileType.OOXML_DOCX # Default OOXML

    def _fallback_mime(self, base_type: str | None) -> str:
        return {
            "OLE": "application/vnd.ms-office",
            "OOXML": "application/zip",
            "PDF": "application/pdf",
            "RTF": "application/rtf",
        }.get(base_type, "application/octet-stream")

    def _check_extension_mismatch(self, context: AnalysisContext) -> None:
        ext = context.extension
        ftype = context.file_type
        
        mismatch = False
        if ftype in (FileType.OLE_DOC, FileType.OOXML_DOCX, FileType.OOXML_DOCM, FileType.RTF):
            if ext not in ('doc', 'docx', 'docm', 'rtf', 'dot', 'dotm', 'dotx'):
                mismatch = True
        elif ftype in (FileType.OLE_XLS, FileType.OOXML_XLSX, FileType.OOXML_XLSM):
            if ext not in ('xls', 'xlsx', 'xlsm', 'xlsb', 'xla', 'xlam', 'xltx', 'xltm'):
                mismatch = True
        elif ftype in (FileType.OLE_PPT, FileType.OOXML_PPTX, FileType.OOXML_PPTM):
            if ext not in ('ppt', 'pptx', 'pptm', 'pps', 'ppsx', 'ppsm', 'potx', 'potm'):
                mismatch = True
        elif ftype == FileType.PDF:
            if ext != 'pdf':
                mismatch = True
                
        if mismatch:
            self._add_finding(
                context,
                title="File Extension Mismatch",
                description=f"File extension '.{ext}' does not match detected format '{ftype.value}'",
                severity=FindingSeverity.HIGH,
                details={"extension": ext, "detected_type": ftype.value, "mime": context.mime_type}
            )
