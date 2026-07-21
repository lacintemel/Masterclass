from __future__ import annotations

import io
import zipfile
from importlib import import_module
from pathlib import Path
from typing import Any, TypedDict

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..core.limits import AnalysisLimits
from ..utils.archive_utils import read_zip_member, validate_zip_archive
from ..utils.file_utils import get_file_extension

try:
    magic: Any = import_module("magic")
except ImportError:  # pragma: no cover - depends on optional system package
    magic = None


class FileTypeDetector(BaseAnalyzer):
    """Detects the file type using magic bytes, MIME, and structural inspection."""

    @property
    def name(self) -> str:
        return "FileTypeDetector"

    @property
    def description(self) -> str:
        return "Detects real file type and checks for extension mismatches."

    MAGIC_BYTES = {
        b"\xd0\xcf\x11\xe0": "OLE",
        b"\x50\x4b\x03\x04": "ZIP",
        b"\x25\x50\x44\x46": "PDF",
        b"\x7b\x5c\x72\x74\x36": "RTF",  # {\rtf
        b"\x7b\x5c\x72\x74\x66": "RTF",  # {\rtf
        b"\x4d\x5a": "PE",
        b"\x7f\x45\x4c\x46": "ELF",
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
        if base_type == "OLE":
            file_type = self._detect_ole_subtype(context.file_path, data)
        elif base_type == "ZIP":
            file_type = self._detect_ooxml_subtype(context.file_path, data, context.limits)
        elif base_type == "PDF":
            file_type = FileType.PDF
        elif base_type == "RTF":
            file_type = FileType.RTF

        context.file_type = file_type

        if file_type == FileType.UNKNOWN:
            context.extra["unsupported_file_type"] = {
                "base_type": base_type or "unknown",
                "mime": context.mime_type,
                "extension": context.extension,
            }
            self._add_finding(
                context,
                title="Unsupported File Type",
                description=(
                    "MODA did not identify this file as a supported Office, RTF, or PDF "
                    "document. The result is inconclusive for this file type."
                ),
                severity=FindingSeverity.MEDIUM,
                details=context.extra["unsupported_file_type"],
            )
            return

        # 4. Check for extension mismatch
        self._check_extension_mismatch(context)

    def _check_magic_bytes(self, data: bytes) -> str | None:
        for magic_sig, ftype in self.MAGIC_BYTES.items():
            if data.startswith(magic_sig):
                return ftype
        return None

    def _detect_ole_subtype(self, file_path: Path, data: bytes) -> FileType:
        try:
            import olefile

            if olefile.isOleFile(data):
                with olefile.OleFileIO(data) as ole:
                    streams = {"/".join(item).lower() for item in ole.listdir()}
                if any(name.endswith("worddocument") for name in streams):
                    return FileType.OLE_DOC
                if any(name.endswith(("workbook", "book")) for name in streams):
                    return FileType.OLE_XLS
                if any(name.endswith("powerpoint document") for name in streams):
                    return FileType.OLE_PPT
        except (ImportError, OSError):
            pass
        ext = get_file_extension(file_path)
        if ext in ("xls", "xla", "xlt", "xlsb"):
            return FileType.OLE_XLS
        elif ext in ("ppt", "pps", "pot", "ppa", "ppam"):
            return FileType.OLE_PPT
        return FileType.OLE_DOC  # Default OLE

    def _detect_ooxml_subtype(
        self,
        file_path: Path,
        data: bytes,
        limits: AnalysisLimits,
    ) -> FileType:
        # OOXML type is usually defined in [Content_Types].xml or by extension
        package = self._inspect_ooxml_package(data, limits)
        if not package["is_ooxml"]:
            return FileType.UNKNOWN
        ext = get_file_extension(file_path)
        content_types = str(package["content_types"]).lower()
        names = package["names"]

        if "word/vbaproject.bin" in names or ext in ("docm", "dotm", "docxm"):
            return FileType.OOXML_DOCM
        if "xl/vbaproject.bin" in names or ext in ("xlsm", "xltm", "xlam"):
            return FileType.OOXML_XLSM
        if "ppt/vbaproject.bin" in names or ext in ("pptm", "ppsm", "potm", "ppam"):
            return FileType.OOXML_PPTM
        if "presentationml.template.macroenabled" in content_types:
            return FileType.OOXML_PPTM
        if "spreadsheetml.sheet.macroenabled" in content_types:
            return FileType.OOXML_XLSM
        if "wordprocessingml.document.macroenabled" in content_types:
            return FileType.OOXML_DOCM

        if ext in ("xlsx", "xlst", "xltx", "xlsb"):
            return FileType.OOXML_XLSX
        elif ext in ("pptx", "ppsx", "potx"):
            return FileType.OOXML_PPTX
        elif ext in ("docx", "dotx"):
            return FileType.OOXML_DOCX

        if any(name.startswith("xl/") for name in names):
            return FileType.OOXML_XLSX
        if any(name.startswith("ppt/") for name in names):
            return FileType.OOXML_PPTX
        return FileType.OOXML_DOCX  # Default OOXML

    def _is_ooxml_package(self, data: bytes, limits: AnalysisLimits | None = None) -> bool:
        return bool(self._inspect_ooxml_package(data, limits or AnalysisLimits())["is_ooxml"])

    def _inspect_ooxml_package(
        self,
        data: bytes,
        limits: AnalysisLimits,
    ) -> _OOXMLPackage:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                validate_zip_archive(archive, limits)
                names = {name.lower() for name in archive.namelist()}
                content_types = (
                    read_zip_member(
                        archive,
                        archive.getinfo("[Content_Types].xml"),
                        limits,
                        max_bytes=limits.max_text_part_bytes,
                    ).decode("utf-8", errors="ignore")
                    if "[content_types].xml" in names
                    else ""
                )
        except zipfile.BadZipFile:
            return {"is_ooxml": False, "names": set(), "content_types": ""}
        is_ooxml = "[content_types].xml" in names and (
            "word/document.xml" in names
            or "xl/workbook.xml" in names
            or "xl/workbook.bin" in names
            or "ppt/presentation.xml" in names
        )
        return {"is_ooxml": is_ooxml, "names": names, "content_types": content_types}

    def _fallback_mime(self, base_type: str | None) -> str:
        return {
            "OLE": "application/vnd.ms-office",
            "ZIP": "application/zip",
            "PDF": "application/pdf",
            "RTF": "application/rtf",
            "PE": "application/vnd.microsoft.portable-executable",
            "ELF": "application/x-elf",
        }.get(base_type or "", "application/octet-stream")

    def _check_extension_mismatch(self, context: AnalysisContext) -> None:
        ext = context.extension
        ftype = context.file_type

        mismatch = False
        if ftype in (FileType.OLE_DOC, FileType.OOXML_DOCX, FileType.OOXML_DOCM, FileType.RTF):
            if ext not in ("doc", "docx", "docm", "docxm", "rtf", "dot", "dotm", "dotx"):
                mismatch = True
        elif ftype in (FileType.OLE_XLS, FileType.OOXML_XLSX, FileType.OOXML_XLSM):
            if ext not in ("xls", "xlsx", "xlsm", "xlsb", "xla", "xlam", "xlt", "xltx", "xltm"):
                mismatch = True
        elif ftype in (FileType.OLE_PPT, FileType.OOXML_PPTX, FileType.OOXML_PPTM):
            if ext not in (
                "ppt",
                "pptx",
                "pptm",
                "pps",
                "ppsx",
                "ppsm",
                "pot",
                "potx",
                "potm",
                "ppa",
                "ppam",
            ):
                mismatch = True
        elif ftype == FileType.PDF:
            if ext != "pdf":
                mismatch = True

        if mismatch:
            self._add_finding(
                context,
                title="File Extension Mismatch",
                description=f"File extension '.{ext}' does not match detected format '{ftype.value}'",
                severity=FindingSeverity.HIGH,
                details={"extension": ext, "detected_type": ftype.value, "mime": context.mime_type},
            )


class _OOXMLPackage(TypedDict):
    is_ooxml: bool
    names: set[str]
    content_types: str
