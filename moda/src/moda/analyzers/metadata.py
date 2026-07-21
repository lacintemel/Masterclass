from __future__ import annotations

import zipfile
import xml.etree.ElementTree as ET

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover - optional analyzer dependency
    PdfReader = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..core.exceptions import ResourceLimitError
from ..utils.archive_utils import read_zip_member, validate_zip_archive

class MetadataAnalyzer(BaseAnalyzer):
    """Extracts and analyzes document metadata for suspicious patterns."""
    
    @property
    def name(self) -> str:
        return "MetadataAnalyzer"
        
    @property
    def description(self) -> str:
        return "Extracts metadata and flags suspicious authors, applications, or timestamps."

    SUSPICIOUS_AUTHORS = ["admin", "user", "test", "root", "administrator", "pc", "windows"]

    def analyze(self, context: AnalysisContext) -> None:
        ftype = context.file_type
        metadata = {}
        
        if ftype in (FileType.OLE_DOC, FileType.OLE_XLS, FileType.OLE_PPT):
            metadata = self._extract_ole_metadata(context)
        elif ftype in (FileType.OOXML_DOCX, FileType.OOXML_DOCM, FileType.OOXML_XLSX, FileType.OOXML_XLSM, FileType.OOXML_PPTX, FileType.OOXML_PPTM):
            metadata = self._extract_ooxml_metadata(context)
        elif ftype == FileType.PDF:
            metadata = self._extract_pdf_metadata(context)
            
        context.metadata = metadata
        self._flag_suspicious_metadata(context, metadata)

    def _extract_ole_metadata(self, context: AnalysisContext) -> dict:
        metadata = {}
        try:
            if olefile is None:
                return metadata
            if olefile.isOleFile(context.file_bytes):
                with olefile.OleFileIO(context.file_bytes) as ole:
                    meta = ole.get_metadata()
                    metadata['Author'] = meta.author.decode('utf-8', errors='ignore') if meta.author else None
                    metadata['LastSavedBy'] = meta.last_saved_by.decode('utf-8', errors='ignore') if meta.last_saved_by else None
                    metadata['CreateTime'] = str(meta.create_time) if meta.create_time else None
                    metadata['LastSavedTime'] = str(meta.last_saved_time) if meta.last_saved_time else None
                    metadata['CreatingApplication'] = meta.creating_application.decode('utf-8', errors='ignore') if meta.creating_application else None
        except ResourceLimitError:
            raise
        except Exception as e:
            self.logger.debug(f"Error parsing OLE metadata: {e}")
        return metadata

    def _extract_ooxml_metadata(self, context: AnalysisContext) -> dict:
        metadata = {}
        try:
            # Note: We simulate reading zip from memory
            import io
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as z:
                validate_zip_archive(z, context.limits)
                if 'docProps/core.xml' in z.namelist():
                    core_xml = read_zip_member(
                        z,
                        'docProps/core.xml',
                        context.limits,
                        max_bytes=context.limits.max_text_part_bytes,
                    )
                    root = ET.fromstring(core_xml)
                    namespaces = {'dc': 'http://purl.org/dc/elements/1.1/', 'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties', 'dcterms': 'http://purl.org/dc/terms/'}
                    
                    creator = root.find('.//dc:creator', namespaces)
                    last_mod_by = root.find('.//cp:lastModifiedBy', namespaces)
                    created = root.find('.//dcterms:created', namespaces)
                    
                    metadata['Author'] = creator.text if creator is not None else None
                    metadata['LastSavedBy'] = last_mod_by.text if last_mod_by is not None else None
                    metadata['CreateTime'] = created.text if created is not None else None
        except ResourceLimitError:
            raise
        except Exception as e:
            self.logger.debug(f"Error parsing OOXML metadata: {e}")
        return metadata

    def _extract_pdf_metadata(self, context: AnalysisContext) -> dict:
        metadata = {}
        try:
            if PdfReader is None:
                return metadata
            import io
            reader = PdfReader(io.BytesIO(context.file_bytes))
            meta = reader.metadata
            if meta:
                metadata['Author'] = meta.author
                metadata['Creator'] = meta.creator
                metadata['Producer'] = meta.producer
                metadata['CreationDate'] = meta.creation_date
        except Exception as e:
            self.logger.debug(f"Error parsing PDF metadata: {e}")
        return metadata

    def _flag_suspicious_metadata(self, context: AnalysisContext, metadata: dict) -> None:
        author = str(metadata.get('Author', '')).lower()
        if author in self.SUSPICIOUS_AUTHORS:
            self._add_finding(
                context,
                title="Suspicious Document Author",
                description=f"The document author '{author}' is generic and commonly used by malware builders.",
                severity=FindingSeverity.LOW,
                details={"author": author}
            )
            
        if metadata.get('CreateTime') == metadata.get('LastSavedTime') and metadata.get('CreateTime') is not None:
             pass # Common for newly created documents
