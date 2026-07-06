from __future__ import annotations

import zipfile
import io

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
                if 'word/vbaProject.bin' in files or 'xl/vbaProject.bin' in files or 'ppt/vbaProject.bin' in files:
                    self._add_finding(context, "VBA Macros Present", "OOXML document contains a vbaProject.bin file", FindingSeverity.HIGH)
                    
                embeddings = [f for f in files if 'embeddings/' in f]
                if embeddings:
                    self._add_finding(context, "Embedded Objects", f"Found {len(embeddings)} embedded objects", FindingSeverity.MEDIUM, {"files": embeddings})
        except Exception as e:
            context.errors.append(f"OOXML parsing error: {e}")
