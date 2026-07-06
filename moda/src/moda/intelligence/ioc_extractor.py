from __future__ import annotations

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import IOCType
from ..utils.regex_patterns import URL_PATTERN, IPV4_PATTERN

class IOCExtractor(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "IOCExtractor"
        
    @property
    def description(self) -> str:
        return "Extracts IOCs from findings and text content."

    def analyze(self, context: AnalysisContext) -> None:
        text = context.get_all_text()
        
        # Extract URLs
        for match in URL_PATTERN.finditer(text):
            url = match.group()
            self._add_ioc(context, IOCType.URL, url, self.name)
            
        # Extract IPs
        for match in IPV4_PATTERN.finditer(text):
            ip = match.group()
            self._add_ioc(context, IOCType.IP, ip, self.name)
