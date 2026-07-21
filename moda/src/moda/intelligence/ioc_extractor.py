from __future__ import annotations

from urllib.parse import urlsplit

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import IOCType
from ..core.models import IOC
from ..utils.regex_patterns import (
    BENIGN_DOMAINS,
    IOC_PATTERNS,
    is_defanged,
    is_private_ip,
    refang,
)

class IOCExtractor(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "IOCExtractor"
        
    @property
    def description(self) -> str:
        return "Extracts IOCs from findings and text content."

    def analyze(self, context: AnalysisContext) -> None:
        text = context.get_all_text()
        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                original = match.group().strip("\"'<>[](){}.,;")
                value = refang(original)
                if self._should_filter(ioc_type, value):
                    continue
                start = max(0, match.start() - 80)
                end = min(len(text), match.end() + 80)
                context.add_ioc(
                    IOC(
                        ioc_type=ioc_type,
                        value=value,
                        source=self.name,
                        context=text[start:end].replace("\n", " ")[:240],
                        confidence=self._confidence(ioc_type),
                        defanged=is_defanged(original),
                    )
                )
                if len(context.iocs) >= context.limits.max_iocs:
                    context.extra["ioc_limit_reached"] = context.limits.max_iocs
                    return

    def _should_filter(self, ioc_type: IOCType, value: str) -> bool:
        if ioc_type is IOCType.IP:
            return is_private_ip(value)
        domain = ""
        if ioc_type is IOCType.URL:
            try:
                domain = (urlsplit(value).hostname or "").lower().rstrip(".")
            except ValueError:
                return True
        elif ioc_type is IOCType.DOMAIN:
            domain = value.lower().rstrip(".")
        if domain and any(domain == item or domain.endswith(f".{item}") for item in BENIGN_DOMAINS):
            return True
        return False

    def _confidence(self, ioc_type: IOCType) -> float:
        return {
            IOCType.URL: 0.85,
            IOCType.IP: 0.8,
            IOCType.DOMAIN: 0.7,
            IOCType.EMAIL: 0.65,
            IOCType.COMMAND: 0.9,
            IOCType.REGISTRY_KEY: 0.85,
            IOCType.FILE_PATH: 0.65,
            IOCType.EXECUTABLE_NAME: 0.6,
        }.get(ioc_type, 0.5)
