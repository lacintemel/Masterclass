from __future__ import annotations

import re

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FileType, FindingSeverity
from ..utils.file_utils import extract_strings


class RTFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "RTFAnalyzer"

    @property
    def description(self) -> str:
        return "Analyzes RTF files."

    def can_run(self, context: AnalysisContext) -> bool:
        return context.file_type == FileType.RTF

    EXPLOIT_HINTS = (
        "equation.3",
        "eqnedt32",
        "mscomctl",
        "shell.application",
        "packager",
    )

    def analyze(self, context: AnalysisContext) -> None:
        text = context.file_bytes.decode("latin-1", errors="ignore")
        lowered = text.lower()
        context.raw_strings.extend(
            extract_strings(
                context.file_bytes,
                min_length=5,
                max_strings=context.limits.max_extracted_strings,
                max_string_length=context.limits.max_string_length,
            )
        )

        object_count = lowered.count(r"\object")
        objdata_count = lowered.count(r"\objdata")
        if object_count or objdata_count:
            self._add_finding(
                context,
                title="RTF Embedded Object Data",
                description="RTF contains embedded object control words.",
                severity=FindingSeverity.MEDIUM,
                details={"object_count": object_count, "objdata_count": objdata_count},
            )

        for hint in self.EXPLOIT_HINTS:
            if hint in lowered:
                self._add_finding(
                    context,
                    title="RTF Exploit Indicator",
                    description=f"RTF references suspicious object/class marker '{hint}'.",
                    severity=FindingSeverity.HIGH,
                    details={"indicator": hint},
                )

        if r"\dde" in lowered or "ddeauto" in lowered:
            self._add_finding(
                context,
                title="RTF DDE Reference",
                description="RTF contains DDE-related control words.",
                severity=FindingSeverity.HIGH,
            )

        hex_blob_count = 0
        longest = 0
        for match in re.finditer(r"(?:[0-9a-fA-F]{2}\s*){256,}", text):
            hex_blob_count += 1
            longest = max(longest, len(match.group()))
            if hex_blob_count >= 1_000:
                break
        if hex_blob_count:
            self._add_finding(
                context,
                title="Large RTF Hex Blob",
                description="RTF contains large hex-encoded data blocks.",
                severity=FindingSeverity.MEDIUM,
                details={"hex_blob_count": hex_blob_count, "largest_chars": longest},
            )
