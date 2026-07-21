from __future__ import annotations

import io
import zipfile

try:
    import olefile
except ImportError:  # pragma: no cover - optional analyzer dependency
    olefile = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.enums import FindingSeverity
from ..utils.archive_utils import read_zip_member, validate_zip_archive
from ..utils.file_utils import calculate_entropy, extract_strings, is_pe_file


class EmbeddedObjectAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "EmbeddedObjectAnalyzer"

    @property
    def description(self) -> str:
        return "Analyzes embedded objects."

    SCRIPT_EXTENSIONS = (".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta", ".wsf")

    def analyze(self, context: AnalysisContext) -> None:
        embedded = self._collect_ooxml_embedded(context)
        if not context.file_type.is_ooxml:
            embedded.extend(self._collect_raw_nested_payloads(context))
        if not embedded:
            return

        context.extra["embedded_objects"] = embedded
        for item in embedded:
            item_type = str(item["type"])
            severity = self._severity_for_type(item_type)
            self._add_finding(
                context,
                title=f"Embedded {item_type}",
                description=f"Detected embedded {item_type.lower()} content.",
                severity=severity,
                details=item,
            )

    def _collect_ooxml_embedded(self, context: AnalysisContext) -> list[dict[str, object]]:
        if not context.file_type.is_ooxml:
            return []

        embedded: list[dict[str, object]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as archive:
                validate_zip_archive(archive, context.limits)
                for name in archive.namelist():
                    lowered = name.lower()
                    if not self._is_interesting_ooxml_part(lowered):
                        continue
                    data = read_zip_member(archive, name, context.limits)
                    item_type = self._classify(name, data)
                    embedded.append(
                        {
                            "name": name,
                            "type": item_type,
                            "size": len(data),
                            "entropy": round(calculate_entropy(data), 3),
                        }
                    )
                    context.embedded_strings.extend(
                        extract_strings(
                            data,
                            min_length=5,
                            max_strings=50,
                            max_string_length=context.limits.max_string_length,
                        )
                    )
        except zipfile.BadZipFile:
            return []
        return embedded

    def _collect_raw_nested_payloads(
        self,
        context: AnalysisContext | bytes,
    ) -> list[dict[str, object]]:
        data = context.file_bytes if isinstance(context, AnalysisContext) else context
        max_nested_payloads = (
            context.limits.max_nested_payloads if isinstance(context, AnalysisContext) else 100
        )
        embedded: list[dict[str, object]] = []
        signatures = [
            (b"MZ", "PE Executable"),
            (b"%PDF", "Nested PDF"),
            (b"\xd0\xcf\x11\xe0", "Nested OLE Document"),
            (b"PK\x03\x04", "Nested ZIP/OOXML"),
        ]
        for signature, item_type in signatures:
            start = 1
            while True:
                offset = data.find(signature, start)
                if offset == -1:
                    break
                if not self._is_valid_raw_payload(signature, data, offset):
                    start = offset + 1
                    continue
                embedded.append(
                    {
                        "name": f"raw_offset_{offset}",
                        "type": item_type,
                        "offset": offset,
                        "size": len(data) - offset,
                    }
                )
                if len(embedded) >= max_nested_payloads:
                    return embedded
                start = offset + len(signature)
        return embedded

    def _is_valid_raw_payload(self, signature: bytes, data: bytes, offset: int) -> bool:
        if signature == b"MZ":
            return is_pe_file(memoryview(data)[offset:])
        if signature == b"PK\x03\x04":
            return data.find(b"PK\x05\x06", offset) >= 0
        if signature == b"\xd0\xcf\x11\xe0":
            return len(data) - offset > 512
        if signature == b"%PDF":
            return data.find(b"%%EOF", offset, min(len(data), offset + 20 * 1024 * 1024)) >= 0
        return True

    def _is_interesting_ooxml_part(self, name: str) -> bool:
        return (
            "/embeddings/" in name or name.endswith(self.SCRIPT_EXTENSIONS) or "/activex/" in name
        )

    def _classify(self, name: str, data: bytes) -> str:
        lowered = name.lower()
        if is_pe_file(data):
            return "PE Executable"
        if data.startswith(b"%PDF"):
            return "Nested PDF"
        if data.startswith(b"\xd0\xcf\x11\xe0"):
            return "OLE Object"
        if data.startswith(b"PK\x03\x04"):
            return "Nested ZIP/OOXML"
        if lowered.endswith(self.SCRIPT_EXTENSIONS):
            return "Script"
        if "/activex/" in lowered:
            return "ActiveX"
        return "Unknown Binary"

    def _severity_for_type(self, item_type: object) -> FindingSeverity:
        if item_type in {"PE Executable", "Script"}:
            return FindingSeverity.CRITICAL
        if item_type in {"VBA Project", "OLE Object", "ActiveX"}:
            return FindingSeverity.HIGH
        if item_type in {"Nested PDF", "Nested ZIP/OOXML", "Unknown Binary"}:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW
