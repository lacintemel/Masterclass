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
from ..utils.file_utils import calculate_entropy, extract_strings, is_pe_file

class EmbeddedObjectAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str: return "EmbeddedObjectAnalyzer"
    @property
    def description(self) -> str: return "Analyzes embedded objects."

    SCRIPT_EXTENSIONS = (".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta", ".wsf")

    def analyze(self, context: AnalysisContext) -> None:
        embedded = self._collect_ooxml_embedded(context)
        if not context.file_type.is_ooxml:
            embedded.extend(self._collect_raw_nested_payloads(context.file_bytes))
        if not embedded:
            return

        context.extra["embedded_objects"] = embedded
        for item in embedded:
            severity = self._severity_for_type(item["type"])
            self._add_finding(
                context,
                title=f"Embedded {item['type']}",
                description=f"Detected embedded {item['type'].lower()} content.",
                severity=severity,
                details=item,
            )

    def _collect_ooxml_embedded(self, context: AnalysisContext) -> list[dict[str, object]]:
        if not context.file_type.is_ooxml:
            return []

        embedded: list[dict[str, object]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(context.file_bytes)) as archive:
                for name in archive.namelist():
                    lowered = name.lower()
                    if not self._is_interesting_ooxml_part(lowered):
                        continue
                    data = archive.read(name)
                    item_type = self._classify(name, data)
                    embedded.append(
                        {
                            "name": name,
                            "type": item_type,
                            "size": len(data),
                            "entropy": round(calculate_entropy(data), 3),
                        }
                    )
                    context.embedded_strings.extend(extract_strings(data, min_length=5)[:50])
        except zipfile.BadZipFile:
            return []
        return embedded

    def _collect_raw_nested_payloads(self, data: bytes) -> list[dict[str, object]]:
        embedded: list[dict[str, object]] = []
        signatures = [
            (b"MZ", "PE Executable"),
            (b"%PDF", "Nested PDF"),
            (b"\xD0\xCF\x11\xE0", "Nested OLE Document"),
            (b"PK\x03\x04", "Nested ZIP/OOXML"),
        ]
        for signature, item_type in signatures:
            start = 1
            while True:
                offset = data.find(signature, start)
                if offset == -1:
                    break
                payload = data[offset:]
                if not self._is_valid_raw_payload(signature, payload):
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
                start = offset + len(signature)
        return embedded

    def _is_valid_raw_payload(self, signature: bytes, payload: bytes) -> bool:
        if signature == b"MZ":
            return is_pe_file(payload)
        if signature == b"PK\x03\x04":
            return zipfile.is_zipfile(io.BytesIO(payload))
        if signature == b"\xD0\xCF\x11\xE0":
            return olefile.isOleFile(payload) if olefile is not None else len(payload) > 512
        if signature == b"%PDF":
            return b"%%EOF" in payload[:20 * 1024 * 1024]
        return True

    def _is_interesting_ooxml_part(self, name: str) -> bool:
        return (
            "/embeddings/" in name
            or name.endswith(self.SCRIPT_EXTENSIONS)
            or "/activex/" in name
        )

    def _classify(self, name: str, data: bytes) -> str:
        lowered = name.lower()
        if is_pe_file(data):
            return "PE Executable"
        if data.startswith(b"%PDF"):
            return "Nested PDF"
        if data.startswith(b"\xD0\xCF\x11\xE0"):
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
