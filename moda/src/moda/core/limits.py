"""Resource budgets applied while analysing untrusted documents."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    """Hard limits that keep hostile documents from exhausting the process."""

    max_file_bytes: int = 100 * 1024 * 1024
    max_archive_entries: int = 2_000
    max_archive_entry_bytes: int = 25 * 1024 * 1024
    max_archive_uncompressed_bytes: int = 200 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_text_part_bytes: int = 8 * 1024 * 1024
    max_extracted_strings: int = 10_000
    max_string_length: int = 16_384
    max_iocs: int = 2_000
    max_nested_payloads: int = 100

    @classmethod
    def for_file_size_mb(cls, max_file_size_mb: int) -> AnalysisLimits:
        return cls(max_file_bytes=max_file_size_mb * 1024 * 1024)
