"""Bounded ZIP helpers for OOXML packages supplied by untrusted users."""

from __future__ import annotations

import zipfile

from moda.core.exceptions import ResourceLimitError
from moda.core.limits import AnalysisLimits


def validate_zip_archive(archive: zipfile.ZipFile, limits: AnalysisLimits) -> None:
    """Validate archive metadata before any member is decompressed."""
    entries = archive.infolist()
    if len(entries) > limits.max_archive_entries:
        raise ResourceLimitError(
            f"archive contains {len(entries)} entries; limit is {limits.max_archive_entries}"
        )

    total = 0
    for info in entries:
        if info.file_size > limits.max_archive_entry_bytes:
            raise ResourceLimitError(
                f"archive member {info.filename!r} expands to {info.file_size} bytes; "
                f"limit is {limits.max_archive_entry_bytes}"
            )
        total += info.file_size
        if total > limits.max_archive_uncompressed_bytes:
            raise ResourceLimitError(
                f"archive expands to more than {limits.max_archive_uncompressed_bytes} bytes"
            )
        if info.file_size:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > limits.max_compression_ratio:
                raise ResourceLimitError(
                    f"archive member {info.filename!r} has compression ratio {ratio:.1f}; "
                    f"limit is {limits.max_compression_ratio:.1f}"
                )


def read_zip_member(
    archive: zipfile.ZipFile,
    name: str | zipfile.ZipInfo,
    limits: AnalysisLimits,
    *,
    max_bytes: int | None = None,
) -> bytes:
    """Read one member with both metadata and streamed byte limits."""
    info = name if isinstance(name, zipfile.ZipInfo) else archive.getinfo(name)
    effective_limit = min(
        limits.max_archive_entry_bytes,
        max_bytes if max_bytes is not None else limits.max_archive_entry_bytes,
    )
    if info.file_size > effective_limit:
        raise ResourceLimitError(
            f"archive member {info.filename!r} exceeds {effective_limit} byte read limit"
        )
    with archive.open(info) as handle:
        data = handle.read(effective_limit + 1)
    if len(data) > effective_limit:
        raise ResourceLimitError(
            f"archive member {info.filename!r} exceeded {effective_limit} byte read limit"
        )
    return data
