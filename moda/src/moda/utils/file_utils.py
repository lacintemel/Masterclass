from __future__ import annotations

import os
import math
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

def safe_read_file(
    path: Path,
    max_size_mb: int = 100,
    *,
    max_size_bytes: int | None = None,
) -> bytes:
    """Read a file safely, ensuring it doesn't exceed the maximum size."""
    max_bytes = max_size_bytes or max_size_mb * 1024 * 1024
    if path.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds maximum size of {max_size_mb}MB")
    return path.read_bytes()

def get_file_extension(path: Path) -> str:
    """Get lowercase file extension without dot."""
    return path.suffix.lower().lstrip('.')

def extract_strings(
    data: bytes,
    min_length: int = 4,
    *,
    max_strings: int = 10_000,
    max_string_length: int = 16_384,
) -> list[str]:
    """Extract a bounded number of bounded-length ASCII and UTF-16LE strings."""
    import re
    # Simple ASCII and Unicode extraction
    ascii_pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
    unicode_pattern = re.compile(rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}')
    
    strings: list[str] = []
    for match in ascii_pattern.finditer(data):
        strings.append(match.group()[:max_string_length].decode('ascii', errors='ignore'))
        if len(strings) >= max_strings:
            return strings
        
    for match in unicode_pattern.finditer(data):
        # Decode utf-16-le
        s = match.group()[: max_string_length * 2].decode('utf-16-le', errors='ignore')
        strings.append(s)
        if len(strings) >= max_strings:
            break
        
    return strings

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte array."""
    if not data:
        return 0.0
    
    entropy = 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    for count in counts:
        p_x = float(count) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_pe_file(data: bytes) -> bool:
    """Check if data is a valid PE file."""
    if len(data) < 64:
        return False
    if data[0:2] != b'MZ':
        return False
    pe_offset = int.from_bytes(data[60:64], byteorder='little')
    if len(data) < pe_offset + 4:
        return False
    return data[pe_offset:pe_offset+4] == b'PE\x00\x00'

@contextmanager
def safe_temp_dir() -> Generator[Path, None, None]:
    """Provide a secure temporary directory that is automatically cleaned up."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)
