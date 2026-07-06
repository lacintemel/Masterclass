from __future__ import annotations

import base64
import binascii
import re

def decode_base64_strings(text: str) -> list[str]:
    """Attempt to decode base64 strings found in text."""
    from .regex_patterns import BASE64_PATTERN
    results = []
    for match in BASE64_PATTERN.finditer(text):
        b64_str = match.group()
        if len(b64_str) < 16:  # Skip short strings to avoid false positives
            continue
        try:
            # Fix padding if missing
            padding = len(b64_str) % 4
            if padding:
                b64_str += '=' * (4 - padding)
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            if len(decoded.strip()) > 3:
                results.append(decoded)
        except Exception:
            pass
    return results

def decode_hex_strings(text: str) -> list[str]:
    """Attempt to decode hex-encoded strings."""
    from .regex_patterns import HEX_STRING_PATTERN
    results = []
    for match in HEX_STRING_PATTERN.finditer(text):
        hex_str = match.group().replace(' ', '')
        if len(hex_str) < 16:
            continue
        try:
            decoded = binascii.unhexlify(hex_str).decode('utf-8', errors='ignore')
            if len(decoded.strip()) > 3:
                results.append(decoded)
        except Exception:
            pass
    return results

def deobfuscate_chr_calls(text: str) -> str:
    """Deobfuscate VBA Chr(X) calls."""
    chr_pattern = re.compile(r'Chrw?\s*\(\s*([0-9]+)\s*\)', re.IGNORECASE)
    
    def replace_chr(match):
        try:
            return chr(int(match.group(1)))
        except ValueError:
            return match.group(0)
            
    return chr_pattern.sub(replace_chr, text)

def strip_null_bytes(data: bytes) -> bytes:
    """Strip null bytes from data."""
    return data.replace(b'\x00', b'')

def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text to single spaces."""
    return re.sub(r'\s+', ' ', text).strip()

def defang_url(url: str) -> str:
    """Defang a URL for safe sharing."""
    return url.replace('http', 'hxxp').replace('.', '[.]')

def defang_ip(ip: str) -> str:
    """Defang an IP address for safe sharing."""
    return ip.replace('.', '[.]')
