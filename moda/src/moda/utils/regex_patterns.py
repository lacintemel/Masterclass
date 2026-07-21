"""Pre-compiled regular-expression patterns for IOC extraction.

All patterns are compiled once at module-import time for optimal
performance during repeated scanning.  Each pattern maps to an
``IOCType`` from :mod:`moda.core.enums`.

Usage::

    from moda.utils.regex_patterns import IOC_PATTERNS, DEFANG_MAP
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            ...
"""

from __future__ import annotations

import ipaddress as _ipaddress
import re
from typing import Final

from moda.core.enums import IOCType

# ======================================================================
# Helper constants
# ======================================================================

#: TLDs commonly seen in malicious documents (non-exhaustive).
_COMMON_TLDS: Final[str] = (
    r"(?:com|net|org|info|biz|ru|cn|tk|xyz|top|pw|cc|"
    r"ws|ga|cf|gq|ml|work|click|link|live|online|site|"
    r"club|pro|io|co|us|uk|de|fr|br|in|au|ca|eu|gov|edu|mil)"
)

#: Pattern fragment matching a defanged or normal dot.
_DOT: Final[str] = r"(?:\.|\[\.\]|\(\.\))"

#: Pattern fragment matching a defanged or normal ``://``.
_SCHEME_SEP: Final[str] = r"(?::\/\/|:\[\/\/\]|:\(\/\/\))"

# ======================================================================
# Individual pattern strings
# ======================================================================

#: Matches HTTP/HTTPS URLs (including defanged variants like hxxp).
_URL_PATTERN: Final[str] = (
    r"(?:h[tx]{2}ps?|ftp)" + _SCHEME_SEP + r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]){4,}"
)

#: Domain names with at least one dot — anchored to word boundaries.
_DOMAIN_PATTERN: Final[str] = (
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?" + _DOT + r")+" + _COMMON_TLDS + r"\b"
)

#: IPv4 addresses (standard dotted-quad) including defanged forms.
_IPV4_PATTERN: Final[str] = (
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)" + _DOT + r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

#: Simplified IPv6 — matches common representations, not exhaustive.
_IPV6_PATTERN: Final[str] = (
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

#: Email addresses.
_EMAIL_PATTERN: Final[str] = (
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+"
    r"\.[a-zA-Z]{2,}\b"
)

#: Windows registry paths (HKLM, HKCU, HKCR, HKU, HKCC).
_REGISTRY_PATTERN: Final[str] = (
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|"
    r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|"
    r"HKEY_CURRENT_CONFIG)"
    r"(?:\\[^\s\\\"']{1,255}){1,}"
)

#: PowerShell invocations with common evasion flags.
_POWERSHELL_PATTERN: Final[str] = (
    r"\b(?:powershell|pwsh)(?:\.exe)?\s+"
    r"(?:-\w+\s+)*"
    r"(?:-(?:e(?:nc(?:odedcommand)?)?|c(?:ommand)?|"
    r"ex(?:ecutionpolicy)?|nop(?:rofile)?|"
    r"w(?:indowstyle)?|sta)\s+)?"
    r"[^\r\n]{3,}"
)

#: cmd.exe invocations (cmd /c …, cmd /k …).
_CMD_PATTERN: Final[str] = r"\bcmd(?:\.exe)?\s+/[ckr]\s+[^\r\n]{3,}"

#: Executable file references (.exe, .dll, .scr, .bat, .cmd, .vbs, .js, .ps1, .hta, .pif, .com).
_EXECUTABLE_PATTERN: Final[str] = (
    r"\b[a-zA-Z0-9_\-]{1,64}"
    r"\.(?:exe|dll|scr|bat|cmd|vbs|vbe|js|jse|"
    r"wsf|wsh|ps1|pif|hta|com|cpl|msi|jar)\b"
)

#: Windows file paths (C:\…, \\UNC\…).
_FILE_PATH_PATTERN: Final[str] = (
    r"(?:[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]{1,255}\\)*"
    r"[^\s\\/:*?\"<>|]{1,255})"
    r"|(?:\\\\[a-zA-Z0-9._\-]+\\[^\s\\/:*?\"<>|]+"
    r"(?:\\[^\s\\/:*?\"<>|]+)*)"
)

# ======================================================================
# Compiled pattern mapping
# ======================================================================

#: Master mapping from ``IOCType`` to its compiled regex.
IOC_PATTERNS: Final[dict[IOCType, re.Pattern[str]]] = {
    IOCType.URL: re.compile(_URL_PATTERN, re.IGNORECASE),
    IOCType.DOMAIN: re.compile(_DOMAIN_PATTERN, re.IGNORECASE),
    IOCType.IP: re.compile(
        rf"(?:{_IPV4_PATTERN})|(?:{_IPV6_PATTERN})",
        re.IGNORECASE,
    ),
    IOCType.EMAIL: re.compile(_EMAIL_PATTERN, re.IGNORECASE),
    IOCType.REGISTRY_KEY: re.compile(_REGISTRY_PATTERN),
    IOCType.COMMAND: re.compile(
        rf"(?:{_POWERSHELL_PATTERN})|(?:{_CMD_PATTERN})",
        re.IGNORECASE,
    ),
    IOCType.EXECUTABLE_NAME: re.compile(_EXECUTABLE_PATTERN, re.IGNORECASE),
    IOCType.FILE_PATH: re.compile(_FILE_PATH_PATTERN),
}

URL_PATTERN: Final[re.Pattern[str]] = IOC_PATTERNS[IOCType.URL]
IPV4_PATTERN: Final[re.Pattern[str]] = re.compile(_IPV4_PATTERN, re.IGNORECASE)
BASE64_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
HEX_STRING_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:[0-9A-Fa-f]{2}\s*){8,}\b")

# ======================================================================
# Defanging support
# ======================================================================

#: Ordered replacement pairs to re-fang defanged IOCs.
DEFANG_MAP: Final[list[tuple[str, str]]] = [
    ("hxxp", "http"),
    ("hXXp", "http"),
    ("HXXP", "HTTP"),
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("(://)", "://"),
    ("[at]", "@"),
    ("[@]", "@"),
    ("[dot]", "."),
]


def refang(value: str) -> str:
    """Convert a defanged IOC string back to its canonical form.

    Examples::

        >>> refang("hxxp://evil[.]com/payload")
        'http://evil.com/payload'
    """
    result = value
    for defanged, canonical in DEFANG_MAP:
        result = result.replace(defanged, canonical)
    return result


def is_defanged(value: str) -> bool:
    """Return ``True`` if *value* contains any known defanging notation."""
    lower = value.lower()
    return any(d.lower() in lower for d, _ in DEFANG_MAP)


# ======================================================================
# Benign domain allow-list
# ======================================================================

#: Domains that are almost always benign and should be filtered out by
#: default to reduce noise.  All comparisons should be case-insensitive
#: and match the *suffix* (so ``update.microsoft.com`` is also excluded).
BENIGN_DOMAINS: Final[frozenset[str]] = frozenset(
    {
        "microsoft.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "apple.com",
        "adobe.com",
        "akamai.net",
        "akamaized.net",
        "cloudflare.com",
        "amazonaws.com",
        "windowsupdate.com",
        "windows.net",
        "office.com",
        "office365.com",
        "live.com",
        "outlook.com",
        "bing.com",
        "msn.com",
        "verisign.com",
        "symantec.com",
        "digicert.com",
        "globalsign.com",
        "w3.org",
        "xml.org",
        "openxmlformats.org",
        "schemas.microsoft.com",
        "purl.org",
        "xmlsoap.org",
        "mozilla.org",
        "mozilla.com",
        "github.com",
        "linkedin.com",
        "facebook.com",
        "twitter.com",
        "schema.org",
    }
)

# ======================================================================
# Private IP ranges (for filtering)
# ======================================================================

#: RFC-1918 / link-local / loopback networks.
PRIVATE_NETWORKS: Final[tuple[_ipaddress.IPv4Network | _ipaddress.IPv6Network, ...]] = (
    _ipaddress.IPv4Network("10.0.0.0/8"),
    _ipaddress.IPv4Network("172.16.0.0/12"),
    _ipaddress.IPv4Network("192.168.0.0/16"),
    _ipaddress.IPv4Network("127.0.0.0/8"),
    _ipaddress.IPv4Network("169.254.0.0/16"),
    _ipaddress.IPv6Network("::1/128"),
    _ipaddress.IPv6Network("fc00::/7"),
    _ipaddress.IPv6Network("fe80::/10"),
)


def is_private_ip(ip_str: str) -> bool:
    """Return ``True`` if *ip_str* is a private/loopback/link-local address."""
    try:
        addr = _ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)
