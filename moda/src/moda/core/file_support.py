"""Canonical file-extension support lists used across MODA."""

SUPPORTED_OFFICE_EXTENSIONS = frozenset(
    {
        ".doc",
        ".docx",
        ".docm",
        ".dot",
        ".dotx",
        ".dotm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".xlsb",
        ".xla",
        ".xlam",
        ".xlt",
        ".xltx",
        ".xltm",
        ".xml",
        ".ppt",
        ".pptx",
        ".pptm",
        ".pps",
        ".ppsx",
        ".ppsm",
        ".pot",
        ".potx",
        ".potm",
        ".ppa",
        ".ppam",
        ".rtf",
    }
)

SUPPORTED_EXTENSIONS = SUPPORTED_OFFICE_EXTENSIONS | {".pdf"}
