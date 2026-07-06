"""MODA core enumerations.

Defines all enumeration types used throughout the MODA analysis pipeline,
including file types, risk levels, finding severities, and IOC categories.
"""

from __future__ import annotations

from enum import Enum, IntEnum, unique


@unique
class FileType(Enum):
    """Supported document file types for analysis.

    Each variant maps to a specific Office or PDF format that MODA can inspect.
    UNKNOWN is used when the file type cannot be determined.
    """

    OLE_DOC = "ole_doc"
    OLE_XLS = "ole_xls"
    OLE_PPT = "ole_ppt"
    OOXML_DOCX = "ooxml_docx"
    OOXML_DOCM = "ooxml_docm"
    OOXML_XLSX = "ooxml_xlsx"
    OOXML_XLSM = "ooxml_xlsm"
    OOXML_PPTX = "ooxml_pptx"
    OOXML_PPTM = "ooxml_pptm"
    RTF = "rtf"
    PDF = "pdf"
    UNKNOWN = "unknown"

    @property
    def is_ole(self) -> bool:
        """Return True if this file type is an OLE compound binary format."""
        return self in {FileType.OLE_DOC, FileType.OLE_XLS, FileType.OLE_PPT}

    @property
    def is_ooxml(self) -> bool:
        """Return True if this file type is an OOXML (ZIP-based Office) format."""
        return self in {
            FileType.OOXML_DOCX,
            FileType.OOXML_DOCM,
            FileType.OOXML_XLSX,
            FileType.OOXML_XLSM,
            FileType.OOXML_PPTX,
            FileType.OOXML_PPTM,
        }

    @property
    def is_macro_enabled(self) -> bool:
        """Return True if this file type can contain VBA macros."""
        return self in {
            FileType.OLE_DOC,
            FileType.OLE_XLS,
            FileType.OLE_PPT,
            FileType.OOXML_DOCM,
            FileType.OOXML_XLSM,
            FileType.OOXML_PPTM,
        }

    @property
    def is_pdf(self) -> bool:
        """Return True if this file type is a PDF."""
        return self is FileType.PDF

    @property
    def label(self) -> str:
        """Human-readable label for display purposes."""
        labels: dict[FileType, str] = {
            FileType.OLE_DOC: "OLE Word Document (.doc)",
            FileType.OLE_XLS: "OLE Excel Spreadsheet (.xls)",
            FileType.OLE_PPT: "OLE PowerPoint Presentation (.ppt)",
            FileType.OOXML_DOCX: "OOXML Word Document (.docx)",
            FileType.OOXML_DOCM: "OOXML Word Macro-Enabled (.docm)",
            FileType.OOXML_XLSX: "OOXML Excel Spreadsheet (.xlsx)",
            FileType.OOXML_XLSM: "OOXML Excel Macro-Enabled (.xlsm)",
            FileType.OOXML_PPTX: "OOXML PowerPoint Presentation (.pptx)",
            FileType.OOXML_PPTM: "OOXML PowerPoint Macro-Enabled (.pptm)",
            FileType.RTF: "Rich Text Format (.rtf)",
            FileType.PDF: "PDF Document (.pdf)",
            FileType.UNKNOWN: "Unknown File Type",
        }
        return labels[self]


@unique
class RiskLevel(IntEnum):
    """Overall risk assessment level for an analyzed document.

    Ordered from lowest to highest severity so comparisons work naturally.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @property
    def color(self) -> str:
        """ANSI/Rich color name for terminal output."""
        colors: dict[RiskLevel, str] = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }
        return colors[self]

    @property
    def label(self) -> str:
        """Human-readable label for display and reports."""
        labels: dict[RiskLevel, str] = {
            RiskLevel.LOW: "Low Risk",
            RiskLevel.MEDIUM: "Medium Risk",
            RiskLevel.HIGH: "High Risk",
            RiskLevel.CRITICAL: "Critical Risk",
        }
        return labels[self]


@unique
class FindingSeverity(IntEnum):
    """Severity level for individual findings produced by analyzers.

    Ordered from lowest to highest so comparisons (e.g. severity >= HIGH)
    work correctly. Each severity carries a numeric weight used in scoring.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def color(self) -> str:
        """ANSI/Rich color name for terminal output."""
        colors: dict[FindingSeverity, str] = {
            FindingSeverity.INFO: "blue",
            FindingSeverity.LOW: "green",
            FindingSeverity.MEDIUM: "yellow",
            FindingSeverity.HIGH: "red",
            FindingSeverity.CRITICAL: "bold red",
        }
        return colors[self]

    @property
    def weight(self) -> int:
        """Numeric weight used by the scoring engine.

        Higher weights contribute more to the overall risk score.
        """
        weights: dict[FindingSeverity, int] = {
            FindingSeverity.INFO: 0,
            FindingSeverity.LOW: 5,
            FindingSeverity.MEDIUM: 15,
            FindingSeverity.HIGH: 30,
            FindingSeverity.CRITICAL: 50,
        }
        return weights[self]


@unique
class IOCType(Enum):
    """Types of Indicators of Compromise (IOCs) that MODA can extract.

    Each variant represents a distinct category of observable artifact
    that may indicate malicious behaviour.
    """

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    COMMAND = "command"
    FILE_PATH = "file_path"
    EXECUTABLE_NAME = "executable_name"

    @property
    def label(self) -> str:
        """Human-readable label for display."""
        return self.value.replace("_", " ").title()
