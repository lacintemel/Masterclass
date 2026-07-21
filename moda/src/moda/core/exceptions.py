"""MODA custom exception hierarchy.

All MODA-specific exceptions inherit from MODAError, enabling callers to
catch the base class for broad error handling or a specific subclass for
targeted recovery.
"""

from __future__ import annotations

from pathlib import Path


class MODAError(Exception):
    """Base exception for all MODA errors.

    Every MODA-specific exception inherits from this class so that callers
    can use ``except MODAError`` as a catch-all for library errors while
    still distinguishing them from unrelated Python exceptions.
    """

    def __init__(self, message: str = "An error occurred in MODA") -> None:
        self.message = message
        super().__init__(self.message)


class AnalyzerError(MODAError):
    """Raised when an individual analyzer encounters an unrecoverable error.

    Attributes:
        analyzer_name: The name of the analyzer that failed.
        original_error: The underlying exception, if any.
    """

    def __init__(
        self,
        message: str,
        analyzer_name: str = "unknown",
        original_error: Exception | None = None,
    ) -> None:
        self.analyzer_name = analyzer_name
        self.original_error = original_error
        full_message = f"Analyzer '{analyzer_name}' failed: {message}"
        if original_error:
            full_message += f" (caused by {type(original_error).__name__}: {original_error})"
        super().__init__(full_message)


class UnsupportedFileTypeError(MODAError):
    """Raised when a file's type is not supported by MODA.

    Attributes:
        file_path: Path to the unsupported file.
        detected_type: The MIME type or description that was detected.
    """

    def __init__(
        self,
        file_path: Path | str,
        detected_type: str = "unknown",
    ) -> None:
        self.file_path = Path(file_path)
        self.detected_type = detected_type
        super().__init__(
            f"Unsupported file type '{detected_type}' for file: {self.file_path}"
        )


class ConfigurationError(MODAError):
    """Raised when a configuration file is missing, malformed, or invalid.

    Attributes:
        config_path: Path to the problematic configuration file, if known.
    """

    def __init__(
        self,
        message: str,
        config_path: Path | str | None = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path else None
        prefix = f"Configuration error in '{self.config_path}': " if self.config_path else ""
        super().__init__(f"{prefix}{message}")


class ReportingError(MODAError):
    """Raised when report generation or output fails.

    Attributes:
        reporter_name: The reporter that encountered the error.
    """

    def __init__(
        self,
        message: str,
        reporter_name: str = "unknown",
    ) -> None:
        self.reporter_name = reporter_name
        super().__init__(f"Reporter '{reporter_name}' failed: {message}")


class YaraError(MODAError):
    """Raised when YARA rule compilation or scanning fails.

    Attributes:
        rule_path: Path to the YARA rule file that caused the error, if known.
    """

    def __init__(
        self,
        message: str,
        rule_path: Path | str | None = None,
    ) -> None:
        self.rule_path = Path(rule_path) if rule_path else None
        prefix = f"YARA error in '{self.rule_path}': " if self.rule_path else "YARA error: "
        super().__init__(f"{prefix}{message}")


class FileTooLargeError(MODAError):
    """Raised when a file exceeds the configured maximum size for analysis.

    Attributes:
        file_path: Path to the oversized file.
        file_size: Actual file size in bytes.
        max_size: Maximum allowed size in bytes.
    """

    def __init__(
        self,
        file_path: Path | str,
        file_size: int,
        max_size: int,
    ) -> None:
        self.file_path = Path(file_path)
        self.file_size = file_size
        self.max_size = max_size
        file_mb = file_size / (1024 * 1024)
        max_mb = max_size / (1024 * 1024)
        super().__init__(
            f"File '{self.file_path.name}' is too large for analysis: "
            f"{file_mb:.1f} MB (limit: {max_mb:.1f} MB)"
        )


class ResourceLimitError(MODAError):
    """Raised when decompression or extraction exceeds a safety budget."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Analysis resource limit exceeded: {message}")
