"""Abstract base class for all MODA reporters.

Every reporter must inherit from :class:`BaseReporter` and implement the
:meth:`generate` method.  The base class provides a default :meth:`save`
implementation that writes the generated output to a file.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from moda.core.models import AnalysisResult

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """Abstract base class that defines the reporter contract.

    All reporters share two responsibilities:

    1. **generate** — transform an :class:`AnalysisResult` into a
       report payload (``str`` for text formats, ``bytes`` for binary).
    2. **save** — persist the generated report to the filesystem.

    Subclasses *must* implement :meth:`generate` and *should* set
    :attr:`format_name` to a short identifier (e.g. ``"json"``).

    Parameters:
        config: Arbitrary keyword configuration forwarded from the
            reporter factory.
    """

    #: Short, machine-friendly format identifier (override in subclass).
    format_name: str = "base"

    #: Default file extension including the leading dot.
    file_extension: str = ".txt"

    def __init__(self, **config: Any) -> None:
        self.config = config
        self.logger = logging.getLogger(
            f"moda.reporting.{self.format_name}",
        )

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def generate(self, result: AnalysisResult) -> str | bytes:
        """Transform an analysis result into a report payload.

        Args:
            result: The completed analysis result to render.

        Returns:
            A ``str`` for text-based formats (JSON, HTML, console)
            or ``bytes`` for binary formats (PDF).
        """

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def save(
        self,
        result: AnalysisResult,
        output_path: str | Path,
    ) -> None:
        """Generate the report and write it to *output_path*.

        The parent directories are created automatically if they do not
        already exist.

        Args:
            result: The completed analysis result.
            output_path: Destination path for the report file.

        Raises:
            OSError: If the file cannot be written.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = self.generate(result)

        if isinstance(payload, bytes):
            output_path.write_bytes(payload)
        else:
            output_path.write_text(payload, encoding="utf-8")

        self.logger.info(
            "Report saved: %s (%s, %d bytes)",
            output_path,
            self.format_name,
            output_path.stat().st_size,
        )

    def get_default_filename(self, result: AnalysisResult) -> str:
        """Produce a sensible default filename for the report.

        The name is derived from the analysed file's name and the
        reporter's format extension.

        Args:
            result: The analysis result (used for file naming).

        Returns:
            A filename string such as ``"malware.docm_report.html"``.
        """
        stem = Path(result.file_name).stem if result.file_name else "report"
        return f"{stem}_report{self.file_extension}"

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def severity_color(severity: str) -> str:
        """Map a severity string to a CSS / terminal colour name.

        Args:
            severity: One of ``critical``, ``high``, ``medium``,
                ``low``, ``info``.

        Returns:
            A colour keyword suitable for terminal or CSS use.
        """
        return {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(severity.lower(), "white")

    @staticmethod
    def risk_level_emoji(level: str) -> str:
        """Return an emoji representing the risk level.

        Args:
            level: Risk level string.

        Returns:
            A Unicode emoji character.
        """
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "clean": "🟢",
        }.get(level.lower(), "⚪")

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} format={self.format_name!r}>"
