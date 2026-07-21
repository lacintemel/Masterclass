"""Abstract base class for all MODA analyzers.

Every analyzer in the pipeline inherits from ``BaseAnalyzer`` and must
implement the ``analyze`` method.  The base class provides:

* Structured logging bound to the analyzer name.
* Uniform ``__repr__`` / ``__str__``.
* A template-method ``run()`` that wraps ``analyze()`` with timing,
  error handling, and logging.
* ``can_run()`` gating so analyzers can skip inapplicable file types.
* ``_add_finding()`` / ``_add_ioc()`` convenience helpers.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from moda.core.context import AnalysisContext
from moda.core.enums import FindingSeverity, IOCType
from moda.core.exceptions import AnalyzerError, ResourceLimitError
from moda.core.models import IOC, Finding


class BaseAnalyzer(ABC):
    """Abstract base for all MODA analyzers.

    Subclasses **must** override :meth:`analyze` and :meth:`can_run`.
    They **may** override :meth:`setup` and :meth:`teardown` for
    one-time init/cleanup logic.

    Parameters:
        name: Human-friendly analyzer name (defaults to class name).
        config: Arbitrary keyword configuration forwarded to subclass.
    """

    def __init__(self, name: str | None = None, **config: Any) -> None:
        self._name: str = name or self.__class__.__name__
        self.config: dict[str, Any] = config
        self.logger: logging.Logger = logging.getLogger(
            f"moda.analyzer.{self.name}",
        )

    @property
    def name(self) -> str:
        """Human-friendly analyzer name."""
        return self._name

    @property
    def description(self) -> str:
        """Human-readable summary of the analyzer's purpose."""
        return "Abstract base analyzer"

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Optional one-time initialization (load rules, compile regex…)."""

    def teardown(self) -> None:
        """Optional cleanup hook."""

    # ------------------------------------------------------------------
    # Gating
    # ------------------------------------------------------------------

    def can_run(self, context: AnalysisContext) -> bool:
        """Return ``True`` if this analyzer is applicable to *context*.

        Override in subclasses to restrict execution to specific file
        types or context states.  The default implementation returns
        ``True`` (always run).
        """
        return True

    # ------------------------------------------------------------------
    # Template method
    # ------------------------------------------------------------------

    def run(self, context: AnalysisContext) -> AnalysisContext:
        """Execute the analyzer with timing and error handling.

        This is the public entry point called by the pipeline.
        It delegates to :meth:`analyze` which subclasses implement.
        Skips execution if :meth:`can_run` returns ``False``.

        Returns:
            The (mutated) ``AnalysisContext``.

        Raises:
            AnalyzerError: If ``analyze`` raises an unhandled exception.
        """
        if not self.can_run(context):
            self.logger.debug(
                "Skipping %s — can_run returned False",
                self.name,
            )
            return context

        self.logger.info("Starting %s …", self.name)
        start = time.perf_counter()
        try:
            self.analyze(context)
        except (AnalyzerError, ResourceLimitError):
            raise
        except Exception as exc:
            self.logger.exception("Unhandled error in %s", self.name)
            raise AnalyzerError(
                message=str(exc),
                analyzer_name=self.name,
                original_error=exc,
            ) from exc
        finally:
            elapsed = time.perf_counter() - start
            self.logger.info(
                "%s completed in %.3f s",
                self.name,
                elapsed,
            )
        return context

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> None:
        """Perform analysis and mutate *context* in place.

        Implementations **must not** return a value; they communicate
        results exclusively through ``context``.
        """

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def _add_finding(
        self,
        context: AnalysisContext,
        title: str,
        description: str,
        severity: FindingSeverity,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Create a :class:`Finding` and append it to *context*."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            analyzer=self.name,
            details=details or {},
        )
        context.add_finding(finding)

    def _add_ioc(
        self,
        context: AnalysisContext,
        ioc_type: IOCType,
        value: str,
        source: str | None = None,
        context_info: str = "",
    ) -> None:
        """Create an :class:`IOC` and add it to *context*."""
        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            source=source or self.name,
            context=context_info,
        )
        context.add_ioc(ioc)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    def __str__(self) -> str:
        return self.name
