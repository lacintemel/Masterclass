from __future__ import annotations

from importlib import import_module
from typing import Any

from ..core.models import AnalysisResult
from .base import BaseReporter
from .view_model import build_report_view

try:
    Console: Any = import_module("rich.console").Console
    Panel: Any = import_module("rich.panel").Panel
    Table: Any = import_module("rich.table").Table
except ImportError:  # pragma: no cover - depends on optional CLI dependency
    Console = None
    Table = None
    Panel = None


class ConsoleReporter(BaseReporter):
    format_name = "console"

    def __init__(self, use_color: bool = True):
        self.console = Console(color_system="auto" if use_color else None) if Console else None

    def generate(self, result: AnalysisResult) -> str:
        view = build_report_view(result)
        if self.console is None:
            return self._generate_plain(result)

        # Banner
        self.console.print(
            Panel.fit(
                "[bold cyan]MODA - Malicious Office Document Analyzer[/bold cyan]",
                border_style="cyan",
            )
        )

        # Risk Score
        risk_color = {
            "low": "green",
            "medium": "yellow",
            "high": "orange3",
            "critical": "red",
        }.get(result.risk_level, "white")

        self.console.print(
            f"\n[bold]Overall Risk:[/bold] [{risk_color}]{result.risk_level.upper()} ({result.risk_score}/100)[/{risk_color}]"
        )
        self.console.print(f"[bold]Analysis completeness:[/bold] {view['analysis_status'].upper()}")

        # File Info
        info_table = Table(title="File Information", show_header=False)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value")
        info_table.add_row("Path", result.file_path)
        info_table.add_row("Type", result.file_type)
        info_table.add_row("MIME", result.mime_type)
        info_table.add_row("Size", f"{result.file_size} bytes")
        for algo, h in {
            "MD5": result.file_hash_md5,
            "SHA1": result.file_hash_sha1,
            "SHA256": result.file_hash_sha256,
        }.items():
            info_table.add_row(algo, h)
        self.console.print(info_table)

        # Findings
        if result.findings:
            self.console.print("\n[bold]Findings:[/bold]")
            for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
                sev_color = "red" if f.severity.name.lower() in ("critical", "high") else "yellow"
                self.console.print(
                    f"[{sev_color}][{f.severity.name}][/{sev_color}] {f.title}: {f.description}"
                )
                if f.details:
                    self.console.print(f"    Details: {f.details}")

        # YARA
        if result.yara_matches:
            self.console.print("\n[bold]YARA Matches:[/bold]")
            for ym in result.yara_matches:
                self.console.print(f"[red]{ym.rule_name}[/red]")

        # IOCs
        if result.iocs:
            self.console.print("\n[bold]Extracted IOCs:[/bold]")
            for ioc in result.iocs:
                self.console.print(f"[cyan]{ioc.ioc_type.name}:[/cyan] {ioc.value}")
        if view["errors"]:
            self.console.print("\n[bold red]Analyzer warnings/errors:[/bold red]")
            for error in view["errors"]:
                self.console.print(f"[red]- {error}[/red]")

        return ""  # Console reporter prints directly

    def _generate_plain(self, result: AnalysisResult) -> str:
        """Render a console report without optional rich formatting."""
        view = build_report_view(result)
        lines = [
            "MODA - Malicious Office Document Analyzer",
            f"Overall Risk: {result.risk_level.upper()} ({result.risk_score}/100)",
            f"Analysis Completeness: {view['analysis_status'].upper()}",
            "",
            "File Information",
            f"  Path: {result.file_path}",
            f"  Type: {result.file_type}",
            f"  MIME: {result.mime_type}",
            f"  Size: {result.file_size} bytes",
            f"  MD5: {result.file_hash_md5}",
            f"  SHA1: {result.file_hash_sha1}",
            f"  SHA256: {result.file_hash_sha256}",
        ]
        if result.findings:
            lines.append("")
            lines.append("Findings")
            for finding in sorted(result.findings, key=lambda item: item.severity, reverse=True):
                lines.append(f"  [{finding.severity.name}] {finding.title}: {finding.description}")
        if result.yara_matches:
            lines.append("")
            lines.append("YARA Matches")
            lines.extend(f"  {match.rule_name}" for match in result.yara_matches)
        if result.iocs:
            lines.append("")
            lines.append("Extracted IOCs")
            lines.extend(f"  {ioc.ioc_type.name}: {ioc.value}" for ioc in result.iocs)
        if view["errors"]:
            lines.extend(["", "Analyzer Warnings/Errors"])
            lines.extend(f"  {error}" for error in view["errors"])

        report = "\n".join(lines)
        print(report)
        return report
