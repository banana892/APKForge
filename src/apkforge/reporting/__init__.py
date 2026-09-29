"""APKForge reporting foundation.

The reporting layer is responsible for transforming a
:class:`~apkforge.core.models.Report` into a human- or machine-readable
output format.

Phase 0 establishes:
- A :class:`ReportRenderer` Protocol that all reporters must satisfy.
- A :class:`ConsoleReporter` that renders a minimal summary to the terminal
  using Rich.  This is sufficient for ``apkforge inspect`` (Phase 1+).

Future phases will add:
- JSON reporter
- HTML reporter
- Markdown reporter
- PDF reporter (via external tooling)
- SARIF reporter (for CI/CD integration)

All reporters are registered as :class:`~apkforge.core.plugins.ReporterPlugin`
instances in the plugin registry.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from rich.console import Console
from rich.table import Table

from apkforge.core.models import AnalysisStatus, Report, Severity

__all__ = ["ConsoleReporter", "ReportRenderer"]

_SEVERITY_COLOUR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFORMATIONAL: "dim",
}

_STATUS_COLOUR: dict[AnalysisStatus, str] = {
    AnalysisStatus.COMPLETE: "green",
    AnalysisStatus.PARTIAL: "yellow",
    AnalysisStatus.FAILED: "red",
}


@runtime_checkable
class ReportRenderer(Protocol):
    """Protocol that all APKForge report renderers must satisfy."""

    def render(self, report: Report, *, verbose: bool = False) -> None:
        """Render *report* to the output destination.

        Args:
            report: The report to render.
            verbose: Include additional detail (e.g. evidence snippets).
        """
        ...


class ConsoleReporter:
    """Renders a :class:`~apkforge.core.models.Report` to the terminal.

    Uses Rich for styled, coloured output.

    Args:
        console: Rich console to write to.  Defaults to a new stdout console.
    """

    #: Plugin metadata — satisfies ReporterPlugin protocol
    name: str = "reporting.console"
    version: str = "0.1.0"

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def capabilities(self) -> list[str]:
        return ["reporter", "console"]

    def is_available(self) -> bool:
        return True

    def render(self, report: Report, *, verbose: bool = False) -> None:
        """Render the report to the console.

        Args:
            report: The report to render.
            verbose: When True, include evidence and limitation details.
        """
        c = self._console
        status_colour = _STATUS_COLOUR.get(report.overall_status, "white")

        c.rule("[bold]APKForge Report[/bold]")
        c.print(f"  APK : [bold]{report.apk.path}[/bold]")
        c.print(f"  SHA : {report.apk.sha256 or '(not computed)'}")
        c.print(f"  Status: [{status_colour}]{report.overall_status.upper()}[/{status_colour}]")
        c.print(f"  Generated: {report.generated_at.isoformat()}")

        if report.metadata.package_name:
            c.print(f"  Package: {report.metadata.package_name}")

        c.print()

        # Analysis module summary table
        if report.analysis_results:
            table = Table(title="Analysis Modules", show_header=True, header_style="bold blue")
            table.add_column("Module")
            table.add_column("Status")
            table.add_column("Findings", justify="right")
            table.add_column("Errors", justify="right")

            for result in report.analysis_results:
                sc = _STATUS_COLOUR.get(result.status, "white")
                table.add_row(
                    result.module_name,
                    f"[{sc}]{result.status.upper()}[/{sc}]",
                    str(len(result.findings)),
                    str(len(result.errors)),
                )
            c.print(table)
            c.print()

        # Findings
        findings = report.all_findings
        if findings:
            table = Table(title="Findings", show_header=True, header_style="bold magenta")
            table.add_column("Severity")
            table.add_column("ID")
            table.add_column("Title")
            table.add_column("Confidence")

            for f in findings:
                sev_colour = _SEVERITY_COLOUR.get(f.severity, "white")
                table.add_row(
                    f"[{sev_colour}]{f.severity.upper()}[/{sev_colour}]",
                    f.finding_id,
                    f.title,
                    f.confidence,
                )
            c.print(table)
        else:
            c.print("[dim]No findings.[/dim]")

        if report.limitations and verbose:
            c.print()
            c.print("[bold]Limitations[/bold]")
            for lim in report.limitations:
                c.print(f"  • {lim}")

        c.rule()
