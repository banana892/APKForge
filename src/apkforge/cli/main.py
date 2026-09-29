"""APKForge CLI — main entry point.

Architecture notes
------------------
The CLI is **thin**.  All it does is:

1. Parse arguments (Typer handles this).
2. Set up logging / configuration.
3. Delegate to a core service.

Business logic must NOT live here.  The CLI layer exists so that a future
GUI or API can use the exact same core services without going through Typer.

Command structure (Phase 0 — stubs)::

    apkforge
    ├── version          — print version and exit
    ├── inspect  <apk>   — (stub) basic APK metadata
    ├── analyze  <apk>   — (stub) full security/privacy analysis
    ├── scan     <apk>   — (stub) quick security scan
    ├── diff     <a> <b> — (stub) compare two APKs
    ├── modify   <apk>   — (stub) apply modifications
    └── verify   <apk>   — (stub) verify a built APK
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import apkforge
from apkforge.core.config import load_default_config
from apkforge.core.logging import setup_logging
from apkforge.core.models import AnalysisStatus, Severity

if TYPE_CHECKING:
    from apkforge.diff.models import DiffResult
    from apkforge.inspection import InspectionResult
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import FullAnalysisResult, SecurityResult

app = typer.Typer(
    name="apkforge",
    help=(
        "APKForge — Android APK Security & Modification Workbench.\n\n"
        "A local-first workbench for static analysis, security review, privacy auditing,\n"
        "comparison, and controlled modification of Android APK files.\n\n"
        "[dim]Phase 0: Foundation — most commands are not yet implemented.[/dim]"
    ),
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,  # Avoid leaking APK data in tracebacks
)

_console = Console()

# ---------------------------------------------------------------------------
# Shared options callback — runs before every command
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        _console.print(f"APKForge [bold]{apkforge.__version__}[/bold]")
        raise typer.Exit()


@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable DEBUG logging."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress INFO output."),
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """APKForge global options."""
    cfg = load_default_config()
    if verbose:
        setup_logging(level="DEBUG")
    elif quiet:
        setup_logging(level="ERROR")
    else:
        setup_logging(level=cfg.log_level)


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@app.command("version")
def cmd_version() -> None:
    """Print the APKForge version and exit."""
    _console.print(
        Panel(
            f"[bold green]APKForge[/bold green] [white]{apkforge.__version__}[/white]",
            subtitle="Android APK Security & Modification Workbench",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# inspect command
# ---------------------------------------------------------------------------


def _render_inspect_summary(
    result: InspectionResult,
    *,
    show_manifest: bool = False,
    show_dex: bool = False,
    show_native: bool = False,
    show_network: bool = False,
    show_resources: bool = False,
    show_assets: bool = False,
    show_embedded: bool = False,
    show_obfuscation: bool = False,
) -> None:
    """Format and print a rich inspection summary to the console."""
    table = Table(
        title="APKForge Package Inspection",
        show_header=False,
        box=None,
        padding=(0, 2),
    )
    table.add_column("Key", style="bold cyan", width=22)
    table.add_column("Value", style="white")

    # Status color
    if result.status == AnalysisStatus.COMPLETE:
        status_str = f"[bold green]{result.status.value.upper()}[/bold green]"
    elif result.status == AnalysisStatus.PARTIAL:
        status_str = f"[bold yellow]{result.status.value.upper()}[/bold yellow]"
    else:
        status_str = f"[bold red]{result.status.value.upper()}[/bold red]"

    input_name = (
        result.input_path.name
        if result.input_path
        else (result.package.input_path.name if result.package else "N/A")
    )
    table.add_row("Input", input_name)
    pkg_type_str = result.package_type.value.upper() if result.package_type else "APK"
    table.add_row("Type", pkg_type_str)
    fmt_str = (
        result.package.input_format.value
        if (result.package and result.package.input_format)
        else "single_apk"
    )
    table.add_row("Format", fmt_str)
    table.add_row("Status", status_str)
    table.add_section()

    pkg_name = result.metadata.package_name or (
        result.manifest.package_name if result.manifest else None
    )
    table.add_row("Package", pkg_name or "[dim]N/A[/dim]")
    ver_name = result.metadata.version_name or (
        result.manifest.version_name if result.manifest else None
    )
    table.add_row("Version", ver_name or "[dim]N/A[/dim]")
    vcode = (
        result.metadata.version_code
        if result.metadata.version_code is not None
        else (result.manifest.version_code if result.manifest else None)
    )
    table.add_row("Version Code", str(vcode) if vcode is not None else "[dim]N/A[/dim]")
    min_sdk = (
        result.metadata.min_sdk
        if result.metadata.min_sdk is not None
        else (result.manifest.min_sdk if result.manifest else None)
    )
    table.add_row("Min SDK", str(min_sdk) if min_sdk is not None else "[dim]N/A[/dim]")
    tgt_sdk = (
        result.metadata.target_sdk
        if result.metadata.target_sdk is not None
        else (result.manifest.target_sdk if result.manifest else None)
    )
    table.add_row("Target SDK", str(tgt_sdk) if tgt_sdk is not None else "[dim]N/A[/dim]")
    if result.metadata.compile_sdk is not None:
        table.add_row("Compile SDK", str(result.metadata.compile_sdk))
    if result.metadata.application_label:
        table.add_row("Application Label", result.metadata.application_label)
    if result.metadata.application_debuggable is not None:
        table.add_row("Debuggable", str(result.metadata.application_debuggable))

    table.add_section()
    if result.hashes:
        table.add_row("SHA-256", result.hashes.sha256)
        table.add_row("SHA-1", result.hashes.sha1)
        table.add_row("MD5", result.hashes.md5)
    else:
        table.add_row("Hashes", "[dim]N/A[/dim]")

    table.add_section()
    inv = result.inventory
    table.add_row("Manifest", f"{inv.manifest_count}")
    table.add_row("DEX files", f"{inv.dex_count}")
    table.add_row("Native libraries", f"{inv.native_library_count}")
    table.add_row("Resource files", f"{inv.resource_count}")
    table.add_row("Assets", f"{inv.asset_count}")
    if inv.embedded_apk_count:
        table.add_row("Embedded APKs", f"{inv.embedded_apk_count}")
    if inv.embedded_dex_count:
        table.add_row("Embedded DEX", f"{inv.embedded_dex_count}")
    if inv.executable_file_count:
        table.add_row("Executable files", f"{inv.executable_file_count}")
    table.add_row("Signing certificates", f"{inv.certificate_count}")
    if result.package and result.package.splits:
        table.add_row("Split APKs", str(len(result.package.splits)))
    table.add_row("Total archive files", f"{inv.total_file_count}")
    table.add_row("Analysis warnings", str(len(result.warnings)))

    _console.print(table)

    # Detailed sections on request
    if show_manifest and result.manifest:
        _console.print("\n[bold cyan]Manifest Inspection:[/bold cyan]")
        _console.print(f"  Permissions ({len(result.manifest.permissions)}):")
        for perm in result.manifest.permissions:
            prot = f" ({perm.protection_level})" if perm.protection_level else ""
            _console.print(f"    • {perm.name}{prot}")

        _console.print(f"  Activities ({len(result.manifest.activities)}):")
        for act in result.manifest.activities:
            exp = " [green](exported)[/green]" if act.exported else ""
            _console.print(f"    • {act.name}{exp}")

        _console.print(f"  Services ({len(result.manifest.services)}):")
        for srv in result.manifest.services:
            exp = " [green](exported)[/green]" if srv.exported else ""
            _console.print(f"    • {srv.name}{exp}")

        _console.print(f"  Broadcast Receivers ({len(result.manifest.receivers)}):")
        for rcv in result.manifest.receivers:
            exp = " [green](exported)[/green]" if rcv.exported else ""
            _console.print(f"    • {rcv.name}{exp}")

        _console.print(f"  Content Providers ({len(result.manifest.providers)}):")
        for prv in result.manifest.providers:
            auth = f" (auth: {prv.authorities})" if prv.authorities else ""
            _console.print(f"    • {prv.name}{auth}")

    if show_dex and result.dex:
        _console.print("\n[bold cyan]DEX Inspection:[/bold cyan]")
        _console.print(f"  Total classes: {result.dex.total_classes}")
        _console.print(f"  Total methods: {result.dex.total_methods}")
        _console.print(f"  Total fields:  {result.dex.total_fields}")
        for df in result.dex.dex_files:
            _console.print(
                f"  • [bold]{df.name}[/bold] ({df.file_size} bytes, version {df.dex_version}): "
                f"{df.class_count} classes, {df.method_count} methods, {df.field_count} fields"
            )

    if show_native and result.native:
        _console.print("\n[bold cyan]Native Library Inspection:[/bold cyan]")
        _console.print(f"  ABIs detected: {', '.join(result.native.abis_found) or 'none'}")
        for lib in result.native.libraries:
            abi = f" [{lib.abi}]" if lib.abi else ""
            mach = f" ({lib.machine_type})" if lib.machine_type else ""
            _console.print(f"  • [bold]{lib.path}[/bold]{abi}{mach} — {lib.size} bytes")

    if show_network and result.network:
        _console.print("\n[bold cyan]Network Extraction (Static):[/bold cyan]")
        _console.print(f"  Extracted URLs ({len(result.network.urls)}):")
        for u in result.network.urls[:20]:
            src = f" [dim]({u.source.file})[/dim]" if u.source else ""
            _console.print(f"    • {u.url}{src}")
        if len(result.network.urls) > 20:
            _console.print(f"    ... and {len(result.network.urls) - 20} more URLs")

        _console.print(f"  Extracted Domains ({len(result.network.domains)}):")
        for d in result.network.domains[:20]:
            _console.print(f"    • {d.domain}")

        _console.print(f"  Extracted IP Addresses ({len(result.network.ip_addresses)}):")
        for ip in result.network.ip_addresses:
            _console.print(f"    • {ip.address} (IPv{ip.version})")

    if show_resources and result.resources:
        _console.print("\n[bold cyan]Resource Structure Inspection:[/bold cyan]")
        _console.print(f"  resources.arsc present: {result.resources.has_resources_arsc}")
        _console.print(f"  Total resource files:   {result.resources.resource_file_count}")
        for rc in result.resources.resource_types:
            _console.print(f"    • {rc.resource_type}: {rc.count}")

    if show_assets and result.assets:
        _console.print("\n[bold cyan]Asset Inspection:[/bold cyan]")
        _console.print(f"  Total assets: {result.assets.total_assets}")
        for asset in result.assets.assets[:25]:
            mime = f" [{asset.mime_type}]" if asset.mime_type else ""
            ent = f" (entropy: {asset.entropy})" if asset.entropy is not None else ""
            _console.print(f"    • {asset.path} ({asset.size} bytes){mime}{ent}")

    if show_embedded and result.embedded:
        _console.print("\n[bold cyan]Embedded Files Detection:[/bold cyan]")
        if result.embedded.embedded_apks:
            _console.print(f"  Embedded APKs ({len(result.embedded.embedded_apks)}):")
            for ea in result.embedded.embedded_apks:
                _console.print(f"    • {ea.path} ({ea.size} bytes)")
        if result.embedded.embedded_dex:
            _console.print(f"  Additional DEX files ({len(result.embedded.embedded_dex)}):")
            for ed in result.embedded.embedded_dex:
                _console.print(f"    • {ed.path} ({ed.size} bytes)")
        if result.embedded.executable_files:
            _console.print(f"  Executable-looking files ({len(result.embedded.executable_files)}):")
            for ex in result.embedded.executable_files:
                _console.print(f"    • {ex.path} [{ex.detected_type}] ({ex.size} bytes)")

    if show_obfuscation and result.obfuscation:
        _console.print("\n[bold cyan]Obfuscation Indicators (Structural Only):[/bold cyan]")
        obs = result.obfuscation
        ind = obs.indicators
        likely = "[yellow]Yes[/yellow]" if obs.is_likely_obfuscated else "[green]No[/green]"
        _console.print(f"  Likely obfuscated: {likely}")
        _console.print(f"  Short class names (<= 2 chars): {ind.short_class_name_pct:.1f}%")
        _console.print(f"  Short method names (<= 2 chars): {ind.short_method_name_pct:.1f}%")
        _console.print(f"  Short field names (<= 2 chars):  {ind.short_field_name_pct:.1f}%")
        for o in ind.observations:
            _console.print(f"    • {o}")

    if result.package and result.package.splits:
        _console.print("\n[bold cyan]Contained Splits:[/bold cyan]")
        for s in result.package.splits:
            _console.print(f"  • [bold]{s.name}[/bold] ({s.split_type.value})")

    if result.limitations:
        _console.print("\n[bold magenta]Analysis Limitations:[/bold magenta]")
        for lim in result.limitations:
            _console.print(f"  [magenta]*[/magenta] {lim}")

    if result.warnings:
        _console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            _console.print(f"  [yellow]![/yellow] {w}")

    if result.errors:
        _console.print("\n[bold red]Errors:[/bold red]")
        for e in result.errors:
            _console.print(f"  [red]✗[/red] {e}")


@app.command("inspect")
def cmd_inspect(
    apk: Path = typer.Argument(
        ...,
        metavar="PATH",
        help="Path to the APK, APKS, XAPK file or split APK directory to inspect.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output normalized machine-readable JSON.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text | json.",
    ),
    keep_workspace: bool = typer.Option(
        False,
        "--keep-workspace",
        help="Retain workspace directory after inspection.",
    ),
    manifest: bool = typer.Option(
        False,
        "--manifest",
        help="Show detailed manifest inspection (permissions, components, intent filters).",
    ),
    dex: bool = typer.Option(
        False,
        "--dex",
        help="Show detailed DEX inspection (classes, methods, fields, API refs).",
    ),
    native: bool = typer.Option(
        False,
        "--native",
        help="Show detailed native library inspection (ELF, ABIs, symbols).",
    ),
    network: bool = typer.Option(
        False,
        "--network",
        help="Show static network extraction (URLs, domains, IP addresses).",
    ),
    resources: bool = typer.Option(
        False,
        "--resources",
        help="Show resource structure inventory.",
    ),
    assets: bool = typer.Option(
        False,
        "--assets",
        help="Show asset directory inventory with Shannon entropy.",
    ),
    embedded: bool = typer.Option(
        False,
        "--embedded",
        help="Show embedded APKs, DEX, and executable-looking files.",
    ),
    obfuscation: bool = typer.Option(
        False,
        "--obfuscation",
        help="Show structural obfuscation indicators.",
    ),
) -> None:
    """Inspect APK metadata, certificates, hashes, and structural inventory."""
    from apkforge.core.models import AnalysisStatus
    from apkforge.inspection.engine import InspectionEngine

    engine = InspectionEngine()
    result = engine.inspect(apk, keep_workspace=keep_workspace)

    if json_output or output_format.lower() == "json":
        _console.print(result.model_dump_json(indent=2), soft_wrap=True)
    else:
        _render_inspect_summary(
            result,
            show_manifest=manifest,
            show_dex=dex,
            show_native=native,
            show_network=network,
            show_resources=resources,
            show_assets=assets,
            show_embedded=embedded,
            show_obfuscation=obfuscation,
        )

    if result.status == AnalysisStatus.FAILED:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


@app.command("analyze")
def cmd_analyze(
    apk: Path = typer.Argument(
        ...,
        metavar="APK",
        help="Path to the APK file to analyse across inspection, privacy, and security.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON format.",
    ),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | json."),
    output_file: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    keep_workspace: bool = typer.Option(
        False,
        "--keep-workspace",
        help="Retain workspace directory after analysis.",
    ),
) -> None:
    """Run unified analysis orchestrating Inspection, Privacy, and Security engines."""
    from apkforge.inspection.engine import InspectionEngine
    from apkforge.privacy.engine import PrivacyEngine
    from apkforge.security.engine import SecurityEngine
    from apkforge.security.models import FullAnalysisResult

    cfg = load_default_config()
    setup_logging(cfg.log_level)

    # 1. Inspection
    insp_engine = InspectionEngine(cfg)
    insp_res = insp_engine.inspect(apk, keep_workspace=keep_workspace)

    # 2. Privacy
    priv_engine = PrivacyEngine(config=cfg)
    priv_res = priv_engine.analyze(insp_res)

    # 3. Security
    sec_engine = SecurityEngine(config=cfg)
    sec_res = sec_engine.analyze(insp_res, privacy=priv_res)

    total_sdks = (
        priv_res.advertising.total_advertising_sdks
        + priv_res.analytics.total_analytics_sdks
        + priv_res.trackers.total_trackers
        + priv_res.telemetry.total_telemetry_sdks
    )

    full_result = FullAnalysisResult(
        status=sec_res.status,
        package_name=sec_res.package_name,
        version_name=sec_res.version_name,
        version_code=sec_res.version_code,
        inspection_status=insp_res.status,
        privacy_status=priv_res.status,
        security_status=sec_res.security_status,
        inspection_summary={
            "total_files": insp_res.inventory.total_file_count,
            "dex_files": insp_res.inventory.dex_count,
            "native_libraries": insp_res.inventory.native_library_count,
        },
        privacy_summary={
            "declared_permissions": len(priv_res.permissions.declared_permissions),
            "detected_sdks": total_sdks,
            "total_endpoints": priv_res.endpoints.total_endpoints,
        },
        security_summary=sec_res.summary,
        security_findings=sec_res.findings,
        warnings=sec_res.warnings,
        errors=sec_res.errors,
        limitations=sec_res.limitations,
    )

    if json_output or output_format.lower() == "json":
        json_str = full_result.model_dump_json(indent=2)
        if output_file:
            output_file.write_text(json_str, encoding="utf-8")
            _console.print(f"[green]Report written to {output_file}[/green]")
        else:
            _console.print(json_str, soft_wrap=True)
    else:
        _render_full_analysis_summary(full_result, sec_res, priv_res, insp_res)
        if output_file:
            output_file.write_text(full_result.model_dump_json(indent=2), encoding="utf-8")
            _console.print(f"[green]JSON report also saved to {output_file}[/green]")

    if full_result.status == AnalysisStatus.FAILED:
        raise typer.Exit(code=1)


def _render_full_analysis_summary(
    full_result: FullAnalysisResult,
    sec_res: SecurityResult,
    priv_res: PrivacyResult,
    insp_res: InspectionResult,
) -> None:
    """Render unified full analysis summary to console."""
    pkg_str = full_result.package_name or "Unknown Package"
    ver_str = f"v{full_result.version_name}" if full_result.version_name else ""
    code_str = f"({full_result.version_code})" if full_result.version_code else ""

    _console.print(
        Panel(
            f"[bold]{pkg_str}[/bold] {ver_str} {code_str}\n\n"
            f"Inspection Status: [green]{full_result.inspection_status.value.upper()}[/green]\n"
            f"Privacy Status:    [green]{full_result.privacy_status.value.upper()}[/green]\n"
            f"Security Status:   [bold red]{full_result.security_status.value.upper()}[/bold red]",
            title="[bold magenta]APKForge Unified Analysis[/bold magenta]",
            expand=False,
        )
    )

    # Core Inventory Table
    table = Table(title="Inventory & Privacy Summary", show_header=True, box=None)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total Files", str(full_result.inspection_summary.get("total_files", 0)))
    table.add_row("DEX Files", str(full_result.inspection_summary.get("dex_files", 0)))
    table.add_row(
        "Native Libraries", str(full_result.inspection_summary.get("native_libraries", 0))
    )
    table.add_row(
        "Declared Permissions", str(full_result.privacy_summary.get("declared_permissions", 0))
    )
    table.add_row(
        "Detected SDKs (Trackers/Ads)", str(full_result.privacy_summary.get("detected_sdks", 0))
    )
    table.add_row("Network Endpoints", str(full_result.privacy_summary.get("total_endpoints", 0)))
    _console.print(table)
    _console.print()

    # Security Summary
    sum_info = full_result.security_summary
    sec_table = Table(title="Security Findings Summary", show_header=True, box=None)
    sec_table.add_column("Severity", style="bold")
    sec_table.add_column("Count", justify="right")
    sec_table.add_row("[bold red]Critical[/bold red]", str(sum_info.critical_count))
    sec_table.add_row("[red]High[/red]", str(sum_info.high_count))
    sec_table.add_row("[yellow]Medium[/yellow]", str(sum_info.medium_count))
    sec_table.add_row("[cyan]Low[/cyan]", str(sum_info.low_count))
    sec_table.add_row("[dim]Info[/dim]", str(sum_info.info_count))
    _console.print(sec_table)
    _console.print()

    # Prominent High & Critical Findings
    prominent = [
        f for f in full_result.security_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if prominent:
        _console.print("[bold red]CRITICAL & HIGH SECURITY FINDINGS[/bold red]")
        _console.print("─" * 50)
        for f in prominent:
            _console.print(
                f"[bold red][{f.severity.value.upper()}][/bold red] [bold]{f.id}[/bold]: {f.title}"
            )
            _console.print(f"  [bold]Assessment:[/bold] {f.assessment}")
            if f.evidence:
                _console.print(f"  [dim]Evidence:[/dim] {f.evidence[0].description}")
            _console.print()
    else:
        _console.print("[green]No Critical or High severity security findings detected.[/green]\n")


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@app.command("scan")
def cmd_scan(
    apk: Path = typer.Argument(
        ...,
        help="Path to the APK file to scan.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format."),
) -> None:
    """[yellow]⚡ Phase 1[/yellow] — Quick security scan.

    A fast, high-signal scan that highlights the most actionable findings.
    Use ``analyze`` for a comprehensive report.
    """
    _not_implemented("scan", apk=str(apk))


def _render_diff_summary(
    result: DiffResult,
    verbose: bool = False,
    show_manifest: bool = False,
    show_dex: bool = False,
    show_native: bool = False,
    show_network: bool = False,
    show_resources: bool = False,
    show_assets: bool = False,
    show_embedded: bool = False,
    show_files: bool = False,
) -> None:
    """Render a human-readable diff summary to the console using Rich."""
    from apkforge.diff.models import ChangeType

    # 1. Package comparison header table
    table = Table(
        title="APKForge Package Diff",
        show_header=True,
        header_style="bold cyan",
        box=None,
    )
    table.add_column("Property", style="bold", width=18)
    table.add_column("APK A (Original)", width=35)
    table.add_column("APK B (Modified)", width=35)

    table.add_row(
        "File",
        result.apk_a.file_name or "Unknown",
        result.apk_b.file_name or "Unknown",
    )
    table.add_row(
        "Package",
        result.apk_a.package_name or "Unknown",
        result.apk_b.package_name or "Unknown",
    )
    v_a = f"{result.apk_a.version_name or '?'} ({result.apk_a.version_code or '?'})"
    v_b = f"{result.apk_b.version_name or '?'} ({result.apk_b.version_code or '?'})"
    table.add_row("Version", v_a, v_b)

    sha_a = (result.apk_a.sha256[:16] + "...") if result.apk_a.sha256 else "Unknown"
    sha_b = (result.apk_b.sha256[:16] + "...") if result.apk_b.sha256 else "Unknown"
    table.add_row("SHA-256", sha_a, sha_b)

    status_color = (
        "green"
        if result.status == AnalysisStatus.COMPLETE
        else ("yellow" if result.status == AnalysisStatus.PARTIAL else "red")
    )
    table.add_row(
        "Status",
        f"[{status_color}]{result.status.value.upper()}[/{status_color}]",
        f"[{status_color}]{result.status.value.upper()}[/{status_color}]",
    )

    _console.print(table)
    _console.print()

    # 2. SUMMARY section
    _console.print("[bold underline]MODIFICATION SUMMARY[/bold underline]")
    for line in result.summary.text_lines:
        if line.startswith("+"):
            _console.print(f"  [green]{line}[/green]")
        elif line.startswith("-"):
            _console.print(f"  [red]{line}[/red]")
        elif line.startswith("~"):
            _console.print(f"  [yellow]{line}[/yellow]")
        elif line.startswith("Certificate:"):
            c_color = "green" if "SAME" in line or "UNCHANGED" in line else "bold magenta"
            _console.print(f"  [{c_color}]{line}[/{c_color}]")
        else:
            _console.print(f"  {line}")

    # 3. Detailed sections
    if verbose or show_manifest:
        if (
            result.identity.changes
            or result.manifest.attribute_changes
            or result.manifest.sdk_changes
        ):
            _console.print("\n[bold cyan]Manifest & Attribute Changes:[/bold cyan]")
            for c in result.identity.changes:
                _console.print(
                    f"  • {c.identifier}: [dim]{c.before}[/dim] -> [bold]{c.after}[/bold]"
                )
            for c in result.manifest.sdk_changes:
                _console.print(
                    f"  • {c.identifier}: [dim]{c.before}[/dim] -> [bold]{c.after}[/bold]"
                )
            for c in result.manifest.attribute_changes:
                _console.print(
                    f"  • {c.identifier}: [dim]{c.before}[/dim] -> [bold]{c.after}[/bold]"
                )

        if (
            result.permissions.added
            or result.permissions.removed
            or result.permissions.declared_modified
        ):
            _console.print("\n[bold cyan]Permission Differences:[/bold cyan]")
            for p in result.permissions.added:
                _console.print(f"  [green]+ {p}[/green]")
            for p in result.permissions.removed:
                _console.print(f"  [red]- {p}[/red]")
            for dp in result.permissions.declared_modified:
                _console.print(
                    f"  [yellow]~ {dp.identifier} "
                    f"(protectionLevel: {dp.before} -> {dp.after})[/yellow]"
                )

        comps = result.components
        all_comps = comps.activities + comps.services + comps.receivers + comps.providers
        mod_or_add_rem = [c for c in all_comps if c.change_type != ChangeType.UNCHANGED]
        if mod_or_add_rem:
            _console.print("\n[bold cyan]Component Differences:[/bold cyan]")
            for c in mod_or_add_rem:
                pfx = (
                    "+"
                    if c.change_type == ChangeType.ADDED
                    else ("-" if c.change_type == ChangeType.REMOVED else "~")
                )
                col = "green" if pfx == "+" else ("red" if pfx == "-" else "yellow")
                exp = (
                    f" (exported: {c.exported_before} -> {c.exported_after})"
                    if c.exported_before != c.exported_after
                    else ""
                )
                _console.print(f"  [{col}]{pfx} [{c.component_type}] {c.name}{exp}[/{col}]")
                if c.intent_filter_diff and c.intent_filter_diff.has_changes:
                    if c.intent_filter_diff.actions_added:
                        _console.print(
                            f"      + actions: {', '.join(c.intent_filter_diff.actions_added)}"
                        )
                    if c.intent_filter_diff.actions_removed:
                        _console.print(
                            f"      - actions: {', '.join(c.intent_filter_diff.actions_removed)}"
                        )

    if verbose or show_dex:
        dex = result.dex
        if (
            dex.classes_added
            or dex.classes_removed
            or dex.classes_modified
            or dex.api_references_added
            or dex.api_references_removed
        ):
            _console.print("\n[bold cyan]DEX Bytecode & Class Differences:[/bold cyan]")
            for cl in dex.classes_added[:30]:
                _console.print(f"  [green]+ {cl}[/green]")
            if len(dex.classes_added) > 30:
                _console.print(
                    f"    [dim]... and {len(dex.classes_added) - 30} more classes added[/dim]"
                )
            for cl in dex.classes_removed[:30]:
                _console.print(f"  [red]- {cl}[/red]")
            if len(dex.classes_removed) > 30:
                _console.print(
                    f"    [dim]... and {len(dex.classes_removed) - 30} more classes removed[/dim]"
                )
            for cm in dex.classes_modified[:20]:
                _console.print(f"  [yellow]~ {cm.class_name}[/yellow]")
                for m in cm.methods_added:
                    _console.print(f"      + method {m}")
                for m in cm.methods_removed:
                    _console.print(f"      - method {m}")
                for md in cm.methods_modified:
                    _console.print(
                        f"      ~ method {md.method_name} "
                        f"(flags: {md.access_flags_before} -> {md.access_flags_after})"
                    )
            if len(dex.classes_modified) > 20:
                _console.print(
                    f"    [dim]... and {len(dex.classes_modified) - 20} more classes modified[/dim]"
                )

            if dex.api_references_added:
                _console.print("  Framework APIs added:")
                for api in dex.api_references_added[:20]:
                    _console.print(f"    [green]+ {api}[/green]")
            if dex.api_references_removed:
                _console.print("  Framework APIs removed:")
                for api in dex.api_references_removed[:20]:
                    _console.print(f"    [red]- {api}[/red]")

    if verbose or show_native:
        nat = result.native
        if (
            nat.libraries_added
            or nat.libraries_removed
            or nat.libraries_modified
            or nat.abis_added
            or nat.abis_removed
        ):
            _console.print("\n[bold cyan]Native Library Differences:[/bold cyan]")
            if nat.abis_added:
                _console.print(f"  ABIs added: {', '.join(nat.abis_added)}")
            if nat.abis_removed:
                _console.print(f"  ABIs removed: {', '.join(nat.abis_removed)}")
            for lib in nat.libraries_added:
                _console.print(f"  [green]+ {lib.path} ({lib.abi}, {lib.size_after} bytes)[/green]")
            for lib in nat.libraries_removed:
                _console.print(f"  [red]- {lib.path} ({lib.abi})[/red]")
            for lib in nat.libraries_modified:
                _console.print(
                    f"  [yellow]~ {lib.path} (size: {lib.size_before} -> {lib.size_after})[/yellow]"
                )
                if lib.symbols_exported_added:
                    _console.print(f"      + {len(lib.symbols_exported_added)} exported symbols")
                if lib.symbols_exported_removed:
                    _console.print(f"      - {len(lib.symbols_exported_removed)} exported symbols")

    if verbose or show_network:
        net = result.network
        if (
            net.domains_added
            or net.domains_removed
            or net.urls_added
            or net.urls_removed
            or net.ips_added
            or net.ips_removed
        ):
            _console.print("\n[bold cyan]Network Differences:[/bold cyan]")
            for d in net.domains_added:
                _console.print(f"  [green]+ Domain: {d}[/green]")
            for d in net.domains_removed:
                _console.print(f"  [red]- Domain: {d}[/red]")
            for u in net.urls_added[:20]:
                src = f" [dim]({u.source_class})[/dim]" if u.source_class else ""
                _console.print(f"  [green]+ URL: {u.url}{src}[/green]")
            if len(net.urls_added) > 20:
                _console.print(f"    [dim]... and {len(net.urls_added) - 20} more URLs added[/dim]")
            for u in net.urls_removed[:20]:
                _console.print(f"  [red]- URL: {u.url}[/red]")
            for ip in net.ips_added:
                _console.print(f"  [green]+ IP: {ip}[/green]")
            for ip in net.ips_removed:
                _console.print(f"  [red]- IP: {ip}[/red]")

    if verbose or show_resources:
        res = result.resources
        _console.print("\n[bold cyan]Resource Differences:[/bold cyan]")
        _console.print(f"  resources.arsc: {res.resources_arsc_change.value.upper()}")
        for rtype, counts in sorted(res.by_type.items()):
            parts = []
            if counts["added"] > 0:
                parts.append(f"+{counts['added']}")
            if counts["removed"] > 0:
                parts.append(f"-{counts['removed']}")
            if counts["modified"] > 0:
                parts.append(f"~{counts['modified']}")
            if parts:
                _console.print(f"  • res/{rtype}: {', '.join(parts)}")

    if verbose or show_assets:
        ast = result.assets
        _console.print("\n[bold cyan]Asset Differences:[/bold cyan]")
        _console.print(
            f"  Added: {ast.total_added}, Removed: {ast.total_removed}, "
            f"Modified: {ast.total_modified}"
        )
        for ec in ast.entropy_changes:
            if ec.delta and abs(ec.delta) > 0.5:
                _console.print(
                    f"  • {ec.path}: entropy delta {ec.delta:+.2f} "
                    f"({ec.entropy_before} -> {ec.entropy_after})"
                )

    if verbose or show_embedded:
        emb = result.embedded
        if (
            emb.apks_added
            or emb.apks_removed
            or emb.dex_added
            or emb.dex_removed
            or emb.executables_added
            or emb.executables_removed
        ):
            _console.print("\n[bold cyan]Embedded Executables Differences:[/bold cyan]")
            for ep in emb.apks_added:
                _console.print(f"  [green]+ Embedded APK: {ep}[/green]")
            for ep in emb.apks_removed:
                _console.print(f"  [red]- Embedded APK: {ep}[/red]")
            for ep in emb.dex_added:
                _console.print(f"  [green]+ Secondary DEX: {ep}[/green]")
            for ep in emb.dex_removed:
                _console.print(f"  [red]- Secondary DEX: {ep}[/red]")
            for ep in emb.executables_added:
                _console.print(f"  [green]+ Executable: {ep}[/green]")
            for ep in emb.executables_removed:
                _console.print(f"  [red]- Executable: {ep}[/red]")

    if verbose or show_files:
        _console.print("\n[bold cyan]File-Level Differences:[/bold cyan]")
        for entry in result.files.entries:
            if entry.change_type != ChangeType.UNCHANGED:
                sym = (
                    "+"
                    if entry.change_type == ChangeType.ADDED
                    else ("-" if entry.change_type == ChangeType.REMOVED else "~")
                )
                col = "green" if sym == "+" else ("red" if sym == "-" else "yellow")
                sz = f" ({entry.size_after} bytes)" if entry.size_after is not None else ""
                _console.print(f"  [{col}]{sym} {entry.path}{sz}[/{col}]")

    # Certificates
    if verbose or result.certificates.status != "SAME":
        _console.print("\n[bold cyan]Certificate Details:[/bold cyan]")
        _console.print(f"  Status: {result.certificates.status}")
        for fc in result.certificates.fingerprint_changes:
            sym = "+" if fc.change_type == ChangeType.ADDED else "-"
            _console.print(f"  {sym} SHA-256: {fc.after or fc.before}")

    # Limitations, Warnings, Errors
    if result.limitations:
        _console.print("\n[bold magenta]Diff Limitations:[/bold magenta]")
        for lim in result.limitations:
            _console.print(f"  [magenta]*[/magenta] {lim}")

    if result.warnings:
        _console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            _console.print(f"  [yellow]![/yellow] {w}")

    if result.errors:
        _console.print("\n[bold red]Errors:[/bold red]")
        for e in result.errors:
            _console.print(f"  [red]x[/red] {e}")


# ---------------------------------------------------------------------------
# diff command
# ---------------------------------------------------------------------------


@app.command("diff")
def cmd_diff(
    original: Path = typer.Argument(
        ...,
        metavar="APK_A",
        help="Path to the first APK (e.g. original).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    modified: Path = typer.Argument(
        ...,
        metavar="APK_B",
        help="Path to the second APK (e.g. modified).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON format.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text | json.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed breakdown across all categories.",
    ),
    show_manifest: bool = typer.Option(
        False,
        "--manifest",
        help="Show detailed manifest, permission, and component differences.",
    ),
    show_dex: bool = typer.Option(
        False,
        "--dex",
        help="Show detailed DEX, class, method, and API differences.",
    ),
    show_native: bool = typer.Option(
        False,
        "--native",
        help="Show detailed native library and symbol differences.",
    ),
    show_network: bool = typer.Option(
        False,
        "--network",
        help="Show detailed URL, domain, and IP differences.",
    ),
    show_resources: bool = typer.Option(
        False,
        "--resources",
        help="Show detailed resource table and res/ differences.",
    ),
    show_assets: bool = typer.Option(
        False,
        "--assets",
        help="Show detailed asset and Shannon entropy differences.",
    ),
    show_embedded: bool = typer.Option(
        False,
        "--embedded",
        help="Show detailed embedded APK/DEX/executable differences.",
    ),
    show_files: bool = typer.Option(
        False,
        "--files",
        help="Show file-by-file differences.",
    ),
    keep_workspace: bool = typer.Option(
        False,
        "--keep-workspace",
        help="Retain workspace directory after comparison.",
    ),
) -> None:
    """Compare two APK packages and produce a structured, evidence-based diff."""
    from apkforge.diff.engine import DiffEngine

    cfg = load_default_config()
    setup_logging(cfg.log_level)

    engine = DiffEngine(config=cfg)
    result = engine.diff(original, modified, keep_workspace=keep_workspace)

    if json_output or output_format.lower() == "json":
        _console.print(result.model_dump_json(indent=2), soft_wrap=True)
    else:
        _render_diff_summary(
            result,
            verbose=verbose,
            show_manifest=show_manifest,
            show_dex=show_dex,
            show_native=show_native,
            show_network=show_network,
            show_resources=show_resources,
            show_assets=show_assets,
            show_embedded=show_embedded,
            show_files=show_files,
        )

    if result.status == AnalysisStatus.FAILED:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# privacy command
# ---------------------------------------------------------------------------


@app.command("privacy")
def cmd_privacy(
    apk: Path = typer.Argument(
        ...,
        metavar="APK",
        help="Path to the APK file to analyse for privacy and trackers.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON format.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text | json.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed breakdown across all categories.",
    ),
    show_permissions: bool = typer.Option(
        False,
        "--permissions",
        help="Show detailed permission privacy analysis and code correlation.",
    ),
    show_trackers: bool = typer.Option(
        False,
        "--trackers",
        help="Show detailed tracker, advertising, and analytics SDK detections.",
    ),
    show_endpoints: bool = typer.Option(
        False,
        "--endpoints",
        help="Show detailed network endpoint classifications and provenance.",
    ),
    show_data: bool = typer.Option(
        False,
        "--data",
        help="Show data capability assessments and device identifiers.",
    ),
    keep_workspace: bool = typer.Option(
        False,
        "--keep-workspace",
        help="Retain workspace directory after analysis.",
    ),
) -> None:
    """Analyze an APK for privacy capabilities, third-party trackers, and network endpoints."""
    from apkforge.privacy.engine import PrivacyEngine

    cfg = load_default_config()
    setup_logging(cfg.log_level)

    engine = PrivacyEngine()
    result = engine.analyze(apk, keep_workspace=keep_workspace)

    if json_output or output_format.lower() == "json":
        _console.print(result.model_dump_json(indent=2), soft_wrap=True)
    else:
        _render_privacy_summary(
            result,
            verbose=verbose,
            show_permissions=show_permissions,
            show_trackers=show_trackers,
            show_endpoints=show_endpoints,
            show_data=show_data,
        )

    if result.status == AnalysisStatus.FAILED:
        raise typer.Exit(code=1)


def _render_privacy_summary(
    result: PrivacyResult,
    *,
    verbose: bool = False,
    show_permissions: bool = False,
    show_trackers: bool = False,
    show_endpoints: bool = False,
    show_data: bool = False,
) -> None:
    """Render human-readable privacy analysis summary to the console."""
    pkg_str = result.package_name or "Unknown Package"
    ver_str = f"v{result.version_name}" if result.version_name else ""
    code_str = f"({result.version_code})" if result.version_code else ""
    status_color = "green" if result.status == AnalysisStatus.COMPLETE else "yellow"

    _console.print(
        Panel(
            f"[bold]{pkg_str}[/bold] {ver_str} {code_str}\n"
            f"Status: [{status_color}]{result.status.value.upper()}[/{status_color}]",
            title="[bold blue]APKForge Privacy & Tracker Analysis[/bold blue]",
            expand=False,
        )
    )

    # Permissions Section
    _console.print("\n[bold cyan]PERMISSIONS[/bold cyan]")
    _console.print("─" * 40)
    if result.permissions.categorized_permissions:
        for cat, perms in sorted(result.permissions.categorized_permissions.items()):
            _console.print(f"[bold]{cat.replace('_', ' ').capitalize()}:[/bold]")
            for p in perms:
                _console.print(f"  {p}")
    else:
        _console.print("  [dim]No declared permissions observed.[/dim]")

    if (verbose or show_permissions) and result.permissions.usage_details:
        ptbl = Table(title="Permission Code Correlation", show_header=True)
        ptbl.add_column("Permission", style="cyan")
        ptbl.add_column("Category", style="green")
        ptbl.add_column("Protection", style="yellow")
        ptbl.add_column("Usage Status", style="magenta")
        ptbl.add_column("Relevance", style="blue")
        ptbl.add_column("Correlated APIs", style="white")

        for u in result.permissions.usage_details:
            apis_str = ", ".join(u.related_apis) if u.related_apis else "-"
            ptbl.add_row(
                u.permission.split(".")[-1],
                u.category.value,
                u.protection_level or "-",
                u.usage_status.value,
                u.relevance.value,
                apis_str,
            )
        _console.print(ptbl)

    # Trackers & SDKs Section
    _console.print("\n[bold cyan]TRACKERS / SDKs[/bold cyan]")
    _console.print("─" * 40)
    all_sdks = (
        result.advertising.detected_advertising_sdks
        + result.analytics.detected_analytics_sdks
        + result.trackers.detected_trackers
        + result.telemetry.detected_telemetry_sdks
    )
    if all_sdks:
        for sdk in sorted(all_sdks, key=lambda s: (s.category.value, s.name)):
            _console.print(f"[bold]{sdk.name}[/bold]")
            _console.print(f"  Category: {sdk.category.value.upper()}")
            _console.print(f"  Confidence: {sdk.confidence.value.upper()}")
            if sdk.vendor:
                _console.print(f"  Vendor: {sdk.vendor}")
            if verbose or show_trackers:
                for ev in sdk.evidence[:3]:
                    _console.print(f"  ✓ {ev.snippet}")
            _console.print()
    else:
        _console.print("  [dim]No known tracking, advertising, or analytics SDKs detected.[/dim]\n")

    # Network Endpoints Section
    _console.print("\n[bold cyan]NETWORK ENDPOINTS[/bold cyan]")
    _console.print("─" * 40)
    if result.endpoints.classified_endpoints:
        domains_shown = set()
        for ep in result.endpoints.classified_endpoints:
            if not ep.domain or ep.domain in domains_shown:
                continue
            domains_shown.add(ep.domain)
            party_str = (
                "[green]1st Party[/green]" if ep.is_first_party else "[yellow]3rd Party[/yellow]"
            )
            sdk_str = f" ({ep.associated_sdk})" if ep.associated_sdk else ""
            _console.print(f"[bold]{ep.domain}[/bold]{sdk_str}")
            _console.print(f"  Category: {ep.category.value.upper()} | {party_str}")
            if (verbose or show_endpoints) and ep.provenance:
                _console.print(f"  Provenance: {ep.provenance[0]}")
    else:
        _console.print("  [dim]No external domains or endpoints extracted.[/dim]")

    # Data Capabilities Section
    _console.print("\n[bold cyan]DATA CAPABILITIES[/bold cyan]")
    _console.print("─" * 40)
    if result.data_collection.capabilities:
        for cap in result.data_collection.capabilities:
            _console.print(f"[bold]{cap.capability.value.replace('_', ' ').capitalize()}[/bold]")
            _console.print(f"  {cap.assessment}")
            if verbose or show_data:
                if cap.permissions:
                    _console.print(f"  Permissions: {', '.join(cap.permissions)}")
                if cap.apis:
                    _console.print(f"  APIs: {', '.join(cap.apis[:3])}")
    else:
        _console.print("  [dim]No sensitive data collection capabilities identified.[/dim]")

    if result.data_collection.device_identifiers_detected:
        _console.print(
            f"\n[bold yellow]Device Identifiers Referenced:[/bold yellow] "
            f"{', '.join(result.data_collection.device_identifiers_detected)}"
        )
    if result.data_collection.advertising_id_detected:
        _console.print("[bold yellow]Advertising ID (AAID):[/bold yellow] Referenced")
    if result.data_collection.clipboard_access_detected:
        _console.print("[bold yellow]Clipboard Access:[/bold yellow] Referenced")
    if result.data_collection.accessibility_service_detected:
        _console.print("[bold yellow]Accessibility Service:[/bold yellow] Declared / Implemented")

    # Limitations Section
    _console.print("\n[bold cyan]LIMITATIONS[/bold cyan]")
    _console.print("─" * 40)
    for lim in result.limitations:
        _console.print(f"• {lim}")
    _console.print()


# ---------------------------------------------------------------------------
# security command
# ---------------------------------------------------------------------------


@app.command("security")
def cmd_security(
    apk: Path = typer.Argument(
        ...,
        metavar="APK",
        help="Path to the APK file to analyse for security indicators and vulnerabilities.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    diff_apk: Path | None = typer.Option(
        None,
        "--diff",
        "-d",
        help="Optional second APK for diff-aware security analysis.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON format.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text | json.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed findings and full evidence lists.",
    ),
    show_malware: bool = typer.Option(
        False,
        "--malware",
        help="Filter to show only malware indicator findings.",
    ),
    show_spyware: bool = typer.Option(
        False,
        "--spyware",
        help="Filter to show only spyware indicator findings.",
    ),
    show_vulns: bool = typer.Option(
        False,
        "--vulns",
        help="Filter to show only vulnerability indicator findings.",
    ),
    keep_workspace: bool = typer.Option(
        False,
        "--keep-workspace",
        help="Retain workspace directory after analysis.",
    ),
) -> None:
    """Analyze an APK for security indicators, suspicious combinations, and vulnerabilities."""
    from apkforge.diff.engine import DiffEngine
    from apkforge.inspection.engine import InspectionEngine
    from apkforge.privacy.engine import PrivacyEngine
    from apkforge.security.engine import SecurityEngine

    cfg = load_default_config()
    setup_logging(cfg.log_level)

    insp_engine = InspectionEngine(config=cfg)
    priv_engine = PrivacyEngine(config=cfg)
    sec_engine = SecurityEngine(config=cfg)

    # Inspect primary APK
    insp_res = insp_engine.inspect(apk, keep_workspace=keep_workspace)
    priv_res = priv_engine.analyze(apk, keep_workspace=keep_workspace)

    diff_res = None
    if diff_apk is not None:
        diff_engine = DiffEngine(config=cfg)
        diff_res = diff_engine.diff(apk, diff_apk, keep_workspace=keep_workspace)

    sec_res = sec_engine.analyze(
        inspection=insp_res,
        privacy=priv_res,
        diff=diff_res,
        apk_path=apk,
    )

    if json_output or output_format.lower() == "json":
        _console.print(sec_res.model_dump_json(indent=2), soft_wrap=True)
    else:
        _render_security_summary(
            sec_res,
            verbose=verbose,
            show_malware=show_malware,
            show_spyware=show_spyware,
            show_vulns=show_vulns,
        )

    if sec_res.status == AnalysisStatus.FAILED:
        raise typer.Exit(code=1)


def _render_security_summary(
    result: SecurityResult,
    *,
    verbose: bool = False,
    show_malware: bool = False,
    show_spyware: bool = False,
    show_vulns: bool = False,
) -> None:
    """Render human-readable security analysis summary to console."""
    from apkforge.security.models import SecurityCategory, SecurityStatus

    pkg_str = result.package_name or "Unknown Package"
    ver_str = f"v{result.version_name}" if result.version_name else ""
    code_str = f"({result.version_code})" if result.version_code else ""

    status_color = "green" if result.status == AnalysisStatus.COMPLETE else "yellow"
    sec_status_color = (
        "red" if result.security_status == SecurityStatus.FINDINGS_PRESENT else "green"
    )

    _console.print(
        Panel(
            f"[bold]{pkg_str}[/bold] {ver_str} {code_str}\n"
            f"Analysis Status: [{status_color}]{result.status.value.upper()}[/{status_color}]\n"
            f"Security Status: "
            f"[{sec_status_color}]{result.security_status.value.upper()}[/{sec_status_color}]",
            title="[bold red]APKForge Security Analysis[/bold red]",
            expand=False,
        )
    )

    # Severity Summary Table
    table = Table(title="Security Findings Summary", show_header=True, box=None)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Categories Included")

    sum_info = result.summary
    table.add_row(
        "[bold red]Critical[/bold red]",
        str(sum_info.critical_count),
        "Severe vulnerability / payload",
    )
    table.add_row(
        "[red]High[/red]", str(sum_info.high_count), "High-impact capability / surveillance"
    )
    table.add_row(
        "[yellow]Medium[/yellow]",
        str(sum_info.medium_count),
        "Suspicious combinations / exposed surfaces",
    )
    table.add_row(
        "[cyan]Low[/cyan]", str(sum_info.low_count), "Minor weaknesses / insecure configs"
    )
    table.add_row(
        "[dim]Info[/dim]", str(sum_info.info_count), "Capability inventory / observations"
    )
    _console.print(table)
    _console.print()

    # Filter findings if requested
    findings = result.findings
    if show_malware:
        findings = [f for f in findings if f.category == SecurityCategory.MALWARE_INDICATOR]
    elif show_spyware:
        findings = [f for f in findings if f.category == SecurityCategory.SPYWARE_INDICATOR]
    elif show_vulns:
        findings = [f for f in findings if f.category == SecurityCategory.VULNERABILITY]

    _console.print("[bold]FINDINGS[/bold]")
    _console.print("─" * 50)
    if not findings:
        _console.print("  [dim]No matching security findings recorded.[/dim]")
    else:
        for f in findings:
            sev_color = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "cyan",
                Severity.INFO: "dim",
            }.get(f.severity, "white")

            _console.print(
                f"[{sev_color}][{f.severity.value.upper()}][/{sev_color}] "
                f"[bold]{f.id}[/bold]: {f.title}"
            )
            cat_val = f.category.value
            conf_val = f.confidence.value.upper()
            _console.print(
                f"  [dim]Category:[/dim] {cat_val} | [dim]Confidence:[/dim] [cyan]{conf_val}[/cyan]"
            )
            _console.print(f"  [bold]Assessment:[/bold] {f.assessment}")

            if f.evidence:
                _console.print("  [dim]Evidence:[/dim]")
                display_ev = f.evidence if verbose else f.evidence[:5]
                for ev in display_ev:
                    loc_str = f" ({ev.location})" if ev.location else ""
                    _console.print(f"    • {ev.description}{loc_str}")
                if len(f.evidence) > 5 and not verbose:
                    rem_ev = len(f.evidence) - 5
                    _console.print(
                        f"    [dim]... and {rem_ev} more evidence items (use -v to view all)[/dim]"
                    )

            if f.limitations:
                _console.print("  [dim]Limitations:[/dim]")
                for lim in f.limitations:
                    _console.print(f"    - {lim}")

            _console.print()

    if result.warnings:
        _console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            _console.print(f"  [yellow]![/yellow] {w}")

    if result.limitations:
        _console.print("\n[bold dim]Analysis Limitations:[/bold dim]")
        for lim in result.limitations:
            _console.print(f"  [dim]• {lim}[/dim]")
    _console.print()


@app.command("modify")
def cmd_modify(
    apk: Path = typer.Argument(
        ...,
        help="Path to the APK file to modify.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    plan_file: Path | None = typer.Option(
        None,
        "--plan",
        "-p",
        help="Path to a modification plan TOML/JSON file.",
    ),
) -> None:
    """[yellow]⚡ Phase 3[/yellow] — Apply modifications to an APK.

    Applies a structured modification plan to a working copy of the APK
    without touching the original file.  The result must be rebuilt and
    verified before use.
    """
    _not_implemented("modify", apk=str(apk))


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------


@app.command("verify")
def cmd_verify(
    apk: Path = typer.Argument(
        ...,
        help="Path to the APK to verify.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """[yellow]⚡ Phase 3[/yellow] — Verify a rebuilt APK.

    Runs post-build verification checks: signature validation, hash
    consistency, structural integrity.
    """
    _not_implemented("verify", apk=str(apk))


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _not_implemented(command: str, **kwargs: str) -> None:
    """Display a consistent 'not implemented yet' message and exit cleanly."""
    detail = "  ".join(f"[dim]{k}=[/dim][cyan]{v}[/cyan]" for k, v in kwargs.items())
    _console.print(
        Panel(
            f"[bold yellow]apkforge {command}[/bold yellow] is not yet implemented.\n\n"
            f"{detail}\n\n"
            "[dim]This command will be implemented in a future phase.[/dim]",
            title="[yellow]Not Implemented[/yellow]",
            border_style="yellow",
        )
    )
    raise typer.Exit(code=0)
