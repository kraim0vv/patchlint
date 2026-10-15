"""Command Line Interface (CLI) for PatchLint DAST Security Linter."""

from __future__ import annotations

import asyncio
import sys
from typing import Sequence

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from patchlint.engine import AuditEngine, TargetUnreachableError
from patchlint.models import Finding, Severity
from patchlint.reporter import ConsoleReporter, HtmlReporter, JsonReporter
from patchlint.rules import RuleRegistry

__version__ = "1.0.0"


def print_banner(console: Console) -> None:
    """Render startup banner."""
    banner = Text()
    banner.append("  _____       _       _     _     _       _   \n", style="bold cyan")
    banner.append(" |  __ \\     | |     | |   | |   (_)     | |  \n", style="bold cyan")
    banner.append(" | |__) |__ _| |_ ___| |__ | |    _ _ __ | |_ \n", style="bold blue")
    banner.append(" |  ___/ _` | __/ __| '_ \\| |   | | '_ \\| __|\n", style="bold blue")
    banner.append(" | |  | (_| | || (__| | | | |___| | | | | |_ \n", style="bold magenta")
    banner.append(" |_|   \\__,_|\\__\\___|_| |_|______|_|_| |_|\\__|\n", style="bold magenta")
    banner.append(f"     Actionable DAST & Security Linter v{__version__}\n", style="bold white")
    console.print(banner)


def list_registered_rules(console: Console) -> None:
    """Print a Rich table detailing all available detection rules."""
    registry = RuleRegistry()
    rules = registry.get_all()

    table = Table(
        title="[bold green]PatchLint - Built-in Security Rules[/bold green]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Rule ID", style="cyan", width=32)
    table.add_column("Severity", width=12)
    table.add_column("Category", style="white", width=22)
    table.add_column("Title", style="bold white")

    for rule in sorted(rules, key=lambda r: r.severity.rank, reverse=True):
        table.add_row(
            rule.id,
            Text(f" {rule.severity.value} ", style=rule.severity.rich_color),
            rule.category.value,
            rule.title,
        )

    console.print(table)
    console.print(f"\n[dim]Total available rules: {len(rules)}[/dim]\n")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", required=False)
@click.option(
    "-f",
    "--format",
    "report_format",
    type=click.Choice(["terminal", "json", "html"], case_sensitive=False),
    default="terminal",
    help="Output report format (default: terminal).",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="File path to save the generated report (JSON or HTML).",
)
@click.option(
    "-k",
    "--insecure",
    is_flag=True,
    default=False,
    help="Disable SSL certificate verification (useful for local self-signed HTTPS).",
)
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=10.0,
    show_default=True,
    help="HTTP connection and read timeout in seconds.",
)
@click.option(
    "-c",
    "--concurrency",
    type=int,
    default=10,
    show_default=True,
    help="Maximum concurrent network requests for active probes.",
)
@click.option(
    "-s",
    "--min-severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Minimum severity threshold to report.",
)
@click.option(
    "--headers-only",
    is_flag=True,
    default=False,
    help="Perform passive security header checks only (skip path and file probing).",
)
@click.option(
    "--no-remediation",
    is_flag=True,
    default=False,
    help="Hide detailed remediation and configuration code snippets in console output.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="HIGH",
    show_default=True,
    help="Exit with non-zero status code (1) if findings of this severity or higher are found.",
)
@click.option(
    "--user-agent",
    type=str,
    default=None,
    help="Custom HTTP User-Agent string.",
)
@click.option(
    "--list-rules",
    is_flag=True,
    default=False,
    help="List all registered security rules and exit.",
)
@click.version_option(__version__, "-v", "--version", prog_name="patchlint")
def main(
    target: str | None,
    report_format: str,
    output_file: str | None,
    insecure: bool,
    timeout: float,
    concurrency: int,
    min_severity: str | None,
    headers_only: bool,
    no_remediation: bool,
    fail_on: str,
    user_agent: str | None,
    list_rules: bool,
) -> None:
    """PatchLint: Actionable DAST & Security Linter for developers.

    Audits local and staging web applications for missing security headers,
    exposed credentials, and dangerous misconfigurations, providing ready-to-use
    remediation configurations for Nginx, Apache, and web frameworks.

    Examples:

      patchlint http://localhost:8000

      patchlint https://app.local -k -f html -o security_report.html

      patchlint http://127.0.0.1:3000 --headers-only -f json
    """
    console = Console()

    if list_rules:
        list_registered_rules(console)
        sys.exit(0)

    if not target:
        print_banner(console)
        console.print("[bold red]Error:[/bold red] Missing argument TARGET URL.")
        console.print("[dim]Run 'patchlint --help' for usage instructions.[/dim]\n")
        sys.exit(3)

    if report_format == "terminal" and not output_file:
        print_banner(console)

    # Automatically infer output format from extension if -o is specified
    if output_file and report_format == "terminal":
        if output_file.lower().endswith(".html"):
            report_format = "html"
        elif output_file.lower().endswith(".json"):
            report_format = "json"

    min_sev_enum = Severity(min_severity.upper()) if min_severity else None
    fail_on_enum = Severity(fail_on.upper())

    engine = AuditEngine(
        timeout=timeout,
        concurrency=concurrency,
        verify_ssl=not insecure,
        user_agent=user_agent,
        headers_only=headers_only,
        min_severity=min_sev_enum,
    )

    findings_streamed: list[Finding] = []

    # Real-time progress bar
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    with progress:
        task_id = progress.add_task("[bold cyan]Scanning target...[/bold cyan]", total=100)

        def on_progress(completed: int, total: int, current_title: str) -> None:
            pct = (completed / total * 100) if total > 0 else 0
            progress.update(
                task_id,
                completed=pct,
                description=f"[bold cyan]Checking:[/bold cyan] {current_title[:40]}",
            )

        def on_finding(finding: Finding) -> None:
            findings_streamed.append(finding)

        try:
            report = asyncio.run(
                engine.scan(
                    target_url=target,
                    on_progress=on_progress,
                    on_finding=on_finding,
                )
            )
        except TargetUnreachableError as exc:
            console.print(
                Panel(
                    f"[bold red]Target Unreachable:[/bold red] {exc}",
                    title="[bold red]Connection Error[/bold red]",
                    border_style="red",
                )
            )
            sys.exit(2)
        except Exception as exc:
            console.print(
                Panel(
                    f"[bold red]Unexpected Failure:[/bold red] {exc}",
                    title="[bold red]Audit Error[/bold red]",
                    border_style="red",
                )
            )
            sys.exit(3)

    # Generate Reports
    if report_format == "terminal":
        reporter = ConsoleReporter(console=console, show_remediation=not no_remediation)
        reporter.render(report)
    elif report_format == "json":
        reporter = JsonReporter()
        content = reporter.render(report, destination=output_file)
        if not output_file:
            print(content)
        else:
            console.print(f"[bold green]✔ JSON report successfully saved to:[/bold green] {output_file}")
    elif report_format == "html":
        reporter = HtmlReporter()
        dest = output_file or "patchlint_report.html"
        reporter.render(report, destination=dest)
        console.print(f"[bold green]✔ Interactive HTML report generated at:[/bold green] {dest}")

    # CI/CD exit code determination
    # Exit 1 when at least one finding reaches or exceeds the --fail-on threshold.
    # With no findings, default=-1 ensures the comparison always fails cleanly.
    highest_severity_rank = max(
        (f.severity.rank for f in report.findings),
        default=-1,
    )

    if highest_severity_rank >= fail_on_enum.rank:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
