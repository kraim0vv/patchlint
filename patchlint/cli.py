"""Command Line Interface (CLI) for PatchLint DAST Security Linter."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

import click
from click.core import ParameterSource
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from patchlint._version import __version__
from patchlint.config import CONFIG_FILENAME, ConfigError, apply_baseline, find_config, load_baseline, load_config
from patchlint.engine import AuditEngine, AuditEngineError, TargetUnreachableError, normalize_target_url
from patchlint.models import Severity
from patchlint.reporter import ConsoleReporter, HtmlReporter, JsonReporter, SarifReporter
from patchlint.rules import RuleRegistry



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


SEVERITY_CHOICES = click.Choice([s.value for s in Severity], case_sensitive=False)
FORMAT_BY_EXTENSION = {".html": "html", ".htm": "html", ".json": "json", ".sarif": "sarif"}


def _split_rule_ids(values: tuple[str, ...] | list[str]) -> set[str]:
    """Accept both repeated --exclude flags and comma-separated lists."""
    return {part.strip() for v in values for part in v.split(",") if part.strip()}


def _fail(console: Console, message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {escape(message)}")
    sys.exit(3)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", required=False)
@click.option(
    "-f",
    "--format",
    "report_format",
    type=click.Choice(["terminal", "json", "sarif", "html"], case_sensitive=False),
    default="terminal",
    help="Output report format (default: terminal). Inferred from -o extension when omitted.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="File path to save the generated report (JSON, SARIF or HTML).",
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
    type=click.FloatRange(min=0.1),
    default=10.0,
    show_default=True,
    help="HTTP connection and read timeout in seconds.",
)
@click.option(
    "-c",
    "--concurrency",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Maximum concurrent network requests for active probes.",
)
@click.option(
    "-s",
    "--min-severity",
    type=SEVERITY_CHOICES,
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
    type=SEVERITY_CHOICES,
    default="HIGH",
    show_default=True,
    help="Exit with non-zero status code (1) if findings of this severity or higher are found.",
)
@click.option(
    "-e",
    "--exclude",
    "exclude",
    multiple=True,
    metavar="RULE_ID[,RULE_ID]",
    help="Skip the given rule(s). Repeatable or comma-separated. See --list-rules.",
)
@click.option(
    "--baseline",
    type=click.Path(dir_okay=False, exists=True),
    default=None,
    help="PatchLint JSON report of accepted findings; matching findings are suppressed.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, exists=True),
    default=None,
    help=f"Config file (default: ./{CONFIG_FILENAME} or [tool.patchlint] in ./pyproject.toml).",
)
@click.option(
    "--no-config",
    is_flag=True,
    default=False,
    help="Ignore configuration files.",
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
@click.pass_context
def main(
    ctx: click.Context,
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
    exclude: tuple[str, ...],
    baseline: str | None,
    config_path: str | None,
    no_config: bool,
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

      patchlint https://staging.example.com -o results.sarif --exclude missing-hsts-header
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

    try:
        target = normalize_target_url(target)
    except AuditEngineError as exc:
        _fail(console, str(exc))

    # Config file values apply only where the option was not given on the command line.
    config: dict = {}
    if not no_config:
        cfg_file = Path(config_path) if config_path else find_config()
        if cfg_file:
            try:
                config = load_config(cfg_file)
            except ConfigError as exc:
                _fail(console, str(exc))

    def from_config(name: str, value):
        if name in config and ctx.get_parameter_source(name) == ParameterSource.DEFAULT:
            return config[name]
        return value

    insecure = from_config("insecure", insecure)
    timeout = from_config("timeout", timeout)
    concurrency = from_config("concurrency", concurrency)
    min_severity = from_config("min_severity", min_severity)
    headers_only = from_config("headers_only", headers_only)
    fail_on = from_config("fail_on", fail_on)
    user_agent = from_config("user_agent", user_agent)
    baseline = from_config("baseline", baseline)
    excluded = _split_rule_ids(exclude) | _split_rule_ids(config.get("exclude", []))

    known_ids = {r.id for r in RuleRegistry().get_all()}
    unknown = sorted(excluded - known_ids)
    if unknown:
        _fail(console, f"Unknown rule ID(s) in exclude: {', '.join(unknown)}. Run 'patchlint --list-rules'.")

    baseline_fps: set[str] | None = None
    if baseline:
        try:
            baseline_fps = load_baseline(baseline)
        except ConfigError as exc:
            _fail(console, str(exc))

    # Infer output format from the -o extension when -f was not given explicitly.
    if output_file and ctx.get_parameter_source("report_format") == ParameterSource.DEFAULT:
        report_format = FORMAT_BY_EXTENSION.get(Path(output_file).suffix.lower(), report_format)
    report_format = report_format.lower()

    if report_format == "terminal" and not output_file:
        print_banner(console)

    min_sev_enum = Severity(min_severity.upper()) if min_severity else None
    fail_on_enum = Severity(fail_on.upper())

    engine = AuditEngine(
        timeout=timeout,
        concurrency=concurrency,
        verify_ssl=not insecure,
        user_agent=user_agent,
        headers_only=headers_only,
        min_severity=min_sev_enum,
        exclude_rules=excluded,
    )

    # Machine-readable output on stdout must not be mixed with progress rendering.
    progress_console = Console(stderr=True) if output_file is None and report_format in ("json", "sarif") else console
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=progress_console,
        transient=True,
    )

    with progress:
        task_id = progress.add_task("[bold cyan]Scanning target...[/bold cyan]", total=100)

        def on_progress(completed: int, total: int, current_title: str) -> None:
            pct = (completed / total * 100) if total > 0 else 0
            progress.update(
                task_id,
                completed=pct,
                description=f"[bold cyan]Checking:[/bold cyan] {escape(current_title[:40])}",
            )

        try:
            report = asyncio.run(engine.scan(target_url=target, on_progress=on_progress))
        except TargetUnreachableError as exc:
            progress_console.print(
                Panel(
                    f"[bold red]Target Unreachable:[/bold red] {escape(str(exc))}",
                    title="[bold red]Connection Error[/bold red]",
                    border_style="red",
                )
            )
            sys.exit(2)
        except Exception as exc:
            progress_console.print(
                Panel(
                    f"[bold red]Unexpected Failure:[/bold red] {escape(str(exc))}",
                    title="[bold red]Audit Error[/bold red]",
                    border_style="red",
                )
            )
            sys.exit(3)

    if baseline_fps is not None:
        apply_baseline(report, baseline_fps)

    # Generate Reports
    if report_format == "terminal":
        ConsoleReporter(console=console, show_remediation=not no_remediation).render(report)
    elif report_format in ("json", "sarif"):
        reporter = JsonReporter() if report_format == "json" else SarifReporter()
        content = reporter.render(report, destination=output_file)
        if not output_file:
            click.echo(content)
        else:
            console.print(
                f"[bold green]✔ {report_format.upper()} report successfully saved to:[/bold green] {escape(output_file)}"
            )
    elif report_format == "html":
        dest = output_file or "patchlint_report.html"
        HtmlReporter().render(report, destination=dest)
        console.print(f"[bold green]✔ Interactive HTML report generated at:[/bold green] {escape(dest)}")

    if report.errors and report_format != "terminal":
        err_console = Console(stderr=True)
        for e in report.errors:
            err_console.print(f"[bold yellow]Warning:[/bold yellow] rule {escape(e.rule_id)} failed: {escape(e.message)}")

    # CI/CD exit code: 1 when at least one finding reaches the --fail-on threshold.
    highest_severity_rank = max((f.severity.rank for f in report.findings), default=-1)
    if highest_severity_rank >= fail_on_enum.rank:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
