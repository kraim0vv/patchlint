"""Reporting engines for PatchLint: Terminal (Rich), JSON, and standalone HTML."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from patchlint._version import __version__
from patchlint.models import Finding, ScanReport, Severity
from patchlint.templates import HTML_REPORT_TEMPLATE


class BaseReporter:
    """Base interface for all report generators."""

    def render(self, report: ScanReport, destination: str | None = None) -> str:
        """Render report and optionally write to destination file.

        Returns string representation of report.
        """
        raise NotImplementedError


class ConsoleReporter(BaseReporter):
    """Terminal reporter using Rich for interactive terminal output."""

    def __init__(self, console: Console | None = None, show_remediation: bool = True) -> None:
        self.console = console or Console()
        self.show_remediation = show_remediation

    def render(self, report: ScanReport, destination: str | None = None) -> str:
        s = report.summary

        # 1. Summary Header Panel
        header_text = Text()
        header_text.append(" Target: ", style="bold cyan")
        header_text.append(f"{s.target_url}\n", style="bold white")
        header_text.append(" Duration: ", style="bold cyan")
        header_text.append(f"{s.duration_seconds:.2f}s | ", style="white")
        header_text.append("Requests: ", style="bold cyan")
        header_text.append(f"{s.total_requests} | ", style="white")
        header_text.append("Findings: ", style="bold cyan")
        header_text.append(f"{s.total_findings}\n", style="bold yellow")
        header_text.append(" Completed: ", style="bold cyan")
        header_text.append(f"{s.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", style="dim")

        self.console.print(
            Panel(
                header_text,
                title="[bold green]PatchLint DAST Security Audit Summary[/bold green]",
                border_style="green",
                expand=False,
            )
        )

        # 2. Severity Breakdown Table
        table = Table(title="Severity Breakdown", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Share", justify="right", width=10)

        for sev in Severity:
            count = s.counts_by_severity.get(sev.value, 0)
            share = (count / s.total_findings * 100) if s.total_findings > 0 else 0.0
            table.add_row(
                Text(f" {sev.value} ", style=sev.rich_color),
                str(count),
                f"{share:.1f}%",
            )

        self.console.print(table)
        self.console.print()

        if report.suppressed_count:
            self.console.print(
                f"[dim]{report.suppressed_count} known finding(s) suppressed by baseline.[/dim]\n"
            )

        if report.errors:
            err_text = Text()
            for e in report.errors:
                err_text.append(f"{e.rule_id}: ", style="bold yellow")
                err_text.append(f"{e.message}\n")
            self.console.print(
                Panel(
                    err_text,
                    title="[bold yellow]⚠ Rules failed to run — results are incomplete[/bold yellow]",
                    border_style="yellow",
                    expand=False,
                )
            )

        # 3. Findings Details
        if not report.findings:
            if report.errors:
                return ""
            self.console.print(
                Panel(
                    "[bold green]✔ Clean bill of health! No security issues found.[/bold green]",
                    border_style="green",
                )
            )
            return ""

        self.console.print(
            Text(f"DETAILED FINDINGS ({len(report.findings)})", style="bold underline")
        )
        self.console.print()

        for idx, finding in enumerate(report.findings, start=1):
            self._render_finding_panel(idx, finding)

        return ""

    def _render_finding_panel(self, index: int, finding: Finding) -> None:
        title_text = Text()
        title_text.append(f"#{index} ", style="dim")
        title_text.append(f"[{finding.severity.value}] ", style=finding.severity.rich_color)
        title_text.append(finding.title, style="bold white")

        body_elements: list[Any] = []

        # Category and Location
        cat_url = Text()
        cat_url.append("Category: ", style="bold cyan")
        cat_url.append(f"{finding.category.value}  |  ", style="white")
        cat_url.append("URL: ", style="bold cyan")
        cat_url.append(finding.url, style="blue underline")
        if finding.response_status:
            cat_url.append(f" (HTTP {finding.response_status})", style="yellow")
        self.console.print(cat_url)

        # Description
        desc_text = Text(f"\n{finding.description}\n", style="dim white")
        self.console.print(desc_text)

        # Evidence
        ev_panel = Panel(
            Text(finding.evidence, style="red"),
            title="[bold red]Evidence[/bold red]",
            border_style="red",
            expand=False,
        )
        self.console.print(ev_panel)

        # Remediation
        if self.show_remediation and finding.remediation:
            rem = finding.remediation
            rem_text = Text()
            rem_text.append("\n💡 Guidance:\n", style="bold yellow")
            rem_text.append(f"{rem.guidance}\n", style="white")
            self.console.print(rem_text)

            for example in rem.examples:
                self.console.print(
                    Text(f"▸ {example.title} ({example.language}):", style="bold cyan")
                )
                syntax = Syntax(
                    example.snippet.strip(),
                    example.language,
                    theme="monokai",
                    line_numbers=False,
                    word_wrap=True,
                )
                self.console.print(syntax)
                self.console.print()

            if rem.references:
                ref_text = Text("References:\n", style="bold dim")
                for ref in rem.references:
                    ref_text.append(f"  • {ref}\n", style="blue")
                self.console.print(ref_text)

        self.console.print("─" * 70)
        self.console.print()


class JsonReporter(BaseReporter):
    """JSON reporter for CI/CD pipelines and automated analysis."""

    def render(self, report: ScanReport, destination: str | None = None) -> str:
        data = report.to_dict()
        content = json.dumps(data, indent=2, ensure_ascii=False)
        if destination:
            Path(destination).write_text(content, encoding="utf-8")
        return content


class SarifReporter(BaseReporter):
    """SARIF 2.1.0 reporter for GitHub code scanning and other SARIF-aware tools."""

    SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    LEVELS = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    # GitHub buckets security-severity: >=9 critical, 7-8.9 high, 4-6.9 medium, <4 low.
    SECURITY_SEVERITY = {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }

    def render(self, report: ScanReport, destination: str | None = None) -> str:
        content = json.dumps(self.build(report), indent=2, ensure_ascii=False)
        if destination:
            Path(destination).write_text(content, encoding="utf-8")
        return content

    def build(self, report: ScanReport) -> dict[str, Any]:
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        results: list[dict[str, Any]] = []

        for f in report.findings:
            if f.rule_id not in rule_index:
                rule_index[f.rule_id] = len(rules)
                rules.append(self._rule_descriptor(f))
            results.append(
                {
                    "ruleId": f.rule_id,
                    "ruleIndex": rule_index[f.rule_id],
                    "level": self.LEVELS[f.severity],
                    "message": {"text": f"{f.title}: {f.evidence}"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": f.url}}}
                    ],
                    "partialFingerprints": {"patchlintFingerprint/v1": f.fingerprint},
                    "properties": {"severity": f.severity.value},
                }
            )

        return {
            "$schema": self.SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PatchLint",
                            "version": __version__,
                            "informationUri": "https://github.com/kraim0vv/patchlint",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": not report.errors,
                            "toolExecutionNotifications": [
                                {"level": "error", "message": {"text": f"{e.rule_id}: {e.message}"}}
                                for e in report.errors
                            ],
                        }
                    ],
                }
            ],
        }

    def _rule_descriptor(self, f: Finding) -> dict[str, Any]:
        rem = f.remediation
        md = [rem.guidance, ""]
        for ex in rem.examples:
            md += [f"**{ex.title}**", f"```{ex.language}", ex.snippet, "```", ""]
        if rem.references:
            md += ["References:"] + [f"- {r}" for r in rem.references]
        return {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "help": {"text": rem.guidance, "markdown": "\n".join(md)},
            "helpUri": rem.references[0] if rem.references else "https://github.com/kraim0vv/patchlint",
            "defaultConfiguration": {"level": self.LEVELS[f.severity]},
            "properties": {
                "tags": ["security", f.category.value],
                "security-severity": self.SECURITY_SEVERITY[f.severity],
            },
        }


class HtmlReporter(BaseReporter):
    """HTML reporter creating standalone, self-contained interactive reports."""

    def render(self, report: ScanReport, destination: str | None = None) -> str:
        html_content = self._render_template(report)
        if destination:
            Path(destination).write_text(html_content, encoding="utf-8")
        return html_content

    def _render_template(self, report: ScanReport) -> str:
        try:
            from jinja2 import Template

            template_str = HTML_REPORT_TEMPLATE.read_text(encoding="utf-8")
            # Evidence and URLs come from the scanned target and must be escaped.
            template = Template(template_str, autoescape=True)
            return template.render(
                summary=report.summary,
                findings=report.findings,
                errors=report.errors,
                suppressed_count=report.suppressed_count,
            )
        except ImportError:
            # Fallback zero-dependency HTML generator if jinja2 is not installed
            return self._fallback_render(report)

    def _fallback_render(self, report: ScanReport) -> str:
        """Lightweight HTML generator when Jinja2 is unavailable."""
        s = report.summary
        findings_html = []

        for f in report.findings:
            snippets = []
            for ex in f.remediation.examples:
                snippets.append(
                    f"<div style='margin-top:8px;'><strong>{html.escape(ex.title)} ({html.escape(ex.language)}):</strong>"
                    f"<pre style='background:#030712;color:#38bdf8;padding:10px;border-radius:6px;'>"
                    f"<code>{html.escape(ex.snippet)}</code></pre></div>"
                )

            refs = "".join(
                f"<a href='{html.escape(r)}' target='_blank' style='color:#60a5fa;margin-right:10px;'>{html.escape(r)}</a>"
                for r in f.remediation.references
            )

            card = f"""
            <div style="background:#111827;border-left:5px solid {f.severity.hex_color};padding:20px;margin-bottom:15px;border-radius:8px;">
                <div style="display:flex;gap:8px;margin-bottom:8px;">
                    <span style="background:{f.severity.hex_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">{f.severity.value}</span>
                    <span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:11px;">{html.escape(f.category.value)}</span>
                </div>
                <h3 style="color:#fff;margin:0 0 6px 0;">{html.escape(f.title)}</h3>
                <div style="color:#60a5fa;font-family:monospace;font-size:13px;margin-bottom:10px;">{html.escape(f.url)}</div>
                <p style="color:#d1d5db;font-size:14px;">{html.escape(f.description)}</p>
                <div style="background:#030712;color:#ef4444;padding:10px;border-radius:6px;margin:10px 0;font-family:monospace;font-size:13px;">
                    <strong>Evidence:</strong> {html.escape(f.evidence)}
                </div>
                <div style="background:rgba(30,41,59,0.5);padding:14px;border-radius:6px;margin-top:10px;">
                    <strong style="color:#38bdf8;">💡 Remediation:</strong>
                    <p style="color:#cbd5e1;white-space:pre-line;margin:6px 0;">{html.escape(f.remediation.guidance)}</p>
                    {''.join(snippets)}
                    <div style="margin-top:10px;font-size:12px;">{refs}</div>
                </div>
            </div>
            """
            findings_html.append(card)

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PatchLint Report - {html.escape(s.target_url)}</title>
    <style>
        body {{ background:#0b0f19; color:#f3f4f6; font-family:-apple-system,sans-serif; margin:0; padding:25px; }}
        .wrap {{ max-width:1100px; margin:0 auto; }}
        .header {{ background:#111827; border:1px solid #1f2937; padding:25px; border-radius:10px; margin-bottom:25px; }}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="header">
            <h1 style="margin:0 0 10px 0;">PatchLint DAST Security Audit</h1>
            <p style="margin:4px 0;color:#9ca3af;">Target: <strong style="color:#fff;">{html.escape(s.target_url)}</strong></p>
            <p style="margin:4px 0;color:#9ca3af;">Duration: {s.duration_seconds:.2f}s | Findings: {s.total_findings} | Requests: {s.total_requests}</p>
        </div>
        <div>{''.join(findings_html) if findings_html else '<p style="color:#10b981;">Clean scan! No issues found.</p>'}</div>
    </div>
</body>
</html>"""


def get_reporter(report_format: str, console: Console | None = None) -> BaseReporter:
    """Factory function for acquiring appropriate reporter."""
    fmt = report_format.lower()
    if fmt == "json":
        return JsonReporter()
    if fmt == "sarif":
        return SarifReporter()
    if fmt == "html":
        return HtmlReporter()
    if fmt == "terminal" or fmt == "console":
        return ConsoleReporter(console=console)
    raise ValueError(f"Unsupported report format '{report_format}'. Supported: terminal, json, sarif, html")
