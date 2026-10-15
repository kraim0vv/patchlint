"""Unit tests for PatchLint CLI exit codes and behavior."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from click.testing import CliRunner

from patchlint.cli import main
from patchlint.engine import TargetUnreachableError
from patchlint.models import (
    Category,
    Finding,
    Remediation,
    RemediationExample,
    ScanReport,
    ScanSummary,
    Severity,
)


def _build_mock_report(findings: list[Finding]) -> ScanReport:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    summary = ScanSummary(
        target_url="http://localhost:8000",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=0.1,
        total_requests=10,
        total_findings=len(findings),
        counts_by_severity=counts,
    )
    return ScanReport(summary=summary, findings=findings)


def _make_dummy_finding(severity: Severity, rule_id: str = "test-rule") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Test {severity.value} issue",
        severity=severity,
        category=Category.INFORMATION_DISCLOSURE,
        url="http://localhost:8000/test",
        description="A test vulnerability description",
        evidence="Found test evidence",
        remediation=Remediation(
            guidance="Fix this issue",
            examples=[RemediationExample("Nginx", "nginx", "deny all;")],
        ),
        response_status=200,
    )


def test_cli_exit_code_3_missing_target():
    """Exit code 3 when target argument is missing."""
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code == 3
    assert "Missing argument TARGET URL" in result.output


def test_cli_exit_code_2_network_unreachable():
    """Exit code 2 when target web application cannot be reached."""
    runner = CliRunner()
    with patch(
        "patchlint.cli.AuditEngine.scan",
        new_callable=AsyncMock,
        side_effect=TargetUnreachableError("Connection refused at http://localhost:9999"),
    ):
        result = runner.invoke(main, ["http://localhost:9999"])
        assert result.exit_code == 2
        assert "Target Unreachable" in result.output


def test_cli_exit_code_0_when_findings_below_threshold():
    """Exit code 0 when findings exist but their severity is below the --fail-on threshold (e.g. LOW with default --fail-on HIGH)."""
    runner = CliRunner()
    low_finding = _make_dummy_finding(Severity.LOW, "missing-referrer-policy")
    mock_report = _build_mock_report([low_finding])

    with patch(
        "patchlint.cli.AuditEngine.scan",
        new_callable=AsyncMock,
        return_value=mock_report,
    ):
        # Default --fail-on is HIGH; finding is LOW (rank 1 < rank 3), so exit code must be 0
        result = runner.invoke(main, ["http://localhost:8000"])
        assert result.exit_code == 0


def test_cli_exit_code_1_when_findings_meet_or_exceed_threshold():
    """Exit code 1 when findings meet or exceed the --fail-on threshold (e.g. HIGH finding with default --fail-on HIGH)."""
    runner = CliRunner()
    high_finding = _make_dummy_finding(Severity.HIGH, "missing-csp-header")
    mock_report = _build_mock_report([high_finding])

    with patch(
        "patchlint.cli.AuditEngine.scan",
        new_callable=AsyncMock,
        return_value=mock_report,
    ):
        result = runner.invoke(main, ["http://localhost:8000"])
        assert result.exit_code == 1


def test_cli_exit_code_1_with_custom_fail_on():
    """Exit code 1 when a LOW finding is detected and --fail-on LOW is explicitly requested."""
    runner = CliRunner()
    low_finding = _make_dummy_finding(Severity.LOW, "technology-disclosure-header")
    mock_report = _build_mock_report([low_finding])

    with patch(
        "patchlint.cli.AuditEngine.scan",
        new_callable=AsyncMock,
        return_value=mock_report,
    ):
        result = runner.invoke(main, ["http://localhost:8000", "--fail-on", "LOW"])
        assert result.exit_code == 1


def test_cli_exit_code_0_on_clean_scan_even_with_fail_on_info():
    """Exit code 0 when there are no findings, even if --fail-on INFO is passed."""
    runner = CliRunner()
    mock_report = _build_mock_report([])

    with patch(
        "patchlint.cli.AuditEngine.scan",
        new_callable=AsyncMock,
        return_value=mock_report,
    ):
        result = runner.invoke(main, ["http://localhost:8000", "--fail-on", "INFO"])
        assert result.exit_code == 0


def test_cli_list_rules_exits_0():
    """CLI exits 0 and prints rules table when --list-rules is passed."""
    runner = CliRunner()
    result = runner.invoke(main, ["--list-rules"])
    assert result.exit_code == 0
    assert "PatchLint - Built-in Security Rules" in result.output
    assert "exposed-swagger-spec" in result.output
