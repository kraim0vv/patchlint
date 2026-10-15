"""Unit tests for PatchLint engine and reporters."""

from datetime import datetime, timezone
import json
import pytest

from patchlint.models import (
    Category,
    Finding,
    Remediation,
    RemediationExample,
    ScanReport,
    ScanSummary,
    Severity,
)
from patchlint.reporter import HtmlReporter, JsonReporter


@pytest.fixture
def sample_report():
    rem = Remediation(
        guidance="Add Content-Security-Policy header to HTTP responses.",
        examples=[
            RemediationExample(
                title="Nginx",
                language="nginx",
                snippet="add_header Content-Security-Policy \"default-src 'self';\" always;",
            )
        ],
        references=["https://owasp.org/www-project-secure-headers/"],
    )

    finding = Finding(
        rule_id="missing-csp-header",
        title="Missing Content-Security-Policy (CSP)",
        severity=Severity.HIGH,
        category=Category.SECURITY_HEADERS,
        url="http://localhost:8000/",
        description="CSP header is missing.",
        evidence="Header 'Content-Security-Policy' is absent in HTTP response.",
        remediation=rem,
        response_status=200,
    )

    summary = ScanSummary(
        target_url="http://localhost:8000",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=0.42,
        total_requests=12,
        total_findings=1,
        counts_by_severity={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )

    return ScanReport(summary=summary, findings=[finding])


def test_json_reporter(sample_report, tmp_path):
    reporter = JsonReporter()
    output_file = tmp_path / "report.json"
    rendered = reporter.render(sample_report, destination=str(output_file))

    parsed = json.loads(rendered)
    assert parsed["summary"]["target_url"] == "http://localhost:8000"
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "missing-csp-header"
    assert parsed["findings"][0]["severity"] == "HIGH"
    assert output_file.exists()


def test_html_reporter(sample_report, tmp_path):
    reporter = HtmlReporter()
    output_file = tmp_path / "report.html"
    rendered = reporter.render(sample_report, destination=str(output_file))

    assert "<!DOCTYPE html>" in rendered or "<html>" in rendered
    assert "http://localhost:8000" in rendered
    assert "Missing Content-Security-Policy" in rendered
    assert "add_header Content-Security-Policy" in rendered
    assert output_file.exists()
