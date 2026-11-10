"""Data models and abstractions for PatchLint DAST Security Linter.

Defines Severities, Categories, Remediation formats, Rule structures,
and Scan Result containers with full serialization capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


class Severity(str, Enum):
    """Vulnerability and finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    # Python 3.11+ renders str-mixin enums as "Severity.X" in str()/templates.
    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher = more severe).

        CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0.
        """
        ranks = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return ranks.get(self, 0)

    @property
    def rich_color(self) -> str:
        """Rich terminal color string."""
        colors = {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "bold blue",
        }
        return colors.get(self, "white")

    @property
    def hex_color(self) -> str:
        """Hex color code for HTML reports."""
        colors = {
            Severity.CRITICAL: "#ef4444",
            Severity.HIGH: "#f97316",
            Severity.MEDIUM: "#eab308",
            Severity.LOW: "#06b6d4",
            Severity.INFO: "#3b82f6",
        }
        return colors.get(self, "#94a3b8")


class Category(str, Enum):
    """Categorization for security checks."""

    SECURITY_HEADERS = "Security Headers"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    MISCONFIGURATION = "Misconfiguration"

    def __str__(self) -> str:
        return self.value


@dataclass(slots=True, frozen=True)
class RemediationExample:
    """Ready-to-use secure configuration or code example."""

    title: str
    language: str
    snippet: str

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "language": self.language,
            "snippet": self.snippet,
        }


@dataclass(slots=True)
class Remediation:
    """Structured remediation instructions for developers."""

    guidance: str
    examples: list[RemediationExample] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "guidance": self.guidance,
            "examples": [e.to_dict() for e in self.examples],
            "references": self.references,
        }


def compute_fingerprint(rule_id: str, url: str) -> str:
    path = urlsplit(url).path or "/"
    return hashlib.sha256(f"{rule_id}|{path}".encode()).hexdigest()[:16]


@dataclass(slots=True)
class Finding:
    """An individual security finding detected during the scan."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    url: str
    description: str
    evidence: str
    remediation: Remediation
    response_status: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        """Stable ID of rule + URL path (host-independent, so baselines work across environments)."""
        return compute_fingerprint(self.rule_id, self.url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "response_status": self.response_status,
            "timestamp": self.timestamp.isoformat(),
            "remediation": self.remediation.to_dict(),
        }


@dataclass(slots=True)
class ScanSummary:
    """High-level metrics and metadata for a scan run."""

    target_url: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_requests: int
    total_findings: int
    counts_by_severity: dict[str, int]
    status: str = "completed"
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "total_requests": self.total_requests,
            "total_findings": self.total_findings,
            "counts_by_severity": self.counts_by_severity,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass(slots=True)
class RuleError:
    """A rule that crashed during the scan; surfaced so failures never look like a clean result."""

    rule_id: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "message": self.message}


@dataclass(slots=True)
class ScanReport:
    """Complete scan results container."""

    summary: ScanSummary
    findings: list[Finding]
    errors: list[RuleError] = field(default_factory=list)
    suppressed_count: int = 0

    def recount(self) -> None:
        """Re-sync summary counters after findings were filtered."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        self.summary.counts_by_severity = counts
        self.summary.total_findings = len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": [e.to_dict() for e in self.errors],
            "suppressed_count": self.suppressed_count,
        }
