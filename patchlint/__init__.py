"""PatchLint: Actionable DAST & Security Linter for developers."""

from patchlint.engine import AuditEngine, TargetUnreachableError
from patchlint.models import (
    Category,
    Finding,
    Remediation,
    RemediationExample,
    ScanReport,
    ScanSummary,
    Severity,
)
from patchlint.rules import (
    BaseRule,
    HeaderRule,
    MultiPathExposureRule,
    PathExposureRule,
    RuleRegistry,
)

__version__ = "1.0.0"

__all__ = [
    "AuditEngine",
    "TargetUnreachableError",
    "Severity",
    "Category",
    "Remediation",
    "RemediationExample",
    "Finding",
    "ScanReport",
    "ScanSummary",
    "BaseRule",
    "HeaderRule",
    "MultiPathExposureRule",
    "PathExposureRule",
    "RuleRegistry",
    "__version__",
]
