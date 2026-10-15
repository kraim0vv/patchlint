"""Rules package and registry for PatchLint."""

from __future__ import annotations

from typing import Iterable

from patchlint.rules.base import BaseRule, HeaderRule, MultiPathExposureRule, PathExposureRule, ScanContext
from patchlint.rules.exposure import (
    DebugModeRule,
    ExposedConfigJsonRule,
    ExposedDatabaseDumpRule,
    ExposedDockerComposeRule,
    ExposedEnvFileRule,
    ExposedGitDirectoryRule,
    ExposedSwaggerJsonRule,
)
from patchlint.rules.headers import (
    MissingCSPRule,
    MissingHSTSRule,
    MissingReferrerPolicyRule,
    MissingXContentTypeOptionsRule,
    MissingXFrameOptionsRule,
    ServerVersionDisclosureRule,
    XPoweredByDisclosureRule,
)


class RuleRegistry:
    """Central registry holding all configured audit rules."""

    def __init__(self, rules: Iterable[BaseRule] | None = None) -> None:
        self._rules: dict[str, BaseRule] = {}
        if rules:
            for rule in rules:
                self.register(rule)
        else:
            self.register_defaults()

    def register(self, rule: BaseRule) -> None:
        """Register a new or custom rule."""
        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> None:
        """Unregister a rule by ID."""
        self._rules.pop(rule_id, None)

    def get(self, rule_id: str) -> BaseRule | None:
        """Retrieve a rule by its unique ID."""
        return self._rules.get(rule_id)

    def get_all(self) -> list[BaseRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def get_header_rules(self) -> list[HeaderRule]:
        """Return only header inspection rules."""
        return [r for r in self._rules.values() if isinstance(r, HeaderRule)]

    def get_active_rules(self) -> list[BaseRule]:
        """Return active rules (file exposure, probes, debug checks)."""
        return [r for r in self._rules.values() if not isinstance(r, HeaderRule)]

    def register_defaults(self) -> None:
        """Populate the registry with the default standard rule set."""
        default_rules: list[BaseRule] = [
            # Security Headers
            MissingCSPRule(),
            MissingHSTSRule(),
            MissingXFrameOptionsRule(),
            MissingXContentTypeOptionsRule(),
            MissingReferrerPolicyRule(),
            ServerVersionDisclosureRule(),
            XPoweredByDisclosureRule(),
            # Information Disclosure & Exposed Files
            ExposedEnvFileRule(),
            ExposedGitDirectoryRule(),
            ExposedDockerComposeRule(),
            ExposedConfigJsonRule(),
            ExposedDatabaseDumpRule(),
            ExposedSwaggerJsonRule(),
            # Misconfiguration
            DebugModeRule(),
        ]
        for rule in default_rules:
            self.register(rule)


__all__ = [
    "BaseRule",
    "HeaderRule",
    "MultiPathExposureRule",
    "PathExposureRule",
    "ScanContext",
    "RuleRegistry",
    "MissingCSPRule",
    "MissingHSTSRule",
    "MissingXFrameOptionsRule",
    "MissingXContentTypeOptionsRule",
    "MissingReferrerPolicyRule",
    "ServerVersionDisclosureRule",
    "XPoweredByDisclosureRule",
    "ExposedEnvFileRule",
    "ExposedGitDirectoryRule",
    "ExposedDockerComposeRule",
    "ExposedConfigJsonRule",
    "ExposedDatabaseDumpRule",
    "ExposedSwaggerJsonRule",
    "DebugModeRule",
]
