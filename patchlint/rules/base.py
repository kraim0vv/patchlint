"""Base interfaces and abstractions for security linter rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
import re
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    import httpx

from patchlint.models import Category, Finding, Remediation, Severity


@dataclass(slots=True)
class ScanContext:
    """Execution context provided to rules during an audit."""

    base_url: str
    client: httpx.AsyncClient
    base_response: httpx.Response | None = None
    is_spa_wildcard: bool = False
    wildcard_length: int = 0
    increment_request_count: Callable[[], None] = field(
        default_factory=lambda: (lambda: None)
    )


class BaseRule(ABC):
    """Abstract base rule class.

    All detection rules inherit from this class and declare vulnerability metadata,
    remediation guidance, and automated check logic.
    """

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        category: Category,
        title: str,
        description: str,
        remediation: Remediation,
        tags: list[str] | None = None,
    ) -> None:
        self.id = rule_id
        self.severity = severity
        self.category = category
        self.title = title
        self.description = description
        self.remediation = remediation
        self.tags = tags or []

    @abstractmethod
    async def check(self, context: ScanContext) -> list[Finding]:
        """Execute the rule check logic against the given target context.

        Returns a list of Findings if issues are detected, or an empty list.
        """
        raise NotImplementedError

    def create_finding(
        self,
        url: str,
        evidence: str,
        response_status: int | None = None,
        custom_description: str | None = None,
    ) -> Finding:
        """Helper to create a normalized Finding from this rule."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            url=url,
            description=custom_description or self.description,
            evidence=evidence,
            remediation=self.remediation,
            response_status=response_status,
        )


class HeaderRule(BaseRule):
    """Specialized rule for evaluating HTTP response headers.

    Executes passively against the pre-fetched baseline response,
    avoiding unnecessary network requests.
    """

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        category: Category,
        title: str,
        description: str,
        remediation: Remediation,
        target_header: str,
        tags: list[str] | None = None,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            tags=tags,
        )
        self.target_header = target_header.lower()

    @abstractmethod
    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        """Evaluate headers.

        Returns (is_vulnerable, evidence_message).
        """
        raise NotImplementedError

    async def check(self, context: ScanContext) -> list[Finding]:
        if context.base_response is None:
            return []

        is_vulnerable, evidence = self.evaluate_headers(
            context.base_response.headers, context.base_response
        )
        if is_vulnerable:
            return [
                self.create_finding(
                    url=str(context.base_response.url),
                    evidence=evidence,
                    response_status=context.base_response.status_code,
                )
            ]
        return []


class PathExposureRule(BaseRule):
    """Rule for checking sensitive file and directory exposures.

    Implements robust false-positive mitigation (e.g. SPA routers returning 200
    for 404s, custom error pages, and content-type checking).
    """

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        category: Category,
        title: str,
        description: str,
        remediation: Remediation,
        path: str,
        expected_status: tuple[int, ...] = (200,),
        signature_regexes: list[re.Pattern[str]] | None = None,
        signature_strings: list[str] | None = None,
        disallowed_content_types: list[str] | None = None,
        min_body_length: int = 1,
        tags: list[str] | None = None,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            tags=tags,
        )
        self.path = path if path.startswith("/") else f"/{path}"
        self.expected_status = expected_status
        self.signature_regexes = signature_regexes or []
        self.signature_strings = signature_strings or []
        self.disallowed_content_types = disallowed_content_types or ["text/html"]
        self.min_body_length = min_body_length

    async def check(self, context: ScanContext) -> list[Finding]:
        target_url = context.base_url.rstrip("/") + self.path
        try:
            context.increment_request_count()
            resp = await context.client.get(target_url, follow_redirects=False)
        except Exception:
            # Network failures for this specific path are handled gracefully
            return []

        if resp.status_code not in self.expected_status:
            return []

        body_text = resp.text
        if len(body_text.strip()) < self.min_body_length:
            return []

        content_type = resp.headers.get("content-type", "").lower()

        # False-positive mitigation: if SPA wildcard is detected and response looks like HTML
        if context.is_spa_wildcard and "text/html" in content_type:
            # Compare response length with wildcard length; if close, it's the SPA fallback
            if abs(len(resp.content) - context.wildcard_length) < 50:
                return []

        # If disallowed content type matches and no signature overrides it
        if any(dt in content_type for dt in self.disallowed_content_types):
            # Check if any strict signature matches despite HTML header
            has_strong_sig = False
            for sig in self.signature_strings:
                if sig in body_text:
                    has_strong_sig = True
                    break
            if not has_strong_sig:
                for regex in self.signature_regexes:
                    if regex.search(body_text):
                        has_strong_sig = True
                        break
            if not has_strong_sig:
                return []

        # Signature matching
        matched_evidence: list[str] = []
        if self.signature_strings:
            for sig in self.signature_strings:
                if sig in body_text:
                    matched_evidence.append(f"Contains signature '{sig}'")
            if not matched_evidence:
                return []

        if self.signature_regexes:
            for regex in self.signature_regexes:
                match = regex.search(body_text)
                if match:
                    snippet = match.group(0)[:80].replace("\n", " ").strip()
                    matched_evidence.append(f"Matched pattern: '{snippet}'")
            if not matched_evidence:
                return []

        evidence_str = (
            f"Exposed file at {self.path} (HTTP {resp.status_code}, Content-Type: {content_type or 'None'}). "
            + ("; ".join(matched_evidence) if matched_evidence else "Accessible without authentication.")
        )

        return [
            self.create_finding(
                url=target_url,
                evidence=evidence_str,
                response_status=resp.status_code,
            )
        ]


class MultiPathExposureRule(BaseRule):
    """Rule that probes multiple URL paths for a single vulnerability.

    Adds strict Content-Type validation and optional body parsing (JSON/YAML)
    to prevent false positives caused by SPA catch-all routers returning HTML
    on every path.

    Subclasses provide:
        - paths: list of URL suffixes to probe (e.g. ["/openapi.json", "/swagger.json"])
        - allowed_content_types: accepted MIME types (e.g. ["application/json"])
        - require_json_body: if True the response body MUST parse as a JSON dict
        - signature_strings: list of strings that must appear in the body
    """

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        category: Category,
        title: str,
        description: str,
        remediation: Remediation,
        paths: list[str],
        expected_status: tuple[int, ...] = (200,),
        allowed_content_types: list[str] | None = None,
        require_json_body: bool = False,
        signature_strings: list[str] | None = None,
        signature_regexes: list[re.Pattern[str]] | None = None,
        min_body_length: int = 1,
        tags: list[str] | None = None,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            tags=tags,
        )
        self.paths = [p if p.startswith("/") else f"/{p}" for p in paths]
        self.expected_status = expected_status
        self.allowed_content_types = allowed_content_types or []
        self.require_json_body = require_json_body
        self.signature_strings = signature_strings or []
        self.signature_regexes = signature_regexes or []
        self.min_body_length = min_body_length

    async def check(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.paths:
            result = await self._check_single_path(context, path)
            if result:
                findings.append(result)
        return findings

    async def _check_single_path(
        self, context: ScanContext, path: str
    ) -> Finding | None:
        target_url = context.base_url.rstrip("/") + path
        try:
            context.increment_request_count()
            resp = await context.client.get(target_url, follow_redirects=False)
        except Exception:
            return None

        # --- Status code gate ---
        if resp.status_code not in self.expected_status:
            return None

        body_text = resp.text
        if len(body_text.strip()) < self.min_body_length:
            return None

        content_type = resp.headers.get("content-type", "").lower()

        # --- Content-Type gate ---
        if self.allowed_content_types:
            if not any(ct in content_type for ct in self.allowed_content_types):
                return None

        # --- Reject HTML bodies (SPA fallback) ---
        if "text/html" in content_type:
            return None

        # --- Optional JSON body parsing gate ---
        if self.require_json_body:
            try:
                parsed = json.loads(body_text)
                if not isinstance(parsed, dict):
                    return None
            except (json.JSONDecodeError, ValueError):
                return None

        # --- SPA wildcard length comparison ---
        if context.is_spa_wildcard:
            if abs(len(resp.content) - context.wildcard_length) < 50:
                return None

        # --- Signature matching ---
        matched_evidence: list[str] = []
        if self.signature_strings:
            for sig in self.signature_strings:
                if sig in body_text:
                    matched_evidence.append(f"Contains signature '{sig}'")
            if not matched_evidence:
                return None

        if self.signature_regexes:
            regex_matched = False
            for regex in self.signature_regexes:
                match = regex.search(body_text)
                if match:
                    snippet = match.group(0)[:80].replace("\n", " ").strip()
                    matched_evidence.append(f"Matched pattern: '{snippet}'")
                    regex_matched = True
            if not regex_matched and not matched_evidence:
                return None

        evidence_str = (
            f"Exposed file at {path} (HTTP {resp.status_code}, "
            f"Content-Type: {content_type or 'None'}). "
            + ("; ".join(matched_evidence) if matched_evidence else "Accessible without authentication.")
        )

        return self.create_finding(
            url=target_url,
            evidence=evidence_str,
            response_status=resp.status_code,
        )
