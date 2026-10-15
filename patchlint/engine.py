"""High-performance asynchronous audit engine using HTTPX."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ssl
import time
from typing import Callable
import uuid

import httpx

from patchlint.models import Finding, ScanReport, ScanSummary, Severity
from patchlint.rules import BaseRule, HeaderRule, RuleRegistry
from patchlint.rules.base import ScanContext


class AuditEngineError(Exception):
    """Base exception for audit engine failures."""


class TargetUnreachableError(AuditEngineError):
    """Raised when the target web application cannot be reached."""


class AuditEngine:
    """Asynchronous DAST scanner engine."""

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        timeout: float = 10.0,
        concurrency: int = 10,
        verify_ssl: bool = True,
        user_agent: str | None = None,
        headers_only: bool = False,
        min_severity: Severity | None = None,
    ) -> None:
        self.registry = registry or RuleRegistry()
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "PatchLint/1.0 (+https://github.com/kraim0vv/patchlint)"
        self.headers_only = headers_only
        self.min_severity = min_severity

        self._request_count = 0

    def _increment_request(self) -> None:
        self._request_count += 1

    def _build_client(self) -> httpx.AsyncClient:
        """Instantiate configured httpx.AsyncClient with connection pooling."""
        limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=15.0,
        )
        timeout_config = httpx.Timeout(
            timeout=self.timeout,
            connect=min(5.0, self.timeout),
            read=self.timeout,
            write=min(5.0, self.timeout),
        )
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }

        # Build custom SSL context if verify_ssl is False to suppress loud warnings
        ssl_context: ssl.SSLContext | bool = True
        if not self.verify_ssl:
            ssl_context = False

        return httpx.AsyncClient(
            verify=ssl_context,
            timeout=timeout_config,
            limits=limits,
            headers=headers,
            follow_redirects=True,
        )

    async def _fetch_baseline(
        self, client: httpx.AsyncClient, target_url: str
    ) -> httpx.Response:
        """Fetch baseline target response with comprehensive exception translation."""
        self._increment_request()
        try:
            resp = await client.get(target_url)
            return resp
        except httpx.ConnectTimeout as exc:
            raise TargetUnreachableError(
                f"Connection timed out while connecting to {target_url} (timeout: {self.timeout}s). "
                "Check if the server is running."
            ) from exc
        except httpx.ReadTimeout as exc:
            raise TargetUnreachableError(
                f"Read timed out waiting for response from {target_url}."
            ) from exc
        except httpx.ConnectError as exc:
            err_msg = str(exc)
            if "Errno 11001" in err_msg or "getaddrinfo failed" in err_msg:
                raise TargetUnreachableError(
                    f"DNS resolution failed for {target_url}. Please verify the hostname."
                ) from exc
            if "Connection refused" in err_msg or "10061" in err_msg:
                raise TargetUnreachableError(
                    f"Connection refused at {target_url}. Is the service running on this port?"
                ) from exc
            raise TargetUnreachableError(
                f"Failed to connect to target {target_url}: {err_msg}"
            ) from exc
        except httpx.RemoteProtocolError as exc:
            raise TargetUnreachableError(
                f"Remote protocol error communicating with {target_url}: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            # Check for SSL errors
            exc_str = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in exc_str or "certificate" in exc_str.lower():
                raise TargetUnreachableError(
                    f"SSL/TLS certificate verification failed for {target_url}. "
                    "If using a local or self-signed certificate, pass '--insecure' / '-k'."
                ) from exc
            raise TargetUnreachableError(f"HTTP request error: {exc}") from exc

    async def _detect_spa_wildcard(
        self, client: httpx.AsyncClient, base_url: str
    ) -> tuple[bool, int]:
        """Detect if the target server returns HTTP 200 HTML for non-existent paths (SPA catch-all)."""
        probe_path = f"{base_url.rstrip('/')}/_patchlint_wildcard_probe_{uuid.uuid4().hex[:8]}"
        try:
            self._increment_request()
            resp = await client.get(probe_path, follow_redirects=False)
            content_type = resp.headers.get("content-type", "").lower()
            if resp.status_code == 200 and "text/html" in content_type:
                return True, len(resp.content)
        except Exception:
            pass
        return False, 0

    async def scan(
        self,
        target_url: str,
        on_progress: Callable[[int, int, str], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> ScanReport:
        """Run complete DAST security audit on the specified target."""
        self._request_count = 0
        start_time = datetime.now(timezone.utc)
        start_mono = time.monotonic()

        # Normalize target URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        findings: list[Finding] = []

        async with self._build_client() as client:
            # Phase 1: Reachability & Baseline
            base_resp = await self._fetch_baseline(client, target_url)

            # Detect SPA wildcard catch-all
            is_spa, wildcard_len = await self._detect_spa_wildcard(client, target_url)

            context = ScanContext(
                base_url=target_url,
                client=client,
                base_response=base_resp,
                is_spa_wildcard=is_spa,
                wildcard_length=wildcard_len,
                increment_request_count=self._increment_request,
            )

            # Phase 2: Select rules
            if self.headers_only:
                rules_to_run = self.registry.get_header_rules()
            else:
                rules_to_run = self.registry.get_all()

            total_rules = len(rules_to_run)
            completed_rules = 0

            # Phase 3: Execute rules
            # Header rules run synchronously first (no extra network overhead)
            header_rules = [r for r in rules_to_run if isinstance(r, HeaderRule)]
            active_rules = [r for r in rules_to_run if not isinstance(r, HeaderRule)]

            for rule in header_rules:
                if on_progress:
                    on_progress(completed_rules, total_rules, rule.title)
                rule_findings = await rule.check(context)
                for f in rule_findings:
                    if self._matches_min_severity(f.severity):
                        findings.append(f)
                        if on_finding:
                            on_finding(f)
                completed_rules += 1

            # Active rules run with controlled concurrency via Semaphore
            sem = asyncio.Semaphore(self.concurrency)

            async def run_active_rule(rule: BaseRule) -> None:
                nonlocal completed_rules
                async with sem:
                    if on_progress:
                        on_progress(completed_rules, total_rules, rule.title)
                    try:
                        rule_findings = await rule.check(context)
                        for f in rule_findings:
                            if self._matches_min_severity(f.severity):
                                findings.append(f)
                                if on_finding:
                                    on_finding(f)
                    except Exception:
                        # Individual rule failures do not abort the scan
                        pass
                    finally:
                        completed_rules += 1

            if active_rules:
                await asyncio.gather(*(run_active_rule(r) for r in active_rules))

            if on_progress:
                on_progress(total_rules, total_rules, "Scan complete")

        duration = time.monotonic() - start_mono
        end_time = datetime.now(timezone.utc)

        # Sort findings by severity (CRITICAL first)
        findings.sort(key=lambda f: f.severity.rank, reverse=True)

        # Calculate metrics
        counts_by_severity = {s.value: 0 for s in Severity}
        for f in findings:
            counts_by_severity[f.severity.value] += 1

        summary = ScanSummary(
            target_url=target_url,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_requests=self._request_count,
            total_findings=len(findings),
            counts_by_severity=counts_by_severity,
            status="completed",
        )

        return ScanReport(summary=summary, findings=findings)

    def _matches_min_severity(self, severity: Severity) -> bool:
        if self.min_severity is None:
            return True
        return severity.rank >= self.min_severity.rank
