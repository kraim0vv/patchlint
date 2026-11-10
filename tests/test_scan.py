"""End-to-end tests for AuditEngine.scan() using an in-memory HTTP transport."""

import httpx
import pytest
from click.testing import CliRunner

from patchlint.cli import main
from patchlint.engine import AuditEngine, AuditEngineError, normalize_target_url
from patchlint.models import Severity

SECURE_HEADERS = {
    "content-type": "text/html",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


class MockEngine(AuditEngine):
    def __init__(self, handler, **kwargs):
        super().__init__(**kwargs)
        self._handler = handler
        self.requested_urls: list[str] = []

    def _build_client(self) -> httpx.AsyncClient:
        def record(request: httpx.Request) -> httpx.Response:
            self.requested_urls.append(str(request.url))
            return self._handler(request)

        return httpx.AsyncClient(transport=httpx.MockTransport(record))


def hardened_site(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/":
        return httpx.Response(200, headers=SECURE_HEADERS, text="<html>ok</html>")
    return httpx.Response(404, headers={"content-type": "text/plain"}, text="not found")


def leaky_site(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/.env":
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="APP_KEY=base64:secret\n")
    return hardened_site(request)


def spa_site(request: httpx.Request) -> httpx.Response:
    # Catch-all router: every path returns the same index.html.
    return httpx.Response(200, headers=SECURE_HEADERS, text="<html><div id=root></div></html>")


@pytest.mark.asyncio
async def test_scan_hardened_site_has_no_findings():
    engine = MockEngine(hardened_site)
    report = await engine.scan("https://example.test")
    assert report.findings == []
    assert report.summary.total_requests == len(engine.requested_urls)


@pytest.mark.asyncio
async def test_scan_detects_env_and_masks_secret():
    report = await MockEngine(leaky_site).scan("https://example.test")
    env = [f for f in report.findings if f.rule_id == "exposed-env-file"]
    assert len(env) == 1
    assert "APP_KEY=***" in env[0].evidence
    assert "secret" not in env[0].evidence
    assert report.summary.counts_by_severity["CRITICAL"] == 1


@pytest.mark.asyncio
async def test_scan_spa_catch_all_is_not_flagged():
    report = await MockEngine(spa_site).scan("https://example.test")
    assert report.findings == []


@pytest.mark.asyncio
async def test_headers_only_does_not_probe_paths():
    engine = MockEngine(leaky_site, headers_only=True)
    await engine.scan("https://example.test")
    assert not any("/.env" in u for u in engine.requested_urls)


@pytest.mark.asyncio
async def test_min_severity_filters_findings():
    def bare_site(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    report = await MockEngine(bare_site, min_severity=Severity.HIGH).scan("https://example.test")
    assert report.findings
    assert all(f.severity.rank >= Severity.HIGH.rank for f in report.findings)


@pytest.mark.asyncio
async def test_query_string_is_not_part_of_probe_urls():
    engine = MockEngine(hardened_site)
    await engine.scan("https://example.test/app?x=1#frag")
    assert "https://example.test/app/.env" in engine.requested_urls
    assert not any("?x=1" in u for u in engine.requested_urls)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("localhost:8000", "http://localhost:8000/"),
        ("  HTTPS://example.test/app?x=1#f ", "https://example.test/app"),
        ("http://127.0.0.1", "http://127.0.0.1/"),
    ],
)
def test_normalize_target_url(raw, expected):
    assert normalize_target_url(raw) == expected


@pytest.mark.parametrize("raw", ["ftp://example.test", "http://"])
def test_normalize_target_url_rejects_invalid(raw):
    with pytest.raises(AuditEngineError):
        normalize_target_url(raw)


def test_cli_rejects_unsupported_scheme():
    result = CliRunner().invoke(main, ["ftp://example.test"])
    assert result.exit_code == 3
    assert "Unsupported URL scheme" in result.output
