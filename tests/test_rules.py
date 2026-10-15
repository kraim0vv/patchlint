"""Unit tests for PatchLint security rules."""

import pytest
import httpx
import respx

from patchlint.models import Severity
from patchlint.rules.base import ScanContext
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


@pytest.fixture
def mock_context():
    def _create_context(headers=None, status_code=200, text=""):
        req = httpx.Request("GET", "https://app.local/")
        resp = httpx.Response(
            status_code=status_code,
            headers=headers or {},
            text=text,
            request=req,
        )
        return ScanContext(
            base_url="https://app.local",
            client=httpx.AsyncClient(),
            base_response=resp,
        )

    return _create_context


@pytest.mark.asyncio
async def test_missing_csp_rule(mock_context):
    rule = MissingCSPRule()

    # Case 1: Missing header
    ctx = mock_context(headers={})
    findings = await rule.check(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "missing-csp-header"
    assert findings[0].severity == Severity.HIGH

    # Case 2: Present and strong
    ctx_good = mock_context(headers={"content-security-policy": "default-src 'self'"})
    assert len(await rule.check(ctx_good)) == 0

    # Case 3: Insecure inline without nonce
    ctx_weak = mock_context(headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    weak_findings = await rule.check(ctx_weak)
    assert len(weak_findings) == 1
    assert "unsafe-inline" in weak_findings[0].evidence


@pytest.mark.asyncio
async def test_missing_hsts_rule(mock_context):
    rule = MissingHSTSRule()

    # Case 1: Missing on HTTPS
    ctx = mock_context(headers={})
    findings = await rule.check(ctx)
    assert len(findings) == 1

    # Case 2: Present with good max-age
    ctx_good = mock_context(headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
    assert len(await rule.check(ctx_good)) == 0

    # Case 3: Too short max-age
    ctx_short = mock_context(headers={"strict-transport-security": "max-age=300"})
    short_findings = await rule.check(ctx_short)
    assert len(short_findings) == 1
    assert "lower than recommended" in short_findings[0].evidence


@pytest.mark.asyncio
async def test_missing_x_frame_options_rule(mock_context):
    rule = MissingXFrameOptionsRule()

    # Case 1: Missing
    ctx = mock_context(headers={})
    findings = await rule.check(ctx)
    assert len(findings) == 1

    # Case 2: Configured via DENY
    ctx_deny = mock_context(headers={"x-frame-options": "DENY"})
    assert len(await rule.check(ctx_deny)) == 0

    # Case 3: Superseded by CSP frame-ancestors
    ctx_csp = mock_context(headers={"content-security-policy": "frame-ancestors 'self'"})
    assert len(await rule.check(ctx_csp)) == 0


@pytest.mark.asyncio
async def test_server_and_x_powered_by_disclosure(mock_context):
    srv_rule = ServerVersionDisclosureRule()
    xpb_rule = XPoweredByDisclosureRule()

    # Verbose headers
    ctx = mock_context(headers={"server": "nginx/1.18.0 (Ubuntu)", "x-powered-by": "PHP/8.1.2"})
    srv_findings = await srv_rule.check(ctx)
    xpb_findings = await xpb_rule.check(ctx)

    assert len(srv_findings) == 1
    assert "nginx/1.18.0" in srv_findings[0].evidence

    assert len(xpb_findings) == 1
    assert "PHP/8.1.2" in xpb_findings[0].evidence

    # Hardened server header
    ctx_hardened = mock_context(headers={"server": "cloudflare"})
    assert len(await srv_rule.check(ctx_hardened)) == 0
    assert len(await xpb_rule.check(ctx_hardened)) == 0


@pytest.mark.asyncio
async def test_debug_mode_detection(mock_context):
    rule = DebugModeRule()

    # Baseline response has Werkzeug traceback
    ctx = mock_context(text="<html><body><h3>Werkzeug Powered Traceback</h3></body></html>")
    findings = await rule.check(ctx)
    assert len(findings) == 1
    assert "Werkzeug Debug Console" in findings[0].evidence


@pytest.mark.asyncio
async def test_spa_wildcard_mitigation():
    """Verify that SPA router returning HTML 200 for 404 does not cause false positives."""
    rule = ExposedEnvFileRule()

    spa_html = "<html><head><title>My SPA</title></head><body><div id='root'></div></body></html>"

    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text=spa_html,
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        ctx = ScanContext(
            base_url="http://localhost:3000",
            client=client,
            is_spa_wildcard=True,
            wildcard_length=len(spa_html.encode("utf-8")),
        )
        findings = await rule.check(ctx)
        # Should be filtered out because it is text/html without env signatures
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_real_env_exposure_detection():
    """Verify that a real exposed .env with secrets is detected."""
    rule = ExposedEnvFileRule()

    env_body = "DB_HOST=127.0.0.1\nDB_PASSWORD=SuperSecretPass123!\nAPI_KEY=xyz789\n"

    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text=env_body,
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        ctx = ScanContext(
            base_url="http://localhost:8000",
            client=client,
        )
        findings = await rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "DB_PASSWORD" in findings[0].evidence


@respx.mock
@pytest.mark.asyncio
async def test_swagger_rule_valid_json():
    """Verify detection of valid Swagger/OpenAPI JSON with status 200."""
    rule = ExposedSwaggerJsonRule()
    swagger_payload = {
        "openapi": "3.0.0",
        "info": {"title": "Production API", "version": "1.0.0"},
        "paths": {"/admin": {"get": {"summary": "Admin dashboard"}}},
    }

    # Mock /openapi.json returning valid JSON
    respx.get("http://api.local/openapi.json").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/json; charset=utf-8"},
            json=swagger_payload,
        )
    )
    # Other paths return 404
    respx.get("http://api.local/swagger.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/api/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/v2/api-docs").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        ctx = ScanContext(base_url="http://api.local", client=client)
        findings = await rule.check(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "exposed-swagger-spec"
    assert findings[0].severity == Severity.LOW
    assert "openapi.json" in findings[0].url
    assert findings[0].response_status == 200


@respx.mock
@pytest.mark.asyncio
async def test_swagger_rule_alternative_path_detected():
    """Verify detection on alternative paths like /v2/api-docs."""
    rule = ExposedSwaggerJsonRule()
    swagger_v2_payload = {
        "swagger": "2.0",
        "info": {"title": "Legacy Spring API", "version": "2.0"},
    }

    respx.get("http://api.local/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/swagger.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/api/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/v2/api-docs").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=swagger_v2_payload,
        )
    )

    async with httpx.AsyncClient() as client:
        ctx = ScanContext(base_url="http://api.local", client=client)
        findings = await rule.check(ctx)

    assert len(findings) == 1
    assert "/v2/api-docs" in findings[0].url


@respx.mock
@pytest.mark.asyncio
async def test_swagger_rule_ignores_404():
    """Verify that 404 responses on all paths produce no findings."""
    rule = ExposedSwaggerJsonRule()

    respx.get("http://api.local/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/swagger.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/api/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/v2/api-docs").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        ctx = ScanContext(base_url="http://api.local", client=client)
        findings = await rule.check(ctx)

    assert len(findings) == 0


@respx.mock
@pytest.mark.asyncio
async def test_swagger_rule_ignores_spa_html_fallback():
    """Verify that HTTP 200 returning HTML (SPA catch-all) is ignored even if it contains keywords."""
    rule = ExposedSwaggerJsonRule()

    # SPA index.html that happens to contain "openapi": or "swagger": in a script tag or text
    spa_html = (
        "<!DOCTYPE html><html><head><title>SPA App</title></head>"
        "<body><div id='root'></div>"
        "<script>window.__CONFIG__ = {'swagger': false, 'openapi': false};</script>"
        "</body></html>"
    )

    # All paths return 200 with text/html
    for path in rule.paths:
        respx.get(f"http://spa.local{path}").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html; charset=utf-8"},
                text=spa_html,
            )
        )

    async with httpx.AsyncClient() as client:
        ctx = ScanContext(base_url="http://spa.local", client=client, is_spa_wildcard=True)
        findings = await rule.check(ctx)

    # Must be 0 because content-type is text/html and body is not a JSON object
    assert len(findings) == 0


@respx.mock
@pytest.mark.asyncio
async def test_swagger_rule_rejects_malformed_json():
    """Verify that HTTP 200 with application/json header but invalid JSON body is ignored."""
    rule = ExposedSwaggerJsonRule()

    respx.get("http://api.local/openapi.json").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/json"},
            text='{"openapi": broken json string...',
        )
    )
    respx.get("http://api.local/swagger.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/api/openapi.json").mock(return_value=httpx.Response(404))
    respx.get("http://api.local/v2/api-docs").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        ctx = ScanContext(base_url="http://api.local", client=client)
        findings = await rule.check(ctx)

    assert len(findings) == 0
