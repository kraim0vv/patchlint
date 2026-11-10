"""Tests for cookie/CORS rules, rule-error reporting, SARIF, baseline and config support."""

import json

import httpx
import pytest
from click.testing import CliRunner

from patchlint.cli import main
from patchlint.config import ConfigError, apply_baseline, load_baseline, load_config
from patchlint.engine import AuditEngine
from patchlint.models import Category, Remediation, Severity
from patchlint.reporter import JsonReporter, SarifReporter
from patchlint.rules import RuleRegistry
from patchlint.rules.base import BaseRule, ScanContext
from patchlint.rules.cookies import InsecureCookieRule
from patchlint.rules.cors import PROBE_ORIGIN, CorsMisconfigurationRule
from patchlint.rules.headers import MissingHSTSRule

from tests.test_scan import SECURE_HEADERS, MockEngine


def _ctx(url="https://app.local/", headers=None, client=None):
    resp = httpx.Response(200, headers=headers or {}, request=httpx.Request("GET", url))
    return ScanContext(base_url=url, client=client or httpx.AsyncClient(), base_response=resp)


# --- Cookies ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_cookie_rule_flags_missing_attributes_without_leaking_value():
    headers = [("set-cookie", "sessionid=TOPSECRETVALUE; Path=/")]
    findings = await InsecureCookieRule().check(_ctx(headers=headers))
    assert len(findings) == 1
    ev = findings[0].evidence
    assert "'sessionid' missing Secure, HttpOnly, SameSite" in ev
    assert "TOPSECRETVALUE" not in ev


@pytest.mark.asyncio
async def test_cookie_rule_accepts_hardened_cookie_and_ignores_secure_on_http():
    good = [("set-cookie", "sid=x; Secure; HttpOnly; SameSite=Lax")]
    assert await InsecureCookieRule().check(_ctx(headers=good)) == []

    http_cookie = [("set-cookie", "sid=x; HttpOnly; SameSite=Strict")]
    assert await InsecureCookieRule().check(_ctx(url="http://app.local/", headers=http_cookie)) == []


@pytest.mark.asyncio
async def test_cookie_rule_samesite_none_requires_secure():
    headers = [("set-cookie", "sid=x; HttpOnly; SameSite=None")]
    findings = await InsecureCookieRule().check(_ctx(url="http://app.local/", headers=headers))
    assert "Secure (required by SameSite=None)" in findings[0].evidence


# --- CORS ------------------------------------------------------------------


def _cors_client(reflect: bool, credentials: bool, allow_null: bool = False):
    def handler(request):
        origin = request.headers.get("origin")
        headers = {}
        if origin and (reflect or (allow_null and origin == "null")):
            headers["access-control-allow-origin"] = origin
            if credentials:
                headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, headers=headers)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reflect", "credentials", "allow_null", "expected"),
    [
        (True, True, False, Severity.HIGH),
        (True, False, False, Severity.MEDIUM),
        (False, True, True, Severity.HIGH),
        (False, False, False, None),
    ],
)
async def test_cors_rule(reflect, credentials, allow_null, expected):
    async with _cors_client(reflect, credentials, allow_null) as client:
        findings = await CorsMisconfigurationRule().check(_ctx(client=client))
    if expected is None:
        assert findings == []
    else:
        assert len(findings) == 1
        assert findings[0].severity == expected


@pytest.mark.asyncio
async def test_cors_wildcard_without_reflection_is_not_flagged():
    def handler(request):
        return httpx.Response(200, headers={"access-control-allow-origin": "*"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await CorsMisconfigurationRule().check(_ctx(client=client)) == []
    assert PROBE_ORIGIN.endswith(".invalid")


# --- HSTS on plain HTTP ----------------------------------------------------


@pytest.mark.asyncio
async def test_hsts_missing_is_info_on_http_and_high_on_https():
    http_findings = await MissingHSTSRule().check(_ctx(url="http://app.local/"))
    https_findings = await MissingHSTSRule().check(_ctx(url="https://app.local/"))
    assert http_findings[0].severity == Severity.INFO
    assert https_findings[0].severity == Severity.HIGH


# --- Engine: rule errors and exclusions ------------------------------------


class ExplodingRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="exploding-rule",
            severity=Severity.HIGH,
            category=Category.MISCONFIGURATION,
            title="Exploding",
            description="boom",
            remediation=Remediation(guidance="none"),
        )

    async def check(self, context):
        raise RuntimeError("boom")


def _site(request):
    if request.url.path == "/":
        return httpx.Response(200, headers=SECURE_HEADERS, text="<html></html>")
    return httpx.Response(404, text="nope")


@pytest.mark.asyncio
async def test_failing_rule_is_reported_not_swallowed():
    registry = RuleRegistry()
    registry.register(ExplodingRule())
    report = await MockEngine(_site, registry=registry).scan("https://example.test")
    assert [e.rule_id for e in report.errors] == ["exploding-rule"]
    assert "RuntimeError: boom" in report.errors[0].message
    assert report.summary.status == "completed_with_errors"
    assert json.loads(JsonReporter().render(report))["errors"][0]["rule_id"] == "exploding-rule"


@pytest.mark.asyncio
async def test_excluded_rules_do_not_run():
    def bare(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    report = await MockEngine(bare, exclude_rules={"missing-csp-header"}).scan("https://example.test")
    ids = {f.rule_id for f in report.findings}
    assert "missing-csp-header" not in ids
    assert "missing-x-frame-options" in ids


# --- SARIF -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_sarif_report_structure():
    def bare(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    report = await MockEngine(bare).scan("https://example.test")
    sarif = json.loads(SarifReporter().render(report))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert len(run["results"]) == len(report.findings)
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")
    csp = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "missing-csp-header")
    assert csp["properties"]["security-severity"] == "8.0"
    assert "```nginx" in csp["help"]["markdown"]


# --- Baseline --------------------------------------------------------------


@pytest.mark.asyncio
async def test_baseline_roundtrip_suppresses_known_findings(tmp_path):
    def bare(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    first = await MockEngine(bare).scan("https://staging.example.test")
    baseline_file = tmp_path / "baseline.json"
    JsonReporter().render(first, destination=str(baseline_file))

    # Same paths on a different host must still match (fingerprints are host-independent).
    second = await MockEngine(bare).scan("https://prod.example.test")
    total = len(second.findings)
    apply_baseline(second, load_baseline(baseline_file))
    assert second.findings == []
    assert second.suppressed_count == total
    assert second.summary.total_findings == 0
    assert sum(second.summary.counts_by_severity.values()) == 0


def test_load_baseline_rejects_non_report(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"foo": 1}')
    with pytest.raises(ConfigError):
        load_baseline(bad)


# --- Config ----------------------------------------------------------------


def test_load_config_validates(tmp_path):
    good = tmp_path / ".patchlint.toml"
    good.write_text('exclude = ["missing-hsts-header"]\nfail_on = "critical"\nbaseline = "b.json"\n')
    cfg = load_config(good)
    assert cfg["fail_on"] == "CRITICAL"
    assert cfg["baseline"].endswith("b.json")

    for body in ('unknown_key = 1\n', 'timeout = true\n', 'fail_on = "nope"\n', 'exclude = [1]\n'):
        bad = tmp_path / "bad.toml"
        bad.write_text(body)
        with pytest.raises(ConfigError):
            load_config(bad)


def test_load_config_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\n\n[tool.patchlint]\nconcurrency = 3\n')
    assert load_config(pyproject) == {"concurrency": 3}


# --- CLI integration -------------------------------------------------------


def _patch_scan(monkeypatch, handler):
    captured = {}
    original_init = AuditEngine.__init__

    def build_client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def init(self, *args, **kwargs):
        captured.update(kwargs)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(AuditEngine, "_build_client", build_client)
    monkeypatch.setattr(AuditEngine, "__init__", init)
    return captured


def _bare(request):
    return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")


def test_cli_rejects_unknown_excluded_rule():
    result = CliRunner().invoke(main, ["https://example.test", "--exclude", "no-such-rule"])
    assert result.exit_code == 3
    assert "no-such-rule" in result.output


def test_cli_config_file_applies_and_cli_overrides(monkeypatch, tmp_path):
    captured = _patch_scan(monkeypatch, _bare)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".patchlint.toml").write_text(
        'exclude = ["missing-csp-header"]\nfail_on = "CRITICAL"\nconcurrency = 2\n'
    )
    result = CliRunner().invoke(
        main, ["https://example.test", "-f", "json", "-c", "7", "-e", "insecure-cookie-flags"]
    )
    assert result.exit_code == 0, result.output  # HIGH findings remain, but fail_on is CRITICAL
    assert captured["concurrency"] == 7
    assert captured["exclude_rules"] == {"missing-csp-header", "insecure-cookie-flags"}
    data = json.loads(result.stdout)
    assert "missing-csp-header" not in {f["rule_id"] for f in data["findings"]}


def test_cli_infers_sarif_from_extension_and_applies_baseline(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, _bare)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    first = runner.invoke(main, ["https://example.test", "-o", "base.json", "--no-config"])
    assert first.exit_code == 1
    second = runner.invoke(main, ["https://example.test", "-o", "out.sarif", "--baseline", "base.json"])
    assert second.exit_code == 0, second.output
    sarif = json.loads((tmp_path / "out.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
