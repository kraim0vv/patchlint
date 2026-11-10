"""Security rules for session cookie attributes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from patchlint.models import Category, Remediation, RemediationExample, Severity
from patchlint.rules.base import HeaderRule


def parse_set_cookie(header_value: str) -> tuple[str, dict[str, str]]:
    """Return the cookie name and its lower-cased attributes (the value is deliberately discarded)."""
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip().lower()
    return name, attrs


class InsecureCookieRule(HeaderRule):
    """Checks Set-Cookie headers for missing Secure, HttpOnly and SameSite attributes."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="insecure-cookie-flags",
            severity=Severity.MEDIUM,
            category=Category.MISCONFIGURATION,
            title="Cookies Without Secure / HttpOnly / SameSite",
            description=(
                "One or more cookies are set without recommended security attributes. "
                "Missing HttpOnly lets injected scripts steal session cookies (XSS), missing Secure "
                "allows cookies to leak over plain HTTP, and missing SameSite weakens CSRF protection."
            ),
            remediation=Remediation(
                guidance=(
                    "Set session and authentication cookies with 'Secure; HttpOnly; SameSite=Lax' "
                    "(or 'Strict'). Only cookies that JavaScript must read (e.g. a CSRF token) may "
                    "omit HttpOnly. 'SameSite=None' always requires 'Secure'."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: enforce flags on proxied cookies (1.19.3+)",
                        language="nginx",
                        snippet="proxy_cookie_flags ~ secure httponly samesite=lax;",
                    ),
                    RemediationExample(
                        title="Apache: append flags to all Set-Cookie headers",
                        language="apache",
                        snippet=(
                            "<IfModule mod_headers.c>\n"
                            '    Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"\n'
                            "</IfModule>"
                        ),
                    ),
                    RemediationExample(
                        title="Express.js (express-session)",
                        language="javascript",
                        snippet=(
                            "app.use(session({\n"
                            "  secret: process.env.SESSION_SECRET,\n"
                            "  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },\n"
                            "}));"
                        ),
                    ),
                    RemediationExample(
                        title="Django (settings.py)",
                        language="python",
                        snippet=(
                            "SESSION_COOKIE_SECURE = True\n"
                            "SESSION_COOKIE_HTTPONLY = True\n"
                            "SESSION_COOKIE_SAMESITE = 'Lax'\n"
                            "CSRF_COOKIE_SECURE = True"
                        ),
                    ),
                    RemediationExample(
                        title="Flask",
                        language="python",
                        snippet=(
                            "app.config.update(\n"
                            "    SESSION_COOKIE_SECURE=True,\n"
                            "    SESSION_COOKIE_HTTPONLY=True,\n"
                            "    SESSION_COOKIE_SAMESITE='Lax',\n"
                            ")"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                ],
            ),
            target_header="set-cookie",
            tags=["cookies", "session", "xss", "csrf"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        is_https = response.url.scheme == "https"
        problems: list[str] = []
        for raw in headers.get_list("set-cookie"):
            name, attrs = parse_set_cookie(raw)
            if not name:
                continue
            missing: list[str] = []
            # Secure cannot be meaningfully required when the target itself is plain HTTP.
            if is_https and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            samesite = attrs.get("samesite")
            if samesite is None:
                missing.append("SameSite")
            elif samesite == "none" and "secure" not in attrs:
                missing.append("Secure (required by SameSite=None)")
            if missing:
                problems.append(f"'{name}' missing {', '.join(missing)}")

        if problems:
            return True, "Cookie attributes: " + "; ".join(problems)
        return False, ""
