"""Security rules for HTTP Response Headers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from patchlint.models import Category, Remediation, RemediationExample, Severity
from patchlint.rules.base import HeaderRule


class MissingCSPRule(HeaderRule):
    """Checks for Content-Security-Policy header."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="missing-csp-header",
            severity=Severity.HIGH,
            category=Category.SECURITY_HEADERS,
            title="Missing Content-Security-Policy (CSP)",
            description=(
                "Content-Security-Policy (CSP) header is not set. CSP prevents Cross-Site "
                "Scripting (XSS), clickjacking, and arbitrary code injection by restricting "
                "trusted sources for scripts, styles, images, and other sub-resources."
            ),
            remediation=Remediation(
                guidance=(
                    "Define a strict Content-Security-Policy header. Start with a baseline policy "
                    "restricting resources to 'self', and explicitly allow external domains if necessary."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx Configuration",
                        language="nginx",
                        snippet=(
                            '# Add to server {} or location {} block:\n'
                            'add_header Content-Security-Policy "default-src \'self\'; '
                            'script-src \'self\'; style-src \'self\'; img-src \'self\' data:; '
                            'font-src \'self\'; connect-src \'self\'; frame-ancestors \'none\'; '
                            'form-action \'self\';" always;'
                        ),
                    ),
                    RemediationExample(
                        title="Apache (.htaccess / httpd.conf)",
                        language="apache",
                        snippet=(
                            '<IfModule mod_headers.c>\n'
                            '    Header always set Content-Security-Policy "default-src \'self\'; '
                            'script-src \'self\'; style-src \'self\'; frame-ancestors \'none\';"\n'
                            '</IfModule>'
                        ),
                    ),
                    RemediationExample(
                        title="Express.js (Node.js Helmet)",
                        language="javascript",
                        snippet=(
                            "const helmet = require('helmet');\n"
                            "app.use(helmet.contentSecurityPolicy({\n"
                            "    directives: {\n"
                            "        defaultSrc: [\"'self'\"],\n"
                            "        scriptSrc: [\"'self'\"],\n"
                            "        frameAncestors: [\"'none'\"]\n"
                            "    }\n"
                            "}));"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-secure-headers/#content-security-policy",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                ],
            ),
            target_header="content-security-policy",
            tags=["headers", "xss", "csp"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        csp = headers.get("content-security-policy")
        if not csp:
            return True, "Header 'Content-Security-Policy' is absent in HTTP response."
        if "unsafe-inline" in csp and "nonce-" not in csp and "sha256-" not in csp:
            return (
                True,
                f"Content-Security-Policy contains weak directive 'unsafe-inline' without nonces/hashes: '{csp}'",
            )
        return False, ""


class MissingHSTSRule(HeaderRule):
    """Checks for Strict-Transport-Security header."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="missing-hsts-header",
            severity=Severity.HIGH,
            category=Category.SECURITY_HEADERS,
            title="Missing Strict-Transport-Security (HSTS)",
            description=(
                "HTTP Strict Transport Security (HSTS) informs browsers that the site must only "
                "be accessed using HTTPS. Without HSTS, applications are vulnerable to SSL-stripping "
                "and Man-in-the-Middle (MitM) attacks."
            ),
            remediation=Remediation(
                guidance=(
                    "Enforce HSTS with a long max-age (at least 1 year = 31536000 seconds), "
                    "include subdomains, and consider preloading."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx Configuration",
                        language="nginx",
                        snippet=(
                            '# Add to your HTTPS server {} block:\n'
                            'add_header Strict-Transport-Security '
                            '"max-age=31536000; includeSubDomains; preload" always;'
                        ),
                    ),
                    RemediationExample(
                        title="Apache Configuration",
                        language="apache",
                        snippet=(
                            '<IfModule mod_headers.c>\n'
                            '    Header always set Strict-Transport-Security '
                            '"max-age=31536000; includeSubDomains; preload"\n'
                            '</IfModule>'
                        ),
                    ),
                    RemediationExample(
                        title="FastAPI / Starlette Middleware",
                        language="python",
                        snippet=(
                            "from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware\n"
                            "# Redirect all HTTP traffic to HTTPS, then set headers via reverse proxy or middleware\n"
                            "app.add_middleware(HTTPSRedirectMiddleware)"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-secure-headers/#strict-transport-security",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ],
            ),
            target_header="strict-transport-security",
            tags=["headers", "hsts", "ssl"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        hsts = headers.get("strict-transport-security")
        is_https = response.url.scheme == "https"

        if not hsts:
            protocol_hint = " (Site is served over HTTPS)" if is_https else " (Target is HTTP, but HSTS must be configured on HTTPS)"
            return True, f"Header 'Strict-Transport-Security' is absent.{protocol_hint}"

        # Check for weak max-age
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            if max_age < 15768000:  # 6 months
                return True, f"HSTS max-age is lower than recommended 6 months ({max_age}s): '{hsts}'"
        return False, ""


class MissingXFrameOptionsRule(HeaderRule):
    """Checks for X-Frame-Options or frame-ancestors CSP directive."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="missing-x-frame-options",
            severity=Severity.MEDIUM,
            category=Category.SECURITY_HEADERS,
            title="Missing X-Frame-Options (Clickjacking Protection)",
            description=(
                "X-Frame-Options header (or CSP frame-ancestors) is missing. This allows "
                "malicious websites to frame your site in an <iframe> and trick users into "
                "clicking hidden buttons or entering sensitive data (Clickjacking)."
            ),
            remediation=Remediation(
                guidance=(
                    "Configure X-Frame-Options to DENY or SAMEORIGIN, or specify frame-ancestors in CSP."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx Configuration",
                        language="nginx",
                        snippet=(
                            '# Disallow framing completely:\n'
                            'add_header X-Frame-Options "DENY" always;\n'
                            '# OR allow only same origin:\n'
                            '# add_header X-Frame-Options "SAMEORIGIN" always;'
                        ),
                    ),
                    RemediationExample(
                        title="Apache (.htaccess)",
                        language="apache",
                        snippet=(
                            '<IfModule mod_headers.c>\n'
                            '    Header always append X-Frame-Options "SAMEORIGIN"\n'
                            '</IfModule>'
                        ),
                    ),
                    RemediationExample(
                        title="Django (settings.py)",
                        language="python",
                        snippet=(
                            "# Django enables this by default via CommonMiddleware:\n"
                            "X_FRAME_OPTIONS = 'DENY'"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ],
            ),
            target_header="x-frame-options",
            tags=["headers", "clickjacking"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")

        # If CSP has frame-ancestors, XFO is superseded
        if "frame-ancestors" in csp.lower():
            return False, ""

        if not xfo:
            return (
                True,
                "Neither 'X-Frame-Options' header nor CSP 'frame-ancestors' directive is configured.",
            )

        val = xfo.strip().upper()
        if val not in ("DENY", "SAMEORIGIN"):
            return (
                True,
                f"X-Frame-Options has non-standard or deprecated value: '{xfo}' (Use DENY or SAMEORIGIN).",
            )
        return False, ""


class MissingXContentTypeOptionsRule(HeaderRule):
    """Checks for X-Content-Type-Options: nosniff."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="missing-x-content-type-options",
            severity=Severity.LOW,
            category=Category.SECURITY_HEADERS,
            title="Missing X-Content-Type-Options: nosniff",
            description=(
                "The X-Content-Type-Options header is absent or not set to 'nosniff'. "
                "This allows older browsers and certain HTTP clients to execute MIME-type sniffing, "
                "potentially interpreting uploaded text or media files as executable JavaScript (XSS)."
            ),
            remediation=Remediation(
                guidance="Set X-Content-Type-Options to 'nosniff' for all HTTP responses.",
                examples=[
                    RemediationExample(
                        title="Nginx Configuration",
                        language="nginx",
                        snippet='add_header X-Content-Type-Options "nosniff" always;',
                    ),
                    RemediationExample(
                        title="Apache (.htaccess)",
                        language="apache",
                        snippet=(
                            '<IfModule mod_headers.c>\n'
                            '    Header always set X-Content-Type-Options "nosniff"\n'
                            '</IfModule>'
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-secure-headers/#x-content-type-options",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                ],
            ),
            target_header="x-content-type-options",
            tags=["headers", "mime"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        val = headers.get("x-content-type-options")
        if not val:
            return True, "Header 'X-Content-Type-Options' is absent."
        if val.strip().lower() != "nosniff":
            return True, f"Header 'X-Content-Type-Options' is '{val}', expected 'nosniff'."
        return False, ""


class MissingReferrerPolicyRule(HeaderRule):
    """Checks for Referrer-Policy header."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="missing-referrer-policy",
            severity=Severity.LOW,
            category=Category.SECURITY_HEADERS,
            title="Missing Referrer-Policy Header",
            description=(
                "The Referrer-Policy header is missing. The browser might leak private path parameters, "
                "session tokens, or sensitive IDs in the HTTP 'Referer' header when navigating to "
                "external third-party links."
            ),
            remediation=Remediation(
                guidance=(
                    "Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer' "
                    "to prevent leaking private query parameters."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx Configuration",
                        language="nginx",
                        snippet='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
                    ),
                    RemediationExample(
                        title="Apache (.htaccess)",
                        language="apache",
                        snippet=(
                            '<IfModule mod_headers.c>\n'
                            '    Header always set Referrer-Policy "strict-origin-when-cross-origin"\n'
                            '</IfModule>'
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-secure-headers/#referrer-policy",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                ],
            ),
            target_header="referrer-policy",
            tags=["headers", "privacy"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        policy = headers.get("referrer-policy")
        if not policy:
            return True, "Header 'Referrer-Policy' is absent."
        weak_policies = ("unsafe-url", "no-referrer-when-downgrade")
        if policy.strip().lower() in weak_policies:
            return True, f"Referrer-Policy is using insecure value '{policy}'."
        return False, ""


class ServerVersionDisclosureRule(HeaderRule):
    """Checks for detailed server version disclosure in Server header."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="server-version-disclosure",
            severity=Severity.LOW,
            category=Category.INFORMATION_DISCLOSURE,
            title="Server Version Information Disclosure",
            description=(
                "The 'Server' response header reveals precise web server software and version numbers. "
                "Attackers use this banner information to target known CVE vulnerabilities."
            ),
            remediation=Remediation(
                guidance="Disable detailed server banners and OS version strings in the web server configuration.",
                examples=[
                    RemediationExample(
                        title="Nginx (nginx.conf)",
                        language="nginx",
                        snippet=(
                            "# In http {} block:\n"
                            "server_tokens off;"
                        ),
                    ),
                    RemediationExample(
                        title="Apache (httpd.conf)",
                        language="apache",
                        snippet=(
                            "ServerTokens Prod\n"
                            "ServerSignature Off"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
            ),
            target_header="server",
            tags=["headers", "fingerprinting", "info-disclosure"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        server = headers.get("server")
        if not server:
            return False, ""

        # Check for presence of numbers/versions (e.g., nginx/1.18.0, Apache/2.4.41)
        if re.search(r"/\d+(\.\d+)*", server) or re.search(r"\(\w+\)", server):
            return (
                True,
                f"Server header exposes software and version details: '{server}'",
            )
        return False, ""


class XPoweredByDisclosureRule(HeaderRule):
    """Checks for X-Powered-By technology disclosure header."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="technology-disclosure-header",
            severity=Severity.LOW,
            category=Category.INFORMATION_DISCLOSURE,
            title="Technology Disclosure (X-Powered-By Header)",
            description=(
                "The 'X-Powered-By' header discloses backend framework and language runtimes "
                "(e.g., Express, PHP/8.1, Next.js, ASP.NET). This provides attackers with "
                "fingerprinting intelligence to craft targeted exploits."
            ),
            remediation=Remediation(
                guidance=(
                    "Strip the X-Powered-By header at the application layer or reverse proxy."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx Reverse Proxy",
                        language="nginx",
                        snippet=(
                            "# Strip backend headers in location / {} block:\n"
                            "proxy_hide_header X-Powered-By;\n"
                            "fastcgi_hide_header X-Powered-By;"
                        ),
                    ),
                    RemediationExample(
                        title="PHP (php.ini)",
                        language="ini",
                        snippet="expose_php = Off",
                    ),
                    RemediationExample(
                        title="Express.js (Node.js)",
                        language="javascript",
                        snippet="app.disable('x-powered-by');",
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                ],
            ),
            target_header="x-powered-by",
            tags=["headers", "fingerprinting", "info-disclosure"],
        )

    def evaluate_headers(
        self, headers: httpx.Headers, response: httpx.Response
    ) -> tuple[bool, str]:
        xpb = headers.get("x-powered-by")
        if xpb:
            return True, f"X-Powered-By header reveals backend technology: '{xpb}'"
        return False, ""
