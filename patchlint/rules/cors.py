"""Security rule for permissive Cross-Origin Resource Sharing (CORS) policies."""

from __future__ import annotations

from patchlint.models import Category, Finding, Remediation, RemediationExample, Severity
from patchlint.rules.base import BaseRule, ScanContext

PROBE_ORIGIN = "https://patchlint-cors-probe.invalid"


class CorsMisconfigurationRule(BaseRule):
    """Detects servers that reflect arbitrary or 'null' origins in Access-Control-Allow-Origin."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="cors-misconfiguration",
            severity=Severity.HIGH,
            category=Category.MISCONFIGURATION,
            title="Permissive CORS Policy (Origin Reflection)",
            description=(
                "The server echoes an untrusted Origin back in Access-Control-Allow-Origin. "
                "Combined with Access-Control-Allow-Credentials: true, any website can make "
                "authenticated requests on behalf of a logged-in user and read the responses."
            ),
            remediation=Remediation(
                guidance=(
                    "Validate the Origin header against an explicit allowlist of trusted origins. "
                    "Never reflect arbitrary origins or allow 'null' when credentials are enabled."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: allowlist via map",
                        language="nginx",
                        snippet=(
                            "# In the http {} block:\n"
                            "map $http_origin $cors_origin {\n"
                            "    default \"\";\n"
                            "    \"https://app.example.com\" $http_origin;\n"
                            "}\n"
                            "# In server {} / location {}:\n"
                            "add_header Access-Control-Allow-Origin $cors_origin always;\n"
                            "add_header Vary Origin always;"
                        ),
                    ),
                    RemediationExample(
                        title="Express.js (cors)",
                        language="javascript",
                        snippet=(
                            "const cors = require('cors');\n"
                            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"
                        ),
                    ),
                    RemediationExample(
                        title="FastAPI / Starlette",
                        language="python",
                        snippet=(
                            "from fastapi.middleware.cors import CORSMiddleware\n"
                            "app.add_middleware(\n"
                            "    CORSMiddleware,\n"
                            "    allow_origins=['https://app.example.com'],\n"
                            "    allow_credentials=True,\n"
                            ")"
                        ),
                    ),
                    RemediationExample(
                        title="Django (django-cors-headers)",
                        language="python",
                        snippet=(
                            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
                            "CORS_ALLOW_ALL_ORIGINS = False"
                        ),
                    ),
                ],
                references=[
                    "https://portswigger.net/web-security/cors",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    "https://cwe.mitre.org/data/definitions/942.html",
                ],
            ),
            tags=["cors", "misconfiguration"],
        )

    async def check(self, context: ScanContext) -> list[Finding]:
        url = context.base_url
        worst: tuple[Severity, str, int] | None = None
        for origin in (PROBE_ORIGIN, "null"):
            try:
                context.increment_request_count()
                resp = await context.client.get(url, headers={"Origin": origin}, follow_redirects=False)
            except Exception:
                continue

            acao = resp.headers.get("access-control-allow-origin", "").strip()
            credentials = resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
            if acao != origin:
                continue

            severity = Severity.HIGH if credentials else Severity.MEDIUM
            evidence = (
                f"Request with 'Origin: {origin}' was answered with "
                f"'Access-Control-Allow-Origin: {acao}'"
                + (" and 'Access-Control-Allow-Credentials: true'." if credentials else ".")
            )
            if worst is None or severity.rank > worst[0].rank:
                worst = (severity, evidence, resp.status_code)

        if worst is None:
            return []
        severity, evidence, status = worst
        return [
            self.create_finding(url=url, evidence=evidence, response_status=status, severity=severity)
        ]
