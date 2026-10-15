"""Security rules for Information Disclosure, Exposed Files, and Debug Mode."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from patchlint.models import Category, Finding, Remediation, RemediationExample, Severity
from patchlint.rules.base import BaseRule, MultiPathExposureRule, PathExposureRule, ScanContext


class ExposedEnvFileRule(PathExposureRule):
    """Detects exposed environment files containing secrets (/.env)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-env-file",
            severity=Severity.CRITICAL,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed Environment File (/.env)",
            description=(
                "The application's environment configuration file (/.env) is publicly accessible. "
                "This typically leaks database credentials, API keys, encryption secrets, "
                "and private tokens, allowing complete compromise of the application and underlying infrastructure."
            ),
            remediation=Remediation(
                guidance=(
                    "1. Immediately rotate all leaked credentials (database passwords, API keys, tokens).\n"
                    "2. Store .env files outside of the web server document root.\n"
                    "3. Configure the web server to deny access to all hidden files and dotfiles."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: Deny All Hidden Files",
                        language="nginx",
                        snippet=(
                            "# Add inside your server {} block:\n"
                            "location ~ /\\.(?!well-known).* {\n"
                            "    deny all;\n"
                            "    access_log off;\n"
                            "    log_not_found off;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                    RemediationExample(
                        title="Apache: Block .env and Hidden Files (.htaccess)",
                        language="apache",
                        snippet=(
                            "<FilesMatch \"^\\.env\">\n"
                            "    Require all denied\n"
                            "</FilesMatch>\n"
                            "\n"
                            "# Block all hidden files:\n"
                            "<FilesMatch \"^\\.\">\n"
                            "    Require all denied\n"
                            "</FilesMatch>"
                        ),
                    ),
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/552.html",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                ],
            ),
            path="/.env",
            expected_status=(200,),
            signature_regexes=[
                re.compile(
                    r"(?i)\b(DB_(PASSWORD|HOST|USERNAME)|APP_KEY|SECRET_KEY|DATABASE_URL|API_KEY|JWT_SECRET|AWS_SECRET)\s*=",
                    re.MULTILINE,
                ),
                re.compile(r"^[A-Z0-9_]{3,}\s*=\s*['\"]?[^\r\n]+", re.MULTILINE),
            ],
            disallowed_content_types=["text/html"],
            tags=["exposure", "credentials", "env", "critical"],
        )


class ExposedGitDirectoryRule(PathExposureRule):
    """Detects exposed Git repository directory (/.git/HEAD)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-git-directory",
            severity=Severity.CRITICAL,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed Git Repository (/.git/HEAD)",
            description=(
                "The Git version control directory (/.git) is publicly accessible via the web root. "
                "Attackers can download the entire source code repository, including commit history, "
                "unreleased features, comments, and hardcoded credentials using tools like git-dumper."
            ),
            remediation=Remediation(
                guidance=(
                    "1. Never copy the .git directory to production deployment targets (use CI/CD artifacts or .dockerignore).\n"
                    "2. Configure the web server to immediately block access to .git and all dotfiles."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: Deny .git directory",
                        language="nginx",
                        snippet=(
                            "# Deny access to .git and its contents:\n"
                            "location ~ /\\.git {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                    RemediationExample(
                        title="Apache: Deny .git directory",
                        language="apache",
                        snippet=(
                            "<DirectoryMatch \"/\\.git\">\n"
                            "    Require all denied\n"
                            "</DirectoryMatch>"
                        ),
                    ),
                    RemediationExample(
                        title=".dockerignore: Exclude .git",
                        language="dockerfile",
                        snippet=(
                            "# In your project root .dockerignore:\n"
                            ".git\n"
                            ".gitignore\n"
                            ".env"
                        ),
                    ),
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/527.html",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                ],
            ),
            path="/.git/HEAD",
            expected_status=(200,),
            signature_regexes=[
                re.compile(r"^ref:\s+refs/heads/", re.MULTILINE),
                re.compile(r"^[0-9a-f]{40}\s*$", re.MULTILINE),
            ],
            disallowed_content_types=["text/html"],
            tags=["exposure", "git", "source-code", "critical"],
        )


class ExposedDockerComposeRule(PathExposureRule):
    """Detects exposed docker-compose configuration file."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-docker-compose",
            severity=Severity.HIGH,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed Docker Compose File (/docker-compose.yml)",
            description=(
                "The docker-compose configuration file is accessible via HTTP. This reveals internal "
                "container architectures, environment variables, linked databases, open ports, "
                "and private network service names."
            ),
            remediation=Remediation(
                guidance=(
                    "Do not publish orchestration manifests in the web root. Keep docker-compose.yml "
                    "in the server administration tree outside the publicly served web folder."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: Block YAML configuration files",
                        language="nginx",
                        snippet=(
                            "location ~* \\.(ya?ml|json|conf|ini|toml)$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                    RemediationExample(
                        title="Apache: Block YAML files",
                        language="apache",
                        snippet=(
                            "<FilesMatch \"\\.(ya?ml)$\">\n"
                            "    Require all denied\n"
                            "</FilesMatch>"
                        ),
                    ),
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            ),
            path="/docker-compose.yml",
            expected_status=(200,),
            signature_regexes=[
                re.compile(r"(?m)^\s*services:\s*$"),
                re.compile(r"(?m)^\s*version:\s*['\"]?[0-9]"),
            ],
            disallowed_content_types=["text/html"],
            tags=["exposure", "docker", "devops"],
        )


class ExposedConfigJsonRule(PathExposureRule):
    """Detects exposed config.json file."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-config-json",
            severity=Severity.HIGH,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed Configuration File (/config.json)",
            description=(
                "A configuration file (/config.json) containing internal application settings "
                "or secrets is publicly reachable."
            ),
            remediation=Remediation(
                guidance=(
                    "Move internal JSON configuration files outside the web directory. "
                    "For frontend build outputs, verify that sensitive server variables are not bundled."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: Block sensitive json paths",
                        language="nginx",
                        snippet=(
                            "location ~* /(config|settings|database)\\.json$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            ),
            path="/config.json",
            expected_status=(200,),
            signature_regexes=[
                re.compile(
                    r"(?i)\"(database|db|password|secret|api_key|token|connectionString|auth)\"\s*:",
                    re.MULTILINE,
                ),
            ],
            disallowed_content_types=["text/html"],
            tags=["exposure", "config", "json"],
        )


class ExposedDatabaseDumpRule(PathExposureRule):
    """Detects exposed database SQL dump files (/dump.sql)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-database-dump",
            severity=Severity.CRITICAL,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed Database Dump (/dump.sql)",
            description=(
                "A database SQL backup or dump file is publicly downloadable. This allows anyone "
                "to inspect schemas, administrative records, passwords hashes, and private customer data."
            ),
            remediation=Remediation(
                guidance=(
                    "1. Delete all database dump files from the web root immediately.\n"
                    "2. Store database backups in a dedicated, access-controlled private storage bucket or directory.\n"
                    "3. Configure web server rules to deny access to .sql, .dump, and .tar.gz archives."
                ),
                examples=[
                    RemediationExample(
                        title="Nginx: Block SQL and Backup Files",
                        language="nginx",
                        snippet=(
                            "location ~* \\.(sql|dump|bak|backup|tar\\.gz|zip)$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                    RemediationExample(
                        title="Apache: Block SQL Dumps",
                        language="apache",
                        snippet=(
                            "<FilesMatch \"\\.(sql|dump|bak)$\">\n"
                            "    Require all denied\n"
                            "</FilesMatch>"
                        ),
                    ),
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/538.html",
                ],
            ),
            path="/dump.sql",
            expected_status=(200,),
            signature_regexes=[
                re.compile(r"(?i)\b(INSERT\s+INTO|CREATE\s+TABLE|CREATE\s+DATABASE)\b"),
                re.compile(r"(?i)(MySQL\s+dump|PostgreSQL\s+database\s+dump|SQLite\s+format)"),
            ],
            disallowed_content_types=["text/html"],
            tags=["exposure", "database", "dump", "critical"],
        )


class DebugModeRule(BaseRule):
    """Checks for active framework debug mode and stack traces."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="debug-mode-enabled",
            severity=Severity.HIGH,
            category=Category.MISCONFIGURATION,
            title="Application Debug Mode Enabled",
            description=(
                "The application appears to run in debug or development mode. "
                "Interactive debuggers (like Werkzeug, Django Debug, Laravel Ignition) leak "
                "full environment variables, database queries, source code snippets, and in some "
                "cases allow Remote Code Execution (RCE) via interactive consoles."
            ),
            remediation=Remediation(
                guidance=(
                    "Disable debug mode in production. Ensure DEBUG=False in Django/Flask, "
                    "APP_DEBUG=false in Laravel, and NODE_ENV=production in Node.js."
                ),
                examples=[
                    RemediationExample(
                        title="Django (settings.py / .env)",
                        language="python",
                        snippet=(
                            "# In production settings or environment variable:\n"
                            "DEBUG = False\n"
                            "ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']"
                        ),
                    ),
                    RemediationExample(
                        title="Flask (app.py / environment)",
                        language="python",
                        snippet=(
                            "# Set environment variable before starting:\n"
                            "# FLASK_ENV=production\n"
                            "app.run(debug=False)"
                        ),
                    ),
                    RemediationExample(
                        title="Laravel (.env)",
                        language="ini",
                        snippet=(
                            "APP_ENV=production\n"
                            "APP_DEBUG=false"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling",
                    "https://cwe.mitre.org/data/definitions/215.html",
                ],
            ),
            tags=["misconfiguration", "debug", "rce-risk"],
        )

        self._debug_signatures = [
            (re.compile(r"Werkzeug Powered Traceback", re.I), "Werkzeug Debug Console"),
            (
                re.compile(
                    r"You're seeing this error because you have <code>DEBUG = True</code>",
                    re.I,
                ),
                "Django Debug Page",
            ),
            (re.compile(r"Whoops! There was an error\.", re.I), "Laravel Whoops Debugger"),
            (re.compile(r"ignition-ui", re.I), "Laravel Ignition Debugger"),
            (
                re.compile(r"Traceback \(most recent call last\):", re.I),
                "Python Stack Trace",
            ),
            (
                re.compile(r"Fatal error:.*in <b>.*</b> on line <b>\d+</b>", re.I),
                "PHP Error Display",
            ),
            (
                re.compile(
                    r"Whitelabel Error Page.*This application has no explicit mapping for /error",
                    re.I | re.DOTALL,
                ),
                "Spring Boot Whitelabel Error Page",
            ),
        ]

    async def check(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # Check 1: baseline response text
        if context.base_response:
            matched = self._match_signatures(context.base_response.text)
            if matched:
                findings.append(
                    self.create_finding(
                        url=str(context.base_response.url),
                        evidence=f"Baseline response contains debug signature: {matched}",
                        response_status=context.base_response.status_code,
                    )
                )
                return findings

        # Check 2: probe a deliberately invalid endpoint that triggers standard error handlers
        probe_path = context.base_url.rstrip("/") + "/_patchlint_debug_probe_404_test"
        try:
            context.increment_request_count()
            resp = await context.client.get(probe_path, follow_redirects=False)
            matched = self._match_signatures(resp.text)
            if matched:
                findings.append(
                    self.create_finding(
                        url=probe_path,
                        evidence=f"Error response contains active debug output: {matched}",
                        response_status=resp.status_code,
                    )
                )
        except Exception:
            pass

        return findings

    def _match_signatures(self, text: str) -> str | None:
        for pattern, name in self._debug_signatures:
            if pattern.search(text):
                return name
        return None


class ExposedSwaggerJsonRule(MultiPathExposureRule):
    """Detects publicly accessible OpenAPI / Swagger specification files.

    Probes multiple common paths and validates that the response is genuine
    JSON (not an HTML SPA fallback) before reporting.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="exposed-swagger-spec",
            severity=Severity.LOW,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed OpenAPI/Swagger Specification",
            description=(
                "An OpenAPI or Swagger JSON specification file is publicly accessible. "
                "This reveals all API endpoints, request/response schemas, authentication "
                "requirements, and internal data models to potential attackers, enabling "
                "targeted exploitation of undocumented or administrative routes."
            ),
            remediation=Remediation(
                guidance=(
                    "Restrict access to API specification files in production. "
                    "Disable automatic documentation endpoints or place them behind authentication."
                ),
                examples=[
                    RemediationExample(
                        title="FastAPI: Disable docs in production",
                        language="python",
                        snippet=(
                            "import os\n"
                            "from fastapi import FastAPI\n"
                            "\n"
                            "is_production = os.getenv('ENV') == 'production'\n"
                            "app = FastAPI(\n"
                            "    docs_url=None if is_production else '/docs',\n"
                            "    redoc_url=None if is_production else '/redoc',\n"
                            "    openapi_url=None if is_production else '/openapi.json',\n"
                            ")"
                        ),
                    ),
                    RemediationExample(
                        title="Nginx: Block Swagger/OpenAPI paths",
                        language="nginx",
                        snippet=(
                            "location ~* /(openapi|swagger)\\.(json|yaml)$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}\n"
                            "location ~* /v[0-9]+/api-docs$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                    ),
                    RemediationExample(
                        title="Spring Boot: Disable Swagger UI in production (application.yml)",
                        language="yaml",
                        snippet=(
                            "springdoc:\n"
                            "  api-docs:\n"
                            "    enabled: false\n"
                            "  swagger-ui:\n"
                            "    enabled: false"
                        ),
                    ),
                ],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            ),
            paths=[
                "/openapi.json",
                "/swagger.json",
                "/api/openapi.json",
                "/v2/api-docs",
            ],
            expected_status=(200,),
            allowed_content_types=["application/json", "application/yaml", "text/yaml"],
            require_json_body=True,
            signature_strings=['"openapi":', '"swagger":'],
            tags=["exposure", "swagger", "openapi", "api-docs"],
        )
