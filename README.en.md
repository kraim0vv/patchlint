# PatchLint - Security linter that gives copy-paste remediation configs for Nginx, Apache & frameworks

PatchLint is an asynchronous dynamic application security testing (DAST) utility and security linter designed for local auditing of web applications.

Unlike traditional scanners that merely flag issues, PatchLint focuses on actionable remediation, providing ready-to-use configuration snippets for Nginx, Apache, Express.js, Django, Flask, and FastAPI.

Language versions:
- [English version (README.en.md)](README.en.md)
- [Russian version (README.ru.md)](README.ru.md)

---

## Key Features

- Asynchronous network stack (httpx):
  - High performance via concurrent request execution and connection pooling (httpx.Limits).
  - Configurable timeouts and concurrency controls (--concurrency).
  - Support for --insecure (-k) mode for local self-signed SSL/TLS certificates (https://localhost).
  - Resilient error handling covering timeouts, connection resets, and DNS resolution failures (getaddrinfo failed).
- False Positive Mitigation:
  - Automatic detection of Single Page Application (SPA) wildcard routing (when React, Vue, or Angular returns HTTP 200 with index.html for any requested path).
  - Content-Type header verification (application/json, application/yaml) and JSON parsing validation.
  - Content signature verification (validating Git commit hash structures in /.git/HEAD and KEY=VALUE syntax in /.env), rather than relying purely on HTTP status codes.
- Informative terminal output (rich):
  - Color-coded severity indicators (CRITICAL, HIGH, MEDIUM, LOW, INFO).
  - Real-time progress bar with an interactive spinner.
  - Summary metrics tables and syntax-highlighted remediation configuration blocks.
- Report Export (JSON and HTML):
  - JSON (--format json -o report.json): Structured machine-readable schema for CI/CD integration (GitHub Actions, GitLab CI).
  - HTML (--format html -o report.html): Standalone interactive dashboard (zero external CDN dependencies, works fully offline) featuring severity filters, instant search, and one-click copy buttons for configuration snippets.
- Modular Rule-Based Architecture:
  - Clean separation of inspection logic from the execution engine.
  - Easily extendable with custom detection rules in a few lines of code.

---

## Project Structure

```text
d:\webchec\
├── patchlint\
│   ├── __init__.py           # Package exports for core engine and models
│   ├── __main__.py           # Entrypoint for python -m patchlint
│   ├── cli.py                # Command-line interface (Click + Rich)
│   ├── engine.py             # Asynchronous DAST engine using HTTPX
│   ├── models.py             # Data models (Severity, Finding, Remediation, ScanReport)
│   ├── reporter.py           # Report dispatchers (Terminal, JSON, HTML)
│   ├── rules\
│   │   ├── __init__.py       # Central rule registry (RuleRegistry)
│   │   ├── base.py           # Base abstractions (BaseRule, HeaderRule, PathExposureRule, MultiPathExposureRule)
│   │   ├── headers.py        # Security header rules (CSP, HSTS, XFO, MIME, Referrer, Server, XPB)
│   │   └── exposure.py       # File leak rules (/.env, /.git, config, dump, openapi) and Debug Mode
│   └── templates\
│       ├── __init__.py
│       └── report_template.html  # Standalone interactive HTML report template
├── tests\
│   ├── __init__.py
│   ├── test_cli.py           # Tests for CLI exit codes and --fail-on thresholds
│   ├── test_rules.py         # Unit tests for rules and false-positive prevention
│   └── test_engine.py        # Tests for engine execution and report rendering
├── demo_target.py            # Local vulnerable server for rapid testing (standard library)
├── requirements.txt          # Project dependencies
├── pyproject.toml            # Build metadata and console script registration
├── setup.py                  # Package setup script
├── README.md                 # Main documentation file
├── README.en.md              # English documentation
└── README.ru.md              # Russian documentation
```

---

## Installation and Quick Start

### 1. Requirements
- Python 3.10 or higher.

### 2. Environment Setup and Installation
```bash
# Navigate to the project directory
cd d:\webchec

# Create a virtual environment
python -m venv venv

# Activate the virtual environment:
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies:
pip install -r requirements.txt

# Install the CLI in development mode:
pip install -e .
```

---

## Usage Examples

### Basic scan of a local server:
```bash
patchlint http://localhost:8000
# or run directly as a Python module:
python -m patchlint http://localhost:8000
```

### Exporting an interactive HTML report:
```bash
patchlint http://localhost:8000 -f html -o audit_report.html
```

### Exporting to JSON for CI/CD:
```bash
patchlint http://localhost:8000 -f json -o scan_results.json
```

### Scanning HTTPS with a self-signed certificate (--insecure / -k):
```bash
patchlint https://localhost:8443 -k
```

### Inspecting security headers only (skipping file probes):
```bash
patchlint http://localhost:8000 --headers-only
```

### Filtering by minimum severity threshold:
```bash
patchlint http://localhost:8000 -s HIGH
```

### Listing all registered rules:
```bash
patchlint --list-rules
```

---

## Testing with the Built-in Demo Target

The repository includes a lightweight test server (demo_target.py) simulating common developer misconfigurations and sensitive file exposures:
- Missing CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers.
- Information disclosure in Server: Apache/2.4.41 and X-Powered-By: PHP/8.1.0 headers.
- Exposed /.env file containing sample database credentials and secrets.
- Exposed /.git/HEAD file.
- Exposed /docker-compose.yml and /dump.sql files.
- Exposed OpenAPI specification (/openapi.json).
- Active Debug Mode (500 error page exposing Werkzeug traceback signatures).

### Running the demo test:

In your first terminal window:
```bash
python demo_target.py
# Server starts on http://127.0.0.1:8888
```

In your second terminal window:
```bash
patchlint http://127.0.0.1:8888 -f html -o demo_report.html
```

---

## Base Rule Set v1.0

### Category: Security Headers
| Rule ID | Severity | Problem Description |
| :--- | :--- | :--- |
| missing-csp-header | HIGH | Content-Security-Policy is missing. Risk of XSS and data injection. |
| missing-hsts-header | HIGH | Strict-Transport-Security is missing. Risk of MitM and SSL stripping. |
| missing-x-frame-options | MEDIUM | Missing clickjacking protection (framing restrictions). |
| missing-x-content-type-options | LOW | Missing nosniff directive. Risk of browser MIME confusion. |
| missing-referrer-policy | LOW | Missing control over sensitive URL query parameters in Referer headers. |
| server-version-disclosure | LOW | Server header discloses precise software version numbers. |
| technology-disclosure-header | LOW | X-Powered-By header discloses backend runtime and frameworks. |

### Category: Information Disclosure & Exposed Files
| Rule ID | Severity | Problem Description |
| :--- | :--- | :--- |
| exposed-env-file | CRITICAL | The /.env file is accessible and contains secrets or database credentials. |
| exposed-git-directory | CRITICAL | The /.git/HEAD file is reachable, enabling repository extraction. |
| exposed-database-dump | CRITICAL | Database backup file (/dump.sql) is publicly downloadable. |
| exposed-docker-compose | HIGH | Configuration file (/docker-compose.yml) reveals service architecture. |
| exposed-config-json | HIGH | Internal settings file (/config.json) is publicly exposed. |
| exposed-swagger-spec | LOW | OpenAPI/Swagger specification (/openapi.json, /swagger.json, /api/openapi.json, /v2/api-docs) is publicly accessible. |

### Category: Misconfiguration
| Rule ID | Severity | Problem Description |
| :--- | :--- | :--- |
| debug-mode-enabled | HIGH | Application runs in debug mode (Django Debug, Werkzeug Traceback, Laravel Ignition). Risk of RCE. |

---

## Writing a Custom Rule

Creating a new rule is straightforward by subclassing BaseRule, HeaderRule, PathExposureRule, or MultiPathExposureRule:

```python
from patchlint.models import Severity, Category, Remediation, RemediationExample
from patchlint.rules.base import PathExposureRule

class ExposedGraphQLRule(PathExposureRule):
    def __init__(self):
        super().__init__(
            rule_id="exposed-graphql-endpoint",
            severity=Severity.LOW,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed GraphQL Endpoint",
            description="GraphQL endpoint is publicly accessible.",
            remediation=Remediation(
                guidance="Disable GraphQL introspection and playground in production.",
                examples=[
                    RemediationExample(
                        title="FastAPI: Disable GraphQL introspection",
                        language="python",
                        snippet="app.add_route('/graphql', GraphQLApp(schema=schema, introspection=False))"
                    )
                ]
            ),
            path="/graphql",
            signature_strings=['"__schema"', '"IntrospectionQuery"'],
        )
```

Registering the rule in the registry:
```python
from patchlint.rules import RuleRegistry

registry = RuleRegistry()
registry.register(ExposedGraphQLRule())
```

---

## CLI Exit Codes (CI/CD Integration)

- 0: Scan completed successfully, no vulnerabilities found exceeding the --fail-on threshold.
- 1: Vulnerabilities found matching or exceeding the --fail-on threshold (default: HIGH and CRITICAL).
- 2: Network error (target unreachable, connection timeout, or DNS resolution error).
- 3: Invalid CLI argument configuration.

---

## Running Unit Tests

```bash
pytest -v
```
