"""Project configuration (.patchlint.toml / [tool.patchlint]) and baseline suppression."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

from patchlint.models import ScanReport, Severity, compute_fingerprint

CONFIG_FILENAME = ".patchlint.toml"

# Option name -> expected Python type(s).
CONFIG_SCHEMA: dict[str, tuple[type, ...]] = {
    "exclude": (list,),
    "fail_on": (str,),
    "min_severity": (str,),
    "timeout": (int, float),
    "concurrency": (int,),
    "insecure": (bool,),
    "headers_only": (bool,),
    "user_agent": (str,),
    "baseline": (str,),
}


class ConfigError(Exception):
    """Invalid configuration or baseline file."""


def find_config(start: Path | None = None) -> Path | None:
    """Return .patchlint.toml, or pyproject.toml containing [tool.patchlint], in the given dir."""
    base = start or Path.cwd()
    candidate = base / CONFIG_FILENAME
    if candidate.is_file():
        return candidate
    pyproject = base / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            return None
        if "patchlint" in data.get("tool", {}):
            return pyproject
    return None


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate configuration; relative paths resolve against the config file's dir."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read config '{path}': {exc}") from exc

    if path.name == "pyproject.toml":
        data = data.get("tool", {}).get("patchlint", {})

    unknown = sorted(set(data) - set(CONFIG_SCHEMA))
    if unknown:
        raise ConfigError(
            f"Unknown option(s) in '{path}': {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(CONFIG_SCHEMA))}."
        )
    for key, value in data.items():
        expected = CONFIG_SCHEMA[key]
        # bool is a subclass of int; don't accept true/false for numeric options.
        if not isinstance(value, expected) or (isinstance(value, bool) and bool not in expected):
            names = " or ".join(t.__name__ for t in expected)
            raise ConfigError(f"Option '{key}' in '{path}' must be of type {names}.")
    if "exclude" in data and not all(isinstance(x, str) for x in data["exclude"]):
        raise ConfigError(f"Option 'exclude' in '{path}' must be a list of rule IDs.")
    for key in ("fail_on", "min_severity"):
        if key in data:
            data[key] = data[key].upper()
            if data[key] not in Severity.__members__:
                raise ConfigError(f"Option '{key}' in '{path}' must be one of {', '.join(Severity.__members__)}.")
    if "baseline" in data:
        data["baseline"] = str((path.parent / data["baseline"]).resolve())
    return data


def load_baseline(path: str | Path) -> set[str]:
    """Read fingerprints from a previous PatchLint JSON report."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read baseline '{path}': {exc}") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise ConfigError(f"Baseline '{path}' is not a PatchLint JSON report (missing 'findings').")
    fingerprints: set[str] = set()
    for item in findings:
        if isinstance(item, dict) and "rule_id" in item and "url" in item:
            fingerprints.add(item.get("fingerprint") or compute_fingerprint(item["rule_id"], item["url"]))
    return fingerprints


def apply_baseline(report: ScanReport, fingerprints: set[str]) -> None:
    """Drop findings already present in the baseline and update summary counters in place."""
    kept = [f for f in report.findings if f.fingerprint not in fingerprints]
    report.suppressed_count += len(report.findings) - len(kept)
    report.findings = kept
    report.recount()
