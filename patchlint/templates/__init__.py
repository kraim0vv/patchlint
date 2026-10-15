"""Templates package for PatchLint reports."""

from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parent
HTML_REPORT_TEMPLATE = TEMPLATES_DIR / "report_template.html"

__all__ = ["TEMPLATES_DIR", "HTML_REPORT_TEMPLATE"]
