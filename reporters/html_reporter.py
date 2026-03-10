"""
HTML reporter for threat intelligence analysis results.
"""

import os
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader
from models import Verdict


class HTMLReporter:
    """Generates HTML reports from verdict data."""

    def __init__(self):
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate(self, verdict: Verdict) -> str:
        """
        Generate HTML report from verdict.

        Args:
            verdict: Analysis verdict

        Returns:
            HTML string
        """
        template = self.env.get_template("report.html.j2")

        # Prepare data for template
        data = self._prepare_template_data(verdict)

        return template.render(**data)

    def _prepare_template_data(self, verdict: Verdict) -> Dict[str, Any]:
        """Prepare data for HTML template."""
        # Group evidence by category and severity
        evidence_by_category = {}
        for evidence in verdict.evidence:
            category = evidence.category
            if category not in evidence_by_category:
                evidence_by_category[category] = []
            evidence_by_category[category].append(evidence)

        # Sort evidence by score_delta descending
        for category in evidence_by_category:
            evidence_by_category[category].sort(
                key=lambda e: e.score_delta, reverse=True
            )

        return {
            "verdict": verdict,
            "evidence_by_category": evidence_by_category,
            "severity_colors": {
                "critical": "danger",
                "high": "danger",
                "medium": "warning",
                "low": "info",
            },
            "level_colors": {
                "Critical": "danger",
                "High": "danger",
                "Medium": "warning",
                "Low": "success",
                "Inconclusive": "secondary",
            },
        }
