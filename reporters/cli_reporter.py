"""
CLI reporter for threat intelligence verdicts.
"""

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from typing import List
from models import Verdict, EvidenceItem

console = Console()


class CLIReporter:
    """Generates CLI/console reports from verdicts."""

    def generate(self, verdict: Verdict) -> None:
        """
        Print formatted verdict to console.

        Args:
            verdict: Analysis verdict
        """
        # Header
        title = f"🔍 Threat Intelligence Analysis: {verdict.object_type.upper()} {verdict.object_value}"
        console.print(Panel.fit(title, style="bold blue"))
        console.print()

        # Key metrics
        self._print_key_metrics(verdict)
        console.print()

        # Summary
        self._print_summary(verdict)
        console.print()

        # Evidence table
        if verdict.evidence:
            self._print_evidence_table(verdict.evidence)
            console.print()

        # Tags
        if verdict.tags:
            self._print_tags(verdict.tags)
            console.print()

    def _print_key_metrics(self, verdict: Verdict) -> None:
        """Print key analysis metrics."""
        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("Final Score", f"{verdict.final_score}/100")
        table.add_row("Reputation Score", str(verdict.reputation_score))
        table.add_row("Contextual Score", str(verdict.contextual_score))
        table.add_row("Verdict Level", self._format_level(verdict.level))
        table.add_row("Confidence", f"{verdict.confidence:.1%}")
        table.add_row("Decision", self._format_decision(verdict.decision))

        console.print(table)

    def _print_summary(self, verdict: Verdict) -> None:
        """Print analysis summary."""
        summary_panel = Panel(verdict.summary, title="📋 Summary", border_style="green")
        console.print(summary_panel)

    def _print_evidence_table(self, evidence: List[EvidenceItem]) -> None:
        """Print evidence in a table format."""
        table = Table(title="🔎 Evidence Details")
        table.add_column("Source", style="magenta", no_wrap=True)
        table.add_column("Title", style="white", max_width=40)
        table.add_column("Severity", style="yellow")
        table.add_column("Score Δ", style="red")
        table.add_column("Confidence", style="blue")

        for item in evidence:
            score_delta = f"{item.score_delta:+d}" if item.score_delta != 0 else "0"
            confidence = f"{item.confidence:.1%}"

            table.add_row(
                item.source.upper(),
                item.title,
                item.severity.upper(),
                score_delta,
                confidence,
            )

        console.print(table)

        # Print evidence details
        for i, item in enumerate(evidence, 1):
            detail_panel = Panel(
                item.detail,
                title=f"Evidence {i}: {item.title}",
                border_style="dim blue",
            )
            console.print(detail_panel)
            console.print()

    def _print_tags(self, tags: List[str]) -> None:
        """Print semantic tags."""
        tag_text = Text("🏷️  Semantic Tags: ", style="bold cyan")
        tag_list = Text(", ".join(f"`{tag}`" for tag in tags), style="white")
        console.print(tag_text + tag_list)

    def _format_level(self, level: str) -> str:
        """Format verdict level with color."""
        colors = {
            "Low": "[green]🟢 Low[/green]",
            "Medium": "[yellow]🟡 Medium[/yellow]",
            "High": "[red]🟠 High[/red]",
            "Critical": "[red]🔴 Critical[/red]",
            "Inconclusive": "[white]⚪ Inconclusive[/white]",
        }
        return colors.get(level, level)

    def _format_decision(self, decision: str) -> str:
        """Format decision for readability."""
        decision_map = {
            "allow_with_monitoring": "Allow with Monitoring",
            "investigate": "Investigate",
            "alert_and_review": "Alert and Review",
            "contain_or_block": "Contain or Block",
            "collect_more_context": "Collect More Context",
        }
        formatted = decision_map.get(decision, decision.replace("_", " ").title())

        # Color based on severity
        if decision in ["contain_or_block"]:
            return f"[red]{formatted}[/red]"
        elif decision in ["alert_and_review", "investigate"]:
            return f"[yellow]{formatted}[/yellow]"
        else:
            return f"[green]{formatted}[/green]"
