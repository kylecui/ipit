"""
CLI interface for Threat Intelligence Reasoning Engine.
"""

import asyncio
from typing import Optional
from pathlib import Path
import typer
from .service import ThreatIntelService
from ..reporters.json_reporter import JSONReporter
from ..reporters.markdown_reporter import MarkdownReporter
from ..reporters.cli_reporter import CLIReporter

app = typer.Typer(help="Threat Intelligence Reasoning Engine CLI")
service = ThreatIntelService()


@app.command()
def lookup(
    ip: str = typer.Argument(..., help="IP address to lookup"),
    format: str = typer.Option("cli", help="Output format: cli, json, md"),
):
    """Quick lookup of an IP address."""
    verdict = asyncio.run(service.analyze_ip(ip))

    if format == "json":
        reporter = JSONReporter()
        output = reporter.generate(verdict)
    elif format == "md":
        reporter = MarkdownReporter()
        output = reporter.generate(verdict)
    else:  # cli
        reporter = CLIReporter()
        reporter.generate(verdict)
        return  # CLI reporter prints directly

    typer.echo(output)


@app.command()
def report(
    ip: str = typer.Argument(..., help="IP address to analyze"),
    format: str = typer.Option("md", help="Output format: json, md"),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
):
    """Generate detailed report for an IP address."""
    verdict = asyncio.run(service.analyze_ip(ip))

    if format == "json":
        reporter = JSONReporter()
        content = reporter.generate(verdict)
    elif format == "md":
        reporter = MarkdownReporter()
        content = reporter.generate(verdict)
    else:
        typer.echo("Invalid format. Use 'json' or 'md'", err=True)
        raise typer.Exit(1)

    if output:
        output.write_text(content, encoding="utf-8")
        typer.echo(f"Report saved to {output}")
    else:
        typer.echo(content)


@app.command()
def analyze(
    ip: str = typer.Argument(..., help="IP address to analyze"),
    port: Optional[int] = typer.Option(None, help="Port number"),
    direction: Optional[str] = typer.Option(
        None, help="Traffic direction (inbound/outbound)"
    ),
    hostname: Optional[str] = typer.Option(None, help="Associated hostname"),
    protocol: Optional[str] = typer.Option(None, help="Protocol (tcp/udp)"),
    process_name: Optional[str] = typer.Option(None, help="Process name"),
    format: str = typer.Option("cli", help="Output format: cli, json, md"),
):
    """Context-aware analysis with additional behavioral context."""
    # For now, context is not implemented, so this is same as lookup
    typer.echo("Context-aware analysis not yet implemented. Performing basic lookup...")
    verdict = asyncio.run(service.analyze_ip(ip))

    if format == "json":
        reporter = JSONReporter()
        output = reporter.generate(verdict)
    elif format == "md":
        reporter = MarkdownReporter()
        output = reporter.generate(verdict)
    else:  # cli
        reporter = CLIReporter()
        reporter.generate(verdict)
        return

    typer.echo(output)


@app.command()
def batch(
    input_file: Path = typer.Argument(..., help="Input CSV file with observables"),
    format: str = typer.Option("json", help="Output format: json, md"),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
):
    """Batch analysis of multiple observables."""
    typer.echo("Batch analysis not yet implemented", err=True)
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
