"""CLI interface for API Security Tester."""

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .tester import APISecurityTester
from .reporter import generate_report

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def main():
    """API Security Tester - Automated security testing for REST APIs."""
    pass


@main.command()
@click.option("--url", "-u", required=True, help="Target API base URL")
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file")
@click.option("--token", "-t", help="Authentication token (Bearer token)")
@click.option("--test", type=click.Choice(["all", "auth", "authz", "injection", "ratelimit", "exposure", "headers"]), 
              default="all", help="Test category to run")
@click.option("--report", "-r", type=click.Path(), help="Output report file")
@click.option("--format", "-f", type=click.Choice(["html", "json", "md"]), default="html", help="Report format")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), 
              help="Exit with error if issues of this severity or higher are found")
def scan(url, config, token, test, report, format, fail_on):
    """Run security tests against an API."""
    console.print(f"\n[bold cyan]🔍 API Security Tester v1.0.0[/bold cyan]")
    console.print(f"[dim]Target: {url}[/dim]\n")
    
    # Initialize tester
    tester = APISecurityTester(base_url=url, auth_token=token)
    
    # Load config if provided
    if config:
        tester.load_config(config)
    
    # Run tests
    test_map = {
        "all": tester.run_all,
        "auth": tester.run_authentication_tests,
        "authz": tester.run_authorization_tests,
        "injection": tester.run_injection_tests,
        "ratelimit": tester.run_rate_limit_tests,
        "exposure": tester.run_exposure_tests,
        "headers": tester.run_header_tests,
    }
    
    results = test_map[test]()
    
    # Display results
    display_results(results)
    
    # Generate report if requested
    if report:
        generate_report(results, report, format)
        console.print(f"\n[green]Report saved to {report}[/green]")
    
    # Check fail condition
    if fail_on:
        severity_order = ["low", "medium", "high", "critical"]
        fail_level = severity_order.index(fail_on)
        
        for finding in results.get("findings", []):
            finding_level = severity_order.index(finding["severity"].lower())
            if finding_level >= fail_level:
                raise SystemExit(1)


def display_results(results):
    """Display test results in a formatted table."""
    findings = results.get("findings", [])
    
    # Summary table
    summary = Table(title="Test Summary", box=box.ROUNDED)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")
    
    summary.add_row("Tests Run", str(results.get("tests_run", 0)))
    summary.add_row("Passed", f"[green]{results.get('passed', 0)}[/green]")
    summary.add_row("Failed", f"[red]{results.get('failed', 0)}[/red]")
    summary.add_row("Duration", f"{results.get('duration', 0):.2f}s")
    
    console.print(summary)
    console.print()
    
    if not findings:
        console.print("[bold green]✓ No security issues found![/bold green]")
        return
    
    # Findings table
    findings_table = Table(title="Security Findings", box=box.ROUNDED)
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Test")
    findings_table.add_column("Endpoint")
    findings_table.add_column("Description")
    
    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
    }
    
    for finding in findings:
        severity = finding["severity"].lower()
        color = severity_colors.get(severity, "white")
        findings_table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            finding["test"],
            finding.get("endpoint", "N/A"),
            finding["description"][:50] + "..." if len(finding.get("description", "")) > 50 else finding.get("description", ""),
        )
    
    console.print(findings_table)


if __name__ == "__main__":
    main()
