"""Bantay-Eye command-line interface."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bantay_eye import __version__
from bantay_eye.categories import CATEGORIES
from bantay_eye.config import Config, default_config_path, find_config_file, load_config
from bantay_eye.disclosure import TEMPLATE_NAMES, render as render_disclosure
from bantay_eye.models import Finding
from bantay_eye.survey import run_survey

app = typer.Typer(
    name="bantay-eye",
    help=(
        "Defensive internet exposure survey utility. Part of the OSINT-PH "
        "tool suite. See https://blog.osintph.info for methodology."
    ),
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.callback()
def _main() -> None:
    """Bantay-Eye: defensive exposure survey."""


@app.command()
def version() -> None:
    """Print the installed version."""

    typer.echo(f"bantay-eye {__version__}")


@app.command("config-path")
def config_path() -> None:
    """Print the path where the user config lives."""

    typer.echo(str(default_config_path()))


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config."),
    location: str = typer.Option(
        "cwd",
        "--location",
        help="Where to write the config: 'cwd' or 'user'.",
    ),
) -> None:
    """Create a starter bantay_eye.toml in the current directory or user config dir."""

    # The example file ships at the repo root next to pyproject.toml.
    # When installed via pip the example may not be present at all, so
    # fall back to a built-in default if the bundled example is missing.
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "bantay_eye.toml.example",
        Path.cwd() / "bantay_eye.toml.example",
    ]
    example: Path | None = next((c for c in candidates if c.exists()), None)

    if location == "cwd":
        target = Path.cwd() / "bantay_eye.toml"
    elif location == "user":
        target = default_config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
    else:
        console.print(f"[red]Unknown location {location!r}; use 'cwd' or 'user'.[/red]")
        raise typer.Exit(1)

    if target.exists() and not force:
        console.print(f"[yellow]{target} already exists. Use --force to overwrite.[/yellow]")
        raise typer.Exit(1)

    if example is None:
        target.write_text(_BUILTIN_CONFIG_TEMPLATE)
        console.print(f"[green]Wrote built-in config template to {target}[/green]")
    else:
        shutil.copy(example, target)
        console.print(f"[green]Wrote {target}[/green]")
    console.print("Edit this file to add your Shodan, Censys, and ZoomEye API credentials.")


_BUILTIN_CONFIG_TEMPLATE = """# Bantay-Eye configuration. Fill in API keys for engines you want to use.
[engines.shodan]
enabled = true
api_key = "YOUR_SHODAN_API_KEY"
min_delay_seconds = 1.0

[engines.censys]
enabled = true
api_id = "YOUR_CENSYS_API_ID"
api_secret = "YOUR_CENSYS_API_SECRET"
min_delay_seconds = 0.5

[engines.zoomeye]
enabled = true
api_key = "YOUR_ZOOMEYE_API_KEY"
min_delay_seconds = 1.0

[survey]
country = "PH"
max_results_per_query = 100
output_dir = "./findings"
honeypot_filter = "tag"

[categories]
enabled = ["ics", "government", "remote_access", "telecom", "iot"]

[disclosure]
researcher_name = "Your Name"
researcher_email = "you@example.com"
researcher_org = "Your Organisation"
researcher_pgp_url = ""
default_timeline_days = 90
escalation_timeline_days = 14

[disclosure.ncert]
email = "cybersecurity@dict.gov.ph"
phone = "+63 2 920 0101 local 1002"
authority_name = "National Computer Emergency Response Team (NCERT-PH)"
"""


@app.command()
def categories() -> None:
    """List the available survey categories."""

    table = Table(title="Bantay-Eye categories", show_lines=True)
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Queries", justify="right")
    table.add_column("Disclosure path")

    for cat in CATEGORIES:
        table.add_row(
            cat.slug,
            cat.title,
            str(len(cat.queries)),
            cat.disclosure_path,
        )

    console.print(table)


@app.command()
def survey(
    config_file: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a bantay_eye.toml file."
    ),
    category: list[str] | None = typer.Option(
        None,
        "--category",
        help="Limit to one or more category slugs (repeat flag for multiples).",
    ),
    all_categories: bool = typer.Option(
        False, "--all", help="Run every category with queries defined."
    ),
    country: str | None = typer.Option(
        None,
        "--country",
        help="ISO 3166-1 alpha-2 country code. Overrides config.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the survey report JSON to this path (default: output/<timestamp>.json).",
    ),
) -> None:
    """Run a survey and write a JSON report."""

    config = load_config(config_file)

    slugs: list[str] | None
    if all_categories:
        slugs = [c.slug for c in CATEGORIES if c.queries]
    elif category:
        slugs = list(category)
    else:
        slugs = config.categories.enabled

    report = run_survey(config, categories=slugs, country=country, console=console)

    out_path = output or _default_output_path(config)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.model_dump_json(indent=2))

    console.print()
    console.print(f"[green]Survey complete.[/green] Wrote {out_path}")
    table = Table(title="Findings by category")
    table.add_column("Category")
    table.add_column("Findings", justify="right")
    for slug, count in report.findings_by_category.items():
        table.add_row(slug, str(count))
    table.add_row("[bold]Total[/bold]", f"[bold]{report.total_findings}[/bold]")
    console.print(table)


def _default_output_path(config: Config) -> Path:
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    return Path(config.survey.output_dir) / f"survey-{timestamp}.json"


@app.command()
def disclose(
    finding_id: str = typer.Argument(..., help="Finding ID in the form ip-port-category."),
    report: Path = typer.Option(..., "--report", "-r", help="Path to a survey JSON report."),
    template: str = typer.Option(
        "ncert",
        "--template",
        help=f"Template to use. Choices: {', '.join(TEMPLATE_NAMES)}.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to this path instead of stdout."
    ),
    config_file: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a bantay_eye.toml file."
    ),
) -> None:
    """Generate a disclosure advisory for a single finding."""

    config = load_config(config_file)

    if not report.exists():
        console.print(f"[red]Report file not found: {report}[/red]")
        raise typer.Exit(1)

    data = json.loads(report.read_text())
    matching: Finding | None = None
    for raw in data.get("findings", []):
        finding = Finding.model_validate(raw)
        if finding.finding_id == finding_id:
            matching = finding
            break

    if matching is None:
        console.print(f"[red]No finding with id {finding_id!r} in {report}[/red]")
        raise typer.Exit(1)

    rendered = render_disclosure(matching, template=template, config=config)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        console.print(f"[green]Wrote {output}[/green]")
    else:
        sys.stdout.write(rendered)


@app.command()
def doctor(
    config_file: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a bantay_eye.toml file."
    ),
) -> None:
    """Diagnose your installation and configuration."""

    table = Table(title="Bantay-Eye doctor")
    table.add_column("Check")
    table.add_column("Status")

    config_path_obj = find_config_file(config_file)
    table.add_row(
        "Config file",
        f"[green]{config_path_obj}[/green]" if config_path_obj else "[red]not found[/red]",
    )

    config = load_config(config_file)
    table.add_row(
        "Shodan",
        "[green]ready[/green]"
        if config.engines.shodan.is_usable()
        else "[yellow]not configured[/yellow]",
    )
    table.add_row(
        "Censys",
        "[green]ready[/green]"
        if config.engines.censys.is_usable()
        else "[yellow]not configured[/yellow]",
    )
    table.add_row(
        "ZoomEye",
        "[green]ready[/green]"
        if config.engines.zoomeye.is_usable()
        else "[yellow]not configured[/yellow]",
    )
    table.add_row("Country", config.survey.country)
    table.add_row("Honeypot filter", config.survey.honeypot_filter)
    table.add_row("Output directory", config.survey.output_dir)
    table.add_row("Enabled categories", ", ".join(config.categories.enabled))

    console.print(table)


if __name__ == "__main__":
    app()
