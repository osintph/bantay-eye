"""Survey orchestration.

Pulls all configured engines, runs the configured categories, applies
dedupe and honeypot filtering, and returns a :class:`SurveyReport`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from bantay_eye.categories import CATEGORIES, Category, get_category, render_query
from bantay_eye.config import Config
from bantay_eye.dedupe import dedupe
from bantay_eye.engines import CensysEngine, EngineAdapter, EngineError, ShodanEngine, ZoomEyeEngine
from bantay_eye.honeypot import annotate as honeypot_annotate
from bantay_eye.models import EngineName, Finding, SurveyReport


def build_engines(config: Config, console: Console | None = None) -> dict[EngineName, EngineAdapter]:
    """Instantiate engines that have usable credentials."""

    console = console or Console()
    engines: dict[EngineName, EngineAdapter] = {}

    if config.engines.shodan.is_usable():
        try:
            engines[EngineName.SHODAN] = ShodanEngine(
                api_key=config.engines.shodan.api_key,
                min_delay_seconds=config.engines.shodan.min_delay_seconds,
            )
        except EngineError as e:
            console.print(f"[yellow]Shodan disabled: {e}[/yellow]")

    if config.engines.censys.is_usable():
        try:
            engines[EngineName.CENSYS] = CensysEngine(
                api_id=config.engines.censys.api_id,
                api_secret=config.engines.censys.api_secret,
                min_delay_seconds=config.engines.censys.min_delay_seconds,
            )
        except EngineError as e:
            console.print(f"[yellow]Censys disabled: {e}[/yellow]")

    if config.engines.zoomeye.is_usable():
        try:
            engines[EngineName.ZOOMEYE] = ZoomEyeEngine(
                api_key=config.engines.zoomeye.api_key,
                min_delay_seconds=config.engines.zoomeye.min_delay_seconds,
            )
        except EngineError as e:
            console.print(f"[yellow]ZoomEye disabled: {e}[/yellow]")

    return engines


def _select_categories(slugs: list[str] | None) -> list[Category]:
    if slugs is None:
        return list(CATEGORIES)
    return [get_category(slug) for slug in slugs]


def run_survey(
    config: Config,
    *,
    categories: list[str] | None = None,
    country: str | None = None,
    console: Console | None = None,
) -> SurveyReport:
    """Run a full survey across the configured engines and categories."""

    console = console or Console()
    started = datetime.now(timezone.utc)
    country_code = (country or config.survey.country).upper()

    engines = build_engines(config, console=console)
    if not engines:
        console.print(
            "[red]No usable engines configured. Edit your bantay_eye.toml to add API keys.[/red]"
        )

    chosen = _select_categories(categories or config.categories.enabled)
    findings: list[Finding] = []
    per_category: dict[str, int] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        for category in chosen:
            if not category.queries:
                console.print(
                    f"[dim]Skipping {category.slug} (no queries defined; reserved category).[/dim]"
                )
                per_category[category.slug] = 0
                continue

            task = progress.add_task(f"Surveying {category.title}", total=None)
            category_findings: list[Finding] = []

            for query in category.queries:
                for engine_name, engine in engines.items():
                    template = getattr(query, engine_name.value)
                    if not template:
                        continue
                    rendered = render_query(template, country_code)
                    progress.update(
                        task,
                        description=f"{category.slug} / {query.label} / {engine_name.value}",
                    )
                    try:
                        results = engine.search(
                            query=rendered,
                            category=category.slug,
                            max_results=config.survey.max_results_per_query,
                        )
                        category_findings.extend(results)
                    except EngineError as e:
                        console.print(
                            f"[yellow]{engine_name.value} failed on "
                            f"{query.label}: {e}[/yellow]"
                        )

            merged = dedupe(category_findings)
            for finding in merged:
                honeypot_annotate(finding)

            if config.survey.honeypot_filter == "exclude":
                merged = [f for f in merged if not f.is_likely_honeypot]

            findings.extend(merged)
            per_category[category.slug] = len(merged)
            progress.remove_task(task)

    finished = datetime.now(timezone.utc)
    return SurveyReport(
        started_at=started,
        finished_at=finished,
        country=country_code,
        categories_run=[c.slug for c in chosen],
        engines_used=list(engines.keys()),
        total_findings=len(findings),
        findings_by_category=per_category,
        findings=findings,
        config_fingerprint={
            "honeypot_filter": config.survey.honeypot_filter,
            "max_results_per_query": config.survey.max_results_per_query,
        },
    )
