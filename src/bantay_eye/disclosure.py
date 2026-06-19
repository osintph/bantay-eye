"""Render disclosure templates for findings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from bantay_eye.config import Config
from bantay_eye.models import Finding

TEMPLATE_NAMES = {
    "ncert": "advisory_ncert.md.j2",
    "owner": "advisory_owner.md.j2",
    "npc": "advisory_npc.md.j2",
}


def _template_search_paths() -> list[Path]:
    """Locations to look for templates.

    Order: bundled package templates first, then any ``./templates``
    in the current working directory as a user override hook.
    """

    paths: list[Path] = []

    # Bundled inside the installed package
    try:
        bundled = files("bantay_eye").joinpath("templates")
        if bundled.is_dir():  # type: ignore[union-attr]
            paths.append(Path(str(bundled)))
    except (ModuleNotFoundError, FileNotFoundError):
        pass

    # User override in current working directory
    cwd_local = Path.cwd() / "templates"
    if cwd_local.is_dir():
        paths.append(cwd_local)

    return paths


def render(finding: Finding, template: str, config: Config) -> str:
    """Render the given template for one finding."""

    if template not in TEMPLATE_NAMES:
        raise KeyError(
            f"Unknown template {template!r}; choose one of: {', '.join(TEMPLATE_NAMES)}"
        )

    paths = _template_search_paths()
    if not paths:
        raise FileNotFoundError(
            "Could not locate template directory. Reinstall bantay-eye or "
            "run from the source checkout."
        )

    env = Environment(
        loader=FileSystemLoader([str(p) for p in paths]),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template(TEMPLATE_NAMES[template])

    now = datetime.now(timezone.utc)
    timeline = config.disclosure.default_timeline_days
    escalation = config.disclosure.escalation_timeline_days

    return tmpl.render(
        finding=finding,
        config=config,
        ncert=config.disclosure.ncert,
        researcher={
            "name": config.disclosure.researcher_name,
            "email": config.disclosure.researcher_email,
            "org": config.disclosure.researcher_org,
            "pgp_url": config.disclosure.researcher_pgp_url,
        },
        today=now.date().isoformat(),
        deadline=(now + timedelta(days=timeline)).date().isoformat(),
        escalation_deadline=(now + timedelta(days=escalation)).date().isoformat(),
        timeline_days=timeline,
        escalation_days=escalation,
    )
