"""Data models for findings, sources, and disclosure metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EngineName(str, Enum):
    SHODAN = "shodan"
    CENSYS = "censys"
    ZOOMEYE = "zoomeye"


class HoneypotSignal(str, Enum):
    """Why a finding might be a honeypot."""

    SHODAN_TAG = "shodan_tag"
    CLOUD_ASN = "cloud_asn"
    SOLE_ENGINE = "sole_engine"
    OPEN_PORT_GRID = "open_port_grid"


class Source(BaseModel):
    """One engine's view of a finding."""

    engine: EngineName
    query: str
    raw_banner: str | None = None
    seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    """A single exposure finding, possibly observed by multiple engines.

    The dedupe layer merges engine-specific records on (ip, port) into one
    Finding with a list of Sources.
    """

    ip: str
    port: int
    transport: str = "tcp"
    service: str | None = None
    product: str | None = None
    product_version: str | None = None
    asn: int | None = None
    asn_name: str | None = None
    org: str | None = None
    hostname: str | None = None
    country: str | None = None
    city: str | None = None
    category: str
    sources: list[Source] = Field(default_factory=list)
    honeypot_signals: list[HoneypotSignal] = Field(default_factory=list)
    notes: str | None = None

    @property
    def finding_id(self) -> str:
        """Stable identifier for use in filenames and disclosure templates."""

        return f"{self.ip}-{self.port}-{self.category}"

    @property
    def engines_observed(self) -> list[EngineName]:
        return sorted({s.engine for s in self.sources}, key=lambda e: e.value)

    @property
    def is_likely_honeypot(self) -> bool:
        """Heuristic: multiple honeypot signals make it likely a honeypot.

        One signal is suggestive but not definitive; two or more is treated
        as likely. Final judgement is left to the analyst.
        """

        return len(self.honeypot_signals) >= 2


class SurveyReport(BaseModel):
    """Output of a single survey run."""

    started_at: datetime
    finished_at: datetime
    country: str
    categories_run: list[str]
    engines_used: list[EngineName]
    total_findings: int
    findings_by_category: dict[str, int]
    findings: list[Finding]
    config_fingerprint: dict[str, Any] = Field(default_factory=dict)
