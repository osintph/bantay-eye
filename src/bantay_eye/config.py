"""Configuration loading and validation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from platformdirs import user_config_dir
from pydantic import BaseModel, Field, field_validator


class ShodanConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""
    min_delay_seconds: float = 1.0

    def is_usable(self) -> bool:
        return self.enabled and bool(self.api_key) and self.api_key != "YOUR_SHODAN_API_KEY"


class CensysConfig(BaseModel):
    enabled: bool = True
    api_id: str = ""
    api_secret: str = ""
    min_delay_seconds: float = 0.5

    def is_usable(self) -> bool:
        return (
            self.enabled
            and bool(self.api_id)
            and bool(self.api_secret)
            and self.api_id != "YOUR_CENSYS_API_ID"
        )


class ZoomEyeConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""
    min_delay_seconds: float = 1.0

    def is_usable(self) -> bool:
        return self.enabled and bool(self.api_key) and self.api_key != "YOUR_ZOOMEYE_API_KEY"


class EnginesConfig(BaseModel):
    shodan: ShodanConfig = Field(default_factory=ShodanConfig)
    censys: CensysConfig = Field(default_factory=CensysConfig)
    zoomeye: ZoomEyeConfig = Field(default_factory=ZoomEyeConfig)


class SurveyConfig(BaseModel):
    country: str = "PH"
    max_results_per_query: int = 100
    output_dir: str = "./findings"
    honeypot_filter: str = "tag"

    @field_validator("honeypot_filter")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        if v not in ("tag", "exclude", "off"):
            raise ValueError(f"honeypot_filter must be one of: tag, exclude, off (got {v!r})")
        return v


class CategoriesConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: ["ics", "government", "remote_access", "telecom", "iot"]
    )


class NcertConfig(BaseModel):
    email: str = "cybersecurity@dict.gov.ph"
    phone: str = "+63 2 920 0101 local 1002"
    authority_name: str = "National Computer Emergency Response Team (NCERT-PH)"


class DisclosureConfig(BaseModel):
    researcher_name: str = "Anonymous Researcher"
    researcher_email: str = ""
    researcher_org: str = ""
    researcher_pgp_url: str = ""
    default_timeline_days: int = 90
    escalation_timeline_days: int = 14
    ncert: NcertConfig = Field(default_factory=NcertConfig)


class Config(BaseModel):
    engines: EnginesConfig = Field(default_factory=EnginesConfig)
    survey: SurveyConfig = Field(default_factory=SurveyConfig)
    categories: CategoriesConfig = Field(default_factory=CategoriesConfig)
    disclosure: DisclosureConfig = Field(default_factory=DisclosureConfig)


def default_config_path() -> Path:
    """Platform-appropriate default config path."""

    return Path(user_config_dir("bantay-eye")) / "bantay_eye.toml"


def find_config_file(explicit_path: Path | None = None) -> Path | None:
    """Locate a config file using a small search path.

    Precedence:
      1. Explicit path passed in (always wins, raises if missing).
      2. ./bantay_eye.toml in the current working directory.
      3. Platform user config directory.
    """

    if explicit_path is not None:
        if not explicit_path.exists():
            raise FileNotFoundError(f"Config file not found: {explicit_path}")
        return explicit_path

    cwd_path = Path.cwd() / "bantay_eye.toml"
    if cwd_path.exists():
        return cwd_path

    user_path = default_config_path()
    if user_path.exists():
        return user_path

    return None


def load_config(explicit_path: Path | None = None) -> Config:
    """Load and validate config from disk, falling back to defaults."""

    path = find_config_file(explicit_path)
    if path is None:
        return Config()

    with path.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)

    return Config.model_validate(data)
