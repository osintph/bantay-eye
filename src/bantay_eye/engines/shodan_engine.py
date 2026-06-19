"""Shodan adapter."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bantay_eye.engines.base import EngineAdapter, EngineError
from bantay_eye.models import EngineName, Finding, HoneypotSignal, Source


class ShodanEngine(EngineAdapter):
    """Adapter for the official Shodan SDK."""

    name = "shodan"

    def __init__(self, api_key: str, min_delay_seconds: float = 1.0) -> None:
        super().__init__(min_delay_seconds=min_delay_seconds)
        try:
            import shodan
        except ImportError as e:
            raise EngineError("shodan package not installed") from e
        self._client = shodan.Shodan(api_key)
        self._shodan_module = shodan

    def _search(self, query: str, max_results: int) -> Iterable[Finding]:
        try:
            response = self._client.search(query, limit=max_results)
        except self._shodan_module.APIError as e:
            raise EngineError(f"Shodan API error: {e}") from e
        except Exception as e:  # network failures, etc.
            raise EngineError(f"Shodan call failed: {e}") from e

        for match in response.get("matches", []):
            finding = self._match_to_finding(match, query)
            if finding is not None:
                yield finding

    def _match_to_finding(self, match: dict[str, Any], query: str) -> Finding | None:
        ip = match.get("ip_str") or match.get("ip")
        port = match.get("port")
        if ip is None or port is None:
            return None

        location = match.get("location") or {}
        tags = match.get("tags") or []

        # Surface honeypot signal from Shodan's own tag, since the tag is
        # visible on result cards without enterprise.
        signals: list[HoneypotSignal] = []
        if isinstance(tags, list) and "honeypot" in tags:
            signals.append(HoneypotSignal.SHODAN_TAG)

        return Finding(
            ip=str(ip),
            port=int(port),
            transport=str(match.get("transport") or "tcp"),
            service=match.get("_shodan", {}).get("module"),
            product=match.get("product"),
            product_version=match.get("version"),
            asn=int(match["asn"][2:]) if match.get("asn", "").startswith("AS") else None,
            asn_name=None,
            org=match.get("org"),
            hostname=(match.get("hostnames") or [None])[0],
            country=location.get("country_code"),
            city=location.get("city"),
            category="unknown",  # set by EngineAdapter.search
            sources=[
                Source(
                    engine=EngineName.SHODAN,
                    query=query,
                    raw_banner=match.get("data"),
                )
            ],
            honeypot_signals=signals,
        )
