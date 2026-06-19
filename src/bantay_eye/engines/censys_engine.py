"""Censys adapter (Censys Search v2)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bantay_eye.engines.base import EngineAdapter, EngineError
from bantay_eye.models import EngineName, Finding, Source


class CensysEngine(EngineAdapter):
    """Adapter for the Censys v2 hosts search API."""

    name = "censys"

    def __init__(
        self,
        api_id: str,
        api_secret: str,
        min_delay_seconds: float = 0.5,
    ) -> None:
        super().__init__(min_delay_seconds=min_delay_seconds)
        try:
            from censys.search import CensysHosts
            from censys.common.exceptions import CensysException
        except ImportError as e:
            raise EngineError("censys package not installed") from e
        self._client = CensysHosts(api_id=api_id, api_secret=api_secret)
        self._CensysException = CensysException

    def _search(self, query: str, max_results: int) -> Iterable[Finding]:
        try:
            page = self._client.search(query, per_page=min(100, max_results), pages=1)
            results = list(page())
        except self._CensysException as e:
            raise EngineError(f"Censys API error: {e}") from e
        except Exception as e:
            raise EngineError(f"Censys call failed: {e}") from e

        flat: list[dict[str, Any]] = []
        for batch in [results] if not results or isinstance(results[0], dict) else results:
            if isinstance(batch, list):
                flat.extend(batch)
            elif isinstance(batch, dict):
                flat.append(batch)

        yielded = 0
        for host in flat:
            if yielded >= max_results:
                break
            for finding in self._host_to_findings(host, query):
                yield finding
                yielded += 1
                if yielded >= max_results:
                    break

    def _host_to_findings(self, host: dict[str, Any], query: str) -> Iterable[Finding]:
        ip = host.get("ip")
        if not ip:
            return

        location = host.get("location") or {}
        autonomous_system = host.get("autonomous_system") or {}
        services = host.get("services") or []

        for service in services:
            port = service.get("port")
            if port is None:
                continue

            software_list = service.get("software") or []
            product = None
            product_version = None
            if software_list:
                first = software_list[0]
                product = first.get("product")
                product_version = first.get("version")

            yield Finding(
                ip=str(ip),
                port=int(port),
                transport=str(service.get("transport_protocol") or "tcp").lower(),
                service=service.get("service_name"),
                product=product,
                product_version=product_version,
                asn=autonomous_system.get("asn"),
                asn_name=autonomous_system.get("name"),
                org=autonomous_system.get("description") or autonomous_system.get("name"),
                hostname=None,
                country=location.get("country_code"),
                city=(location.get("city") if isinstance(location.get("city"), str) else None),
                category="unknown",  # set by EngineAdapter.search
                sources=[
                    Source(
                        engine=EngineName.CENSYS,
                        query=query,
                        raw_banner=service.get("banner"),
                    )
                ],
            )
