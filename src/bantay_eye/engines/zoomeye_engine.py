"""ZoomEye adapter using the public REST API.

ZoomEye does not ship a maintained official Python SDK, so this adapter
talks to the v2 REST API directly via httpx.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from typing import Any

import httpx

from bantay_eye.engines.base import EngineAdapter, EngineError
from bantay_eye.models import EngineName, Finding, Source

ZOOMEYE_API_BASE = "https://api.zoomeye.org"


class ZoomEyeEngine(EngineAdapter):
    """Adapter for the ZoomEye REST API."""

    name = "zoomeye"

    def __init__(self, api_key: str, min_delay_seconds: float = 1.0, timeout: float = 30.0) -> None:
        super().__init__(min_delay_seconds=min_delay_seconds)
        self._api_key = api_key
        self._client = httpx.Client(
            base_url=ZOOMEYE_API_BASE,
            headers={"API-KEY": api_key, "User-Agent": "bantay-eye/0.1.0"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ZoomEyeEngine:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _search(self, query: str, max_results: int) -> Iterable[Finding]:
        qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        page = 1
        pagesize = min(100, max_results)
        yielded = 0

        while yielded < max_results:
            payload = {
                "qbase64": qbase64,
                "page": page,
                "pagesize": pagesize,
            }
            try:
                response = self._client.post("/v2/search", json=payload)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                raise EngineError(f"ZoomEye HTTP error: {e}") from e
            except json.JSONDecodeError as e:
                raise EngineError(f"ZoomEye returned non-JSON: {e}") from e

            if data.get("code") not in (0, None) and "data" not in data:
                raise EngineError(f"ZoomEye API error: {data.get('message') or data}")

            matches = data.get("data") or []
            if not matches:
                return

            for raw in matches:
                if yielded >= max_results:
                    break
                finding = self._raw_to_finding(raw, query)
                if finding is not None:
                    yield finding
                    yielded += 1

            if len(matches) < pagesize:
                return
            page += 1
            self._wait()

    def _raw_to_finding(self, raw: dict[str, Any], query: str) -> Finding | None:
        ip = raw.get("ip")
        port_value = raw.get("port")
        if ip is None or port_value is None:
            return None

        try:
            port = int(port_value)
        except (TypeError, ValueError):
            return None

        asn_value = raw.get("asn")
        asn_int: int | None = None
        if isinstance(asn_value, int):
            asn_int = asn_value
        elif isinstance(asn_value, str) and asn_value.upper().startswith("AS"):
            try:
                asn_int = int(asn_value[2:])
            except ValueError:
                pass

        return Finding(
            ip=str(ip),
            port=port,
            transport=str(raw.get("protocol") or "tcp").lower(),
            service=raw.get("service"),
            product=raw.get("product"),
            product_version=raw.get("version"),
            asn=asn_int,
            asn_name=raw.get("organization"),
            org=raw.get("organization"),
            hostname=(raw.get("hostname") or [None])[0]
            if isinstance(raw.get("hostname"), list)
            else raw.get("hostname"),
            country=(raw.get("geoinfo") or {}).get("country", {}).get("code"),
            city=(raw.get("geoinfo") or {}).get("city", {}).get("name"),
            category="unknown",  # set by EngineAdapter.search
            sources=[
                Source(
                    engine=EngineName.ZOOMEYE,
                    query=query,
                    raw_banner=raw.get("raw_data") or raw.get("banner"),
                )
            ],
        )
