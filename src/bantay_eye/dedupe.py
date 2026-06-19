"""Cross-engine deduplication.

Findings from different engines on the same ``(ip, port)`` are merged
into a single :class:`Finding` with the union of source records and the
best-quality metadata from each source.
"""

from __future__ import annotations

from collections.abc import Iterable

from bantay_eye.models import Finding


def _prefer(*values: object) -> object | None:
    """Return the first non-empty value."""

    for value in values:
        if value not in (None, "", []):
            return value
    return None


def merge(a: Finding, b: Finding) -> Finding:
    """Merge two findings on the same (ip, port). Mutates and returns ``a``."""

    a.sources.extend(b.sources)
    a.service = _prefer(a.service, b.service)  # type: ignore[assignment]
    a.product = _prefer(a.product, b.product)  # type: ignore[assignment]
    a.product_version = _prefer(a.product_version, b.product_version)  # type: ignore[assignment]
    a.asn = _prefer(a.asn, b.asn)  # type: ignore[assignment]
    a.asn_name = _prefer(a.asn_name, b.asn_name)  # type: ignore[assignment]
    a.org = _prefer(a.org, b.org)  # type: ignore[assignment]
    a.hostname = _prefer(a.hostname, b.hostname)  # type: ignore[assignment]
    a.country = _prefer(a.country, b.country)  # type: ignore[assignment]
    a.city = _prefer(a.city, b.city)  # type: ignore[assignment]

    # Union honeypot signals
    for signal in b.honeypot_signals:
        if signal not in a.honeypot_signals:
            a.honeypot_signals.append(signal)

    return a


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse findings with matching ``(ip, port, category)`` keys."""

    by_key: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.ip, f.port, f.category)
        if key in by_key:
            by_key[key] = merge(by_key[key], f)
        else:
            by_key[key] = f
    return list(by_key.values())
