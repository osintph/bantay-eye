"""Honeypot identification heuristics.

The three signals used:

1. Shodan's own ``honeypot`` tag (already surfaced by the Shodan adapter).
2. ASN match against a curated list of commercial cloud providers that
   commonly host honeypots and research scanners.
3. Sole-engine observation: a finding seen by only one engine is more
   likely to be transient or synthetic than one corroborated by two or
   three.

None of these is conclusive on its own; the model flags findings with two
or more signals as :pyattr:`Finding.is_likely_honeypot`.
"""

from __future__ import annotations

from bantay_eye.models import EngineName, Finding, HoneypotSignal

# ASNs commonly hosting honeypots, research scanners, or short-lived test
# infrastructure. Not exhaustive. Update as the threat-intel landscape
# changes.
KNOWN_HONEYPOT_HOSTING_ASNS: set[int] = {
    14061,  # DigitalOcean
    63949,  # Linode / Akamai Connected Cloud
    16509,  # Amazon AWS (lots of honeypots)
    14618,  # Amazon AWS (alt)
    8075,   # Microsoft Azure
    15169,  # Google Cloud Platform
    20473,  # Choopa / Vultr
    20454,  # Vultr Holdings
    16276,  # OVH SAS (commercial)
    24940,  # Hetzner Online
    39351,  # 31173 Services (research)
    202425, # IP Volume
}


def annotate(finding: Finding) -> Finding:
    """Apply ASN and sole-engine signals to a finding in place."""

    if (
        finding.asn is not None
        and finding.asn in KNOWN_HONEYPOT_HOSTING_ASNS
        and HoneypotSignal.CLOUD_ASN not in finding.honeypot_signals
    ):
        finding.honeypot_signals.append(HoneypotSignal.CLOUD_ASN)

    engines = finding.engines_observed
    if len(engines) == 1 and EngineName.SHODAN in engines:
        # Sole-Shodan observations are common because Shodan crawls more
        # aggressively than Censys or ZoomEye; weight this signal lightly
        # by only marking it when Shodan also tagged the result.
        if HoneypotSignal.SHODAN_TAG in finding.honeypot_signals:
            if HoneypotSignal.SOLE_ENGINE not in finding.honeypot_signals:
                finding.honeypot_signals.append(HoneypotSignal.SOLE_ENGINE)

    return finding
