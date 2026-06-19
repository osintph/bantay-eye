"""The seven Operation Liwanag categories with validated multi-engine queries.

Each category contains query strings for Shodan, Censys, and ZoomEye. The
{country} placeholder is rendered against the configured ISO 3166-1 alpha-2
country code (lowercase for ZoomEye name resolution, uppercase for Shodan,
full name for Censys).

These queries were validated against live Shodan, Censys, and ZoomEye
accounts as part of the Operation Liwanag survey methodology. See
https://blog.osintph.info for the underlying article.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Map ISO country codes to the country name Censys and ZoomEye expect.
# Extend as you survey new geographies.
COUNTRY_NAMES: dict[str, str] = {
    "PH": "Philippines",
    "ID": "Indonesia",
    "MY": "Malaysia",
    "SG": "Singapore",
    "TH": "Thailand",
    "VN": "Vietnam",
    "JP": "Japan",
    "KR": "South Korea",
    "TW": "Taiwan",
    "HK": "Hong Kong",
    "AU": "Australia",
    "NZ": "New Zealand",
    "US": "United States",
    "GB": "United Kingdom",
}


@dataclass
class Query:
    """A single query, expressed for one engine."""

    label: str
    shodan: str | None = None
    censys: str | None = None
    zoomeye: str | None = None


@dataclass
class Category:
    """A category of exposure with multiple queries across engines."""

    slug: str
    title: str
    description: str
    disclosure_path: str
    queries: list[Query] = field(default_factory=list)


def render(template: str, country_code: str) -> str:
    """Substitute country placeholders in a query template."""

    name = COUNTRY_NAMES.get(country_code.upper(), country_code)
    return template.format(
        country=country_code.upper(),
        country_name=name,
    )


CATEGORIES: list[Category] = [
    Category(
        slug="ics",
        title="Industrial Control Systems and SCADA",
        description=(
            "Modbus, Siemens S7, BACnet, and other industrial protocol "
            "endpoints reachable from the public internet."
        ),
        disclosure_path="NCERT-PH first, then asset owner if response window allows.",
        queries=[
            Query(
                label="Modbus TCP",
                shodan="port:502 country:{country}",
                censys='host.services.port: 502 and host.location.country: "{country_name}"',
                zoomeye='port="502" && country="{country_name}"',
            ),
            Query(
                label="Siemens S7",
                shodan="port:102 country:{country}",
                censys='host.services.port: 102 and host.location.country: "{country_name}"',
                zoomeye='port="102" && country="{country_name}"',
            ),
            Query(
                label="BACnet",
                shodan="port:47808 country:{country}",
                censys='host.services.port: 47808 and host.location.country: "{country_name}"',
                zoomeye='port="47808" && country="{country_name}"',
            ),
        ],
    ),
    Category(
        slug="government",
        title="Government infrastructure",
        description=(
            "Portals, admin panels, file shares, and management interfaces "
            "operated by government entities (default: .gov.{country} zone)."
        ),
        disclosure_path="NCERT-PH first, then the agency directly if response window allows.",
        queries=[
            Query(
                label="Government cert subject (Shodan)",
                shodan="ssl.cert.subject.cn:*.gov.{country_lower}",
                censys='host.services.cert.names: ".gov.{country_lower}"',
                zoomeye='ssl="gov.{country_lower}" && country="{country_name}"',
            ),
            Query(
                label="Government cert on non-443 ports",
                shodan="ssl.cert.subject.cn:*.gov.{country_lower} port:!443",
                censys=None,  # subsumed by names: substring match
                zoomeye=None,
            ),
            Query(
                label="Government login titles",
                shodan='http.title:"Sign in" hostname:.gov.{country_lower}',
                censys=None,
                zoomeye=None,
            ),
        ],
    ),
    Category(
        slug="remote_access",
        title="Remote access infrastructure",
        description=(
            "RDP, VDI gateways, and webmail endpoints. Sector-agnostic; "
            "do not infer BPO presence from these protocols alone."
        ),
        disclosure_path="Owner directly; NCERT-PH on escalation.",
        queries=[
            Query(
                label="RDP",
                shodan="port:3389 country:{country}",
                censys='host.services.port: 3389 and host.location.country: "{country_name}"',
                zoomeye='port="3389" && country="{country_name}"',
            ),
            Query(
                label="VMware Horizon",
                shodan='port:443 product:"VMware Horizon" country:{country}',
                censys='host.services.software.product: "VMware Horizon" and host.location.country: "{country_name}"',
                zoomeye='app="VMware Horizon" && country="{country_name}"',
            ),
            Query(
                label="Citrix",
                shodan='port:443 product:"Citrix" country:{country}',
                censys='host.services.software.product: "Citrix" and host.location.country: "{country_name}"',
                zoomeye='app="Citrix" && country="{country_name}"',
            ),
            Query(
                label="Outlook Web App",
                shodan='http.title:"Outlook Web App" country:{country}',
                censys='host.services.http.response.html_title: "Outlook Web App" and host.location.country: "{country_name}"',
                zoomeye='title="Outlook Web App" && country="{country_name}"',
            ),
        ],
    ),
    Category(
        slug="telecom",
        title="Telecommunications infrastructure",
        description=(
            "Carrier CPE, BMC/IPMI, telnet, and SIP endpoints attributable "
            "to telco operators."
        ),
        disclosure_path="Operator NOC directly; NCERT-PH on escalation.",
        queries=[
            Query(
                label="MikroTik RouterOS",
                shodan='country:{country} product:"RouterOS"',
                censys='host.services.software.product: "RouterOS" and host.location.country: "{country_name}"',
                zoomeye='app="RouterOS" && country="{country_name}"',
            ),
            Query(
                label="Huawei vendor devices",
                shodan='country:{country} product:"Huawei"',
                censys='host.services.software.vendor: "Huawei" and host.location.country: "{country_name}"',
                zoomeye='app="Huawei" && country="{country_name}"',
            ),
            Query(
                label="Telnet",
                shodan="port:23 country:{country}",
                censys='host.services.port: 23 and host.location.country: "{country_name}"',
                zoomeye='port="23" && country="{country_name}"',
            ),
            Query(
                label="SIP",
                shodan="port:5060 country:{country}",
                censys='host.services.port: 5060 and host.location.country: "{country_name}"',
                zoomeye='port="5060" && country="{country_name}"',
            ),
        ],
    ),
    Category(
        slug="banking",
        title="Banking and fintech",
        description=(
            "Reserved category. The methodology applies but no targeted "
            "queries ship by default; banking-sector disclosures route "
            "through BSP Cybersecurity Surveillance, not NCERT-PH."
        ),
        disclosure_path="BSP Cybersecurity Surveillance Division via the supervised entity's compliance officer.",
        queries=[],  # deliberately empty
    ),
    Category(
        slug="iot",
        title="Building management and IoT",
        description=(
            "IP cameras, DVRs, building automation controllers, and "
            "consumer-grade IoT devices."
        ),
        disclosure_path="Owner directly; National Privacy Commission if personal data is exposed.",
        queries=[
            Query(
                label="RTSP cameras",
                shodan="port:554 country:{country}",
                censys='host.services.port: 554 and host.location.country: "{country_name}"',
                zoomeye='port="554" && country="{country_name}"',
            ),
            Query(
                label="Hikvision",
                shodan='product:"Hikvision" country:{country}',
                censys='host.services.software.product: "Hikvision" and host.location.country: "{country_name}"',
                zoomeye='app="Hikvision" && country="{country_name}"',
            ),
            Query(
                label="Dahua",
                shodan='product:"Dahua" country:{country}',
                censys='host.services.software.product: "Dahua" and host.location.country: "{country_name}"',
                zoomeye='app="Dahua" && country="{country_name}"',
            ),
        ],
    ),
    Category(
        slug="cloud",
        title="Cloud-hosted misconfigurations",
        description=(
            "Exposed databases and orchestration APIs hosted by entities "
            "in the survey country. Note: S3/Azure Blob/GCS bucket "
            "enumeration requires purpose-built tools and is out of scope."
        ),
        disclosure_path="Owner directly; National Privacy Commission if personal data is exposed.",
        queries=[
            Query(
                label="MongoDB",
                shodan='port:27017 country:{country} product:"MongoDB"',
                censys='host.services.software.product: "MongoDB" and host.location.country: "{country_name}"',
                zoomeye='app="MongoDB" && country="{country_name}"',
            ),
            Query(
                label="Elasticsearch",
                shodan='port:9200 country:{country} product:"Elastic"',
                censys='host.services.software.product: "Elasticsearch" and host.location.country: "{country_name}"',
                zoomeye='app="Elasticsearch" && country="{country_name}"',
            ),
            Query(
                label="Redis",
                shodan='port:6379 country:{country} product:"Redis"',
                censys='host.services.software.product: "Redis" and host.location.country: "{country_name}"',
                zoomeye='app="Redis" && country="{country_name}"',
            ),
            Query(
                label="Docker API",
                shodan="port:2375 country:{country}",
                censys='host.services.port: 2375 and host.location.country: "{country_name}"',
                zoomeye='port="2375" && country="{country_name}"',
            ),
        ],
    ),
]


def get_category(slug: str) -> Category:
    """Look up a category by slug. Raises KeyError if unknown."""

    for cat in CATEGORIES:
        if cat.slug == slug:
            return cat
    raise KeyError(f"Unknown category: {slug}")


def render_query(template: str, country_code: str) -> str:
    """Apply country substitutions, including lowercase variant for TLDs."""

    name = COUNTRY_NAMES.get(country_code.upper(), country_code)
    return template.format(
        country=country_code.upper(),
        country_lower=country_code.lower(),
        country_name=name,
    )
