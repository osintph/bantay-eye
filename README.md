# Bantay-Eye

> Defensive internet exposure survey utility. Part of the [OSINT-PH](https://blog.osintph.info) tool suite.

Bantay-Eye runs the [Operation Liwanag](https://blog.osintph.info) methodology end-to-end: it queries Shodan, Censys, and ZoomEye for a country's exposed attack surface across seven categories, deduplicates findings across engines, flags likely honeypots, and generates ready-to-send disclosure templates for NCERT-PH, the asset owner, and the National Privacy Commission.

It does not include exploit code, does not connect to discovered devices, and does not enumerate targets in any way beyond what the three upstream search engines already index publicly.

`Bantay` is Tagalog for "watch" or "guard". `Eye` is a deliberate nod to [HackingPassion's](https://hackingpassion.com) "Eye" suite, on whose practitioner-first publishing style this tool's documentation is modelled.

## What it does

- **Seven categories of exposure**: ICS/SCADA, government, remote access, telecom, banking (reserved), IoT, and cloud-hosted misconfigurations.
- **Three engines, one query layer**: every query is expressed for all three engines using the validated syntax for each (Shodan, Censys Search v2 with `host.` prefix, ZoomEye REST with quoted values and `&&`).
- **Cross-engine deduplication**: findings on the same `(ip, port, category)` are merged into one record with the union of sources.
- **Honeypot annotation**: Shodan's own `honeypot` tag, ASN matching against known commercial cloud honeypot ranges, and single-engine observation are surfaced as signals.
- **Polite rate limiting**: configurable per-engine minimum delay between calls so you do not torch your free-tier quotas.
- **Disclosure templates**: Jinja-rendered NCERT-PH, owner-direct, and NPC notification templates pre-filled from finding data.
- **JSON output**: every survey writes a structured report you can diff between runs.

## What it does not do

- It does not connect to discovered devices.
- It does not query device registers, attempt authentication, or trigger any service.
- It does not include CVE lookups, exploit code, or vulnerability proof-of-concepts.
- It does not enumerate targets by name. The country filter and category queries are the only selectors.

The intent is captured in the LICENSE file: a defensive survey utility for responsible disclosure work. Use it for that.

## Requirements

- Python 3.10 or newer
- API access to at least one of the three search engines

### API tiers, with prices

| Engine | Free-tier viability | What you actually need |
| --- | --- | --- |
| **Shodan** | Limited. The truly free tier restricts searches significantly. | A one-time **Membership** purchase (~$59 USD, often discounted to ~$5 during Black Friday) gives 100 result pages per query, 10,000 result credits per month, and is the practical "working tier" for survey work. Tag filters (`tag:ics`, etc.) require enterprise and are not used by Bantay-Eye for that reason. |
| **Censys** | Genuinely free. | A free account gives 250 search queries per month, sufficient for several full Bantay-Eye runs. Sign up at [search.censys.io](https://search.censys.io). |
| **ZoomEye** | Genuinely free. | A free account gives ~10,000 query points per month. Sign up at [zoomeye.org](https://zoomeye.org). |

You can run Bantay-Eye with any subset of engines configured; engines without credentials are skipped silently. Recommended minimum: Censys + ZoomEye, which are both truly free.

## Installation

### Option A: pipx (recommended for end users)

```
pipx install git+https://github.com/osintph/bantay-eye.git
```

### Option B: pip in a virtualenv (recommended for development)

```
git clone https://github.com/osintph/bantay-eye.git
cd bantay-eye
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Option C: direct install from GitHub

```
pip install --user git+https://github.com/osintph/bantay-eye.git
```

## Quickstart

```
# 1. Create a starter config in the current directory
bantay-eye init

# 2. Edit bantay_eye.toml and add your API keys
vi bantay_eye.toml

# 3. Verify your installation and credentials
bantay-eye doctor

# 4. List available categories
bantay-eye categories

# 5. Run a survey of all categories with queries defined
bantay-eye survey --all

# 6. Or run a single category, e.g. ICS
bantay-eye survey --category ics

# 7. Generate a disclosure template for one finding
bantay-eye disclose 203.0.113.42-502-ics \
    --report findings/survey-20260617T093000.json \
    --template ncert \
    --output disclosures/ncert-203.0.113.42.md
```

## Configuration

Bantay-Eye looks for `bantay_eye.toml` in this order:

1. The path passed to `--config`.
2. `./bantay_eye.toml` in the current working directory.
3. The platform user-config directory (run `bantay-eye config-path` to see).

Run `bantay-eye init --location user` to drop a starter config in the user-config directory if you prefer system-wide settings.

See `bantay_eye.toml.example` for every available knob.

## Country support

The default country is the Philippines (`PH`). The tool is country-agnostic and ships with name mappings for the rest of ASEAN, the major East-Asian economies, Australia, New Zealand, the US, and the UK. Add new countries to `COUNTRY_NAMES` in `src/bantay_eye/categories.py` and they immediately work across all three engines.

## Output structure

```
findings/
├── survey-20260617T093000.json    # full survey report
disclosures/
├── ncert-203.0.113.42.md          # rendered disclosure templates
├── owner-198.51.100.7.md
└── npc-198.51.100.7.md
```

## Methodology

The seven categories and their queries are described in detail in the Operation Liwanag post on [blog.osintph.info](https://blog.osintph.info). Read that first; this tool is the operationalisation of that essay, not a replacement for understanding why the queries are what they are.

## Contributing

Pull requests welcome on:

- New country mappings
- New categories of exposure (the schema is open; add to `categories.py`)
- Better honeypot heuristics
- Translations of the disclosure templates (Filipino, Bahasa Indonesia, Vietnamese welcome)
- ASN mappings for new commercial cloud providers

Pull requests will be declined for:

- Anything that adds active connection to discovered devices
- Vulnerability scanning, fingerprinting, or fuzzing
- Credential enumeration
- Anything that makes this useful as an offensive tool

## License

MIT, with an ethical-use notice. See LICENSE.

## Acknowledgements

- The [Shodan](https://shodan.io), [Censys](https://censys.io), and [ZoomEye](https://zoomeye.org) teams for the underlying data.
- [HackingPassion](https://hackingpassion.com) for the documentation style and the practitioner-first publishing tradition.
- NCERT-PH for accepting disclosures even when they cannot publicly acknowledge them.
