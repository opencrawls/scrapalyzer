<div align="center">

# Scrapalyzer

**Know how a website serves its data before you write a scraper.**

Scrapalyzer profiles a site and tells you whether it has an API, which anti-bot vendor protects it, whether you need a login or a browser, and where the structured data lives. Every answer comes with the evidence behind it.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#roadmap)
[![Schema](https://img.shields.io/badge/output-scrapalyzer.profile%2F1-6f42c1)](schema/profile-1.json)

[Quickstart](#quickstart) · [CLI](#cli) · [Python API](#python-api) · [Profile format](#the-profile) · [How it works](#how-it-works) · [Roadmap](#roadmap) · [Contributing](#contributing)

</div>

---

## Why

Before you build a scraper you usually spend an hour in DevTools working out the same things for every site: is there a JSON endpoint, is the page server-rendered, is Cloudflare or DataDome in front, and does the content sit behind a login. Scrapalyzer makes a few polite requests, answers those questions, and records how it reached each answer.

Scrapalyzer is the engine behind [OpenCrawls](https://github.com/opencrawls) Targets.

## Example

```console
$ scrapalyzer https://www.ticketmaster.com
ticketmaster.com  ·  2 requests  ·  homepage only

Blocked?    no · homepage 200
Anti-bot    none seen · 12 vendors checked on 2 requests (protection often starts on deeper pages)
Login?      not required for the 1 page(s) fetched
Browser?    no · data embedded as JSON in __NEXT_DATA__ (globalTranslations, initialReduxState, …) [ssr_hydrated, medium confidence]
API?        YES · 33 internal API routes referenced in the page (found in source, not called yet)
              /api/venue/info
              /api/search/events
              /api/resale/{eventId}
              /api/eventinfo/{eventId}
              /api/artist/{artistId}/info
              … 23 more (-v for all)
              likely need login (8): /api/reserve/{eventId}, /api/unlock/{eventId}, …
              Next.js convention: /_next/data/{buildId}/{path}.json serves page data as JSON on pages-router sites
Search URL  https://www.ticketmaster.com/search?q={search_term_string}
Feeds       none linked from the homepage
Markup      JSON-LD WebSite, Organization
robots.txt  93 disallow rules · homepage allowed · crawl-delay none · 0 sitemap(s)
Stack       Next.js · CDN Fastly · CDN Varnish
Pagination  not checked yet (needs a listing page)
```

## Features

| Question | What Scrapalyzer checks |
|---|---|
| **Is there an API?** | Internal REST and GraphQL routes referenced in the page source, with path parameters templated (`/api/event/{eventId}`). Routes that likely need auth are listed separately, and telemetry and asset URLs are filtered out. Also reports RSS/Atom feeds and OpenSearch descriptions. |
| **What anti-bot?** | 12 vendors: Cloudflare, Akamai, DataDome, HUMAN (PerimeterX), Imperva, Kasada, AWS WAF, Queue-it, reCAPTCHA, hCaptcha, Turnstile and Arkose Labs. For each one it separates *CDN/edge only*, *bot management active* and *challenge served*. |
| **Do I need a browser?** | Classifies the page as `static`, `ssr_hydrated` or `csr`, and names the hydration blob (`__NEXT_DATA__`, `__NUXT__`, …) along with its top-level keys. |
| **Do I need a login?** | Login redirects, password forms on the landing page, and paywalls declared in schema.org. |
| **Structured data** | JSON-LD types and properties, microdata, OpenGraph, and the schema.org `SearchAction` URL template. |
| **Stack** | 24 technologies (Next.js, Nuxt, Shopify, Magento, WordPress, Algolia, …), each with a hint on how to get its data, plus 10 CDNs. |
| **Policy** | robots.txt rules, crawl-delay, sitemaps, AI user agents named in robots.txt, terms URL, and security headers. |

## Quickstart

> Scrapalyzer is not on PyPI yet. Install it from source.

```bash
# as a global command
pipx install git+https://github.com/opencrawls/scrapalyzer.git

# or for development
git clone https://github.com/opencrawls/scrapalyzer.git
cd scrapalyzer
uv sync
uv run scrapalyzer https://www.temu.com
```

Requires Python 3.10 or later. The only runtime dependencies are `httpx`, `pydantic` and `protego`.

## CLI

```bash
scrapalyzer https://www.temu.com                        # summary for a human
scrapalyzer https://quotes.toscrape.com -v               # plus every finding, with basis and confidence
scrapalyzer https://www.allbirds.com --json              # profile/1 JSON on stdout
scrapalyzer https://news.ycombinator.com -o hn.json      # write the profile to a file
scrapalyzer https://www.ticketmaster.com --save runs/tm  # keep the raw exchanges
scrapalyzer replay runs/tm                               # re-run detectors offline, no network
scrapalyzer schema                              # print the profile/1 JSON Schema
```

| Flag | Default | Meaning |
|---|---|---|
| `--depth quick\|standard\|deep` | `standard` | Request budget (4 / 25 / 60) |
| `--robots report\|respect` | `report` | `report` records robots.txt decisions, `respect` also denies disallowed URLs |
| `--max-requests N` | per depth | Hard cap on requests |
| `--user-agent UA` | desktop Chrome | User-Agent sent with each request |

The exit code is `0` when the site was analyzed, including when it turned out to be blocked, and `2` on a usage error.

## Python API

```python
from scrapalyzer import analyze_sync, analyze_replay

profile = analyze_sync("https://shopee.com", depth="quick")

for f in profile.findings(section="anti_bot"):
    print(f.id, f.status, f.confidence, f.value)

profile.to_file("shopee.json")

# offline: rerun the detectors over a saved run
profile = analyze_replay("runs/tm")
```

An `async` version, `analyze()`, is also available for use inside an event loop.

## The profile

Output follows the versioned `scrapalyzer.profile/1` format. Its JSON Schema, [schema/profile-1.json](schema/profile-1.json), is generated from the pydantic models, and a test fails if the schema file is out of date.

A profile has three layers, and each layer points to the one below it:

```
exchanges   every HTTP request made: url, status, safe headers, cookie names, policy decision
   ▲
evidence    a fact read from an exchange: a header, a cookie name, a script src, an excerpt
   ▲
findings    a conclusion: status + basis + confidence + the evidence ids that support it
```

```json
{
  "id": "rendering:requires_browser",
  "status": "detected",
  "basis": "inferred",
  "confidence": "medium",
  "value": "no",
  "evidence": ["e4", "e5"],
  "analyzer": "rendering@0.1.0",
  "limitations": ["Inferred from raw HTML only; no rendered comparison"]
}
```

- **basis** says how the conclusion was reached: `declared` (the site says so, e.g. robots.txt or a feed `<link>`), `observed` (seen in traffic) or `inferred` (deduced).
- **confidence** is `high` when two independent kinds of signal agree and `medium` when only one is present.
- **coverage** on every section records what was checked, so a missing finding can be told apart from a check that never ran.
- Every reference in the document must resolve, and validation rejects a profile that points to missing evidence.

## How it works

```
 collectors ──► Gate ──► Store ──► detectors ──► Profile
 (only I/O)   (policy)  (exchanges) (pure functions)
```

1. **Collectors** are the only code that does network I/O, and every request goes through one policy **Gate**. The Gate enforces the request budget, per-host rate limits and crawl-delay, scope (same site only), robots.txt, `Retry-After`, manual redirect following, a 5 MB body cap, and header redaction. Cookie values are never stored, only cookie names.
2. The **Store** keeps each exchange and its body. `--save` writes the Store to disk, and `replay` loads it back.
3. **Detectors** are pure functions over the Store, so they behave the same on a live run and on a replay. A detector that crashes produces an error entry and a `failed` section, and the rest of the profile is still built.
4. **Signatures are data.** Technologies, anti-bot vendors and CDNs live in [signatures.json](src/scrapalyzer/signatures.json), in a subset of the Wappalyzer format. Adding a vendor does not require code changes.

## Scope and ethics

Scrapalyzer **identifies** protections. It does not evade them. It does not solve challenges, rotate fingerprints, fuzz endpoints or call the APIs it finds. It sends a small, rate-limited number of requests, reports what robots.txt says, and can be set to obey it (`--robots respect`). Check that you are allowed to collect a site's data before you scrape it.

## Roadmap

- [x] `profile/1` models and JSON Schema
- [x] Policy Gate, exchange store and offline replay
- [x] Detectors for access, anti-bot, technologies, rendering, structured data, infrastructure and endpoints
- [x] `scrapalyzer` CLI and Python API
- [ ] Declared sources: sitemaps, feeds, OpenSearch, `llms.txt`
- [ ] Sample listing and detail pages: pagination, deeper-page anti-bot checks
- [ ] Summary synthesis (`summary` block, citing findings)
- [ ] Optional browser stage: rendered vs. raw diff, XHR/fetch capture
- [ ] HTTP/2, PyPI release

## Development

```bash
uv sync
uv run pytest                        # full suite, runs offline against local servers
uv run python scripts/write_schema.py  # regenerate schema/profile-1.json after model changes
```

## Contributing

Issues and pull requests are welcome. The easiest way to start is adding a signature: put an entry in [signatures.json](src/scrapalyzer/signatures.json), plus one positive and one negative case in [tests/test_detect.py](tests/test_detect.py). A test checks that every signature has a positive case.

## License

[Apache-2.0](pyproject.toml)
