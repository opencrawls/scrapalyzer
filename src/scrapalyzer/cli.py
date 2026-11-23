"""scrapalyzer command line.

    scrapalyzer https://example.com              human summary
    scrapalyzer https://example.com -v           plus every finding
    scrapalyzer https://example.com --json       profile/1 JSON on stdout (-o FILE to write it)
    scrapalyzer https://example.com --save DIR   also keep the exchanges for offline replay
    scrapalyzer replay DIR                       re-run detectors over a saved run, no network
    scrapalyzer schema                           print the profile/1 JSON Schema

Exit codes: 0 analyzed (a blocked site is still 0), 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

from .api import analyze_replay, analyze_sync
from .engine import BUDGETS
from .models import Profile, json_schema


def _items(p: Profile, section: str, status: str = "detected"):
    return [f for f in p.findings(section=section) if f.status == status]


def summary(p: Profile, show_all: bool = False) -> str:
    """The questions a scraping engineer asks first, each answered from findings (never from raw data)."""
    get = lambda fid: next((f for f in p.findings() if f.id == fid), None)
    ex = lambda eid: p.evidence[eid].excerpt or p.evidence[eid].key
    r = p.run.requests
    pages = sum(1 for x in p.exchanges.values() if x.purpose != "robots" and x.policy == "sent")
    rows: list[tuple[str, str]] = []

    reach, blocked = get("access:reachable"), get("access:blocked")
    if reach is None or reach.status == "unknown":
        rows.append(("Blocked?", "unknown · the homepage request failed (see errors)"))
    elif blocked and blocked.status == "detected":
        rows.append(("Blocked?", f"YES · challenge served with {blocked.value['status']}"))
    elif blocked and blocked.status == "unknown":
        rows.append(("Blocked?", f"maybe · {blocked.value['status']} with no known challenge page"))
    else:
        rows.append(("Blocked?", f"no · homepage {reach.value['status']}"))

    level = {"edge_present": "CDN/edge only, no bot management seen", "bot_management_signal": "bot management active",
             "challenge_observed": "CHALLENGE / CAPTCHA served"}
    bots = _items(p, "anti_bot")
    if bots:
        for i, f in enumerate(bots):
            signals = ", ".join(sorted({ex(e) for e in f.evidence}))[:90]
            rows.append(("Anti-bot" if i == 0 else "", f"{f.value['vendor']} · {level[f.value['level']]} ({signals})"))
    else:
        n = p.anti_bot.coverage.signatures_checked
        rows.append(("Anti-bot", f"none seen · {n} vendors checked on {r.sent} requests (protection often starts on deeper pages)"))

    login = get("access:login_required")
    rows.append(("Login?", "YES · " + login.value["how"] if login and login.status == "detected"
                 else f"not required for the {pages} page(s) fetched"))
    if get("access:paywall"):
        rows.append(("Paywall?", "YES · declared in schema.org (isAccessibleForFree: false)"))

    need, hyd = get("rendering:requires_browser"), get("rendering:hydration")
    if need:
        verdict = "YES" if need.value == "yes" else "no"
        where = ""
        if hyd:
            h = hyd.value[0]
            keys = ", ".join(h.get("top_keys", [])[:6])
            where = f" · data embedded as JSON in {h['name']}" + (f" ({keys})" if keys else "")
        elif need.value == "no":
            where = " · content is in the raw HTML"
        rows.append(("Browser?", f"{verdict}{where} [{p.rendering.mode}, {need.confidence} confidence]"))

    eps = [f for f in _items(p, "endpoints") if f.value.get("source") == "page_source"]
    feeds = [f for f in _items(p, "endpoints") if f.value.get("source") == "link_tag"]
    hints = [f for f in _items(p, "technologies") if (f.value or {}).get("acquisition_hint")]
    if eps:
        data_first = re.compile(r"search|event|product|item|listing|catalog|categor|venue|artist|offer|price|inventory", re.I)
        public = sorted((f for f in eps if f.value["auth"] != "likely"),
                        key=lambda f: (not data_first.search(f.value["url_template"]), len(f.value["url_template"])))
        private = [f for f in eps if f.value["auth"] == "likely"]
        rows.append(("API?", f"YES · {len(eps)} internal API routes referenced in the page (found in source, not called yet)"))
        shown = public if show_all else public[:10]
        rows += [("", "  " + f.value["url_template"]) for f in shown]
        if len(public) > len(shown):
            rows.append(("", f"  … {len(public) - len(shown)} more (-v for all)"))
        if private:
            names = [f.value["url_template"] for f in private]
            rows.append(("", f"  likely need login ({len(private)}): " + ", ".join(names if show_all else names[:4])
                         + ("" if show_all or len(names) <= 4 else ", …")))
    else:
        rows.append(("API?", "none referenced in the page source (browser traffic not checked yet)"))
    rows += [("", f"  {f.value['name']} convention: {f.value['acquisition_hint']['text']}") for f in hints]
    if (f := get("structured_data:search_action")):
        rows.append(("Search URL", f.value["url_template"]))
    rows.append(("Feeds", ", ".join(f"{f.value['format']} {f.value['url_template']}" for f in feeds) or "none linked from the homepage"))

    data = []
    if (f := get("structured_data:jsonld")):
        data.append("JSON-LD " + ", ".join(t["type"] for t in f.value))
    if (f := get("structured_data:microdata")):
        data.append("microdata " + ", ".join(t["type"].rsplit("/", 1)[-1] for t in f.value))
    rows.append(("Markup", " · ".join(data) or "no schema.org markup"))

    if (f := get("access:robots")) and f.value and f.value.get("found"):
        v = f.value
        rows.append(("robots.txt", f"{v['disallow']} disallow rules · homepage {'allowed' if v['home_allowed'] else 'DISALLOWED'}"
                     f" · crawl-delay {v['crawl_delay'] or 'none'} · {v['sitemaps']} sitemap(s)"
                     + (f" · names AI bots: {', '.join(v['ai_agents_named'])}" if v["ai_agents_named"] else "")))
    else:
        rows.append(("robots.txt", "not found (no rules)"))
    stack = [f.value["name"] for f in _items(p, "technologies") if f.basis == "observed"]
    cdn = [f.value["name"] for f in _items(p, "infrastructure") if f.id.startswith("infrastructure:cdn_")]
    rows.append(("Stack", " · ".join(stack + [f"CDN {c}" for c in cdn]) or "not identified"))
    rows.append(("Pagination", "not checked yet (needs a listing page)"))

    head = f"{p.target.site}  ·  {r.sent} requests" + (f" ({r.denied} denied)" if r.denied else "") + "  ·  homepage only"
    out = [head, ""] + [f"{k:<12}{v}" for k, v in rows]
    out += [f"Error       {e.stage}: {e.type} {e.message}" for e in p.errors]
    return "\n".join(out)


def findings(p: Profile) -> str:
    out = []
    for name, s in p.sections().items():
        if not s.items:
            continue
        out.append(f"\n{name}  [{s.coverage.status}]")
        for f in s.items:
            tag = f"{f.basis}/{f.confidence}" if f.basis else ""
            out.append(f"  {f.id:38} {f.status:13} {tag:16} {json.dumps(f.value)[:100]}")
    return "\n".join(out)


def emit(p: Profile, args) -> None:
    if args.output:
        p.to_file(args.output)
    if args.json:
        print(p.to_json())
    elif not args.output or args.verbose:
        print(summary(p, show_all=args.verbose))
        if args.verbose:
            print(findings(p))
    if args.output:
        print(f"wrote {args.output}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = argparse.ArgumentParser(add_help=False)
    out.add_argument("--json", action="store_true", help="print the profile/1 JSON")
    out.add_argument("-o", "--output", help="write the profile/1 JSON to a file")
    out.add_argument("-v", "--verbose", action="store_true", help="list every finding")

    if argv[:1] == ["schema"]:
        print(json.dumps(json_schema(), indent=2))
        return 0
    if argv[:1] == ["replay"]:
        ap = argparse.ArgumentParser(prog="scrapalyzer replay", parents=[out], description="Re-run detectors offline.")
        ap.add_argument("dir")
        args = ap.parse_args(argv[1:])
        emit(analyze_replay(args.dir), args)
        return 0

    ap = argparse.ArgumentParser(prog="scrapalyzer", parents=[out], description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--depth", choices=list(BUDGETS), default="standard")
    ap.add_argument("--robots", choices=["report", "respect"], default="report")
    ap.add_argument("--max-requests", type=int)
    ap.add_argument("--user-agent")
    ap.add_argument("--save", metavar="DIR", help="keep the exchanges for `scrapalyzer replay`")
    args = ap.parse_args(argv)
    kw = {k: v for k, v in dict(depth=args.depth, robots=args.robots, max_requests=args.max_requests,
                                user_agent=args.user_agent, save=args.save).items() if v is not None}
    emit(analyze_sync(args.url, **kw), args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
