"""Detectors: pure functions over a Store. No I/O, never raise (a failure becomes an error and a failed section).

Each detector reads exchanges (and earlier detectors' results on the Board) and returns a Section. Evidence goes
through Board.cite so every finding points at exchange bytes. Signatures are data, in signatures.json.
"""
from __future__ import annotations

import hashlib
import json
import re
from functools import cached_property
from html.parser import HTMLParser
from importlib.resources import files
from typing import Any, Callable

from protego import Protego

from .engine import Record, Store
from .models import Coverage, Error, Evidence, Finding, RenderingSection, Section

VERSION = "0.1.0"
SIGNATURES: dict[str, Any] = json.loads(files("scrapalyzer").joinpath("signatures.json").read_text())
LEVELS = ("edge_present", "bot_management_signal", "challenge_observed")
HYDRATION = {  # name -> regex on raw HTML (script ids are handled by Page.json_scripts)
    "self.__next_f": r"self\.__next_f\.push", "__NUXT__": r"window\.__NUXT__\s*=", "__APOLLO_STATE__": r"__APOLLO_STATE__\s*=",
    "__INITIAL_STATE__": r"window\.__INITIAL_STATE__\s*=", "__PRELOADED_STATE__": r"window\.__PRELOADED_STATE__\s*=",
}
APP_ROOTS = {"root", "app", "__next", "__nuxt", "___gatsby", "svelte"}
LOGIN_PATH = re.compile(r"/(log-?in|sign-?in|signin|auth|account/login|users/sign_in|sso)(/|\?|$)", re.I)
AI_AGENTS = ("gptbot", "chatgpt-user", "oai-searchbot", "ccbot", "claudebot", "anthropic-ai", "claude-web",
             "google-extended", "perplexitybot", "bytespider", "applebot-extended", "meta-externalagent")
# API routes referenced in page source: quoted, root-relative or absolute, under an API-looking prefix
API_REF = re.compile(r'''["'`]((?:https?:)?//[a-z0-9.-]+)?(/(?:api|graphql|gql|rest|ajax|v\d+|_next/data|wp-json|services|json)'''
                     r'''(?:[/?.][^"'`\s<>\\]*)?)["'`]''', re.I)
TELEMETRY = re.compile(r"/(errors?|log|logs|track|tracking|metrics|analytics|beacon|collect|page/view|events?/log|rum|csp-report)(/|$)", re.I)
AUTH_HINT = re.compile(r"/(user|users|me|account|accounts|cart|checkout|orders?|reserve|login|logout|token|unlock\w*|passbook|barcode|wallet|payment)s?(/|$|\?)", re.I)
FEED_TYPES = {"application/rss+xml": "rss", "application/atom+xml": "atom", "application/feed+json": "json_feed", "application/json": "json"}
# ponytail: fixed text thresholds; calibrate against the OpenCrawls corpus in slice 7
MIN_TEXT = 1500


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


class Page(HTMLParser):
    """One pass over an HTML document, keeping only what detectors need."""

    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.script_srcs: list[str] = []
        self.inline_scripts = 0
        self.json_scripts: list[tuple[str, str, str]] = []  # (type, id, text)
        self.meta: dict[str, str] = {}
        self.links: list[tuple[str, str]] = []  # (href, text)
        self.link_tags: list[dict[str, str]] = []  # <link rel type href title>
        self.itemtypes: list[str] = []
        self.password_inputs = self.forms = self.text_chars = 0
        self.empty_roots: list[str] = []
        self._script: dict[str, str] | None = None
        self._buf: list[str] = []
        self._skip = 0  # inside style/noscript/template
        self._root: str | None = None
        self._root_seen = False
        self._a: list[Any] | None = None
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        a = {k: v or "" for k, v in attrs}
        if self._root:
            self._root_seen = True
        if tag == "script":
            if a.get("src"):
                self.script_srcs.append(a["src"])
            self._script, self._buf = a, []
        elif tag in ("style", "noscript", "template"):
            self._skip += 1
        elif tag == "meta":
            key = a.get("name") or a.get("property") or a.get("itemprop")
            if key and "content" in a:
                self.meta.setdefault(key.lower(), a["content"])
        elif tag == "link" and a.get("href"):
            self.link_tags.append({k: a.get(k, "") for k in ("rel", "type", "href", "title")})
        elif tag == "a" and a.get("href"):
            self._a = [a["href"], ""]
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "div" and a.get("id") in APP_ROOTS and not self._root:
            self._root, self._root_seen = a["id"], False
        if a.get("itemtype"):
            self.itemtypes += a["itemtype"].split()

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            t = self._script.get("type", "").lower()
            text = "".join(self._buf)
            if "json" in t:
                self.json_scripts.append((t, self._script.get("id", ""), text))
            elif not self._script.get("src") and text.strip():
                self.inline_scripts += 1
            self._script = None
        elif tag in ("style", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._a:
            self.links.append((self._a[0], self._a[1].strip()))
            self._a = None
        elif tag == "div" and self._root:
            if not self._root_seen:
                self.empty_roots.append(self._root)
            self._root = None

    def handle_data(self, data):
        if self._script is not None:
            self._buf.append(data)
            return
        if self._skip:
            return
        stripped = data.strip()
        if stripped:
            self.text_chars += len(stripped)
            if self._root:
                self._root_seen = True
            if self._a is not None:
                self._a[1] += " " + stripped

    @cached_property
    def jsonld(self) -> tuple[list[dict], int]:
        """(nodes, invalid_blocks); @graph and top-level arrays are flattened."""
        nodes, invalid = [], 0
        for t, _, text in self.json_scripts:
            if t != "application/ld+json":
                continue
            try:
                data = json.loads(text)
            except ValueError:
                invalid += 1
                continue
            stack = data if isinstance(data, list) else [data]
            while stack:
                n = stack.pop(0)
                if isinstance(n, dict):
                    nodes.append(n)
                    stack += n.get("@graph", []) if isinstance(n.get("@graph"), list) else []
        return nodes, invalid


def decode(record: Record) -> str:
    ct = record.exchange.content_type or ""
    m = re.search(r"charset=([\w-]+)", ct, re.I)
    try:
        return record.body.decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        return record.body.decode("utf-8", "replace")


class Board:
    """Shared state for one detection pass: evidence, sections, errors, parsed pages."""

    def __init__(self, store: Store):
        self.store = store
        self.evidence: dict[str, Evidence] = {}
        self.sections: dict[str, Section] = {}
        self.errors: list[Error] = []
        self.challenged: set[str] = set()  # exchange ids where a challenge signature matched
        self._pages: dict[str, Page | None] = {}
        self._text: dict[str, str] = {}

    def cite(self, xid: str | None, location: str, key: str | None = None, excerpt: str | None = None,
             matcher: str | None = None) -> str:
        ev = Evidence(exchange=xid, location=location, key=key, excerpt=excerpt[:200] if excerpt else None,
                      matcher=matcher, observed_at=self.store.records[xid].exchange.at if xid else None)
        for eid, existing in self.evidence.items():
            if existing == ev:
                return eid
        eid = f"e{len(self.evidence) + 1}"
        self.evidence[eid] = ev
        return eid

    def sent(self) -> list[str]:
        return [x for x, r in self.store.records.items() if r.exchange.policy == "sent" and r.exchange.status is not None]

    def html(self) -> list[str]:
        return [x for x in self.sent() if "html" in (self.store.records[x].exchange.content_type or "")
                and self.store.records[x].body]

    def home(self) -> str | None:
        return next((x for x, r in self.store.records.items() if r.exchange.purpose == "homepage"), None)

    def robots(self) -> str | None:
        return next((x for x, r in self.store.records.items() if r.exchange.purpose == "robots"), None)

    def text(self, xid: str) -> str:
        if xid not in self._text:
            self._text[xid] = decode(self.store.records[xid])
        return self._text[xid]

    def page(self, xid: str) -> Page | None:
        if xid not in self._pages:
            self._pages[xid] = Page(self.text(xid)) if xid in self.html() else None
        return self._pages[xid]


# --- signature matching, shared by technologies, anti_bot and cdn

def match(board: Board, xid: str, spec: dict, sig_id: str) -> list[tuple[str, str]]:
    """Return (kind, evidence id) for every signal of `spec` present in exchange `xid`."""
    r, hits = board.store.records[xid], []
    for i, (name, value) in enumerate(spec.get("headers", {}).items()):
        for k, v in r.headers:
            if re.fullmatch(name, k, re.I) and re.search(value, v, re.I):
                hits.append(("headers", board.cite(xid, "header", k, f"{k}: {v[:80]}", f"sig:{sig_id}/header#{i}")))
                break
    names = r.exchange.set_cookie_names
    for i, pat in enumerate(spec.get("cookies", [])):
        if hit := next((n for n in names if re.search(pat, n, re.I)), None):
            hits.append(("cookies", board.cite(xid, "cookie_name", hit, hit, f"sig:{sig_id}/cookie#{i}")))
    if r.exchange.status in spec.get("status", []):
        hits.append(("status", board.cite(xid, "header", ":status", str(r.exchange.status), f"sig:{sig_id}/status")))
    page = board.page(xid)
    if page is None:
        return hits
    for i, pat in enumerate(spec.get("scriptSrc", [])):
        if hit := next((s for s in page.script_srcs if re.search(pat, s, re.I)), None):
            hits.append(("scriptSrc", board.cite(xid, "dom", "script[src]", hit, f"sig:{sig_id}/scriptSrc#{i}")))
    for i, (name, value) in enumerate(spec.get("meta", {}).items()):
        if name in page.meta and re.search(value, page.meta[name], re.I):
            hits.append(("meta", board.cite(xid, "dom", f"meta[name={name}]", page.meta[name][:80], f"sig:{sig_id}/meta#{i}")))
    text = board.text(xid)
    for i, pat in enumerate(spec.get("html", [])):
        if m := re.search(pat, text, re.I):
            hits.append(("html", board.cite(xid, "body", "html", m.group(0)[:120], f"sig:{sig_id}/html#{i}")))
    return hits


def band(hits: list[tuple[str, str]]) -> str:
    """Two independent kinds of signal -> high, one -> medium (blueprint §9 rule 4)."""
    return "high" if len({k for k, _ in hits}) >= 2 else "medium"


def coverage(board: Board, surfaces: list[str], **kw) -> Coverage:
    return Coverage(status="complete" if surfaces else "failed", surfaces=surfaces, methods=["http"],
                    reason=None if surfaces else "no usable response", **kw)


def finding(section: str, name: str, status: str, value: Any = None, evidence: list[str] = (), basis: str | None = None,
            confidence: str | None = None, limitations: list[str] = ()) -> Finding:
    return Finding(id=f"{section}:{name}", status=status, basis=basis, confidence=confidence, value=value,
                   evidence=sorted(set(evidence), key=lambda e: int(e[1:])), analyzer=f"{section}@{VERSION}",
                   limitations=list(limitations))


# --- detectors

def technologies(board: Board) -> Section:
    sigs, items, found = SIGNATURES["technologies"], [], {}
    pages = board.html()
    for name, spec in sigs.items():
        hits = [h for x in board.sent() for h in match(board, x, spec, slug(name))]
        if hits:
            found[name] = hits
            value = {"name": name, "categories": spec["cats"]}
            if "hint" in spec:
                value["acquisition_hint"] = {"text": spec["hint"], "basis": "inferred"}
            items.append(finding("technologies", slug(name), "detected", value, [e for _, e in hits], "observed", band(hits)))
    for name, hits in list(found.items()):
        for implied in sigs[name].get("implies", []):
            if implied not in found:
                found[implied] = []
                items.append(finding("technologies", slug(implied), "detected",
                                     {"name": implied, "categories": sigs[implied]["cats"], "implied_by": name},
                                     [e for _, e in hits], "inferred", "medium"))
    return Section(coverage=coverage(board, pages, signatures_checked=len(sigs)), items=items)


def anti_bot(board: Board) -> Section:
    sigs, items = SIGNATURES["anti_bot"], []
    surfaces = board.sent()
    for vendor, levels in sigs.items():
        seen: dict[str, list[str]] = {}
        evidence: list[str] = []
        all_hits: list[tuple[str, str]] = []
        for level in LEVELS:
            for x in surfaces:
                hits = match(board, x, levels.get(level, {}), f"{slug(vendor)}/{level}")
                if "status" in levels.get(level, {}) and len(hits) < 2:  # a status code alone proves nothing
                    hits = []
                if hits:
                    seen.setdefault(level, []).append(x)
                    evidence += [e for _, e in hits]
                    all_hits += hits
                    if level == "challenge_observed":
                        board.challenged.add(x)
        if seen:
            top = max(seen, key=LEVELS.index)
            items.append(finding("anti_bot", slug(vendor), "detected",
                                 {"vendor": vendor, "level": top, "surfaces": sorted(set(sum(seen.values(), [])), key=lambda x: int(x[1:])),
                                  "levels": {lv: seen[lv] for lv in LEVELS if lv in seen}},
                                 evidence, "observed", band(all_hits)))
    n = len(surfaces)
    cov = coverage(board, surfaces, signatures_checked=len(sigs),
                   limitations=[f"Behavioral protections may not show on {n} low-rate request{'s' * (n != 1)}"])
    return Section(coverage=cov, items=items)


def _hydration(board: Board, xid: str) -> list[dict]:
    page, text, out = board.page(xid), board.text(xid), []
    for t, sid, body in page.json_scripts:
        if t == "application/ld+json" or not sid:
            continue
        entry: dict[str, Any] = {"name": sid}
        try:
            data = json.loads(body)
            if sid == "__NEXT_DATA__":
                data = data.get("props", {}).get("pageProps", data)
            if isinstance(data, dict):
                entry["top_keys"] = sorted(data)[:30]
        except ValueError:
            entry["parse_error"] = True
        entry["bytes"] = len(body)
        out.append(entry)
    out += [{"name": name} for name, pat in HYDRATION.items() if re.search(pat, text)]
    return out


def rendering(board: Board) -> RenderingSection:
    home = board.home()
    page = board.page(home) if home else None
    if page is None:
        return RenderingSection(coverage=Coverage(status="failed", methods=["http"], reason="no HTML homepage"), mode="unknown")
    hydration = _hydration(board, home)
    rich = page.text_chars >= MIN_TEXT
    mode = "ssr_hydrated" if hydration and rich else "csr" if page.empty_roots or not rich else "static"
    stats = (f"{page.text_chars:,} visible text chars, {len(page.script_srcs) + page.inline_scripts} scripts, "
             f"{'empty app root #' + page.empty_roots[0] if page.empty_roots else 'no empty app root'}")
    ev = [board.cite(home, "body", "visible_text", stats)]
    items = []
    if hydration:
        hev = board.cite(home, "dom", "script#" + hydration[0]["name"], ", ".join(h["name"] for h in hydration))
        items.append(finding("rendering", "hydration", "detected", hydration, [hev], "observed", "high"))
        ev.append(hev)
    if mode == "csr" and not hydration:
        need, conf = "yes", "medium"
    elif mode == "csr":
        need, conf = "no", "low"  # data may already be in the hydration payload
    else:
        need, conf = "no", "medium"
    items.insert(0, finding("rendering", "requires_browser", "detected", need, ev, "inferred", conf,
                            ["Inferred from raw HTML only; no rendered comparison"]))
    return RenderingSection(coverage=Coverage(status="partial", surfaces=[home], methods=["http"], reason="browser stage disabled"),
                            mode=mode, items=items)


def structured_data(board: Board) -> Section:
    pages = board.html()
    types: dict[str, dict[str, Any]] = {}
    og: dict[str, Any] = {}
    micro: dict[str, list[str]] = {}
    search, invalid, ev = None, 0, {"jsonld": [], "og": [], "micro": [], "search": []}
    for x in pages:
        page = board.page(x)
        nodes, bad = page.jsonld
        invalid += bad
        for n in nodes:
            for t in (n.get("@type") if isinstance(n.get("@type"), list) else [n.get("@type")]):
                if not isinstance(t, str):
                    continue
                entry = types.setdefault(t, {"type": t, "properties": set(), "pages": set()})
                entry["properties"] |= {k for k in n if not k.startswith("@")}
                entry["pages"].add(x)
            action = n.get("potentialAction")
            for a in action if isinstance(action, list) else [action]:
                if isinstance(a, dict) and a.get("@type") == "SearchAction":
                    target = a.get("target")
                    template = target.get("urlTemplate") if isinstance(target, dict) else target
                    if isinstance(template, str) and search is None:
                        search = {"url_template": template, "query_input": a.get("query-input")}
                        ev["search"].append(board.cite(x, "body", "ld+json SearchAction.target", template))
        if nodes:
            ev["jsonld"].append(board.cite(x, "body", "script[type=application/ld+json]",
                                           ", ".join(sorted({str(n.get('@type')) for n in nodes}))))
        props = sorted(k for k in page.meta if k.startswith(("og:", "twitter:")))
        if props:
            og.setdefault("properties", set()).update(props)
            if "og:type" in page.meta:
                og.setdefault("types", set()).add(page.meta["og:type"])
            ev["og"].append(board.cite(x, "dom", "meta[property^=og:]", ", ".join(props)[:200]))
        for t in page.itemtypes:
            micro.setdefault(t, []).append(x)
        if page.itemtypes:
            ev["micro"].append(board.cite(x, "dom", "[itemtype]", ", ".join(sorted(set(page.itemtypes)))))
    items = []
    if types:
        value = [{"type": t["type"], "properties": sorted(t["properties"]), "pages": sorted(t["pages"])} for t in types.values()]
        lim = [f"{invalid} JSON-LD block(s) failed to parse"] if invalid else []
        items.append(finding("structured_data", "jsonld", "detected", value, ev["jsonld"], "declared", "high", lim))
    if micro:
        items.append(finding("structured_data", "microdata", "detected",
                             [{"type": t, "pages": sorted(set(p))} for t, p in micro.items()], ev["micro"], "declared", "high"))
    if og:
        items.append(finding("structured_data", "opengraph", "detected", {k: sorted(v) for k, v in og.items()},
                             ev["og"], "declared", "high"))
    if search:
        items.append(finding("structured_data", "search_action", "detected", search, ev["search"], "declared", "high"))
    return Section(coverage=coverage(board, pages), items=items)


def infrastructure(board: Board) -> Section:
    home = board.home()
    if not home or home not in board.sent():
        return Section(coverage=Coverage(status="failed", methods=["http"], reason="no homepage response"))
    r, items = board.store.records[home], []
    h = dict(r.headers)
    for name, spec in SIGNATURES["cdn"].items():
        if hits := match(board, home, spec, f"cdn/{slug(name)}"):
            items.append(finding("infrastructure", "cdn_" + slug(name), "detected", {"name": name},
                                 [e for _, e in hits], "observed", band(hits)))
    http = {"version": r.exchange.http_version, "h3_advertised": "h3" in h.get("alt-svc", ""),
            "compression": h.get("content-encoding"), "cache_control": h.get("cache-control")}
    items.append(finding("infrastructure", "http", "detected", http,
                         [board.cite(home, "header", ":version", f"{r.exchange.http_version}, {h.get('content-encoding') or 'identity'}")],
                         "observed", "high"))
    chain = r.exchange.redirects
    if chain:
        items.append(finding("infrastructure", "redirects", "detected",
                             {"count": len(chain), "chain": chain + [r.exchange.url],
                              "https_upgrade": chain[0].startswith("http:") and r.exchange.url.startswith("https:")},
                             [board.cite(home, "url", "redirects", " -> ".join(chain + [r.exchange.url]))], "observed", "high"))
    sec = {k: k in h for k in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")}
    items.append(finding("infrastructure", "security_headers", "detected", sec,
                         [board.cite(home, "header", "security", ", ".join(k for k, v in sec.items() if v) or "none")],
                         "observed", "high"))
    return Section(coverage=coverage(board, [home], signatures_checked=len(SIGNATURES["cdn"])), items=items)


def _robots(board: Board) -> Finding:
    xid = board.robots()
    r = board.store.records.get(xid) if xid else None
    if r is None or r.exchange.status is None:
        return finding("access", "robots", "unknown", limitations=["robots.txt could not be fetched"])
    if not 200 <= r.exchange.status < 300:
        return finding("access", "robots", "not_detected", {"found": False, "status": r.exchange.status},
                       [board.cite(xid, "header", ":status", str(r.exchange.status))])
    text = decode(r).lstrip("﻿")
    lines = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    field = lambda name: [ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith(name + ":")]
    rules = Protego.parse(text)
    agents = {a.lower() for a in field("user-agent")}
    home = board.home()
    value = {
        "found": True,
        "disallow": len(field("disallow")), "allow": len(field("allow")),
        "crawl_delay": rules.crawl_delay("*"), "sitemaps": len(list(rules.sitemaps)),
        "home_allowed": rules.can_fetch(board.store.records[home].exchange.url, "*") if home else None,
        "ai_agents_named": sorted(a for a in agents if a in AI_AGENTS),
        "rules_sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16],
    }
    excerpt = f"{value['disallow']} disallow, {value['allow']} allow, {value['sitemaps']} sitemap"
    return finding("access", "robots", "detected", value, [board.cite(xid, "body", "robots.txt", excerpt)], "declared", "high")


def access(board: Board) -> Section:
    items = [_robots(board)]
    home = board.home()
    r = board.store.records.get(home) if home else None
    if r is None or r.exchange.status is None:
        items.append(finding("access", "reachable", "unknown", limitations=["The homepage request failed; see errors"]))
        return Section(coverage=Coverage(status="partial", surfaces=[x for x in [board.robots()] if x], methods=["http"],
                                         reason="no homepage response"), items=items)
    status = r.exchange.status
    sev = board.cite(home, "header", ":status", str(status))
    ok = 200 <= status < 300
    items.append(finding("access", "reachable", "detected" if ok else "not_detected", {"status": status}, [sev],
                         "observed" if ok else None, "high" if ok else None))
    challenged = home in board.challenged
    if status in (401, 403, 429, 503) and challenged:
        items.append(finding("access", "blocked", "detected", {"status": status, "challenge": True}, [sev], "observed", "high"))
    elif status in (401, 403, 429, 503):
        items.append(finding("access", "blocked", "unknown", {"status": status}, [sev],
                             limitations=[f"{status} without a known challenge signature"]))
    elif challenged:
        items.append(finding("access", "blocked", "detected", {"status": status, "challenge": True}, [sev], "observed", "medium",
                             ["Challenge served with a success status"]))
    else:
        items.append(finding("access", "blocked", "not_detected", {"status": status}, [sev],
                             limitations=["One request from one vantage point"]))
    page = board.page(home)
    login = next((u for u in r.exchange.redirects + [r.exchange.url] if LOGIN_PATH.search(u)), None)
    www_auth = dict(r.headers).get("www-authenticate")
    if login or www_auth or (page and page.password_inputs and page.text_chars < MIN_TEXT):
        how = (f"redirect to {login}" if login else f"WWW-Authenticate: {www_auth[:60]}" if www_auth
               else "password form is the main content")
        items.append(finding("access", "login_required", "detected", {"how": how},
                             [board.cite(home, "url" if login else "header" if www_auth else "dom", "login", how)], "observed", "high"))
    else:
        items.append(finding("access", "login_required", "not_detected", limitations=["Checked the homepage only"]))
    if page:
        nodes, _ = page.jsonld
        if any(n.get("isAccessibleForFree") in (False, "False", "false") for n in nodes):
            items.append(finding("access", "paywall", "detected", {"source": "schema.org isAccessibleForFree"},
                                 [board.cite(home, "body", "ld+json isAccessibleForFree", "false")], "declared", "high"))
        terms = next((href for href, text in page.links
                      if re.search(r"\bterms\b|terms[-_ ]of|conditions|/tos\b|/legal", f"{href} {text}", re.I)), None)
        if terms:
            items.append(finding("access", "terms_url", "detected", {"url": terms},
                                 [board.cite(home, "dom", "a[href]", terms)], "observed", "medium"))
    return Section(coverage=coverage(board, [x for x in [board.robots(), home] if x]), items=items)


def _template(path: str) -> str:
    path = re.sub(r"\{\{\s*(\w+)\s*\}\}|\$\{\s*(\w+)\s*\}|:(\w+)(?=/|$)", lambda m: "{" + next(g for g in m.groups() if g) + "}", path)
    return re.sub(r"/\d{3,}(?=/|$)", "/{id}", path.split("#")[0])


def endpoints(board: Board) -> Section:
    """API routes the site itself declares or references. Nothing here was called: referenced routes are `inferred`."""
    pages, items, seen = board.html(), [], set()
    site = re.sub(r"^www\.", "", re.sub(r"^https?://", "", board.store.records[board.home()].exchange.url).split("/")[0]) if board.home() else ""
    for x in pages:
        page = board.page(x)
        for link in page.link_tags:
            rel, kind = link["rel"].lower(), FEED_TYPES.get(link["type"].lower())
            if "alternate" in rel and kind or "search" in rel and "opensearch" in link["type"].lower():
                kind = kind or "opensearch"
                fid = f"feed_{slug(link['href'])[:60]}"
                if fid in seen:
                    continue
                seen.add(fid)
                items.append(finding("endpoints", fid, "detected",
                                     {"url_template": link["href"], "kind": "feed" if kind != "opensearch" else "opensearch",
                                      "format": kind, "title": link["title"] or None, "source": "link_tag", "auth": "none"},
                                     [board.cite(x, "dom", f"link[rel={rel}]", link["href"])], "declared", "high"))
        refs: dict[str, tuple[str, str]] = {}
        for m in API_REF.finditer(board.text(x)):
            host, path = re.sub(r"^(https?:)?//", "", m.group(1) or ""), m.group(2)
            if TELEMETRY.search(path) or path.endswith((".js", ".css", ".png", ".svg", ".jpg", ".woff2")):
                continue
            tpl = _template(path)
            refs.setdefault(f"https://{host}{tpl}" if host else tpl, (host, m.group(0)[1:-1]))
        for key, (host, raw) in refs.items():
            fid = slug(re.sub(r"^https://", "", key))[:80]
            if fid in seen:
                continue
            seen.add(fid)
            path = key.split(host, 1)[1] if host else key
            value = {"url_template": key, "kind": "graphql" if "graph" in path or "gql" in path else "rest",
                     "params": re.findall(r"\{(\w+)\}", key), "auth": "likely" if AUTH_HINT.search(path) else "unknown",
                     "first_party": not host or host.removeprefix("www.").endswith(site), "source": "page_source"}
            items.append(finding("endpoints", fid, "detected", value, [board.cite(x, "body", "api_reference", raw)],
                                 "inferred", "low", ["Referenced in page source, not called; method and response unknown"]))
    cov = coverage(board, pages)
    if pages:
        cov.status, cov.reason = "partial", "page source only; browser traffic and API docs not checked"
    return Section(coverage=cov, items=items)


DETECTORS: dict[str, Callable[[Board], Section]] = {  # run in order; access reads anti_bot's challenge results
    "technologies": technologies, "anti_bot": anti_bot, "rendering": rendering,
    "structured_data": structured_data, "infrastructure": infrastructure, "endpoints": endpoints, "access": access,
}


def run_detectors(store: Store) -> Board:
    board = Board(store)
    for name, fn in DETECTORS.items():
        try:
            board.sections[name] = fn(board)
        except Exception as exc:  # a detector bug must not lose the profile
            board.errors.append(Error(id=f"det{len(board.errors) + 1}", stage="detect", analyzer=name, type="internal",
                                      message=f"{type(exc).__name__}: {exc}"[:300], affects=[name]))
            board.sections[name] = Section(coverage=Coverage(status="failed", methods=["http"], reason="detector error"))
    return board
