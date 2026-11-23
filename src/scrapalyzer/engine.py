"""The policy gate and exchange store: the only path from Scrapalyzer to the network.

Every request goes through `Gate.fetch`, which checks scope, robots.txt, budget and per-host rate, records an
`Exchange` (redacted, for the profile) plus the raw headers and body (in memory, for detectors), and never raises
for site behavior. Detectors read the `Store`; `Store.save` / `Store.load` make a run replayable offline.
"""
from __future__ import annotations

import asyncio
import email.utils
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from protego import Protego

from .models import Error, Exchange, RobotsPolicy

log = logging.getLogger("scrapalyzer")

BUDGETS = {"quick": 4, "standard": 25, "deep": 60}
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/142.0.0.0 Safari/537.36")
# headers safe to publish in a profile; detectors still see every header through Record.headers
SAFE_HEADERS = {
    "server", "content-type", "content-length", "content-encoding", "content-language", "cache-control", "age",
    "vary", "via", "x-cache", "x-powered-by", "x-generator", "cf-ray", "cf-cache-status", "x-served-by",
    "x-frame-options", "strict-transport-security", "link", "location", "retry-after", "x-robots-tag",
    "www-authenticate", "alt-svc", "last-modified", "etag",
}
REDIRECTS = {301, 302, 303, 307, 308}


@dataclass
class Record:
    exchange: Exchange
    headers: list[tuple[str, str]] = field(default_factory=list)  # raw, lowercased names
    body: bytes = b""


class Store:
    """Per-run exchanges keyed x1, x2, ... in request order."""

    def __init__(self) -> None:
        self.records: dict[str, Record] = {}
        self._n = 0

    def add(self, record: Record) -> str:
        self._n += 1
        xid = f"x{self._n}"
        self.records[xid] = record
        return xid

    def find(self, url: str) -> str | None:
        return next((x for x, r in self.records.items() if r.exchange.url == url and r.exchange.policy == "sent"), None)

    def exchanges(self) -> dict[str, Exchange]:
        return {x: r.exchange for x, r in self.records.items()}

    def save(self, path: str | Path) -> None:
        """Write a replayable fixture: exchanges.json plus bodies/<id>.bin."""
        path = Path(path)
        (path / "bodies").mkdir(parents=True, exist_ok=True)
        data = {}
        for xid, r in self.records.items():
            data[xid] = {"exchange": r.exchange.model_dump(mode="json", exclude_none=True), "headers": r.headers}
            if r.body:
                (path / "bodies" / f"{xid}.bin").write_bytes(r.body)
        (path / "exchanges.json").write_text(json.dumps(data, indent=2) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> Store:
        path = Path(path)
        store = cls()
        for xid, d in json.loads((path / "exchanges.json").read_text()).items():
            body = path / "bodies" / f"{xid}.bin"
            store.records[xid] = Record(Exchange.model_validate(d["exchange"]),
                                        [tuple(h) for h in d.get("headers", [])],
                                        body.read_bytes() if body.exists() else b"")
        store._n = max((int(x[1:]) for x in store.records), default=0)
        return store


def replay(path: str | Path) -> Store:
    """Load a saved exchange store. No network."""
    return Store.load(path)


def normalize(url: str) -> str:
    # ponytail: drops the fragment only; sorting the query and stripping tracking params can come with samples
    s = urlsplit(url)
    return urlunsplit((s.scheme, s.netloc.lower(), s.path or "/", s.query, ""))


def origin_of(url: str) -> str:
    s = urlsplit(url)
    return f"{s.scheme}://{s.netloc.lower()}"


def _error_type(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    text = repr(exc) + repr(exc.__cause__) + repr(exc.__context__)
    if "SSL" in text or "CERTIFICATE" in text:
        return "tls"
    if "gaierror" in text or "nodename" in text or "Name or service" in text:
        return "dns"
    return "http"


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    if value.strip().isdigit():
        return float(value)
    try:
        return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


class Gate:
    def __init__(self, target: str, *, max_requests: int = BUDGETS["standard"], rate_per_host: float = 1.0,
                 robots: RobotsPolicy = "report", user_agent: str = USER_AGENT, timeout: float = 20.0,
                 max_body: int = 5_000_000, max_retry_wait: float = 30.0, transport: httpx.AsyncBaseTransport | None = None):
        host = urlsplit(target).hostname or ""
        # ponytail: "same site" = same host minus www., plus its subdomains; Public Suffix List lands with D-9
        self.site = host.removeprefix("www.")
        self.max_requests, self.rate_per_host, self.robots_policy = max_requests, rate_per_host, robots
        self.user_agent, self.max_body, self.max_retry_wait = user_agent, max_body, max_retry_wait
        self.store = Store()
        self.errors: list[Error] = []
        self.sent = self.denied = 0
        self.robots: dict[str, Protego | None] = {}  # origin -> parsed rules; None = couldn't read them
        self.robots_exchange: dict[str, str] = {}  # origin -> exchange id of its robots.txt
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._halted = False
        self.client = httpx.AsyncClient(headers={"user-agent": user_agent}, timeout=timeout,
                                        follow_redirects=False, transport=transport)

    async def __aenter__(self) -> Gate:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()

    # --- policy
    def in_scope(self, url: str) -> bool:
        host = urlsplit(url).hostname or ""
        return host == self.site or host.endswith("." + self.site)

    def robots_status(self, url: str) -> str:
        rules = self.robots.get(origin_of(url))
        if rules is None:
            return "unknown"
        return "allowed" if rules.can_fetch(url, self.user_agent) else "disallowed"

    def interval(self, url: str) -> float:
        rules = self.robots.get(origin_of(url))
        delay = rules.crawl_delay(self.user_agent) if rules else None
        return max(1.0 / self.rate_per_host, float(delay or 0))

    def error(self, stage: str, type_: str, message: str) -> None:
        self.errors.append(Error(id=f"err{len(self.errors) + 1}", stage=stage, type=type_, message=message))

    # --- requests
    async def load_robots(self, origin: str) -> str | None:
        """Fetch and parse robots.txt once per origin. Returns its exchange id."""
        if origin in self.robots:
            return self.robots_exchange.get(origin)
        self.robots[origin] = None  # reserve, so the robots fetch itself isn't gated on robots
        xid = self.robots_exchange[origin] = await self.fetch(origin + "/robots.txt", "robots", follow=True)
        r = self.store.records[xid]
        status = r.exchange.status
        if status is not None and 200 <= status < 300:
            self.robots[origin] = Protego.parse(r.body.decode("utf-8", "replace").lstrip("﻿"))
        elif status is not None and 400 <= status < 500:
            self.robots[origin] = Protego.parse("")  # RFC 9309: unavailable robots.txt means no rules
        r.exchange.robots = "allowed"
        return xid

    async def fetch(self, url: str, purpose: str, *, follow: bool = False) -> str:
        """GET url through the gate and return its exchange id. Redirects are followed by hand when follow=True,
        each hop gated and counted; the final exchange lists the earlier URLs in `redirects`."""
        url, chain = normalize(url), []
        if xid := self.store.find(url):
            return xid
        while True:
            record = await self._one(url, purpose, chain)
            ex, location = record.exchange, dict(record.headers).get("location")
            if not (follow and ex.policy == "sent" and ex.status in REDIRECTS and location):
                return self.store.add(record)  # hops live on in the final exchange's `redirects`
            nxt = normalize(urljoin(url, location))
            if nxt in chain or nxt == url or len(chain) >= 10:
                self.error(purpose, "http", f"redirect loop or too many redirects at {url}")
                return self.store.add(record)
            chain.append(url)
            url = nxt

    async def _one(self, url: str, purpose: str, chain: list[str]) -> Record:
        origin = origin_of(url)
        if self.in_scope(url) and origin not in self.robots:
            await self.load_robots(origin)
        ex = Exchange(purpose=purpose, url=url, redirects=list(chain), robots=self.robots_status(url))
        if not self.in_scope(url):
            ex.policy = "denied:scope"
        elif self.robots_policy == "respect" and ex.robots == "disallowed":
            ex.policy = "denied:robots"
        elif self._halted or self.sent >= self.max_requests:
            ex.policy = "denied:budget"
        if ex.policy != "sent":
            self.denied += 1
            log.info("DENY %s %s (%s)", purpose, url, ex.policy)
            return Record(ex)
        record = await self._send(ex)
        wait = _retry_after(dict(record.headers).get("retry-after"))
        if record.exchange.status in (429, 503) and (wait is not None or record.exchange.status == 429):
            if wait is not None and wait <= self.max_retry_wait and self.sent < self.max_requests:
                await asyncio.sleep(wait)
                record = await self._send(ex)
            if record.exchange.status in (429, 503):  # asked to back off twice: a finding, not something to push through
                self._halted = True
                self.error(purpose, "budget", f"{record.exchange.status} at {url}: stopped sending requests")
        return record

    async def _send(self, ex: Exchange) -> Record:
        host = urlsplit(ex.url).netloc
        async with self._locks.setdefault(host, asyncio.Lock()):
            if host in self._last:
                await asyncio.sleep(max(0.0, self._last[host] + self.interval(ex.url) - time.monotonic()))
            self.sent += 1
            started, ex = time.monotonic(), ex.model_copy()
            ex.at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            record = Record(ex)
            try:
                async with self.client.stream("GET", ex.url) as resp:
                    chunks, size = [], 0
                    async for chunk in resp.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= self.max_body:
                            self.error(ex.purpose, "budget", f"body over {self.max_body} bytes cut off at {ex.url}")
                            break
                    record.body = b"".join(chunks)[: self.max_body]
                    record.headers = [(k.lower(), v) for k, v in resp.headers.multi_items()]
                    ex.status, ex.http_version = resp.status_code, resp.http_version
                    ex.content_type = resp.headers.get("content-type")
                    ex.headers = {k: v for k, v in record.headers if k in SAFE_HEADERS}
                    ex.set_cookie_names = [v.split("=", 1)[0].strip() for k, v in record.headers if k == "set-cookie"]
                    ex.bytes, ex.body_sha256 = len(record.body), hashlib.sha256(record.body).hexdigest()
            except httpx.HTTPError as exc:
                self.error(ex.purpose, _error_type(exc), f"{type(exc).__name__} at {ex.url}: {exc}"[:300])
            ex.ms = round((time.monotonic() - started) * 1000)
            self._last[host] = time.monotonic()
            log.info("GET %s %s %s %sms", ex.purpose, ex.url, ex.status, ex.ms)
            return record


# --- collectors: decide what to fetch, write exchanges, return their ids

async def collect_robots(gate: Gate, url: str) -> str | None:
    return await gate.load_robots(origin_of(url))


async def collect_home(gate: Gate, url: str) -> str:
    return await gate.fetch(url, "homepage", follow=True)
