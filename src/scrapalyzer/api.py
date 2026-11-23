"""Public entry points: analyze a live URL or a saved store and get a profile/1 document."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__
from .detect import Board, run_detectors
from .engine import BUDGETS, USER_AGENT, Gate, Store, collect_home, collect_robots, origin_of, replay
from .models import AnalyzerRun, Policy, Profile, Requests, RobotsPolicy, Run, Target, Tool, Vantage


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_profile(url: str, store: Store, board: Board, *, started_at: str, depth: str = "standard",
                  robots: RobotsPolicy = "report", max_requests: int | None = None, rate_per_host: float = 1.0,
                  user_agent: str = USER_AGENT, errors: list = ()) -> Profile:
    home = board.home()
    final = store.records[home].exchange.url if home else None
    sent = sum(1 for r in store.records.values() if r.exchange.policy == "sent")
    host = urlsplit(url).hostname or ""
    run = Run(id=uuid.uuid4().hex[:12], started_at=started_at, finished_at=_now(), depth=depth,
              tool=Tool(version=__version__), vantage=Vantage(user_agent=user_agent),
              policy=Policy(robots=robots, max_requests=max_requests or BUDGETS[depth], rate_per_host=rate_per_host),
              requests=Requests(sent=sent, denied=len(store.records) - sent),
              analyzers=[AnalyzerRun(name=n, version="0.1.0", status="error" if any(e.analyzer == n for e in board.errors) else "ok")
                         for n in board.sections])
    # ponytail: summary stays empty until slice 5 (synthesis); every summary value must cite findings
    return Profile(target=Target(input=url, origin=origin_of(url), final_url=final, site=host.removeprefix("www.")),
                   run=run, evidence=board.evidence, exchanges=store.exchanges(),
                   errors=list(errors) + board.errors, **board.sections)


async def analyze(url: str, *, depth: str = "standard", robots: RobotsPolicy = "report", max_requests: int | None = None,
                  rate_per_host: float = 1.0, user_agent: str = USER_AGENT, save: str | None = None) -> Profile:
    if urlsplit(url).scheme not in ("http", "https"):
        url = "https://" + url
    started = _now()
    budget = max_requests or BUDGETS[depth]
    async with Gate(url, max_requests=budget, rate_per_host=rate_per_host, robots=robots, user_agent=user_agent) as gate:
        await collect_robots(gate, url)
        await collect_home(gate, url)
        # ponytail: robots + home only; declared/samples collectors arrive in slice 4
        if save:
            gate.store.save(save)
        board = run_detectors(gate.store)
        return build_profile(url, gate.store, board, started_at=started, depth=depth, robots=robots,
                             max_requests=budget, rate_per_host=rate_per_host, user_agent=user_agent, errors=gate.errors)


def analyze_sync(url: str, **kw) -> Profile:
    return asyncio.run(analyze(url, **kw))


def analyze_replay(path: str) -> Profile:
    """Re-run the detectors over a saved store. No network."""
    store = replay(path)
    board = run_detectors(store)
    home = board.home()
    rec = store.records[home].exchange if home else next(iter(store.records.values())).exchange
    url = (rec.redirects or [rec.url])[0]
    return build_profile(url, store, board, started_at=rec.at or _now())
