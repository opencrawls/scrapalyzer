"""Policy gate against a local http.server: budget, rate, robots report/respect, redirect chain, Retry-After, replay."""
import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scrapalyzer.engine import Gate, collect_home, collect_robots, replay

ROBOTS = b"User-agent: *\nDisallow: /private\nSitemap: /sitemap.xml\n"


class Site:
    """routes: path -> (status, headers, body) or a list of those, served in turn."""

    def __init__(self, routes):
        self.routes, self.log = routes, []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                site.log.append((self.path, time.monotonic()))
                route = site.routes.get(self.path, (404, {}, b"not found"))
                if isinstance(route, list):
                    route = route.pop(0) if len(route) > 1 else route[0]
                status, headers, body = route
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v.replace("{base}", site.base))
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()

    def paths(self):
        return [p for p, _ in self.log]

    def gaps(self):
        times = [t for _, t in self.log]
        return [b - a for a, b in zip(times, times[1:])]


@pytest.fixture
def site():
    sites = []

    def make(routes):
        sites.append(Site({"/robots.txt": (200, {}, ROBOTS), **routes}))
        return sites[-1]

    yield make
    for s in sites:
        s.server.shutdown()


def run(coro_fn, base, **kw):
    async def main():
        async with Gate(base, **{"rate_per_host": 100, **kw}) as gate:
            await coro_fn(gate)
            return gate
    return asyncio.run(main())


PAGE = (200, {"content-type": "text/html", "set-cookie": "sid=secret123; Path=/", "server": "test",
              "x-secret-token": "abc"}, b"<html>hello</html>")


def test_robots_reported_not_enforced(site):
    s = site({"/": PAGE, "/private/x": PAGE})

    async def go(g):
        await collect_robots(g, s.base)
        await g.fetch(s.base + "/private/x", "sample")
    g = run(go, s.base)
    x1, x2 = g.store.records["x1"].exchange, g.store.records["x2"].exchange
    assert (x1.purpose, x1.robots) == ("robots", "allowed")
    assert (x2.robots, x2.policy, x2.status) == ("disallowed", "sent", 200)
    assert s.paths() == ["/robots.txt", "/private/x"]


def test_robots_respect_skips_disallowed(site):
    s = site({"/private/x": PAGE})
    g = run(lambda g: g.fetch(s.base + "/private/x", "sample"), s.base, robots="respect")
    x = g.store.records["x2"].exchange
    assert (x.policy, x.status) == ("denied:robots", None)
    assert s.paths() == ["/robots.txt"] and (g.sent, g.denied) == (1, 1)


def test_budget_caps_requests(site):
    s = site({f"/p{i}": PAGE for i in range(5)})

    async def go(g):
        for i in range(5):
            await g.fetch(f"{s.base}/p{i}", "sample")
    g = run(go, s.base, max_requests=3)
    assert len(s.log) == 3 and (g.sent, g.denied) == (3, 3)  # robots + p0 + p1, then p2..p4 denied
    assert [r.exchange.policy for r in g.store.records.values()][-3:] == ["denied:budget"] * 3


def test_duplicate_urls_cost_one_request(site):
    s = site({"/": PAGE})

    async def go(g):
        assert await g.fetch(s.base + "/", "homepage") == await g.fetch(s.base + "/#top", "homepage")
    run(go, s.base)
    assert s.paths() == ["/robots.txt", "/"]


def test_rate_per_host(site):
    s = site({f"/p{i}": PAGE for i in range(3)})

    async def go(g):
        for i in range(3):
            await g.fetch(f"{s.base}/p{i}", "sample")
    run(go, s.base, rate_per_host=10)
    assert all(gap >= 0.095 for gap in s.gaps()), s.gaps()


def test_crawl_delay_raises_interval(site):
    s = site({"/robots.txt": (200, {}, b"User-agent: *\nCrawl-delay: 0.3\n"), "/a": PAGE, "/b": PAGE})

    async def go(g):
        await g.fetch(s.base + "/a", "sample")
        await g.fetch(s.base + "/b", "sample")
    run(go, s.base)
    assert all(gap >= 0.29 for gap in s.gaps()), s.gaps()


def test_redirect_chain_is_recorded(site):
    s = site({"/": (301, {"location": "/a"}, b""), "/a": (302, {"location": "{base}/en/"}, b""), "/en/": PAGE})
    g = run(lambda g: collect_home(g, s.base), s.base)
    home = g.store.records["x2"].exchange
    assert (home.url, home.status, home.purpose) == (s.base + "/en/", 200, "homepage")
    assert home.redirects == [s.base + "/", s.base + "/a"]
    assert len(g.store.records) == 2 and g.sent == 4  # hops are counted but folded into one exchange


def test_redirect_off_site_is_out_of_scope(site):
    s = site({"/": (302, {"location": "http://elsewhere.invalid/"}, b"")})
    g = run(lambda g: collect_home(g, s.base), s.base)
    home = g.store.records["x2"].exchange
    assert (home.policy, home.url, home.redirects) == ("denied:scope", "http://elsewhere.invalid/", [s.base + "/"])


def test_redirect_loop_stops(site):
    s = site({"/": (302, {"location": "/a"}, b""), "/a": (302, {"location": "/"}, b"")})
    g = run(lambda g: collect_home(g, s.base), s.base)
    assert s.paths() == ["/robots.txt", "/", "/a"]
    assert "redirect loop" in g.errors[0].message


def test_retry_after_waits_once(site):
    s = site({"/": [(429, {"retry-after": "0"}, b""), PAGE]})
    g = run(lambda g: collect_home(g, s.base), s.base)
    assert g.store.records["x2"].exchange.status == 200 and s.paths().count("/") == 2 and not g.errors


def test_second_429_stops_the_run(site):
    s = site({"/": (429, {"retry-after": "0"}, b""), "/b": PAGE})

    async def go(g):
        await collect_home(g, s.base)
        await g.fetch(s.base + "/b", "sample")
    g = run(go, s.base)
    assert s.paths() == ["/robots.txt", "/", "/"]
    assert g.store.records["x3"].exchange.policy == "denied:budget" and g.errors[0].type == "budget"


def test_missing_robots_means_allowed(site):
    s = site({"/robots.txt": (404, {}, b""), "/": PAGE})
    g = run(lambda g: collect_home(g, s.base), s.base, robots="respect")
    assert g.store.records["x2"].exchange.robots == "allowed"


def test_network_errors_are_recorded_not_raised():
    g = run(lambda g: collect_home(g, "http://127.0.0.1:9/"), "http://127.0.0.1:9/")
    assert g.store.records["x2"].exchange.status is None
    assert {e.stage for e in g.errors} == {"robots", "homepage"}


def test_redaction_and_replay(site, tmp_path):
    s = site({"/": PAGE})
    g = run(lambda g: collect_home(g, s.base), s.base)
    ex = g.store.records["x2"].exchange
    assert ex.headers == {"content-type": "text/html", "server": "test", "content-length": "18"}
    assert ex.set_cookie_names == ["sid"] and "secret123" not in ex.model_dump_json()
    g.store.save(tmp_path)
    back = replay(tmp_path)
    assert back.exchanges() == g.store.exchanges()
    assert back.records["x2"].body == b"<html>hello</html>"
    assert ("x-secret-token", "abc") in back.records["x2"].headers  # raw headers stay available to detectors
    assert back.add(back.records["x1"]) == "x3"
