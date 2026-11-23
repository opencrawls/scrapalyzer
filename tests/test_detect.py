"""Detectors over hand-built exchange stores: a positive case for every signature, plus the negative traps."""
import pytest

from scrapalyzer.detect import SIGNATURES, run_detectors, slug
from scrapalyzer.engine import Record, Store
from scrapalyzer.models import Exchange, Policy, Profile, Run, Target, Tool, Vantage

ROBOTS = b"User-agent: *\nDisallow: /cart\nAllow: /cart/help\nCrawl-delay: 2\nSitemap: https://s.example/sitemap.xml\n\nUser-agent: GPTBot\nDisallow: /\n"
ARTICLE = "<p>" + "Plain words about boots and other things. " * 60 + "</p>"


def store(body: str = ARTICLE, headers: dict | None = None, cookies: list[str] = (), status: int = 200,
          url: str = "https://s.example/", redirects: list[str] = (), robots: bytes = ROBOTS) -> Store:
    s = Store()
    s.add(Record(Exchange(purpose="robots", url="https://s.example/robots.txt", status=200, content_type="text/plain"),
                 [("content-type", "text/plain")], robots))
    h = [("content-type", "text/html; charset=utf-8")] + [(k.lower(), v) for k, v in (headers or {}).items()]
    h += [("set-cookie", f"{c}=1; Path=/") for c in cookies]
    s.add(Record(Exchange(purpose="homepage", url=url, status=status, content_type="text/html; charset=utf-8",
                          set_cookie_names=list(cookies), redirects=list(redirects), at="2026-11-23T10:00:00Z"),
                 h, f"<html><head></head><body>{body}</body></html>".encode()))
    return s


def ids(board, section):
    return {f.id: f for f in board.sections[section].items}


TECH = {  # one positive per technology signature
    "Next.js": dict(headers={"x-powered-by": "Next.js"}),
    "Nuxt": dict(body='<script>window.__NUXT__={}</script>' + ARTICLE),
    "Gatsby": dict(body='<div id="___gatsby"></div>' + ARTICLE),
    "SvelteKit": dict(body='<body data-sveltekit-preload-data="hover">' + ARTICLE),
    "Astro": dict(body='<astro-island uid="1"></astro-island>' + ARTICLE),
    "Angular": dict(body='<app-root ng-version="17.0.0"></app-root>' + ARTICLE),
    "React": dict(body='<div data-reactroot="">' + ARTICLE + '</div>'),
    "Vue.js": dict(body='<div data-v-1a2b3c4d>' + ARTICLE + '</div>'),
    "Apollo GraphQL": dict(body='<script>window.__APOLLO_STATE__={}</script>' + ARTICLE),
    "Shopify": dict(cookies=["_shopify_y"], body='<script src="//cdn.shopify.com/s/theme.js"></script>' + ARTICLE),
    "WooCommerce": dict(body='<script src="/wp-content/plugins/woocommerce/a.js"></script>' + ARTICLE),
    "Magento": dict(cookies=["X-Magento-Vary"]),
    "BigCommerce": dict(body='<script src="https://cdn11.bigcommerce.com/s-1/a.js"></script>' + ARTICLE),
    "Salesforce Commerce Cloud": dict(cookies=["dwsid"]),
    "WordPress": dict(body='<meta name="generator" content="WordPress 6.6">' + ARTICLE),
    "Drupal": dict(headers={"x-generator": "Drupal 10"}),
    "Ghost": dict(body='<meta name="generator" content="Ghost 5.0">' + ARTICLE),
    "Squarespace": dict(body='<link href="https://static1.squarespace.com/x.css">' + ARTICLE),
    "Wix": dict(headers={"x-wix-request-id": "1"}),
    "Webflow": dict(body='<html data-wf-site="abc">' + ARTICLE),
    "Algolia": dict(body='<script src="https://cdn.jsdelivr.net/npm/algoliasearch@4/dist/a.js"></script>' + ARTICLE),
    "ASP.NET": dict(cookies=["ASP.NET_SessionId"]),
    "PHP": dict(headers={"x-powered-by": "PHP/8.2"}),
    "Express": dict(headers={"x-powered-by": "Express"}),
}

ANTI_BOT = {  # vendor -> (store kwargs, expected level)
    "Cloudflare": (dict(headers={"cf-ray": "8e-AMS"}, cookies=["__cf_bm"]), "bot_management_signal"),
    "Akamai": (dict(cookies=["_abck", "bm_sz"]), "bot_management_signal"),
    "DataDome": (dict(status=403, body='<script src="https://geo.captcha-delivery.com/captcha/"></script>', cookies=["datadome"]),
                 "challenge_observed"),
    "HUMAN (PerimeterX)": (dict(cookies=["_pxhd"]), "bot_management_signal"),
    "Imperva": (dict(headers={"x-iinfo": "1-2-3"}, cookies=["incap_ses_1_2"]), "bot_management_signal"),
    "Kasada": (dict(status=429, headers={"x-kpsdk-ct": "abc"}), "challenge_observed"),
    "AWS WAF": (dict(cookies=["aws-waf-token"]), "bot_management_signal"),
    "Queue-it": (dict(body='<script src="//static.queue-it.net/script/queueclient.min.js"></script>' + ARTICLE), "bot_management_signal"),
    "Google reCAPTCHA": (dict(body='<script src="https://www.google.com/recaptcha/api.js"></script>' + ARTICLE), "challenge_observed"),
    "hCaptcha": (dict(body='<div class="h-captcha" data-sitekey="x"></div>' + ARTICLE), "challenge_observed"),
    "Cloudflare Turnstile": (dict(body='<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>' + ARTICLE), "challenge_observed"),
    "Arkose Labs": (dict(body='<script src="https://client-api.arkoselabs.com/v2/api.js"></script>' + ARTICLE), "challenge_observed"),
}

CDN = {
    "Cloudflare": {"server": "cloudflare"}, "Fastly": {"x-served-by": "cache-mrs1530023-MRS"}, "Akamai": {"server": "AkamaiGHost"},
    "Amazon CloudFront": {"x-amz-cf-pop": "AMS1"}, "Google Cloud CDN": {"via": "1.1 google"}, "Microsoft Azure Front Door": {"x-azure-ref": "1"},
    "Vercel": {"x-vercel-id": "fra1::abc"}, "Netlify": {"x-nf-request-id": "1"}, "Imperva": {"x-cdn": "Imperva"}, "Varnish": {"x-varnish": "1"},
}


def test_every_signature_has_a_positive_case():
    assert set(TECH) == set(SIGNATURES["technologies"])
    assert set(ANTI_BOT) == set(SIGNATURES["anti_bot"])
    assert set(CDN) == set(SIGNATURES["cdn"])


@pytest.mark.parametrize("name", TECH)
def test_technology_positive(name):
    found = ids(run_detectors(store(**TECH[name])), "technologies")
    assert f"technologies:{slug(name)}" in found
    assert found[f"technologies:{slug(name)}"].basis == "observed"


@pytest.mark.parametrize("vendor", ANTI_BOT)
def test_anti_bot_positive(vendor):
    kwargs, level = ANTI_BOT[vendor]
    f = ids(run_detectors(store(**kwargs)), "anti_bot")[f"anti_bot:{slug(vendor)}"]
    assert f.value["level"] == level and f.value["surfaces"] == ["x2"]


@pytest.mark.parametrize("name", CDN)
def test_cdn_positive(name):
    assert f"infrastructure:cdn_{slug(name)}" in ids(run_detectors(store(headers=CDN[name])), "infrastructure")


def test_plain_page_matches_no_signature():
    b = run_detectors(store())
    assert ids(b, "technologies") == {} and ids(b, "anti_bot") == {}
    assert not any(i.startswith("infrastructure:cdn_") for i in ids(b, "infrastructure"))
    assert b.sections["anti_bot"].coverage.signatures_checked == len(SIGNATURES["anti_bot"])


def test_cloudflare_cdn_is_not_bot_management():
    f = ids(run_detectors(store(headers={"cf-ray": "8e-AMS", "server": "cloudflare"})), "anti_bot")["anti_bot:cloudflare"]
    assert f.value["level"] == "edge_present"


def test_captcha_key_in_config_is_not_a_challenge():
    b = run_detectors(store(body='<script>var c={"recaptchaKey":"6Lf","createPath":"/reserve/captcha"}</script>' + ARTICLE))
    assert ids(b, "anti_bot") == {} and ids(b, "access")["access:blocked"].status == "not_detected"


def test_429_alone_is_not_kasada():
    b = run_detectors(store(status=429))
    assert ids(b, "anti_bot") == {}
    assert ids(b, "access")["access:blocked"].status == "unknown"


def test_jquery_mention_is_not_react():
    assert ids(run_detectors(store(body="<!-- react to this: uses jQuery 1.4 -->" + ARTICLE)), "technologies") == {}


def test_challenge_page_means_blocked():
    b = run_detectors(store(status=403, headers={"cf-mitigated": "challenge", "cf-ray": "1"},
                            body="<title>Just a moment...</title>"))
    assert ids(b, "anti_bot")["anti_bot:cloudflare"].value["level"] == "challenge_observed"
    blocked = ids(b, "access")["access:blocked"]
    assert (blocked.status, blocked.confidence) == ("detected", "high")


def test_implied_technology_is_inferred():
    f = ids(run_detectors(store(**TECH["Next.js"])), "technologies")["technologies:react"]
    assert (f.basis, f.value["implied_by"]) == ("inferred", "Next.js")


def test_robots_findings():
    f = ids(run_detectors(store()), "access")["access:robots"]
    assert f.basis == "declared"
    assert {k: f.value[k] for k in ("disallow", "allow", "crawl_delay", "sitemaps", "home_allowed", "ai_agents_named")} == \
        {"disallow": 2, "allow": 1, "crawl_delay": 2.0, "sitemaps": 1, "home_allowed": True, "ai_agents_named": ["gptbot"]}


def test_missing_robots():
    s = store()
    s.records["x1"].exchange.status = 404
    assert ids(run_detectors(s), "access")["access:robots"].value == {"found": False, "status": 404}


def test_login_redirect():
    b = run_detectors(store(url="https://s.example/account/login?next=/", redirects=["https://s.example/"]))
    assert ids(b, "access")["access:login_required"].status == "detected"


def test_paywall_and_terms():
    body = ('<script type="application/ld+json">{"@type":"NewsArticle","isAccessibleForFree":false,"headline":"x"}</script>'
            '<a href="/legal/terms">Terms of Use</a>' + ARTICLE)
    a = ids(run_detectors(store(body=body)), "access")
    assert a["access:paywall"].basis == "declared" and a["access:terms_url"].value == {"url": "/legal/terms"}


def test_rendering_modes():
    csr = run_detectors(store(body='<div id="root"></div><script src="/app.js"></script>'))
    assert csr.sections["rendering"].mode == "csr"
    assert ids(csr, "rendering")["rendering:requires_browser"].value == "yes"
    assert run_detectors(store()).sections["rendering"].mode == "static"
    next_ = '<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"product":{},"reviews":[]}}}</script>'
    ssr = run_detectors(store(body=ARTICLE + next_))
    assert ssr.sections["rendering"].mode == "ssr_hydrated"
    assert ids(ssr, "rendering")["rendering:hydration"].value[0]["top_keys"] == ["product", "reviews"]
    hydrated_csr = run_detectors(store(body='<div id="__next"></div>' + next_))
    f = ids(hydrated_csr, "rendering")["rendering:requires_browser"]
    assert (hydrated_csr.sections["rendering"].mode, f.value, f.confidence) == ("csr", "no", "low")


def test_structured_data_keeps_names_not_values():
    body = ('<script type="application/ld+json">{"@context":"https://schema.org","@graph":['
            '{"@type":"Product","name":"Secret Boot","offers":{"price":"99"}},'
            '{"@type":"WebSite","potentialAction":{"@type":"SearchAction","target":"https://s.example/s?q={q}","query-input":"required name=q"}}]}</script>'
            '<script type="application/ld+json">{broken</script>'
            '<meta property="og:type" content="product"><div itemscope itemtype="https://schema.org/Offer"></div>' + ARTICLE)
    b = run_detectors(store(body=body))
    sd = ids(b, "structured_data")
    jsonld = {t["type"]: t["properties"] for t in sd["structured_data:jsonld"].value}
    assert jsonld["Product"] == ["name", "offers"] and "Secret Boot" not in str(sd)
    assert sd["structured_data:jsonld"].limitations == ["1 JSON-LD block(s) failed to parse"]
    assert sd["structured_data:search_action"].value["url_template"] == "https://s.example/s?q={q}"
    assert sd["structured_data:opengraph"].value["types"] == ["product"]
    assert sd["structured_data:microdata"].value[0]["type"] == "https://schema.org/Offer"


def test_redirects_and_http():
    b = run_detectors(store(redirects=["http://s.example/"], headers={"alt-svc": 'h3=":443"'}))
    i = ids(b, "infrastructure")
    assert i["infrastructure:redirects"].value["https_upgrade"] is True
    assert i["infrastructure:http"].value["h3_advertised"] is True


def test_failed_homepage_still_produces_sections():
    s = store()
    s.records["x2"].exchange.status = None
    b = run_detectors(s)
    assert not b.errors
    assert ids(b, "access")["access:reachable"].status == "unknown"
    assert b.sections["rendering"].coverage.status == "failed"


def test_detector_bug_becomes_an_error(monkeypatch):
    from scrapalyzer import detect
    monkeypatch.setitem(detect.DETECTORS, "rendering", lambda board: 1 / 0)
    b = run_detectors(store())
    assert b.errors[0].analyzer == "rendering" and b.sections["rendering"].coverage.status == "failed"


def test_board_builds_a_valid_profile():
    """Every finding -> evidence -> exchange reference resolves (the Profile validator checks it)."""
    s = store(headers={"cf-ray": "1", "x-powered-by": "Next.js"}, cookies=["__cf_bm"])
    b = run_detectors(s)
    Profile(target=Target(input="https://s.example", origin="https://s.example"),
            run=Run(id="t", started_at="2026-11-23T10:00:00Z", tool=Tool(version="0.1.0"), vantage=Vantage(user_agent="ua"),
                    policy=Policy(max_requests=25, rate_per_host=1.0)),
            evidence=b.evidence, exchanges=s.exchanges(), **b.sections)


def test_endpoints_from_page_source():
    body = ('<script>window.cfg={"search":"/api/search/events","event":"/api/eventinfo/{{eventId}}",'
            '"me":"/api/user/details/v2","log":"/api/errors","gql":"https://api.s.example/graphql","js":"/api/x.js",'
            '"other":"https://tracker.example/api/collect"}</script>'
            '<link rel="alternate" type="application/rss+xml" title="News" href="/feed.xml">'
            '<link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml">' + ARTICLE)
    e = {f.value["url_template"]: f for f in run_detectors(store(body=body)).sections["endpoints"].items}
    assert set(e) == {"/api/search/events", "/api/eventinfo/{eventId}", "/api/user/details/v2", "https://api.s.example/graphql",
                      "/feed.xml", "/opensearch.xml"}  # telemetry, assets and third-party collectors dropped
    assert e["/api/eventinfo/{eventId}"].value["params"] == ["eventId"]
    assert e["/api/user/details/v2"].value["auth"] == "likely" and e["/api/search/events"].value["auth"] == "unknown"
    assert e["https://api.s.example/graphql"].value["kind"] == "graphql" and e["https://api.s.example/graphql"].value["first_party"]
    assert (e["/api/search/events"].basis, e["/api/search/events"].confidence) == ("inferred", "low")
    assert (e["/feed.xml"].value["format"], e["/feed.xml"].basis) == ("rss", "declared")
    assert e["/opensearch.xml"].value["kind"] == "opensearch"


def test_no_endpoints_on_plain_page():
    assert run_detectors(store()).sections["endpoints"].items == []
