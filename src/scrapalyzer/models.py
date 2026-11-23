"""The profile/1 contract: one JSON document per origin per run.

Layers: exchanges (requests made) -> evidence (atomic facts in them) -> findings (claims, grouped in sections).
Every finding carries status / basis / confidence; every section says what it covered, so "not found" is never
confused with "not looked for". Freshness and human verification are OpenCrawls concerns, never stored here.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA = "scrapalyzer.profile/1"
SCHEMA_MINOR = 0

Status = Literal["detected", "not_detected", "unknown", "not_checked", "not_applicable"]
Basis = Literal["declared", "observed", "inferred"]
Confidence = Literal["high", "medium", "low"]
CoverageStatus = Literal["complete", "partial", "skipped", "failed", "not_checked"]
Method = Literal["http", "browser", "extension", "archive", "import"]
RobotsPolicy = Literal["report", "respect"]


class _Model(BaseModel):
    # unknown fields are a contract violation; plugins write under Profile.extensions
    model_config = ConfigDict(extra="forbid")


class Evidence(_Model):
    exchange: str | None = None  # None for evidence not tied to a request (e.g. DNS)
    location: Literal["header", "cookie_name", "body", "url", "dom", "network", "tls", "dns", "archive"]
    key: str | None = None
    excerpt: str | None = Field(None, max_length=200)
    matcher: str | None = None
    observed_at: str | None = None


class Exchange(_Model):
    purpose: str
    method: str = "GET"
    url: str
    status: int | None = None
    http_version: str | None = None
    ms: int | None = None
    bytes: int | None = None
    content_type: str | None = None
    headers: dict[str, str] = {}  # safe subset only: no cookie values, no auth
    set_cookie_names: list[str] = []
    redirects: list[str] = []
    body_sha256: str | None = None
    at: str | None = None
    via: Literal["http", "browser", "extension", "import"] = "http"
    robots: Literal["allowed", "disallowed", "unknown"] = "unknown"  # what robots.txt says about this URL
    policy: Literal["sent", "denied:robots", "denied:budget", "denied:scope"] = "sent"


class Coverage(_Model):
    status: CoverageStatus = "not_checked"
    surfaces: list[str] = []
    methods: list[Method] = []
    signatures_checked: int | None = None
    reason: str | None = None
    limitations: list[str] = []


class Finding(_Model):
    id: str = Field(pattern=r"^[a-z_]+:[a-z0-9_.-]+$")  # "section:slug", stable across runs
    status: Status
    basis: Basis | None = None
    confidence: Confidence | None = None
    value: Any = None
    evidence: list[str] = []
    analyzer: str | None = None
    limitations: list[str] = []

    @model_validator(mode="after")
    def _basis_when_detected(self) -> Finding:
        if self.status == "detected" and (self.basis is None or self.confidence is None):
            raise ValueError(f"{self.id}: a detected finding needs basis and confidence")
        if self.status != "detected" and self.basis is not None:
            raise ValueError(f"{self.id}: basis only applies to detected findings")
        if self.basis == "inferred" and self.confidence == "high" and not self.evidence:
            raise ValueError(f"{self.id}: an inferred finding can't be high confidence without evidence")
        return self


class Section(_Model):
    coverage: Coverage = Coverage()
    items: list[Finding] = []


class RenderingSection(Section):
    mode: Literal["static", "ssr_hydrated", "csr", "unknown"] | None = None


class Target(_Model):
    input: str
    origin: str
    final_url: str | None = None
    site: str | None = None  # registrable domain


class Tool(_Model):
    name: str = "scrapalyzer"
    version: str
    signatures: str | None = None


class Vantage(_Model):
    user_agent: str
    proxy: bool = False
    region: str | None = None
    client: str | None = None  # e.g. "chrome-extension/0.3.0"
    session: Literal["signed_out", "signed_in"] = "signed_out"
    user_driven: bool = False


class Policy(_Model):
    robots: RobotsPolicy = "report"
    max_requests: int
    rate_per_host: float


class Requests(_Model):
    sent: int = 0
    denied: int = 0


class AnalyzerRun(_Model):
    name: str
    version: str | None = None
    status: Literal["ok", "partial", "skipped", "error"]
    ms: int | None = None
    reason: str | None = None
    error: str | None = None


class Source(_Model):
    kind: Literal["live", "opencrawls"] = "live"
    target_id: str | None = None
    url: str | None = None
    fetched_at: str | None = None


class Run(_Model):
    id: str
    started_at: str
    finished_at: str | None = None
    tool: Tool
    depth: Literal["quick", "standard", "deep"] = "standard"
    methods: list[Method] = ["http"]
    vantage: Vantage
    policy: Policy
    requests: Requests = Requests()
    analyzers: list[AnalyzerRun] = []
    source: Source = Source()


class Error(_Model):
    id: str
    stage: str
    analyzer: str | None = None
    type: Literal["timeout", "dns", "tls", "http", "parse", "budget", "policy", "internal"]
    message: str
    affects: list[str] = []


SECTIONS = ("access", "technologies", "anti_bot", "rendering", "structured_data", "discovery",
            "endpoints", "pagination", "data_inventory", "infrastructure")


class Profile(_Model):
    schema_: Literal["scrapalyzer.profile/1"] = Field(SCHEMA, alias="schema")
    schema_minor: int = SCHEMA_MINOR
    target: Target
    run: Run
    summary: dict[str, Any] = {}  # derived answers; every value points at findings via "ref"
    access: Section = Section()
    technologies: Section = Section()
    anti_bot: Section = Section()
    rendering: RenderingSection = RenderingSection()
    structured_data: Section = Section()
    discovery: Section = Section()
    endpoints: Section = Section()
    pagination: Section = Section()
    data_inventory: Section = Section()
    infrastructure: Section = Section()
    evidence: dict[str, Evidence] = {}
    exchanges: dict[str, Exchange] = {}
    errors: list[Error] = []
    extensions: dict[str, Any] = {}

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def sections(self) -> dict[str, Section]:
        return {name: getattr(self, name) for name in SECTIONS}

    def findings(self, section: str | None = None, status: Status | None = None) -> list[Finding]:
        return [f for name, s in self.sections().items() if section in (None, name)
                for f in s.items if status in (None, f.status)]

    @model_validator(mode="after")
    def _references_resolve(self) -> Profile:
        """Every id a profile mentions must exist in it: findings -> evidence -> exchanges, summary -> findings."""
        problems: list[str] = []
        ids: set[str] = set()
        for name, s in self.sections().items():
            for f in s.items:
                if not f.id.startswith(name + ":"):
                    problems.append(f"finding {f.id} is in section {name}")
                if f.id in ids:
                    problems.append(f"duplicate finding id {f.id}")
                ids.add(f.id)
                problems += [f"{f.id} cites missing evidence {e}" for e in f.evidence if e not in self.evidence]
            problems += [f"{name}.coverage cites missing exchange {x}" for x in s.coverage.surfaces if x not in self.exchanges]
        for eid, e in self.evidence.items():
            if e.exchange is not None and e.exchange not in self.exchanges:
                problems.append(f"evidence {eid} cites missing exchange {e.exchange}")
        for key, v in self.summary.items():
            refs = v.get("ref") if isinstance(v, dict) else None
            refs = [refs] if isinstance(refs, str) else refs
            if not refs:
                problems.append(f"summary.{key} has no ref (summary may not introduce facts)")
            problems += [f"summary.{key} cites missing finding {r}" for r in refs or [] if r not in ids]
        if problems:
            raise ValueError("; ".join(problems))
        return self

    # --- serialization
    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(by_alias=True, exclude_none=True, indent=indent)

    def to_file(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json() + "\n")

    @classmethod
    def from_json(cls, text: str | bytes) -> Profile:
        return cls.model_validate_json(text)


def json_schema() -> dict[str, Any]:
    """The published JSON Schema for profile/1 (written to schema/profile-1.json)."""
    s = Profile.model_json_schema(by_alias=True)
    s["$id"] = "https://github.com/opencrawls/scrapalyzer/blob/main/schema/profile-1.json"
    s["title"] = SCHEMA
    return s
