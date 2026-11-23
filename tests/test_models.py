"""profile/1 contract: the fixture validates and round-trips; broken references and bad states are rejected."""
import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scrapalyzer import Profile, json_schema

ROOT = Path(__file__).parent.parent
FIXTURE = json.loads((ROOT / "tests/fixtures/profiles/northwind.json").read_text())


def mutated(fn):
    d = copy.deepcopy(FIXTURE)
    fn(d)
    return d


def test_fixture_validates_and_round_trips():
    p = Profile.model_validate(FIXTURE)
    assert p.to_dict()["schema"] == "scrapalyzer.profile/1"
    assert Profile.from_json(p.to_json()) == p
    assert [f.id for f in p.findings(section="anti_bot")] == ["anti_bot:cloudflare"]
    assert len(p.findings(status="not_detected")) == 1


def test_robots_is_reported_not_enforced():
    p = Profile.model_validate(FIXTURE)
    assert p.run.policy.robots == "report"
    cart = p.exchanges["x4"]
    assert (cart.robots, cart.policy) == ("disallowed", "sent")


@pytest.mark.parametrize("break_it, message", [
    (lambda d: d["access"]["items"][0].update(evidence=["e99"]), "missing evidence e99"),
    (lambda d: d["evidence"]["e1"].update(exchange="x99"), "missing exchange x99"),
    (lambda d: d["summary"].update(extra={"value": 1}), "has no ref"),
    (lambda d: d["summary"].update(extra={"value": 1, "ref": "access:nope"}), "missing finding access:nope"),
    (lambda d: d["access"]["items"][0].update(id="anti_bot:reachable"), "is in section access"),
    (lambda d: d["access"]["items"][0].pop("basis"), "needs basis and confidence"),
    (lambda d: d["access"]["items"][2].update(basis="observed"), "basis only applies"),
    (lambda d: d["rendering"]["items"][0].update(confidence="high", evidence=[]), "can't be high confidence"),
    (lambda d: d["target"].update(surprise=True), "Extra inputs are not permitted"),
    (lambda d: d.update(schema="scrapalyzer.profile/2"), "scrapalyzer.profile/1"),
])
def test_contract_violations_are_rejected(break_it, message):
    with pytest.raises(ValidationError, match=message.replace("(", r"\(")):
        Profile.model_validate(mutated(break_it))


def test_published_schema_is_current():
    path = ROOT / "schema/profile-1.json"
    current = json.dumps(json_schema(), indent=2) + "\n"
    assert path.exists() and path.read_text() == current, "run: uv run python scripts/write_schema.py"
