"""CLI over a saved store: the summary prints and --json is a valid profile/1 document."""
import json

from scrapalyzer import Profile
from scrapalyzer.cli import main
from test_detect import store


def test_replay_summary_and_json(tmp_path, capsys):
    store(headers={"cf-ray": "1", "x-powered-by": "Next.js"}, cookies=["__cf_bm"]).save(tmp_path)
    assert main(["replay", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "Cloudflare · bot management active" in text and "Next.js" in text
    assert main(["replay", str(tmp_path), "--json"]) == 0
    p = Profile.model_validate(json.loads(capsys.readouterr().out))
    assert p.target.site == "s.example" and p.run.requests.sent == 2
