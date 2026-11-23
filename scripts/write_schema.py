"""Regenerate schema/profile-1.json from the models. tests/test_models.py fails when it is out of date."""
import json
from pathlib import Path

from scrapalyzer import json_schema

out = Path(__file__).parent.parent / "schema/profile-1.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(json_schema(), indent=2) + "\n")
print("wrote", out)
