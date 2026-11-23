"""Scrapalyzer: profile how a website exposes its data. The engine behind OpenCrawls Targets."""
__version__ = "0.1.0.dev0"

from .models import SCHEMA, Finding, Profile, json_schema  # noqa: E402
from .api import analyze, analyze_replay, analyze_sync  # noqa: E402

__all__ = ["SCHEMA", "Finding", "Profile", "json_schema", "analyze", "analyze_sync", "analyze_replay", "__version__"]
