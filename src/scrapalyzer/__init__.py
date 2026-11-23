"""Scrapalyzer: profile how a website exposes its data. The engine behind OpenCrawls Targets."""
from .models import SCHEMA, Finding, Profile, json_schema

__version__ = "0.1.0.dev0"
__all__ = ["SCHEMA", "Finding", "Profile", "json_schema", "__version__"]
