"""agents — Pillar 1: agent identity inventory (KeySentry).

Parses agent / MCP config files and inventories which agents exist in a
repo and which credentials each one holds.

HARD RULES (same spine as the rest of aiscan):
  * Only fingerprints (SHA-256 first 16 hex) and prefix4-masked values
    ever leave this module. A raw key value is fingerprinted in-memory
    and discarded immediately; it never appears in any returned dict,
    printed output, or log line.
  * Values marked as example / test keys (detectors.is_example_key)
    are never reported as credentials — the example-key filter is
    load-bearing and is never weakened here.
  * No network calls, no provider APIs, stdlib only.
"""
from __future__ import annotations

from .scanner import (
    build_inventory,
    build_mapping,
    find_agent_configs,
    load_result_fingerprints,
    scan_config_file,
)

__all__ = [
    "build_inventory",
    "build_mapping",
    "find_agent_configs",
    "load_result_fingerprints",
    "scan_config_file",
]
