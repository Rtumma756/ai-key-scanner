"""Detector package: provider regex registry + Shannon entropy."""
from .entropy import shannon_entropy
from .registry import DETECTORS, RawMatch, is_example_key, provider_names, scan_line

__all__ = ["DETECTORS", "RawMatch", "is_example_key", "provider_names",
           "scan_line", "shannon_entropy"]
