"""Shannon entropy helpers for generic secret detection."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Random tokens score high; English low."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
