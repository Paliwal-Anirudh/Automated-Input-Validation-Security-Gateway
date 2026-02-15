from __future__ import annotations

import math
from typing import Any, Dict, Iterable, Mapping

def _safe_score_value(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(score):
        return 0.0
    if score < 0:
        return 0.0
    return score


def score_risk(hits: Iterable[Dict[str, Any]] | None) -> float:
    if hits is None:
        return 0.0

    total = 0.0
    for hit in hits:
        if not isinstance(hit, Mapping):
            continue
        # Fallback to severity_weight if score is missing or malformed.
        raw_score = hit.get("score", hit.get("severity_weight", 0.0))
        total += _safe_score_value(raw_score)
    return round(total, 4)
