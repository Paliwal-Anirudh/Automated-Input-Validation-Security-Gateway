from __future__ import annotations

import math
from typing import Any, Dict

DEFAULT_BLOCK_THRESHOLD = 1.75
DEFAULT_WARN_THRESHOLD = 0.55


def _coerce_float(value: Any, default: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(result):
        return default
    return result


def _normalized_thresholds(thresholds: Dict[str, float]) -> tuple[float, float]:
    warn_threshold = _coerce_float(thresholds.get("warn"), DEFAULT_WARN_THRESHOLD)
    block_threshold = _coerce_float(thresholds.get("block"), DEFAULT_BLOCK_THRESHOLD)

    if warn_threshold < 0:
        warn_threshold = DEFAULT_WARN_THRESHOLD
    if block_threshold < 0:
        block_threshold = DEFAULT_BLOCK_THRESHOLD
    if warn_threshold > block_threshold:
        block_threshold = warn_threshold

    return warn_threshold, block_threshold

def decide(score: float, thresholds: Dict[str, float]) -> str:
    score_value = _coerce_float(score, float("inf"))
    if score_value == float("inf"):
        return "block"

    warn_threshold, block_threshold = _normalized_thresholds(thresholds)
    if score_value >= block_threshold:
        return "block"
    if score_value >= warn_threshold:
        return "warn"
    return "allow"
