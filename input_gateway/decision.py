from typing import Dict


def decide(score: float, thresholds: Dict[str, float]) -> str:
    block_threshold = float(thresholds.get("block", 1.75))
    warn_threshold = float(thresholds.get("warn", 0.55))
    if score >= block_threshold:
        return "block"
    if score >= warn_threshold:
        return "warn"
    return "allow"
