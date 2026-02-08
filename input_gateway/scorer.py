from typing import Dict, Any, Iterable


def score_risk(hits: Iterable[Dict[str, Any]]) -> float:
    return round(sum(float(hit.get("score", 0.0)) for hit in hits), 4)
