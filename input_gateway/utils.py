from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import math
from typing import Any, Dict, List

VALID_DECISIONS = {"allow", "warn", "block"}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _safe_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(score) or score < 0:
        return 0.0
    return round(score, 4)


def _safe_hits(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [hit for hit in value if isinstance(hit, dict)]


def _safe_decision(value: Any) -> str:
    decision = _safe_text(value).strip().lower()
    if decision in VALID_DECISIONS:
        return decision
    return "block"


def _safe_reason(hit: Dict[str, Any]) -> str:
    return _safe_text(hit.get("reason", ""))


def build_report(raw_text: Any, normalized_text: Any, hits: Any, score: Any, decision: Any) -> Dict[str, Any]:
    raw = _safe_text(raw_text)
    normalized = _safe_text(normalized_text)
    safe_hits = _safe_hits(hits)
    safe_score = _safe_score(score)
    safe_decision = _safe_decision(decision)

    return {
        "timestamp": now_iso(),
        "input": {
            "sha256": sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
            "length": len(raw),
        },
        "normalized": {
            "length": len(normalized),
        },
        "hits": safe_hits,
        "score": safe_score,
        "decision": safe_decision,
        "explanation": {
            "summary": f"Decision '{safe_decision}' from score {safe_score} based on {len(safe_hits)} hit(s).",
            "reasons": [_safe_reason(hit) for hit in safe_hits],
        },
    }


def build_error_report(message: Any) -> Dict[str, Any]:
    safe_message = _safe_text(message).strip() or "Unknown error"
    return {
        "timestamp": now_iso(),
        "decision": "block",
        "score": 999.0,
        "error": {"message": safe_message},
        "explanation": {"summary": "Fail-safe block due to input/runtime error."},
    }
