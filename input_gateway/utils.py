from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Any, List


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report(raw_text: str, normalized_text: str, hits: List[Dict[str, Any]], score: float, decision: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "input": {
            "sha256": sha256(raw_text.encode("utf-8")).hexdigest(),
            "length": len(raw_text),
        },
        "normalized": {
            "length": len(normalized_text),
        },
        "hits": hits,
        "score": score,
        "decision": decision,
        "explanation": {
            "summary": f"Decision '{decision}' from score {score} based on {len(hits)} hit(s).",
            "reasons": [hit.get("reason", "") for hit in hits],
        },
    }


def build_error_report(message: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "decision": "block",
        "score": 999.0,
        "error": {"message": message},
        "explanation": {"summary": "Fail-safe block due to input/runtime error."},
    }
