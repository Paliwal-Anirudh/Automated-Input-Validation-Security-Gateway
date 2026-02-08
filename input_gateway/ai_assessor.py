from __future__ import annotations

import json
from typing import Any, Dict
from urllib import request


VALID_DECISIONS = {"allow", "warn", "block"}


def ai_assess(raw_text: str, current_report: Dict[str, Any], ai_cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not ai_cfg.get("enabled", False):
        return {"enabled": False}

    endpoint = str(ai_cfg.get("endpoint", "")).strip()
    api_key = str(ai_cfg.get("api_key", "")).strip()
    model = str(ai_cfg.get("model", "")).strip()
    timeout_s = int(ai_cfg.get("timeout_s", 8))

    if not endpoint or not api_key or not model:
        return {
            "enabled": True,
            "status": "skipped",
            "reason": "AI enabled but endpoint/api_key/model is missing",
        }

    prompt = (
        "You are a security validator. Return strict JSON with keys "
        "recommended_decision (allow|warn|block), confidence (0-1), explanation. "
        "Input: " + raw_text[:3000] + "\nCurrent report: " + json.dumps(current_report)
    )

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }

    req = request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not isinstance(content, str):
            return {
                "enabled": True,
                "status": "invalid_response",
                "reason": "AI response content is not text",
            }
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            return {
                "enabled": True,
                "status": "invalid_response",
                "reason": "AI response was not valid JSON",
            }

        recommended = str(parsed.get("recommended_decision", "")).lower()
        if recommended not in VALID_DECISIONS:
            return {
                "enabled": True,
                "status": "invalid_response",
                "reason": "AI recommended_decision was missing or invalid",
            }

        return {
            "enabled": True,
            "status": "ok",
            "recommended_decision": recommended,
            "confidence": parsed.get("confidence", 0.5),
            "explanation": parsed.get("explanation", "No explanation."),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "reason": str(exc),
        }
