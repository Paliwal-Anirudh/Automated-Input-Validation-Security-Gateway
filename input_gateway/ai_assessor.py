from __future__ import annotations

import json
from typing import Any, Dict
from urllib import error, request


VALID_DECISIONS = {"allow", "warn", "block"}


def _normalize_timeout(value: Any) -> int:
    try:
        timeout_s = int(value)
    except (TypeError, ValueError):
        return 8
    return max(1, min(timeout_s, 120))


def _extract_content(body: Dict[str, Any]) -> str | None:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message", {})
    if not isinstance(message, dict):
        return None
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None

    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        text = block.get("text")
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts) if parts else None


def _strip_code_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```") and value.endswith("```"):
        lines = value.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return value


def _parse_model_json(content: str) -> Dict[str, Any] | None:
    cleaned = _strip_code_fence(content)
    candidates = [cleaned]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        candidates.append(cleaned[start : end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _normalize_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    if confidence < 0:
        return 0.0
    if confidence > 1:
        return 1.0
    return confidence


def ai_assess(raw_text: str, current_report: Dict[str, Any], ai_cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not ai_cfg.get("enabled", False):
        return {"enabled": False}

    endpoint = str(ai_cfg.get("endpoint", "")).strip()
    api_key = str(ai_cfg.get("api_key", "")).strip()
    model = str(ai_cfg.get("model", "")).strip()
    timeout_s = _normalize_timeout(ai_cfg.get("timeout_s", 8))

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
        if not isinstance(body, dict):
            return {
                "enabled": True,
                "status": "invalid_response",
                "reason": "AI response body was not an object",
            }
        content = _extract_content(body)
        if content is None:
            return {
                "enabled": True,
                "status": "invalid_response",
                "reason": "AI response content was missing or invalid",
            }
        parsed = _parse_model_json(content)
        if parsed is None:
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
            "confidence": _normalize_confidence(parsed.get("confidence", 0.5)),
            "explanation": str(parsed.get("explanation", "No explanation.")),
        }
    except error.HTTPError as exc:
        detail = ""
        try:
            payload = exc.read().decode("utf-8", errors="replace").strip()
            if payload:
                detail = f": {payload[:300]}"
        except Exception:
            detail = ""
        return {
            "enabled": True,
            "status": "error",
            "reason": f"HTTP {exc.code} {exc.reason}{detail}",
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "reason": str(exc),
        }
