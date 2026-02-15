from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "decision_thresholds": {"block": 1.75, "warn": 0.55},
    "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
    "max_input_chars": 100000,
    "log_path": "logs/audit.jsonl",
    "db_path": "logs/gateway.db",
    "rule_overrides": {},
    "mitre_overrides": {},
    "ai": {
        "enabled": False,
        "provider": "openai-compatible",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "api_key": "",
        "model": "gpt-5.2-chat",
        "timeout_s": 30,
    },
}


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("YAML config requested but PyYAML is not installed") from exc

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping/object")
    return data


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def _ensure_mapping(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping/object")
    return value


def _ensure_number(value: Any, field_name: str) -> float:
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be numeric")
    return float(value)


def _ensure_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _normalize_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _resolve_ai_api_key(configured_key: str) -> str:
    if configured_key:
        return configured_key
    for name in ("AIVSG_AI_API_KEY", "OPENAI_API_KEY"):
        from_env = os.getenv(name, "").strip()
        if from_env:
            return from_env
    return ""


def _normalize_rule_overrides(cfg: Dict[str, Any]) -> None:
    raw_rule = cfg.get("rule_overrides")
    raw_legacy = cfg.get("mitre_overrides")

    if raw_rule is None and raw_legacy is None:
        normalized: Dict[str, Any] = {}
    elif raw_rule is None:
        normalized = _ensure_mapping(raw_legacy, "mitre_overrides")
    elif raw_legacy is None:
        normalized = _ensure_mapping(raw_rule, "rule_overrides")
    else:
        normalized = {
            **_ensure_mapping(raw_legacy, "mitre_overrides"),
            **_ensure_mapping(raw_rule, "rule_overrides"),
        }

    cfg["rule_overrides"] = dict(normalized)
    # Backward-compatible alias for older code paths/tests.
    cfg["mitre_overrides"] = dict(normalized)


def _validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    thresholds = _ensure_mapping(cfg.get("decision_thresholds"), "decision_thresholds")
    warn = _ensure_number(thresholds.get("warn"), "decision_thresholds.warn")
    block = _ensure_number(thresholds.get("block"), "decision_thresholds.block")
    if warn < 0 or block < 0:
        raise ValueError("decision_thresholds values must be >= 0")
    if warn > block:
        raise ValueError("decision_thresholds.warn must be <= decision_thresholds.block")
    thresholds["warn"] = warn
    thresholds["block"] = block

    severity_weights = _ensure_mapping(cfg.get("severity_weights"), "severity_weights")
    for level in ("low", "medium", "high"):
        value = _ensure_number(severity_weights.get(level), f"severity_weights.{level}")
        if value < 0:
            raise ValueError(f"severity_weights.{level} must be >= 0")
        severity_weights[level] = value

    max_input_chars = cfg.get("max_input_chars")
    if not isinstance(max_input_chars, int):
        raise ValueError("max_input_chars must be an integer")
    if max_input_chars <= 0:
        raise ValueError("max_input_chars must be > 0")

    cfg["log_path"] = _ensure_nonempty_string(cfg.get("log_path"), "log_path")
    cfg["db_path"] = _ensure_nonempty_string(cfg.get("db_path"), "db_path")

    _normalize_rule_overrides(cfg)

    ai = _ensure_mapping(cfg.get("ai"), "ai")
    if not isinstance(ai.get("enabled"), bool):
        raise ValueError("ai.enabled must be a boolean")
    ai["provider"] = _ensure_nonempty_string(ai.get("provider"), "ai.provider")
    ai["endpoint"] = _normalize_string(ai.get("endpoint"))
    ai["model"] = _normalize_string(ai.get("model"))
    ai["api_key"] = _resolve_ai_api_key(_normalize_string(ai.get("api_key")))

    timeout_s = ai.get("timeout_s")
    if not isinstance(timeout_s, int):
        raise ValueError("ai.timeout_s must be an integer")
    if timeout_s <= 0 or timeout_s > 120:
        raise ValueError("ai.timeout_s must be between 1 and 120")
    if ai["enabled"]:
        if not ai["endpoint"]:
            raise ValueError("ai.endpoint must be a non-empty string when ai.enabled is true")
        if not ai["model"]:
            raise ValueError("ai.model must be a non-empty string when ai.enabled is true")
        if not ai["api_key"]:
            raise ValueError("ai.api_key is required when ai.enabled is true")

    return cfg


def load_config(config_path: str | None) -> Dict[str, Any]:
    if not config_path:
        return _validate_config(copy.deepcopy(DEFAULT_CONFIG))

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if path.suffix.lower() in {".yaml", ".yml"}:
        custom = _load_yaml(path)
    else:
        with path.open("r", encoding="utf-8-sig") as handle:
            custom = json.load(handle)
        if not isinstance(custom, dict):
            raise ValueError("Config root must be a mapping/object")

    merged = _deep_merge(DEFAULT_CONFIG, custom)
    return _validate_config(merged)
