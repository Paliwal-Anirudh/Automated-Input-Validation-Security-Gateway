from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "decision_thresholds": {"block": 1.75, "warn": 0.55},
    "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
    "max_input_chars": 100000,
    "log_path": "logs/audit.jsonl",
    "db_path": "logs/gateway.db",
    "rule_overrides": {},
    "ai": {
        "enabled": False,
        "provider": "openai-compatible",
        "endpoint": "",
        "api_key": "",
        "model": "",
        "timeout_s": 8,
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


def load_config(config_path: str | None) -> Dict[str, Any]:
    if not config_path:
        return dict(DEFAULT_CONFIG)

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if path.suffix.lower() in {".yaml", ".yml"}:
        custom = _load_yaml(path)
    else:
        with path.open("r", encoding="utf-8") as handle:
            custom = json.load(handle)
        if not isinstance(custom, dict):
            raise ValueError("Config root must be a mapping/object")

    merged = dict(DEFAULT_CONFIG)
    for key, value in custom.items():
        if key in {"decision_thresholds", "severity_weights", "ai"} and isinstance(value, dict):
            merged[key] = {**DEFAULT_CONFIG[key], **value}
        else:
            merged[key] = value
    return merged
