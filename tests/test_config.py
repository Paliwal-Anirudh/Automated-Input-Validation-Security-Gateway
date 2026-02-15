from __future__ import annotations

import json

import pytest

from input_gateway.config import load_config


def test_load_config_returns_deep_copied_defaults() -> None:
    cfg_a = load_config(None)
    cfg_a["ai"]["timeout_s"] = 99
    cfg_a["decision_thresholds"]["warn"] = 0.99

    cfg_b = load_config(None)
    assert cfg_b["ai"]["timeout_s"] == 30
    assert cfg_b["decision_thresholds"]["warn"] == 0.55
    assert cfg_b["ai"]["enabled"] is False
    assert cfg_b["ai"]["api_key"] == ""


def test_load_config_deep_merges_nested_mappings(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "decision_thresholds": {"warn": 0.8},
                "ai": {"timeout_s": 12},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(str(path))
    assert cfg["decision_thresholds"]["warn"] == 0.8
    assert cfg["decision_thresholds"]["block"] == 1.75
    assert cfg["ai"]["timeout_s"] == 12
    assert cfg["ai"]["model"] == "gpt-5.2-chat"


def test_load_config_rejects_threshold_order(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "decision_thresholds": {"warn": 2.0, "block": 1.0},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="warn must be <= decision_thresholds.block"):
        load_config(str(path))


def test_load_config_rejects_non_numeric_severity_weight(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "severity_weights": {"low": "x"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="severity_weights.low must be numeric"):
        load_config(str(path))


def test_load_config_rejects_invalid_ai_timeout(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "ai": {"timeout_s": 0},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ai.timeout_s must be between 1 and 120"):
        load_config(str(path))


def test_load_config_rejects_empty_ai_api_key_when_enabled(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "ai": {"enabled": True, "api_key": "   "},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ai.api_key is required when ai.enabled is true"):
        load_config(str(path))


def test_load_config_allows_empty_ai_api_key_when_disabled(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "ai": {"enabled": False, "api_key": "   ", "endpoint": "", "model": ""},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(str(path))
    assert cfg["ai"]["enabled"] is False
    assert cfg["ai"]["api_key"] == ""


def test_load_config_uses_env_api_key_when_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "env-secret")
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps(
            {
                "ai": {"enabled": True, "api_key": ""},
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(str(path))
    assert cfg["ai"]["api_key"] == "env-secret"


def test_load_config_reads_utf8_bom_json(tmp_path) -> None:
    path = tmp_path / "cfg-bom.json"
    path.write_text(json.dumps({"ai": {"enabled": False}}), encoding="utf-8-sig")
    cfg = load_config(str(path))
    assert cfg["ai"]["enabled"] is False


def test_load_config_rejects_non_mapping_root(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(["invalid"]), encoding="utf-8")
    with pytest.raises(ValueError, match="Config root must be a mapping/object"):
        load_config(str(path))
