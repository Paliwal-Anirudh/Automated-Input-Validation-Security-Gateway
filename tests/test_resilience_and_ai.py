import argparse
import json

from input_gateway.main import run_scan
from input_gateway.normalizer import normalize_text
from input_gateway.rules import evaluate_rules


def test_invalid_mitre_override_severity_falls_back_to_default() -> None:
    text = normalize_text("SELECT * FROM users")
    hits = evaluate_rules(
        text,
        {"low": 0.33, "medium": 0.55, "high": 1.75},
        {"SQLI_KEYWORD": {"severity": "HIGH"}},
    )
    sqli_hit = [h for h in hits if h["rule"] == "SQLI_KEYWORD"][0]
    assert sqli_hit["severity"] == "high"
    assert sqli_hit["score"] == 1.75


def test_scan_returns_structured_error_when_init_db_fails(monkeypatch, capsys) -> None:
    class BrokenLogger:
        def __init__(self, *_args, **_kwargs):
            pass

        def init_db(self) -> None:
            raise OSError("db init failed")

        def write_jsonl(self, _report):
            return

    monkeypatch.setattr("input_gateway.main.GatewayLogger", BrokenLogger)

    cfg = {
        "log_path": "logs/audit.jsonl",
        "db_path": "logs/gateway.db",
        "max_input_chars": 100000,
        "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
        "mitre_overrides": {},
        "decision_thresholds": {"warn": 0.55, "block": 1.75},
        "ai": {"enabled": False},
    }
    args = argparse.Namespace(text="hello", file=None, explain=False)
    code = run_scan(args, cfg)

    assert code == 1
    _, err = capsys.readouterr()
    payload = json.loads(err)
    assert payload["decision"] == "block"
    assert "db init failed" in payload["error"]["message"]


def test_ai_invalid_response_does_not_escalate(monkeypatch, capsys) -> None:
    monkeypatch.setattr("input_gateway.main.ai_assess", lambda *_args, **_kwargs: {"enabled": True, "status": "invalid_response", "reason": "bad format"})

    cfg = {
        "log_path": "logs/audit.jsonl",
        "db_path": "logs/gateway.db",
        "max_input_chars": 100000,
        "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
        "mitre_overrides": {},
        "decision_thresholds": {"warn": 0.55, "block": 1.75},
        "ai": {"enabled": True},
    }
    args = argparse.Namespace(text="hello normal input", file=None, explain=False)
    code = run_scan(args, cfg)

    assert code == 0
    out, _ = capsys.readouterr()
    payload = json.loads(out)
    assert payload["decision"] == "allow"
    assert payload["ai_assessment"]["status"] == "invalid_response"
