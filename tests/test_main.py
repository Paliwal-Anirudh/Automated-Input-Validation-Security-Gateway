from __future__ import annotations

import argparse
import json

from input_gateway.main import run_ai_assess, run_history, run_scan


class CaptureLogger:
    def __init__(self, *_args, **_kwargs):
        self.reports: list[dict] = []

    def init_db(self) -> None:
        return

    def write_jsonl(self, report) -> None:
        self.reports.append(report)

    def save_decision(self, _report) -> None:
        return

    def fetch_recent(self, _limit: int = 10):
        return [{"id": 1, "decision": "allow"}]


def base_cfg() -> dict:
    return {
        "log_path": "logs/audit.jsonl",
        "db_path": "logs/gateway.db",
        "max_input_chars": 100000,
        "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
        "mitre_overrides": {},
        "decision_thresholds": {"warn": 0.55, "block": 1.75},
        "ai": {"enabled": True, "endpoint": "https://example.test", "api_key": "k", "model": "m", "timeout_s": 8},
    }


def test_run_scan_refreshes_summary_after_ai_escalation(monkeypatch, capsys) -> None:
    monkeypatch.setattr("input_gateway.main.GatewayLogger", CaptureLogger)
    monkeypatch.setattr(
        "input_gateway.main.ai_assess",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "status": "ok",
            "recommended_decision": "block",
            "confidence": 0.9,
            "explanation": "model escalation",
        },
    )

    args = argparse.Namespace(text="hello world", file=None, explain=False)
    code = run_scan(args, base_cfg())

    assert code == 0
    out, _ = capsys.readouterr()
    payload = json.loads(out)
    assert payload["decision"] == "block"
    assert payload["explanation"]["summary"].startswith("Decision 'block'")


def test_run_history_returns_structured_error_on_failure(monkeypatch, capsys) -> None:
    class BrokenHistoryLogger(CaptureLogger):
        def init_db(self) -> None:
            raise OSError("history db failed")

    monkeypatch.setattr("input_gateway.main.GatewayLogger", BrokenHistoryLogger)
    args = argparse.Namespace(limit=10)

    code = run_history(args, base_cfg())

    assert code == 1
    _, err = capsys.readouterr()
    payload = json.loads(err)
    assert payload["decision"] == "block"
    assert "history db failed" in payload["error"]["message"]


def test_run_ai_assess_returns_structured_error_for_bad_report_path(monkeypatch, capsys) -> None:
    monkeypatch.setattr("input_gateway.main.GatewayLogger", CaptureLogger)
    args = argparse.Namespace(text="hello", file=None, config_report="does-not-exist.json")

    code = run_ai_assess(args, base_cfg())

    assert code == 1
    _, err = capsys.readouterr()
    payload = json.loads(err)
    assert payload["decision"] == "block"
    assert "does-not-exist.json" in payload["error"]["message"]


def test_run_ai_assess_enforces_max_input_chars(monkeypatch, capsys) -> None:
    monkeypatch.setattr("input_gateway.main.GatewayLogger", CaptureLogger)
    cfg = base_cfg()
    cfg["max_input_chars"] = 3
    args = argparse.Namespace(text="hello", file=None, config_report=None)

    code = run_ai_assess(args, cfg)

    assert code == 1
    _, err = capsys.readouterr()
    payload = json.loads(err)
    assert "max_input_chars" in payload["error"]["message"]
