from __future__ import annotations

import json
from pathlib import Path

from input_gateway.logger import GatewayLogger


def _sample_report(i: int) -> dict:
    return {
        "timestamp": f"2026-01-01T00:00:0{i}Z",
        "input": {"sha256": f"hash-{i}"},
        "decision": "allow",
        "score": 0.1 * i,
        "hits": [{"reason": f"reason-{i}"}],
    }


def test_write_jsonl_appends_single_line(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "audit.jsonl"
    db_path = tmp_path / "logs" / "gateway.db"
    logger = GatewayLogger(str(log_path), str(db_path))

    report = _sample_report(1)
    logger.write_jsonl(report)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["input"]["sha256"] == "hash-1"


def test_save_decision_and_fetch_recent_round_trip(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "audit.jsonl"
    db_path = tmp_path / "logs" / "gateway.db"
    logger = GatewayLogger(str(log_path), str(db_path))
    logger.init_db()

    logger.save_decision(_sample_report(1))
    logger.save_decision(_sample_report(2))

    rows = logger.fetch_recent(10)
    assert len(rows) == 2
    assert rows[0]["input_hash"] == "hash-2"
    assert rows[1]["input_hash"] == "hash-1"
    assert rows[0]["reasons"] == "reason-2"


def test_save_decision_handles_malformed_report_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "audit.jsonl"
    db_path = tmp_path / "logs" / "gateway.db"
    logger = GatewayLogger(str(log_path), str(db_path))
    logger.init_db()

    malformed_report = {
        "input": "not-a-mapping",
        "decision": None,
        "score": "not-a-number",
        "hits": [{"reason": None}, "bad-hit-shape"],
        "timestamp": None,
    }
    logger.save_decision(malformed_report)

    rows = logger.fetch_recent(1)
    assert len(rows) == 1
    assert rows[0]["input_hash"] == "error"
    assert rows[0]["decision"] == "block"
    assert rows[0]["score"] == 0.0
    assert rows[0]["reasons"] == ""
    assert rows[0]["timestamp"] == ""


def test_fetch_recent_normalizes_bad_limits(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "audit.jsonl"
    db_path = tmp_path / "logs" / "gateway.db"
    logger = GatewayLogger(str(log_path), str(db_path))
    logger.init_db()

    for i in range(1, 16):
        logger.save_decision(_sample_report(i))

    assert len(logger.fetch_recent(0)) == 10
    assert len(logger.fetch_recent(-3)) == 10
    assert len(logger.fetch_recent(5)) == 5
    assert len(logger.fetch_recent(5000)) == 15
