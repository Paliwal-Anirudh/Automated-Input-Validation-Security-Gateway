from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any

MAX_FETCH_LIMIT = 1000
DEFAULT_FETCH_LIMIT = 10


class GatewayLogger:
    def __init__(self, log_path: str, db_path: str) -> None:
        self.log_path = Path(log_path)
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=5.0)

    def _normalize_limit(self, limit: int) -> int:
        if not isinstance(limit, int):
            return DEFAULT_FETCH_LIMIT
        if limit <= 0:
            return DEFAULT_FETCH_LIMIT
        return min(limit, MAX_FETCH_LIMIT)

    def _safe_score(self, value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _safe_input_hash(self, report: Dict[str, Any]) -> str:
        input_section = report.get("input")
        if not isinstance(input_section, dict):
            return "error"
        value = input_section.get("sha256", "error")
        return str(value) if value is not None else "error"

    def _safe_decision(self, report: Dict[str, Any]) -> str:
        value = report.get("decision", "block")
        return str(value) if value is not None else "block"

    def _safe_timestamp(self, report: Dict[str, Any]) -> str:
        value = report.get("timestamp", "")
        return str(value) if value is not None else ""

    def _safe_reasons(self, report: Dict[str, Any]) -> str:
        hits = report.get("hits", [])
        if not isinstance(hits, list):
            return ""

        reasons: list[str] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            reason = hit.get("reason", "")
            if reason is None:
                continue
            reasons.append(str(reason))
        return "; ".join(reasons)

    def write_jsonl(self, report: Dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(report, ensure_ascii=False) + "\n")

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    input_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    score REAL NOT NULL,
                    reasons TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp)")

    def save_decision(self, report: Dict[str, Any]) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        reasons = self._safe_reasons(report)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO decisions (input_hash, decision, score, reasons, timestamp) VALUES (?, ?, ?, ?, ?)",
                (
                    self._safe_input_hash(report),
                    self._safe_decision(report),
                    self._safe_score(report.get("score", 0.0)),
                    reasons,
                    self._safe_timestamp(report),
                ),
            )

    def fetch_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        safe_limit = self._normalize_limit(limit)
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, input_hash, decision, score, reasons, timestamp FROM decisions ORDER BY id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]
