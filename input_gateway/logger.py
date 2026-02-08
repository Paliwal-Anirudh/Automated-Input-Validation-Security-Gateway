from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any


class GatewayLogger:
    def __init__(self, log_path: str, db_path: str) -> None:
        self.log_path = Path(log_path)
        self.db_path = Path(db_path)

    def write_jsonl(self, report: Dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(report) + "\n")

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
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
        reasons = "; ".join(hit.get("reason", "") for hit in report.get("hits", []))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO decisions (input_hash, decision, score, reasons, timestamp) VALUES (?, ?, ?, ?, ?)",
                (
                    report.get("input", {}).get("sha256", "error"),
                    report.get("decision", "block"),
                    float(report.get("score", 0.0)),
                    reasons,
                    report.get("timestamp", ""),
                ),
            )

    def fetch_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, input_hash, decision, score, reasons, timestamp FROM decisions ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
