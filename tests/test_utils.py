from __future__ import annotations

from datetime import datetime
from hashlib import sha256

from input_gateway.utils import build_error_report, build_report, now_iso


def test_now_iso_is_timezone_aware_isoformat() -> None:
    value = now_iso()
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None


def test_build_report_basic_shape() -> None:
    raw = "Hello"
    normalized = "hello"
    hits = [{"rule": "X", "reason": "why", "score": 0.55}]
    report = build_report(raw, normalized, hits, 0.55, "warn")

    assert report["input"]["sha256"] == sha256(raw.encode("utf-8")).hexdigest()
    assert report["input"]["length"] == 5
    assert report["normalized"]["length"] == 5
    assert report["decision"] == "warn"
    assert report["score"] == 0.55
    assert report["explanation"]["reasons"] == ["why"]


def test_build_report_handles_malformed_inputs() -> None:
    report = build_report(
        raw_text=None,
        normalized_text=123,
        hits=[{"reason": None}, "bad-hit-shape", {"reason": 404}],
        score=float("nan"),
        decision="unexpected",
    )

    assert report["input"]["length"] == 0
    assert report["normalized"]["length"] == 3
    assert report["decision"] == "block"
    assert report["score"] == 0.0
    assert report["hits"] == [{"reason": None}, {"reason": 404}]
    assert report["explanation"]["reasons"] == ["", "404"]


def test_build_error_report_normalizes_message() -> None:
    report = build_error_report(None)
    assert report["decision"] == "block"
    assert report["score"] == 999.0
    assert report["error"]["message"] == "Unknown error"
