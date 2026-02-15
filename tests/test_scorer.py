from __future__ import annotations

from input_gateway.scorer import score_risk


def test_score_risk_sums_hit_scores() -> None:
    hits = [{"score": 0.55}, {"score": 1.75}]
    assert score_risk(hits) == 2.3


def test_score_risk_uses_severity_weight_fallback() -> None:
    hits = [{"severity_weight": 0.33}, {"score": 0.55}]
    assert score_risk(hits) == 0.88


def test_score_risk_ignores_invalid_and_nonfinite_values() -> None:
    hits = [{"score": "bad"}, {"score": float("nan")}, {"score": float("inf")}, {"score": 0.5}]
    assert score_risk(hits) == 0.5


def test_score_risk_clamps_negative_scores_to_zero() -> None:
    hits = [{"score": -4.0}, {"score": 1.0}]
    assert score_risk(hits) == 1.0


def test_score_risk_handles_none_and_malformed_hits() -> None:
    assert score_risk(None) == 0.0
    assert score_risk([{"score": 0.4}, "invalid-hit", 123, {"score": 0.1}]) == 0.5
