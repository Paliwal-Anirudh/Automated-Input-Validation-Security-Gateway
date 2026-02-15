from __future__ import annotations

from input_gateway.decision import decide


def test_decide_respects_default_thresholds() -> None:
    assert decide(2.0, {"warn": 0.55, "block": 1.75}) == "block"
    assert decide(0.7, {"warn": 0.55, "block": 1.75}) == "warn"
    assert decide(0.2, {"warn": 0.55, "block": 1.75}) == "allow"


def test_decide_blocks_on_invalid_score() -> None:
    assert decide("bad-score", {"warn": 0.55, "block": 1.75}) == "block"
    assert decide(float("nan"), {"warn": 0.55, "block": 1.75}) == "block"


def test_decide_uses_defaults_when_thresholds_invalid() -> None:
    assert decide(0.6, {"warn": "bad", "block": "bad"}) == "warn"
    assert decide(2.0, {"warn": "bad", "block": "bad"}) == "block"


def test_decide_handles_warn_greater_than_block_safely() -> None:
    # If thresholds are misconfigured, ensure no warn/block inversion occurs.
    assert decide(1.0, {"warn": 2.0, "block": 1.0}) == "allow"
    assert decide(2.0, {"warn": 2.0, "block": 1.0}) == "block"
