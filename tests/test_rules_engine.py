from input_gateway.decision import decide
from input_gateway.normalizer import normalize_text
from input_gateway.rules import evaluate_rules
from input_gateway.scorer import score_risk

SEVERITY_WEIGHTS = {"low": 0.33, "medium": 0.55, "high": 1.75}


def test_sqli_detected_and_blocked() -> None:
    text = normalize_text("SELECT * FROM users WHERE a OR 1=1")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    assert any(hit["rule"] == "SQLI_KEYWORD" for hit in hits)
    assert any(hit["severity"] == "high" for hit in hits)
    score = score_risk(hits)
    assert decide(score, {"block": 1.75, "warn": 0.55}) == "block"


def test_clean_input_allowed() -> None:
    text = normalize_text("hello world this is harmless")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    score = score_risk(hits)
    assert hits == []
    assert decide(score, {"block": 1.75, "warn": 0.55}) == "allow"


def test_repetition_rule_warn() -> None:
    text = normalize_text("../ ../ ../ file path")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    assert any(hit["rule"] == "REPETITION_PATTERN" for hit in hits)
    score = score_risk(hits)
    assert decide(score, {"block": 1.75, "warn": 0.55}) in {"allow", "warn"}
