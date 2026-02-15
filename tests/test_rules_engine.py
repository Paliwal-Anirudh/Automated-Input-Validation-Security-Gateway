import re

from input_gateway.decision import decide
from input_gateway.normalizer import normalize_text
from input_gateway.rules import ALL_RULES, evaluate_rules
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


def test_all_rule_patterns_compile() -> None:
    for rule in ALL_RULES:
        for pattern in rule.patterns:
            re.compile(pattern, re.IGNORECASE)


def test_format_validators_are_not_applied_in_default_scan() -> None:
    text = normalize_text("hello world this is harmless")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    assert all(hit["rule"] != "SAFE_CHARSET" for hit in hits)
    assert all(hit["rule"] != "INTEGER_ONLY" for hit in hits)


def test_format_validator_can_be_applied_explicitly() -> None:
    text = normalize_text("not-an-email")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {}, active_rule_names=["EMAIL_FORMAT"])
    assert any(hit["rule"] == "EMAIL_FORMAT" for hit in hits)


def test_command_injection_detects_shell_chaining() -> None:
    text = normalize_text("user input && whoami")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    assert any(hit["rule"] == "COMMAND_INJECTION" for hit in hits)


def test_xss_markup_does_not_trigger_command_injection_by_angle_brackets() -> None:
    text = normalize_text("<script>alert(1)</script>")
    hits = evaluate_rules(text, SEVERITY_WEIGHTS, {})
    assert any(hit["rule"] == "XSS_PATTERN" for hit in hits)
    assert all(hit["rule"] != "COMMAND_INJECTION" for hit in hits)
