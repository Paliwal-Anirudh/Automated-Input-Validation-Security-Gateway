from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Dict, Any

VALID_SEVERITIES = {"low", "medium", "high"}


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    description: str
    patterns: list[str]
    mitre_techniques: list[str]


DEFAULT_RULES: list[Rule] = [
    Rule("SQLI_KEYWORD", "high", "Potential SQL keywords/operators.", [r"\bselect\b", r"\bunion\b", r"\bdrop\b", r"\bor\s+1=1\b", r"--", r"/\*"], ["T1190", "T1059"]),
    Rule("COMMAND_INJECTION", "high", "Shell command chaining/metacharacters.", [r";", r"&&", r"\|\|", r"`", r"\$\("], ["T1059"]),
    Rule("XSS_PATTERN", "medium", "Script/event handler patterns.", [r"<\s*script", r"onerror\s*=", r"onload\s*=", r"javascript:"], ["T1059", "T1189"]),
    Rule("PATH_TRAVERSAL", "medium", "Traversal indicators.", [r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"], ["T1006"]),
]


def _make_hit(rule: str, severity: str, reason: str, matched: str, severity_weights: Dict[str, float], mitre: list[str]) -> Dict[str, Any]:
    weight = float(severity_weights.get(severity, 0.0))
    return {
        "rule": rule,
        "severity": severity,
        "severity_weight": weight,
        "score": weight,
        "reason": reason,
        "matched": matched,
        "mitre_techniques": mitre,
    }


def _length_charset_rules(text: str, severity_weights: Dict[str, float]) -> list[Dict[str, Any]]:
    hits: list[Dict[str, Any]] = []
    if len(text) > 5000:
        hits.append(_make_hit("LENGTH_ANOMALY", "medium", "Input length is unusually large.", f"length={len(text)}", severity_weights, ["T1499"]))
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    if text and special / len(text) > 0.3:
        hits.append(_make_hit("SPECIAL_CHAR_DENSITY", "medium", "High special-character density can indicate obfuscation.", f"density={special/len(text):.2f}", severity_weights, ["T1027"]))
    return hits


def _repetition_rules(text: str, severity_weights: Dict[str, float]) -> list[Dict[str, Any]]:
    hits: list[Dict[str, Any]] = []
    for token in ["../", "<script", "or 1=1", "\\x", "%"]:
        if text.count(token) >= 3:
            hits.append(_make_hit("REPETITION_PATTERN", "low", "Suspicious pattern repetition detected.", f"{token} repeated {text.count(token)} times", severity_weights, ["T1027"]))
            break
    return hits


def _normalize_override_severity(override_severity: Any, default_severity: str) -> tuple[str, bool]:
    if not isinstance(override_severity, str):
        return default_severity, False
    candidate = override_severity.strip().lower()
    if candidate in VALID_SEVERITIES:
        return candidate, True
    return default_severity, False


def _override(rule_name: str, severity: str, description: str, mitre_overrides: Dict[str, Any]) -> tuple[str, str]:
    override = mitre_overrides.get(rule_name, {})
    if not isinstance(override, dict):
        return severity, description

    chosen_severity, _ = _normalize_override_severity(override.get("severity"), severity)
    chosen_description = override.get("description", description)
    if not isinstance(chosen_description, str):
        chosen_description = description

    return chosen_severity, chosen_description


def evaluate_rules(text: str, severity_weights: Dict[str, float], mitre_overrides: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    mitre_overrides = mitre_overrides or {}
    hits: List[Dict[str, Any]] = []
    for rule in DEFAULT_RULES:
        severity, description = _override(rule.name, rule.severity, rule.description, mitre_overrides)
        for pattern in rule.patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                hits.append(_make_hit(rule.name, severity, description, pattern, severity_weights, rule.mitre_techniques))
                break
    hits.extend(_length_charset_rules(text, severity_weights))
    hits.extend(_repetition_rules(text, severity_weights))
    return hits
