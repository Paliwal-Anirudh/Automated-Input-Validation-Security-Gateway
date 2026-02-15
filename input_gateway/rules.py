from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List

VALID_SEVERITIES = {"low", "medium", "high"}
VALID_MODES = {"detect", "allowlist"}


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    description: str
    patterns: list[str]
    tags: list[str]
    mode: str = "detect"


DEFAULT_RULES: list[Rule] = [
    Rule(
        "SQLI_KEYWORD",
        "high",
        "Potential SQL keywords/operators.",
        [
            r"\bselect\b",
            r"\bunion\b",
            r"\bdrop\b",
            r"\binsert\b",
            r"\bupdate\b",
            r"\bdelete\b",
            r"\bwhere\b",
            r"\bfrom\b",
            r"\btable\b",
            r"\bor\s+1=1\b",
            r"--",
            r"/\*",
            r"\bexec\b",
            r"\bcast\b",
            r"\bconvert\b",
            r"\bchar\b",
            r"\bconcat\b",
            r"\bsubstr\b",
            r"\bmid\b",
            r"\bbenchmark\b",
            r"\bsleep\b",
            r"\bwaitfor\b",
            r"\bpg_sleep\b",
            r"\bpg_terminate_backend\b",
        ],
        ["injection", "sqli"],
    ),
    Rule(
        "COMMAND_INJECTION",
        "high",
        "Shell command chaining/metacharacters.",
        [
            r"(?:;|&&|\|\|)\s*[a-zA-Z_./-]+",
            r"`[^`]+`",
            r"\$\([^)]*\)",
            r"(?:^|[\s;|&])(?:bash|sh|zsh|cmd|powershell|pwsh|python|perl|ruby|wget|curl|nc|netcat)\b",
            r"(?:^|[\s;|&])(?:cat|type|echo|printf)\b[^\n\r]*(?:>>?|<)\s*\S+",
            r"\x00",
            r"\x1a",
            r"\x1b",
            r"\x7f",
        ],
        ["command-execution"],
    ),
    Rule(
        "XSS_PATTERN",
        "medium",
        "Script/event handler patterns.",
        [
            r"<\s*script",
            r"onerror\s*=",
            r"onload\s*=",
            r"javascript:",
            r"<iframe",
            r"<img",
            r"<svg",
            r"<object",
            r"<embed",
            r"<link",
            r"<body",
            r"<style",
            r"<base",
            r"<form",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
            r"eval\(",
            r"alert\(",
            r"src\s*=\s*['\"]?javascript:",
        ],
        ["script-injection", "xss"],
    ),
    Rule(
        "PATH_TRAVERSAL",
        "medium",
        "Traversal indicators.",
        [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"/etc/passwd",
            r"/windows/win.ini",
            r"\bboot\.ini\b",
        ],
        ["path-traversal"],
    ),
]


OPTIONAL_FORMAT_RULES: list[Rule] = [
    Rule("CSRF_TOKEN_FORMAT", "high", "CSRF token must be a valid UUID or hex string.", [r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9\-]{36})$"], ["token-validation"], mode="allowlist"),
    Rule("INTEGER_ONLY", "high", "Input must be a valid integer.", [r"^-?\d+$"], ["format-validation"], mode="allowlist"),
    Rule("FLOAT_ONLY", "high", "Input must be a valid float.", [r"^-?\d+(\.\d+)?$"], ["format-validation"], mode="allowlist"),
    Rule("EMAIL_FORMAT", "medium", "Input must be a valid email address.", [r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"], ["format-validation"], mode="allowlist"),
    Rule("URL_FORMAT", "medium", "Input must be a valid URL.", [r"^(https?|ftp)://[\w\-]+(\.[\w\-]+)+([/?#][^\s]*)?$"], ["format-validation"], mode="allowlist"),
    Rule("DATE_ISO8601", "medium", "Input must be a valid ISO 8601 date.", [r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$"], ["format-validation"], mode="allowlist"),
    Rule("SAFE_FILE_PATH", "high", "File path must be safe (no traversal, only allowed chars, no leading slash).", [r"^(?![\\/])(?:(?!\.\./|\.\.\\)[\w\-./])+$"], ["format-validation"], mode="allowlist"),
    Rule("SAFE_CHARSET", "medium", "Input must only contain safe printable characters.", [r"^[\x20-\x7E]+$"], ["format-validation"], mode="allowlist"),
]

ALL_RULES: list[Rule] = DEFAULT_RULES + OPTIONAL_FORMAT_RULES
RULES_BY_NAME: dict[str, Rule] = {rule.name: rule for rule in ALL_RULES}


def _make_hit(rule: str, severity: str, reason: str, matched: str, severity_weights: Dict[str, float], tags: list[str]) -> Dict[str, Any]:
    weight = float(severity_weights.get(severity, 0.0))
    return {
        "rule": rule,
        "severity": severity,
        "severity_weight": weight,
        "score": weight,
        "reason": reason,
        "matched": matched,
        "tags": tags,
    }


def _length_charset_rules(text: str, severity_weights: Dict[str, float]) -> list[Dict[str, Any]]:
    hits: list[Dict[str, Any]] = []
    if len(text) > 5000:
        hits.append(_make_hit("LENGTH_ANOMALY", "medium", "Input length is unusually large.", f"length={len(text)}", severity_weights, ["resource-abuse"]))
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    if text and special / len(text) > 0.3:
        hits.append(_make_hit("SPECIAL_CHAR_DENSITY", "medium", "High special-character density can indicate obfuscation.", f"density={special/len(text):.2f}", severity_weights, ["obfuscation"]))
    return hits


def _repetition_rules(text: str, severity_weights: Dict[str, float]) -> list[Dict[str, Any]]:
    hits: list[Dict[str, Any]] = []
    for token in ["../", "<script", "or 1=1", "\\x", "%"]:
        if text.count(token) >= 3:
            hits.append(_make_hit("REPETITION_PATTERN", "low", "Suspicious pattern repetition detected.", f"{token} repeated {text.count(token)} times", severity_weights, ["obfuscation"]))
            break
    return hits


def _normalize_override_severity(override_severity: Any, default_severity: str) -> tuple[str, bool]:
    if not isinstance(override_severity, str):
        return default_severity, False
    candidate = override_severity.strip().lower()
    if candidate in VALID_SEVERITIES:
        return candidate, True
    return default_severity, False


def _override(rule_name: str, severity: str, description: str, rule_overrides: Dict[str, Any]) -> tuple[str, str]:
    override = rule_overrides.get(rule_name, {})
    if not isinstance(override, dict):
        return severity, description

    chosen_severity, _ = _normalize_override_severity(override.get("severity"), severity)
    chosen_description = override.get("description", description)
    if not isinstance(chosen_description, str):
        chosen_description = description

    return chosen_severity, chosen_description


def _first_matching_pattern(text: str, patterns: list[str]) -> tuple[str | None, int]:
    valid_patterns = 0
    for pattern in patterns:
        try:
            matched = re.search(pattern, text, flags=re.IGNORECASE)
            valid_patterns += 1
            if matched:
                return pattern, valid_patterns
        except re.error:
            continue
    return None, valid_patterns


def _select_rules(active_rule_names: list[str] | None) -> list[Rule]:
    if not active_rule_names:
        return DEFAULT_RULES
    selected: list[Rule] = []
    for name in active_rule_names:
        rule = RULES_BY_NAME.get(name)
        if rule is not None:
            selected.append(rule)
    return selected


def evaluate_rules(
    text: str,
    severity_weights: Dict[str, float],
    rule_overrides: Dict[str, Any] | None = None,
    active_rule_names: list[str] | None = None,
    mitre_overrides: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    if rule_overrides is None:
        rule_overrides = mitre_overrides or {}
    elif isinstance(mitre_overrides, dict) and mitre_overrides:
        merged = dict(mitre_overrides)
        merged.update(rule_overrides)
        rule_overrides = merged

    hits: List[Dict[str, Any]] = []
    for rule in _select_rules(active_rule_names):
        if rule.mode not in VALID_MODES:
            continue
        severity, description = _override(rule.name, rule.severity, rule.description, rule_overrides)
        matched_pattern, valid_patterns = _first_matching_pattern(text, rule.patterns)
        if valid_patterns == 0:
            continue

        if rule.mode == "detect" and matched_pattern is not None:
            hits.append(_make_hit(rule.name, severity, description, matched_pattern, severity_weights, rule.tags))
        if rule.mode == "allowlist" and matched_pattern is None:
            hits.append(_make_hit(rule.name, severity, description, "<no allowlist pattern match>", severity_weights, rule.tags))

    if active_rule_names is None:
        hits.extend(_length_charset_rules(text, severity_weights))
        hits.extend(_repetition_rules(text, severity_weights))
    return hits
