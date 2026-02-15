from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Dict, Any

VALID_SEVERITIES = {"low", "medium", "high"}
ALLOWLIST_RULES = {
    "CSRF_TOKEN_FORMAT",
    "INTEGER_ONLY",
    "FLOAT_ONLY",
    "EMAIL_FORMAT",
    "URL_FORMAT",
    "DATE_ISO8601",
    "SAFE_FILE_PATH",
    "SAFE_CHARSET",
}


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    description: str
    patterns: list[str]
    tags: list[str]


DEFAULT_RULES: list[Rule] = [
    # SQL Injection
    Rule("SQLI_KEYWORD", "high", "Potential SQL keywords/operators.", [
        r"\bselect\b", r"\bunion\b", r"\bdrop\b", r"\binsert\b", r"\bupdate\b", r"\bdelete\b", r"\bwhere\b", r"\bfrom\b", r"\btable\b",
        r"\bor\s+1=1\b", r"--", r"/\*", r"\bexec\b", r"\bcast\b", r"\bconvert\b", r"\bchar\b", r"\bconcat\b", r"\bsubstr\b", r"\bmid\b",
        r"\bbenchmark\b", r"\bsleep\b", r"\bwaitfor\b", r"\bpg_sleep\b", r"\bpg_terminate_backend\b"
    ], ["injection", "sqli"]),
    # Command Injection
    Rule("COMMAND_INJECTION", "high", "Shell command chaining/metacharacters.", [
        r";", r"&&", r"\|\|", r"`", r"\$\(", r"\|", r">", r"<", r"\n", r"\r", r"\x00", r"\x1a", r"\x1b", r"\x7f"
    ], ["command-execution"]),
    # XSS
    Rule("XSS_PATTERN", "medium", "Script/event handler patterns.", [
        r"<\s*script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"<iframe", r"<img", r"<svg", r"<object", r"<embed", r"<link", r"<body", r"<style", r"<base", r"<form", r"document\\.cookie", r"document\\.location", r"window\\.location", r"eval\(", r"alert\(", r"src\s*=\s*['\"]?javascript:"
    ], ["script-injection", "xss"]),
    # Path Traversal
    Rule("PATH_TRAVERSAL", "medium", "Traversal indicators.", [
        r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c", r"/etc/passwd", r"/windows/win.ini", r"\bboot\.ini\b"
    ], ["path-traversal"]),
    # CSRF tokens (allowlist: must match strict UUID or hex pattern)
    Rule("CSRF_TOKEN_FORMAT", "high", "CSRF token must be a valid UUID or hex string.", [
        r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9\-]{36})$"
    ], ["token-validation"]),
    # Integer allowlist (context-specific, e.g. age, id)
    Rule("INTEGER_ONLY", "high", "Input must be a valid integer.", [
        r"^-?\d+$"
    ], []),
    # Float allowlist
    Rule("FLOAT_ONLY", "high", "Input must be a valid float.", [
        r"^-?\d+(\.\d+)?$"
    ], []),
    # Email allowlist
    Rule("EMAIL_FORMAT", "medium", "Input must be a valid email address.", [
        r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    ], []),
    # URL allowlist
    Rule("URL_FORMAT", "medium", "Input must be a valid URL.", [
        r"^(https?|ftp)://[\w\-]+(\.[\w\-]+)+([/?#][^\s]*)?$"
    ], []),
    # Date allowlist (ISO 8601)
    Rule("DATE_ISO8601", "medium", "Input must be a valid ISO 8601 date.", [
        r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$"
    ], []),
    # Safe file path allowlist (no traversal, only safe chars, no leading slash)
    Rule("SAFE_FILE_PATH", "high", "File path must be safe (no traversal, only allowed chars, no leading slash).", [
        r"^(?![\\/])(?:(?!\.\./|\.\.\\)[\w\-./])+$"
    ], []),
    # Safe character set (ASCII printable, no control chars)
    Rule("SAFE_CHARSET", "medium", "Input must only contain safe printable characters.", [
        r"^[\x20-\x7E]+$"
    ], []),
]


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


def evaluate_rules(text: str, severity_weights: Dict[str, float], rule_overrides: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    rule_overrides = rule_overrides or {}
    hits: List[Dict[str, Any]] = []
    for rule in DEFAULT_RULES:
        if rule.name in ALLOWLIST_RULES:
            continue
        severity, description = _override(rule.name, rule.severity, rule.description, rule_overrides)
        for pattern in rule.patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                hits.append(_make_hit(rule.name, severity, description, pattern, severity_weights, rule.tags))
                break
    hits.extend(_length_charset_rules(text, severity_weights))
    hits.extend(_repetition_rules(text, severity_weights))
    return hits
