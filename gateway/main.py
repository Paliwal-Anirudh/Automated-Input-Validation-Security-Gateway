#!/usr/bin/env python3
import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Iterable, List, Dict, Any, Optional


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    description: str
    patterns: Iterable[str]


RULES: List[Rule] = [
    Rule(
        name="SQLI_KEYWORD",
        severity="high",
        description="Common SQL injection keywords and operators.",
        patterns=[r"\bselect\b", r"\bunion\b", r"\bdrop\b", r"\binsert\b", r"\bupdate\b", r"--", r"/\*", r"\bor\s+1=1\b"],
    ),
    Rule(
        name="COMMAND_INJECTION",
        severity="high",
        description="Shell control operators often used for command injection.",
        patterns=[r";", r"&&", r"\|\|", r"\|", r"`", r"\$\("],
    ),
    Rule(
        name="XSS_SCRIPT",
        severity="medium",
        description="XSS script tags or inline event handlers.",
        patterns=[r"<\s*script", r"onerror\s*=", r"onload\s*=", r"javascript:"],
    ),
    Rule(
        name="PATH_TRAVERSAL",
        severity="medium",
        description="Path traversal patterns.",
        patterns=[r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"],
    ),
]

SEVERITY_WEIGHTS = {"low": 10, "medium": 30, "high": 70}


def normalize_text(raw_text: str) -> str:
    cleaned = raw_text.strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.lower()


def validate_text(text: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for rule in RULES:
        for pattern in rule.patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                hits.append(
                    {
                        "rule": rule.name,
                        "severity": rule.severity,
                        "description": rule.description,
                        "pattern": pattern,
                    }
                )
                break
    return hits


def score_risk(hits: Iterable[Dict[str, Any]]) -> int:
    total = 0
    for hit in hits:
        total += SEVERITY_WEIGHTS.get(hit["severity"], 0)
    return total


def decide(score: int) -> str:
    if score >= 51:
        return "block"
    if score >= 31:
        return "warn"
    return "allow"


def build_report(raw_text: str, normalized_text: str, hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = score_risk(hits)
    decision = decide(score)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input": {
            "sha256": sha256(raw_text.encode("utf-8")).hexdigest(),
            "length": len(raw_text),
        },
        "normalized": {
            "length": len(normalized_text),
        },
        "hits": hits,
        "score": score,
        "decision": decision,
        "explanation": {
            "summary": f"Decision '{decision}' based on score {score}.",
            "rule_count": len(hits),
        },
    }


def build_error_report(message: str, source: str = "cli") -> Dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": "block",
        "score": 100,
        "error": {
            "source": source,
            "message": message,
        },
        "explanation": {
            "summary": "Fail-safe block due to input or runtime error.",
        },
    }


def log_report(report: Dict[str, Any], log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(report) + "\n")


def load_input(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        return Path(args.file).read_text(encoding="utf-8")
    raise ValueError("Provide --text or --file")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automated Input Validation & Security Gateway")
    parser.add_argument("--log", default="logs/audit.jsonl", help="Path to JSONL log file")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--text", help="Raw input text to evaluate")
    input_group.add_argument("--file", help="Path to a file containing input")

    return parser.parse_args(argv)


def main() -> None:
    try:
        args = parse_args()
        raw_text = load_input(args)
        normalized = normalize_text(raw_text)
        hits = validate_text(normalized)
        report = build_report(raw_text, normalized, hits)
        log_report(report, Path(args.log))
        print(json.dumps(report, indent=2))
    except Exception as exc:  # fail-safe: block and explain instead of traceback
        log_path = Path("logs/audit.jsonl")
        if "args" in locals() and getattr(args, "log", None):
            log_path = Path(args.log)
        error_report = build_error_report(str(exc), source="runtime")
        try:
            log_report(error_report, log_path)
        finally:
            print(json.dumps(error_report, indent=2), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
