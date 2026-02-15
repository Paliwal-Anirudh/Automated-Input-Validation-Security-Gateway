#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from input_gateway.ai_assessor import ai_assess
from input_gateway.config import load_config
from input_gateway.decision import decide
from input_gateway.logger import GatewayLogger
from input_gateway.normalizer import normalize_text
from input_gateway.rules import evaluate_rules
from input_gateway.scorer import score_risk
from input_gateway.utils import build_error_report, build_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Input Validation Security Gateway")
    parser.add_argument("--config", help="Path to JSON/YAML config file", default=None)

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan input and produce decision")
    group = scan.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Inline input text")
    group.add_argument("--file", help="Path to input file")
    scan.add_argument("--explain", action="store_true", help="Print pretty explanation")

    history = sub.add_parser("history", help="Show recent decisions")
    history.add_argument("--limit", type=int, default=10)

    return parser.parse_args()


def _load_scan_text(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        return Path(args.file).read_text(encoding="utf-8")
    # Interactive prompt if neither provided
    print("No --text or --file provided. Please enter input text (end with Ctrl+D or Ctrl+Z on Windows):")
    try:
        # For multi-line input, read until EOF
        return sys.stdin.read().strip()
    except EOFError:
        raise ValueError("No input provided.")


def _escalate_decision(current: str, ai_recommended: str) -> str:
    order = {"allow": 0, "warn": 1, "block": 2}
    if ai_recommended not in order:
        return current
    return ai_recommended if order[ai_recommended] > order.get(current, 0) else current


def _safe_write_error(logger: GatewayLogger | None, error: dict) -> None:
    if logger is None:
        return
    try:
        logger.write_jsonl(error)
    except Exception:
        return


def run_scan(args: argparse.Namespace, cfg: dict) -> int:
    logger: GatewayLogger | None = None

    try:
        logger = GatewayLogger(cfg["log_path"], cfg["db_path"])
        logger.init_db()

        raw_text = _load_scan_text(args)
        if len(raw_text) > int(cfg["max_input_chars"]):
            raise ValueError(f"Input exceeds max_input_chars={cfg['max_input_chars']}")

        normalized = normalize_text(raw_text)
        overrides = cfg.get("rule_overrides")
        if not isinstance(overrides, dict):
            overrides = cfg.get("mitre_overrides", {})
        hits = evaluate_rules(normalized, cfg["severity_weights"], overrides)
        hits = evaluate_rules(normalized, cfg["severity_weights"], cfg.get("rule_overrides", {}))
        score = score_risk(hits)
        decision = decide(score, cfg["decision_thresholds"])
        report = build_report(raw_text, normalized, hits, score, decision)

        ai_result = ai_assess(raw_text, report, cfg.get("ai", {}))
        report["ai_assessment"] = ai_result
        if ai_result.get("status") == "ok":
            report["decision"] = _escalate_decision(report["decision"], str(ai_result.get("recommended_decision", "warn")))

        logger.write_jsonl(report)
        logger.save_decision(report)

        print(json.dumps(report, indent=2))
        if args.explain:
            print(f"\nExplanation: {report['explanation']['summary']}")
        return 0
    except Exception as exc:
        error = build_error_report(str(exc))
        _safe_write_error(logger, error)
        print(json.dumps(error, indent=2), file=sys.stderr)
        return 1


def run_history(args: argparse.Namespace, cfg: dict) -> int:
    logger = GatewayLogger(cfg["log_path"], cfg["db_path"])
    logger.init_db()
    rows = logger.fetch_recent(args.limit)
    print(json.dumps(rows, indent=2))
    return 0


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    if args.command == "scan":
        raise SystemExit(run_scan(args, cfg))
    if args.command == "history":
        raise SystemExit(run_history(args, cfg))
    raise SystemExit(2)


if __name__ == "__main__":
    main()
