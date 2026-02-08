# Automated Input Validation & Security Gateway

A modular, CLI-first security gateway that normalizes input, evaluates configurable rules, scores risk, makes decisions, logs structured output, and stores decision history in SQLite.

## Project Structure

```text
input_gateway/
├── main.py         # CLI commands: scan, history
├── normalizer.py   # Input normalization
├── rules.py        # Rule engine + MITRE technique mapping
├── scorer.py       # Weighted risk score aggregation
├── decision.py     # allow/warn/block threshold logic
├── logger.py       # JSONL logs + SQLite persistence
├── config.py       # JSON/YAML config loading
├── ai_assessor.py  # Optional AI second-opinion API integration
└── utils.py        # report/error helpers
```

## Scoring Algorithm (current)

Every rule hit has:
- `severity`: `low` / `medium` / `high`
- `severity_weight`: configurable weight (defaults below)
- `score`: same as the weight (additive)

Default severity weights:
- `low = 0.33`
- `medium = 0.55`
- `high = 1.75`

Total risk score is the sum of all hit scores. Decision uses thresholds:
- `score >= 1.75` => `block`
- `score >= 0.55` => `warn`
- else `allow`

## MITRE Integration (practical starter)

Rules include MITRE ATT&CK technique IDs (example: `T1190`, `T1059`).
You can override rule severity/reason using `mitre_overrides` in config to align with your threat intel process.

## Optional AI Assessment

If enabled in config, an OpenAI-compatible API is called after rule scoring.
AI response can escalate decision (`allow -> warn -> block`) but never de-escalates it.

## CLI Commands

### Scan input

```bash
python -m input_gateway.main scan --text "SELECT * FROM users"
python -m input_gateway.main scan --file ./sample.txt --explain
```

### Show recent decision history

```bash
python -m input_gateway.main history --limit 20
```

## Config (JSON or YAML)

```json
{
  "decision_thresholds": {"block": 1.75, "warn": 0.55},
  "severity_weights": {"low": 0.33, "medium": 0.55, "high": 1.75},
  "max_input_chars": 100000,
  "log_path": "logs/audit.jsonl",
  "db_path": "logs/gateway.db",
  "mitre_overrides": {
    "SQLI_KEYWORD": {"severity": "high", "description": "SQLi attempt aligned to current intel"}
  },
  "ai": {
    "enabled": false,
    "endpoint": "https://your-openai-compatible-endpoint/v1/chat/completions",
    "api_key": "",
    "model": "",
    "timeout_s": 8
  }
}
```

## Tests

```bash
pytest -q
```

## Reliability Safeguards

- `scan` now wraps logger initialization inside the fail-safe path so DB/path failures still return structured JSON block errors (no traceback leaks).
- `mitre_overrides` severity values are normalized/validated; invalid values fall back to the rule default severity, preventing accidental zero-risk bypasses.
- AI parse failures are marked as `invalid_response` and do **not** escalate decisions; only validated AI JSON can escalate.
