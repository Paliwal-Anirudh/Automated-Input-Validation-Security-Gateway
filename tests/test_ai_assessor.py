from __future__ import annotations

import json
from urllib.error import URLError

from input_gateway.ai_assessor import ai_assess


class DummyResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def valid_ai_cfg() -> dict:
    return {
        "enabled": True,
        "endpoint": "https://example.test/v1/chat/completions",
        "api_key": "test-key",
        "model": "test-model",
        "timeout_s": 8,
    }


def test_ai_assess_disabled() -> None:
    result = ai_assess("hello", {}, {"enabled": False})
    assert result == {"enabled": False}


def test_ai_assess_skipped_when_required_config_missing() -> None:
    result = ai_assess("hello", {}, {"enabled": True})
    assert result["status"] == "skipped"


def test_ai_assess_parses_plain_json_content(monkeypatch) -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"recommended_decision":"warn","confidence":0.7,"explanation":"suspicious token"}'
                }
            }
        ]
    }
    monkeypatch.setattr("input_gateway.ai_assessor.request.urlopen", lambda *_args, **_kwargs: DummyResponse(payload))

    result = ai_assess("hello", {}, valid_ai_cfg())
    assert result["status"] == "ok"
    assert result["recommended_decision"] == "warn"
    assert result["confidence"] == 0.7


def test_ai_assess_parses_fenced_json_and_normalizes_confidence(monkeypatch) -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '```json\n{"recommended_decision":"block","confidence":"3","explanation":"critical"}\n```'
                }
            }
        ]
    }
    monkeypatch.setattr("input_gateway.ai_assessor.request.urlopen", lambda *_args, **_kwargs: DummyResponse(payload))

    result = ai_assess("hello", {}, valid_ai_cfg())
    assert result["status"] == "ok"
    assert result["recommended_decision"] == "block"
    assert result["confidence"] == 1.0


def test_ai_assess_parses_content_blocks(monkeypatch) -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": [
                        {
                            "type": "output_text",
                            "text": '{"recommended_decision":"allow","confidence":0.2,"explanation":"looks normal"}',
                        }
                    ]
                }
            }
        ]
    }
    monkeypatch.setattr("input_gateway.ai_assessor.request.urlopen", lambda *_args, **_kwargs: DummyResponse(payload))

    result = ai_assess("hello", {}, valid_ai_cfg())
    assert result["status"] == "ok"
    assert result["recommended_decision"] == "allow"


def test_ai_assess_invalid_decision_returns_invalid_response(monkeypatch) -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"recommended_decision":"permit","confidence":0.7,"explanation":"bad enum"}'
                }
            }
        ]
    }
    monkeypatch.setattr("input_gateway.ai_assessor.request.urlopen", lambda *_args, **_kwargs: DummyResponse(payload))

    result = ai_assess("hello", {}, valid_ai_cfg())
    assert result["status"] == "invalid_response"


def test_ai_assess_network_error_returns_error_status(monkeypatch) -> None:
    def raise_url_error(*_args, **_kwargs):
        raise URLError("connection refused")

    monkeypatch.setattr("input_gateway.ai_assessor.request.urlopen", raise_url_error)

    result = ai_assess("hello", {}, valid_ai_cfg())
    assert result["status"] == "error"
    assert "connection refused" in result["reason"]
