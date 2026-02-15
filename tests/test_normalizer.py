from __future__ import annotations

from input_gateway.normalizer import normalize_text


def test_normalize_text_trims_and_casefolds() -> None:
    assert normalize_text("  HeLLo   WORLD  ") == "hello world"


def test_normalize_text_normalizes_unicode_width_forms() -> None:
    # Full-width characters normalize to their ASCII equivalents with NFKC.
    assert normalize_text("\uff33\uff25\uff2c\uff25\uff23\uff34\u3000\uff0a\u3000\uff26\uff32\uff2f\uff2d") == "select * from"


def test_normalize_text_removes_zero_width_chars() -> None:
    assert normalize_text("a\u200bb\u200dc") == "abc"


def test_normalize_text_preserves_newlines() -> None:
    assert normalize_text(" line1 \r\n line2 \r line3 ") == "line1\nline2\nline3"


def test_normalize_text_handles_non_string_inputs() -> None:
    assert normalize_text(12345) == "12345"
    assert normalize_text(None) == ""
