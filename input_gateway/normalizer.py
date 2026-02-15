from __future__ import annotations

import re
import unicodedata

_HORIZONTAL_WS_RE = re.compile(r"[^\S\r\n]+")
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def normalize_text(raw_text: object) -> str:
    if raw_text is None:
        return ""

    if not isinstance(raw_text, str):
        raw_text = str(raw_text)

    cleaned = unicodedata.normalize("NFKC", raw_text)
    cleaned = _ZERO_WIDTH_RE.sub("", cleaned)
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _HORIZONTAL_WS_RE.sub(" ", cleaned)
    cleaned = "\n".join(part.strip() for part in cleaned.split("\n"))
    cleaned = cleaned.strip()
    return cleaned.casefold()
