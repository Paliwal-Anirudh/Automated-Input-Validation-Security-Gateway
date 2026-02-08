import re


def normalize_text(raw_text: str) -> str:
    cleaned = raw_text.strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.lower()
