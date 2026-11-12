"""Redact credentials from log text before it goes to the external LLM provider
(team answer Q8). The database keeps the raw line unchanged, for integrity.

Covers what lab logs plausibly carry: key=value and "key": "value" pairs with a
credential-like key (query strings, form bodies, JSON, command lines), Bearer/Basic
authorization values, and passwords in URLs. Anything else, such as a password
passed as a bare command-line argument (mysql -pSECRET), is not recognized.
"""

import re

_KEYS = (
    r"pass(?:word|wd)?|pwd|secret|token|access_token|refresh_token|api[_-]?key"
    r"|access[_-]?key|session(?:id)?|cookie|authorization|credentials?"
)
_PAIR = re.compile(
    r'(?i)(?<![A-Za-z0-9_])("?)(' + _KEYS + r')\1(\s*[=:]\s*)("(?:[^"\\]|\\.)*"|[^\s&;,"}]+)'
)
_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}")
_URL_PASSWORD = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]*:)[^/\s@]+@")

REDACTED = "[REDACTED]"


def _pair(m: re.Match) -> str:
    value = f'"{REDACTED}"' if m[4].startswith('"') else REDACTED
    return f"{m[1]}{m[2]}{m[1]}{m[3]}{value}"


def redact(text: str) -> str:
    text = _SCHEME.sub(lambda m: f"{m[1]} {REDACTED}", text)
    text = _URL_PASSWORD.sub(lambda m: f"{m[1]}{REDACTED}@", text)
    return _PAIR.sub(_pair, text)
