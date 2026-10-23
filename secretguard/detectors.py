"""Pattern + entropy detectors for the pre-commit secret guard.

Adapted from the detector core of the sibling build
``tool-output-pii-redactor`` (same pattern table, validators and
specificity-first overlap idea), extended with:

  * a generic secret-assignment detector (``api_key = <value>``) whose span
    is the *value only*, so a specific detector (AWS, Stripe, ...) matching
    the same value wins the overlap and one secret yields one finding;
  * a severity per detector (see ``scanner.SEVERITY`` consumers);
  * placeholder rejection for assigned values (``changeme``, ``${...}``,
    ``os.environ.get(...)`` references, dotted attribute paths, ...).

Each detector is a dict:
    id        stable rule id, e.g. "PAT-AWS-KEY"
    kind      finding kind, e.g. "aws_access_key"
    severity  "critical" | "high" | "medium" | "low"
    pattern   compiled regex
    span_group  regex group whose span is the secret (default 0 = whole)
    validate  fn(match) -> bool, semantic checks (Luhn, SSN rules, ...)
    priority  lower wins when two detectors match the same span
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RawMatch:
    detector: str
    kind: str
    severity: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_card(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:  # 0000... / 1111... runs are not cards
        return False
    return _luhn_ok(digits)


def _valid_ssn(m: re.Match) -> bool:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _valid_phone(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) == 10:
        return True
    return len(digits) == 11 and digits.startswith("1")


def _always(_m: re.Match) -> bool:
    return True


# ---------------------------------------------------------------------------
# generic secret assignment:  name = "value"  /  name: value
# ---------------------------------------------------------------------------

_PLACEHOLDER_EXACT = {
    "changeme", "change-me", "change_me", "password", "password123",
    "secret", "token", "example", "placeholder", "dummy", "fake",
    "none", "null", "true", "false", "xxx", "xxxxxx", "redacted",
    "your-api-key", "your_api_key", "your-token", "insert-here",
    "todo", "tbd",
}
_PLACEHOLDER_SUBSTR = (
    "example", "placeholder", "changeme", "your-", "your_",
    "insert", "replace-me", "replace_me", "demo-key", "sample",
)
_REFERENCE_RE = re.compile(
    r"^(?:os\.environ|process\.env|env\.|getenv|config\.|settings\.|self\.)"
)


def _valid_assigned_value(value: str) -> bool:
    """True when an assigned literal looks like a real secret, not a
    placeholder, template, or a reference to config/env."""
    low = value.lower()
    if len(value) < 8:
        return False
    if low in _PLACEHOLDER_EXACT:
        return False
    if any(s in low for s in _PLACEHOLDER_SUBSTR):
        return False
    if value.startswith(("${", "<", "{{", "%(")):
        return False  # template / placeholder syntax, not a literal
    if _REFERENCE_RE.match(value):
        return False  # a reference to config/env, not a literal secret
    if re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+(?:\(.*)?", value):
        return False  # dotted attribute path / call, e.g. self.cfg.token
    if "(" in value or ")" in value:
        return False
    if len(set(value)) <= 2:
        return False  # "aaaaaaaa" / "abababab" filler
    return shannon_entropy(value) >= 2.5


_GENERIC_ASSIGN_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret(?:[_-]?key)?|"
    r"passwd|password|auth[_-]?token|access[_-]?token|private[_-]?key|"
    r"client[_-]?secret|token)"
    r"\s*[:=]\s*"
    r"(?:[\"']([^\"'\s]{8,})[\"']|([^\s\"',;}\]]{8,}))"
)


def _assigned_value_match(m: re.Match):
    """Normalize the two alternation branches into (value, span)."""
    if m.group(1) is not None:
        return m.group(1), m.start(1), m.end(1)
    return m.group(2), m.start(2), m.end(2)


# ---------------------------------------------------------------------------
# detector table
# ---------------------------------------------------------------------------

DETECTORS = [
    {
        "id": "PAT-PRIVATE-KEY",
        "kind": "private_key",
        "severity": "critical",
        "pattern": re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "validate": _always,
        "priority": 10,
    },
    {
        "id": "PAT-JWT",
        "kind": "jwt",
        "severity": "high",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
            r"(?![A-Za-z0-9_-])"
        ),
        "validate": _always,
        "priority": 20,
    },
    {
        "id": "PAT-AWS-KEY",
        "kind": "aws_access_key",
        "severity": "critical",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "validate": _always,
        "priority": 30,
    },
    {
        "id": "PAT-GITHUB-TOKEN",
        "kind": "github_token",
        "severity": "critical",
        "pattern": re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
        ),
        "validate": _always,
        "priority": 40,
    },
    {
        "id": "PAT-STRIPE-KEY",
        "kind": "stripe_key",
        "severity": "critical",
        "pattern": re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "validate": _always,
        "priority": 50,
    },
    {
        "id": "PAT-GENERIC-SECRET",
        "kind": "generic_secret",
        "severity": "high",
        # span/value resolved by _assigned_value_match, see pattern_matches
        "pattern": _GENERIC_ASSIGN_RE,
        "validate": _always,  # value validation happens pre-match below
        "priority": 60,
        "assigned_value": True,
    },
    {
        "id": "PAT-CARD",
        "kind": "credit_card",
        "severity": "high",
        "pattern": re.compile(r"(?<!\d)(?:\d[ \-. ]?){12,18}\d(?!\d)"),
        "validate": _valid_card,
        "priority": 70,
    },
    {
        "id": "PAT-SSN",
        "kind": "ssn",
        "severity": "high",
        "pattern": re.compile(r"(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)"),
        "validate": _valid_ssn,
        "priority": 80,
    },
    {
        "id": "PAT-PHONE",
        "kind": "phone",
        "severity": "low",
        "pattern": re.compile(
            r"(?<!\d)(?:\+\d{1,3}[-. ]?)?(?:\(\d{3}\)[-. ]?|\d{3}[-. ])"
            r"\d{3}[-. ]?\d{4}(?!\d)"
        ),
        "validate": _valid_phone,
        "priority": 90,
    },
    {
        "id": "PAT-EMAIL",
        "kind": "email",
        "severity": "low",
        "pattern": re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
        ),
        "validate": _always,
        "priority": 100,
    },
]


# ---------------------------------------------------------------------------
# entropy detector (unlabeled high-entropy tokens in secret context, or
# very high entropy on shape alone)
# ---------------------------------------------------------------------------

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,512}")
_CONTEXT_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|passwd|password|bearer|auth|credential)"
    r"|[:=]\s*[\"']?$"
)
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

ENTROPY_THRESHOLD = 4.0          # with secret context nearby
ENTROPY_THRESHOLD_BARE = 4.5     # shape alone, no context
CONTEXT_WINDOW = 80
LONG_TOKEN_MIN_LEN = 32


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(text: str) -> int:
    classes = 0
    if re.search(r"[a-z]", text) or re.search(r"[A-Z]", text):
        classes += 1
    if re.search(r"\d", text):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", text):
        classes += 1
    return classes


def _has_secret_context(text: str, start: int) -> bool:
    window = text[max(0, start - CONTEXT_WINDOW):start]
    return bool(_CONTEXT_RE.search(window))


def entropy_matches(text: str) -> list[RawMatch]:
    out: list[RawMatch] = []
    for m in _CANDIDATE_RE.finditer(text):
        cand = m.group(0)
        if _UUID_RE.match(cand):
            continue  # identifiers, not secrets
        if _HEX_RE.match(cand) and len(cand) in (32, 40, 64):
            continue  # MD5 / SHA-1 / SHA-256 digests are hashes, not keys
        if _char_classes(cand) < 2:
            continue
        ent = shannon_entropy(cand)
        ctx = _has_secret_context(text, m.start())
        if ent >= ENTROPY_THRESHOLD_BARE or (ctx and ent >= ENTROPY_THRESHOLD):
            out.append(RawMatch("ENT-SECRET", "entropy_secret", "high",
                                m.start(), m.end()))
        elif ctx and len(cand) >= LONG_TOKEN_MIN_LEN and ent >= 3.5:
            out.append(RawMatch("ENT-SECRET-CTX", "entropy_secret", "high",
                                m.start(), m.end()))
    return out


def pattern_matches(text: str) -> list[RawMatch]:
    out: list[RawMatch] = []
    for det in DETECTORS:
        if det.get("assigned_value"):
            for m in det["pattern"].finditer(text):
                value, start, end = _assigned_value_match(m)
                if _valid_assigned_value(value):
                    out.append(RawMatch(det["id"], det["kind"],
                                        det["severity"], start, end))
            continue
        group = det.get("span_group", 0)
        for m in det["pattern"].finditer(text):
            if det["validate"](m):
                out.append(
                    RawMatch(det["id"], det["kind"], det["severity"],
                             m.start(group), m.end(group))
                )
    return out


def all_raw_matches(text: str) -> list[RawMatch]:
    return pattern_matches(text) + entropy_matches(text)
