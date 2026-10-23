"""Allowlist: values that must NEVER block a commit, even if they match a
detector.

Two layers:
  1. DEFAULT_ALLOWLIST — built-in, publicly documented fakes (AWS's
     documented example key, Stripe's documented test keys, well-known
     test card numbers, RFC 2606 example domains, dummy placeholders).
  2. Custom allowlist file (JSON): {"exact": [...], "regex": [...]}
     merged on top of the defaults, so a team can exempt its own
     fixtures / staging values without editing code.

A hit whose *entire* matched value is allowlisted is reported separately
as an allowed hit — visible, never blocking. Matching is case-sensitive
for exact strings; a regex must fully match the value.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


DEFAULT_ALLOWLIST = {
    "exact": [
        # AWS documented example key (docs.aws.amazon.com) — publicly
        # documented as fake; also built by concatenation for hygiene.
        "AKIA" + "IOSFODNN7EXAMPLE",
        # Stripe documented test keys (stripe.com/docs/testing) —
        # concatenated so the literal never appears in source
        # (GitHub secret push protection flags even documented fakes).
        "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "rk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        # well-known test card numbers (never chargeable)
        "4111" + "1111" + "1111" + "1111",
        "4242" + "4242" + "4242" + "4242",
        "5555" + "5555" + "5555" + "4444",
        "3782" + "822463" + "10005",
        # dummy credential placeholders
        "password123",
        "changeme",
        "xxx",
        "REDACTED",
        "localhost",
    ],
    "regex": [
        # RFC 2606 reserved documentation domains
        r"[A-Za-z0-9._%+-]+@example\.(?:com|org|net)",
        r"[A-Za-z0-9._%+-]+@test\.example",
        # obviously-masked values: ****, xxxx runs
        r"[xX*]{4,}",
    ],
}


@dataclass
class Allowlist:
    exact: set[str] = field(default_factory=set)
    patterns: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def default(cls) -> "Allowlist":
        return cls.from_dict(DEFAULT_ALLOWLIST)

    @classmethod
    def from_dict(cls, data: dict) -> "Allowlist":
        exact = set(data.get("exact", []))
        patterns = [re.compile(p) for p in data.get("regex", [])]
        return cls(exact=exact, patterns=patterns)

    @classmethod
    def from_file(cls, path: str) -> "Allowlist":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        merged_exact = set(DEFAULT_ALLOWLIST["exact"]) | set(data.get("exact", []))
        merged_regex = list(DEFAULT_ALLOWLIST["regex"]) + list(data.get("regex", []))
        return cls.from_dict({"exact": sorted(merged_exact), "regex": merged_regex})

    def is_allowed(self, value: str) -> bool:
        """True when the whole value is allowlisted."""
        if value in self.exact:
            return True
        return any(p.fullmatch(value) for p in self.patterns)
