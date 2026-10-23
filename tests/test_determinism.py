"""Determinism: same input -> byte-identical report, every time."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import scan_diff  # noqa: E402
from tests.fakes import AWS, CARD, SSN  # noqa: E402

DIFF = (
    "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n"
    "@@ -1,1 +1,3 @@\n ctx\n"
    f"+ssn {SSN}\n"
    f"+card {CARD}\n"
    "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
    "@@ -1,1 +1,2 @@\n ctx\n"
    f"+KEY = \"{AWS}\"\n"
    "+mail ops@helioshome.test\n"
)


def test_scan_is_deterministic():
    renders = set()
    for _ in range(5):
        r = scan_diff(DIFF)
        renders.add(json.dumps(r.to_dict(), sort_keys=True))
    assert len(renders) == 1


def test_finding_order_is_stable():
    r = scan_diff(DIFF)
    keys = [(f.path, f.line, f.detector) for f in r.findings]
    assert keys == sorted(keys), keys
