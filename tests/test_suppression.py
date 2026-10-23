"""Inline suppression: `secretguard: allow` records, never silences."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import scan_text  # noqa: E402
from tests.fakes import AWS, STRIPE_LIVE  # noqa: E402


def test_inline_allow_suppresses_and_records():
    r = scan_text(f'k = "{AWS}"  # secretguard: allow', "t.txt")
    assert r.findings == []
    assert len(r.suppressed) == 1
    assert "secretguard: allow" in r.suppressed[0].note
    assert r.suppressed[0].kind == "aws_access_key"
    assert r.exit_code == 0


def test_suppression_is_line_scoped():
    r = scan_text(f'k = "{AWS}"\nother = "{STRIPE_LIVE}"  # secretguard: allow', "t.txt")
    assert [f.kind for f in r.findings] == ["aws_access_key"]
    assert [f.kind for f in r.suppressed] == ["stripe_key"]
    assert r.exit_code == 2  # the unsuppressed line still blocks


def test_detector_scoped_suppression():
    r = scan_text(
        f'k = "{AWS}"  # secretguard: allow=PAT-AWS-KEY', "t.txt")
    assert r.findings == [] and len(r.suppressed) == 1


def test_detector_scoped_suppression_wrong_id_does_not_apply():
    r = scan_text(
        f'k = "{AWS}"  # secretguard: allow=PAT-STRIPE-KEY', "t.txt")
    assert [f.kind for f in r.findings] == ["aws_access_key"]


def test_suppression_in_diff_applies_to_added_line():
    from secretguard import scan_diff
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,1 +1,1 @@\n-ctx\n"
        f'+k = "{AWS}"  # secretguard: allow\n'
    )
    r = scan_diff(diff)
    assert r.findings == [] and len(r.suppressed) == 1
    assert r.suppressed[0].line == 1
