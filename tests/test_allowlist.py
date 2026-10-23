"""Allowlist: defaults, custom merge, never blocks, separator-normalized."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import Allowlist, scan_text  # noqa: E402
from tests.fakes import (  # noqa: E402
    AWS, AWS_DOC, STRIPE_DOC, TEST_CARD, TEST_CARD_SPACED, CARD,
)


def test_documented_aws_example_key_allowed():
    assert Allowlist.default().is_allowed(AWS_DOC)


def test_real_key_not_allowed():
    assert not Allowlist.default().is_allowed(AWS)


def test_documented_stripe_test_key_allowed():
    assert Allowlist.default().is_allowed(STRIPE_DOC)


def test_test_cards_allowed():
    a = Allowlist.default()
    assert a.is_allowed(TEST_CARD)
    assert a.is_allowed("4242" + "4242" + "4242" + "4242")


def test_example_domains_allowed():
    a = Allowlist.default()
    assert a.is_allowed("ops@example.com")
    assert not a.is_allowed("ops@helioshome.test")


def test_allowed_hit_reported_not_blocking():
    r = scan_text(f'k = "{AWS_DOC}"', "t.txt")
    assert r.findings == []
    assert [f.kind for f in r.allowed] == ["aws_access_key"]
    assert r.exit_code == 0
    assert r.allowed[0].note


def test_spaced_test_card_normalized_to_allowlist():
    # the allowlist holds bare digits; the same documented card written
    # with spaces must match too (caught by smoke test during build)
    r = scan_text(f"card {TEST_CARD_SPACED}", "t.txt")
    assert r.findings == []
    assert [f.kind for f in r.allowed] == ["credit_card"]
    assert r.exit_code == 0


def test_real_card_still_fires():
    r = scan_text(f"card {CARD}", "t.txt")
    assert [f.kind for f in r.findings] == ["credit_card"]
    assert r.exit_code == 2


def test_custom_allowlist_file_merges():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "allow.json")
        with open(path, "w") as fh:
            json.dump({"exact": [AWS], "regex": [r"stage-[0-9]+"], "x": 1}, fh)
        a = Allowlist.from_file(path)
        assert a.is_allowed(AWS)               # custom exact merged
        assert a.is_allowed(AWS_DOC)           # defaults still merged
        assert a.is_allowed("stage-42")        # custom regex merged
        assert not a.is_allowed("stage-x")
    r = scan_text(f'k = "{AWS}"', "t.txt", allowlist=a)
    assert r.findings == [] and r.exit_code == 0
    assert [f.kind for f in r.allowed] == ["aws_access_key"]
