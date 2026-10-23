"""One test cluster per detector, incl. validity traps."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import scan_text  # noqa: E402
from tests.fakes import (  # noqa: E402
    AWS, CARD, CARD_SPACED, GITHUB, JWT, SSN, STRIPE_LIVE,
)


def kinds(text):
    return [f.kind for f in scan_text(text, "t.txt").findings]


def test_aws_key():
    assert kinds(f'k = "{AWS}"') == ["aws_access_key"]
    assert kinds('k = "AKIA" + "short"') == []  # too short in one literal


def test_github_token():
    assert kinds(f't = "{GITHUB}"') == ["github_token"]


def test_stripe_live_key():
    assert kinds(f's = "{STRIPE_LIVE}"') == ["stripe_key"]


def test_jwt():
    assert kinds(f'auth = "Bearer {JWT}"') == ["jwt"]


def test_private_key_block_multiline_and_start_line():
    text = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA7aB3cD\n"
            "-----END RSA PRIVATE KEY-----\n")
    r = scan_text(text, "k.pem")
    assert [f.kind for f in r.findings] == ["private_key"]
    assert r.findings[0].line == 1
    assert r.findings[0].severity == "critical"


def test_generic_secret_assignment():
    assert kinds('api_key = "Tr7!qZ9wX2eR8tY6uI"') == ["generic_secret"]
    assert kinds("db_password: 'Xk9#mQ2wErT8yU'") == ["generic_secret"]


def test_generic_placeholders_and_references_do_not_fire():
    for line in (
        'api_key = "changeme"',
        'password = "your-api-key-here"',
        'secret = "example-secret-value"',
        'api_key = "${HELIOS_API_KEY}"',
        'api_key = os.environ.get("HELIOS_API_KEY")',
        "token = config.token",
        "token = self.session_token_value",
        'password = "aaaaaaaa"',
    ):
        assert kinds(line) == [], line


def test_specific_detector_wins_over_generic():
    # one secret = one finding: the AWS assignment must not double-fire
    # as both aws_access_key and generic_secret
    assert kinds(f'aws_secret_key = "{AWS}"') == ["aws_access_key"]
    assert kinds(f'stripe_secret = "{STRIPE_LIVE}"') == ["stripe_key"]


def test_email_and_phone_are_low_severity():
    r = scan_text("mail priya.sharma@helioshome.test, call (214) 555-0182", "t")
    assert sorted(f.kind for f in r.findings) == ["email", "phone"]
    assert all(f.severity == "low" for f in r.findings)


def test_phone_formats():
    assert kinds("call 214-555-0182") == ["phone"]
    assert kinds("call +1 214.555.0182") == ["phone"]
    assert kinds("order 1234567890 shipped") == []  # bare digits: no separator


def test_ssn_validity_rules():
    assert kinds(f"ssn {SSN}") == ["ssn"]
    for bad in ("000-09-9999", "666-09-9999", "900-09-9999",
                "219-00-9999", "219-09-0000"):
        assert kinds(f"ssn {bad}") == [], bad


def test_card_luhn():
    assert kinds(f"card {CARD}") == ["credit_card"]
    assert kinds(f"card {CARD_SPACED}") == ["credit_card"]
    bad = CARD[:-1] + ("0" if CARD[-1] != "0" else "1")
    assert kinds(f"card {bad}") == [], "Luhn-failing digits must not fire"
    assert kinds("card 1234 5678 9012 3456") == []


def test_entropy_bare_high_entropy_token():
    tok = "aB3dF6hJ9kL2" + "mN5pQ8sT1vX4zA7bC0eF"
    assert kinds(f'blob = "{tok}"') == ["entropy_secret"]


def test_entropy_traps_uuid_and_sha():
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    sha = "9f86d081884c7d659a2feaa0c55ad015" + "a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert kinds(f"id {uuid}") == []
    assert kinds(f"commit {sha}") == []
    assert kinds(f"md5 {'a' * 32}") == []


def test_entropy_needs_entropy():
    assert kinds('note = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"') == []
    assert kinds('note = "the quick brown fox jumps over"') == []


def test_no_finding_value_leak_in_dict():
    r = scan_text(f'k = "{AWS}"', "t")
    d = r.findings[0].to_dict()
    assert AWS not in str(d)
    assert len(d["value_sha256"]) == 64
