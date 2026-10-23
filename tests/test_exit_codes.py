"""Severity model -> CI exit codes."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import compute_exit_code, scan_diff, scan_text  # noqa: E402
from tests.fakes import AWS, SSN  # noqa: E402


def test_clean_is_zero():
    assert scan_text("hello world\n", "t").exit_code == 0
    assert compute_exit_code(scan_diff("")) == 0


def test_warnings_only_is_one():
    r = scan_text("mail ops@helioshome.test\ncall (214) 555-0182\n", "t")
    assert r.exit_code == 1
    assert not r.blocked


def test_secret_is_two():
    assert scan_text(f'k = "{AWS}"', "t").exit_code == 2
    assert scan_text(f"ssn {SSN}", "t").exit_code == 2


def test_mixed_warnings_and_secret_is_two():
    r = scan_text(f'mail ops@helioshome.test\nk = "{AWS}"\n', "t")
    assert r.exit_code == 2


def test_suppressed_secret_is_zero():
    r = scan_text(f'k = "{AWS}"  # secretguard: allow', "t")
    assert r.exit_code == 0


def test_severity_assignment():
    r = scan_text(f'k = "{AWS}"\nssn {SSN}\nmail ops@helioshome.test\n', "t")
    sev = {f.kind: f.severity for f in r.findings}
    assert sev == {"aws_access_key": "critical", "ssn": "high",
                   "email": "low"}, sev


def test_blocking_flag():
    r = scan_text("mail ops@helioshome.test\n", "t")
    assert not r.blocked
    r = scan_text(f"k = '{AWS}'", "t")
    assert r.blocked
