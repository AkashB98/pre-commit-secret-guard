"""Asserted end-to-end demo for pre-commit-secret-guard.

Scenario (fictional Helios Home): a developer is about to commit a config
file with live-looking credentials staged. The guard blocks it (exit 2).
A clean diff passes, a documented fake passes via the allowlist, an
inline suppression is honored *and recorded*, the scanner works on plain
files too, the hook installs into a throwaway repo, and the JSON API
answers a live localhost /check round-trip.

Every fake secret below is assembled by string concatenation so no
literal real-looking secret string sits in this source file (the lesson
GitHub's secret push protection taught the sibling build).
Run with `python demo.py` or `python -m secretguard demo`.
"""

import io
import json
import os
import sys
import tempfile
import threading
import urllib.request
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secretguard import scan_diff, scan_text  # noqa: E402
from secretguard.cli import main as cli_main, make_server  # noqa: E402
from secretguard.hook import HOOK_SCRIPT, install_hook  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

AWS = "AKIA" + "Z7XK2P9QW4RT8N3M"
STRIPE = "sk_" + "live_" + "51H7xK9mQ2wErTyUiOpAsDfG"
CARD = "4532" + "0151" + "1283" + "0366"
AWS_DOC = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key

SECRETS_DIFF = f"""diff --git a/helios/config.py b/helios/config.py
--- a/helios/config.py
+++ b/helios/config.py
@@ -1,1 +1,4 @@
 import os
+AWS_ACCESS_KEY = "{AWS}"
+STRIPE_KEY = "{STRIPE}"
+BACKUP_CARD = "{CARD}"
"""

SUPPRESSED_DIFF = f"""diff --git a/helios/fixtures.py b/helios/fixtures.py
--- a/helios/fixtures.py
+++ b/helios/fixtures.py
@@ -0,0 +1,1 @@
+EXAMPLE_KEY = "{AWS}"  # secretguard: allow
"""


def _quiet_cli(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(argv)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


def run() -> None:
    # 1. staged secrets block the commit ---------------------------------
    r = scan_diff(SECRETS_DIFF)
    kinds = sorted(f.kind for f in r.findings)
    assert kinds == ["aws_access_key", "credit_card", "stripe_key"], kinds
    assert r.exit_code == 2 and r.blocked
    lines = {f.kind: f.line for f in r.findings}
    assert lines == {"aws_access_key": 2, "stripe_key": 3,
                     "credit_card": 4}, lines
    rc, _out, _err = _quiet_cli(["check"], stdin_text=SECRETS_DIFF)
    assert rc == 2, rc
    print("1. staged secrets: aws+stripe+card blocked, CLI check exit 2, "
          "line numbers 2/3/4 in the new file")

    # 2. clean diff passes -------------------------------------------------
    clean = open(os.path.join(HERE, "fixtures", "clean.diff")).read()
    r = scan_diff(clean)
    assert r.findings == [] and r.exit_code == 0, r.findings
    rc, _o, _e = _quiet_cli(["check"], stdin_text=clean)
    assert rc == 0, rc
    print("2. clean diff: 0 findings, exit 0 (env-var reference is not a "
          "literal secret)")

    # 3. warnings only -> exit 1, not blocked ------------------------------
    warn = open(os.path.join(HERE, "fixtures", "warnings.diff")).read()
    r = scan_diff(warn)
    assert sorted(f.kind for f in r.findings) == ["email", "phone"]
    assert r.exit_code == 1 and not r.blocked
    print("3. warnings diff: email+phone only, exit 1 (warns, never blocks)")

    # 4. allowlisted documented fake passes --------------------------------
    fake_diff = SECRETS_DIFF.replace(AWS, AWS_DOC)
    fake_diff = fake_diff.replace(STRIPE, "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc")
    r = scan_diff(fake_diff)
    allowed_kinds = sorted(f.kind for f in r.allowed)
    assert allowed_kinds == ["aws_access_key", "stripe_key"], allowed_kinds
    assert [f.kind for f in r.findings] == ["credit_card"]  # the real one stays
    print("4. allowlist: documented AWS/Stripe fakes reported as allowed, "
          "the non-fake card still blocks")

    # 5. inline suppression works and is recorded --------------------------
    r = scan_diff(SUPPRESSED_DIFF)
    assert r.findings == [] and r.exit_code == 0
    assert len(r.suppressed) == 1
    assert "secretguard: allow" in r.suppressed[0].note
    assert r.suppressed[0].kind == "aws_access_key"
    print("5. suppression: line-level `secretguard: allow` honored, "
          "suppression recorded with its note")

    # 6. scan mode on a plain file -----------------------------------------
    r = scan_text(f'stripe = "{STRIPE}"\n', "plain.py")
    assert [f.kind for f in r.findings] == ["stripe_key"]
    assert r.findings[0].line == 1
    print("6. scan: plain-file mode finds the same secrets outside a diff")

    # 7. hook generation + install (refuses silent overwrite) --------------
    assert "secretguard check" in HOOK_SCRIPT and HOOK_SCRIPT.startswith("#!/bin/sh")
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".git", "hooks"))
        path = install_hook(tmp)
        assert os.access(path, os.X_OK)
        try:
            install_hook(tmp)
            raise AssertionError("second install should refuse to overwrite")
        except Exception as exc:
            assert "refusing to overwrite" in str(exc)
        install_hook(tmp, force=True)
    print("7. hook: script generated, installed executable, overwrite "
          "refused without --force")

    # 8. live localhost /check round-trip ----------------------------------
    srv = make_server(0)
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/check",
            data=json.dumps({"diff": SECRETS_DIFF}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())
        assert payload["exit_code"] == 2 and payload["blocked"] is True
        assert sorted(f["kind"] for f in payload["findings"]) == kinds
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health",
                                    timeout=10) as resp:
            assert json.loads(resp.read()) == {"ok": True}
    finally:
        srv.shutdown()
    print("8. serve: live POST /check round-trip returns exit_code 2 + "
          "the same findings; /health ok")

    print("\ndemo ok: the redactor scrubs what agents emit; "
          "this guard blocks what humans commit.")


if __name__ == "__main__":
    run()
