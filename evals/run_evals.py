"""Golden evals: pinned guard behavior on fixture diffs.

Fixture diffs that need secret-shaped values are built here by string
concatenation, so no literal real-looking secret sits in any source
file. Expectations are pinned in evals/golden/expected.json (verified by
hand against the fixtures when written — locations, kinds, severities,
exit codes, false-positive traps).

The report at evals/eval_report.json must be byte-identical across runs
(determinism is itself part of the contract). Exit 0 = all pass.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from secretguard import scan_diff  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "fixtures")

# fake secrets, concatenated (see module docstring)
AWS = "AKIA" + "Z7XK2P9QW4RT8N3M"
AWS_DOC = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "x7K9mQ2wErTyUiOpAsDfGhJkLzXcVbN3mQ"
STRIPE = "sk_" + "live_" + "51H7xK9mQ2wErTyUiOpAsDfG"
STRIPE_DOC = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
CARD = "4532" + "0151" + "1283" + "0366"
TEST_CARD = "4111" + "1111" + "1111" + "1111"
TEST_CARD_SPACED = "4111" + " 1111" + " 1111" + " 1111"
JWT = ("eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "."
       + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "."
       + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
SSN = "219" + "-09-" + "9999"
UUID = "123e4567-e89b-12d3-a456-426614174000"
SHA256 = "9f86d081884c7d659a2feaa0c55ad015" + "a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _load_fixture(name: str) -> str:
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


SECRETS_DIFF = f"""diff --git a/helios/config.py b/helios/config.py
--- a/helios/config.py
+++ b/helios/config.py
@@ -5,2 +5,9 @@
 import os
 MODE = "prod"
+AWS_KEY = "{AWS}"
+API_TOKEN = "{GITHUB}"
+STRIPE_KEY = "{STRIPE}"
+SESSION_JWT = "{JWT}"
+BACKUP_CARD = "{CARD}"
+OWNER_SSN = "{SSN}"
+BACKUP_PASSWORD = "Tr7!qZ9wX2eR8tY6uI"
diff --git a/helios/contact.py b/helios/contact.py
--- a/helios/contact.py
+++ b/helios/contact.py
@@ -1,1 +1,3 @@
 CONTACTS = {{}}
+SUPPORT_EMAIL = "ops@helioshome.test"
+SUPPORT_PHONE = "(214) 555-0182"
"""

FP_TRAPS_DIFF = f"""diff --git a/helios/docs.py b/helios/docs.py
--- a/helios/docs.py
+++ b/helios/docs.py
@@ -0,0 +1,10 @@
+# AWS docs example key: {AWS_DOC}
+# Stripe documented test key: {STRIPE_DOC}
+# test card {TEST_CARD}
+# test card spaced {TEST_CARD_SPACED}
+# docs mail help@example.com
+# build id {UUID}
+# commit {SHA256}
+# password = "changeme"
+# api_key = os.environ.get("HELIOS_API_KEY")
+# api_token = "${{HELIOS_TOKEN}}"
"""

SUPPRESSION_DIFF = f"""diff --git a/helios/fixtures.py b/helios/fixtures.py
--- a/helios/fixtures.py
+++ b/helios/fixtures.py
@@ -0,0 +1,2 @@
+DEMO_KEY = "{AWS}"  # secretguard: allow
+LIVE_KEY = "{STRIPE}"
"""

RENAME_NEWFILE_DIFF = f"""diff --git a/helios/old_cfg.py b/helios/new_cfg.py
similarity index 90%
rename from helios/old_cfg.py
rename to helios/new_cfg.py
--- a/helios/old_cfg.py
+++ b/helios/new_cfg.py
@@ -2,1 +2,2 @@
 ctx
+KEY = "{AWS}"
diff --git a/helios/notes.txt b/helios/notes.txt
new file mode 100644
--- /dev/null
+++ b/helios/notes.txt
@@ -0,0 +1,2 @@
+contact ops@helioshome.test
+second line is clean
"""

PEM_DIFF = """diff --git a/helios/key.pem b/helios/key.pem
new file mode 100644
--- /dev/null
+++ b/helios/key.pem
@@ -0,0 +1,3 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA7aB3cD4eF5
+-----END RSA PRIVATE KEY-----
"""

DIFFS = {
    "staged_secrets": SECRETS_DIFF,
    "clean_fixture": None,        # loaded from fixtures/clean.diff
    "warnings_fixture": None,     # loaded from fixtures/warnings.diff
    "fp_traps": FP_TRAPS_DIFF,
    "suppression": SUPPRESSION_DIFF,
    "rename_and_newfile": RENAME_NEWFILE_DIFF,
    "pem_block": PEM_DIFF,
}
FIXTURE_FILES = {"clean_fixture": "clean.diff",
                 "warnings_fixture": "warnings.diff"}


def _tuples(findings):
    return [[f.detector, f.kind, f.severity, f.path, f.line]
            for f in findings]


def run_case(name: str, diff_text: str, want: dict) -> dict:
    r = scan_diff(diff_text)
    got = {
        "exit": r.exit_code,
        "findings": _tuples(r.findings),
        "allowed_kinds": sorted(f.kind for f in r.allowed),
        "suppressed": [[f.kind, f.line] for f in r.suppressed],
    }
    ok = all(got[k] == want[k] for k in want)
    return {"pass": ok, "got": got, "want": want}


def main() -> int:
    with open(os.path.join(HERE, "golden", "expected.json"),
              encoding="utf-8") as fh:
        expected = json.load(fh)
    results, all_pass = {}, True
    for name, diff_text in DIFFS.items():
        if diff_text is None:
            diff_text = _load_fixture(FIXTURE_FILES[name])
        try:
            r = run_case(name, diff_text, expected[name])
        except Exception as exc:  # noqa: BLE001
            r = {"pass": False, "error": repr(exc)}
        results[name] = r
        all_pass = all_pass and bool(r["pass"])
        print(("PASS " if r["pass"] else "FAIL ") + name)
        if not r["pass"]:
            print("  got :", json.dumps(r.get("got"), sort_keys=True))
            print("  want:", json.dumps(expected[name], sort_keys=True))
    report = {"cases": {k: {"pass": v["pass"]} for k, v in results.items()},
              "all_pass": all_pass, "n_cases": len(DIFFS)}
    path = os.path.join(HERE, "eval_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    md5 = hashlib.md5(open(path, "rb").read()).hexdigest()
    print(f"\nreport: {path}  md5={md5}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
