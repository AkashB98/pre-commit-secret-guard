# pre-commit-secret-guard

**Shift-left secret prevention: the cheapest place to stop a leaked key is
before the commit exists.**

Every leaked-credential incident starts the same way — a real key lands in a
staged diff, somebody hits `git commit`, and from that moment the secret is
in history forever: rotation, history rewriting, and an incident report.
This tool sits in the one moment when the leak is still free to prevent. It
scans **only the added lines of the staged diff**, reports exact file/line
locations in the new file, and blocks the commit (or the CI job) when a real
secret is present.

It is the inbound half of a pair with
[`tool-output-pii-redactor`](https://github.com/AkashB98/tool-output-pii-redactor):
the redactor **scrubs the outputs** an agent emits; this guard **blocks the
commits** a human makes. Same detector core, same allowlist philosophy, two
different trust boundaries.

Stdlib-only Python. No network, no API keys, nothing to install.

## Quickstart

```bash
# check a staged diff in this repo (runs git diff --cached)
python -m secretguard check --repo .

# check a diff from a file or stdin
python -m secretguard check --diff change.diff
git diff --cached | python -m secretguard check

# install the actual pre-commit hook
python -m secretguard hook --install --repo .

# scan plain files/directories (no diff involved)
python -m secretguard scan src/ config.py

# asserted end-to-end demo
python demo.py            # or: python -m secretguard demo

# JSON API on localhost
python -m secretguard serve --port 8093
curl -s -X POST localhost:8093/check -H 'Content-Type: application/json' \
     -d '{"diff": "<unified diff text>"}'
```

Exit codes make it a one-line CI gate:

| Code | Meaning |
|------|---------|
| 0 | clean — no findings |
| 1 | warnings only (low severity: email, phone) — never blocks |
| 2 | blocking secrets found — abort the commit / fail the job |
| 3 | usage / tool error (bad args, unreadable input, git failure) |

The installed hook translates these for git: 0 and 1 let the commit proceed
(warnings print but don't block), 2 blocks, and 3 blocks too — a broken
checker fails **closed**, never open.

## What it catches

| Detector | Kind | Severity | Notes |
|----------|------|----------|-------|
| PEM block | `private_key` | critical | multi-line; reported at the block's first line |
| AWS access key | `aws_access_key` | critical | `AKIA`/`ASIA` + 16 |
| GitHub token | `github_token` | critical | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, fine-grained `github_pat_` |
| Stripe key | `stripe_key` | critical | `sk_`/`rk_` live or test |
| JWT | `jwt` | high | `eyJ…` three-segment shape |
| Generic assignment | `generic_secret` | high | `api_key`/`password`/`secret`/`token` `=` a literal that isn't a placeholder, template, or env/config reference |
| Credit card | `credit_card` | high | **Luhn-verified**, 13–19 digits, separators allowed |
| SSN | `ssn` | high | SSA validity rules (area ≠ 000/666/9xx, group ≠ 00, serial ≠ 0000) |
| High-entropy token | `entropy_secret` | high | Shannon entropy ≥ 4.5 bare, ≥ 4.0 with secret context; UUIDs and MD5/SHA digests exempt |
| Email | `email` | low (warning) | |
| US phone | `phone` | low (warning) | needs a separator/parens/country code — bare 10-digit order numbers don't fire |

Overlap resolution is specificity-first (earliest start, longest span, then
detector priority), so **one secret produces exactly one finding**: an AWS
key assigned to `aws_secret_key = "…"` reports as `aws_access_key`, not
also as `generic_secret`.

Findings never contain the secret itself — reports carry a SHA-256 of the
matched value, enough to dedupe and audit, useless to an attacker.

## The diff parser

Only added (`+`) lines are scanned. Removed lines are never scanned — a
secret being *deleted* must not block the commit that deletes it. Context
lines are never scanned either, but they **do** advance the new-file line
counter, so reported line numbers are the line numbers in the file after
the commit lands. New files, deleted files, renames (findings are reported
under the new path), binary diffs, multiple files and hunks, and even a
literal `+++` line inside a hunk are all handled.

## Allowlist

Two layers, checked before a hit can block:

1. **Built-in documented fakes** — AWS's documented example key, Stripe's
   documented test keys, well-known test card numbers (matched digit-wise,
   so `4111 1111 1111 1111` is as allowed as `4111111111111111`), RFC 2606
   `example.com` addresses, dummy placeholders.
2. **Custom JSON file** (`--allowlist team.json`), merged on top:
   `{"exact": ["..."], "regex": ["..."]}` — exact values and/or regexes
   that must fully match the value.

Allowlisted hits are **reported separately** as `allowed`, never silently
dropped, and never block.

## Inline suppression

A line can exempt itself, auditable in the report:

```python
DEMO_KEY = "AKIA…"  # secretguard: allow
DEMO_KEY = "AKIA…"  # secretguard: allow=PAT-AWS-KEY   # one detector only
```

Suppressed hits land in the report's `suppressed` list with the note
`inline suppression: secretguard: allow…` — the suppression is itself a
recorded finding-level fact, so a reviewer can grep for every place a
human overrode the guard.

## CLI reference

| Command | What it does |
|---------|--------------|
| `check [--diff FILE\|- ] [--repo DIR] [--allowlist F] [--format text\|json]` | check a diff from a file, stdin, or `git diff --cached` in `--repo` |
| `scan PATH... [--allowlist F] [--format text\|json]` | scan plain files/dirs directly (skips `.git`, `__pycache__`, binaries) |
| `hook [--install --repo DIR] [--force]` | print the hook script, or install it as `.git/hooks/pre-commit` (refuses to overwrite an existing hook unless `--force`) |
| `demo` | run the asserted end-to-end demo |
| `serve [--port 8093] [--allowlist F]` | stdlib JSON API on 127.0.0.1: `POST /check` (JSON `{"diff": …}` or a raw diff body) → findings JSON + exit code; `GET /health` |

## Architecture

```
secretguard/
  detectors.py   pattern table + validators (Luhn, SSN rules) + generic
                 assignment + entropy detector (adapted from the
                 tool-output-pii-redactor detector core)
  allowlist.py   documented fakes + custom JSON merge
  diffparse.py   unified-diff parser: added lines + new-file line numbers
  scanner.py     overlap resolution, allowlist/suppression routing,
                 severity model, exit codes
  hook.py        hook script + safe installation
  cli.py         check / scan / hook / demo / serve
tests/           67 hermetic tests (stdlib runner, socket-stubbed
                 no-network guard)
evals/           7 golden cases pinning findings/kinds/locations/exit
                 codes on fixture diffs, incl. false-positive traps
fixtures/        clean + warnings-only sample diffs (Helios Home, fictional)
demo.py          asserted end-to-end scenario incl. a live /check call
```

## Tests & evals

```bash
python tests/run_tests.py     # 67/67
python evals/run_evals.py     # 7/7, eval_report.json byte-identical across runs
python demo.py                # all 8 steps asserted
```

Golden evals pin exact finding tuples (detector, kind, severity, path,
line) on a 9-secret staged diff, a warnings-only fixture, a rename +
new-file diff, and a multi-line PEM block — plus a false-positive trap
diff (documented fakes, a UUID, a SHA-256, `changeme`, an env-var
reference, a `${...}` template) that must produce **zero** findings.

## Honest limitations

- Regex + entropy heuristics, not a semantic analyzer: an obfuscated or
  split secret (string concatenation in the committed code itself) can
  evade it, and a genuinely random-looking non-secret can trip the
  entropy detector. It raises the cost of an accidental leak; it is not
  proof a repo is clean.
- `scan` reads whole files into memory; fine for source trees, not a
  whole-filesystem auditor.
- US-centric PII (SSN, US phone formats, Luhn cards). Non-US national IDs
  and phone formats are out of scope.
- The entropy threshold is a blunt instrument: 4.0/4.5 bits-per-char was
  chosen so UUIDs and hex digests stay exempt while random base64 tokens
  (~5.9 bits/char) fire.
- Diff paths containing spaces rely on git's quoting; exotic path forms
  degrade gracefully (findings may land under a best-effort path).

## Dev loop — bugs the tests actually caught

1. **Spaced test card escaped the allowlist.** The allowlist holds bare
   digit strings (`4111111111111111`), but the card detector matches the
   spaced form (`4111 1111 1111 1111`) as one span, so the documented
   test card blocked as a "real" card. Fixed by digit-normalizing
   card-shaped values before the allowlist check; pinned by
   `test_spaced_test_card_normalized_to_allowlist`.
2. **A suppression test asserted the mirror image of its intent** (the
   marked line expected as the finding, the unmarked line as suppressed).
   The scanner was right; the test now pins line-scoped suppression
   correctly.
3. **The warnings golden miscounted its own fixture.** The golden
   expected findings at lines 5/6, but the fixture has a single context
   line — the text after the `@@` hunk header is a context *label*, not
   a line. The eval failed, the parser was verified right by hand, and
   the golden was corrected to 4/5. (This is why goldens are pinned by
   hand-checking, not captured blindly.)

## License

MIT — see `LICENSE`.
