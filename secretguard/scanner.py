"""Scanner: run the detectors over diff-added lines (or whole files),
resolve overlaps, apply the allowlist and inline suppressions, and map
everything to findings with file/line locations.

Severity model:
    critical / high  -> blocking secrets (exit 2)
    low              -> warnings only (exit 1), e.g. email / phone
    (medium is reserved for future detectors and also blocks)

Inline suppression: a line containing ``secretguard: allow`` suppresses
every hit on that line; ``secretguard: allow=PAT-XXX`` suppresses only
that detector on that line. Suppressed hits are returned separately with
a note recording the suppression — a suppression is itself auditable,
never silent.

Allowlisted hits are likewise returned separately and never block.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .allowlist import Allowlist
from .detectors import DETECTORS, all_raw_matches
from .diffparse import FileDiff, parse_diff

BLOCKING_SEVERITIES = {"critical", "high", "medium"}
SUPPRESS_RE = re.compile(r"secretguard:\s*allow(?:=([A-Za-z0-9_-]+))?")


@dataclass
class Finding:
    detector: str
    kind: str
    severity: str
    path: str | None
    line: int | None          # line number in the NEW file version
    note: str = ""            # e.g. the inline-suppression record
    value_sha256: str = ""    # hash of the matched value, never the value

    @property
    def blocking(self) -> bool:
        return self.severity in BLOCKING_SEVERITIES

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "note": self.note,
            "value_sha256": self.value_sha256,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)     # active
    allowed: list[Finding] = field(default_factory=list)      # allowlisted
    suppressed: list[Finding] = field(default_factory=list)   # inline-allowed

    @property
    def exit_code(self) -> int:
        if any(f.blocking for f in self.findings):
            return 2
        if self.findings:
            return 1
        return 0

    @property
    def blocked(self) -> bool:
        return self.exit_code == 2

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "allowed": [f.to_dict() for f in self.allowed],
            "suppressed": [f.to_dict() for f in self.suppressed],
            "exit_code": self.exit_code,
            "blocked": self.blocked,
        }


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_allowlisted(allow: Allowlist, value: str) -> bool:
    if allow.is_allowed(value):
        return True
    # card-shaped values: the allowlist holds bare digit strings, but the
    # same documented test card written with spaces/dashes must match too
    if re.fullmatch(r"[\d .\-]+", value):
        digits = re.sub(r"\D", "", value)
        if digits != value and allow.is_allowed(digits):
            return True
    return False


def _suppression_for(line_text: str, detector: str) -> str | None:
    m = SUPPRESS_RE.search(line_text)
    if not m:
        return None
    only = m.group(1)
    if only and only != detector:
        return None
    return f"inline suppression: secretguard: allow{f'={only}' if only else ''}"


def scan_lines(numbered: list[tuple[int, str]], path: str | None,
               allowlist: Allowlist | None = None) -> ScanResult:
    """Scan (line_number, text) pairs from one file as one document, so
    multi-line detectors (PEM blocks) work; offsets map back to lines."""
    allow = allowlist or Allowlist.default()
    result = ScanResult()
    if not numbered:
        return result
    text = "\n".join(t for _, t in numbered)
    # char offset -> line number, via cumulative line starts
    starts: list[tuple[int, int]] = []
    off = 0
    for lineno, t in numbered:
        starts.append((off, lineno))
        off += len(t) + 1

    def line_at(pos: int) -> int:
        line = starts[0][1]
        for start, lineno in starts:
            if start > pos:
                break
            line = lineno
        return line

    def line_text_at(pos: int) -> str:
        for (start, _), (_n, t) in zip(starts, numbered):
            if start <= pos < start + len(t) + 1:
                return t
        return numbered[-1][1]

    raw = all_raw_matches(text)
    # overlap resolution, specificity-first: earliest start, then longest
    # span, then detector priority — one secret yields exactly one finding
    prio = {}
    for det in DETECTORS:
        prio[det["id"]] = det["priority"]
    prio["ENT-SECRET"] = 110
    prio["ENT-SECRET-CTX"] = 111
    raw.sort(key=lambda r: (r.start, -(r.end - r.start), prio.get(r.detector, 999)))
    accepted = []
    taken: list[tuple[int, int]] = []
    for r in raw:
        if any(r.start < e and s < r.end for s, e in taken):
            continue
        taken.append((r.start, r.end))
        accepted.append(r)
    accepted.sort(key=lambda r: r.start)

    for r in accepted:
        value = text[r.start:r.end]
        finding = Finding(
            detector=r.detector, kind=r.kind, severity=r.severity,
            path=path, line=line_at(r.start), value_sha256=_sha(value),
        )
        if _is_allowlisted(allow, value):
            finding.note = "allowlisted value (documented fake or custom allowlist)"
            result.allowed.append(finding)
            continue
        note = _suppression_for(line_text_at(r.start), r.detector)
        if note:
            finding.note = note
            result.suppressed.append(finding)
            continue
        result.findings.append(finding)
    return result


def _merge(into: ScanResult, other: ScanResult) -> None:
    into.findings.extend(other.findings)
    into.allowed.extend(other.allowed)
    into.suppressed.extend(other.suppressed)


def scan_diff(diff_text: str, allowlist: Allowlist | None = None) -> ScanResult:
    result = ScanResult()
    for fd in parse_diff(diff_text):
        if fd.is_binary or not fd.added:
            continue
        _merge(result, scan_lines(fd.added, fd.path, allowlist))
    # deterministic order: path, line, detector
    for lst in (result.findings, result.allowed, result.suppressed):
        lst.sort(key=lambda f: (f.path or "", f.line or 0, f.detector))
    return result


def scan_text(text: str, path: str | None,
              allowlist: Allowlist | None = None) -> ScanResult:
    numbered = [(i + 1, line) for i, line in enumerate(text.splitlines())]
    return scan_lines(numbered, path, allowlist)


def compute_exit_code(result: ScanResult) -> int:
    return result.exit_code
