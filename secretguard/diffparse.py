"""Unified git-diff parser.

Extracts ONLY the added lines of a diff, each tagged with its file path
and its line number in the NEW version of the file. Removed and context
lines are never scanned (a secret being *deleted* must not block the
commit that deletes it), but context lines still advance the new-file
line counter, which is what makes reported line numbers land on the
right line in the post-commit file.

Handled, gracefully:
  * new files (``--- /dev/null``)
  * deleted files (``+++ /dev/null`` — no added lines by definition)
  * renames (``rename from/to``, with or without content hunks; findings
    are reported under the NEW path)
  * binary diffs (``Binary files ... differ`` / ``GIT binary patch`` —
    recorded, no lines scanned)
  * multiple files and multiple hunks per file
  * a literal ``+++`` line *inside* a hunk (an added line whose content
    starts with ``++``) — only the header position counts as a header
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class FileDiff:
    path: str | None            # new path (None for a deleted file)
    old_path: str | None = None
    is_new: bool = False
    is_binary: bool = False
    is_rename: bool = False
    added: list[tuple[int, str]] = field(default_factory=list)  # (new_line, text)


def _strip_prefix(p: str) -> str:
    p = p.strip()
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    new_line = 0
    in_hunk = False

    def _flush():
        nonlocal cur
        if cur is not None:
            files.append(cur)
            cur = None

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            _flush()
            in_hunk = False
            parts = raw[len("diff --git "):].split(" ")
            # paths may contain spaces; git quotes those — the common
            # two-token form is handled, quoted form falls back gracefully
            old = _strip_prefix(parts[0]) if parts else None
            new = _strip_prefix(parts[-1]) if len(parts) > 1 else old
            cur = FileDiff(path=new, old_path=old)
            continue
        if cur is None:
            # preamble / garbage before the first file header
            if raw.startswith(("--- ", "+++ ")):
                cur = FileDiff(path=None)
            else:
                continue
        if raw.startswith("new file mode"):
            cur.is_new = True
            continue
        if raw.startswith("rename from "):
            cur.is_rename = True
            cur.old_path = raw[len("rename from "):].strip()
            continue
        if raw.startswith("rename to "):
            cur.is_rename = True
            cur.path = raw[len("rename to "):].strip()
            continue
        if raw.startswith(("Binary files ", "GIT binary patch")):
            cur.is_binary = True
            in_hunk = False
            continue
        if raw.startswith("--- ") and not in_hunk:
            p = raw[4:].strip()
            if p == "/dev/null":
                cur.is_new = True
                cur.old_path = None
            else:
                cur.old_path = _strip_prefix(p)
            continue
        if raw.startswith("+++ ") and not in_hunk:
            p = raw[4:].strip()
            cur.path = None if p == "/dev/null" else _strip_prefix(p)
            continue
        m = _HUNK_RE.match(raw)
        if m:
            in_hunk = True
            new_line = int(m.group(1))
            continue
        if not in_hunk or cur.is_binary:
            continue
        if raw.startswith("+"):
            if cur.path is not None:
                cur.added.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            pass  # removed: new-file counter does not advance, never scanned
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            # context line (leading space, or a bare empty line in sloppy
            # diffs): advances the new-file counter, never scanned
            new_line += 1
    _flush()
    return files
