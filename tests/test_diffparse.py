"""Diff parsing: added lines only, correct NEW-file line numbers."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard import parse_diff  # noqa: E402
from tests.fakes import AWS  # noqa: E402


def test_added_lines_and_line_numbers():
    diff = (
        "diff --git a/a.py b/a.py\n"
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -10,3 +10,4 @@ def f():\n"
        " ctx\n"
        "-removed\n"
        f"+KEY = \"{AWS}\"\n"
        " ctx2\n"
        "+tail\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.path == "a.py"
    assert fd.added == [(11, f'KEY = "{AWS}"'), (13, "tail")], fd.added


def test_removed_secret_is_not_scanned():
    from secretguard import scan_diff
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,2 +1,1 @@\n"
        f"-KEY = \"{AWS}\"\n"
        " keep\n"
    )
    r = scan_diff(diff)
    assert r.findings == [] and r.exit_code == 0


def test_multiple_hunks_advance_counter():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,1 +1,2 @@\n a\n+one\n"
        "@@ -50,1 +51,2 @@\n b\n+two\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.added == [(2, "one"), (52, "two")], fd.added


def test_new_file():
    diff = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+first\n+second\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.is_new and fd.old_path is None and fd.path == "new.py"
    assert fd.added == [(1, "first"), (2, "second")]


def test_deleted_file_has_no_path_or_added():
    diff = (
        "diff --git a/gone.py b/gone.py\n"
        "deleted file mode 100644\n"
        "--- a/gone.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-one\n-two\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.path is None and fd.added == []


def test_rename_reports_new_path():
    from secretguard import scan_diff
    diff = (
        "diff --git a/old.py b/new.py\n"
        "similarity index 80%\n"
        "rename from old.py\n"
        "rename to new.py\n"
        "--- a/old.py\n"
        "+++ b/new.py\n"
        "@@ -1,1 +1,2 @@\n"
        " ctx\n"
        f"+KEY = \"{AWS}\"\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.is_rename and fd.path == "new.py" and fd.old_path == "old.py"
    r = scan_diff(diff)
    assert r.findings[0].path == "new.py" and r.findings[0].line == 2


def test_binary_diff_is_graceful():
    diff = (
        "diff --git a/logo.png b/logo.png\n"
        "Binary files a/logo.png and b/logo.png differ\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n"
        "@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    fds = parse_diff(diff)
    assert fds[0].is_binary and fds[0].added == []
    assert fds[1].added == [(1, "new")]


def test_plus_plus_plus_inside_hunk_is_content():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,1 +1,2 @@\n"
        " ctx\n"
        "+++not-a-header\n"
    )
    (fd,) = parse_diff(diff)
    assert fd.added == [(2, "++not-a-header")], fd.added


def test_multiple_files():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,1 +1,1 @@\n-x\n+y\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n"
        "@@ -5,1 +5,1 @@\n-x\n+z\n"
    )
    fds = parse_diff(diff)
    assert [f.path for f in fds] == ["a.py", "b.py"]
    assert fds[1].added == [(5, "z")]


def test_empty_and_garbage_input():
    assert parse_diff("") == []
    assert parse_diff("not a diff at all\njust text\n") == []
