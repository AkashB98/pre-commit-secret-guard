"""CLI: check / scan / hook / serve, exit codes 0/1/2/3."""

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.request
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretguard.cli import main, make_server  # noqa: E402
from tests.fakes import AWS  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_DIFF = (
    "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
    "@@ -1,1 +1,2 @@\n ctx\n"
    f"+KEY = \"{AWS}\"\n"
)
WARN_DIFF = (
    "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
    "@@ -1,1 +1,2 @@\n ctx\n"
    "+mail ops@helioshome.test\n"
)


def run_cli(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    old = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
    finally:
        sys.stdin = old
    return rc, out.getvalue(), err.getvalue()


def test_check_stdin_blocking_exit_2():
    rc, _o, _e = run_cli(["check"], stdin_text=SECRET_DIFF)
    assert rc == 2


def test_check_stdin_warnings_exit_1():
    rc, _o, _e = run_cli(["check"], stdin_text=WARN_DIFF)
    assert rc == 1


def test_check_stdin_clean_exit_0():
    rc, _o, _e = run_cli(["check"], stdin_text="diff --git a/x b/x\n")
    assert rc == 0


def test_check_diff_file_and_json_format():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "d.diff")
        open(p, "w").write(SECRET_DIFF)
        rc, out, _e = run_cli(["check", "--diff", p, "--format", "json"])
        assert rc == 2
        payload = json.loads(out)
        assert payload["blocked"] is True
        assert payload["findings"][0]["kind"] == "aws_access_key"
        assert payload["findings"][0]["line"] == 2


def test_check_missing_diff_file_exit_3():
    rc, _o, err = run_cli(["check", "--diff", "/nonexistent/nope.diff"])
    assert rc == 3 and "error" in err


def test_check_bad_allowlist_exit_3():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "bad.json")
        open(p, "w").write("{not json")
        rc, _o, _e = run_cli(["check", "--allowlist", p],
                             stdin_text=SECRET_DIFF)
        assert rc == 3


def test_check_bad_args_exit_3():
    try:
        with redirect_stderr(io.StringIO()):
            main(["check", "--format", "yaml"])
        raise AssertionError("argparse should have exited")
    except SystemExit as exc:
        assert exc.code == 3, exc.code


def test_check_repo_uses_staged_diff():
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "init", "-q"], cwd=tmp, env=env, check=True)
        open(os.path.join(tmp, "a.py"), "w").write(f'KEY = "{AWS}"\n')
        subprocess.run(["git", "add", "a.py"], cwd=tmp, env=env, check=True)
        rc, _o, _e = run_cli(["check", "--repo", tmp])
        assert rc == 2
        # unstage everything -> clean
        subprocess.run(["git", "reset", "-q"], cwd=tmp, env=env, check=True)
        rc, _o, _e = run_cli(["check", "--repo", tmp])
        assert rc == 0


def test_scan_file_and_dir():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "cfg.py")
        open(p, "w").write(f'KEY = "{AWS}"\n')
        rc, _o, _e = run_cli(["scan", p])
        assert rc == 2
        rc, _o, _e = run_cli(["scan", tmp])
        assert rc == 2
        open(p, "w").write("clean = True\n")
        rc, _o, _e = run_cli(["scan", tmp])
        assert rc == 0


def test_scan_missing_path_exit_3():
    rc, _o, _e = run_cli(["scan", "/nonexistent/nope"])
    assert rc == 3


def test_scan_skips_binary_files():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "blob.bin")
        open(p, "wb").write(b"\x00\x01" + AWS.encode())
        rc, _o, _e = run_cli(["scan", p])
        assert rc == 0


def test_hook_prints_script():
    rc, out, _e = run_cli(["hook"])
    assert rc == 0
    assert out.startswith("#!/bin/sh")
    assert "secretguard check" in out


def test_hook_install_and_refusal_and_force():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".git"))
        rc, out, _e = run_cli(["hook", "--install", "--repo", tmp])
        assert rc == 0 and "installed" in out
        path = os.path.join(tmp, ".git", "hooks", "pre-commit")
        assert os.path.exists(path) and os.access(path, os.X_OK)
        rc, _o, err = run_cli(["hook", "--install", "--repo", tmp])
        assert rc == 3 and "refusing to overwrite" in err
        rc, _o, _e = run_cli(["hook", "--install", "--repo", tmp, "--force"])
        assert rc == 0


def test_hook_install_requires_git_repo():
    with tempfile.TemporaryDirectory() as tmp:
        rc, _o, _e = run_cli(["hook", "--install", "--repo", tmp])
        assert rc == 3


def test_hook_install_requires_repo_arg():
    rc, _o, _e = run_cli(["hook", "--install"])
    assert rc == 3


def test_serve_check_roundtrip():
    srv = make_server(0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_port
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/check",
            data=json.dumps({"diff": SECRET_DIFF}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())
        assert payload["exit_code"] == 2 and payload["blocked"] is True
        # raw-text body form
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/check",
            data=SECRET_DIFF.encode(),
            headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())
        assert payload["exit_code"] == 2
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health",
                                    timeout=10) as resp:
            assert json.loads(resp.read()) == {"ok": True}
    finally:
        srv.shutdown()


def test_module_entrypoint_subprocess():
    proc = subprocess.run(
        [sys.executable, "-m", "secretguard", "check"],
        input=SECRET_DIFF, capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 2, proc.stderr
