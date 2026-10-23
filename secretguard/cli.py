"""CLI: check / scan / hook / demo / serve.

Exit codes for `check` and `scan` (CI-friendly):
    0 = clean
    1 = warnings only (low severity, e.g. email / phone)
    2 = blocking secrets found
    3 = usage / tool error (bad args, unreadable input, git failure) —
        the exit-3-for-errors convention follows the sibling
        llm-judge-calibration CLI; argparse errors also exit 3 here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from .allowlist import Allowlist
from .hook import HOOK_SCRIPT, HookError, install_hook
from .scanner import ScanResult, scan_diff, scan_text

DEFAULT_PORT = 8093


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors exit 3, not argparse's 2
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(3)


def _make_allowlist(path: str | None) -> Allowlist:
    return Allowlist.from_file(path) if path else Allowlist.default()


def _report(result: ScanResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return
    for f in result.findings:
        tag = "BLOCK" if f.blocking else "warn"
        print(f"{tag} {f.detector} [{f.kind}/{f.severity}] "
              f"{f.path}:{f.line}")
    for f in result.allowed:
        print(f"allow {f.detector} [{f.kind}] {f.path}:{f.line} ({f.note})")
    for f in result.suppressed:
        print(f"suppr {f.detector} [{f.kind}] {f.path}:{f.line} ({f.note})")
    if not result.findings:
        print("secretguard: no blocking findings")
    elif result.blocked:
        print(f"secretguard: {sum(1 for f in result.findings if f.blocking)} "
              "blocking finding(s) - commit should be aborted",
              file=sys.stderr)


def _staged_diff(repo: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo, "diff", "--cached", "--no-color"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff --cached failed in {repo}: "
                           f"{proc.stderr.strip()}")
    return proc.stdout


def cmd_check(args: argparse.Namespace) -> int:
    try:
        allow = _make_allowlist(args.allowlist)
    except Exception as exc:
        print(f"error: bad allowlist file: {exc}", file=sys.stderr)
        return 3
    try:
        if args.diff and args.diff != "-":
            with open(args.diff, "r", encoding="utf-8") as fh:
                diff_text = fh.read()
        elif args.repo:
            diff_text = _staged_diff(args.repo)
        elif not sys.stdin.isatty():
            diff_text = sys.stdin.read()
        else:
            print("error: no diff source: pass --diff FILE, --repo DIR, "
                  "or pipe a diff on stdin", file=sys.stderr)
            return 3
    except (OSError, RuntimeError) as exc:
        print(f"error: cannot obtain diff: {exc}", file=sys.stderr)
        return 3
    result = scan_diff(diff_text, allow)
    _report(result, args.format)
    return result.exit_code


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        allow = _make_allowlist(args.allowlist)
    except Exception as exc:
        print(f"error: bad allowlist file: {exc}", file=sys.stderr)
        return 3
    files: list[str] = []
    for target in args.paths:
        if os.path.isfile(target):
            files.append(target)
        elif os.path.isdir(target):
            for root, dirs, names in os.walk(target):
                dirs[:] = sorted(d for d in dirs
                                   if d not in (".git", "__pycache__"))
                for name in sorted(names):
                    files.append(os.path.join(root, name))
        else:
            print(f"error: no such file or directory: {target}",
                  file=sys.stderr)
            return 3
    merged = ScanResult()
    for path in sorted(files):
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 3
        if b"\x00" in blob[:8192]:
            continue  # binary file: nothing line-shaped to scan
        text = blob.decode("utf-8", errors="replace")
        r = scan_text(text, path, allow)
        merged.findings.extend(r.findings)
        merged.allowed.extend(r.allowed)
        merged.suppressed.extend(r.suppressed)
    _report(merged, args.format)
    return merged.exit_code


def cmd_hook(args: argparse.Namespace) -> int:
    if not args.install:
        sys.stdout.write(HOOK_SCRIPT)
        return 0
    if not args.repo:
        print("error: hook --install requires --repo DIR", file=sys.stderr)
        return 3
    try:
        path = install_hook(args.repo, force=args.force)
    except HookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(f"installed pre-commit hook: {path}")
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import demo
    demo.run()
    return 0


class _Handler(BaseHTTPRequestHandler):
    allow: Allowlist = Allowlist.default()

    def log_message(self, *a):  # quiet
        pass

    def _send_json(self, code: int, obj: dict) -> None:
        payload = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"ok": True})
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        if self.path != "/check":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        diff_text = ""
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self.send_error(400, "invalid JSON")
                return
            diff_text = str(body.get("diff", body.get("text", "")))
        else:
            diff_text = raw.decode("utf-8", errors="replace")
        result = scan_diff(diff_text, self.allow)
        self._send_json(200, result.to_dict())


def make_server(port: int, allowlist: Allowlist | None = None) -> HTTPServer:
    _Handler.allow = allowlist or Allowlist.default()
    return HTTPServer(("127.0.0.1", port), _Handler)


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        allow = _make_allowlist(args.allowlist)
    except Exception as exc:
        print(f"error: bad allowlist file: {exc}", file=sys.stderr)
        return 3
    srv = make_server(args.port, allow)
    print(f"serving POST /check on 127.0.0.1:{srv.server_port}",
          file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="secretguard",
                description="Scan staged git diffs for secrets and PII; "
                            "block the commit before a leaked key exists.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check a diff: exit 0 clean / "
                                     "1 warnings / 2 blocking / 3 error")
    c.add_argument("--diff", help="diff file to read ('-' or omitted: "
                                  "stdin, unless --repo is given)")
    c.add_argument("--repo", help="repo dir: run git diff --cached there")
    c.add_argument("--allowlist", help="custom allowlist JSON file")
    c.add_argument("--format", choices=("text", "json"), default="text")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("scan", help="scan plain files/dirs directly")
    s.add_argument("paths", nargs="+", help="files or directories")
    s.add_argument("--allowlist", help="custom allowlist JSON file")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("hook", help="print or install the pre-commit hook")
    h.add_argument("--install", action="store_true",
                   help="write .git/hooks/pre-commit in --repo")
    h.add_argument("--repo", help="repo dir for --install")
    h.add_argument("--force", action="store_true",
                   help="overwrite an existing hook")
    h.set_defaults(func=cmd_hook)

    d = sub.add_parser("demo", help="run the asserted end-to-end demo")
    d.set_defaults(func=cmd_demo)

    v = sub.add_parser("serve", help="JSON API: POST /check on 127.0.0.1")
    v.add_argument("--port", type=int, default=DEFAULT_PORT)
    v.add_argument("--allowlist", help="custom allowlist JSON file")
    v.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
