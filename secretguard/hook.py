"""Pre-commit hook generation and installation.

The hook is a small POSIX shell script that runs the checker against the
staged diff and translates the checker's CI exit codes into git's
language: any non-zero hook exit blocks the commit.

    checker 0 (clean)          -> hook 0, commit proceeds
    checker 1 (warnings only)  -> hook 0, commit proceeds, warnings shown
    checker 2 (blocking)       -> hook 1, commit BLOCKED
    checker 3 (tool error)     -> hook 1, commit BLOCKED (fail closed)
"""

from __future__ import annotations

import os
import stat

HOOK_SCRIPT = """#!/bin/sh
# pre-commit hook installed by pre-commit-secret-guard
# Blocks the commit when staged changes contain blocking secrets.
# Warnings (email/phone) are printed but do not block.
repo="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 1
python3 -m secretguard check --repo "$repo"
rc=$?
if [ "$rc" -eq 2 ]; then
  echo "secretguard: blocking secrets in staged changes - commit aborted" >&2
  exit 1
fi
if [ "$rc" -eq 3 ]; then
  echo "secretguard: checker error - commit aborted (fail closed)" >&2
  exit 1
fi
exit 0
"""


class HookError(Exception):
    pass


def hook_path(repo: str) -> str:
    return os.path.join(repo, ".git", "hooks", "pre-commit")


def install_hook(repo: str, force: bool = False) -> str:
    """Write the hook into <repo>/.git/hooks/pre-commit.

    Refuses to overwrite an existing hook unless force=True.
    Returns the hook path.
    """
    git_dir = os.path.join(repo, ".git")
    if not os.path.isdir(git_dir):
        raise HookError(f"not a git repository (no .git directory): {repo}")
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    path = hook_path(repo)
    if os.path.exists(path) and not force:
        raise HookError(
            f"a pre-commit hook already exists at {path}; "
            "refusing to overwrite (pass --force to replace it)"
        )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HOOK_SCRIPT)
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
