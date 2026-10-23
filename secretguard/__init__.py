"""Expose the public API at package level."""

from .allowlist import Allowlist
from .diffparse import FileDiff, parse_diff
from .hook import HOOK_SCRIPT, HookError, install_hook
from .scanner import Finding, ScanResult, compute_exit_code, scan_diff, scan_text

__all__ = [
    "Allowlist",
    "FileDiff",
    "Finding",
    "HOOK_SCRIPT",
    "HookError",
    "ScanResult",
    "compute_exit_code",
    "install_hook",
    "parse_diff",
    "scan_diff",
    "scan_text",
]
