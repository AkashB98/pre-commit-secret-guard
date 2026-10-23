"""No-network guard: scanning must never touch the network.

Same discipline as every sibling build: stub out socket at import and
fail any test that triggers a real connection. (The serve tests bind a
localhost socket explicitly and are not run under this guard.)
"""

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class _GuardedSocket(socket.socket):
    def connect(self, *a, **k):
        raise AssertionError("network access attempted in hermetic test")


def test_no_network_import_and_scan():
    real = socket.socket
    socket.socket = _GuardedSocket
    try:
        for mod in [m for m in list(sys.modules)
                    if m.startswith("secretguard")]:
            del sys.modules[mod]
        from secretguard import scan_diff, scan_text
        scan_text("nothing to see here\n", "t.txt")
        scan_diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n"
                  "@@ -1,1 +1,1 @@\n-a\n+b\n")
    finally:
        socket.socket = real
