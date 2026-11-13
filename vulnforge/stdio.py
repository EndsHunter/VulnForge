"""Make CLI output survive non-UTF-8 streams.

Help text, status lines and reports contain characters such as ``→`` and ``—``.
On Windows, a redirected or piped stdout (``vf status > out.txt``, CI logs, the
installer's ``vf --help | Out-Null``) uses the ANSI codepage (cp1252), which
cannot encode them, so ``print`` raises UnicodeEncodeError and the command dies.
The interactive Windows console is already UTF-8 and is left alone.
"""

from __future__ import annotations

import sys


def ensure_utf8_stdio() -> None:
    """Switch stdout/stderr to UTF-8 when they are not already. Idempotent."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding == "utf8":
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            # Replaced by something that is not a TextIOWrapper (test capture, IDE).
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Stream already has data buffered or is closed; keep it as it is.
            pass
