#!/usr/bin/env python3
"""Assert seeded hunt library count ≥30 and Arch class mix floors.

Usage (from repo root, after ensure_library / tests autouse seed)::

    python scripts/assert_hunt_mix.py

Exits 0 on pass, 1 on fail. Prints hunt count and class histogram.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

# Allow running without install when cwd is repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.benchmarks import (  # noqa: E402
    ensure_library,
    get_def,
    list_defs,
    set_library_root,
)
from vulnforge.paths import PROJECT_ROOT  # noqa: E402

MIX_FLOORS = {
    "injection": 3,
    "access-control": 3,
    "web-protocol-auth": 2,
    "business-logic": 1,
}
AI_OR_SUPPLY = ("ai-llm", "supply-chain")


def main() -> int:
    # Ephemeral library so we never touch benchmarks/library/
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="vf-hunt-mix-"))
    set_library_root(root)
    ensure_library()

    hunts = [d for d in list_defs() if "hunt" in (d.get("types") or [])]
    hist: Counter[str] = Counter()
    for d in hunts:
        row = get_def(d["id"])
        findings = (row.get("oracle") or {}).get("findings") or []
        if findings and isinstance(findings[0], dict):
            cls = str(findings[0].get("class") or "").strip().lower()
            if cls:
                hist[cls] += 1

    print(f"hunt_count={len(hunts)}")
    print("class_histogram=" + str(dict(sorted(hist.items()))))
    print(f"library_root={root} (ephemeral)")
    print(f"project={PROJECT_ROOT}")

    errors: list[str] = []
    if len(hunts) < 30:
        errors.append(f"hunt count {len(hunts)} < 30")
    for cls, floor in MIX_FLOORS.items():
        got = hist.get(cls, 0)
        if got < floor:
            errors.append(f"{cls}: {got} < floor {floor}")
    if sum(hist.get(c, 0) for c in AI_OR_SUPPLY) < 1:
        errors.append("need ≥1 ai-llm or supply-chain")
    # memory-safety: document skip only when no seed exists
    if hist.get("memory-safety", 0) < 1:
        errors.append(
            "memory-safety: 0 (expected ≥1 via fixtures/hunt_extra; "
            "would skip/document if class unavailable)"
        )

    if errors:
        print("FAIL:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
