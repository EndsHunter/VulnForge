#!/usr/bin/env python3
"""CLI: validate a VulnForge tool draft package.

Usage:
  python scripts/validate_tool.py config/tool_drafts/<id>
  python scripts/validate_tool.py config/tool_drafts/<id> --json
  python scripts/validate_tool.py config/tool_drafts/<id> --integrate

Exit codes: 0 hard pass, 1 hard fail, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root without install
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.toolgen.validate import validate_draft_dir  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate a VulnForge tool draft")
    p.add_argument(
        "draft_dir",
        type=Path,
        help="Path to draft directory (e.g. config/tool_drafts/my_tool)",
    )
    p.add_argument("--json", action="store_true", help="Print full JSON report")
    p.add_argument(
        "--integrate",
        action="store_true",
        help="Use integrate-time hard checks (wireup + tests required)",
    )
    args = p.parse_args(argv)

    ddir = args.draft_dir.expanduser().resolve()
    if not ddir.is_dir():
        print(f"error: not a directory: {ddir}", file=sys.stderr)
        return 2

    report = validate_draft_dir(ddir, for_integrate=args.integrate)
    # Persist next to draft when possible
    try:
        out = ddir / "validation_report.json"
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report.get("ok") else "FAIL"
        print(f"{status}  draft={report.get('draft_id')}")
        for c in report.get("checks") or []:
            mark = "ok" if c.get("pass") else "FAIL" if c.get("level") == "hard" else "warn"
            detail = f" — {c['detail']}" if c.get("detail") else ""
            print(f"  [{mark}] {c.get('id')} ({c.get('level')}){detail}")
        if report.get("hard_fail"):
            print("hard_fail:")
            for h in report["hard_fail"]:
                print(f"  - {h}")
        print(f"guide: {report.get('guide_ref')}")

    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
