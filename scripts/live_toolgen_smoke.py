#!/usr/bin/env python3
"""Live toolgen smoke against Ornith / LM Studio (no FakeLLM).

Creates a temporary draft under config/tool_drafts/ (or TOOLGEN_DRAFTS_ROOT),
runs generate spec → impl → validate → optional one fix → dry-run integrate.

Usage (repo root, venv active, model server up)::

    python scripts/live_toolgen_smoke.py
    VF_MODEL=ornith-1.0-35b@4bit python scripts/live_toolgen_smoke.py

Does **not** apply integrate (never writes package tools by default).
Pass ``--apply`` only after reviewing impl.py (mutates the package).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    p = argparse.ArgumentParser(description="Live Ornith toolgen smoke")
    p.add_argument("--draft-id", default="live_line_count", help="Draft / tool id")
    p.add_argument(
        "--apply",
        action="store_true",
        help="Apply integrate (writes vulnforge/tools + extra_registry). Default: dry-run only.",
    )
    p.add_argument("--skip-fix", action="store_true", help="Do not run AI fix on hard_fail")
    args = p.parse_args()

    from vulnforge.cli import load_config
    from vulnforge.toolgen.generate import GenerateToolError, generate_fix, generate_impl, generate_spec
    from vulnforge.toolgen.integrate import integrate
    from vulnforge.toolgen.store import create_draft, delete_draft, get_draft
    from vulnforge.toolgen.validate import validate_draft

    cfg = load_config()
    llm = cfg.setdefault("llm", {})
    llm["toolgen_max_tokens"] = max(int(llm.get("toolgen_max_tokens") or 0), 8192)
    llm["max_tokens"] = max(int(llm.get("max_tokens") or 0), 4096)

    did = args.draft_id
    print(f"config model={llm.get('model')} base_url={llm.get('base_url')}")
    print(f"draft_id={did}")

    try:
        delete_draft(did)
    except Exception:
        pass

    create_draft(
        brief=(
            "Read-only tool: count newline-terminated lines in a single file "
            "under the target tree. One path arg. No writes."
        ),
        suggested_id=did,
        stages=["hunt"],
        risk_class="read_only",
        slots={
            "problem_statement": "Agents need a cheap line count for evidence sizing.",
            "non_goals": "No directory recursion, no network, no shell.",
            "io_contract": 'path:str -> {"ok":true,"lines":int} or {"ok":false,"error":str}',
            "safety_constraints": "resolve_target_path; read_only; return ok dict",
        },
    )

    try:
        print("→ generate_spec …")
        out = generate_spec(cfg, did)
        print("  ok model_id=", out.get("model_id"))
        print("→ generate_impl …")
        out = generate_impl(cfg, did)
        print("  ok model_id=", out.get("model_id"), "impl_chars=", len(get_draft(did).get("impl_py") or ""))
        report = validate_draft(did, for_integrate=True, persist=True)
        print("→ validate hard_fail=", report.get("hard_fail"))
        if not report.get("ok") and not args.skip_fix:
            print("→ generate_fix …")
            fix = generate_fix(cfg, did)
            print("  validation=", (fix.get("validation") or {}).get("hard_fail"))
            report = validate_draft(did, for_integrate=True, persist=True)
        print("→ final validate ok=", report.get("ok"), "hard_fail=", report.get("hard_fail"))
        dry = integrate(did, dry_run=True, apply=False)
        print("→ dry integrate keys=", list(dry.keys()))
        if args.apply:
            if not report.get("ok"):
                print("REFUSE apply: validation not ok", file=sys.stderr)
                return 2
            print("→ APPLY integrate …")
            applied = integrate(did, dry_run=False, apply=True)
            print(applied)
        else:
            print("dry-run only (pass --apply to write package files after review)")
        print("draft files under config/tool_drafts/" + did)
        return 0 if report.get("ok") else 1
    except GenerateToolError as e:
        print(f"GenerateToolError: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
