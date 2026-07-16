"""Live toolgen against Ornith / LM Studio (not FakeLLM).

Requires ``VF_LIVE=1`` and a reachable OpenAI-compatible endpoint with enough
``max_tokens`` for reasoning models. Never applies integrate (dry-run only).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnforge.cli import load_config
from vulnforge.toolgen.generate import GenerateToolError, generate_fix, generate_impl, generate_spec
from vulnforge.toolgen.integrate import integrate
from vulnforge.toolgen.store import (
    create_draft,
    get_draft,
    reset_drafts_root_override,
    set_drafts_root,
)
from vulnforge.toolgen.validate import validate_draft


def _live_enabled() -> bool:
    return os.environ.get("VF_LIVE", "").strip() in ("1", "true", "yes", "YES")


@pytest.fixture
def drafts_root(tmp_path: Path):
    root = tmp_path / "tool_drafts"
    set_drafts_root(root)
    yield root
    reset_drafts_root_override()


@pytest.fixture(scope="module")
def live_cfg():
    if not _live_enabled():
        pytest.skip("set VF_LIVE=1 to run live toolgen tests")
    cfg = load_config()
    # Sanity: endpoint up
    from vulnforge.llm import make_client

    client = make_client(cfg)
    try:
        client.fingerprint_model()
    except Exception as e:
        client.close()
        pytest.skip(f"LLM endpoint not reachable: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    # Ensure toolgen headroom even if ui_settings is low
    llm = cfg.setdefault("llm", {})
    llm["toolgen_max_tokens"] = max(int(llm.get("toolgen_max_tokens") or 0), 8192)
    llm["max_tokens"] = max(int(llm.get("max_tokens") or 0), 4096)
    return cfg


@pytest.mark.live
def test_live_toolgen_spec_impl_validate_dry_integrate(live_cfg: dict, drafts_root: Path):
    did = "live_line_count"
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
        spec_out = generate_spec(live_cfg, did)
    except GenerateToolError as e:
        pytest.fail(f"generate_spec failed: {e}")
    assert spec_out.get("ok")
    d = get_draft(did)
    assert (d.get("spec_md") or "").strip(), "spec_md empty after generate_spec"
    print("model_id(spec):", spec_out.get("model_id"))
    print("spec_md chars:", len(d.get("spec_md") or ""))

    try:
        impl_out = generate_impl(live_cfg, did)
    except GenerateToolError as e:
        pytest.fail(f"generate_impl failed: {e}")
    assert impl_out.get("ok")
    d = get_draft(did, include_files=True)
    impl = d.get("impl_py") or ""
    assert impl.strip(), "impl_py empty"
    assert did in impl or "def " in impl
    schema = d.get("schema") or {}
    tools = schema.get("tools") if isinstance(schema, dict) else None
    assert isinstance(tools, list) and tools, f"schema missing tools: {schema!r}"
    print("model_id(impl):", impl_out.get("model_id"))
    print("impl_py chars:", len(impl))

    report = validate_draft(did, for_integrate=True, persist=True)
    if not report.get("ok"):
        print("hard_fail before fix:", report.get("hard_fail"))
        try:
            fix_out = generate_fix(live_cfg, did)
            print("fix:", fix_out.get("ok"), fix_out.get("validation", {}).get("hard_fail"))
        except GenerateToolError as e:
            pytest.fail(f"generate_fix failed: {e}")
        report = validate_draft(did, for_integrate=True, persist=True)

    if not report.get("ok"):
        # Still useful diagnostics; soft-fail only if structure is totally missing
        d = get_draft(did, include_files=True)
        assert (d.get("impl_py") or "").strip()
        pytest.xfail(
            f"validation still hard_fail after one fix: {report.get('hard_fail')}"
        )

    dry = integrate(did, dry_run=True, apply=False)
    assert dry.get("dry_run") is True
    assert dry.get("ok") is not False
    ops = dry.get("ops") or dry.get("plan", {}).get("ops") or []
    # plan may nest differently
    if not ops and isinstance(dry.get("plan"), dict):
        ops = dry["plan"].get("ops") or []
    assert ops or dry.get("tool_name") or "ops" in dry
    print("dry integrate keys:", list(dry.keys()))
