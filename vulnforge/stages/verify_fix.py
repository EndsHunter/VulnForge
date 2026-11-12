"""
Stage: verify_fix — independent re-check of one finding against a patched tree.

Operator-queued (or CLI). Exactly one source per task:

- ``patched_path``: an existing directory (used read-only, never deleted)
- ``git_rev`` (+ optional ``repo_path`` / ``subdir``): raw blobs exported into a
  task scratch dir (no checkout filters, no hooks)
- ``use_fix_patch``: target copy + ``evidence/<pack>/fix.patch`` in a scratch dir

Steps: mechanical diff of cited files → PoC re-run in the sandbox against the
patched tree (with a same-task baseline against the original) when the pack has
PoC code → read-only LLM re-check on the validate role, which never sees the
fix author's notes → conservative combiner.

Verdict: ``fixed`` / ``still_vulnerable`` / ``inconclusive``. ``inconclusive``
always lists what would resolve it. Never changes finding state; the human
decides. Writes ``evidence/<pack>/verify_fix.json``.
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from vulnforge.agent_runtime import run_tool_loop as run_agent_tool_loop
from vulnforge.errors import note_swallowed
from vulnforge.fix_patch import (
    FIX_PATCH_RELPATH,
    VERIFY_FIX_RELPATH,
    PatchError,
    check_patch,
    cited_region_diff,
    export_git_tree,
    git_prefix,
    materialize_patched_tree,
    new_scratch_dir,
    remove_scratch_dir,
)
from vulnforge.languages import POC_CODE_EXTS
from vulnforge.llm import InfraError, classify_llm_failure
from vulnforge.packet import (
    OverBudgetError,
    Packet,
    _budget_chars,
    load_prompt_slice,
    refuse_if_over_budget,
    truncate,
)
from vulnforge.paths import system_prompts_root
from vulnforge.stages.fix_common import (
    READ_ONLY_TOOLS,
    eligibility_error,
    guarded_handler,
    parse_finding_id,
    push_history,
    render_slices,
    resolve_evidence_id,
    tool_schemas,
    update_finding_body,
    verifier_view_of_body,
    write_json_atomic,
)
from vulnforge.tools import build_tool_handler
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.util import append_event, target_tool_root, utc_now_iso

STAGE = "verify_fix"
SOURCES = ("patched_path", "git_rev", "use_fix_patch")

# PoC evidence labels (combiner input).
POC_NONE = "no_poc"
POC_NOT_RUN = "not_run"
POC_NO_SIGNAL = "no_signal"
POC_REPRODUCES = "reproduces_on_patched"
POC_SUPPORTS_FIXED = "supports_fixed"

_CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


# --------------------------------------------------------------------------- tree source


def _resolve_tree(
    payload: dict, *, run_dir: Path, tool_root: Path, pack_dir: Path, task_id: Any
) -> tuple[Path, dict[str, Any], Path | None]:
    """(patched_tree, source_info, scratch_dir_to_remove_or_None). Raises PatchError."""
    picked = [k for k in SOURCES if payload.get(k)]
    if len(picked) != 1:
        raise PatchError("need_exactly_one_source:patched_path|git_rev|use_fix_patch")
    src = picked[0]
    if src == "patched_path":
        p = Path(str(payload["patched_path"])).expanduser()
        if not p.is_dir():
            raise PatchError(f"patched_path_not_dir:{p}")
        real = p.resolve()
        evidence_real = (run_dir / "evidence").resolve()
        if real == evidence_real or evidence_real in real.parents:
            raise PatchError("patched_path_inside_evidence")
        return real, {"source": "patched_path", "path": str(real)}, None

    scratch = new_scratch_dir(run_dir, task_id)
    tree = scratch / "tree"
    try:
        if src == "git_rev":
            repo_raw = payload.get("repo_path")
            if repo_raw:
                repo = Path(str(repo_raw)).expanduser().resolve()
                subdir = str(payload.get("subdir") or "")
            else:
                repo = tool_root
                subdir = git_prefix(tool_root)
            info = export_git_tree(repo, str(payload["git_rev"]), tree, subdir=subdir)
            info["repo_path"] = str(repo)
            return tree, info, scratch
        # use_fix_patch
        patch_file = pack_dir / FIX_PATCH_RELPATH
        if not patch_file.is_file():
            raise PatchError("fix_patch_missing:run develop_fix first or pass patched_path/git_rev")
        text = patch_file.read_text(encoding="utf-8")
        chk = check_patch(tool_root, text)
        if not chk["applies"]:
            raise PatchError("fix_patch_does_not_apply:" + ";".join(chk["errors"][:3]))
        info = materialize_patched_tree(tool_root, text, tree)
        import hashlib

        info["patch_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return tree, info, scratch
    except BaseException:
        remove_scratch_dir(run_dir, scratch)
        raise


# --------------------------------------------------------------------------- PoC


def _poc_code_files(pack_dir: Path) -> list[Path]:
    if not pack_dir.is_dir():
        return []
    out: list[Path] = []
    try:
        for child in sorted(pack_dir.iterdir()):
            if child.is_file() and not child.is_symlink() and child.suffix.lower() in POC_CODE_EXTS:
                out.append(child)
    except OSError:
        return []
    return out


def _target_bound(files: list[Path]) -> bool:
    """PoC code must reference the /target mount, or its result says nothing about the tree."""
    for f in files:
        try:
            if "/target" in f.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _mounted(run: dict | None, tree: Path) -> bool:
    if not run:
        return False
    want = f"{Path(tree).resolve()}:/target:ro"
    argv = run.get("argv") or []
    return isinstance(argv, list) and want in [str(a) for a in argv]


def _run_summary(run: dict | None, tree: Path) -> dict[str, Any] | None:
    if run is None:
        return None
    keep = (
        "verdict", "signal_matched", "exit_code", "ran", "timed_out", "isolation",
        "runtime", "spawn_error", "operator_hint", "command", "success_regex", "duration_ms",
    )
    out = {k: run.get(k) for k in keep}
    out["target_mounted"] = _mounted(run, tree)
    out["target_path"] = str(tree)
    out["stdout_excerpt"] = str(run.get("stdout_excerpt") or "")[:2000]
    out["stderr_excerpt"] = str(run.get("stderr_excerpt") or "")[:1000]
    return out


def _poc_phase(
    *,
    payload: dict,
    cfg: dict,
    pack_dir: Path,
    tree: Path,
    original_root: Path,
    finding_id: int,
    body_view: dict,
) -> dict[str, Any]:
    from vulnforge.poc_runner import execute_poc_for_pack, harness_config

    files = _poc_code_files(pack_dir)
    if not files:
        return {"evidence": POC_NONE, "present": False, "reasons": [], "would_resolve": []}
    info: dict[str, Any] = {
        "present": True,
        "code_files": [f.name for f in files],
        "target_bound": _target_bound(files),
        "reasons": [],
        "would_resolve": [],
    }
    hc = harness_config(cfg)
    if not hc["enabled"] and not payload.get("force"):
        info.update(evidence=POC_NOT_RUN)
        info["reasons"].append("poc_harness_disabled")
        info["would_resolve"].append(
            "Enable poc_harness (or pass force) so the PoC re-runs against the patched tree."
        )
        return info

    # The patched tree must be visible to the PoC: force the read-only /target mount.
    run_cfg = copy.deepcopy(cfg or {})
    ph = run_cfg.setdefault("poc_harness", {})
    ph["mount_target_ro"] = True
    if payload.get("force"):
        ph["enabled"] = True
    env: dict[str, str] = {}
    if payload.get("TARGET_URL"):
        env["TARGET_URL"] = str(payload["TARGET_URL"])

    def _exec(path: Path) -> dict[str, Any]:
        return execute_poc_for_pack(
            pack_dir,
            cfg=run_cfg,
            env_extra=env or None,
            finding_body=body_view,
            finding_id=finding_id,
            target_path=str(path),
        )

    patched = _exec(tree)
    baseline = _exec(original_root) if payload.get("baseline", True) is not False else None
    info["patched_run"] = _run_summary(patched, tree)
    info["baseline_run"] = _run_summary(baseline, original_root)

    p_m = _mounted(patched, tree)
    b_m = _mounted(baseline, original_root)
    p_obs = p_m and patched.get("signal_matched") is True and patched.get("verdict") == "signal_observed"
    p_abs = p_m and patched.get("signal_matched") is False and patched.get("verdict") == "signal_absent"
    b_obs = (
        baseline is not None
        and b_m
        and baseline.get("signal_matched") is True
        and baseline.get("verdict") == "signal_observed"
    )
    reasons: list[str] = info["reasons"]
    hints: list[str] = info["would_resolve"]
    if not info["target_bound"]:
        info["evidence"] = POC_NO_SIGNAL
        reasons.append("poc_not_target_bound")
        hints.append(
            "PoC code never references /target, so its result does not depend on the patched "
            "tree. Make the PoC import or build the code under /target."
        )
    elif p_obs:
        info["evidence"] = POC_REPRODUCES
        reasons.append("signal_observed_on_patched_tree")
    elif p_abs and b_obs:
        info["evidence"] = POC_SUPPORTS_FIXED
        reasons.append("baseline_reproduced_patched_did_not")
    else:
        info["evidence"] = POC_NO_SIGNAL
        if not p_m:
            reasons.append(f"patched_run_not_mounted:{patched.get('verdict')}")
            hints.append(
                "Re-run the PoC in a microVM/gVisor sandbox that mounts the patched tree at "
                f"/target (last run: {patched.get('verdict')}; "
                f"{patched.get('operator_hint') or patched.get('spawn_error') or 'no hint'})."
            )
        elif p_abs and baseline is None:
            reasons.append("no_same_task_baseline")
            hints.append("Re-run with baseline enabled so the PoC is shown to reproduce on the original tree.")
        elif p_abs and not b_obs:
            reasons.append(f"baseline_did_not_reproduce:{(baseline or {}).get('verdict')}")
            hints.append(
                "The PoC did not reproduce on the original tree in this task. Fix the PoC "
                "(develop_poc / iterate_poc) so it reproduces before judging the patch."
            )
        else:
            reasons.append(f"patched_run_{patched.get('verdict')}")
            hints.append(
                "The patched-tree PoC run gave no clear signal "
                f"({patched.get('verdict')}). Add a success_regex and a runnable entry point."
            )
    return info


# --------------------------------------------------------------------------- LLM


def parse_verify_output(text: str) -> dict[str, Any]:
    verdict = "inconclusive"
    confidence = "low"
    reasoning = ""
    hints: list[str] = []
    parsed = False
    for line in (text or "").splitlines():
        s = line.strip().strip("`*- ")
        up = s.upper()
        if "=" not in s:
            continue
        val = s.split("=", 1)[1].strip().strip("`\"'")
        if up.startswith("VERDICT="):
            v = val.lower()
            if v in ("fixed", "still_vulnerable", "inconclusive"):
                verdict, parsed = v, True
        elif up.startswith("CONFIDENCE="):
            if val.lower() in _CONF_ORDER:
                confidence = val.lower()
        elif up.startswith("REASONING="):
            reasoning = val
        elif up.startswith("WOULD_RESOLVE="):
            if val:
                hints.append(val[:500])
    if not reasoning:
        reasoning = (text or "")[:1500]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "would_resolve": hints[:10],
        "parsed": parsed,
    }


def pack_verify_fix(
    cfg: dict,
    prompts_root: Path,
    body_view: dict,
    patched_slices: list[dict],
    *,
    diff: dict,
    poc: dict,
) -> Packet:
    try:
        preamble = load_prompt_slice(prompts_root, "preamble.md")
    except FileNotFoundError:
        preamble = ""
    system = (
        (preamble + "\n" if preamble else "")
        + "## Stage: verify_fix\n"
        + "Independently judge whether the finding is still present in the patched tree. "
        + "Your tools read the PATCHED tree, read-only. You are not the patch author. "
        + "Answer VERDICT=fixed|still_vulnerable|inconclusive. Never claim confirmed.\n"
    )
    try:
        stage_md = load_prompt_slice(prompts_root, "verify_fix.md")
    except FileNotFoundError:
        stage_md = "Output VERDICT=, CONFIDENCE=, REASONING=, WOULD_RESOLVE= lines.\n"
    max_slice = int((cfg.get("packet") or {}).get("max_file_slice_chars", 4000))
    diff_view = {
        "cited_code_unchanged": diff.get("cited_code_unchanged"),
        "any_region_changed": diff.get("any_region_changed"),
        "files": [
            {k: v for k, v in f.items() if k != "diff"} for f in diff.get("files") or []
        ],
    }
    diffs = "\n".join(
        f.get("diff") or "" for f in diff.get("files") or [] if f.get("diff")
    ) or "_(no textual change in cited files)_"
    poc_view = {k: poc.get(k) for k in ("evidence", "present", "target_bound", "reasons")}
    for k in ("patched_run", "baseline_run"):
        if poc.get(k):
            poc_view[k] = {
                kk: poc[k].get(kk)
                for kk in ("verdict", "signal_matched", "exit_code", "target_mounted", "stdout_excerpt")
            }
    user = (
        stage_md
        + "\n\n## Finding (claim only)\n```json\n"
        + truncate(json.dumps(body_view, indent=2), 10000, "finding")
        + "\n```\n\n## Cited-file change summary\n```json\n"
        + json.dumps(diff_view, indent=2)
        + "\n```\n\n## Cited-file diff (original → patched)\n```diff\n"
        + truncate(diffs, 12000, "diff")
        + "\n```\n\n## PoC re-run\n```json\n"
        + truncate(json.dumps(poc_view, indent=2), 4000, "poc")
        + "\n```\n\n## Cited slices (patched tree)\n"
        + render_slices(patched_slices, max_slice)
    )
    budget = _budget_chars(cfg)
    total = len(system) + len(user)
    over = total > budget
    return Packet(
        system=system,
        user=truncate(user, budget - len(system), STAGE) if over else user,
        tools_schema=tool_schemas(READ_ONLY_TOOLS, stage=STAGE),
        meta={"chars": total, "budget": budget, "stage": STAGE},
        over_budget=total > budget * 1.5,
    )


def _llm_phase(
    *, task, run_dir: Path, cfg: dict, tree: Path, finding, body_view: dict, diff: dict, poc: dict
) -> dict[str, Any]:
    from vulnforge.llm_models import cfg_for_stage, make_client_for_stage
    from vulnforge.stages.validate_llm import load_citation_slices

    role_cfg = cfg_for_stage(cfg, STAGE)
    per_slice = int((cfg.get("packet") or {}).get("max_file_slice_chars", 4000))
    slices = load_citation_slices(finding, tree, max_chars=max(per_slice, min(per_slice * 3, 12_000)))
    try:
        packet = pack_verify_fix(
            role_cfg, system_prompts_root(), body_view, slices, diff=diff, poc=poc
        )
        refuse_if_over_budget(packet)
    except (FileNotFoundError, OverBudgetError) as e:
        return {"ok": False, "task_error": f"packet:{e}"}

    ctx = {
        "target_root": str(tree),
        "evidence_root": str(run_dir / "evidence"),
        "task_id": getattr(task, "id", 0),
        "cfg": cfg,
        "session": {"tools_used": [], "evidence_files": []},
    }
    handler = guarded_handler(build_tool_handler(ctx), allowed=READ_ONLY_TOOLS)
    client = make_client_for_stage(role_cfg, STAGE)
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {"ok": False, "infra": True, "error": str(e)}
        llm = role_cfg.get("llm") or {}
        result = run_agent_tool_loop(
            client,
            packet,
            handler,
            max_rounds=int(llm.get("max_tool_rounds", 12)),
            temperature=float(llm.get("temperature_disprove", 0.1)),
            cfg=role_cfg,
        )
        usage = record_llm_result(
            run_dir, task_id=getattr(task, "id", 0) or 0, kind=STAGE, model_id=model_id, result=result
        )
        try:
            save_transcript(
                run_dir,
                getattr(task, "id", 0) or 0,
                kind=STAGE,
                model_id=model_id,
                messages=list(result.transcript or []),
                result={
                    "ok": result.ok,
                    "classification": result.classification.value,
                    "error": result.error,
                    "content": result.content,
                    **usage,
                },
                meta={"finding_id": finding.id, "stage": STAGE},
            )
        except OSError as exc:
            note_swallowed(exc, context="verify_fix.save_transcript")
        if not result.ok and result.error not in (None, "max_tool_rounds"):
            if classify_llm_failure(result) == "failed_infra":
                return {
                    "ok": False,
                    "infra": True,
                    "error": result.error or result.classification.value,
                    "model_id": model_id,
                }
        parsed = parse_verify_output(result.content or "")
        if not parsed["parsed"]:
            parsed["would_resolve"].append(
                "Verifier gave no VERDICT line"
                + (f" ({result.error})" if result.error else "")
                + "; re-run verify_fix or review the transcript."
            )
        return {"ok": True, "model_id": model_id, **parsed, **usage}
    finally:
        try:
            client.close()
        except Exception as exc:
            note_swallowed(exc, context="verify_fix.client_close", level=logging.DEBUG)


# --------------------------------------------------------------------------- combiner


def _cap(conf: str, ceiling: str) -> str:
    return conf if _CONF_ORDER.get(conf, 0) <= _CONF_ORDER[ceiling] else ceiling


def combine_verdict(*, llm: dict, poc: dict, diff: dict) -> dict[str, Any]:
    """Conservative, deterministic. ``fixed`` needs two independent supports."""
    lv = str(llm.get("verdict") or "inconclusive")
    lc = str(llm.get("confidence") or "low")
    pe = str(poc.get("evidence") or POC_NONE)
    has_poc = bool(poc.get("present"))
    region = bool(diff.get("any_region_changed"))
    reasons: list[str] = []
    hints: list[str] = list(poc.get("would_resolve") or [])

    if pe == POC_REPRODUCES:
        verdict, conf, basis = "still_vulnerable", "high", "poc"
        reasons.append("PoC signal observed against the patched tree.")
        if lv == "fixed":
            reasons.append("Static verifier said fixed; the PoC run overrides it.")
    elif lv == "still_vulnerable":
        if pe == POC_SUPPORTS_FIXED:
            verdict, conf, basis = "inconclusive", "low", "conflict"
            reasons.append("Static verifier says still vulnerable; PoC stopped reproducing.")
            hints.append(
                "Resolve the conflict: check whether the patch broke the PoC path rather "
                "than the weakness (e.g. renamed entry point), or extend the PoC to the bypass "
                "the verifier describes."
            )
        else:
            verdict, conf, basis = "still_vulnerable", _cap(lc, "medium"), "static"
            reasons.append("Static verifier traced a remaining path to the weakness.")
    elif lv == "fixed":
        if pe == POC_SUPPORTS_FIXED:
            verdict, conf, basis = "fixed", "high", "poc+static"
            reasons.append("PoC reproduced on the original and not on the patched tree; static verifier agrees.")
        elif not has_poc and region:
            verdict, conf, basis = "fixed", _cap(lc, "medium"), "static_only"
            reasons.append("No PoC in the pack; static verifier says fixed and a change overlaps the cited code.")
        else:
            verdict, conf, basis = "inconclusive", "low", "insufficient"
            if has_poc:
                reasons.append(f"Static verifier says fixed, but the PoC gave no usable signal ({pe}).")
            if not region:
                reasons.append("No change overlaps the cited code, so a static-only fixed is not accepted.")
                hints.append(
                    "Show where the fix lives (it may be upstream of the citation), or add a PoC "
                    "that reproduces on the original tree."
                )
    else:
        verdict, conf, basis = "inconclusive", "low", "verifier_inconclusive"
        reasons.append("Static verifier could not decide.")

    hints.extend(llm.get("would_resolve") or [])
    if verdict == "inconclusive" and not hints:
        hints.append(
            "Provide a PoC that reproduces on the original tree, or a human review of the "
            "cited source→sink path in the patched tree."
        )
    # De-dup, keep order.
    seen: set[str] = set()
    uniq = [h for h in hints if not (h in seen or seen.add(h))]
    return {
        "verdict": verdict,
        "confidence": conf,
        "basis": basis,
        "reasons": reasons,
        "would_resolve": uniq if verdict == "inconclusive" else uniq[:5],
    }


# --------------------------------------------------------------------------- run


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(task.payload or {})
    fid, fid_err = parse_finding_id(payload.get("finding_id"))
    if fid is None:
        return {"status": "failed_task", "error": fid_err}
    finding = db.get_finding(fid)
    if finding is None:
        return {"status": "failed_task", "error": "finding_not_found", "finding_id": fid}
    err = eligibility_error(finding, payload)
    if err:
        return {"status": "failed_task", "error": err, "finding_id": fid}
    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run", "finding_id": fid}
    eid, eid_err = resolve_evidence_id(payload, finding)
    if eid is None:
        return {"status": "failed_task", "error": eid_err, "finding_id": fid}

    tool_root = target_tool_root(Path(run_row["target_path"])).resolve()
    pack_dir = run_dir / "evidence" / eid
    task_id = getattr(task, "id", 0) or 0
    try:
        tree, source_info, scratch = _resolve_tree(
            payload, run_dir=run_dir, tool_root=tool_root, pack_dir=pack_dir, task_id=task_id
        )
    except PatchError as e:
        return {"status": "failed_task", "error": str(e), "finding_id": fid}
    except OSError as e:
        return {"status": "failed_task", "error": f"tree_source_failed:{e}", "finding_id": fid}

    keep_tree = bool(payload.get("keep_tree"))
    try:
        body_view = verifier_view_of_body(dict(finding.body or {}))
        diff = cited_region_diff(tool_root, tree, body_view.get("citations") or [])
        poc = _poc_phase(
            payload=payload,
            cfg=cfg,
            pack_dir=pack_dir,
            tree=tree,
            original_root=tool_root,
            finding_id=fid,
            body_view=body_view,
        )
        llm = _llm_phase(
            task=task, run_dir=run_dir, cfg=cfg, tree=tree, finding=finding,
            body_view=body_view, diff=diff, poc=poc,
        )
        if llm.get("infra"):
            return {"status": "failed_infra", "error": llm.get("error"), "finding_id": fid}
        if not llm.get("ok"):
            return {"status": "failed_task", "error": llm.get("task_error"), "finding_id": fid}

        combined = combine_verdict(llm=llm, poc=poc, diff=diff)
        record = {
            "schema": "vulnforge.verify_fix.v1",
            "at": utc_now_iso(),
            "task_id": task_id,
            "finding_id": fid,
            "evidence_id": eid,
            "operator": payload.get("operator") or "agent",
            **combined,
            "source": source_info,
            "cited_diff": diff,
            "poc": poc,
            "static_check": {
                k: llm.get(k)
                for k in ("model_id", "verdict", "confidence", "reasoning", "would_resolve", "parsed")
            },
            "independence": {
                "verifier_role": "validate",
                "withheld_from_verifier": ["fix_notes.md", "fix_* finding fields", "develop_fix transcript"],
            },
            "finding_state": finding.state,
            "caveats": [
                "verify_fix output is evidence only. It does not change finding state.",
                "fixed is not proof of absence; it means two independent checks found no remaining path.",
                "inconclusive is a real result: see would_resolve.",
            ],
        }
        if scratch is not None:
            record["scratch_tree"] = str(tree) if keep_tree else None
        try:
            write_json_atomic(pack_dir / VERIFY_FIX_RELPATH, record)
        except OSError as e:
            return {"status": "failed_task", "error": f"write_verify_fix_failed:{e}", "finding_id": fid}

        entry = {
            "at": record["at"],
            "task_id": task_id,
            "verdict": combined["verdict"],
            "confidence": combined["confidence"],
            "basis": combined["basis"],
            "source": source_info.get("source"),
            "rev": source_info.get("commit") or source_info.get("patch_sha256") or source_info.get("path"),
            "poc_evidence": poc.get("evidence"),
            "verify_relpath": VERIFY_FIX_RELPATH,
            "would_resolve": combined["would_resolve"][:5],
        }
        update_finding_body(db, fid, eid, lambda b: push_history(b, "fix_verification", entry))
        try:
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "fix_verified",
                    "task_id": task_id,
                    "finding_id": fid,
                    "evidence_id": eid,
                    "verdict": combined["verdict"],
                    "basis": combined["basis"],
                    "poc_evidence": poc.get("evidence"),
                },
            )
        except OSError as exc:
            note_swallowed(exc, context="verify_fix.append_event")
        return {
            "status": "succeeded",
            "finding_id": fid,
            "evidence_id": eid,
            "verify_relpath": VERIFY_FIX_RELPATH,
            "verdict": combined["verdict"],
            "confidence": combined["confidence"],
            "basis": combined["basis"],
            "would_resolve": combined["would_resolve"],
            "poc_evidence": poc.get("evidence"),
            "model_id": llm.get("model_id"),
            "finding_state": db.get_finding(fid).state,
        }
    finally:
        if scratch is not None and not keep_tree:
            remove_scratch_dir(run_dir, scratch)
