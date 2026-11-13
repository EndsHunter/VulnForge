"""Live **directed** hunt evals on the BenchmarkRun contract.

Directed = each hunt is pointed at the oracle's file and class
(``hunt_hints_from_oracle``), so recall here means "recall when told where to
look", not campaign recall.

Live creates a ``BenchmarkRun`` row, records a fingerprint (commit, model,
prompt/tool hashes, validate_llm), drives Ralph in a throwaway harness off the
HTTP worker, then scores by finding state (``live_score.score_case``) with
token usage from the eval run's ``llm_usage_summary.json``. GET reconciles.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

import yaml

from vulnforge.benchmarks.compare import member_row, summarize_repeats
from vulnforge.benchmarks.fingerprint import capture_fingerprint
from vulnforge.benchmarks.live_score import score_case
from vulnforge.benchmarks.runner import (
    _normalize_request_types,
    _terminal_status,
)
from vulnforge.benchmarks.suites import SUITES, suite_members, suite_refusal
from vulnforge.benchmarks.runs import (
    TERMINAL_STATUSES,
    BenchmarkRunError,
    create_run,
    get_run,
    is_suite_run,
    list_runs,
    runs_root,
    update_run,
)
from vulnforge.benchmarks.store import (
    BenchmarkLibraryError,
    get_def,
    get_version,
    list_defs,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.settings.load import load_config
from vulnforge.ui.runner import runner_status, start_run, stop_run_hard
from vulnforge.util import utc_now_iso

# Ralph task cap per case: hunt + validate_mech per candidate + disprove.
LIVE_TASKS_PER_HINT = 8
LIVE_MIN_TASKS = 8
LIVE_MAX_REPEAT = 5
LIVE_TASK_TIMEOUT = 600
LIVE_SUITE_CONCURRENCY = 1
LIVE_ORPHAN_SECONDS = 30 * 60
LIVE_POLL_MS = 320

LivePhase = Literal[
    "queued",
    "resolving_target",
    "init",
    "enqueue",
    "ralph",
    "score",
    "done",
]

ORACLE_LEAK_KEYS = frozenset(
    {
        "report_id",
        "title",
        "co_code",
        "l1",
        "l2",
        "ghsa",
        "cwe",
        "severity",
        "match",
    }
)


@dataclass(frozen=True)
class HuntHint:
    """What the hunt agent is allowed to know. No GHSA, title, lines, co_code."""

    path: str
    attack_class: str


@dataclass(frozen=True)
class LiveConfig:
    overlay_path: Path
    eval_runs_root: Path
    max_tasks: int = LIVE_MIN_TASKS
    task_timeout: int = LIVE_TASK_TIMEOUT
    base_url: str = ""
    model: str = ""
    api_mode: str = "chat_completions"


def eval_runs_root_for(run_id: str) -> Path:
    """Throwaway harness root. Never app.state.runs_root, never runs/."""
    rid = str(run_id or "").strip()
    if not rid:
        raise BenchmarkRunError("run_id is required")
    return (PROJECT_ROOT / ".audit" / "benchmarks" / "eval_runs" / rid).resolve()


def overlay_path_for(run_id: str) -> Path:
    return runs_root() / str(run_id) / "live_overlay.yaml"


def live_config_from_settings(run_id: str, cfg: dict[str, Any] | None = None) -> LiveConfig:
    from vulnforge.settings import normalize_api_mode

    data = cfg if isinstance(cfg, dict) else load_config()
    llm = data.get("llm") if isinstance(data.get("llm"), dict) else {}
    return LiveConfig(
        overlay_path=overlay_path_for(run_id),
        eval_runs_root=eval_runs_root_for(run_id),
        max_tasks=LIVE_MIN_TASKS,
        task_timeout=LIVE_TASK_TIMEOUT,
        base_url=str(llm.get("base_url") or "").strip(),
        model=str(llm.get("model") or "").strip(),
        api_mode=normalize_api_mode(llm.get("api_mode")),
    )


def live_refusal(*, types: list[str], suite: bool, def_id: str) -> str | None:
    """None = allowed. Else the error string written onto the BenchmarkRun.

    ``def_id`` is the suite id when ``suite`` is true.
    """
    types_n = [
        str(t).strip().lower().replace(" ", "_")
        for t in (types or [])
        if str(t).strip()
    ]
    if not types_n or any(t != "hunt" for t in types_n):
        return "live mode is hunt-only (recon and finding_report are L0 fixture checks)"
    if suite:
        return suite_refusal(str(def_id or "").strip().lower(), "directed")
    return None


def require_live_llm(cfg: dict[str, Any]) -> str | None:
    """None if llm.base_url and llm.model are non-empty. No network probe."""
    llm = cfg.get("llm") if isinstance(cfg, dict) and isinstance(cfg.get("llm"), dict) else {}
    base = str(llm.get("base_url") or "").strip()
    model = str(llm.get("model") or "").strip()
    if not base or not model:
        return (
            "live hunt needs Settings LLM endpoint and model "
            "(llm.base_url / llm.model)"
        )
    return None


def hunt_hints_from_oracle(oracle: dict[str, Any]) -> list[HuntHint]:
    hints: list[HuntHint] = []
    findings = oracle.get("findings") if isinstance(oracle, dict) else None
    if not isinstance(findings, list):
        return hints
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        path = str(finding.get("sink_path") or "").strip()
        cls = str(finding.get("class") or "wildcard").strip() or "wildcard"
        if path:
            hints.append(HuntHint(path=path, attack_class=cls))
    return hints


def packet_leaks_oracle(payload: dict[str, Any]) -> str | None:
    """Return a reason if the hunt payload smuggles oracle/GHSA text."""
    if not isinstance(payload, dict):
        return "hunt packet is not an object"
    try:
        blob = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        blob = str(payload)
    if "GHSA-" in blob.upper():
        return "hunt packet leaked GHSA"
    leaked = _walk_leak_keys(payload)
    if leaked:
        return f"hunt packet leaked oracle key {leaked}"
    return None


def _walk_leak_keys(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            low = str(key).strip().lower()
            if low in ORACLE_LEAK_KEYS:
                return str(key)
            found = _walk_leak_keys(val)
            if found:
                return found
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found = _walk_leak_keys(item)
            if found:
                return found
    return None


def list_active_runs() -> list[dict[str, Any]]:
    """Queued/running bench runs, suite parents first.

    Live rows are reconciled so a dashboard restart can close or resume them.
    Queued children of an active suite parent are omitted; a running child stays.
    """
    seen: dict[str, dict[str, Any]] = {}
    for status in ("running", "queued"):
        for row in list_runs(status=status, limit=200):
            rid = str(row.get("id") or "")
            if rid:
                seen[rid] = row
    reconciled: list[dict[str, Any]] = []
    for row in seen.values():
        if row.get("mode") == "live" and row.get("status") in ("queued", "running"):
            try:
                row = reconcile_live_run(str(row["id"]))
            except BenchmarkRunError:
                continue
        if row.get("status") not in ("queued", "running"):
            continue
        reconciled.append(row)
    parents = [r for r in reconciled if is_suite_run(r)]
    children = [r for r in reconciled if not is_suite_run(r)]
    member_ids: set[str] = set()
    for parent in parents:
        metrics = parent.get("metrics") if isinstance(parent.get("metrics"), dict) else {}
        for cid in metrics.get("member_run_ids") or []:
            if cid:
                member_ids.add(str(cid))
    children = [
        c
        for c in children
        if str(c.get("id") or "") not in member_ids or c.get("status") == "running"
    ]
    parents.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
    children.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
    return parents + children


def find_active_live_run() -> dict[str, Any] | None:
    """First live BenchmarkRun still queued or running, preferring a suite parent."""
    for row in list_active_runs():
        if row.get("mode") == "live":
            return row
    return None


def start_live_run(
    *,
    def_id: str,
    version: int | None = None,
    types: list[str] | None = None,
    worker: Callable[[str], None] | None = None,
    validate_llm: bool = True,
    note: str = "",
) -> dict[str, Any]:
    """Create one directed BenchmarkRun(mode=live). Spawn drive off the HTTP worker."""
    bid = str(def_id or "").strip().lower()
    if not bid:
        raise BenchmarkRunError("def_id is required")

    try:
        head = get_def(bid, include_oracle=False)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    ver = int(version) if version is not None else int(head.get("head_version") or 1)
    try:
        snap = get_version(bid, ver)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    snap_types = [str(t).strip().lower() for t in (snap.get("types") or [])]
    types_n = _normalize_request_types(types, snap_types=snap_types)
    for t in types_n:
        if t not in snap_types:
            raise BenchmarkRunError(f"benchmark {bid}@{ver} does not include {t}")

    cfg = load_config()
    err = live_refusal(types=types_n, suite=False, def_id=bid) or require_live_llm(cfg)
    run = create_run(
        def_id=bid,
        version=ver,
        types_run=types_n,
        mode="live",
        target_ref=str(snap.get("target_ref") or ""),
        oracle_hash=str(snap.get("oracle_hash") or ""),
        status="running",
        tier="directed",
        fingerprint=capture_fingerprint(cfg, validate_llm=validate_llm),
        note=note,
    )
    rid = run["id"]
    if err:
        return update_run(
            rid,
            status="error",
            error=err,
            metrics={"mode": "live", "confirmed": False},
        )
    _set_live_phase(
        rid,
        "queued",
        eval_runs_root=str(eval_runs_root_for(rid)),
    )
    if worker is not None:
        worker(rid)
    else:
        _spawn_daemon(drive_live_hunt, rid)
    return get_run(rid)


def start_live_suite(
    *,
    suite_id: str,
    repeat: int = 1,
    only: list[str] | None = None,
    worker: Callable[[str], None] | None = None,
    validate_llm: bool = True,
    note: str = "",
) -> dict[str, Any]:
    """Create a ``suite-<id>`` parent + one child per (case, repeat), then one worker.

    Children run sequentially. ``only`` subsets the suite's cases.
    """
    sid = str(suite_id or "").strip().lower()
    reps = max(1, min(int(repeat or 1), LIVE_MAX_REPEAT))
    cfg = load_config()
    fp = capture_fingerprint(cfg, validate_llm=validate_llm)
    err = live_refusal(types=["hunt"], suite=True, def_id=sid) or require_live_llm(cfg)
    parent = create_run(
        def_id=f"suite-{sid}" if sid in SUITES else "suite-unknown",
        version=1,
        types_run=["hunt"],
        mode="live",
        status="running",
        suite_id=sid if sid in SUITES else None,
        tier="directed",
        fingerprint=fp,
        note=note,
    )
    pid = parent["id"]
    base_metrics = {"suite": True, "suite_id": sid, "tier": "directed", "mode": "live", "confirmed": False}
    if err:
        return update_run(pid, status="error", error=err, metrics=base_metrics)

    members = suite_members(sid, "directed", list_defs())
    if only:
        want = {str(x).strip().lower() for x in only if str(x).strip()}
        members = [d for d in members if str(d.get("id") or "").strip().lower() in want]
    if not members:
        return update_run(
            pid,
            status="error",
            error=f"no hunt cases in suite {sid}",
            metrics=base_metrics,
        )

    plan: list[dict[str, Any]] = []
    for rep in range(reps):
        for defn in members:
            bid = str(defn.get("id") or "")
            try:
                head = get_def(bid, include_oracle=False)
                ver = int(head.get("head_version") or 1)
                snap = get_version(bid, ver)
            except BenchmarkLibraryError as e:
                return update_run(pid, status="error", error=str(e), metrics=base_metrics)
            child = create_run(
                def_id=bid,
                version=ver,
                types_run=["hunt"],
                mode="live",
                target_ref=str(snap.get("target_ref") or ""),
                oracle_hash=str(snap.get("oracle_hash") or ""),
                status="queued",
                tier="directed",
                fingerprint=fp,
                parent_id=pid,
            )
            plan.append({"run_id": child["id"], "repeat": rep})

    update_run(
        pid,
        metrics={
            **base_metrics,
            "repeat": reps,
            "member_plan": plan,
            "member_run_ids": [p["run_id"] for p in plan],
            "live": {"phase": "queued", "updated_at": utc_now_iso()},
        },
    )
    project_suite_parent(pid)
    if worker is not None:
        worker(pid)
    else:
        _spawn_daemon(drive_live_suite, pid)
    return get_run(pid)


def reconcile_live_run(run_id: str) -> dict[str, Any]:
    """Converge a live row after restart or during GET poll. Idempotent."""
    run = get_run(run_id)
    if run["status"] in TERMINAL_STATUSES:
        return run
    if run.get("mode") != "live":
        return run
    metrics = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
    if metrics.get("suite"):
        return project_suite_parent(run_id)
    harness = run.get("harness_run_dir")
    if harness:
        run_dir = Path(harness)
        st = runner_status(run_dir)
        if st.get("alive"):
            return run
        from vulnforge.db import Database

        db = Database(run_dir / "harness.db")
        try:
            if db.has_queued_or_leased():
                start_eval_ralph(run_dir, overlay_path_for(run_id))
                return get_run(run_id)
        finally:
            db.close()
        scored = score_live_hunt(run_dir, _oracles_for(run))
        return _close_hunt(run_id, scored)
    if _age_seconds(run) > LIVE_ORPHAN_SECONDS:
        return update_run(
            run_id,
            status="error",
            error="live worker lost before init",
            metrics=_live_metrics(run, phase="done"),
        )
    return run


def cancel_live_run(run_id: str) -> dict[str, Any]:
    """Stop Ralph via stop_run_hard if harness_run_dir set; suite skips queued children."""
    run = get_run(run_id)
    if run["status"] in TERMINAL_STATUSES:
        return run
    if run.get("mode") != "live":
        raise BenchmarkRunError("stop is only for live runs")
    metrics = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
    if metrics.get("suite"):
        for cid in metrics.get("member_run_ids") or []:
            if not cid:
                continue
            try:
                child = get_run(str(cid))
            except BenchmarkRunError:
                continue
            if child["status"] in TERMINAL_STATUSES:
                continue
            _stop_harness(child)
            update_run(
                str(cid),
                status="cancelled",
                metrics=_live_metrics(child, phase="done"),
            )
        update_run(
            run_id,
            status="cancelled",
            metrics=_live_metrics(run, phase="done"),
        )
        return project_suite_parent(run_id)
    _stop_harness(run)
    return update_run(
        run_id,
        status="cancelled",
        metrics=_live_metrics(run, phase="done"),
    )


def drive_live_hunt(run_id: str) -> dict[str, Any]:
    """One hunt case. resolve → overlay → init → enqueue → ralph → score."""
    try:
        run = _open_live(run_id)
        if run is None:
            return get_run(run_id)
        try:
            snap = get_version(run["def_id"], int(run.get("version") or 1))
        except BenchmarkLibraryError as e:
            return _fail(run_id, str(e))
        oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
        findings = [f for f in (oracle.get("findings") or []) if isinstance(f, dict)]
        _set_live_phase(run_id, "resolving_target")
        if _open_live(run_id) is None:
            return get_run(run_id)
        target = resolve_live_target(snap, oracle)
        overlay = write_live_overlay(
            run_id, load_config(), validate_llm=_validate_llm_of(run)
        )
        _set_live_phase(run_id, "init")
        if _open_live(run_id) is None:
            return get_run(run_id)
        eval_root = eval_runs_root_for(run_id)
        run_dir = init_eval_harness(
            run_id=run_id,
            target=target,
            overlay=overlay,
            eval_root=eval_root,
        )
        events = run_dir / "events.jsonl"
        update_run(
            run_id,
            harness_run_dir=str(run_dir),
            events_ref=str(events) if events.is_file() else None,
        )
        hints = hunt_hints_from_oracle(oracle)
        _set_live_phase(
            run_id,
            "enqueue",
            hints=[asdict(h) for h in hints],
            eval_runs_root=str(eval_root),
        )
        if _open_live(run_id) is None:
            return get_run(run_id)
        for hint in hints:
            r = enqueue_eval_hunt(run_dir, hint)
            if not r.get("ok"):
                return _fail(run_id, r.get("error") or "enqueue failed")
        _set_live_phase(run_id, "ralph")
        if _open_live(run_id) is None:
            return get_run(run_id)
        started = start_eval_ralph(run_dir, overlay, max_tasks=max_tasks_for(len(hints)))
        if not started.get("ok") and started.get("error") != "already running":
            return _fail(run_id, started.get("error") or "ralph start failed")
        wait_ralph_idle(run_dir)
        if _open_live(run_id) is None:
            return get_run(run_id)
        _set_live_phase(run_id, "score")
        metrics = score_live_hunt(run_dir, findings)
        return _close_hunt(run_id, metrics)
    except BenchmarkRunError as e:
        if _open_live(run_id) is None:
            return get_run(run_id)
        return _fail(run_id, str(e))
    except Exception as e:  # noqa: BLE001 — terminal error on unexpected failure
        if _open_live(run_id) is None:
            return get_run(run_id)
        return _fail(run_id, f"{type(e).__name__}: {e}")


def drive_live_suite(parent_id: str) -> dict[str, Any]:
    """Sequential for child in member_run_ids: drive_live_hunt; project parent."""
    try:
        parent = get_run(parent_id)
        ids = list((parent.get("metrics") or {}).get("member_run_ids") or [])
        for cid in ids:
            parent = get_run(parent_id)
            if parent["status"] in TERMINAL_STATUSES:
                break
            child = get_run(str(cid))
            if child["status"] not in TERMINAL_STATUSES:
                drive_live_hunt(str(cid))
            project_suite_parent(parent_id)
        return project_suite_parent(parent_id)
    except Exception as e:  # noqa: BLE001 — terminal error on unexpected failure
        parent = get_run(parent_id)
        if parent["status"] in TERMINAL_STATUSES:
            return parent
        return update_run(
            parent_id,
            status="error",
            error=f"{type(e).__name__}: {e}",
            metrics=_live_metrics(parent, phase="done"),
        )


def write_live_overlay(
    run_id: str, cfg: dict[str, Any], *, validate_llm: bool = True
) -> Path:
    """Persist the Settings snapshot next to result.json.

    ``stages.validate_llm`` follows the run (default on, as in production).
    Snapshots ``llm`` (including ``api_mode``: chat_completions / responses /
    messages) so Ralph + Strands use the same endpoint style as Settings.
    """
    from vulnforge.settings import normalize_api_mode

    live = live_config_from_settings(run_id, cfg)
    path = live.overlay_path
    path.parent.mkdir(parents=True, exist_ok=True)
    stages = dict(cfg.get("stages") or {}) if isinstance(cfg.get("stages"), dict) else {}
    stages["validate_llm"] = bool(validate_llm)
    payload = {
        "llm": dict(cfg.get("llm") or {}) if isinstance(cfg.get("llm"), dict) else {},
        "run": dict(cfg.get("run") or {}) if isinstance(cfg.get("run"), dict) else {},
        "stages": stages,
        "packet": dict(cfg.get("packet") or {}) if isinstance(cfg.get("packet"), dict) else {},
        "tools": dict(cfg.get("tools") or {}) if isinstance(cfg.get("tools"), dict) else {},
    }
    payload["llm"].pop("_config_path", None)
    # Pin canonical api_mode so hunt Strands provider matches Settings.
    payload["llm"]["api_mode"] = live.api_mode or normalize_api_mode(
        payload["llm"].get("api_mode")
    )
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")
    return path


def resolve_live_target(snap: dict[str, Any], oracle: dict[str, Any]) -> Path:
    """Existing tree, or checkout_oracle when target_ref is a VulnGym tree."""
    target_ref = str((snap or {}).get("target_ref") or "").strip()
    if not target_ref:
        raise BenchmarkRunError("benchmark version has empty target_ref")
    candidates = [Path(target_ref)]
    if not Path(target_ref).is_absolute():
        candidates.append(PROJECT_ROOT / target_ref)
    for p in candidates:
        if p.is_dir():
            return p.resolve()
    norm = target_ref.replace("\\", "/")
    if "/vulngym/trees/" not in f"/{norm}":
        raise BenchmarkRunError(f"target not found: {target_ref}")
    finding = _vulngym_finding(oracle)
    if finding is None:
        raise BenchmarkRunError(f"target not found: {target_ref}")
    from vulnforge.benchmarks.vulngym import checkout_oracle

    try:
        dest = checkout_oracle(finding)
    except Exception as e:
        raise BenchmarkRunError(
            f"VulnGym checkout failed for {target_ref}: {e}"
        ) from e
    if not dest.is_dir():
        raise BenchmarkRunError(f"target not found: {target_ref}")
    return dest.resolve()


def init_eval_harness(
    *,
    run_id: str,
    target: Path,
    overlay: Path,
    eval_root: Path,
) -> Path:
    """cmd_init in-process: file_by_file, --no-enqueue-hunts, --runs-root eval_root."""
    from vulnforge.cli import cmd_init

    eval_root.mkdir(parents=True, exist_ok=True)
    cfg: dict[str, Any] = {}
    if overlay.is_file():
        loaded = yaml.safe_load(overlay.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            cfg = loaded

    class Args:
        pass

    args = Args()
    args.target = Path(target)
    args.profile = "code_static"
    args.runs_root = Path(eval_root)
    args.strategy = "file_by_file"
    args.docs_path = None
    args.agent_ids = None
    args.operator_notes = ""
    args.dynamic_skills = False
    args.dynamic_skill_count = 3
    args.hunt_skill_mode = "all_active"
    args.hunt_skill_ids = None
    args.enqueue_hunts = False
    args.progress = lambda _update: None
    args.job_id = None

    import io
    from contextlib import redirect_stderr, redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        code = cmd_init(args, cfg)
    if code != 0:
        raise BenchmarkRunError(
            f"eval init failed for {run_id} exit={code}: {buf.getvalue().strip()[:500]}"
        )
    return _find_eval_run_dir(eval_root)


def enqueue_eval_hunt(run_dir: Path, hint: HuntHint) -> dict[str, Any]:
    """hunt_from_selection(path, attack_class, area='eval') only."""
    if not isinstance(hint, HuntHint):
        return {"ok": False, "error": "enqueue_eval_hunt requires HuntHint"}
    from vulnforge.control.ops import hunt_from_selection

    r = hunt_from_selection(
        run_dir,
        path=hint.path,
        attack_class=hint.attack_class,
        area="eval",
    )
    payload = r.get("payload") if isinstance(r.get("payload"), dict) else {}
    leak = packet_leaks_oracle(payload)
    if leak:
        return {"ok": False, "error": leak}
    return r


def start_eval_ralph(
    run_dir: Path, overlay: Path, *, max_tasks: int = LIVE_MIN_TASKS
) -> dict[str, Any]:
    """vulnforge.ui.runner.start_run (pid files, start_new_session)."""
    cfg_path = Path(overlay) if overlay and Path(overlay).is_file() else None
    saved: dict[str, str] = {}
    # Settings overlay is the LLM identity; inherited VF_EVAL_* would pin CLI Ornith.
    for key in ("VF_EVAL_HOST", "VF_EVAL_PORT", "VF_EVAL_MODEL"):
        if key in os.environ:
            saved[key] = os.environ.pop(key)
    try:
        result = start_run(
            Path(run_dir),
            task_timeout=LIVE_TASK_TIMEOUT,
            max_tasks=max_tasks,
            workers=1,
            config=cfg_path,
        )
    finally:
        os.environ.update(saved)
    return result


def wait_ralph_idle(run_dir: Path, *, poll_s: float = 1.0) -> None:
    """Loop runner_status until not alive. Daemon-only. GET does not wait."""
    while True:
        st = runner_status(Path(run_dir))
        if not st.get("alive"):
            return
        time.sleep(max(0.05, float(poll_s)))


def score_live_hunt(run_dir: Path, oracles: list[dict[str, Any]]) -> dict[str, Any]:
    """All findings (any state) + usage summary → ``score_case``."""
    from vulnforge.db import Database
    from vulnforge.usage import load_usage_summary

    db = Database(Path(run_dir) / "harness.db")
    try:
        findings = db.list_findings()
    finally:
        db.close()
    return score_case(findings, list(oracles or []), usage=load_usage_summary(run_dir))


def project_suite_parent(parent_id: str) -> dict[str, Any]:
    """Rebuild parent members + summary from child result.json. Close if all terminal."""
    parent = get_run(parent_id)
    metrics_in = parent.get("metrics") if isinstance(parent.get("metrics"), dict) else {}
    plan = metrics_in.get("member_plan")
    if not isinstance(plan, list) or not plan:
        plan = [{"run_id": cid, "repeat": 0} for cid in (metrics_in.get("member_run_ids") or [])]
    rows: list[dict[str, Any]] = []
    for item in plan:
        if not isinstance(item, dict) or not item.get("run_id"):
            continue
        try:
            child = get_run(str(item["run_id"]))
        except BenchmarkRunError:
            continue
        rows.append(member_row(child, repeat=int(item.get("repeat") or 0)))
    n = len(rows)
    n_pass = sum(1 for r in rows if r.get("status") == "passed")
    n_err = sum(1 for r in rows if r.get("status") == "error")
    n_term = sum(1 for r in rows if r.get("status") in TERMINAL_STATUSES)
    already = parent["status"] in TERMINAL_STATUSES
    if already:
        status = parent["status"]
    elif n > 0 and n_term == n:
        if n_pass == n:
            status = "passed"
        elif n_err == n:
            status = "error"
        else:
            status = "failed"
    else:
        status = "running"
    summary = summarize_repeats(rows)
    parent_metrics: dict[str, Any] = {
        **{k: metrics_in.get(k) for k in ("suite_id", "tier", "repeat") if k in metrics_in},
        "suite": True,
        "mode": "live",
        "confirmed": False,
        "count": n,
        "passed_count": n_pass,
        "failed_count": sum(1 for r in rows if r.get("status") == "failed"),
        "error_count": n_err,
        "recall": summary["headline"].get("recall"),
        "passed": status == "passed",
        "members": rows,
        "member_plan": plan,
        "member_run_ids": [r.get("run_id") for r in rows],
        "summary": summary,
    }
    live = metrics_in.get("live") if isinstance(metrics_in.get("live"), dict) else {}
    parent_metrics["live"] = {
        **live,
        "phase": "done" if status in TERMINAL_STATUSES else live.get("phase") or "queued",
        "done": n_term,
        "total": n,
        "updated_at": utc_now_iso(),
    }
    err_msg = parent.get("error")
    if status in TERMINAL_STATUSES and n_err and status != "cancelled":
        sample = [str(r.get("def_id")) for r in rows if r.get("status") == "error"][:8]
        err_msg = f"{n_err}/{n} cases error" + (": " + ", ".join(sample) if sample else "")
    return update_run(
        parent_id,
        status=status,
        metrics=parent_metrics,
        error=err_msg,
    )


def _set_live_phase(run_id: str, phase: LivePhase, **fields: Any) -> dict[str, Any]:
    """Merge metrics.live. Never sets confirmed true. Never writes oracle text."""
    run = get_run(run_id)
    metrics = _live_metrics(run, phase=phase, **fields)
    return update_run(run_id, metrics=metrics)


def _live_metrics(
    run: dict[str, Any],
    *,
    phase: LivePhase,
    **fields: Any,
) -> dict[str, Any]:
    metrics = dict(run.get("metrics") or {}) if isinstance(run.get("metrics"), dict) else {}
    metrics["mode"] = "live"
    metrics["confirmed"] = False
    live = dict(metrics.get("live") if isinstance(metrics.get("live"), dict) else {})
    live["phase"] = phase
    live["updated_at"] = utc_now_iso()
    for key, val in fields.items():
        live[key] = val
    metrics["live"] = live
    return metrics


def _spawn_daemon(fn: Callable[[str], dict[str, Any]], run_id: str) -> None:
    threading.Thread(
        target=fn,
        args=(run_id,),
        daemon=True,
        name=f"live-{run_id}",
    ).start()


def _open_live(run_id: str) -> dict[str, Any] | None:
    run = get_run(run_id)
    if run["status"] in TERMINAL_STATUSES:
        return None
    return run


def _fail(run_id: str, error: str) -> dict[str, Any]:
    run = get_run(run_id)
    if run["status"] in TERMINAL_STATUSES:
        return run
    return update_run(
        run_id,
        status="error",
        error=str(error),
        metrics=_live_metrics(run, phase="done"),
    )


def _close_hunt(run_id: str, scored: dict[str, Any]) -> dict[str, Any]:
    run = get_run(run_id)
    if run["status"] in TERMINAL_STATUSES:
        return run
    metrics = dict(scored)
    metrics["mode"] = "live"
    metrics["confirmed"] = False
    live = dict((run.get("metrics") or {}).get("live") or {})
    live["phase"] = "done"
    live["updated_at"] = utc_now_iso()
    metrics["live"] = live
    return update_run(
        run_id,
        status=_terminal_status(metrics),
        metrics=metrics,
        error=None,
    )


def _oracles_for(run: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        snap = get_version(str(run.get("def_id") or ""), int(run.get("version") or 1))
    except (BenchmarkLibraryError, TypeError, ValueError):
        return []
    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    return [f for f in (oracle.get("findings") or []) if isinstance(f, dict)]


def _vulngym_finding(oracle: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(oracle, dict):
        return None
    findings = oracle.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict) and finding.get("repo_url") and finding.get("commit"):
                return finding
    if oracle.get("repo_url") and oracle.get("commit"):
        return oracle
    return None


def _find_eval_run_dir(eval_root: Path) -> Path:
    hits: list[Path] = []
    root = Path(eval_root)
    if root.is_dir():
        for db in root.rglob("harness.db"):
            hits.append(db.parent)
    if not hits:
        raise BenchmarkRunError(f"eval init produced no run under {eval_root}")
    hits.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return hits[0]


def _age_seconds(run: dict[str, Any]) -> float:
    raw = str(run.get("started_at") or "")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds())


def _stop_harness(run: dict[str, Any]) -> None:
    harness = run.get("harness_run_dir")
    if not harness:
        return
    try:
        stop_run_hard(Path(harness))
    except Exception:
        return


def max_tasks_for(n_hints: int) -> int:
    """Ralph task cap for one case: enough for hunt + gates per hint."""
    return max(LIVE_MIN_TASKS, LIVE_TASKS_PER_HINT * max(1, int(n_hints or 0)))


def _validate_llm_of(run: dict[str, Any]) -> bool:
    fp = run.get("fingerprint") if isinstance(run.get("fingerprint"), dict) else {}
    return bool(fp.get("validate_llm", True))


__all__ = [
    "HuntHint",
    "LIVE_MAX_REPEAT",
    "LIVE_MIN_TASKS",
    "LIVE_TASKS_PER_HINT",
    "LIVE_ORPHAN_SECONDS",
    "LIVE_POLL_MS",
    "LIVE_SUITE_CONCURRENCY",
    "LIVE_TASK_TIMEOUT",
    "LiveConfig",
    "ORACLE_LEAK_KEYS",
    "cancel_live_run",
    "enqueue_eval_hunt",
    "eval_runs_root_for",
    "find_active_live_run",
    "list_active_runs",
    "hunt_hints_from_oracle",
    "live_refusal",
    "max_tasks_for",
    "packet_leaks_oracle",
    "reconcile_live_run",
    "require_live_llm",
    "score_live_hunt",
    "start_live_run",
    "start_live_suite",
]
