"""
FastAPI dashboard for vulnforge.

  vf dashboard
  # -> http://127.0.0.1:8787
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from vulnforge.cli import PROJECT_ROOT, load_config, resolve_runs_root
from vulnforge.settings import load_ui_settings, save_ui_settings
from vulnforge.step_io import build_graph_snapshot, build_task_io
from vulnforge.transcript import (
    list_transcript_ids,
    list_transcript_passes,
    load_transcript,
)
from vulnforge.ui import ops as dashops
from vulnforge.ui import runner as runctl
from vulnforge.ui import store
from vulnforge.usage import load_usage_for_task

UI_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(UI_DIR / "templates"))
STATIC_DIR = UI_DIR / "static"

# Runner states that mean the outer loop is still driving work.
_RUNNER_ALIVE = frozenset({"running", "pausing", "busy"})


def incomplete_from_flags(has_work: bool, runner_state: str | None) -> bool:
    """True when residual queue work remains but the runner is not alive."""
    rstate = runner_state or "idle"
    return bool(has_work) and rstate not in _RUNNER_ALIVE


def with_runner_flags(
    card: dict[str, Any],
    run_path: Path,
    *,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach runner status, incomplete flag, and stage footgun warnings."""
    runner = runctl.runner_status(run_path)
    card["runner"] = runner
    rstate = (runner or {}).get("state") or "idle"
    card["incomplete"] = incomplete_from_flags(bool(card.get("has_work")), rstate)
    stages = (cfg or {}).get("stages") or {}
    # Mech-pass awaits human; validate_llm (default on) may auto-reject only.
    card["validate_llm_on"] = bool(stages.get("validate_llm"))
    card["validate_llm_suppresses_confirm"] = True  # confirmed is always human-gated
    card["validate_llm_note"] = (
        "mech-pass -> dual disprove -> needs_human or rejected_llm (never auto-confirm)"
        if stages.get("validate_llm")
        else "mech-pass -> needs_human; human confirms or rejects (validate_llm off)"
    )
    return card


class InitBody(BaseModel):
    target: str
    profile: Optional[str] = None
    start: bool = True
    max_tasks: Optional[int] = 50
    task_timeout: float = 900
    # Run mode: discovery | file_by_file | recon_docs (backend may store on run config)
    strategy: Optional[str] = "discovery"
    docs_path: Optional[str] = None
    # Optional recon agent subset + operator brief (discovery / recon_docs)
    agent_ids: Optional[list[str]] = None
    operator_notes: str = ""
    # After recon, author N target-specific hunt skills for this run
    dynamic_skills: bool = False
    dynamic_skill_count: Optional[int] = 3
    # Run-scoped hunt skill policy (does not change global Dev active toggles)
    hunt_skill_mode: Optional[str] = "all_active"
    hunt_skill_ids: Optional[list[str]] = None
    # After recon (or at file_by_file init), enqueue hunt tasks. False = map only / manual.
    enqueue_hunts: bool = True


class ControlBody(BaseModel):
    # None = no Ralph --max-tasks (run until idle / STOP). Explicit int caps progress.
    # UI settings max_tasks is hunt *enqueue* planning only — not applied here.
    max_tasks: Optional[int] = Field(default=None)
    task_timeout: float = 900
    # Safety rail for Ralph outer loop (not a campaign wall). High for real audits.
    max_iterations: int = 10_000
    max_wall_seconds: Optional[float] = None  # None = no wall clock
    workers: Optional[int] = None  # defaults from UI settings
    # Dev/API only: named profile under config/harnesses/ (not operator UI)
    loop_profile_id: Optional[str] = None


class ChatTurnBody(BaseModel):
    message: str = ""
    session_id: Optional[str] = None


class ChatConfirmBody(BaseModel):
    token: str
    session_id: str


def control_start_kwargs(body: ControlBody, ui: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Merge ControlBody with UI settings for start/resume.

    Operator Mission Start/Resume (app.js controlBodyFromSettings):
      - never sends loop_profile_id (dev-only via API)
      - max_tasks=None → no Ralph --max-tasks (run until idle / Pause)
      - max_wall_seconds=None → no wall clock
      - max_iterations defaults high (safety rail only)
      - workers from Settings max_concurrent_agents
      - task_timeout default 900 (hung-task kill; not a campaign wall)

    UI settings ``max_tasks`` is the **hunt enqueue** planning cap (Coverage /
    init), not the Ralph outer-loop budget — do not apply it to start_run.

    When loop_profile_id is set (dev/smoke API), load config/harnesses/<id>.yaml
    as the base; explicit body fields override when provided.
    """
    if ui is None:
        ui = load_ui_settings()
    kwargs: dict[str, Any] = {}
    lease_cap = max(1, int(ui.get("max_concurrent_agents") or 1))

    if body.loop_profile_id:
        from vulnforge.loop_profiles import load_profile, profile_to_start_kwargs

        prof = load_profile(body.loop_profile_id)
        if not prof:
            raise ValueError(f"unknown loop profile: {body.loop_profile_id}")
        kwargs.update(profile_to_start_kwargs(prof))
        # Allow request body to override profile when client sends explicit values
        if body.max_tasks is not None:
            kwargs["max_tasks"] = body.max_tasks
        if body.workers is not None:
            kwargs["workers"] = body.workers
        if body.max_wall_seconds is not None:
            kwargs["max_wall_seconds"] = body.max_wall_seconds
        # Cap workers to lease cap (profile + body can both request too many)
        raw_w = int(kwargs.get("workers") or lease_cap)
        kwargs["workers"] = max(1, min(raw_w, lease_cap))
        # Prefer profile knobs for timeout/iterations when loop_profile_id is set.
        return kwargs

    raw_workers = body.workers if body.workers is not None else lease_cap
    # Never spawn more Ralph processes than concurrent leases allow
    workers = max(1, min(int(raw_workers), lease_cap))
    # None = unlimited Ralph progress budget (omit --max-tasks). Explicit body
    # max_tasks still honored for API clients that want a cap.
    max_tasks = body.max_tasks
    # High safety rail so a runaway loop still eventually stops; not a campaign budget.
    max_iterations = int(body.max_iterations) if body.max_iterations else 10_000
    if max_iterations < 1:
        max_iterations = 10_000
    return {
        "task_timeout": body.task_timeout,
        "max_tasks": max_tasks,
        "max_iterations": max_iterations,
        "max_wall_seconds": body.max_wall_seconds,  # None = no wall
        "workers": workers,
    }


class SettingsBody(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    model: Optional[str] = None
    api_mode: Optional[str] = None  # chat_completions | responses | messages
    # Optional; blank / "none" / "null" clear the key (local servers need none).
    api_key: Optional[str] = None
    # Per-stage model overrides (blank → default model)
    model_recon: Optional[str] = None
    model_hunt: Optional[str] = None
    model_develop_poc: Optional[str] = None
    # Multi-model validation (list or newline/comma string accepted in save)
    validate_models: Optional[list[str]] = None
    validate_consensus: Optional[str] = None  # all | majority
    validate_poc_referee: Optional[bool] = None
    validate_llm: Optional[bool] = None
    max_concurrent_agents: Optional[int] = None
    context_tokens: Optional[int] = None
    max_context_fraction: Optional[float] = None
    max_tokens: Optional[int] = None
    max_tool_rounds: Optional[int] = None
    timeout_seconds: Optional[int] = None
    max_tasks: Optional[int] = None


class SettingsOptimizeBody(BaseModel):
    """Probe live endpoint and recommend settings (optional form overrides)."""

    host: Optional[str] = None
    port: Optional[int] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    apply: bool = False
    test_context: bool = True


class HuntProfileBody(BaseModel):
    """Create or update a hunt profile."""

    id: Optional[str] = None
    body_md: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    active: Optional[bool] = None
    tags: Optional[list[str] | str] = None
    languages: Optional[list[str] | str] = None
    cwe: Optional[list[str] | str] = None
    angle_ids: Optional[list[int] | list[str] | str] = None
    sink_families: Optional[list[str] | str] = None
    specificity: Optional[int] = None
    version: Optional[int] = None
    tools: Optional[list[str] | str] = None
    clear_tools: Optional[bool] = None


class ToolsDefaultsBody(BaseModel):
    """Global default tools per stage (null = built-in packet surface)."""

    recon: Optional[list[str]] = None
    hunt: Optional[list[str]] = None
    develop_poc: Optional[list[str]] = None
    clear_recon: bool = False
    clear_hunt: bool = False
    clear_develop_poc: bool = False


class ToolDraftCreateBody(BaseModel):
    brief: str = ""
    suggested_id: Optional[str] = None
    source: str = "blank"  # blank | tool_gap | extend_existing
    gap: Optional[Any] = None
    stages: Optional[list[str]] = None
    risk_class: str = "read_only"
    prefer_extend: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    slots: Optional[dict[str, Any]] = None


class ToolDraftUpdateBody(BaseModel):
    brief: Optional[str] = None
    slots: Optional[dict[str, Any]] = None
    title: Optional[str] = None
    description: Optional[str] = None
    stages: Optional[list[str]] = None
    risk_class: Optional[str] = None
    prefer_extend: Optional[str] = None
    operator_notes: Optional[str] = None
    spec_md: Optional[str] = None
    impl_py: Optional[str] = None
    tool_schema: Optional[dict[str, Any]] = Field(
        default=None, alias="schema", description="OpenAI tool schema package"
    )
    wireup: Optional[dict[str, Any]] = None
    handler_snippet: Optional[str] = None
    test_stub: Optional[str] = None
    status: Optional[str] = None

    model_config = {"populate_by_name": True}


class ToolGenerateBody(BaseModel):
    use_prompt_overrides: bool = True


class ToolPromptPreviewBody(BaseModel):
    stage: str = "spec"  # spec | impl | fix
    use_prompt_overrides: bool = True


class ToolPromptOverrideBody(BaseModel):
    name: str
    content: str


class ToolIntegrateBody(BaseModel):
    dry_run: bool = True
    apply: bool = False
    add_to_profiles: Optional[list[str]] = None


class ToolRejectBody(BaseModel):
    reason: str = ""


class HuntGenerateBody(BaseModel):
    """LLM-author a hunt skill from an operator brief."""

    brief: str
    suggested_id: Optional[str] = None
    activate: bool = False
    save: bool = True
    signals: Optional[Any] = None


class HuntImportBody(BaseModel):
    data: Any
    mode: str = "merge"


class DevSetupImportBody(BaseModel):
    """Import full Dev setup pack (or a legacy single-collection export)."""

    data: Any
    mode: str = "merge"
    include: Optional[list[str]] = None


class ReconAgentBody(BaseModel):
    """Create or update a recon agent."""

    id: Optional[str] = None
    body_md: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    active: Optional[bool] = None
    order: Optional[int] = None
    mode: Optional[str] = None
    tools: Optional[list[str]] = None
    temperature: Optional[float] = None
    max_tool_rounds: Optional[int] = None
    output: Optional[str] = None


class ReconAgentImportBody(BaseModel):
    data: Any
    mode: str = "merge"


class CoverageRequeueBody(BaseModel):
    area: str
    attack_class: str = Field(alias="class")
    path_hints: Optional[list[str]] = None
    force_depth: bool = True
    reason: str = "operator_requeue"
    operator_notes: str = ""
    # Optional focused sinks from Coverage cell detail (path:line:kind records)
    seed_sinks: Optional[list[dict]] = None

    model_config = {"populate_by_name": True}


class CoverageRequeueBulkBody(BaseModel):
    """Multi-cell residual requeue (Coverage2 multi-select / residual repair)."""

    cells: list[dict]  # [{area, class, path_hints?}]
    force_depth: bool = True
    reason: str = "operator_bulk_requeue"
    operator_notes: str = ""


class CoverageModeBody(BaseModel):
    mode: str = "auto"  # auto | all | select
    areas: Optional[list[str]] = None
    classes: Optional[list[str]] = None
    path_targets: Optional[list[dict]] = None  # [{path, is_dir}] from Hunts path picker
    enqueue: bool = True
    uncapped: bool = False  # select: ignore run.max_tasks (all is always uncapped)


class CoverageGenerateSkillBody(BaseModel):
    """Enqueue Ralph generate_skill from Coverage (async)."""

    brief: str
    suggested_id: Optional[str] = None
    activate: bool = False
    enqueue_hunts: bool = True
    areas: Optional[list[str]] = None
    path_targets: Optional[list[dict]] = None


class TaskPriorityBody(BaseModel):
    """Operator queue reorder — tiers map to priority integers (lower = sooner)."""

    tier: str  # run_next | high | normal | low


class TaskCancelBody(BaseModel):
    """Operator queue removal — only queued tasks."""

    reason: str = "operator_cancel"


class TaskPauseBody(BaseModel):
    """Park a queued/leased task so the next queued can run."""

    reason: str = "operator_pause"


class TaskResumeBody(BaseModel):
    """Return a paused task to the queue (default: run next)."""

    tier: str = "run_next"  # run_next | high | normal | low | keep
    reason: str = "operator_resume"


class TaskHaltBody(BaseModel):
    """Terminal-cancel a queued, paused, or leased task."""

    reason: str = "operator_halt"


class SelectionHuntBody(BaseModel):
    path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    attack_class: str = "wildcard"
    area: Optional[str] = None
    note: str = ""
    operator_notes: str = ""


class ReconRerunBody(BaseModel):
    operator_notes: str = ""
    focus_paths: Optional[list[str]] = None
    include_prior_architecture: bool = True
    enqueue_hunts: bool = True
    reason: str = "operator_recon_rerun"
    agent_ids: Optional[list[str]] = None
    hunt_skill_mode: Optional[str] = None
    hunt_skill_ids: Optional[list[str]] = None


class FindingReviewBody(BaseModel):
    """Human accept / reject / reclassify a finding."""

    action: str  # confirm | reject | needs_human
    notes: str = ""
    write_note_to_evidence: bool = True
    operator: str = "operator"


class FindingPocBody(BaseModel):
    """Save PoC draft and optionally enqueue develop_poc agent task."""

    content: Optional[str] = None
    enqueue_agent: bool = False
    operator_notes: str = ""
    operator: str = "operator"


class FindingValidatePocBody(BaseModel):
    """Enqueue validate_poc harness task (never auto-confirms)."""

    operator: str = "operator"
    operator_notes: str = ""
    target_url: str = ""
    referee: bool = False
    command: str = ""


class FindingExportValidationJobBody(BaseModel):
    """Export validation handoff bundle."""

    as_zip: bool = True
    include_citations: bool = True


class FindingsMergeBody(BaseModel):
    """Operator merge: supersede drop_ids into keep_id (never auto-confirm)."""

    keep_id: int
    drop_ids: list[int]
    operator: str = "operator"


class ChainStepBody(BaseModel):
    finding_id: int
    role: str = ""
    notes: str = ""
    poc_path: Optional[str] = None


class ChainBody(BaseModel):
    """Create/update attack chain document under evidence/chains/."""

    id: Optional[str] = None
    title: str = "Attack chain"
    include_states: Optional[list[str]] = None
    steps: list[ChainStepBody] = Field(default_factory=list)


class ChainFromFindingsBody(BaseModel):
    """Build chain from selected findings (or all matching include_states)."""

    finding_ids: Optional[list[int]] = None
    include_states: Optional[list[str]] = None
    title: str = ""
    enqueue_poc: bool = False
    operator: str = "operator"


class ArchitectureEditBody(BaseModel):
    """Manual architecture edit — full architecture dict + optional note."""

    architecture: dict[str, Any]
    note: str = ""


class ArchitectureRestoreBody(BaseModel):
    """Optional note when restoring a revision."""

    note: str = ""


def _validate_architecture_body(arch: Any) -> Optional[str]:
    """Basic structure check for manual architecture PUT. Returns error string or None."""
    if not isinstance(arch, dict):
        return "architecture must be an object"
    if not arch:
        return "architecture must not be empty"
    if "summary" in arch and arch["summary"] is not None and not isinstance(
        arch["summary"], str
    ):
        return "summary must be a string when present"
    for list_key in (
        "components",
        "trust_boundaries",
        "input_surfaces",
        "hunt_focus",
    ):
        if list_key in arch and arch[list_key] is not None:
            if not isinstance(arch[list_key], list):
                return f"{list_key} must be a list when present"
    if "components" in arch and isinstance(arch["components"], list):
        for i, c in enumerate(arch["components"][:200]):
            if c is None:
                continue
            if not isinstance(c, (dict, str)):
                return f"components[{i}] must be an object or string"
            if isinstance(c, dict) and "path_hints" in c and c["path_hints"] is not None:
                if not isinstance(c["path_hints"], list):
                    return f"components[{i}].path_hints must be a list"
    return None


def create_app(runs_root: Optional[Path] = None) -> FastAPI:
    cfg = load_config()
    root = Path(runs_root) if runs_root else resolve_runs_root(cfg)

    app = FastAPI(title="vulnforge dashboard", version="0.1.0")
    app.state.runs_root = root.resolve()
    app.state.project_root = PROJECT_ROOT
    app.state.config = cfg

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ---------- pages ----------

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        # Starlette 0.40+: TemplateResponse(request, name, context=...)
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {"runs_root": str(app.state.runs_root)},
        )

    @app.get("/runs/{target_id}/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, target_id: str, run_id: str):
        try:
            store.resolve_run(app.state.runs_root, target_id, run_id)
        except FileNotFoundError:
            raise HTTPException(404, "run not found")
        return TEMPLATES.TemplateResponse(
            request,
            "run.html",
            {
                "target_id": target_id,
                "run_id": run_id,
                "runs_root": str(app.state.runs_root),
            },
        )

    @app.get("/tool-gaps", response_class=HTMLResponse)
    def tool_gaps_page(request: Request):
        """Dedicated AI tool-gaps roadmap page (opened from Home)."""
        return TEMPLATES.TemplateResponse(
            request,
            "tool_gaps.html",
            {"runs_root": str(app.state.runs_root)},
        )

    @app.get("/dev", response_class=HTMLResponse)
    def dev_page(request: Request):
        """Dev dashboard: hunt profile collection editor (opened from Home)."""
        return TEMPLATES.TemplateResponse(
            request,
            "dev.html",
            {"runs_root": str(app.state.runs_root)},
        )

    @app.get("/chat", response_class=HTMLResponse)
    def chat_page(request: Request):
        """Home AI operator chat (fleet co-pilot)."""
        return TEMPLATES.TemplateResponse(
            request,
            "chat.html",
            {"runs_root": str(app.state.runs_root)},
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        """Dedicated LLM / stage-model / multi-validate settings page."""
        return TEMPLATES.TemplateResponse(
            request,
            "settings.html",
            {"runs_root": str(app.state.runs_root)},
        )

    @app.get("/benchmarks", response_class=HTMLResponse)
    def benchmarks_root(request: Request):
        """Bench desk hub — redirect to Run so /benchmarks lands on a page."""
        return RedirectResponse(url="/benchmarks/run", status_code=307)

    @app.get("/benchmarks/run", response_class=HTMLResponse)
    def benchmarks_run_page(request: Request):
        """Bench desk: Run (stub)."""
        return TEMPLATES.TemplateResponse(
            request,
            "benchmarks.html",
            {"runs_root": str(app.state.runs_root), "active": "run"},
        )

    @app.get("/benchmarks/poc", response_class=HTMLResponse)
    def benchmarks_poc_page(request: Request):
        """Bench desk: POC workshop (stub)."""
        return TEMPLATES.TemplateResponse(
            request,
            "benchmarks.html",
            {"runs_root": str(app.state.runs_root), "active": "poc"},
        )

    @app.get("/benchmarks/results", response_class=HTMLResponse)
    def benchmarks_results_page(request: Request):
        """Bench desk: Results (stub)."""
        return TEMPLATES.TemplateResponse(
            request,
            "benchmarks.html",
            {"runs_root": str(app.state.runs_root), "active": "results"},
        )

    @app.get("/benchmarks/library", response_class=HTMLResponse)
    def benchmarks_library_page(request: Request):
        """Bench desk: Library (stub)."""
        return TEMPLATES.TemplateResponse(
            request,
            "benchmarks.html",
            {"runs_root": str(app.state.runs_root), "active": "library"},
        )

    # ---------- API: operator AI chat ----------

    @app.get("/api/chat/sessions")
    def api_chat_sessions_home():
        from vulnforge.operator_chat import list_sessions as oc_list

        return {
            "sessions": oc_list(
                "home",
                project_root=Path(app.state.project_root),
            )
        }

    @app.get("/api/chat/sessions/{session_id}")
    def api_chat_session_home(session_id: str):
        from vulnforge.operator_chat import load_session as oc_load

        data = oc_load(
            "home",
            session_id,
            project_root=Path(app.state.project_root),
        )
        if not data:
            raise HTTPException(404, "session not found")
        return data

    @app.delete("/api/chat/sessions/{session_id}")
    def api_chat_session_home_delete(session_id: str):
        from vulnforge.operator_chat import delete_session as oc_del

        ok = oc_del(
            "home",
            session_id,
            project_root=Path(app.state.project_root),
        )
        if not ok:
            raise HTTPException(404, "session not found")
        return {"ok": True}

    @app.post("/api/chat")
    def api_chat_home(body: ChatTurnBody):
        from vulnforge.operator_chat import handle_turn

        cfg = load_config()
        r = handle_turn(
            scope="home",
            message=body.message,
            session_id=body.session_id,
            project_root=Path(app.state.project_root),
            runs_root=Path(app.state.runs_root),
            cfg=cfg,
        )
        if not r.get("ok") and r.get("error") == "empty message":
            raise HTTPException(400, r["error"])
        return r

    @app.post("/api/chat/confirm")
    def api_chat_home_confirm(body: ChatConfirmBody):
        from vulnforge.operator_chat import confirm_pending

        cfg = load_config()
        r = confirm_pending(
            token=body.token,
            session_id=body.session_id,
            scope="home",
            project_root=Path(app.state.project_root),
            runs_root=Path(app.state.runs_root),
            cfg=cfg,
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "confirm failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/chat/sessions")
    def api_chat_sessions_run(target_id: str, run_id: str):
        from vulnforge.operator_chat import list_sessions as oc_list

        run = _get_run(target_id, run_id)
        return {
            "sessions": oc_list(
                "run",
                project_root=Path(app.state.project_root),
                run_dir=run.path,
            )
        }

    @app.get("/api/runs/{target_id}/{run_id}/chat/sessions/{session_id}")
    def api_chat_session_run(target_id: str, run_id: str, session_id: str):
        from vulnforge.operator_chat import load_session as oc_load

        run = _get_run(target_id, run_id)
        data = oc_load(
            "run",
            session_id,
            project_root=Path(app.state.project_root),
            run_dir=run.path,
        )
        if not data:
            raise HTTPException(404, "session not found")
        return data

    @app.delete("/api/runs/{target_id}/{run_id}/chat/sessions/{session_id}")
    def api_chat_session_run_delete(target_id: str, run_id: str, session_id: str):
        from vulnforge.operator_chat import delete_session as oc_del

        run = _get_run(target_id, run_id)
        ok = oc_del(
            "run",
            session_id,
            project_root=Path(app.state.project_root),
            run_dir=run.path,
        )
        if not ok:
            raise HTTPException(404, "session not found")
        return {"ok": True}

    @app.post("/api/runs/{target_id}/{run_id}/chat")
    def api_chat_run(target_id: str, run_id: str, body: ChatTurnBody):
        from vulnforge.operator_chat import handle_turn

        run = _get_run(target_id, run_id)
        cfg = load_config()
        r = handle_turn(
            scope="run",
            message=body.message,
            session_id=body.session_id,
            project_root=Path(app.state.project_root),
            runs_root=Path(app.state.runs_root),
            cfg=cfg,
            run=run,
        )
        if not r.get("ok") and r.get("error") == "empty message":
            raise HTTPException(400, r["error"])
        return r

    @app.post("/api/runs/{target_id}/{run_id}/chat/confirm")
    def api_chat_run_confirm(target_id: str, run_id: str, body: ChatConfirmBody):
        from vulnforge.operator_chat import confirm_pending

        run = _get_run(target_id, run_id)
        cfg = load_config()
        r = confirm_pending(
            token=body.token,
            session_id=body.session_id,
            scope="run",
            project_root=Path(app.state.project_root),
            runs_root=Path(app.state.runs_root),
            cfg=cfg,
            run=run,
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "confirm failed")
        return r

    # ---------- API: inventory ----------

    @app.get("/api/health")
    def health():
        return {
            "ok": True,
            "runs_root": str(app.state.runs_root),
            "project_root": str(app.state.project_root),
        }

    @app.get("/api/fs/browse")
    def api_fs_browse(
        path: str = Query(""),
        mode: str = Query("dirs", description="dirs | any"),
    ):
        """Host filesystem browser for New audit path pickers (local operator UI)."""
        r = dashops.browse_host_fs(path, mode=mode)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "browse failed")
        return r

    @app.get("/favicon.ico")
    def favicon():
        ico = STATIC_DIR / "favicon.ico"
        if ico.is_file():
            return FileResponse(ico, media_type="image/x-icon")
        png = STATIC_DIR / "logo.png"
        if png.is_file():
            return FileResponse(png, media_type="image/png")
        return Response(status_code=204)

    @app.get("/api/runs")
    def api_list_runs():
        refs = store.discover_runs(app.state.runs_root)
        cards = []
        for r in refs:
            try:
                card = store.run_card(r)
                cards.append(with_runner_flags(card, r.path, cfg=app.state.config))
            except Exception as e:
                cards.append(
                    {
                        "key": r.key,
                        "target_id": r.target_id,
                        "run_id": r.run_id,
                        "path": str(r.path),
                        "error": str(e),
                    }
                )
        return {"runs": cards, "count": len(cards)}

    # ---------- API: async init (MUST be registered before /api/runs/{target_id}/...) ----------
    # Otherwise GET /api/runs/init-jobs/{id} matches target_id="init-jobs" → "run not found".

    @app.get("/api/runs/init-jobs/{job_id}")
    def api_init_job_status(job_id: str):
        """Poll async init progress (inventory of large trees)."""
        from vulnforge.init_progress import read_job

        job = read_job(Path(app.state.project_root), job_id)
        if not job:
            raise HTTPException(404, f"unknown init job: {job_id}")
        return job

    @app.post("/api/runs/init")
    def api_init(body: InitBody, background: bool = Query(True)):
        """Create a new run (vf init) and optionally start Ralph.

        By default runs in a background thread so the UI can poll
        ``GET /api/runs/init-jobs/{job_id}`` for inventory status on large trees.
        Pass ``?background=false`` for a blocking init (tests / simple clients).
        """
        from vulnforge.cli import cmd_init
        from vulnforge.init_progress import (
            make_progress_writer,
            new_job_id,
            write_job,
        )

        class Args:
            pass

        from vulnforge.util import is_pe_file

        args = Args()
        args.target = Path(body.target)
        profile_raw = (body.profile or "").strip() or None
        args.profile = profile_raw
        args.runs_root = app.state.runs_root
        args.strategy = (body.strategy or "discovery").strip().lower()
        args.docs_path = Path(body.docs_path) if body.docs_path else None
        agents = [
            str(a).strip().lower()
            for a in (body.agent_ids or [])
            if str(a).strip()
        ][:32]
        args.agent_ids = agents or None
        args.operator_notes = (body.operator_notes or "").strip()[:6000]
        args.dynamic_skills = bool(body.dynamic_skills)
        try:
            args.dynamic_skill_count = int(body.dynamic_skill_count or 3)
        except (TypeError, ValueError):
            args.dynamic_skill_count = 3
        from vulnforge.hunt_profiles.generate import clamp_skill_count

        args.dynamic_skill_count = clamp_skill_count(args.dynamic_skill_count)
        mode = str(body.hunt_skill_mode or "all_active").strip().lower().replace("-", "_")
        if mode not in ("all_active", "seed_active", "custom_only", "explicit"):
            mode = "all_active"
        args.hunt_skill_mode = mode
        skill_ids = [
            str(x).strip().lower()
            for x in (body.hunt_skill_ids or [])
            if str(x).strip()
        ][:64]
        args.hunt_skill_ids = skill_ids or None
        args.enqueue_hunts = bool(body.enqueue_hunts)

        profile_n = (args.profile or "code_static").strip().lower()
        if not args.target.exists():
            raise HTTPException(400, f"target not found: {body.target}")
        if is_pe_file(args.target):
            raise HTTPException(
                400,
                f"PE binaries are not supported (source analysis only): {body.target}",
            )
        if not args.target.is_dir() and not args.target.is_file():
            raise HTTPException(
                400,
                f"target must be a directory or a single file: {body.target}",
            )
        if args.strategy == "recon_docs" and args.docs_path is None:
            raise HTTPException(400, "recon_docs strategy requires docs_path")
        if args.strategy == "recon_docs" and not args.docs_path.exists():
            raise HTTPException(400, f"docs_path not found: {body.docs_path}")

        project_root = Path(app.state.project_root)
        job_id = new_job_id()
        write_job(
            project_root,
            job_id,
            {
                "status": "running",
                "phase": "queued",
                "message": "Starting init...",
                "percent": 0,
                "target": str(args.target),
                "strategy": args.strategy,
            },
        )

        def _run_init() -> dict[str, Any]:
            import io
            from contextlib import redirect_stdout

            progress = make_progress_writer(project_root, job_id, also_print=False)
            args.progress = progress
            args.job_id = job_id
            buf = io.StringIO()
            try:
                with redirect_stdout(buf):
                    code = cmd_init(args, app.state.config)
                if code != 0:
                    progress(
                        {
                            "status": "error",
                            "phase": "failed",
                            "message": f"init failed exit={code}: {buf.getvalue()}",
                            "error": buf.getvalue() or f"exit={code}",
                            "percent": 100,
                        }
                    )
                    return {"ok": False, "code": code, "error": buf.getvalue()}
                lines = [ln.strip() for ln in buf.getvalue().splitlines() if ln.strip()]
                run_dir_s = lines[-1] if lines else ""
                run_dir = Path(run_dir_s)
                run_id = run_dir.name
                target_id = run_dir.parent.name
                result: dict[str, Any] = {
                    "ok": True,
                    "run_dir": str(run_dir),
                    "target_id": target_id,
                    "run_id": run_id,
                    "key": f"{target_id}/{run_id}",
                    "job_id": job_id,
                }
                if body.start:
                    progress(
                        {
                            "status": "running",
                            "phase": "ralph",
                            "message": "Starting Ralph agents…",
                            "percent": 95,
                            "run_dir": result["run_dir"],
                            "key": result["key"],
                            "target_id": target_id,
                            "run_id": run_id,
                        }
                    )
                    try:
                        started = runctl.start_run(
                            run_dir,
                            **control_start_kwargs(
                                ControlBody(
                                    max_tasks=body.max_tasks,
                                    task_timeout=body.task_timeout,
                                ),
                                load_ui_settings(),
                            ),
                        )
                        result["started"] = started
                        n_workers = int((started or {}).get("workers") or 1)
                        progress(
                            {
                                "status": "running",
                                "phase": "ralph",
                                "message": (
                                    f"Ralph started ({n_workers} agent"
                                    f"{'s' if n_workers != 1 else ''})"
                                ),
                                "percent": 98,
                            }
                        )
                    except Exception as e:
                        result["start_error"] = str(e)
                progress(
                    {
                        "status": "done",
                        "phase": "done",
                        "message": f"Run ready: {result['key']}",
                        "percent": 100,
                        "run_dir": result["run_dir"],
                        "key": result["key"],
                        "target_id": target_id,
                        "run_id": run_id,
                    }
                )
                return result
            except Exception as e:
                progress(
                    {
                        "status": "error",
                        "phase": "failed",
                        "message": str(e),
                        "error": str(e),
                        "percent": 100,
                    }
                )
                return {"ok": False, "error": str(e)}

        if background:
            import threading

            threading.Thread(target=_run_init, name=f"init-{job_id}", daemon=True).start()
            return {
                "ok": True,
                "async": True,
                "job_id": job_id,
                "status_url": f"/api/runs/init-jobs/{job_id}",
            }

        # Blocking path (tests / simple clients)
        result = _run_init()
        if not result.get("ok"):
            status = 400 if result.get("code") == 30 else 500
            raise HTTPException(status, result.get("error") or "init failed")
        return result

    def _get_run(target_id: str, run_id: str) -> store.RunRef:
        try:
            return store.resolve_run(app.state.runs_root, target_id, run_id)
        except FileNotFoundError:
            raise HTTPException(404, "run not found")
        except PermissionError:
            raise HTTPException(400, "invalid run path")

    @app.get("/api/runs/{target_id}/{run_id}")
    def api_run_detail(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        snap = store.run_snapshot(run)
        return with_runner_flags(snap, run.path, cfg=app.state.config)

    @app.get("/api/runs/{target_id}/{run_id}/events")
    def api_events(
        target_id: str,
        run_id: str,
        after: int = Query(0, ge=0),
        limit: int = Query(500, ge=1, le=5000),
    ):
        run = _get_run(target_id, run_id)
        events, nxt = store.read_events(run, after=after, limit=limit)
        return {"events": events, "next": nxt}

    @app.get("/api/runs/{target_id}/{run_id}/project/{name}")
    def api_project_file(target_id: str, run_id: str, name: str):
        run = _get_run(target_id, run_id)
        try:
            text = store.read_project_file(run, name)
        except FileNotFoundError:
            raise HTTPException(404, "file not found")
        return {"name": Path(name).name, "content": text}

    @app.get("/api/runs/{target_id}/{run_id}/export")
    def api_export_findings(
        target_id: str,
        run_id: str,
        format: str = Query(
            "json",
            alias="format",
            description="One format or comma-separated list (multi → zip): json,md,csv,html,xlsx,docx",
        ),
        include_poc: bool = Query(
            False,
            description="Embed evidence pack / PoC file contents in the export",
        ),
        include_findings: bool = Query(True, description="Include findings table/detail"),
        include_architecture: bool = Query(
            False, description="Include recon architecture map"
        ),
        include_hunts: bool = Query(
            False, description="Include hunt coverage matrix + hunt task list"
        ),
        include_summary: bool = Query(
            False, description="Include campaign / task summary"
        ),
        include_codemap: bool = Query(
            False, description="Include mechanical codemap brief"
        ),
    ):
        """Download audit report for a run (json|md|csv|html|xlsx|docx; multi → zip)."""
        from vulnforge.db import Database
        from vulnforge.export_findings import (
            ExportOptions,
            export_bundle,
            export_filename,
        )

        run = _get_run(target_id, run_id)
        db_path = run.path / "harness.db"
        if not db_path.is_file():
            raise HTTPException(404, "harness.db not found")
        opts = ExportOptions(
            include_findings=bool(include_findings),
            include_architecture=bool(include_architecture),
            include_hunts=bool(include_hunts),
            include_summary=bool(include_summary),
            include_poc=bool(include_poc),
            include_codemap=bool(include_codemap),
        )
        db = Database.open(db_path)
        try:
            try:
                payload, ext, media = export_bundle(
                    format, run.path, db, options=opts
                )
            except ValueError as e:
                raise HTTPException(400, str(e)) from e
            except ImportError as e:
                raise HTTPException(501, str(e)) from e
        finally:
            db.close()
        filename = export_filename(
            target_id, run_id, ext, include_poc=include_poc
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
        return Response(content=payload, media_type=media, headers=headers)

    @app.get("/api/runs/{target_id}/{run_id}/evidence/{pack_id}/{relpath:path}")
    def api_evidence_file(target_id: str, run_id: str, pack_id: str, relpath: str):
        run = _get_run(target_id, run_id)
        try:
            text = store.read_evidence_file(run, pack_id, relpath)
        except (FileNotFoundError, PermissionError, ValueError) as e:
            raise HTTPException(400, str(e))
        return {"pack_id": pack_id, "relpath": relpath, "content": text}

    @app.get("/api/runs/{target_id}/{run_id}/tasks/{task_id}/transcript")
    def api_task_transcript(
        target_id: str,
        run_id: str,
        task_id: int,
        pass_key: Optional[str] = Query(None),
    ):
        run = _get_run(target_id, run_id)
        data = load_transcript(run.path, task_id, pass_key=pass_key)
        if not data:
            raise HTTPException(404, "no transcript for this task")
        passes = list_transcript_passes(run.path, task_id)
        if passes:
            data = dict(data)
            data["passes"] = passes
        return data

    @app.get("/api/runs/{target_id}/{run_id}/tasks/{task_id}/io")
    def api_task_io(
        target_id: str,
        run_id: str,
        task_id: int,
        pass_key: Optional[str] = Query(None),
    ):
        """Normalized step I/O for Harness builder / Tasks panel."""
        run = _get_run(target_id, run_id)
        task_row = None
        try:
            from vulnforge.db import Database

            db = Database(run.path / "harness.db")
            try:
                t = db.get_task(task_id)
                if t:
                    task_row = {
                        "id": t.id,
                        "kind": t.kind,
                        "state": t.state,
                        "payload": t.payload or {},
                        "result": t.result or {},
                        "attempt": t.attempt,
                        "priority": t.priority,
                    }
            finally:
                db.close()
        except Exception:
            task_row = None
        data = build_task_io(run.path, task_id, task=task_row, pass_key=pass_key)
        if not data:
            raise HTTPException(404, "no step I/O for this task")
        return data

    @app.get("/api/runs/{target_id}/{run_id}/tasks/{task_id}/usage")
    def api_task_usage(target_id: str, run_id: str, task_id: int):
        run = _get_run(target_id, run_id)
        return {"task_id": task_id, "events": load_usage_for_task(run.path, task_id)}

    @app.get("/api/runs/{target_id}/{run_id}/graph")
    def api_run_graph(target_id: str, run_id: str):
        """Live agent graph derived from tasks (+ recent events)."""
        run = _get_run(target_id, run_id)
        tasks: list[dict[str, Any]] = []
        try:
            from vulnforge.db import Database

            db = Database(run.path / "harness.db")
            try:
                for t in db.list_tasks(limit=2000):
                    tasks.append(
                        {
                            "id": t.id,
                            "kind": t.kind,
                            "state": t.state,
                            "payload": t.payload or {},
                            "result": t.result or {},
                        }
                    )
            finally:
                db.close()
        except Exception as e:
            raise HTTPException(500, f"graph failed: {e}") from e
        events: list[dict] = []
        try:
            ev_path = run.path / "events.jsonl"
            if ev_path.is_file():
                # Last ~500 lines for edge hints
                lines = ev_path.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[-500:]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict):
                        events.append(row)
        except OSError:
            pass
        graph = build_graph_snapshot(tasks, events=events)
        graph["runner"] = runctl.runner_status(run.path)
        return graph

    @app.post("/api/runs/{target_id}/{run_id}/tasks/{task_id}/priority")
    def api_task_priority(target_id: str, run_id: str, task_id: int, body: TaskPriorityBody):
        """Reorder a queued task: run_next | high | normal | low."""
        run = _get_run(target_id, run_id)
        r = dashops.set_task_priority_tier(run.path, task_id, body.tier)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "priority update failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/tasks/{task_id}/cancel")
    def api_task_cancel(
        target_id: str,
        run_id: str,
        task_id: int,
        body: TaskCancelBody = Body(default_factory=TaskCancelBody),
    ):
        """Remove a queued task from the queue (marks cancelled; not leased)."""
        run = _get_run(target_id, run_id)
        r = dashops.cancel_queued_task(
            run.path, task_id, reason=body.reason or "operator_cancel"
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "cancel failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/tasks/{task_id}/pause")
    def api_task_pause(
        target_id: str,
        run_id: str,
        task_id: int,
        body: TaskPauseBody = Body(default_factory=TaskPauseBody),
    ):
        """Pause a queued or leased task so the next queued can begin.

        Leased: frees the lease slot and stops the run-once worker. The paused
        task re-runs when resumed or when it is the last remaining work.
        """
        run = _get_run(target_id, run_id)
        r = dashops.pause_task(run.path, task_id, reason=body.reason or "operator_pause")
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "pause failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/tasks/{task_id}/resume")
    def api_task_resume(
        target_id: str,
        run_id: str,
        task_id: int,
        body: TaskResumeBody = Body(default_factory=TaskResumeBody),
    ):
        """Resume a paused task back to the queue (default priority: run next)."""
        run = _get_run(target_id, run_id)
        r = dashops.resume_paused_task(
            run.path,
            task_id,
            tier=body.tier or "run_next",
            reason=body.reason or "operator_resume",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "resume failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/tasks/{task_id}/halt")
    def api_task_halt(
        target_id: str,
        run_id: str,
        task_id: int,
        body: TaskHaltBody = Body(default_factory=TaskHaltBody),
    ):
        """Halt (terminal cancel) a queued, paused, or leased task."""
        run = _get_run(target_id, run_id)
        r = dashops.halt_task(run.path, task_id, reason=body.reason or "operator_halt")
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "halt failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/transcripts")
    def api_list_transcripts(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        return {"task_ids": list_transcript_ids(run.path)}

    # --- Harness: Ralph loop profiles ---
    @app.get("/api/loop-profiles")
    def api_loop_profiles_list():
        from vulnforge.loop_profiles import list_profiles

        return {"profiles": list_profiles()}

    @app.get("/api/loop-profiles/{profile_id}")
    def api_loop_profile_get(profile_id: str):
        from vulnforge.loop_profiles import load_profile

        p = load_profile(profile_id)
        if not p:
            raise HTTPException(404, "profile not found")
        return p

    @app.put("/api/loop-profiles/{profile_id}")
    def api_loop_profile_put(profile_id: str, body: dict[str, Any] = Body(...)):
        from vulnforge.loop_profiles import save_profile

        data = dict(body or {})
        data["id"] = profile_id
        try:
            return save_profile(data)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.delete("/api/loop-profiles/{profile_id}")
    def api_loop_profile_delete(profile_id: str):
        from vulnforge.loop_profiles import delete_profile

        try:
            ok = delete_profile(profile_id)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        if not ok:
            raise HTTPException(404, "profile not found")
        return {"ok": True, "id": profile_id}

    @app.get("/api/runs/{target_id}/{run_id}/tool-gaps")
    def api_tool_gaps_get(target_id: str, run_id: str, refresh: bool = Query(False)):
        """Return tool-gap analysis (cached tool_gaps.json unless refresh)."""
        from vulnforge.tool_gaps import load_or_analyze

        run = _get_run(target_id, run_id)
        try:
            return load_or_analyze(run.path, force=refresh, cfg=cfg)
        except Exception as e:
            raise HTTPException(500, f"tool-gaps failed: {e}") from e

    class ToolGapsBody(BaseModel):
        mode: Optional[str] = None  # mechanical | llm | hybrid

    @app.post("/api/runs/{target_id}/{run_id}/tool-gaps")
    def api_tool_gaps_post(
        target_id: str,
        run_id: str,
        body: Optional[ToolGapsBody] = None,
    ):
        """Re-run tool-gap analysis and write project projections."""
        from vulnforge.tool_gaps import analyze_run_mode, write_reports

        run = _get_run(target_id, run_id)
        mode = (body.mode if body else None) or (cfg.get("run") or {}).get("tool_gaps_mode") or "hybrid"
        try:
            analysis = analyze_run_mode(run.path, str(mode), cfg)
            paths = write_reports(run.path, analysis)
        except Exception as e:
            raise HTTPException(500, f"tool-gaps failed: {e}") from e
        return {"ok": True, "written": paths, **analysis}

    @app.get("/api/tool-gaps")
    def api_tool_gaps_home(
        analyze_missing: bool = Query(False),
        mode: Optional[str] = Query(None),
    ):
        """Cross-run tool-gap rollup for the Home page."""
        from vulnforge.tool_gaps import aggregate_tool_gaps

        runs_root = resolve_runs_root(cfg, None)
        m = mode or (cfg.get("run") or {}).get("tool_gaps_mode") or "hybrid"
        try:
            return aggregate_tool_gaps(
                runs_root,
                analyze_missing=analyze_missing,
                mode=str(m),
                cfg=cfg,
            )
        except Exception as e:
            raise HTTPException(500, f"tool-gaps aggregate failed: {e}") from e

    class ToolGapsHomeBody(BaseModel):
        mode: Optional[str] = "hybrid"
        all_runs: bool = True
        target_id: Optional[str] = None
        run_id: Optional[str] = None

    @app.post("/api/tool-gaps/analyze")
    def api_tool_gaps_home_analyze(body: Optional[ToolGapsHomeBody] = None):
        """Analyze one or all runs (AI hybrid by default) and return Home rollup."""
        from vulnforge.tool_gaps import (
            aggregate_tool_gaps,
            analyze_run_mode,
            discover_run_dirs,
            write_reports,
        )

        body = body or ToolGapsHomeBody()
        runs_root = resolve_runs_root(cfg, None)
        mode = body.mode or (cfg.get("run") or {}).get("tool_gaps_mode") or "hybrid"
        written: list[str] = []
        errors: list[dict[str, str]] = []

        if body.target_id and body.run_id:
            run = _get_run(body.target_id, body.run_id)
            try:
                analysis = analyze_run_mode(run.path, str(mode), cfg)
                written.extend(write_reports(run.path, analysis))
            except Exception as e:
                raise HTTPException(500, f"tool-gaps failed: {e}") from e
        else:
            for rd in discover_run_dirs(runs_root):
                try:
                    analysis = analyze_run_mode(rd, str(mode), cfg)
                    written.extend(write_reports(rd, analysis))
                except Exception as e:
                    errors.append({"run_dir": str(rd), "error": str(e)[:200]})

        rollup = aggregate_tool_gaps(runs_root, analyze_missing=False, mode=str(mode), cfg=cfg)
        return {
            "ok": True,
            "mode": mode,
            "written_count": len(written),
            "errors": errors,
            **rollup,
        }

    # ---------- API: coverage ops / target browse / selection hunt ----------

    @app.get("/api/runs/{target_id}/{run_id}/coverage/cell")
    def api_coverage_cell(
        target_id: str,
        run_id: str,
        area: str = Query(...),
        attack_class: str = Query(..., alias="class"),
    ):
        run = _get_run(target_id, run_id)
        return dashops.cell_detail(run.path, area, attack_class)

    @app.post("/api/runs/{target_id}/{run_id}/coverage/requeue")
    def api_coverage_requeue(target_id: str, run_id: str, body: CoverageRequeueBody):
        run = _get_run(target_id, run_id)
        r = dashops.requeue_hunt(
            run.path,
            area=body.area,
            attack_class=body.attack_class,
            path_hints=body.path_hints,
            force_depth=body.force_depth,
            reason=body.reason,
            operator_notes=body.operator_notes or "",
            seed_sinks=list(body.seed_sinks or []) if body.seed_sinks else None,
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "requeue failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/coverage/requeue-bulk")
    def api_coverage_requeue_bulk(
        target_id: str, run_id: str, body: CoverageRequeueBulkBody
    ):
        run = _get_run(target_id, run_id)
        r = dashops.requeue_hunt_bulk(
            run.path,
            cells=list(body.cells or []),
            force_depth=body.force_depth,
            reason=body.reason,
            operator_notes=body.operator_notes or "",
        )
        if not r.get("ok") and not r.get("enqueued"):
            raise HTTPException(400, r.get("error") or "bulk requeue failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/recon/rerun")
    def api_recon_rerun(target_id: str, run_id: str, body: ReconRerunBody):
        run = _get_run(target_id, run_id)
        r = dashops.requeue_recon(
            run.path,
            operator_notes=body.operator_notes or "",
            focus_paths=body.focus_paths,
            include_prior_architecture=body.include_prior_architecture,
            enqueue_hunts=body.enqueue_hunts,
            reason=body.reason,
            agent_ids=body.agent_ids,
            hunt_skill_mode=body.hunt_skill_mode,
            hunt_skill_ids=body.hunt_skill_ids,
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "recon requeue failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/architecture")
    def api_architecture_get(target_id: str, run_id: str):
        """Current architecture map (DB only; not under project/)."""
        from vulnforge.db import Database

        run = _get_run(target_id, run_id)
        db = Database.open(run.path / "harness.db")
        try:
            arch = db.get_architecture()
            return {
                "architecture": arch,
                "has_architecture": bool(arch),
            }
        finally:
            db.close()

    @app.get("/api/runs/{target_id}/{run_id}/architecture/history")
    def api_architecture_history(
        target_id: str,
        run_id: str,
        limit: int = Query(50, ge=1, le=50),
    ):
        from vulnforge.db import Database

        run = _get_run(target_id, run_id)
        db = Database.open(run.path / "harness.db")
        try:
            revs = db.list_architecture_revisions(limit=limit)
            return {"revisions": revs, "count": len(revs)}
        finally:
            db.close()

    @app.get("/api/runs/{target_id}/{run_id}/architecture/history/{rev_id}")
    def api_architecture_revision_get(target_id: str, run_id: str, rev_id: int):
        from vulnforge.db import Database

        run = _get_run(target_id, run_id)
        db = Database.open(run.path / "harness.db")
        try:
            rev = db.get_architecture_revision(rev_id)
            if not rev:
                raise HTTPException(404, "revision not found")
            return rev
        finally:
            db.close()

    @app.post("/api/runs/{target_id}/{run_id}/architecture/restore/{rev_id}")
    def api_architecture_restore(
        target_id: str,
        run_id: str,
        rev_id: int,
        body: ArchitectureRestoreBody = ArchitectureRestoreBody(),
    ):
        from vulnforge.db import Database
        from vulnforge.util import append_event

        run = _get_run(target_id, run_id)
        note = body.note or ""
        db = Database.open(run.path / "harness.db")
        try:
            snap = db.restore_architecture_revision(rev_id, note=note)
            if snap is None:
                raise HTTPException(404, "revision not found or empty")
            comps = snap.get("components") if isinstance(snap, dict) else None
            n_comps = len(comps) if isinstance(comps, list) else 0
            append_event(
                run.path,
                {
                    "event": "architecture_updated",
                    "source": "restore",
                    "rev_id": rev_id,
                    "components": n_comps,
                },
            )
            return {
                "ok": True,
                "restored_id": rev_id,
                "architecture": snap,
            }
        finally:
            db.close()

    @app.put("/api/runs/{target_id}/{run_id}/architecture")
    def api_architecture_put(target_id: str, run_id: str, body: ArchitectureEditBody):
        """Manual architecture edit — validates basic structure, DB only."""
        from vulnforge.db import Database
        from vulnforge.util import append_event

        run = _get_run(target_id, run_id)
        arch = body.architecture
        err = _validate_architecture_body(arch)
        if err:
            raise HTTPException(400, err)
        db = Database.open(run.path / "harness.db")
        try:
            # Overlay operator fields onto existing so inventory / batch markers stay.
            existing = db.get_architecture() or {}
            merged = dict(existing)
            for key, val in arch.items():
                merged[key] = val
            # Never silently drop multi-agent batch finalize markers.
            if (
                "recon_batch_finalize" not in arch
                and isinstance(existing.get("recon_batch_finalize"), dict)
            ):
                merged["recon_batch_finalize"] = existing["recon_batch_finalize"]
            # Normalize list fields that were omitted as empty only when present
            for list_key in (
                "components",
                "trust_boundaries",
                "input_surfaces",
                "hunt_focus",
            ):
                if list_key in merged and merged[list_key] is None:
                    merged[list_key] = []
            if "summary" not in merged:
                merged["summary"] = str(existing.get("summary") or "")
            db.set_architecture(
                merged,
                source="manual",
                note=str(body.note or "")[:2000],
            )
            out_arch = db.get_architecture() or {}
            comps = out_arch.get("components") if isinstance(out_arch, dict) else None
            n_comps = len(comps) if isinstance(comps, list) else 0
            append_event(
                run.path,
                {
                    "event": "architecture_updated",
                    "source": "manual",
                    "components": n_comps,
                },
            )
            return {"ok": True, "architecture": out_arch}
        finally:
            db.close()

    @app.get("/api/runs/{target_id}/{run_id}/codemap")
    def api_codemap_get(
        target_id: str,
        run_id: str,
        include_symbols: bool = False,
        path: str = "",
        max_symbols: int = 200,
    ):
        """Mechanical/merged codemap (DB only; separate from architecture).

        Default omits full files/symbols arrays (counts remain in summary).
        Pass include_symbols=1 or path= to retrieve a symbol subset.
        """
        from vulnforge.db import Database
        from vulnforge.tools.codemap import (
            codemap_summary_for_ui,
            merge_annotations_into_codemap,
            slim_codemap_for_ui,
        )

        run = _get_run(target_id, run_id)
        db = Database.open(run.path / "harness.db")
        try:
            codemap = db.get_codemap()
            if isinstance(codemap, dict):
                notes = db.list_notes(kind="codemap")
                codemap = merge_annotations_into_codemap(codemap, notes)
            summary = codemap_summary_for_ui(
                codemap if isinstance(codemap, dict) else None
            )
            try:
                max_sym = max(1, min(5000, int(max_symbols)))
            except (TypeError, ValueError):
                max_sym = 200
            view = slim_codemap_for_ui(
                codemap if isinstance(codemap, dict) else None,
                include_symbols=bool(include_symbols),
                path=str(path or ""),
                max_symbols=max_sym,
            )
            return {
                "codemap": view,
                "summary": summary,
                "has_codemap": bool(
                    summary.get("has_codemap") if isinstance(summary, dict) else view
                ),
            }
        finally:
            db.close()

    @app.post("/api/runs/{target_id}/{run_id}/codemap/rebuild")
    def api_codemap_rebuild(target_id: str, run_id: str):
        """Rebuild mechanical codemap from target path; does not touch architecture."""
        from pathlib import Path as _Path

        from vulnforge.db import Database
        from vulnforge.tools.codemap import (
            build_codemap,
            codemap_summary_for_ui,
            merge_annotations_into_codemap,
        )

        run = _get_run(target_id, run_id)
        db = Database.open(run.path / "harness.db")
        try:
            row = db.get_run()
            if not row:
                raise HTTPException(404, "run row missing")
            target_path = row["target_path"] if "target_path" in row.keys() else None
            if not target_path:
                raise HTTPException(400, "run has no target_path")
            target = _Path(str(target_path))
            if not target.exists():
                raise HTTPException(400, f"target path does not exist: {target_path}")
            cfg = dashops.get_run_config(db) or {}
            ignore = list((cfg.get("run") or {}).get("ignore_globs") or [])
            # Preserve agent annotations across mechanical rebuild when possible.
            prior_notes = db.list_notes(kind="codemap")
            codemap = build_codemap(target, cfg=cfg, ignore_globs=ignore)
            if prior_notes:
                codemap = merge_annotations_into_codemap(codemap, prior_notes)
            db.set_codemap(codemap, source=str(codemap.get("source") or "mechanical"))
            stored = db.get_codemap()
            summary = codemap_summary_for_ui(stored)
            from vulnforge.tools.codemap import slim_codemap_for_ui

            # Response omits bulk symbols; full map is in DB.
            view = slim_codemap_for_ui(stored, include_symbols=False)
            return {
                "ok": True,
                "codemap": view,
                "summary": summary,
                "has_codemap": bool(
                    summary.get("has_codemap") if isinstance(summary, dict) else view
                ),
            }
        finally:
            db.close()

    @app.get("/api/runs/{target_id}/{run_id}/coverage/policy")
    def api_coverage_policy_get(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        from vulnforge.db import Database

        db = Database.open(run.path / "harness.db")
        try:
            cfg = dashops.get_run_config(db)
            return {"policy": dashops.coverage_policy_from_config(cfg)}
        finally:
            db.close()

    @app.post("/api/runs/{target_id}/{run_id}/coverage/mode")
    def api_coverage_mode(target_id: str, run_id: str, body: CoverageModeBody):
        run = _get_run(target_id, run_id)
        r = dashops.apply_coverage_mode(
            run.path,
            mode=body.mode,
            areas=body.areas,
            classes=body.classes,
            path_targets=body.path_targets,
            enqueue=body.enqueue,
            uncapped=bool(body.uncapped),
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "mode failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/coverage/generate-skill")
    def api_coverage_generate_skill(
        target_id: str, run_id: str, body: CoverageGenerateSkillBody
    ):
        """Queue Ralph generate_skill from Coverage (brief + optional paths)."""
        run = _get_run(target_id, run_id)
        r = dashops.coverage_generate_skill(
            run.path,
            brief=body.brief or "",
            suggested_id=body.suggested_id or "",
            activate=bool(body.activate),
            enqueue_hunts=bool(body.enqueue_hunts),
            areas=body.areas,
            path_targets=body.path_targets,
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "generate-skill failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/target/list")
    def api_target_list(
        target_id: str,
        run_id: str,
        path: str = Query("."),
        max_entries: int = Query(500, ge=1, le=2000),
    ):
        run = _get_run(target_id, run_id)
        r = dashops.target_list(run.path, path=path, max_entries=max_entries)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "list failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/target/read")
    def api_target_read(
        target_id: str,
        run_id: str,
        path: str = Query(...),
        start_line: Optional[int] = Query(None),
        end_line: Optional[int] = Query(None),
    ):
        run = _get_run(target_id, run_id)
        r = dashops.target_read(
            run.path, path=path, start_line=start_line, end_line=end_line
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "read failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/hunts/from-selection")
    def api_hunt_from_selection(target_id: str, run_id: str, body: SelectionHuntBody):
        run = _get_run(target_id, run_id)
        r = dashops.hunt_from_selection(
            run.path,
            path=body.path,
            start_line=body.start_line,
            end_line=body.end_line,
            attack_class=body.attack_class,
            area=body.area,
            note=body.note,
            operator_notes=body.operator_notes or body.note or "",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "enqueue failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/findings/{finding_id}/review")
    def api_finding_review(
        target_id: str, run_id: str, finding_id: int, body: FindingReviewBody
    ):
        """Human confirm / reject / reclassify a finding; optional notes → evidence pack."""
        run = _get_run(target_id, run_id)
        r = dashops.review_finding(
            run.path,
            finding_id,
            action=body.action,
            notes=body.notes or "",
            write_note_to_evidence=body.write_note_to_evidence,
            operator=body.operator or "operator",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "review failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/findings/{finding_id}/poc")
    def api_finding_poc_get(target_id: str, run_id: str, finding_id: int):
        """Load current PoC draft or scaffold (no write)."""
        run = _get_run(target_id, run_id)
        r = dashops.get_finding_poc(run.path, finding_id)
        if not r.get("ok"):
            raise HTTPException(404 if r.get("error") == "finding_not_found" else 400, r.get("error") or "poc load failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/findings/{finding_id}/poc")
    def api_finding_poc_save(
        target_id: str, run_id: str, finding_id: int, body: FindingPocBody
    ):
        """Save PoC draft under evidence pack; optional develop_poc enqueue."""
        run = _get_run(target_id, run_id)
        r = dashops.save_finding_poc(
            run.path,
            finding_id,
            content=body.content,
            enqueue_agent=bool(body.enqueue_agent),
            operator_notes=body.operator_notes or "",
            operator=body.operator or "operator",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "poc save failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/findings/{finding_id}/validate-poc")
    def api_finding_validate_poc(
        target_id: str, run_id: str, finding_id: int, body: FindingValidatePocBody
    ):
        """Enqueue validate_poc harness task; never auto-confirms."""
        run = _get_run(target_id, run_id)
        r = dashops.enqueue_validate_poc(
            run.path,
            finding_id,
            operator=body.operator or "operator",
            operator_notes=body.operator_notes or "",
            target_url=body.target_url or "",
            referee=bool(body.referee),
            command=body.command or "",
        )
        if not r.get("ok"):
            raise HTTPException(
                404 if r.get("error") == "finding_not_found" else 400,
                r.get("error") or "validate-poc enqueue failed",
            )
        return r

    @app.post(
        "/api/runs/{target_id}/{run_id}/findings/{finding_id}/export-validation-job"
    )
    def api_finding_export_validation_job(
        target_id: str,
        run_id: str,
        finding_id: int,
        body: FindingExportValidationJobBody = FindingExportValidationJobBody(),
    ):
        """Export finding + pack as validation handoff bundle under run exports/."""
        run = _get_run(target_id, run_id)
        r = dashops.export_validation_job_op(
            run.path,
            finding_id,
            as_zip=bool(body.as_zip),
            include_citations=bool(body.include_citations),
        )
        if not r.get("ok"):
            raise HTTPException(
                404 if r.get("error") == "finding_not_found" else 400,
                r.get("error") or "export failed",
            )
        return r

    # ---------- Findings clusters / merge (PR-D) ----------

    @app.get("/api/runs/{target_id}/{run_id}/findings/clusters")
    def api_findings_clusters(target_id: str, run_id: str):
        """Overlap clusters (merge_key / path-only) for Report near-dup UI."""
        run = _get_run(target_id, run_id)
        return dashops.list_finding_clusters(run.path)

    @app.post("/api/runs/{target_id}/{run_id}/findings/merge")
    def api_findings_merge(target_id: str, run_id: str, body: FindingsMergeBody):
        """Supersede drop_ids into keep_id; never auto-confirm."""
        run = _get_run(target_id, run_id)
        r = dashops.merge_findings_op(
            run.path,
            int(body.keep_id),
            [int(x) for x in (body.drop_ids or [])],
            operator=body.operator or "operator",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "merge failed")
        return r

    # ---------- Attack chains (PR-E) ----------

    @app.get("/api/runs/{target_id}/{run_id}/chains")
    def api_chains_list(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        return dashops.list_chains_op(run.path)

    @app.post("/api/runs/{target_id}/{run_id}/chains")
    def api_chains_create(target_id: str, run_id: str, body: ChainBody):
        run = _get_run(target_id, run_id)
        payload = {
            "id": body.id,
            "title": body.title or "Attack chain",
            "include_states": body.include_states,
            "steps": [s.model_dump() if hasattr(s, "model_dump") else s.dict() for s in (body.steps or [])],
        }
        # Drop null id so save allocates uuid
        if not payload.get("id"):
            payload.pop("id", None)
        r = dashops.save_chain_op(run.path, payload)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "chain save failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/chains/from-findings")
    def api_chains_from_findings(target_id: str, run_id: str, body: ChainFromFindingsBody):
        run = _get_run(target_id, run_id)
        r = dashops.build_chain_from_findings_op(
            run.path,
            finding_ids=body.finding_ids,
            include_states=body.include_states or ["confirmed"],
            title=body.title or "",
            enqueue_poc=bool(body.enqueue_poc),
            operator=body.operator or "operator",
        )
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "chain build failed")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/chains/{chain_id}")
    def api_chains_get(target_id: str, run_id: str, chain_id: str):
        run = _get_run(target_id, run_id)
        r = dashops.get_chain_op(run.path, chain_id)
        if not r.get("ok"):
            raise HTTPException(404, r.get("error") or "chain not found")
        return r

    @app.put("/api/runs/{target_id}/{run_id}/chains/{chain_id}")
    def api_chains_put(target_id: str, run_id: str, chain_id: str, body: ChainBody):
        run = _get_run(target_id, run_id)
        payload = {
            "id": chain_id,
            "title": body.title or "Attack chain",
            "include_states": body.include_states,
            "steps": [s.model_dump() if hasattr(s, "model_dump") else s.dict() for s in (body.steps or [])],
        }
        r = dashops.save_chain_op(run.path, payload)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "chain save failed")
        return r

    @app.delete("/api/runs/{target_id}/{run_id}/chains/{chain_id}")
    def api_chains_delete(target_id: str, run_id: str, chain_id: str):
        run = _get_run(target_id, run_id)
        r = dashops.delete_chain_op(run.path, chain_id)
        if not r.get("ok"):
            raise HTTPException(404, r.get("error") or "chain not found")
        return r

    @app.get("/api/runs/{target_id}/{run_id}/chains/{chain_id}/export")
    def api_chains_export(target_id: str, run_id: str, chain_id: str):
        """Markdown export of an attack chain (honesty disclaimer included)."""
        run = _get_run(target_id, run_id)
        r = dashops.export_chain_markdown_op(run.path, chain_id)
        if not r.get("ok"):
            raise HTTPException(404, r.get("error") or "chain not found")
        return r

    # ---------- API: global LLM / agent settings ----------

    @app.get("/api/settings")
    def api_get_settings():
        from vulnforge.llm_models import (
            normalize_consensus,
            normalize_model_list,
            resolve_validate_models,
        )
        from vulnforge.settings import normalize_api_key

        ui = load_ui_settings()
        # effective config after merge
        eff = load_config()
        llm = eff.get("llm") or {}
        run = eff.get("run") or {}
        stages = eff.get("stages") or {}
        key = normalize_api_key(llm.get("api_key") if "api_key" in llm else ui.get("api_key"))
        vmodels = resolve_validate_models(eff)
        return {
            "settings": ui,
            "effective": {
                "base_url": llm.get("base_url"),
                "model": llm.get("model"),
                "model_recon": llm.get("model_recon") or "",
                "model_hunt": llm.get("model_hunt") or "",
                "model_develop_poc": llm.get("model_develop_poc") or "",
                "validate_models": vmodels,
                "validate_consensus": normalize_consensus(
                    llm.get("validate_consensus") or ui.get("validate_consensus")
                ),
                "validate_poc_referee": bool(
                    stages.get("validate_poc_referee", ui.get("validate_poc_referee", True))
                ),
                "validate_llm": bool(
                    stages.get("validate_llm", ui.get("validate_llm", True))
                ),
                "api_mode": llm.get("api_mode") or "chat_completions",
                # Do not echo secrets; only whether a key is configured.
                "api_key_set": bool(key),
                "context_tokens": llm.get("context_tokens"),
                "max_context_fraction": llm.get("max_context_fraction"),
                "max_tokens": llm.get("max_tokens"),
                "max_tool_rounds": llm.get("max_tool_rounds"),
                "max_leases_parallel": run.get("max_leases_parallel"),
                "max_tasks": run.get("max_tasks"),
            },
        }

    @app.put("/api/settings")
    def api_put_settings(body: SettingsBody):
        # Include api_key even when "" so operators can clear it (exclude_none alone
        # would drop None but keep ""; we still pass explicit clears).
        updates = body.model_dump(exclude_none=True)
        if "api_key" in body.model_fields_set:
            updates["api_key"] = body.api_key if body.api_key is not None else ""
        # Explicit bool clears (False is valid)
        for bkey in ("validate_poc_referee", "validate_llm"):
            if bkey in body.model_fields_set:
                updates[bkey] = bool(getattr(body, bkey))
        if "validate_models" in body.model_fields_set:
            updates["validate_models"] = body.validate_models or []
        if "model_recon" in body.model_fields_set:
            updates["model_recon"] = body.model_recon or ""
        if "model_hunt" in body.model_fields_set:
            updates["model_hunt"] = body.model_hunt or ""
        if "model_develop_poc" in body.model_fields_set:
            updates["model_develop_poc"] = body.model_develop_poc or ""
        saved = save_ui_settings(updates)
        # refresh app config for init paths in this process
        app.state.config = load_config()
        return {"ok": True, "settings": saved}

    @app.post("/api/settings/optimize")
    def api_optimize_settings(body: SettingsOptimizeBody = Body(default_factory=SettingsOptimizeBody)):
        """Probe the configured LLM and recommend (optionally apply) settings.

        Runs connectivity, model-id resolution, API surface checks, a tool-call
        compliance micro-probe, an empirical context-window test (unless
        ``test_context`` is false), and latency heuristics. Does not touch targets.
        """
        from vulnforge.settings_probe import optimize_ui_settings

        try:
            result = optimize_ui_settings(
                host=body.host,
                port=body.port,
                model=body.model,
                api_key=body.api_key,
                apply=bool(body.apply),
                test_context=True if body.test_context is None else bool(body.test_context),
            )
        except Exception as e:
            raise HTTPException(500, f"optimize failed: {e}") from e
        if result.get("applied"):
            app.state.config = load_config()
        return result

    # ---------- API: hunt profiles (Dev dashboard) ----------

    # ---------- API: full Dev setup pack (fresh-install transfer) ----------

    @app.get("/api/dev-setup/export")
    def api_dev_setup_export():
        from vulnforge.dev_setup import DevSetupError, export_dev_setup

        try:
            data = export_dev_setup()
            return JSONResponse(
                content=data,
                headers={
                    "Content-Disposition": 'attachment; filename="vulnforge_dev_setup.json"'
                },
            )
        except DevSetupError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(500, f"dev setup export failed: {e}") from e

    @app.post("/api/dev-setup/import")
    def api_dev_setup_import(body: DevSetupImportBody):
        from vulnforge.dev_setup import DevSetupError, import_dev_setup

        try:
            return import_dev_setup(
                body.data if isinstance(body.data, dict) else {},
                mode=body.mode or "merge",
                include=body.include,
            )
        except DevSetupError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(500, f"dev setup import failed: {e}") from e

    @app.get("/api/hunt-profiles")
    def api_hunt_profiles_list(include_body: bool = Query(False)):
        from vulnforge.hunt_profiles import HuntProfileError, catalog_for_ui, list_profiles

        try:
            profiles = list_profiles(include_body=include_body)
            return {
                "ok": True,
                "catalog": catalog_for_ui(),
                "profiles": profiles,
            }
        except HuntProfileError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(500, f"hunt profiles failed: {e}") from e

    @app.get("/api/hunt-profiles/export")
    def api_hunt_profiles_export():
        """Legacy: hunt-only export. Prefer GET /api/dev-setup/export for full setup."""
        from vulnforge.hunt_profiles import HuntProfileError, export_collection

        try:
            data = export_collection()
            return JSONResponse(
                content=data,
                headers={
                    "Content-Disposition": 'attachment; filename="hunt_collection.json"'
                },
            )
        except HuntProfileError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/hunt-profiles/import")
    def api_hunt_profiles_import(body: HuntImportBody):
        from vulnforge.hunt_profiles import HuntProfileError, import_collection

        try:
            result = import_collection(body.data, mode=body.mode or "merge")
            return result
        except HuntProfileError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/hunt-profiles/reseed")
    def api_hunt_profiles_reseed():
        from vulnforge.hunt_profiles import HuntProfileError, reseed_from_package

        try:
            return reseed_from_package(replace=True)
        except HuntProfileError as e:
            raise HTTPException(400, str(e)) from e

    class SkillGeneratorBody(BaseModel):
        body_md: str = ""

    @app.get("/api/skill-generator")
    def api_skill_generator_get():
        """Editable skill-generator system prompt (package seed or operator override)."""
        from vulnforge.hunt_profiles.author_prompt import get_author_prompt

        data = get_author_prompt()
        return {"ok": True, **data}

    @app.put("/api/skill-generator")
    def api_skill_generator_put(body: SkillGeneratorBody):
        from vulnforge.hunt_profiles.author_prompt import (
            AuthorPromptError,
            save_author_prompt,
        )

        try:
            data = save_author_prompt(body.body_md or "")
        except AuthorPromptError as e:
            raise HTTPException(400, str(e)) from e
        return {"ok": True, **data}

    @app.post("/api/skill-generator/reseed")
    def api_skill_generator_reseed():
        from vulnforge.hunt_profiles.author_prompt import (
            AuthorPromptError,
            reseed_author_prompt,
        )

        try:
            data = reseed_author_prompt()
        except AuthorPromptError as e:
            raise HTTPException(400, str(e)) from e
        return {"ok": True, **data}

    @app.post("/api/hunt-profiles/generate")
    def api_hunt_profiles_generate(body: HuntGenerateBody):
        """Author a custom hunt skill via LLM; optionally save to the collection."""
        from vulnforge.hunt_profiles.generate import (
            GenerateSkillError,
            generate_hunt_skill,
            save_generated_profile,
        )

        brief = (body.brief or "").strip()
        if not brief:
            raise HTTPException(400, "brief is required")
        cfg = getattr(app.state, "config", None) or load_config()
        try:
            skill = generate_hunt_skill(
                cfg,
                brief=brief,
                signals=body.signals,
                suggested_id=body.suggested_id,
            )
        except GenerateSkillError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(502, f"skill generation failed: {e}") from e

        profile = None
        if body.save:
            try:
                profile = save_generated_profile(skill, active=bool(body.activate))
            except Exception as e:
                raise HTTPException(400, f"save failed: {e}") from e

        return {
            "ok": True,
            "saved": bool(body.save and profile is not None),
            "skill": {
                "id": skill.get("id"),
                "title": skill.get("title"),
                "description": skill.get("description"),
                "body_md": skill.get("body_md"),
                "tags": skill.get("tags") or [],
                "cwe": skill.get("cwe") or [],
                "angle_ids": skill.get("angle_ids") or [],
                "sink_families": skill.get("sink_families") or [],
            },
            "profile": profile,
        }

    @app.get("/api/hunt-profiles/{profile_id}")
    def api_hunt_profile_get(profile_id: str):
        from vulnforge.hunt_profiles import HuntProfileError, get_profile

        try:
            return {"ok": True, "profile": get_profile(profile_id, include_body=True)}
        except HuntProfileError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/hunt-profiles")
    def api_hunt_profile_create(body: HuntProfileBody):
        from vulnforge.hunt_profiles import HuntProfileError, save_profile

        pid = (body.id or "").strip()
        if not pid:
            raise HTTPException(400, "id is required")
        try:
            profile = save_profile(
                pid,
                body_md=body.body_md,
                title=body.title,
                description=body.description,
                active=body.active if body.active is not None else False,
                tags=body.tags,
                languages=body.languages,
                cwe=body.cwe,
                angle_ids=body.angle_ids,
                sink_families=body.sink_families,
                specificity=body.specificity,
                version=body.version,
                tools=body.tools,
                clear_tools=bool(body.clear_tools),
                create=True,
            )
            return {"ok": True, "profile": profile}
        except HuntProfileError as e:
            raise HTTPException(400, str(e)) from e

    @app.put("/api/hunt-profiles/{profile_id}")
    def api_hunt_profile_update(profile_id: str, body: HuntProfileBody):
        from vulnforge.hunt_profiles import HuntProfileError, save_profile

        try:
            profile = save_profile(
                profile_id,
                body_md=body.body_md,
                title=body.title,
                description=body.description,
                active=body.active,
                tags=body.tags,
                languages=body.languages,
                cwe=body.cwe,
                angle_ids=body.angle_ids,
                sink_families=body.sink_families,
                specificity=body.specificity,
                version=body.version,
                tools=body.tools,
                clear_tools=bool(body.clear_tools),
                create=False,
            )
            return {"ok": True, "profile": profile}
        except HuntProfileError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    @app.delete("/api/hunt-profiles/{profile_id}")
    def api_hunt_profile_delete(profile_id: str):
        from vulnforge.hunt_profiles import HuntProfileError, delete_profile

        try:
            return delete_profile(profile_id)
        except HuntProfileError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    @app.post("/api/hunt-profiles/{profile_id}/restore-seed")
    def api_hunt_profile_restore_seed(profile_id: str):
        """Restore body from package seeds/hunt_classes/{id}.md; set source=seed."""
        from vulnforge.hunt_profiles import HuntProfileError, restore_seed_body

        try:
            profile = restore_seed_body(profile_id)
            return {"ok": True, "profile": profile}
        except HuntProfileError as e:
            msg = str(e)
            code = 404 if "unknown" in msg or "no package seed" in msg else 400
            raise HTTPException(code, msg) from e

    @app.get("/api/hunt-profiles/{profile_id}/seed-diff")
    def api_hunt_profile_seed_diff(profile_id: str):
        """Compare current body to package seed markdown."""
        from vulnforge.hunt_profiles import HuntProfileError, seed_diff

        try:
            return {"ok": True, **seed_diff(profile_id)}
        except HuntProfileError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    # ---------- API: recon agents (Dev dashboard) ----------

    @app.get("/api/recon-agents")
    def api_recon_agents_list(include_body: bool = Query(False)):
        from vulnforge.recon_agents import ReconAgentError, catalog_for_ui, list_agents

        try:
            agents = list_agents(include_body=include_body)
            return {
                "ok": True,
                "catalog": catalog_for_ui(),
                "agents": agents,
            }
        except ReconAgentError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(500, f"recon agents failed: {e}") from e

    @app.get("/api/recon-agents/export")
    def api_recon_agents_export():
        from vulnforge.recon_agents import ReconAgentError, export_collection

        try:
            data = export_collection()
            return JSONResponse(
                content=data,
                headers={
                    "Content-Disposition": 'attachment; filename="recon_collection.json"'
                },
            )
        except ReconAgentError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/recon-agents/import")
    def api_recon_agents_import(body: ReconAgentImportBody):
        from vulnforge.recon_agents import ReconAgentError, import_collection

        try:
            result = import_collection(body.data, mode=body.mode or "merge")
            return result
        except ReconAgentError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/recon-agents/reseed")
    def api_recon_agents_reseed():
        from vulnforge.recon_agents import ReconAgentError, reseed_from_package

        try:
            return reseed_from_package(replace=True)
        except ReconAgentError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/api/recon-agents/{agent_id}")
    def api_recon_agent_get(agent_id: str):
        from vulnforge.recon_agents import ReconAgentError, get_agent

        try:
            return {"ok": True, "agent": get_agent(agent_id, include_body=True)}
        except ReconAgentError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/recon-agents")
    def api_recon_agent_create(body: ReconAgentBody):
        from vulnforge.recon_agents import ReconAgentError, save_agent

        aid = (body.id or "").strip()
        if not aid:
            raise HTTPException(400, "id is required")
        try:
            agent = save_agent(
                aid,
                body_md=body.body_md,
                title=body.title,
                description=body.description,
                active=body.active if body.active is not None else False,
                order=body.order,
                mode=body.mode,
                tools=body.tools,
                temperature=body.temperature,
                max_tool_rounds=body.max_tool_rounds,
                output=body.output,
                create=True,
            )
            return {"ok": True, "agent": agent}
        except ReconAgentError as e:
            raise HTTPException(400, str(e)) from e

    @app.put("/api/recon-agents/{agent_id}")
    def api_recon_agent_update(agent_id: str, body: ReconAgentBody):
        from vulnforge.recon_agents import ReconAgentError, save_agent

        try:
            agent = save_agent(
                agent_id,
                body_md=body.body_md,
                title=body.title,
                description=body.description,
                active=body.active,
                order=body.order,
                mode=body.mode,
                tools=body.tools,
                temperature=body.temperature,
                max_tool_rounds=body.max_tool_rounds,
                output=body.output,
                create=False,
            )
            return {"ok": True, "agent": agent}
        except ReconAgentError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    @app.delete("/api/recon-agents/{agent_id}")
    def api_recon_agent_delete(agent_id: str):
        from vulnforge.recon_agents import ReconAgentError, delete_agent

        try:
            return delete_agent(agent_id)
        except ReconAgentError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    # ---------- API: tools catalog + tool drafts (Dev dashboard) ----------

    @app.get("/api/tools")
    def api_tools_list():
        from vulnforge.toolgen.catalog import list_tools

        tools = list_tools()
        return {"ok": True, "tools": tools, "count": len(tools)}

    @app.get("/api/tools/defaults")
    def api_tools_defaults_get():
        """Global default tools per stage (null = built-in packet surface)."""
        from vulnforge.tools.default_tools import defaults_for_api

        return defaults_for_api()

    @app.put("/api/tools/defaults")
    def api_tools_defaults_put(payload_body: ToolsDefaultsBody):
        """Save global default tools. Only catalog/profile-safe names; no shell.

        Omitted stages keep prior values. Explicit null (or clear_*) resets a stage
        to built-in defaults. A non-null list narrows that stage.
        """
        from vulnforge.tools.default_tools import (
            DefaultToolsError,
            load_default_tools,
            save_default_tools,
        )

        current = load_default_tools()
        payload: dict = dict(current)
        if hasattr(payload_body, "model_dump"):
            data = payload_body.model_dump(exclude_unset=True)
        else:
            data = payload_body.dict(exclude_unset=True)  # type: ignore[call-arg]
        for stage, clear_key in (
            ("recon", "clear_recon"),
            ("hunt", "clear_hunt"),
            ("develop_poc", "clear_develop_poc"),
        ):
            if data.get(clear_key):
                payload[stage] = None
            elif stage in data:
                # Explicit null → built-in; list → narrow
                payload[stage] = data[stage]
        try:
            saved = save_default_tools(payload)
        except DefaultToolsError as e:
            raise HTTPException(400, str(e)) from e
        from vulnforge.tools.default_tools import defaults_for_api

        out = defaults_for_api()
        out["defaults"] = saved
        return out

    @app.get("/api/tools/{name}")
    def api_tools_get(name: str):
        from vulnforge.toolgen.catalog import get_tool

        tool = get_tool(name)
        if not tool:
            raise HTTPException(404, f"unknown tool: {name}")
        return {"ok": True, "tool": tool}

    @app.get("/api/tool-drafts")
    def api_tool_drafts_list():
        from vulnforge.toolgen.store import ToolDraftError, list_drafts

        try:
            return {"ok": True, "drafts": list_drafts()}
        except ToolDraftError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/tool-drafts")
    def api_tool_drafts_create(body: ToolDraftCreateBody):
        from vulnforge.toolgen.store import ToolDraftError, create_draft

        try:
            draft = create_draft(
                brief=body.brief,
                suggested_id=body.suggested_id,
                source=body.source,
                source_gap=body.gap,
                stages=body.stages,
                risk_class=body.risk_class,
                prefer_extend=body.prefer_extend,
                title=body.title,
                description=body.description,
                slots=body.slots,
            )
            return {"ok": True, "draft": draft}
        except ToolDraftError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/tool-drafts/from-gap")
    def api_tool_drafts_from_gap(body: ToolDraftCreateBody):
        from vulnforge.toolgen.store import ToolDraftError, create_draft

        gap = body.gap if isinstance(body.gap, dict) else {}
        cap = str(
            (gap.get("tool_or_capability") if gap else None)
            or body.suggested_id
            or "new_tool"
        )
        brief = (body.brief or "").strip() or str(
            gap.get("suggestion") or f"Implement capability {cap} from tool-gap analysis."
        )
        try:
            draft = create_draft(
                brief=brief,
                suggested_id=body.suggested_id or cap,
                source="tool_gap",
                source_gap=gap or body.gap,
                stages=body.stages or ["hunt"],
                risk_class=body.risk_class or "read_only",
                prefer_extend=body.prefer_extend,
                title=body.title or cap,
                description=body.description or brief[:500],
                slots=body.slots,
            )
            return {"ok": True, "draft": draft}
        except ToolDraftError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/api/tool-drafts/{draft_id}")
    def api_tool_draft_get(draft_id: str):
        from vulnforge.toolgen.store import ToolDraftError, get_draft

        try:
            return {"ok": True, "draft": get_draft(draft_id)}
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e

    @app.put("/api/tool-drafts/{draft_id}")
    def api_tool_draft_update(draft_id: str, body: ToolDraftUpdateBody):
        from vulnforge.toolgen.store import ToolDraftError, update_draft

        meta_updates: dict[str, Any] = {}
        if body.title is not None:
            meta_updates["title"] = body.title
        if body.description is not None:
            meta_updates["description"] = body.description
        if body.stages is not None:
            meta_updates["stages"] = body.stages
        if body.risk_class is not None:
            meta_updates["risk_class"] = body.risk_class
        if body.prefer_extend is not None:
            meta_updates["prefer_extend"] = body.prefer_extend
        if body.operator_notes is not None:
            meta_updates["operator_notes"] = body.operator_notes
        try:
            draft = update_draft(
                draft_id,
                brief=body.brief,
                slots=body.slots,
                meta_updates=meta_updates or None,
                spec_md=body.spec_md,
                impl_py=body.impl_py,
                schema=body.tool_schema,
                wireup=body.wireup,
                handler_snippet=body.handler_snippet,
                test_stub=body.test_stub,
                status=body.status,
            )
            return {"ok": True, "draft": draft}
        except ToolDraftError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    @app.delete("/api/tool-drafts/{draft_id}")
    def api_tool_draft_delete(draft_id: str):
        from vulnforge.toolgen.store import ToolDraftError, delete_draft

        try:
            return delete_draft(draft_id)
        except ToolDraftError as e:
            msg = str(e)
            code = 404 if "unknown" in msg else 400
            raise HTTPException(code, msg) from e

    @app.post("/api/tool-drafts/{draft_id}/reject")
    def api_tool_draft_reject(draft_id: str, body: Optional[ToolRejectBody] = None):
        from vulnforge.toolgen.store import ToolDraftError, reject_draft

        try:
            return {
                "ok": True,
                "draft": reject_draft(draft_id, reason=(body.reason if body else "") or ""),
            }
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/tool-drafts/{draft_id}/prompts/preview")
    def api_tool_draft_prompts_preview(draft_id: str, body: Optional[ToolPromptPreviewBody] = None):
        from vulnforge.toolgen.generate import GenerateToolError, build_prompt_preview
        from vulnforge.toolgen.store import ToolDraftError

        stage = (body.stage if body else None) or "spec"
        use_ov = body.use_prompt_overrides if body else True
        try:
            prompts = build_prompt_preview(draft_id, stage, use_overrides=use_ov)
            return {"ok": True, **prompts}
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e
        except GenerateToolError as e:
            raise HTTPException(400, str(e)) from e

    @app.put("/api/tool-drafts/{draft_id}/prompts")
    def api_tool_draft_prompts_save(draft_id: str, body: ToolPromptOverrideBody):
        from vulnforge.toolgen.store import ToolDraftError, save_prompt_override

        try:
            save_prompt_override(draft_id, body.name, body.content)
            return {"ok": True}
        except ToolDraftError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/tool-drafts/{draft_id}/generate/spec")
    def api_tool_draft_generate_spec(draft_id: str, body: Optional[ToolGenerateBody] = None):
        from vulnforge.toolgen.generate import GenerateToolError, generate_spec
        from vulnforge.toolgen.store import ToolDraftError

        cfg = load_config()
        try:
            return generate_spec(
                cfg,
                draft_id,
                use_prompt_overrides=body.use_prompt_overrides if body else True,
            )
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e
        except GenerateToolError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(502, f"LLM generate failed: {e}") from e

    @app.post("/api/tool-drafts/{draft_id}/generate/impl")
    def api_tool_draft_generate_impl(draft_id: str, body: Optional[ToolGenerateBody] = None):
        from vulnforge.toolgen.generate import GenerateToolError, generate_impl
        from vulnforge.toolgen.store import ToolDraftError

        cfg = load_config()
        try:
            return generate_impl(
                cfg,
                draft_id,
                use_prompt_overrides=body.use_prompt_overrides if body else True,
            )
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e
        except GenerateToolError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(502, f"LLM generate failed: {e}") from e

    @app.post("/api/tool-drafts/{draft_id}/generate/fix")
    def api_tool_draft_generate_fix(draft_id: str, body: Optional[ToolGenerateBody] = None):
        from vulnforge.toolgen.generate import GenerateToolError, generate_fix
        from vulnforge.toolgen.store import ToolDraftError

        cfg = load_config()
        try:
            return generate_fix(
                cfg,
                draft_id,
                use_prompt_overrides=body.use_prompt_overrides if body else True,
            )
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e
        except GenerateToolError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            raise HTTPException(502, f"LLM generate failed: {e}") from e

    @app.post("/api/tool-drafts/{draft_id}/validate")
    def api_tool_draft_validate(
        draft_id: str,
        for_integrate: bool = Query(False),
    ):
        from vulnforge.toolgen.store import ToolDraftError, get_draft
        from vulnforge.toolgen.validate import validate_draft

        try:
            report = validate_draft(draft_id, for_integrate=for_integrate, persist=True)
            return {
                "ok": True,
                "validation": report,
                "draft": get_draft(draft_id, include_files=False),
            }
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/tool-drafts/{draft_id}/integrate")
    def api_tool_draft_integrate(draft_id: str, body: Optional[ToolIntegrateBody] = None):
        from vulnforge.toolgen.integrate import IntegrateToolError, integrate
        from vulnforge.toolgen.store import ToolDraftError

        dry = body.dry_run if body else True
        apply = body.apply if body else False
        add = body.add_to_profiles if body else None
        try:
            result = integrate(
                draft_id,
                dry_run=dry if not apply else False,
                apply=apply,
                add_to_profiles=add,
            )
            return {"ok": True, **result}
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e
        except IntegrateToolError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/api/tool-drafts/{draft_id}/export")
    def api_tool_draft_export(draft_id: str):
        from vulnforge.toolgen.store import ToolDraftError, export_draft

        try:
            return export_draft(draft_id)
        except ToolDraftError as e:
            raise HTTPException(404, str(e)) from e

    # ---------- API: lifecycle (start/pause/resume/stop) ----------

    @app.get("/api/runs/{target_id}/{run_id}/runner")
    def api_runner_status(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        return runctl.runner_status(run.path)

    @app.post("/api/runs/{target_id}/{run_id}/start")
    def api_start(target_id: str, run_id: str, body: ControlBody = Body(default_factory=ControlBody)):
        run = _get_run(target_id, run_id)
        try:
            kw = control_start_kwargs(body)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        r = runctl.start_run(run.path, **kw)
        if not r.get("ok"):
            raise HTTPException(409, r.get("error") or "start failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/pause")
    def api_pause(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        r = runctl.pause_run(run.path)
        if not r.get("ok"):
            raise HTTPException(400, r.get("error") or "pause failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/resume")
    def api_resume(target_id: str, run_id: str, body: ControlBody = Body(default_factory=ControlBody)):
        run = _get_run(target_id, run_id)
        try:
            kw = control_start_kwargs(body)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        r = runctl.resume_run(run.path, **kw)
        if not r.get("ok"):
            raise HTTPException(409, r.get("error") or "resume failed")
        return r

    @app.post("/api/runs/{target_id}/{run_id}/stop")
    def api_stop_hard(target_id: str, run_id: str):
        run = _get_run(target_id, run_id)
        return runctl.stop_run_hard(run.path)

    @app.delete("/api/runs/{target_id}/{run_id}")
    def api_delete_run(
        target_id: str,
        run_id: str,
        force: bool = Query(
            True,
            description="Hard-stop runner if alive; also allow delete without harness.db",
        ),
    ):
        """Permanently delete the run directory (DB, evidence, transcripts, project)."""
        # Resolve without requiring harness.db when force (broken runs still deletable)
        try:
            run = store.resolve_run(app.state.runs_root, target_id, run_id)
            tid, rid = run.target_id, run.run_id
        except FileNotFoundError:
            tid, rid = target_id, run_id
        except PermissionError:
            raise HTTPException(400, "invalid run path")
        r = store.delete_run(
            app.state.runs_root,
            tid,
            rid,
            force=force,
            stop_runner=True,
            require_db=not force,
        )
        if not r.get("ok"):
            err = r.get("error") or "delete failed"
            if "not found" in err:
                raise HTTPException(404, err)
            if "alive" in err:
                raise HTTPException(409, err)
            raise HTTPException(400, err)
        return r

    # ---------- SSE live feed ----------

    @app.get("/api/runs/{target_id}/{run_id}/stream")
    async def api_stream(target_id: str, run_id: str, after: int = Query(0, ge=0)):
        run = _get_run(target_id, run_id)

        async def gen():
            offset = after
            while True:
                try:
                    events, nxt = store.read_events(run, after=offset, limit=200)
                    # Same incomplete computation as list/detail APIs so the
                    # live badge is not wiped by raw runner_status snapshots.
                    card = with_runner_flags(
                        store.run_card(run), run.path, cfg=app.state.config
                    )
                    snap = {
                        "type": "snapshot",
                        "card": card,
                        "runner": card.get("runner") or runctl.runner_status(run.path),
                    }
                    # light task/finding counts only in card
                    yield f"data: {json.dumps(snap)}\n\n"
                    if events:
                        payload = {"type": "events", "events": events, "next": nxt}
                        yield f"data: {json.dumps(payload)}\n\n"
                        offset = nxt
                except Exception as e:
                    yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
                await asyncio.sleep(1.5)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8787,
    runs_root: Optional[Path] = None,
) -> None:
    import uvicorn

    app = create_app(runs_root=runs_root)
    print(f"vulnforge dashboard -> http://{host}:{port}")
    print(f"runs root: {app.state.runs_root}")
    uvicorn.run(app, host=host, port=port, log_level="info")
