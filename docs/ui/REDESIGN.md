# Run cockpit redesign (ui-redesign branch)

Source mockups: the "VulnForge Redesign Concepts" design canvas (A Triage Desk, B Campaign
Flow, C Code Atlas). This file is the working spec for implementing them in the real
dashboard. Sub-agents implement one page each and must stay inside their owned files.

## Goals

1. **One job per page.** Six run modes become five tabs. Each tab answers one question.
2. **Each count lives in one place.** The header pipeline strip is the single place for run
   totals. Pages show detail, not repeated KPIs.
3. **The important visual goes above the fold**: the residual matrix on Campaign, the finding
   plus verdict on Review, the map on Atlas.
4. **Honesty rules stay intact** (see `AGENTS.md`). Automation never sets `confirmed`.
   Same-model disprove is labelled a weak signal. Teal "finding filed" never means safe.
   `none` is still residual.

## Information architecture

Internal mode ids (hash keys, `data-mode-panel`) are **kept** so deep links and existing JS
keep working. Only labels, order and page content change.

| Tab (label) | mode id    | Replaces                          | Job                                   |
|-------------|------------|-----------------------------------|---------------------------------------|
| Review      | `report`   | Report (+ needs-review indicator) | Human gate: triage, accept/reject     |
| Campaign    | `hunts`    | Mission stats + Hunts             | Run and steer: pipeline, residual matrix, worker |
| Atlas       | `explorer` | Explorer + Mission architecture   | Understand the target, decide where to hunt |
| Evidence    | `evidence` | Evidence (unchanged content)      | Browse packs                          |
| Tasks       | `audit`    | Tasks / Timeline (unchanged)      | Queue and transcripts                 |
| AI          | `ai`       | overlay (unchanged)               | Co-pilot sheet, opened from ⌘K button |

`#mission/*` now resolves to `hunts`. The default landing tab is **Campaign**. Home,
Settings, Dev and Tool gaps move from the icon rail into the header ⋯ menu.

## Shared shell (Phase 0, done by the lead before page work)

- `run.html` header: logo → run switcher → **text tabs** (Review shows a needs-review count
  badge) → spacer → **pipeline strip** `#run-pipeline-strip` → Ralph status pill
  (`#runner-status`) → Start/Pause/Resume (same ids) → ⌘K (opens AI sheet) → ⋯ menu.
  The icon rail is removed.
- Tokens: `styles.css :root` moves to the mockup palette (graphite `#0e1014`, teal
  `#5cc8b8`, amber `#f2b84b`, severity crit `#ff8a8a` / high `#ffb27a` / med `#f2cc5b` /
  low `#8dbbff`). Token names are unchanged, so legacy CSS restyles automatically.
- `static/shell.css`: header/tabs plus shared primitives every page uses:
  `.vf-card`, `.vf-section-label`, `.vf-pill` (+ `--review|--confirmed|--rejected|--candidate`),
  `.vf-sev` (+ `--crit|--high|--med|--low`), `.vf-btn` (+ `--primary|--danger|--ghost`),
  `.vf-kbd`, `.vf-chip` (+ `[aria-pressed=true]`), `.vf-mono`, `.vf-empty`,
  `.vf-cell` (+ `--finding|--none|--shallow|--aborted|--planned|--running|--empty|--na`).
  Pages use these primitives. They do not invent new colours (use `var(--…)`).
- Snapshot event: `app.js loadRunFull()` dispatches
  `window.dispatchEvent(new CustomEvent("vf:snapshot", { detail: snap }))` after each load.
  Pages subscribe to it instead of patching `app.js`. `window.__VF_last_snap` holds the latest.
  `window.api(path, opts)`, `window.currentKey` and `window.VulnForgeModes.*` stay available.
- Page module contract: each page file is an IIFE that registers
  `window.VFPages.<name> = { mount(el), render(snap), onShow(), onHide() }`. `modes.js` calls
  `onShow`/`onHide` on tab change. Page keyboard shortcuts must check that their panel is
  active and that focus is not in an input.

## File ownership (parallel phase)

Do not edit files you don't own. If you need a change in a shared file, describe it in your
final report and the lead integrates it.

| Owner          | Owns (may edit/create)                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| Review agent   | `static/pages/review.{js,css}`, `report.js`, `report_state_badges.js`, `report_hunt_moa.js`, `hitl_inbox.js`, the `<!-- BEGIN page:review -->…END` block of `run.html`, tests for those |
| Campaign agent | `static/pages/campaign.{js,css}`, `coverage.js`, `mission_overview_helpers.js`, the `page:campaign` block of `run.html`, tests for those |
| Atlas agent    | `static/pages/atlas.{js,css}`, `explorer.js`, the `page:atlas` block of `run.html`, tests for those |
| Home agent     | `static/pages/home.{js,css}`, `templates/index.html`, the home run-list functions in `app.js` (`statusChip` … `loadRuns`: `classifyRun`, `renderRunRow`, `renderHomeStats`, `sevPills`, `renderRunCards`, `matchesFilter`, `matchesQuery`, `runStatusLabel`, `lastEventLine`, `shortAge`), `tests/test_run_nav_js.py::test_home_html_is_the_list` |
| Lead           | `run.html` outside the page blocks, `shell.css`, `styles.css`, `modes.js`, `run_nav.js`, the rest of `app.js`, `app.py`, and the token and nav tests |

**Backend:** pages should use the existing endpoints. If an endpoint is missing data, add a
**read-only** field or route only when it's unavoidable, and flag it in your report. The lead
owns `app.py`. Make the frontend degrade gracefully when the field is missing.

## Page specs

### Review (Triage Desk, mode `report`)
Three columns: **queue | finding | verdict rail**. On narrow screens they stack.
- Queue: findings sorted by evidence tier (`finding.evidence_tier`, server-derived), then
  severity, then state. Each row shows a tier pill. Filter chips: Needs review (default) /
  Candidate / Confirmed / Rejected / Near-dup / All. Keep search. Each row shows a severity
  tag, `#id`, a state pill, the title, `path:line` and the class. Decided rows are dimmed.
- Finding: severity, state, class and "filed by hunt #n · age" → title → summary → **data
  flow** cards (source → flow → sink, built from citations / trace data when present,
  otherwise the cited locations in order) → **cited code** with the cited lines highlighted
  (reuse the existing context loader) → "Open in Atlas" (`VulnForgeModes.goExplorer`).
- Verdict rail: evidence tier at the top, then mechanical gates checklist (`validationReasonsOf`), adversarial disprove
  judges (`llmVerifyMeta`) with the weak-signal note, evidence pack link, PoC status and
  buttons (reuse Develop PoC modal / Run in sandbox), reviewer note plus **Accept / Reject**.
  These go through the existing HITL respond path. Never set state directly.
- Keys: J/K move, A accept, R reject, E open evidence. Only when Review is active and focus
  is not in a field. After a decision, move to the next undecided finding.
- Keep: Export report modal (toolbar button), near-dup clusters, PoC workshop modal, the
  `#poc/<id>` deep link, `VulnForgeReport.openFinding/setFilter/openDevelopPoc` API.

### Campaign (Campaign Flow, mode `hunts`)
- **Pipeline row**: Recon · Hunt · Mech gates · Disprove · Human review · PoC. Each card
  shows a status badge, a big number with a label, a done/waiting bar, a sub-line and an
  exit count (rejected_mech, rejected_llm, rejected_human). Build it from
  `mission_overview_helpers` (`buildVisualPipeline`, `buildFindingFunnel`).
  **Fix:** candidate findings must not be counted as needs_human anywhere.
- **Residual matrix** (main panel, above the fold): area rows × skill columns using
  `.vf-cell--*`. Each row header shows "N open". The honesty sentence: "X of Y applicable
  cells have a deep result…". "Residual only" toggle, "Re-queue N residual" (existing
  bulkRequeue), and the legend with counts.
- **Right column**: selected-cell inspector (state explanation, last hunt, depth, notes →
  re-queue this cell, open transcript; reuse `/coverage/cell`), Now running (leased hunt,
  turn, last tool; open the live task modal), Up next (queued tasks), Activity (recent
  events).
- "Plan hunts" opens the existing planner (`renderModeBar` UI) in a drawer or modal. Don't
  rewrite the planner. Residual explanations move into tooltips / the legend, not paragraphs.

### Atlas (Code Atlas, mode `explorer`)
- **Left**: file tree (reuse explorer tree loading) with badges: finding count (from
  snapshot findings by path), "gap" for areas with residual cells, "live" for a path under
  an active hunt.
- **Centre**: architecture map from `GET /architecture` (+ codemap for paths). Areas are
  grouped into trust zones when the architecture has boundaries/surfaces; otherwise a
  simple grid. Shading toggle: Residual risk / Findings. Each node shows its name, kind, a
  finding count pin and an 8-segment skill bar (from coverage). Draw edges only when the
  architecture has relations. A "Code" view toggle swaps the map for the existing Monaco
  file viewer (select lines → enqueue hunt still works).
- **Right**: area inspector: zone, description, entrypoints, sinks, files, hunt-coverage
  grid, findings here (link to Review), **Hunt this area** composer (gap skills preselected,
  notes, enqueue via the existing selection-hunt / requeue endpoints).
- Bottom: command bar → sends to the run AI sheet (`VulnForgeChat`).
- Moved from Mission: "Run recon with brief", architecture History, Codemap and Raw JSON as
  collapsibles. Empty state when there is no architecture yet.

### Home (run list, `index.html`)
Keep the existing ids that tests assert. Make it a usable overview:
- **Needs your attention** band: runs with needs_human > 0 (count, link to `#report`), runs
  that are paused/stalled, and runs that have errored.
- **Run table/cards**: target / run, status pill, pipeline mini-strip (hunted / gated /
  review / confirmed), last activity, tokens. Running runs first.
- Header: search, New, ⋯ (Settings, Dev, Benchmarks, Tool gaps). Same visual language as
  `shell.css`.

## Verification (every agent)

```bash
V=/tmp/claude-1000/-home-ends-VulnForge/460c6ebf-65f6-4ac3-8f28-32d711edc70e/scratchpad/venv
$V/bin/python -m pytest -q -p no:cacheprovider tests/test_ui_tokens.py tests/test_run_nav_js.py \
  tests/test_report_state_badges_js.py tests/test_mission_overview_helpers_js.py \
  tests/test_hitl_inbox_js.py tests/test_report_hunt_moa_js.py tests/test_dashboard_ops.py
node --test tests/js/
```
Add `node --test` unit tests for any pure helper you add, such as row/cell builders or sort
order. The lead runs the full suite and a visual pass at the end.

## Phases

0. Lead: shell, tokens, nav, snapshot event, page stubs, ownership markers (this branch).
1. Parallel: Review, Campaign, Atlas and Home agents.
2. Lead: integrate any requested shared-file changes, remove the dead Mission/rail code,
   run the full suite, take screenshots of each page against a seeded demo run.
