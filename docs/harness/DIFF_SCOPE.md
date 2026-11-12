# Diff-scoped audits (`vf init --diff base..head`)

Audit a PR, a commit, or a branch instead of the whole tree.

```bash
vf init --target /path/to/repo --diff main..HEAD            # depth from diff.expand_depth (1)
vf init --target /path/to/repo --diff v1.4.0..v1.5.0 --diff-depth 2
```

Dashboard: **New audit → Diff (optional)**, or `POST /api/runs/init` with `"diff": "base..head"`
(`diff_depth` optional).

## What the scope is

| Part | Source |
|------|--------|
| `changed` | Files that differ between the **base and head commit trees** (`git diff <base> <head>`), inside the target, with new-side line ranges (hunks) |
| `expanded` | Callers and callees of the changed symbols: heuristic `name(` call scan over the mechanical codemap symbols, BFS to `diff.expand_depth` (0–3), capped by `diff.max_expanded_files` |
| `excluded` | Changed paths not hunted: `deleted`, `ignored` (run.ignore_globs), `non_code`, `outside_target`, `missing_in_worktree` |
| `untouched_modules` | Count + sample of codemap modules with no scope file |

A three-dot spec (`base...head`, merge-base diff) is refused. It can differ from the tree compare.

The expansion is **not** a resolved call graph or taint proof. Generic or multiply-defined names
(`run`, `get`, names defined in more than three files) are not expanded and are listed in
`expansion.ambiguous_symbols`.

## Refusals (before any run dir is created)

- not a git work tree, unknown revision, base == head
- the repo's work tree does not contain the target at its prefix (for example `core.worktree`
  pointing elsewhere)
- target checkout `HEAD` is not *head*. Hunts read the working tree, so check the head revision
  out (for example in a separate `git worktree`) or use `base..HEAD`
- no hunt-able code change (for example a docs-only diff). An empty run would read as a clean audit

Worktree bytes that differ from the head blob are a **warning** (`worktree.drift`), not a refusal.

## Read-only target

Git runs without a shell, with `GIT_OPTIONAL_LOCKS=0` (no index refresh), hooks, fsmonitor,
external diff and textconv off, submodules ignored, and `GIT_DIR`-style env vars dropped. There is
no worktree diff (that would run repo clean filters); drift is checked by hashing file bytes in
Python. Nothing is checked out, fetched, or written in the target.

## Where the scope applies

| Path | Behaviour |
|------|-----------|
| recon (discovery / recon_docs) | `focus_paths` = scope files; operator brief gets a diff section |
| recon finalize hunt plan | hints rewritten to scope **files** (module dirs never survive: the soft jail treats a dir hint as a prefix); out-of-scope tasks dropped; uncovered changed files get allowed-class tasks; then class routing and `run.max_tasks` |
| file_by_file | changed files first, then callers/callees |
| dynamic run skills, `request_hunt`, `continue_hunt`, split / shallow children | hints clipped to the scope; `diff_scope` carried |
| hunt scans (`grep`, `find_symbol`, `query_flows`, `query_sinks`) | limited to the hunt hints + scope files, before and after a soft widen (`tools/scope.py` `clamp_scan_roots`); `query_sinks(rescan=true)` uses the stored index. Reading a specific file for context stays allowed |
| `run.max_tasks` budget | one task per changed file is kept first, then the rest is spread across areas/classes; the report names changed files that still got no hunt task |
| operator enqueues (Explorer, Hunts matrix, operator chat) | **unscoped**: an explicit human choice |

Each scoped hunt payload carries a short `diff_scope` block (changed files + hunks in its hints,
caller/callee context) that `pack_hunt` renders as **Diff under review**.

## Persistence and report

- `runs.diff_scope_json` in `harness.db` (authority) and `run_dir/diff_scope.json` (manifest, schema
  `vulnforge/diff-scope@1`).
- `db.summary()["run"]["diff_scope"]` is a small count brief; the blob is skipped.
- `project/diff_scope.json` and the **Diff scope** section of `project/REPORT.md` are projections.
- Exports (md / html / docx / json) include the scope section; JSON includes the full manifest.
  Findings that cite code outside the scope (reachable after a widen) are called out.

Nothing here changes finding states. `confirmed` is still human-only.

Code: `vulnforge/diff_scope.py`. Tests: `tests/test_diff_scope.py`. Config: `diff:` in
`config/default.yaml`. CI mode (#188) builds on this.
