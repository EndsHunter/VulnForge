# Binary Architecture Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Mission Architecture preview (overview card + Architecture tab) binary-aware for `binary_re` runs so operators see PE modules, imports/sinks, and address hunt focus—not a source-tree “components / input surfaces” layout that misrepresents reverse-engineering maps.

**Architecture:** Extend `architecture_summary()` to emit a `mode` field (`source` | `binary`) derived from run profile and/or architecture inventory. The dashboard snapshot already carries `architecture_summary`; Mission JS branches rendering on `mode`. Keep raw JSON details for power users. No change to DB schema—only projection + UI.

**Tech Stack:** Python (`vulnforge/control/ops.py`, `vulnforge/ui/store.py`), vanilla JS (`vulnforge/ui/static/app.js`), pytest (`tests/test_dashboard_ops.py`).

---

## File map

| File | Responsibility |
|------|----------------|
| `vulnforge/control/ops.py` | `architecture_summary(arch, *, profile=None)` → compact UI fields + `mode` |
| `vulnforge/ui/store.py` | Pass run `profile` into `architecture_summary` |
| `vulnforge/ui/static/app.js` | Binary layout for Architecture tab + overview brief card |
| `vulnforge/ui/static/styles.css` | Light styling for binary meta chips / sink lists (minimal) |
| `tests/test_dashboard_ops.py` | Unit tests for binary vs source summary shapes |

## Detection rules

`mode = "binary"` when any of:

1. `profile == "binary_re"`
2. `arch.inventory.kind == "single_binary"`
3. `arch.binary` is a non-empty dict
4. Target path is a single file with `.exe`/`.dll` (optional, if available on snapshot)

Else `mode = "source"`.

## Binary summary shape (additions)

```python
{
  "mode": "binary",
  "has_architecture": True,
  "summary": "...",
  "title": "Binary map",  # UI heading
  "binary": {
    "name": "notepad.exe",
    "path": "...",          # optional
    "sha256": "...",        # optional
    "format": "PE",         # if known
    "arch": "x86:LE:64",    # if known
    "function_count": 851,  # if known
  },
  "modules": [  # from components, renamed for UI
    {"name": "...", "role": "...", "path_hints": ["0x..."]}
  ],
  "imports_preview": [...],   # truncated import names/symbols
  "exports_preview": [...],
  "seed_sinks": [{"symbol": "...", "address": "...", "kind": "..."}],
  "hunt_focus": [{"area": "...", "class": "...", "path_hints": [...]}],
  "trust_boundaries": [...],  # keep, label as "Trust edges"
  "recon_agents_run": [...],
  # also keep components for Coverage compatibility
  "components": [...],
  "input_surfaces": [],
}
```

## UI (binary mode)

**Overview card**

- Title: **Binary map** (not “Architecture”)
- Snippet: summary text
- Meta line: `name · arch · N functions · M sinks · K hunt focus`

**Architecture tab**

- Heading: **Binary map**
- Summary prose
- Grid columns: **Modules** | **Dangerous sinks / APIs** | **Hunt focus (addresses)**
- Optional row: imports/exports chips
- Trust edges (if any)
- Keep History / Edit / Refine; empty-state CTA: hide “Open Explorer” emphasis for binary or reword to “Enqueue hunt from Coverage”

## Tasks

### Task 1: Failing tests for binary architecture_summary

**Files:**
- Modify: `tests/test_dashboard_ops.py`
- Modify: `vulnforge/control/ops.py`

- [x] Write tests for source mode (unchanged) and binary mode detection + field projection
- [x] Implement `architecture_summary` extensions
- [x] Pass `profile` from `store.py`
- [x] Update JS renderers + minimal CSS
- [x] Run `pytest tests/test_dashboard_ops.py -q`

### Success criteria

1. Source runs still show Components / Input surfaces / Trust boundaries.
2. `binary_re` / single_binary maps show Binary map with modules, sinks, address hunt focus.
3. Overview card labels and counts match binary semantics.
4. Tests green offline.
