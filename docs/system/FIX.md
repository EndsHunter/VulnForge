# Fix proposal and verification (`develop_fix` / `verify_fix`)

Two operator-triggered stages after a finding is `confirmed` or `needs_human`
(`force` allows other states). Neither changes finding state. Neither writes
to the target.

## `develop_fix.md`

| | |
|--|--|
| **What** | Stage instructions for writing a remediation patch as a unified diff. |
| **Loaded by** | `stages/develop_fix.py` (`pack_develop_fix`). |
| **Model role** | Develop PoC role (`model_develop_poc`). |
| **Tools** | read-only target tools, `list_evidence` / `read_evidence`, and `write_evidence` limited to `fix.patch` and `fix_notes.md`. Any other tool name is refused before dispatch. |
| **Output** | `evidence/<pack>/fix.patch`, optional `fix_notes.md`, and `fix_check.json` (an in-memory dry run against the target: `parse_ok`, `applies`, per-file hunks, errors). |
| **Override** | `config/prompts/overrides/develop_fix.md` |

A patch that parses but does not apply still succeeds, with `applies: false`.
A missing or unsafe patch (absolute or `..` paths, `.git/`, renames, binary) fails the task.

## `verify_fix.md`

| | |
|--|--|
| **What** | Independent re-check of the finding against a patched tree. |
| **Loaded by** | `stages/verify_fix.py` (`pack_verify_fix`). |
| **Model role** | Validate role (`model_validate` / first `validate_models` slot), not the patch author's role. |
| **Tools** | `list_dir`, `file_inventory`, `read_file`, `grep`, `find_symbol` rooted at the **patched tree**. No write tools, no evidence-pack reads. |
| **Withheld** | `fix_notes.md`, every `fix_*` / `remediation`-style finding field, the develop_fix transcript. |
| **Output** | `evidence/<pack>/verify_fix.json`; finding body `fix_verification` history (`fix_verification_latest`). |
| **Override** | `config/prompts/overrides/verify_fix.md` |

### Patched-tree sources (exactly one)

| Payload | Tree |
|---------|------|
| `patched_path` | An existing directory, used read-only, never deleted. |
| `git_rev` (+ `repo_path`, `subdir`) | Raw blobs from `git ls-tree` + `cat-file` into `run_dir/scratch/verify_fix/` (no checkout filters, hooks or attributes run). Default repo is the target. |
| `use_fix_patch` | A target copy plus `fix.patch`, in scratch. Refused when the patch does not apply. |

Scratch trees are removed after the task unless `keep_tree` is set.

### Steps

1. **Cited diff** (mechanical): each cited file, original vs patched. `region_changed` means a change overlaps the cited lines (±2).
2. **PoC re-run** when the pack has PoC code: the sandbox runs it with the read-only `/target` mount forced on, once against the patched tree and once against the original as a same-task baseline (`baseline: false` skips that). A run counts only if the mount is in the argv and the PoC references `/target`.
3. **Static re-check** by the verifier model: `VERDICT=fixed|still_vulnerable|inconclusive`, `CONFIDENCE`, `REASONING`, repeatable `WOULD_RESOLVE`.
4. **Combiner** (deterministic, conservative):
   - PoC signal on the patched tree → `still_vulnerable` (overrides the model).
   - Model `still_vulnerable` → `still_vulnerable`, unless the PoC supports fixed (then `inconclusive`).
   - `fixed` needs the model's `fixed` **and** either the PoC reproducing on the original and not on the patched tree, or no PoC in the pack with a change overlapping the cited code (`static_only`, confidence capped at medium).
   - A PoC that exists but could not give a usable signal blocks static-only `fixed`.
   - Everything else is `inconclusive`, with a non-empty `would_resolve`.

## Triggers

```bash
vf develop-fix --run-dir runs/<t>/run-001 --finding-id 3 [--notes "..."] [--execute]
vf verify-fix  --run-dir runs/<t>/run-001 --finding-id 3 --use-fix-patch [--execute]
vf verify-fix  --run-dir runs/<t>/run-001 --finding-id 3 --git-rev fix-branch [--repo PATH --subdir DIR]
vf verify-fix  --run-dir runs/<t>/run-001 --finding-id 3 --patched-path /path/to/patched/checkout
```

API: `POST .../findings/{id}/develop-fix`, `POST .../findings/{id}/verify-fix`, `GET .../findings/{id}/fix`.

## Honesty

`fixed` is not proof the bug is gone. It means two independent checks found no remaining path. `inconclusive` is a real result. The human decides what to do with the finding.
