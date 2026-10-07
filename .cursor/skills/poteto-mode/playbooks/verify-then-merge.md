# Verify then merge (VulnForge poteto)

Before calling a change Ready, or before asking Ops to squash-merge.
Independent of CI green. Green is not a verdict.

## Steps

1. **Match the surface.** Docs/skills-only with no UI claim → read the landed files and frontmatter. UI/CLI claim → run verify-vulnforge.
2. **Launch isolated proof** (when UI/CLI is in scope):

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify launch
eval "$(.cursor/skills/verify-vulnforge/scripts/vf-verify env)"
.cursor/skills/verify-vulnforge/scripts/vf-verify doctor --write
```

Pass only if `doctor --write` prints `"ok": true`. Refuse to drive on failure.

3. **Drive one mapped feature** from `.cursor/skills/verify-vulnforge/features/`. Capture artifacts under that skill’s `artifacts/` tree. CLI claims need command, exit code, and a second read (`vf status` or `GET /api/runs`).
4. **Cleanup.**

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify stop
```

Confirm health fails afterward and artifacts remain.

5. **Label honesty check.** If the PR mentions findings or labels, re-read PROTOCOL: `needs_human` ≠ proof; no auto-confirm; sandbox PoC opt-in.
6. **Verdict.** Report `PASS`, `PASS+NOTES`, or `FAIL` with the artifacts you produced. Do not merge yourself when the boarding brief says **do not merge**. Hand the verdict to Jonathan / Ops.

## Out of scope

- Live Ralph hunts as the verify target
- Host-exec PoCs or inventing exploits
- Merging from this playbook under a do-not-merge boarding flag
