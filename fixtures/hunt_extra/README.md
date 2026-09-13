# Hunt extra micro-fixtures

Minimal Juliet/CVE-**shaped** trees for library hunt mix floors.
**Not** a vendored Juliet/NIST or CVE corpus — only tiny synthetic files.

## Layout

```
fixtures/hunt_extra/
  <id>/                 # target tree (source under this dir)
  <id>.json             # ground-truth catalog (same shape as fixtures/ground_truth/)
  README.md
```

Seed: `ensure_library()` / `seed_from_ground_truth` imports top-level
`fixtures/hunt_extra/*.json` as hunt defs (`id` = stem; `target` points at
`fixtures/hunt_extra/<id>/`). Prefer filling Arch class-mix gaps over
redundant injection clones.

| Id | Class | Notes |
|----|-------|-------|
| `hx-memcpy-oob` | memory-safety | Unbounded `memcpy` into fixed buffer |
