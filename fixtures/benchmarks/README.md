# Benchmark oracles (non-hunt types)

Hunt benches seed from `fixtures/ground_truth/*.json` (toy_sqli / mono_synth)
and from `fixtures/vulngym/slice.json` (one hunt def per frozen finding, with
`config_overlay.difficulty` and `oracle.findings` length 1). Checkout trees
live under `.audit/vulngym/trees/{id}` (gitignored; not vendored).

This tree holds **type-specific** oracles for mechanical bench desk runs:

| File | Type | Target | Notes |
|------|------|--------|-------|
| `toy_sqli_recon.json` | `recon` | `fixtures/toy_sqli` | Expected components / path_hints; requires `relations` + `trust_boundaries` keys |
| `toy_sqli_finding_report.json` | `finding_report` | `fixtures/toy_sqli` | Required report fields, min citation density, honesty labels; embeds / refs a fixture report |
| `toy_poc_dev.json` | `poc_dev` | `fixtures/toy_sqli` | Pack file expectations + `poc_run.json` (`ok` / `signal` / `network: none`); workshop only |
| `reports/toy_sqli_report.json` | (input) | — | Deterministic finding report JSON for `score_finding_report` (no live hunt) |

Shared oracle envelope: `id`, `target`, `schema_version`, `type`.

**Seed:** `ensure_library()` (empty collection) and `POST /api/benchmarks/seed`
(`seed_from_ground_truth(missing_only=True)`) import missing ids from
`fixtures/ground_truth/` (hunt), `fixtures/vulngym/slice.json` (16 hunt defs),
and `fixtures/benchmarks/*.json` (recon / finding_report / poc_dev). Files
under `reports/` are inputs, not defs.

**poc_dev:** run via POC workshop (`POST /api/benchmarks/poc/runs`), not the
Run page. Harness uses an isolated sandbox + subprocess with `network: none`
(no live-net PoC; never auto-confirms findings).
