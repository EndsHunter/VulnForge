# SARIF 2.1.0 export

`sarif` is a format in the findings export registry (`vulnforge/export_findings.py` → `vulnforge/sarif_export.py`). It feeds GitHub code scanning (`github/codeql-action/upload-sarif`), IDE SARIF viewers, and other consumers.

| Surface | How |
|---------|-----|
| CLI | `vf export --run-dir RUN --format sarif [--out FILE\|-] [--include-needs-human] [--include-rejected] [--state STATE ...]` |
| Report | **Export** modal → **SARIF 2.1.0 (.sarif)**, with *include needs_human* / *include rejected* toggles |
| HTTP | `GET .../export?format=sarif[&sarif_include_needs_human=true][&sarif_include_rejected=true]` (media `application/sarif+json`) |
| Campaign | `GET .../campaign/findings?format=sarif` → `{count, states, skipped_no_location, sarif}` |

## State filter

| Default | Opt-in |
|---------|--------|
| `confirmed` | `needs_human` (`--include-needs-human`), `rejected_*` + `superseded` (`--include-rejected`) |

An explicit state list (`--state`, or campaign `state=`) replaces the default and the flags. `candidate` (not yet through `validate_mech`) is only exported when named that way. Exporting never changes finding state.

## Mapping

- **Rules**: one per weakness class (hunt skill). `ruleId` = class slug (`unclassified` when empty), tags `security`, `vulnforge`, slug. No rule `security-severity`: one score per class would mislabel mixed-severity findings, so severity is carried by the result `level`.
- **Results**: one per finding. `level` from `severity_claim`: CRITICAL/HIGH → `error`, MEDIUM or missing → `warning`, LOW/INFORMATIONAL → `note`. `message.text` starts with the state for anything not `confirmed` (`needs_human: <title>. Mechanical gates passed; not a confirmed vulnerability.`), since code scanning uses the first sentence as the alert title.
- **Fingerprints**: `partialFingerprints` carries `stable_key` as `vulnforge/stableKey/v1` and as `primaryLocationLineHash`. `stable_key` depends on path, symbol and class, not line numbers, so alerts follow the finding across runs and line moves.
- **Properties**: `vulnforge/state`, `vulnforge/finding_id`, `vulnforge/confirmed`, `vulnforge/weakness_class`, `vulnforge/severity_claim`, `vulnforge/evidence_id`, `vulnforge/stable_key`, `vulnforge/human_review_action`. Run properties carry the run id, included states, and the disclaimer.
- **Locations**: the first citation with a path and start line (preferring `sink_path`) is primary; other cited lines go in `relatedLocations`. URIs are relative to the run's target root with no `uriBaseId` and no absolute local paths. For GitHub upload, the audited target must be the repository root, or alerts won't land on the committed files.
- **No location**: a finding with no target-relative path and start line is not emitted as a result. It is listed in `invocations[0].toolExecutionNotifications` (`vulnforge/no-location`).

GitHub upload limits: 10 MB gzipped and 25,000 results per run (5,000 shown). No `automationDetails` is written; set `category` on the upload step.

Honesty: `needs_human` means mechanical gates passed, and `confirmed` means a human accepted it. Neither is exploit proof, and SARIF export never sets `confirmed`.

Tests: `tests/test_export_sarif.py` validates output against the vendored OASIS schema (`tests/fixtures/sarif/sarif-schema-2.1.0.json`, offline).
