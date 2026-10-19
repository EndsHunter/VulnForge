# Validate PoC

`validate_poc` runs a finding's evidence-pack PoC inside the sandbox harness, writes `poc_run.json`, and leaves the finding unconfirmed. The operator enqueues it from the CLI or the HTTP API, or runs one shot in process with `--execute`.

## Sub-features

- `poc-enqueue` queues a `validate_poc` task and does not change finding state.
- `poc-execute` runs that one shot and writes `evidence/<pack>/poc_run.json`.
- `poc-no-confirm` leaves `state` unchanged after a harness result, including `signal_observed`.
- `poc-api` enqueues the same task from `POST .../validate-poc` and returns the task id.
- `poc-referee-off` does not let a model referee replace the harness verdict.

## How to get to it (user POV)

- Run `vf validate-poc --finding-id <id> --run-dir <run-dir>`.
- Add `--execute` to run the one shot in this process.
- `POST /api/runs/{target_id}/{run_id}/findings/{id}/validate-poc` with `{"operator":"operator","referee":false}`.
- Read `evidence/<pack>/poc_run.json` and the finding on `GET /api/runs/{target_id}/{run_id}`.

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` reports `ok: true`.
- A run under `$VF_VERIFY_RUNS_ROOT` already has a finding and an evidence pack. Use the [gate chain](./gate-chain.md) init when the queue must stay free of hunts.
- `poc_harness.enabled` is true. The runner is `sandbox`. Host execution is not a fallback.
- Do not pass `--referee`. Do not pass `--iterate` for this feature.

- **Enqueue.** Run `$VF_VERIFY_VF validate-poc --run-dir <run-dir> --finding-id <id>`. Exit code `0`. Stdout contains `enqueued validate_poc task_id=` and the same `finding_id`. `vf status` shows `has_work: True`. Finding `state` is unchanged on the run snapshot.
- **API enqueue.** `POST $VF_VERIFY_URL/api/runs/<target_id>/<run_id>/findings/<id>/validate-poc` with JSON `{"operator":"operator","operator_notes":"verify","referee":false,"command":""}`. HTTP 200. Body `ok` is true and includes a task id. A missing finding is HTTP 404.
- **Execute.** Run `$VF_VERIFY_VF validate-poc --run-dir <run-dir> --finding-id <id> --execute`. Exit code `0` when the harness finishes, `20` when isolation is an infrastructure failure. Stdout JSON includes `finding_id` and `verdict`.
- **Evidence file.** When the pack was runnable, `<run-dir>/evidence/<pack>/poc_run.json` exists and `schema` is `vulnforge.poc_run.v1`. `verdict` is one of `signal_observed`, `signal_absent`, `poc_broken`, `inconclusive`, `unsafe_skipped`, `sandbox_unavailable`, `build_failed`.
- **No confirm.** The run snapshot finding `state` is the same value as before execute. It is not `confirmed`.
- **Referee stays off.** The command line has no `--referee`, and the POST body has `"referee": false`. `poc_run.json` `verdict` is the harness value. A `referee` object may be absent. It must not be the source of `signal_observed`.
- **Proof.** Save both command transcripts, the POST response, `poc_run.json` when present, and the before/after finding `state`. Record feature id `validate-poc`.

## Gotchas

- `--execute` without a microVM or gVisor runtime returns `sandbox_unavailable` or `unsafe_skipped` and does not run on the host. That is a completed harness refusal, not a signal.
- Missing `run` frontmatter or missing PoC code yields `poc_broken`. Add an entry script before treating that as a harness bug.
- `signal_observed` is not Accept. Re-read `state`.
- A model referee that overwrites `verdict` fails `poc-referee-off`.
- Do not start Ralph to drain the enqueued task unless the recipe says `--execute`.
