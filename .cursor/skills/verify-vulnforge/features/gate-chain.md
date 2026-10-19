# Gate chain

Mechanical validation passes a candidate into `needs_human` with `pending_llm` set, dual disprove may only settle that flag with parsed verdicts, and Accept stays blocked until the flag is clear. Reject stays available the whole time. Nothing in this chain sets `confirmed` by itself.

## Sub-features

- `mech-pending` runs mechanical gates and, when they pass with disprove enabled, sets `needs_human` and `validation_mech.pending_llm` true.
- `accept-blocked` refuses Accept while `pending_llm` is set, including a request that sends `force`.
- `hitl-accept-blocked` refuses the inbox approval value `approved` the same way and writes no response.
- `reject-open` records Reject while `pending_llm` is set and moves the finding to `rejected_human`.
- `disprove-inconclusive` keeps the result inconclusive and leaves `pending_llm` set when disprove produces zero parsed verdicts, an error, or a timeout.

## How to get to it (user POV)

- Run `vf init` against a local fixture, then `vf apply-candidate` and one `vf run-once`.
- Read the run with `vf status` and `vf hitl inbox`.
- Accept or Reject with `POST /api/runs/{target_id}/{run_id}/findings/{id}/review`.
- Accept or Reject from the inbox with `vf hitl respond` on block `finding-{id}-review`.

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` reports `ok: true` for this instance.
- `fixtures/toy_sqli/app.py` exists and defines `search_users`.
- `stages.validate_llm` stays at its default on. Do not flip it off.
- The run was created with `--strategy file_by_file --no-enqueue-hunts`, so the queue starts empty.

- **Init.** Run `$VF_VERIFY_VF init --target fixtures/toy_sqli --runs-root "$VF_VERIFY_RUNS_ROOT" --strategy file_by_file --no-enqueue-hunts`. Exit code `0`. Stdout ends with the absolute run directory `$VF_VERIFY_RUNS_ROOT/<target_id>/run-001`.
- **Evidence pack.** Under that run, write `evidence/e-gate/note.txt` with at least 20 bytes that mention `search_users`. Create `inbox/gate-candidate.json` with `title`, `summary`, `weakness_class` `injection`, a `threat_model` whose `impact` names SQL injection, `evidence_id` `e-gate`, and one citation `{"path":"app.py","start_line":<line of def search_users>,"symbol":"search_users"}`.
- **Apply.** Run `$VF_VERIFY_VF apply-candidate --run-dir <run-dir> --file <run-dir>/inbox/gate-candidate.json`. Exit code `0`. Stdout contains `candidate finding_id=`.
- **Mechanical gate.** Run `$VF_VERIFY_VF run-once --run-dir <run-dir>` exactly once. Exit code `0`. Do not run it again.
- **Pending read.** Run `$VF_VERIFY_VF status --run-dir <run-dir>`. Stdout `findings:` includes `needs_human`. `has_work:` is true because `validate_llm` is still queued. `GET $VF_VERIFY_URL/api/runs/<target_id>/run-001` returns that finding with `state` `needs_human` and `body.validation_mech.pending_llm` true. `GET $VF_VERIFY_URL/api/runs/<target_id>/run-001/hitl/inbox` includes an item `finding-<id>` with `pending_llm` true.
- **Accept blocked.** `POST $VF_VERIFY_URL/api/runs/<target_id>/run-001/findings/<id>/review` with JSON `{"action":"confirm","notes":"too early","force":true}`. HTTP 400. Body `detail` is `Dual disprove still running — Accept after it settles, or Reject now.` The same GET snapshot still shows `state` `needs_human` and `pending_llm` true.
- **Inbox Accept blocked.** Run `$VF_VERIFY_VF hitl respond --run-dir <run-dir> --id finding-<id> --block finding-<id>-review --value approved --note "inbox accept"`. Exit code `30`. Stderr JSON has `"code": "pending_llm"`. A second `vf hitl show --id finding-<id>` has no stored approval response. State is still `needs_human`.
- **Reject.** `POST` the same review path with JSON `{"action":"reject","notes":"drop while disprove is still running"}`. HTTP 200. Body `to_state` is `rejected_human`. The GET snapshot shows `state` `rejected_human`.
- **Disprove inconclusive.** Leave the queued `validate_llm` task unrun unless a scripted disprove client is already configured. When that task does run, zero parsed `VERDICT=` or JSON verdicts, any slot error, or any timeout leaves `validation_llm` inconclusive, leaves `validation_mech.pending_llm` true, and the Accept POST still returns HTTP 400 with the same `detail`. A slot counted as `needs_human` because the text failed to parse is not a parsed verdict.
- **Proof.** Save init stdout, apply stdout, status stdout, the review responses, the hitl respond stderr, and the run snapshot JSON. Record feature id `gate-chain`.

## Gotchas

- A second `run-once` leases `validate_llm` and calls a model. This map does not do that.
- `vf run-once` exits `0` on a finished mechanical gate. Read the finding body. Do not treat a quiet stdout as a skipped gate.
- `vf status` may print a `validate_llm` note on stderr. Assert stdout fields.
- HTTP Accept failure is the `detail` sentence. The `"code": "pending_llm"` field is on `vf hitl respond`, not on the HTTP body.
- `action` `accept` is the same hard block as `confirm`. `force` does not override it.
- Turning `stages.validate_llm` off so Accept succeeds is a failed drive. The flag stays set until disprove settles with parsed verdicts.
- An error, a timeout, or zero parsed verdicts that clears `pending_llm` fails `disprove-inconclusive`. Do not record that as a pass.
