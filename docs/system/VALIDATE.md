# Validate (disprove) system prompts

Runs after mech pass when **`stages.validate_llm`** is true (**default on** in `config/default.yaml`). Set false to opt out.

## `disprove.md`

| | |
|--|--|
| **What** | Shared adversarial contract: try to kill the finding; verdict discipline. |
| **Loaded by** | `packet.pack_disprove`. |
| **Impact** | How aggressive LLM rejection is. Can only demote/reject → more rejects or more stands; **never** auto-confirm or raise severity (enforced in stage code). |
| **Override** | `config/prompts/overrides/disprove.md` |

## `disprove_threat.md`

| | |
|--|--|
| **What** | Threat-model verifier perspective appended after shared disprove. |
| **Loaded by** | Default verifier list in `stages/validate_llm.py` (`threat_model` → this file). |
| **Impact** | Perspective-specific demotions (attacker/boundary realism). |
| **Override** | `config/prompts/overrides/disprove_threat.md` |

## `disprove_code.md`

| | |
|--|--|
| **What** | Code/mitigation verifier perspective. |
| **Loaded by** | Default verifier `code_mitigation`. |
| **Impact** | Focus on mitigations, sinks, dataflow realism. |
| **Override** | `config/prompts/overrides/disprove_code.md` |

## Config

Verifier list can be customized via `llm.disprove_verifiers` (id + prompt basename). Missing perspective files degrade to shared contract only.

Defaults live in `config/default.yaml`. The current shipped values:

```yaml
stages:
  validate_llm: true
  validate_poc_referee: true
poc_harness:
  enabled: true
  runner: sandbox          # microVM (Kata / patched Firecracker) → gVisor runsc → refuse
  timeout_s: 60
  network: none            # allow = isolated bridge for a documented lab; never host
  docker_image: "python:3.12.8-slim-bookworm"
  cpus: "1"
  memory: "512m"
  pids_limit: 128
  mount_target_ro: false
  sandbox_oneshot: false   # per-run opt-in: vf init --sandbox-poc or New audit checkbox
  iterate_max_cycles: 5    # Settings → Sandbox iterate; rewrite/re-run cycles per session
  iterate_wall_ttl_min: 15 # Settings → Sandbox iterate; wall TTL per session
```

### Sandbox one-shot (validate_poc)

Linux only. macOS and Windows need a Linux sandbox host. v1 runs the PoC **once** inside:

1. **MicroVM** — Docker runtime `kata-qemu` / `kata-clh` / `kata`, or `kata-fc` only when host `firecracker` and `jailer` are patched, or direct Firecracker+jailer when `firecracker_kernel` and `firecracker_rootfs` are set and `/dev/kvm` is usable.
2. **gVisor** — Docker runtime `runsc`.
3. **Refuse** — `sandbox_unavailable` or `unsafe_skipped`. No host exec. No plain runc.

`local_subprocess` and plain Docker/runc are hard failures. There is no silent fallback.

**Network** defaults to none (`--network=none`, no Firecracker NIC). Hub `network: allow` is an isolated bridge for a documented lab. `network: host`, `--privileged`, and `docker.sock` are refused. Mounts are the evidence pack read-only, plus an optional read-only target slice (`mount_target_ro`). Secrets, `~/.aws`, `.env`, and a writable audit target are not mounted. Wall TTL, CPU, memory, and a PID cap apply; timeout kills the process group and `docker rm -f` always runs.

**Firecracker patch bar** (CVE-2026-5747 virtio-pci OOB, CVE-2026-1386 jailer symlink overwrite): accept **1.14.4 through 1.14.x**, or **1.15.1 and later**. Boot with `pci=off`. Direct Firecracker uses a fresh `0700` jail dir and jailer. The guest rootfs must read `vf.cmd=<base64>` from `/proc/cmdline` (see `docs/harness/validate/firecracker-guest-init.sh`).

**Outcomes** (evidence only): `signal_observed` | `signal_absent` | `poc_broken` | `inconclusive` | `build_failed` | `sandbox_unavailable` | `unsafe_skipped`. The UI says “sandbox reproduced” / “signal observed”. That does **not** set `confirmed` and does **not** clear `needs_human` or HITL. PoC failure is not a false positive. `validate_mech` and `validate_llm` (when on) still run.

**Run-start toggle** (`vf init --sandbox-poc`, New audit “Sandbox PoC one-shot”, default off): when the queue is idle, Ralph enqueues one `validate_poc` per harness-ready `needs_human` finding. A missing sandbox writes the same fail-closed enums and the campaign continues.

### Iterate in sandbox

`iterate_poc` (Report **Iterate in sandbox**, `vf validate-poc --iterate`, or operator chat `enqueue_iterate_poc`) keeps one session inside the same ladder. Kata and gVisor hold one container and `docker exec` each rewrite/re-run into it. Direct Firecracker pins the same patched jailer policy (no NIC, `pci=off`) and boots one VM per cycle. Host exec and plain runc still refuse.

Defaults: **5** rewrite/re-run cycles and a **15-minute** wall TTL (`poc_harness.iterate_max_cycles`, `poc_harness.iterate_wall_ttl_min`). Settings → **Sandbox iterate** overrides both. Hitting either cap, an operator stop, or a missing sandbox ends the session and writes `poc_session.json` plus a last-cycle `poc_run.json`. That evidence does not set `confirmed`, does not clear `needs_human`, and does not answer HITL.

The workshop **Steer** box appends a note the next cycle reads. It is not a host shell. Human and agent share that session record and, while it is live, the same guest.

Pinned image: `python:3.12.8-slim-bookworm` (override with a digest). Pre-pull it on the sandbox host so the wall TTL is not spent on a registry fetch.

`llm.disprove_verifiers` can list `{id, prompt}` pairs. Missing perspective files fall back to the shared `disprove.md` contract only.

**When to disable validate_llm:** campaign speed, debugging hunt output without LLM filter, or same-model disprove is pure noise. Still never auto-confirms when on.

**Mech floor (always on):** `validate_mech.check_non_vacuous` rejects stub threat models and HIGH/CRITICAL without concrete impact hints — independent of this flag.

## `referee_poc.md`

| | |
|--|--|
| **What** | Optional PoC **run** referee after `validate_poc` mechanical execution. |
| **Loaded by** | `packet.pack_poc_referee` when `stages.validate_poc_referee` or task `referee: true`. |
| **Impact** | Annotates `poc_run.json` / body `poc_validation_latest` only. **Never** sets `confirmed`. |
| **Override** | `config/prompts/overrides/referee_poc.md` |

## See also

- [docs/harness/validate/](../harness/validate/)
- [docs/system/DEVELOP_POC.md](DEVELOP_POC.md) — hub frontmatter + export
- [docs/system/SHARED.md](SHARED.md) — `PRINCIPLES.md` impact/severity pin for hunts
