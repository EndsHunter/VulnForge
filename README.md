# VulnForge

Local, model-agnostic vulnerability discovery harness for LM Studio (or any OpenAI-compatible endpoint) and coding agents.

It runs a durable audit loop: **recon → hunt → mechanical validation → human review**, with a research-cockpit dashboard for steering live campaigns. LLM tool-use stages use the **[Strands Agents](https://strandsagents.com/)** runtime by default.

| Label | Meaning |
|-------|---------|
| **`needs_human`** | Passed **mechanical** gates (shape, citations, evidence / justified `no_poc`). **Not** exploit proof. |
| **`confirmed`** | A **human** accepted the finding in the Report UI. Still **not** exploit proof. |

Automation never auto-confirms. Prefer honest `submit_none` over inventing findings.

---

## Prerequisites

- **Python 3.11+** (`python3 --version`)
- An **OpenAI-compatible chat API** (typical: [LM Studio](https://lmstudio.ai/) on `http://127.0.0.1:1234/v1`)
- ~ few GB free disk for runs, transcripts, and evidence packs

Optional for full campaigns: a loaded local model (e.g. Ornith / other coding model). The dashboard works without a model; recon/hunt tasks need one.

VulnForge is **source-code analysis only** (`code_static` profile). PE binaries and reverse-engineering tooling are not supported.

---

## Project layout (this tree)

Run commands from the **repo root** (the directory that contains `vulnforge/` and `seeds/`):

```text
.
├── vulnforge/           # Python package (control plane, stages, UI)
├── seeds/               # Package seed library (system + hunt_classes + recon_agents)
├── config/              # default.yaml, hunt_profiles/, recon_agents/ (runtime)
├── scripts/ralph.py     # Outer loop
├── docs/                # LAYOUT.md, internal maps / plans
├── fixtures/            # Toy targets for tests / first run
├── skill/SKILL.md       # Optional agent skill for coding agents
├── tests/
└── pyproject.toml
```

If you only cloned the package folder, copy or extract `seeds/`, `config/`, `scripts/`, `fixtures/`, and `pyproject.toml` next to `vulnforge/` so `PROJECT_ROOT` resolves correctly. See [`docs/LAYOUT.md`](docs/LAYOUT.md) and [`seeds/README.md`](seeds/README.md).

---

## Setup (macOS / Linux)

```bash
cd /path/to/this/repo   # directory with pyproject.toml + vulnforge/

# 1. Virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 2. Install VulnForge (editable) + test extras
python -m pip install -U pip
pip install -e ".[dev]"

# 3. Confirm CLI
vf --help
```

### First-time config

1. Open **`config/default.yaml`** and set:
   - `llm.base_url` — LM Studio (or proxy) base, usually `http://127.0.0.1:1234/v1`
   - `llm.model` — **exact** id from `GET /v1/models` (e.g. `ornith-1.0-35b`, not a `models/…` path)
   - `llm.api_mode` — `chat_completions` (LM Studio default), or `responses` / `messages` if needed
   - For AI tool generation: keep `llm.max_tokens` / `llm.toolgen_max_tokens` high (reasoning models burn tokens on chain-of-thought first)
2. Start your local model server and load a model (recommended: **LM Studio + Ornith** on `:1234`).
3. Dashboard **Settings → Optimize AI settings → Save** writes `config/ui_settings.json` (host/model/max_tokens) and overrides YAML. Optimize reads the model card and empirically tests prompt capacity.
4. Env overrides: `VF_BASE_URL`, `VF_MODEL`, `VF_HOST`+`VF_PORT`, `VF_RECON_ORCHESTRATOR`.

**Ornith notes:** Toolgen (Dev → Generate tool) is JSON text generation. Recon/hunt need reliable **tool_calls** — Optimize’s tool probe warns if the model ignores tools. The optional `./start_ornith_server.sh` mlx stack defaults to another host/port and a low server token cap; prefer LM Studio for VulnForge unless you reconfigure both sides (see `toolgen.md` → Local Ornith).

### Smoke test (no long campaign)

```bash
# Optional: unit tests
pytest -q

# Init a run against the toy fixture
vf init --target fixtures/toy_sqli
# prints something like: runs/<target_id>/run-001

# Dashboard (research cockpit)
vf dashboard
# → http://127.0.0.1:8787
```

Leave the dashboard running. Open the new run → **Start** Ralph, or in another terminal:

```bash
python scripts/ralph.py --run-dir runs/<target_id>/run-001 --max-tasks 20
```

---

## Setup (Windows PowerShell)

```powershell
cd C:\path\to\this\repo

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e ".[dev]"

vf --help
vf init --target fixtures\toy_sqli
vf dashboard
# → http://127.0.0.1:8787
```

---

## Daily workflow

| Step | Command / UI |
|------|----------------|
| New audit | Dashboard **New audit**, or `vf init --target PATH` |
| Drive queue | Dashboard **Start**, or `python scripts/ralph.py --run-dir DIR` |
| One task only | `vf run-once --run-dir DIR` |
| Status | `vf status --run-dir DIR` or Mission overview |
| Steer | Explorer (enqueue hunts), Coverage (residual cells), Report (accept/reject) |
| Dev tools | Home → **Dev** — hunt skills + recon agents; generate custom skills |
| Tool gaps | `vf tool-gaps --run-dir DIR` or Home **Tool gaps** |
| Regenerate docs | `vf project --run-dir DIR` |

### Useful CLI

| Command | Use |
|---------|-----|
| `vf init --target PATH` | New run under `runs/` |
| `vf run-once --run-dir DIR` | Lease + execute one task |
| `vf status --run-dir DIR` | Task/finding summary |
| `vf project --run-dir DIR` | Regenerate `project/*` |
| `vf apply-candidate --file …` | Apply inbox candidate JSON |
| `vf tool-gaps --run-dir DIR` | Mine transcripts for tool gaps |
| `vf dashboard` | Research cockpit (`--host` / `--port` optional) |
| `vf delete-run --run-dir DIR` | Permanently delete a run |
| `python scripts/ralph.py --run-dir DIR` | Outer loop until idle / STOP / budget |

Default dashboard: **http://127.0.0.1:8787**

```bash
vf dashboard --host 127.0.0.1 --port 8787
```

---

## What you get in the dashboard

| Surface | Purpose |
|---------|---------|
| **Home** | All runs, progress, LLM token rollups |
| **Mission** | Overview, architecture, operator recon re-run, usage by stage |
| **Coverage** | Residual matrix; re-queue cells |
| **Explorer** | Browse target; enqueue class×path hunts |
| **Report** | Findings review (accept / reject / develop PoC) |
| **Dev** | Hunt skills, recon agents, generate custom hunt skills |

Token usage (when the model returns `usage`, or estimated) appears on Home and Mission overview.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `vf: command not found` | Activate `.venv` and `pip install -e .` from repo root |
| Dashboard import errors | `pip install -e ".[dev]"` (needs fastapi, uvicorn, jinja2) |
| Recon/hunt fail with transport | Start LM Studio; check `config/default.yaml` `base_url` / `model` |
| Empty / truncated answers | Raise `llm.max_tokens` (reasoning models need headroom) |
| Wrong prompts path | Run from repo root; ensure `seeds/system/` exists beside `vulnforge/` |
| Port in use | `vf dashboard --port 8788` |

---

## Docs

- [`PROTOCOL.md`](PROTOCOL.md) — authority model, labels, apply-candidate contract  
- [`AGENTS.md`](AGENTS.md) — extending tools, profiles, and the cockpit  
- [`docs/LAYOUT.md`](docs/LAYOUT.md) — where is X? (seeds, tools, config)  
- [`skill/SKILL.md`](skill/SKILL.md) — optional skill for coding agents using this harness  

## License

MIT
