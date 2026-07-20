# VulnForge offline developer bundle

This archive is a self-contained handoff for developers **without** needing to
clone GitHub or download Ghidra separately (when `ghidra/` and `ghidra-mcp/`
are included in the zip).

## Layout

| Path | Purpose |
|------|---------|
| `vulnforge/` | Python package (dashboard, harness, binary_re) |
| `config/` | Defaults, hunt/recon collections |
| `prompts/` | Seed prompts |
| `scripts/` | Ralph, offline release, GhidraMCP headless launcher |
| `ghidra/` | Full Ghidra distribution (`ghidraRun.bat`, etc.) |
| `ghidra-mcp/` | GhidraMCP plugin source + `build/libs/GhidraMCP-*.jar` |
| `fixtures/` | Toy targets (incl. binary fixture if present) |
| `wheelhouse/` | Optional pre-downloaded pip wheels |
| `OFFLINE_README.md` | This file |
| `OFFLINE_MANIFEST.json` | What was packaged and when |

## Requirements on the offline machine

- **Windows** (primary path for PE / binary_re)
- **Python 3.11+**
- **Java** matching this Ghidra build (**Java 25** for Ghidra 12.2_DEV)
- Optional: local LLM (Ornith / LM Studio OpenAI-compatible API)

## First-time setup

```powershell
# 1) Unpack this zip anywhere, e.g. C:\dev\VulnForge
cd C:\dev\VulnForge

# 2) Python env
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

# If wheelhouse/ exists (fully offline pip):
pip install --no-index --find-links=wheelhouse -e ".[dev]"

# Otherwise (needs network once):
pip install -e ".[dev]"

# 3) Confirm layout
Test-Path .\ghidra\ghidraRun.bat
Get-ChildItem .\ghidra-mcp\build\libs\GhidraMCP*.jar

# 4) Start headless Ghidra MCP (or let vf init start it)
powershell -ExecutionPolicy Bypass -File .\scripts\start_ghidra_mcp_headless.ps1

# 5) Dashboard + binary audit
vf dashboard
# New audit -> pick a .exe/.dll -> profile binary_re -> authorize -> Create
# or:
vf init --target C:\Windows\System32\notepad.exe --profile binary_re --i-am-authorized-for-binary-re
```

## Rebuild GhidraMCP jar (only if missing)

Requires network **or** a pre-filled Maven/Gradle cache:

```powershell
$env:TOOLS_SETUP_BACKEND = "gradle"
$env:GHIDRA_INSTALL_DIR = (Resolve-Path .\ghidra).Path
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.3.9-hotspot"  # adjust
cd ghidra-mcp
py -3 -m tools.setup ensure-prereqs --ghidra-path $env:GHIDRA_INSTALL_DIR
py -3 -m tools.setup build
```

## Config

- LLM: edit `config/default.yaml` -> `llm.base_url` / `llm.model`
- Binary RE: `binary_re.ghidra_install_dir: ghidra` (project-relative)

## Honesty

`needs_human` is not exploit proof. Automation never sets `confirmed`.
Target PE is not executed by default.
