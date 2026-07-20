# Setting up Ghidra and Ghidra MCP for VulnForge

VulnForge’s **`binary_re`** profile audits a **single PE** (`.exe` / `.dll`) using
**headless Ghidra** plus the **GhidraMCP** HTTP API ([bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)).

This guide is for a **normal online developer machine**. For an offline USB handoff that already includes both trees, see [OFFLINE_README.md](OFFLINE_README.md) / the offline release zip.

## What you need

| Component | Role | Expected path in this repo |
|-----------|------|----------------------------|
| **Ghidra** | RE engine (decompile, xrefs, imports) | `./ghidra/` (full distro with `ghidraRun.bat`) |
| **GhidraMCP** | HTTP API on `http://127.0.0.1:8089` | `./ghidra-mcp/` + `build/libs/GhidraMCP-*.jar` |
| **Java** | Runs Ghidra / headless MCP | Match Ghidra’s requirement (this tree’s **12.2_DEV** → **Java 25**) |
| **VulnForge** | Starts MCP, imports the PE, runs recon/hunts | this repo |

Config (project-relative by default) lives in `config/default.yaml` under `binary_re.*`:

- `ghidra_install_dir: ghidra`
- `mcp_base_url: http://127.0.0.1:8089`
- `headless_command: null` (auto-builds a Java launch from `./ghidra` + jar)

---

## 1. Install Java

1. Install a JDK that matches your Ghidra build.
   - **Ghidra 12.2_DEV** (as shipped under `./ghidra` in many VulnForge trees): **Java 25** (e.g. Eclipse Temurin 25).
   - Official public Ghidra 11.x/12.1.x often expects **Java 21** — always check `ghidra/Ghidra/application.properties` → `application.java.min`.
2. Set `JAVA_HOME` to that JDK, and ensure `java -version` matches.

```powershell
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.3.9-hotspot"  # adjust
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
java -version
```

---

## 2. Place Ghidra under `./ghidra`

VulnForge expects a **full Ghidra installation** at the **repo root**:

```text
VulnForge/
  ghidra/
    ghidraRun.bat
    Ghidra/
    support/
    ...
```

### Option A — Already have a build (recommended if you built from source)

Copy or unpack your distro so the path above exists, e.g.:

```powershell
# Example: copy from a local build output
# Copy-Item -Recurse "C:\path\to\ghidra_12.2_DEV\*" ".\ghidra\"
Test-Path .\ghidra\ghidraRun.bat
```

### Option B — Official public release

1. Download a release from [ghidra-sre.org](https://ghidra-sre.org/) or the [NSA Ghidra GitHub releases](https://github.com/NationalSecurityAgency/ghidra/releases).
2. Unzip into `./ghidra` (so `ghidraRun.bat` is directly under `ghidra/`, not nested twice).
3. Note the version and install a matching JDK.

### Option C — Offline zip from a teammate

Unpack a `VulnForge-offline-*.zip` from `scripts/package_offline_release.ps1`. It already includes `ghidra/` when built on a machine that has it.

---

## 3. Get GhidraMCP (`./ghidra-mcp`)

### Option A — Clone next to VulnForge

```powershell
cd C:\path\to\VulnForge
git clone https://github.com/bethington/ghidra-mcp.git ghidra-mcp
```

### Option B — Offline zip / vendor tree

If `ghidra-mcp/` is already present (offline bundle or vendored tree), skip clone. Prefer a tree that still has:

```text
ghidra-mcp/build/libs/GhidraMCP-*.jar
```

or be prepared to build (next section).

---

## 4. Build the GhidraMCP extension jar

From the **VulnForge repo root**:

```powershell
$env:TOOLS_SETUP_BACKEND = "gradle"   # Maven is fine if you have it on PATH
$env:GHIDRA_INSTALL_DIR = (Resolve-Path .\ghidra).Path
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.3.9-hotspot"  # match Ghidra
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

cd ghidra-mcp
py -3 -m tools.setup ensure-prereqs --ghidra-path $env:GHIDRA_INSTALL_DIR
py -3 -m tools.setup build
# Optional GUI plugin install into user Extensions:
py -3 -m tools.setup deploy --ghidra-path $env:GHIDRA_INSTALL_DIR
cd ..
```

Confirm:

```powershell
Get-ChildItem .\ghidra-mcp\build\libs\GhidraMCP*.jar
```

### Version mismatch (Ghidra 12.2 vs upstream 12.1.x)

Upstream ghidra-mcp often pins **Ghidra 12.1.x** and **Java 21**. If `preflight` / `build` fails with a version or toolchain error against **12.2** / **Java 25**:

1. In `ghidra-mcp/pom.xml`, set `<ghidra.version>` to match your install (e.g. `12.2`).
2. In `ghidra-mcp/build.gradle`, set the Java toolchain `languageVersion` to match (e.g. `25`).
3. Rebuild.

Headless VulnForge only needs the **jar** under `build/libs/`; full GUI deploy is optional.

---

## 5. Smoke-test headless MCP

```powershell
# From VulnForge repo root
powershell -ExecutionPolicy Bypass -File .\scripts\start_ghidra_mcp_headless.ps1
```

In another terminal:

```powershell
curl http://127.0.0.1:8089/check_connection
# Expect something like: Connection OK - GhidraMCP Headless Server ...
```

Leave the server running, or stop it and let **`vf init --profile binary_re`** start it automatically (it launches Java with breakaway flags so the process survives after init).

---

## 6. Wire VulnForge and run a PE audit

1. Config defaults should already point at project-relative paths (`config/default.yaml` → `binary_re`).
2. Install VulnForge if needed: `pip install -e ".[dev]"`.
3. Init (authorization required):

```powershell
vf init --target C:\path\to\app.exe --profile binary_re --i-am-authorized-for-binary-re
# Or: dashboard → New audit → pick a .exe/.dll → check authorize → Create
```

4. During New audit, the progress UI shows a **Ghidra** step (start → load PE → auto-analyze).
5. Start Ralph / Resume on the run.

```powershell
python scripts\ralph.py --run-dir runs\<target_id>\run-001 --max-tasks 20
```

---

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| `Ghidra install not found` | `./ghidra/ghidraRun.bat` exists; run from repo root |
| `GhidraMCP jar not found` | Build step 4; jar under `ghidra-mcp/build/libs/` |
| `headless exited early` | Java version; read `runs/.../ghidra_project/headless_stderr.log` |
| `ghidra_not_ready` on recon/hunt | MCP down or PE not loaded; init should load it — re-run init without `--skip-ghidra-init` |
| Port 8089 in use | Stop other MCP/Ghidra instances, or change `binary_re.mcp_base_url` / port consistently |
| Version mismatch on build | Align `ghidra.version` + Java toolchain with `application.properties` |
| Explorer `target/list` 400 on PE run | Update to a build that supports single-file targets (virtual root = the PE only) |

---

## Security notes

- GhidraMCP is intended for **localhost** use by default.
- VulnForge agent tools are **read-only** analysis + evidence under `evidence/` (no unrestricted target writes, no default host shell for `binary_re`).
- `binary_re` requires an explicit authorization flag (`--i-am-authorized-for-binary-re` or config).
- Do not treat `needs_human` as exploit proof.

---

## Related docs

- [AGENTS.md](../AGENTS.md) — binary_re operator surface and honesty rules  
- [PROTOCOL.md](../PROTOCOL.md) — tool surface including `ghidra_*`  
- [OFFLINE_README.md](OFFLINE_README.md) — air-gapped zip layout  
- Upstream: [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) · [Ghidra](https://ghidra-sre.org/)
