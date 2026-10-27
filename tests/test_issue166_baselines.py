"""Issue 166 slice 1 baselines: CLI --help and the stub bench scorecard.

Baselines live under tests/baselines/issue166/, outside bench/ and bench/results/.
Regenerate only when the help text or stub scorecard is supposed to change:

    python tests/test_issue166_baselines.py --write
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "tests" / "baselines" / "issue166"
MANIFEST_PATH = BASELINE_DIR / "manifest.json"
STUB_ARGS = ["-m", "bench", "run", "--stub"]
STUB_FILE = "bench-stub-scorecard.json"
SCRIPT_HELP = (
    "scripts/ralph.py",
    "scripts/validate_tool.py",
    "scripts/eval_recall.py",
    "scripts/eval_hunt_profiles.py",
    "scripts/eval_vulngym.py",
    "scripts/live_toolgen_smoke.py",
    "scripts/strands_spike.py",
)


def _env() -> dict[str, str]:
    env = os.environ.copy()
    prev = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT) if not prev else str(ROOT) + os.pathsep + prev
    env["COLUMNS"] = "80"
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
    return env


def _slug(args: list[str]) -> str:
    parts: list[str] = []
    skip_m = False
    for arg in args:
        if arg == "--help":
            continue
        if arg == "-m":
            skip_m = True
            continue
        if skip_m:
            skip_m = False
            parts.append(arg.replace(".", "-"))
            continue
        parts.append(arg.replace("/", "-").replace(".", "-").replace("_", "-"))
    return "-".join(parts)


def _subcommands(help_text: str) -> list[str]:
    """Names in a usage `{a,b}` group. Option groups such as `{--stub,--live}` are skipped."""
    usage: list[str] = []
    for line in help_text.splitlines():
        if line.startswith(("options:", "positional arguments:")):
            break
        usage.append(line)
    names: list[str] = []
    for match in re.finditer(r"\{([^{}]+)\}\s+\.\.\.", " ".join(usage)):
        for part in match.group(1).split(","):
            name = part.strip()
            if name and not name.startswith("-"):
                names.append(name)
    return names


def _help_tree(prefix: list[str]) -> list[list[str]]:
    proc = run_args([*prefix, "--help"])
    if proc.returncode != 0:
        raise RuntimeError(
            f"{prefix} --help exited {proc.returncode}: {proc.stderr.decode()}"
        )
    found = [prefix + ["--help"]]
    for name in _subcommands(proc.stdout.decode()):
        found.extend(_help_tree(prefix + [name]))
    return found


def help_commands() -> list[dict[str, object]]:
    """Every --help invocation for the vf and bench entry points, plus script CLIs."""
    commands: list[dict[str, object]] = []

    def add(args: list[str]) -> None:
        slug = _slug(args)
        commands.append({"slug": slug, "args": args, "file": f"cli-help/{slug}.txt"})

    for args in _help_tree(["-m", "vulnforge.cli"]):
        add(args)
    for args in _help_tree(["-m", "bench"]):
        add(args)
    for args in _help_tree(["-m", "bench.cli"]):
        add(args)
    for script in SCRIPT_HELP:
        add([script, "--help"])
    slugs = [str(item["slug"]) for item in commands]
    if len(slugs) != len(set(slugs)):
        raise RuntimeError(f"duplicate help slugs: {slugs}")
    return commands


def run_args(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=_env(),
        capture_output=True,
        check=False,
    )


def write_baselines() -> None:
    help_dir = BASELINE_DIR / "cli-help"
    help_dir.mkdir(parents=True, exist_ok=True)
    commands = help_commands()
    for item in commands:
        proc = run_args(item["args"])
        if proc.returncode != 0:
            raise SystemExit(
                f"{item['slug']} --help exited {proc.returncode}\n"
                f"{proc.stderr.decode()}"
            )
        (BASELINE_DIR / item["file"]).write_bytes(proc.stdout)
    results = ROOT / "bench" / "results"
    existed = results.exists()
    proc = run_args(STUB_ARGS)
    if proc.returncode != 0:
        raise SystemExit(
            f"stub scorecard exited {proc.returncode}\n{proc.stderr.decode()}"
        )
    if results.exists() != existed:
        raise SystemExit("python -m bench run --stub changed bench/results existence")
    (BASELINE_DIR / STUB_FILE).write_bytes(proc.stdout)
    manifest = {
        "columns": "80",
        "locale": "C.UTF-8",
        "commands": commands,
        "stub_scorecard": {
            "command": "python -m bench run --stub",
            "args": STUB_ARGS,
            "file": STUB_FILE,
        },
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def test_cli_help_matches_slice1_baseline():
    """--help for every CLI entry point matches the slice 1 baseline."""
    commands = help_commands()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["commands"] == commands
    for item in commands:
        proc = run_args(item["args"])
        assert proc.returncode == 0, (item["slug"], proc.stderr.decode())
        expected = (BASELINE_DIR / item["file"]).read_bytes()
        assert proc.stdout == expected, item["slug"]


def test_bench_stub_scorecard_matches_slice1_baseline():
    """python -m bench run --stub matches the baseline and does not write bench/results."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    stub = manifest["stub_scorecard"]
    assert stub["args"] == STUB_ARGS
    assert stub["command"] == "python -m bench run --stub"
    results = ROOT / "bench" / "results"
    before = results.stat().st_mtime_ns if results.exists() else None
    proc = run_args(STUB_ARGS)
    after = results.stat().st_mtime_ns if results.exists() else None
    assert proc.returncode == 0, proc.stderr.decode()
    assert before == after
    assert proc.stdout == (BASELINE_DIR / stub["file"]).read_bytes()


if __name__ == "__main__":
    if "--write" in sys.argv:
        write_baselines()
    else:
        raise SystemExit("pass --write to regenerate tests/baselines/issue166/")
