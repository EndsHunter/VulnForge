"""The one-command installers must agree with pyproject and stay runnable."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _min_minor_from_pyproject() -> int:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    m = re.fullmatch(r">=3\.(\d+)", data["project"]["requires-python"])
    assert m, "requires-python changed shape; update install.sh / install.ps1 and this test"
    return int(m.group(1))


def test_installers_enforce_the_same_python_floor_as_pyproject():
    want = _min_minor_from_pyproject()
    sh = (ROOT / "install.sh").read_text(encoding="utf-8")
    ps = (ROOT / "install.ps1").read_text(encoding="utf-8")
    assert int(re.search(r"^MIN_MINOR=(\d+)", sh, re.M).group(1)) == want
    assert int(re.search(r"^\$MinMinor = (\d+)", ps, re.M).group(1)) == want


@pytest.mark.parametrize("name", ["install.sh", "start.sh"])
def test_shell_scripts_parse_and_are_executable(name):
    sh = shutil.which("sh")
    if sh is None or os.name == "nt":
        pytest.skip("POSIX sh not available")
    path = ROOT / name
    assert b"\r" not in path.read_bytes(), f"{name} must use LF line endings"
    subprocess.run([sh, "-n", str(path)], check=True)
    assert os.access(path, os.X_OK), f"{name} lost its executable bit"


def test_install_sh_help_does_not_install(tmp_path):
    sh = shutil.which("sh")
    if sh is None or os.name == "nt":
        pytest.skip("POSIX sh not available")
    out = subprocess.run(
        [sh, str(ROOT / "install.sh"), "--help"],
        capture_output=True, text=True, check=True, cwd=tmp_path,
    ).stdout
    assert "--recreate" in out and "--yes" in out


def test_readme_leads_with_the_installer():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quick = readme.split("## Quickstart", 1)[1].split("\n## ", 1)[0]
    for needle in ("./install.sh", "./start.sh", "install.cmd", "start.cmd"):
        assert needle in quick, f"README Quickstart no longer mentions {needle}"
    for script in ("install.sh", "start.sh", "install.ps1", "start.ps1", "install.cmd", "start.cmd"):
        assert (ROOT / script).is_file(), f"{script} is documented but missing"


def test_vf_survives_a_non_utf8_stdout(tmp_path):
    """Windows pipes/redirects are cp1252; `vf --help` has an arrow in it.

    The installer verifies with `vf --help | Out-Null`, so this crashed install on
    Windows CI before vulnforge.stdio.ensure_utf8_stdio.
    """
    import sys

    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    for argv in (["-m", "vulnforge.cli", "--help"], [str(ROOT / "scripts" / "ralph.py"), "--help"]):
        proc = subprocess.run(
            [sys.executable, *argv], capture_output=True, env=env, cwd=ROOT,
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
