"""
Worker jobs with intentional command injection sink (fixture only — do not deploy).
"""

import subprocess


def run_export(job_name: str) -> str:
    # INTENTIONALLY VULNERABLE — mono_synth fixture
    return subprocess.check_output(f"export_tool --job {job_name}", shell=True).decode()


def cleanup_temp(path: str) -> None:
    # INTENTIONALLY VULNERABLE — mono_synth fixture
    subprocess.call(f"rm -rf {path}", shell=True)
