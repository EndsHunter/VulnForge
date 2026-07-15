"""Build an expanded mono_synth tree under tmp_path for large-repo plan tests.

On-disk seed lives in ``fixtures/mono_synth/`` (real packages/auth|api|worker|ui).
This helper copies the seed and generates enough extra files so:

- ``file_count`` > 500 (H2 sample cap, H3 monorepo hard-cap)
- a **canary** sink path sorts *after* the first 500 sorted paths
  (``build_file_index`` uses ``sorted(target_root.rglob("*"))`` then
  ``sample_paths = files[:500]``)

Lexicographic relative-path order (``b`` < ``p`` < ``z``)::

    bulk/f0000.py â€¦ bulk/f{N-1}.py     # pad â€” fills sample_paths first
    packages/â€¦                         # seed sinks (may fall outside sample)
    pyproject.toml
    zzz_canary/deep/canary_sink.py     # CANARY â€” always past sample_paths[:500]
                                       # when n_bulk >= 520
"""

from __future__ import annotations

import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MONO_SYNTH_SEED = PROJECT_ROOT / "fixtures" / "mono_synth"

# Must sort after bulk/* and packages/* under sorted(rglob).
CANARY_REL = "zzz_canary/deep/canary_sink.py"
CANARY_MARKER = "CANARY_SQL_SINK_MONO_SYNTH"
BULK_DIR = "bulk"
DEFAULT_N_BULK = 520


def build_mono_synth(
    dest: Path,
    *,
    n_bulk: int = DEFAULT_N_BULK,
    seed: Path | None = None,
) -> Path:
    """Copy seed monorepo into *dest* and pad with bulk + canary files.

    Returns the target root (same as *dest*).
    """
    seed_root = Path(seed or MONO_SYNTH_SEED)
    if not seed_root.is_dir():
        raise FileNotFoundError(f"mono_synth seed missing: {seed_root}")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    # Copy seed tree (packages/*, pyproject.toml, â€¦)
    for item in seed_root.iterdir():
        target = dest / item.name
        if item.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    bulk = dest / BULK_DIR
    bulk.mkdir(parents=True, exist_ok=True)
    for i in range(int(n_bulk)):
        p = bulk / f"f{i:04d}.py"
        p.write_text(f"# pad file {i}\n", encoding="utf-8")

    canary = dest.joinpath(*CANARY_REL.split("/"))
    canary.parent.mkdir(parents=True, exist_ok=True)
    canary.write_text(
        f'"""Late-sorted canary sink â€” intentionally after sample_paths[:500]."""\n'
        f"# {CANARY_MARKER}\n"
        f"def canary_query(db, q):\n"
        f"    return db.execute(f\"SELECT * FROM t WHERE x = '{{q}}'\")\n",
        encoding="utf-8",
    )
    return dest


def canary_relative_path() -> str:
    """POSIX-style relative path of the canary (matches normalize_relpath)."""
    return CANARY_REL
