"""Load the hand-verified seed. Quotes must sit on the oracle line."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
SEED_DIR = PACKAGE_DIR / "seed"


@dataclass(frozen=True)
class Oracle:
    path: str
    line: int
    symbol: str
    quote: str
    cwe: str


@dataclass(frozen=True)
class Task:
    id: str
    kind: str
    cwe: str | None
    component: str
    disclosure_date: str | None
    split: str
    difficulty_levels: tuple[str, ...]
    oracle: Oracle | None
    vulnerable: Path | None
    fixed: Path | None
    tree: Path | None
    content_hash: str

    def side_root(self, side: str) -> Path:
        if side == "vulnerable":
            if self.vulnerable is None:
                raise KeyError(side)
            return self.vulnerable
        if side == "fixed":
            if self.fixed is None:
                raise KeyError(side)
            return self.fixed
        if side == "benign":
            if self.tree is None:
                raise KeyError(side)
            return self.tree
        raise KeyError(side)


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _check_oracle(root: Path, oracle: Oracle) -> None:
    file_path = root / oracle.path
    if not file_path.is_file():
        raise ValueError(f"oracle file missing: {file_path}")
    lines = file_path.read_text(encoding="utf-8").splitlines()
    if oracle.line < 1 or oracle.line > len(lines):
        raise ValueError(f"{oracle.path}:{oracle.line} out of range")
    if oracle.quote not in lines[oracle.line - 1]:
        raise ValueError(
            f"oracle quote not on {oracle.path}:{oracle.line}: {lines[oracle.line - 1]!r}"
        )


def load_tasks() -> list[Task]:
    manifest = json.loads((SEED_DIR / "manifest.json").read_text(encoding="utf-8"))
    levels = tuple(manifest.get("difficulty_levels") or ["L0", "L1"])
    tasks: list[Task] = []
    for raw in manifest["tasks"]:
        kind = raw["kind"]
        split = raw["split"]
        if split not in {"train", "dev", "held_out"}:
            raise ValueError(f"{raw['id']} split must include held_out domain")
        oracle = None
        vulnerable = fixed = tree = None
        if kind == "pair":
            vulnerable = SEED_DIR / raw["vulnerable"]
            fixed = SEED_DIR / raw["fixed"]
            body = raw["oracle"]
            oracle = Oracle(
                path=body["path"],
                line=int(body["line"]),
                symbol=body["symbol"],
                quote=body["quote"],
                cwe=raw["cwe"],
            )
            _check_oracle(vulnerable, oracle)
            content = tree_hash(vulnerable)
        elif kind == "benign":
            tree = SEED_DIR / raw["tree"]
            if not tree.is_dir():
                raise ValueError(f"missing benign tree {tree}")
            content = tree_hash(tree)
        else:
            raise ValueError(f"unknown kind {kind}")
        tasks.append(
            Task(
                id=raw["id"],
                kind=kind,
                cwe=raw.get("cwe"),
                component=raw["component"],
                disclosure_date=raw.get("disclosure_date"),
                split=split,
                difficulty_levels=levels,
                oracle=oracle,
                vulnerable=vulnerable,
                fixed=fixed,
                tree=tree,
                content_hash=content,
            )
        )
    pairs = [task for task in tasks if task.kind == "pair"]
    benign = [task for task in tasks if task.kind == "benign"]
    if len(pairs) < 1 or len(benign) < 1:
        raise ValueError("seed needs pairs and benign controls")
    if not any(task.split == "held_out" for task in tasks):
        raise ValueError("seed needs a held_out split")
    return tasks


def load_canaries() -> dict:
    return json.loads((SEED_DIR / "canaries.json").read_text(encoding="utf-8"))
