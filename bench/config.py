"""Bench config. Live runs use an OpenAI-compatible base_url."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent


def _as_str(value: object) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()  # type: ignore[no-any-return]
    return str(value)


@dataclass
class ModelSpec:
    id: str
    name: str
    knowledge_cutoff: str


@dataclass
class BenchConfig:
    base_url: str = "http://10.0.0.232:1234/v1"
    api_key_env: str = "OPENAI_API_KEY"
    models: list[ModelSpec] = field(default_factory=list)
    k: int = 3
    workers: int = 4
    timeout_s: float = 120.0
    temperature: float = 0.0
    difficulties: list[str] = field(default_factory=lambda: ["L0", "L1"])
    fpr_cap: float = 0.005
    false_reject_max: float = 0.10
    on_breach: str = "warn"
    prompt_version: str = "bench-1"

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError("k must be >= 1")
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.on_breach not in {"warn", "fail"}:
            raise ValueError("disprove.on_breach must be warn or fail")
        if not self.difficulties:
            raise ValueError("difficulties must list L0 and/or L1")


def default_config_path() -> Path:
    cwd = Path("bench/config.yaml")
    if cwd.is_file():
        return cwd
    return PACKAGE_DIR / "config.yaml"


def load_config(path: Path | None = None) -> BenchConfig:
    cfg_path = path or default_config_path()
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    disprove = raw.get("disprove") or {}
    models = [
        ModelSpec(
            id=str(item["id"]),
            name=str(item.get("name") or item["id"]),
            knowledge_cutoff=_as_str(item["knowledge_cutoff"]),
        )
        for item in (raw.get("models") or [])
    ]
    return BenchConfig(
        base_url=str(raw.get("base_url") or "http://10.0.0.232:1234/v1").rstrip("/"),
        api_key_env=str(raw.get("api_key_env") or "OPENAI_API_KEY"),
        models=models,
        k=int(raw.get("k") or 3),
        workers=int(raw.get("workers") or 4),
        timeout_s=float(raw.get("timeout_s") or 120),
        temperature=float(raw.get("temperature") or 0),
        difficulties=[str(item) for item in (raw.get("difficulties") or ["L0", "L1"])],
        fpr_cap=float(raw.get("fpr_cap") if raw.get("fpr_cap") is not None else 0.005),
        false_reject_max=float(
            disprove.get("false_reject_max")
            if disprove.get("false_reject_max") is not None
            else 0.10
        ),
        on_breach=str(disprove.get("on_breach") or "warn"),
        prompt_version=str(raw.get("prompt_version") or "bench-1"),
    )
