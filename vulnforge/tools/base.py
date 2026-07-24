"""ToolSpec — single declaration for name, schema, stages, and critical flags."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence


@dataclass(frozen=True)
class ToolSpec:
    """One model-facing agent tool.

    Schemas, allowlist membership, stage filtering, and critical-keep sets are
    derived from SPECs discovered under ``vulnforge.tools.agent``.
    """

    name: str
    stages: tuple[str, ...]
    description: str
    # OpenAI-style properties map (not the full parameters object).
    parameters: Mapping[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    # Stages where this tool must survive operator default narrowing.
    critical_for: tuple[str, ...] = ()
    # Optional per-stage description / property overrides (e.g. write_evidence).
    stage_descriptions: Mapping[str, str] = field(default_factory=dict)
    stage_parameters: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    stage_required: Mapping[str, Sequence[str]] = field(default_factory=dict)

    def description_for(self, stage: str) -> str:
        return str(self.stage_descriptions.get(stage) or self.description)

    def properties_for(self, stage: str) -> dict[str, Any]:
        override = self.stage_parameters.get(stage)
        if isinstance(override, Mapping) and override:
            return dict(override)
        return dict(self.parameters or {})

    def required_for(self, stage: str) -> list[str]:
        override = self.stage_required.get(stage)
        if override is not None:
            return [str(x) for x in override]
        return [str(x) for x in self.required]

    def openai_schema(self, stage: str | None = None) -> dict[str, Any]:
        st = stage or (self.stages[0] if self.stages else "")
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description_for(st),
                "parameters": {
                    "type": "object",
                    "properties": self.properties_for(st),
                    "required": self.required_for(st),
                },
            },
        }

    def applies_to_stage(self, stage: str) -> bool:
        if not self.stages:
            return True
        return stage in self.stages


# Callable signature for agent tool run functions.
ToolRunner = Callable[..., dict[str, Any]]
