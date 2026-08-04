"""Shared types for codemap symbol extraction."""

from __future__ import annotations

from typing import Any, TypedDict


class SymbolRecord(TypedDict, total=False):
    id: str
    path: str
    module_id: str
    name: str
    kind: str
    line: int
    end_line: int
    signature: str
    parent: str
    language: str


class FileRecord(TypedDict, total=False):
    path: str
    module_id: str
    language: str
    symbol_count: int


def symbol_id(path: str, name: str, line: int) -> str:
    return f"sym:{path}:{name}:{line}"


def as_symbol_dict(rec: dict[str, Any]) -> dict[str, Any]:
    """Normalize a symbol record for JSON storage."""
    out: dict[str, Any] = {
        "id": str(rec.get("id") or ""),
        "path": str(rec.get("path") or ""),
        "module_id": str(rec.get("module_id") or ""),
        "name": str(rec.get("name") or ""),
        "kind": str(rec.get("kind") or "other"),
        "line": int(rec.get("line") or 0),
        "end_line": int(rec.get("end_line") or rec.get("line") or 0),
        "signature": str(rec.get("signature") or "")[:500],
        "parent": str(rec.get("parent") or ""),
        "language": str(rec.get("language") or ""),
    }
    if not out["id"] and out["path"] and out["name"]:
        out["id"] = symbol_id(out["path"], out["name"], out["line"])
    return out
