"""Optional tree-sitter symbol extraction.

Requires ``tree-sitter`` and language grammars (e.g. ``tree-sitter-language-pack``
or individual packages). When unavailable, callers fall back to heuristic.
"""

from __future__ import annotations

from typing import Any

from vulnforge.tools.symbols.heuristic import language_for_path
from vulnforge.tools.symbols.types import symbol_id

# Capture name → normalized kind
_KIND_MAP = {
    "definition.function": "function",
    "definition.method": "method",
    "definition.class": "class",
    "definition.interface": "interface",
    "definition.type": "type",
    "definition.enum": "enum",
    "definition.module": "module",
    "definition.namespace": "module",
    "definition.macro": "macro",
    "definition.struct": "class",
    "definition.trait": "interface",
    "definition.impl": "class",
    "name.definition.function": "function",
    "name.definition.method": "method",
    "name.definition.class": "class",
    "name.definition.interface": "interface",
    "name.definition.type": "type",
    "name": "other",
}


def extract_file_symbols_tree_sitter(
    rel_path: str,
    text: str,
    *,
    max_symbols: int = 500,
    max_sig_chars: int = 240,
) -> list[dict[str, Any]]:
    """Parse *text* with tree-sitter if a grammar is available."""
    lang_id = language_for_path(rel_path)
    if not lang_id:
        return []
    try:
        import tree_sitter
    except ImportError:
        return []

    language = _load_language(lang_id)
    if language is None:
        return []

    query_src = _tags_query(lang_id)
    if not query_src:
        return []

    parser = tree_sitter.Parser(language)
    data = text.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(data)
    except Exception:
        return []

    try:
        query = tree_sitter.Query(language, query_src)
    except Exception:
        return []

    lines = text.splitlines()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    # tree-sitter 0.22+ uses QueryCursor; support both APIs
    captures: list[tuple[Any, str]] = []
    try:
        cursor = tree_sitter.QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        for _pat_idx, caps in matches:
            # caps: dict[str, list[Node]] or similar
            if isinstance(caps, dict):
                for cap_name, nodes in caps.items():
                    node_list = nodes if isinstance(nodes, list) else [nodes]
                    for node in node_list:
                        captures.append((node, str(cap_name)))
            else:
                # older: list of (node, name)
                for item in caps:
                    if isinstance(item, tuple) and len(item) == 2:
                        captures.append((item[0], str(item[1])))
    except Exception:
        try:
            # Legacy: query.captures(node) -> list[(Node, str)]
            captures = list(query.captures(tree.root_node))  # type: ignore[attr-defined]
        except Exception:
            return []

    for node, cap_name in captures:
        if len(out) >= max_symbols:
            break
        kind = _KIND_MAP.get(cap_name) or _KIND_MAP.get(
            cap_name.replace("name.", "")
        )
        if kind is None or kind == "other":
            # only accept definition-ish captures
            if "definition" not in cap_name and not cap_name.startswith("name"):
                continue
            kind = "function" if "function" in cap_name or "method" in cap_name else "other"
            if "class" in cap_name or "struct" in cap_name:
                kind = "class"
            if "interface" in cap_name or "trait" in cap_name:
                kind = "interface"
            if kind == "other" and "name" in cap_name:
                kind = "function"

        try:
            name = data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
        except Exception:
            continue
        name = name.strip()
        if not name or len(name) > 128 or "\n" in name:
            continue
        # Prefer identifier-only names
        if not name.replace("_", "").replace(".", "").isalnum() and not name[0].isalpha():
            # allow $ for JS
            if not name.startswith("$"):
                continue

        start_line = int(getattr(node, "start_point", (0, 0))[0]) + 1
        end_line = int(getattr(node, "end_point", (0, 0))[0]) + 1
        key = (name, start_line)
        if key in seen:
            continue
        seen.add(key)

        sig = ""
        if 1 <= start_line <= len(lines):
            sig = lines[start_line - 1].strip()[:max_sig_chars]
        if not sig:
            sig = name

        out.append(
            {
                "id": symbol_id(rel_path, name, start_line),
                "path": rel_path,
                "name": name,
                "kind": kind,
                "line": start_line,
                "end_line": end_line,
                "signature": sig,
                "parent": "",
                "language": lang_id,
            }
        )
    return out[:max_symbols]


def _load_language(lang_id: str):
    """Best-effort language object load."""
    # tree-sitter-language-pack style
    try:
        import tree_sitter_language_pack as tslp

        get_language = getattr(tslp, "get_language", None)
        if callable(get_language):
            # map our ids to pack names
            name = {
                "python": "python",
                "javascript": "javascript",
                "typescript": "typescript",
                "go": "go",
                "rust": "rust",
                "java": "java",
                "c": "c",
                "cpp": "cpp",
                "ruby": "ruby",
                "php": "php",
                "csharp": "csharp",
            }.get(lang_id)
            if name:
                return get_language(name)
    except Exception:
        pass

    # Individual packages: tree_sitter_python, etc.
    pkg_map = {
        "python": "tree_sitter_python",
        "javascript": "tree_sitter_javascript",
        "typescript": "tree_sitter_typescript",
        "go": "tree_sitter_go",
        "rust": "tree_sitter_rust",
        "java": "tree_sitter_java",
        "c": "tree_sitter_c",
        "cpp": "tree_sitter_cpp",
        "ruby": "tree_sitter_ruby",
        "php": "tree_sitter_php",
    }
    mod_name = pkg_map.get(lang_id)
    if not mod_name:
        return None
    try:
        import importlib

        mod = importlib.import_module(mod_name)
        if hasattr(mod, "language"):
            lang = mod.language()
            return lang
    except Exception:
        return None
    return None


def _tags_query(lang_id: str) -> str:
    """Minimal tags queries (definition names)."""
    # Compact, portable queries — not full Aider tags.scm, but enough for defs.
    queries = {
        "python": """
(function_definition name: (identifier) @name.definition.function)
(class_definition name: (identifier) @name.definition.class)
""",
        "javascript": """
(function_declaration name: (identifier) @name.definition.function)
(class_declaration name: (identifier) @name.definition.class)
(method_definition name: (property_identifier) @name.definition.method)
(lexical_declaration (variable_declarator name: (identifier) @name.definition.function))
""",
        "typescript": """
(function_declaration name: (identifier) @name.definition.function)
(class_declaration name: (type_identifier) @name.definition.class)
(method_definition name: (property_identifier) @name.definition.method)
(interface_declaration name: (type_identifier) @name.definition.interface)
""",
        "go": """
(function_declaration name: (identifier) @name.definition.function)
(method_declaration name: (field_identifier) @name.definition.method)
(type_spec name: (type_identifier) @name.definition.type)
""",
        "rust": """
(function_item name: (identifier) @name.definition.function)
(struct_item name: (type_identifier) @name.definition.class)
(enum_item name: (type_identifier) @name.definition.enum)
(trait_item name: (type_identifier) @name.definition.interface)
""",
        "java": """
(method_declaration name: (identifier) @name.definition.method)
(class_declaration name: (identifier) @name.definition.class)
(interface_declaration name: (identifier) @name.definition.interface)
(enum_declaration name: (identifier) @name.definition.enum)
""",
        "c": """
(function_definition declarator: (function_declarator declarator: (identifier) @name.definition.function))
(preproc_function_def name: (identifier) @name.definition.macro)
""",
        "cpp": """
(function_definition declarator: (function_declarator declarator: (identifier) @name.definition.function))
(class_specifier name: (type_identifier) @name.definition.class)
(struct_specifier name: (type_identifier) @name.definition.class)
""",
        "ruby": """
(method name: (identifier) @name.definition.method)
(class name: (constant) @name.definition.class)
(module name: (constant) @name.definition.module)
""",
        "php": """
(function_definition name: (name) @name.definition.function)
(method_declaration name: (name) @name.definition.method)
(class_declaration name: (name) @name.definition.class)
""",
    }
    return queries.get(lang_id, "")
