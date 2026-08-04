"""Heuristic / stdlib symbol extraction (no native deps).

Python uses the ``ast`` module. Other languages use line-oriented definition
regexes (same spirit as ``find_symbol``, but extracts *all* defs per file).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from vulnforge.tools.symbols.types import symbol_id
from vulnforge.util import normalize_relpath

# ext → language id
_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".pl": "perl",
    ".pm": "perl",
    ".ads": "ada",
    ".adb": "ada",
}

# (kind, regex) — group 1 = name; optional group for signature tail
_LINE_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "javascript": [
        ("function", re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
        )),
        ("function", re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        )),
        ("class", re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)\b")),
        ("method", re.compile(
            r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*\{"
        )),
    ],
    "typescript": [
        ("function", re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*[<(]"
        )),
        ("function", re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        )),
        ("class", re.compile(
            r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)\b"
        )),
        ("interface", re.compile(
            r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)\b"
        )),
        ("type", re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\b")),
        ("method", re.compile(
            r"^\s*(?:public|private|protected|async|static|\s)*\s*([A-Za-z_$][\w$]*)\s*\("
        )),
    ],
    "go": [
        ("function", re.compile(
            r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][\w]*)\s*\("
        )),
        ("type", re.compile(r"^\s*type\s+([A-Za-z_][\w]*)\s+")),
    ],
    "rust": [
        ("function", re.compile(
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?fn\s+([A-Za-z_][\w]*)\s*[<\(]"
        )),
        ("class", re.compile(  # struct/enum/trait treated as type containers
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+([A-Za-z_][\w]*)\b"
        )),
        ("impl", re.compile(r"^\s*impl(?:\s*<[^>]+>)?\s+(?:.*\s+for\s+)?([A-Za-z_][\w]*)")),
    ],
    "java": [
        ("class", re.compile(
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:abstract\s+)?(class|interface|enum|record)\s+([A-Za-z_][\w]*)\b"
        )),
        ("method", re.compile(
            r"^\s*(?:public|private|protected|static|final|synchronized|native|abstract|default|\s)+[\w.<>,\[\]\s]+\s+([A-Za-z_][\w]*)\s*\("
        )),
    ],
    "c": [
        ("function", re.compile(
            r"^\s*(?:static\s+|inline\s+|extern\s+)*[\w\s\*]+\b([A-Za-z_][\w]*)\s*\([^;]*\)\s*\{?\s*$"
        )),
        ("macro", re.compile(r"^\s*#\s*define\s+([A-Za-z_][\w]*)")),
    ],
    "cpp": [
        ("function", re.compile(
            r"^\s*(?:static\s+|inline\s+|extern\s+|virtual\s+|constexpr\s+)*[\w\s\*:&<>]+\b([A-Za-z_~][\w]*)\s*\([^;]*\)\s*(?:const\s*)?\{?\s*$"
        )),
        ("class", re.compile(
            r"^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct|enum(?:\s+class)?)\s+([A-Za-z_][\w]*)\b"
        )),
        ("macro", re.compile(r"^\s*#\s*define\s+([A-Za-z_][\w]*)")),
    ],
    "ruby": [
        ("function", re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_][\w?!]*)")),
        ("class", re.compile(r"^\s*class\s+([A-Za-z_][\w]*)")),
        ("module", re.compile(r"^\s*module\s+([A-Za-z_][\w]*)")),
    ],
    "php": [
        ("function", re.compile(r"^\s*(?:public|private|protected|static|\s)*function\s+([A-Za-z_][\w]*)\s*\(")),
        ("class", re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][\w]*)\b")),
    ],
    "csharp": [
        ("class", re.compile(
            r"^\s*(?:public|private|protected|internal|static|abstract|sealed|partial|\s)+class\s+([A-Za-z_][\w]*)\b"
        )),
        ("method", re.compile(
            r"^\s*(?:public|private|protected|internal|static|async|virtual|override|\s)+[\w.<>,\[\]\?]+\s+([A-Za-z_][\w]*)\s*\("
        )),
    ],
    "perl": [
        ("function", re.compile(r"^\s*sub\s+([A-Za-z_][\w]*)\b")),
        ("package", re.compile(r"^\s*package\s+([\w:]+)\s*;")),
    ],
    "ada": [
        ("function", re.compile(
            r"^\s*(?:procedure|function)\s+([A-Za-z_][\w]*)\b", re.IGNORECASE
        )),
        ("package", re.compile(r"^\s*package\s+(?:body\s+)?([A-Za-z_][\w.]*)\b", re.IGNORECASE)),
    ],
}

# javascript method pattern is noisy; skip common control keywords
_JS_METHOD_SKIP = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "function",
        "return",
        "typeof",
        "new",
        "await",
        "else",
        "try",
        "do",
        "case",
        "throw",
        "const",
        "let",
        "var",
        "class",
        "import",
        "export",
        "from",
        "default",
        "async",
    }
)

_JAVA_METHOD_SKIP = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "new",
        "else",
        "try",
        "do",
        "case",
        "throw",
        "class",
        "interface",
        "enum",
        "record",
        "package",
        "import",
    }
)


def language_for_path(path: str) -> str:
    ext = Path(path).suffix.lower()
    return _EXT_LANG.get(ext, "")


def extract_file_symbols(
    rel_path: str,
    text: str,
    *,
    max_symbols: int = 500,
    max_sig_chars: int = 240,
) -> list[dict[str, Any]]:
    """Extract definition symbols from one file's text."""
    rel = normalize_relpath(rel_path)
    lang = language_for_path(rel)
    if not lang:
        return []
    if lang == "python":
        return _extract_python(rel, text, max_symbols=max_symbols, max_sig_chars=max_sig_chars)
    # typescript shares most JS patterns already listed under typescript key
    patterns = _LINE_PATTERNS.get(lang) or _LINE_PATTERNS.get(
        "javascript" if lang in ("javascript",) else ""
    )
    if not patterns:
        return []
    return _extract_line_patterns(
        rel,
        text,
        lang,
        patterns,
        max_symbols=max_symbols,
        max_sig_chars=max_sig_chars,
    )


def _extract_python(
    rel: str,
    text: str,
    *,
    max_symbols: int,
    max_sig_chars: int,
) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _extract_python_regex(rel, text, max_symbols=max_symbols, max_sig_chars=max_sig_chars)

    out: list[dict[str, Any]] = []
    lines = text.splitlines()

    def line_sig(lineno: int) -> str:
        if lineno < 1 or lineno > len(lines):
            return ""
        return lines[lineno - 1].strip()[:max_sig_chars]

    def walk(nodes: list[ast.AST], parent: str = "") -> None:
        for node in nodes:
            if len(out) >= max_symbols:
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
                kind = "method" if parent else "function"
                start = int(getattr(node, "lineno", 0) or 0)
                end = int(getattr(node, "end_lineno", None) or start)
                sig = line_sig(start)
                if not sig:
                    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
                    sig = f"{prefix} {name}(...)"
                out.append(
                    {
                        "id": symbol_id(rel, name, start),
                        "path": rel,
                        "name": name,
                        "kind": kind,
                        "line": start,
                        "end_line": end,
                        "signature": sig,
                        "parent": parent,
                        "language": "python",
                    }
                )
                # do not recurse into nested functions for parent chain of methods
                # but still collect nested defs with this function as parent
                walk(list(node.body), parent=name)
            elif isinstance(node, ast.ClassDef):
                name = node.name
                start = int(getattr(node, "lineno", 0) or 0)
                end = int(getattr(node, "end_lineno", None) or start)
                sig = line_sig(start) or f"class {name}"
                out.append(
                    {
                        "id": symbol_id(rel, name, start),
                        "path": rel,
                        "name": name,
                        "kind": "class",
                        "line": start,
                        "end_line": end,
                        "signature": sig,
                        "parent": parent,
                        "language": "python",
                    }
                )
                walk(list(node.body), parent=name)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncWith, ast.AsyncFor)):
                body = list(getattr(node, "body", []) or [])
                body += list(getattr(node, "orelse", []) or [])
                if isinstance(node, ast.Try):
                    for h in node.handlers:
                        body += list(h.body or [])
                    body += list(node.finalbody or [])
                walk(body, parent=parent)

    walk(list(tree.body), parent="")
    return out[:max_symbols]


def _extract_python_regex(
    rel: str,
    text: str,
    *,
    max_symbols: int,
    max_sig_chars: int,
) -> list[dict[str, Any]]:
    patterns = [
        ("function", re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(")),
        ("class", re.compile(r"^(\s*)class\s+([A-Za-z_][\w]*)\b")),
    ]
    out: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []  # (indent, name)
    for i, line in enumerate(text.splitlines(), 1):
        if len(out) >= max_symbols:
            break
        for kind, rx in patterns:
            m = rx.match(line)
            if not m:
                continue
            indent = len(m.group(1).replace("\t", "    "))
            name = m.group(2)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else ""
            skind = "method" if kind == "function" and parent else kind
            out.append(
                {
                    "id": symbol_id(rel, name, i),
                    "path": rel,
                    "name": name,
                    "kind": skind,
                    "line": i,
                    "end_line": i,
                    "signature": line.strip()[:max_sig_chars],
                    "parent": parent,
                    "language": "python",
                }
            )
            if kind == "class":
                stack.append((indent, name))
            break
    return out


def _extract_line_patterns(
    rel: str,
    text: str,
    lang: str,
    patterns: list[tuple[str, re.Pattern[str]]],
    *,
    max_symbols: int,
    max_sig_chars: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for i, line in enumerate(text.splitlines(), 1):
        if len(out) >= max_symbols:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for kind, rx in patterns:
            m = rx.search(line)
            if not m:
                continue
            # java class pattern has kind word in group 1
            if lang == "java" and kind == "class" and m.lastindex and m.lastindex >= 2:
                name = m.group(2)
                jkind = m.group(1)
                if jkind == "interface":
                    kind = "interface"
                elif jkind == "enum":
                    kind = "enum"
                elif jkind == "record":
                    kind = "class"
                else:
                    kind = "class"
            else:
                name = m.group(1) if m.lastindex else ""
            if not name or not re.match(r"^[A-Za-z_~$]", name):
                continue
            if lang in ("javascript", "typescript") and kind == "method":
                if name in _JS_METHOD_SKIP:
                    continue
                # skip likely property assignments without being in class body heuristic:
                # require not starting at column 0-ish for methods... keep simple
            if lang == "java" and kind == "method" and name in _JAVA_METHOD_SKIP:
                continue
            if lang == "rust" and kind == "impl":
                kind = "class"
            if lang in ("perl", "ada") and kind == "package":
                kind = "module"
            key = (name, i)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "id": symbol_id(rel, name, i),
                    "path": rel,
                    "name": name,
                    "kind": kind if kind != "impl" else "class",
                    "line": i,
                    "end_line": i,
                    "signature": stripped[:max_sig_chars],
                    "parent": "",
                    "language": lang,
                }
            )
            break
    return out
