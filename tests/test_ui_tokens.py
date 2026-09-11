"""Cockpit palette: token table, magenta leftovers, contrast floors."""

from __future__ import annotations

import re
from pathlib import Path

from vulnforge.paths import PROJECT_ROOT

STATIC = PROJECT_ROOT / "vulnforge" / "ui" / "static"
TEMPLATES = PROJECT_ROOT / "vulnforge" / "ui" / "templates"
STYLES = STATIC / "styles.css"
MONACO = STATIC / "monaco_loader.js"

MAGENTA_NEEDLES = ("#ff3d6e", "#ff7a9a", "255, 61, 110", "255,61,110")

EXPECTED = {
    "--bg": "#1b1c21",
    "--bg-elev": "#1f2026",
    "--bg-card": "#26272e",
    "--bg-card-hover": "#2c2d35",
    "--bg-header": "#141518",
    "--bg-inset": "#121317",
    "--bg-logo": "#26272e",
    "--border": "#2d2e32",
    "--border-strong": "#3a3b40",
    "--text": "#ece7dc",
    "--text-bright": "#f4f0e6",
    "--text-soft": "#c8c2b4",
    "--text-body-muted": "#c8c2b4",
    "--muted": "#9a9488",
    "--accent": "#6aa8a2",
    "--accent-dim": "#3d6a66",
    "--accent-mid": "#5b9690",
    "--accent-bright": "#8bc0bb",
    "--accent-hover": "#5c9691",
    "--kpi-tasks": "#6aa8a2",
    "--kpi-human": "#e3a01a",
    "--kpi-coverage": "#7db392",
    "--btn-hover-bg": "#2c2d35",
    "--tone-muted-border": "#3a3b40",
    "--tone-muted-bg": "#26272e",
    "--panel-deep": "#1f2026",
    "--panel-mid": "#26272e",
    "--arch-mix": "#2c2d35",
}

MONACO_PAIRING = {
    "#121317": "--bg-inset",
    "#ece7dc": "--text",
    "#9a9488": "--muted",
    "#6aa8a2": "--accent",
    "#8bc0bb": "--accent-bright",
    "#26272e": "--bg-card",
    "#2c2d35": "--bg-card-hover",
    "#2d2e32": "--border",
    "#3a3b40": "--border-strong",
}


def _iter_ui_files():
    for root in (STATIC, TEMPLATES):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "vendor" in path.parts:
                continue
            yield path


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _root_block(css: str) -> str:
    m = re.search(r":root\s*\{", css)
    assert m, ":root block missing in styles.css"
    start = m.end()
    depth = 1
    i = start
    while i < len(css) and depth:
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
        i += 1
    return css[start : i - 1]


def _parse_hex_vars(block: str) -> dict[str, str]:
    found = {}
    for m in re.finditer(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", block):
        found[m.group(1)] = m.group(2).lower()
    return found


def _channel(c: float) -> float:
    c = c / 255.0
    if c <= 0.04045:
        return c / 12.92
    return ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast_ratio(a: str, b: str) -> float:
    l1 = relative_luminance(a)
    l2 = relative_luminance(b)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_no_magenta_literals_in_ui():
    hits = []
    for path in _iter_ui_files():
        text = _read_text(path)
        if text is None:
            continue
        lower = text.lower()
        for needle in MAGENTA_NEEDLES:
            if needle.lower() in lower:
                hits.append(f"{path.relative_to(PROJECT_ROOT)} contains {needle}")
    assert hits == [], "magenta leftovers:\n" + "\n".join(hits)


def test_root_tokens_match_design_table():
    block = _root_block(STYLES.read_text(encoding="utf-8"))
    found = _parse_hex_vars(block)
    missing = [name for name in EXPECTED if name not in found]
    assert missing == [], f"missing tokens: {missing}"
    wrong = {
        name: (EXPECTED[name], found[name])
        for name in EXPECTED
        if found[name] != EXPECTED[name]
    }
    assert wrong == {}, f"token mismatches: {wrong}"


def test_text_and_muted_contrast():
    block = _root_block(STYLES.read_text(encoding="utf-8"))
    found = _parse_hex_vars(block)
    body = contrast_ratio(found["--text"], found["--bg"])
    muted_card = contrast_ratio(found["--muted"], found["--bg-card"])
    muted_elev = contrast_ratio(found["--muted"], found["--bg-elev"])
    assert body >= 4.5, f"--text on --bg contrast {body:.2f} < 4.5"
    assert muted_card >= 3.0, f"--muted on --bg-card contrast {muted_card:.2f} < 3.0"
    assert muted_elev >= 3.0, (
        f"--muted on --bg-elev contrast {muted_elev:.2f} < 3.0 (idle rail labels)"
    )


def test_monaco_hex_pairs_to_tokens():
    text = MONACO.read_text(encoding="utf-8")
    lower = text.lower()
    assert "var(--" not in text, (
        "monaco.editor.defineTheme does not accept CSS variables"
    )
    missing = []
    drifted = []
    for hex_color, token in MONACO_PAIRING.items():
        expected = EXPECTED.get(token)
        if expected != hex_color:
            drifted.append(f"{hex_color} -> {token} (EXPECTED has {expected})")
        if hex_color.lstrip("#").lower() not in lower:
            missing.append(f"{hex_color} ({token})")
    assert drifted == [], f"monaco pairing disagrees with EXPECTED: {drifted}"
    assert missing == [], f"monaco missing pairing hex: {missing}"
    leftovers = [n for n in ("#ff3d6e", "#ff7a9a") if n in lower]
    assert leftovers == [], f"monaco still has magenta hex: {leftovers}"
