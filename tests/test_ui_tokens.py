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
    "--bg": "#0b0f14",
    "--bg-elev": "#10161e",
    "--bg-card": "#141b24",
    "--bg-card-hover": "#1a232e",
    "--bg-header": "#0e141c",
    "--bg-inset": "#0a0e13",
    "--bg-logo": "#121820",
    "--border": "#243044",
    "--border-strong": "#33465c",
    "--text": "#e8eef6",
    "--text-bright": "#f4f7fb",
    "--text-soft": "#c5d0e0",
    "--text-body-muted": "#c5d0e0",
    "--muted": "#8b9bb0",
    "--accent": "#f97316",
    "--accent-dim": "#9a4a12",
    "--accent-mid": "#ea6a12",
    "--accent-bright": "#fb923c",
    "--accent-hover": "#c25c10",
    "--kpi-tasks": "#3b82f6",
    "--kpi-human": "#f97316",
    "--kpi-coverage": "#22c55e",
    "--btn-hover-bg": "#1a232e",
    "--tone-muted-border": "#33465c",
    "--tone-muted-bg": "#141b24",
    "--panel-deep": "#10161e",
    "--panel-mid": "#141b24",
    "--arch-mix": "#1a232e",
}

MONACO_PAIRING = {
    "#0a0e13": "--bg-inset",
    "#e8eef6": "--text",
    "#8b9bb0": "--muted",
    "#f97316": "--accent",
    "#fb923c": "--accent-bright",
    "#141b24": "--bg-card",
    "#1a232e": "--bg-card-hover",
    "#243044": "--border",
    "#33465c": "--border-strong",
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
