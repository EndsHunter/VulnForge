"""Fix mojibake and normalize UI punctuation to plain ASCII-safe strings."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "vulnforge" / "ui"

# Sequences produced when UTF-8 was mis-decoded as Latin-1/CP1252 and re-saved.
# Map to plain ASCII so the browser never shows garbage like "A-·" or "x".
ASCII_MAP: list[tuple[str, str]] = [
    ("\u00c2\u00b7", " | "),  # Â·  (mojibake of ·)
    ("Â·", " | "),
    ("Ã—", " x "),
    ("â€”", " - "),
    ("â€“", "-"),
    ("â€¦", "..."),
    ("â‰ ", "!="),
    ("âš ", "!"),
    ("âš¡", "!"),
    ("âœ“", "OK"),
    ("âœ—", "X"),
    ("â–¶", ">"),
    ("â–º", ">"),
    ("â—‹", "o"),
    ("â—†", "*"),
    ("â˜ ", "!"),
    ("âšâš", "||"),
    ("â‘‚", "2"),
    ("â–¦", "#"),
    ("âŒ•", "x"),
    ("âŒ‚", ""),
    ("â†‘", "Up"),
    ("â†’", "->"),
    ("â†»", "requeue"),
    ("â€º", ">"),
    ("â–¸", ">"),
    ("â—ˆ", "*"),
    ("â€™", "'"),
    ("â€˜", "'"),
    ("â€œ", '"'),
    ("â€\x9d", '"'),
    # Proper unicode punctuation -> ASCII (stable everywhere)
    ("·", " | "),
    ("×", " x "),
    ("—", " - "),
    ("–", "-"),
    ("…", "..."),
    ("≠", "!="),
    ("→", "->"),
    ("↑", "Up"),
    ("›", ">"),
    ("▶", ">"),
    ("►", ">"),
    ("▸", ">"),
    ("⚠", "!"),
    ("✓", "OK"),
    ("✗", "X"),
    ("\u00a0", " "),  # nbsp
]


def fix_text(text: str) -> str:
    for bad, good in ASCII_MAP:
        if bad in text:
            text = text.replace(bad, good)
    # Collapse odd double spaces from replacements (keep single intentional spaces)
    while "  |  " in text:
        text = text.replace("  |  ", " | ")
    return text


def main() -> None:
    fixed: list[Path] = []
    for path in UI.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".js", ".html", ".css", ".py"}:
            continue
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        text = raw.decode("utf-8", errors="replace")
        new = fix_text(text)
        if new != text or path.read_bytes().startswith(b"\xef\xbb\xbf"):
            path.write_text(new, encoding="utf-8", newline="\n")
            fixed.append(path)
    print(f"fixed {len(fixed)} files")
    for p in fixed:
        print(f"  {p.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
