"""
Ingest operator documentation into a compact run-scoped digest.

Supports common text formats with optional extras (pypdf, openpyxl).
No hard dependency on python-docx — .docx is zip+XML.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

# Caps for a single digest used in recon packets / operator brief.
MAX_FILES = 40
MAX_CHARS_TOTAL = 12_000
MAX_CHARS_PER_FILE = 4_000

_TEXT_EXTS = {".md", ".txt", ".text", ".rst", ".log"}
_HTML_EXTS = {".html", ".htm"}
_DOCX_EXTS = {".docx"}
_XLSX_EXTS = {".xlsx"}
_CSV_EXTS = {".csv", ".tsv"}
_PDF_EXTS = {".pdf"}

_SUPPORTED = (
    _TEXT_EXTS | _HTML_EXTS | _DOCX_EXTS | _XLSX_EXTS | _CSV_EXTS | _PDF_EXTS
)


def _ascii_safe(text: str) -> str:
    """Coerce to ASCII-safe text for cross-platform digests."""
    if not text:
        return ""
    # Normalize newlines; drop NULs; replace non-ASCII with ?
    cleaned = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    return cleaned.encode("ascii", errors="replace").decode("ascii")


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 20)] + "\n...[truncated]...\n"


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style", "noscript"):
            self._skip = False
        if tag.lower() in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4"):
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip and data:
            self._chunks.append(data)

    def text(self) -> str:
        raw = "".join(self._chunks)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def extract_html(data: bytes | str) -> str:
    if isinstance(data, bytes):
        try:
            s = data.decode("utf-8")
        except UnicodeDecodeError:
            s = data.decode("latin-1", errors="replace")
    else:
        s = data
    p = _HTMLTextExtractor()
    try:
        p.feed(s)
        p.close()
    except Exception:
        # Best-effort strip tags
        return re.sub(r"<[^>]+>", " ", s)
    return p.text()


def extract_text_file(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def extract_docx(path: Path) -> str:
    """Read Word .docx via zipfile + document.xml (no python-docx)."""
    parts: list[str] = []
    with zipfile.ZipFile(path, "r") as zf:
        name = "word/document.xml"
        if name not in zf.namelist():
            return ""
        xml = zf.read(name)
    # WordprocessingML uses w:t for text runs
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return ""
    # Namespace-agnostic: match localname 't'
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1] if "}" in el.tag else el.tag
        if tag == "t" and el.text:
            parts.append(el.text)
        elif tag == "tab":
            parts.append("\t")
        elif tag in ("br", "cr"):
            parts.append("\n")
        elif tag == "p":
            parts.append("\n")
    text = "".join(parts)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_xlsx(path: Path) -> str:
    """Extract spreadsheet text; prefer openpyxl, else zip-xml best-effort."""
    try:
        import openpyxl  # type: ignore

        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        lines: list[str] = []
        for sheet in wb.worksheets:
            lines.append(f"[sheet: {sheet.title}]")
            for row in sheet.iter_rows(values_only=True):
                cells = [str(c) if c is not None else "" for c in row]
                if any(cells):
                    lines.append("\t".join(cells))
        wb.close()
        return "\n".join(lines)
    except ImportError:
        pass
    except Exception as e:
        return f"[xlsx openpyxl error: {e}]"

    # Best-effort: sharedStrings + first sheet cells from zip
    try:
        with zipfile.ZipFile(path, "r") as zf:
            shared: list[str] = []
            if "xl/sharedStrings.xml" in zf.namelist():
                root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in root.iter():
                    tag = si.tag.rsplit("}", 1)[-1]
                    if tag == "t" and si.text:
                        shared.append(si.text)
            # Collect sheet XML names
            sheet_names = sorted(
                n for n in zf.namelist() if n.startswith("xl/worksheets/sheet")
            )
            lines = []
            for sn in sheet_names[:5]:
                lines.append(f"[sheet: {sn}]")
                try:
                    sroot = ET.fromstring(zf.read(sn))
                except ET.ParseError:
                    continue
                for c in sroot.iter():
                    tag = c.tag.rsplit("}", 1)[-1]
                    if tag != "v" or not c.text:
                        continue
                    # If parent has t="s", value is shared string index
                    parent = None  # ElementTree has no parent; print raw
                    lines.append(c.text)
                    if shared:
                        try:
                            idx = int(c.text)
                            if 0 <= idx < len(shared):
                                lines[-1] = shared[idx]
                        except ValueError:
                            pass
            return "\n".join(lines[:500])
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        return f"[xlsx zip-xml fallback failed: {e}]"


def extract_csv(path: Path) -> str:
    try:
        text = extract_text_file(path)
    except OSError as e:
        return f"[csv read error: {e}]"
    delim = "\t" if path.suffix.lower() == ".tsv" else ","
    out: list[str] = []
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        for i, row in enumerate(reader):
            if i >= 200:
                out.append("...[csv rows truncated]...")
                break
            out.append("\t".join(row))
    except csv.Error:
        return text
    return "\n".join(out)


def extract_pdf(path: Path) -> tuple[str, str | None]:
    """Return (text, warning). Skip with note if pypdf unavailable."""
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError:
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except ImportError:
            return "", "pdf skipped (pypdf not installed)"

    try:
        reader = PdfReader(str(path))
        chunks: list[str] = []
        for page in reader.pages[:40]:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            if t:
                chunks.append(t)
        return "\n".join(chunks), None
    except Exception as e:
        return "", f"pdf extract failed: {e}"


def extract_one(path: Path) -> tuple[str, str | None]:
    """Extract text from one file. Returns (text, optional_warning)."""
    ext = path.suffix.lower()
    try:
        if ext in _TEXT_EXTS:
            return extract_text_file(path), None
        if ext in _HTML_EXTS:
            return extract_html(path.read_bytes()), None
        if ext in _DOCX_EXTS:
            return extract_docx(path), None
        if ext in _XLSX_EXTS:
            return extract_xlsx(path), None
        if ext in _CSV_EXTS:
            return extract_csv(path), None
        if ext in _PDF_EXTS:
            return extract_pdf(path)
    except OSError as e:
        return "", f"read error {path.name}: {e}"
    return "", f"unsupported extension: {ext}"


def _collect_doc_files(docs_path: Path) -> list[Path]:
    docs_path = Path(docs_path)
    if docs_path.is_file():
        return [docs_path]
    if not docs_path.is_dir():
        return []
    files: list[Path] = []
    for p in sorted(docs_path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() in _SUPPORTED:
            files.append(p)
        if len(files) >= MAX_FILES * 2:
            # gather a bit extra then cap later by successful extract
            break
    return files


def ingest_docs(docs_path: Path, out_digest: Path) -> dict[str, Any]:
    """
    Ingest docs_path (file or directory) into out_digest markdown.

    Returns dict: {files: int, chars: int, warnings: list[str], summary: str, digest_path: str}
    """
    docs_path = Path(docs_path).resolve()
    out_digest = Path(out_digest)
    warnings: list[str] = []
    if not docs_path.exists():
        warnings.append(f"docs_path not found: {docs_path}")
        out_digest.parent.mkdir(parents=True, exist_ok=True)
        out_digest.write_text(
            f"# Docs digest\n\n(no content — {warnings[0]})\n",
            encoding="utf-8",
            newline="\n",
        )
        return {
            "files": 0,
            "chars": 0,
            "warnings": warnings,
            "summary": warnings[0],
            "digest_path": str(out_digest),
        }

    candidates = _collect_doc_files(docs_path)
    if not candidates:
        warnings.append(f"no supported doc files under {docs_path}")

    sections: list[str] = []
    used_files = 0
    total_chars = 0
    file_labels: list[str] = []

    header = (
        "# Docs digest\n\n"
        f"Source: `{docs_path}`\n\n"
        "ASCII-safe extract for recon operator brief. Caps: "
        f"max_files={MAX_FILES}, max_chars~={MAX_CHARS_TOTAL}.\n\n"
    )
    budget = MAX_CHARS_TOTAL - len(header)

    for path in candidates:
        if used_files >= MAX_FILES or budget <= 200:
            if used_files >= MAX_FILES:
                warnings.append(f"file cap ({MAX_FILES}) reached; remaining skipped")
            else:
                warnings.append("char budget exhausted; remaining files skipped")
            break
        text, warn = extract_one(path)
        if warn:
            warnings.append(f"{path.name}: {warn}")
        if not text or not text.strip():
            if not warn:
                warnings.append(f"{path.name}: empty extract")
            continue
        try:
            rel = path.name if path.parent == docs_path or path == docs_path else str(
                path.relative_to(docs_path if docs_path.is_dir() else docs_path.parent)
            )
        except ValueError:
            rel = path.name
        rel = rel.replace("\\", "/")
        body = _ascii_safe(text)
        body = _truncate(body, min(MAX_CHARS_PER_FILE, budget - 80))
        section = f"## {rel}\n\n{body.strip()}\n\n"
        if len(section) > budget:
            section = _truncate(section, budget)
        sections.append(section)
        used_files += 1
        total_chars += len(body)
        budget -= len(section)
        file_labels.append(rel)

    body_joined = "".join(sections) if sections else "(no extractable content)\n"
    digest = header + body_joined
    if warnings:
        digest += "\n## Ingest warnings\n\n"
        for w in warnings:
            digest += f"- {_ascii_safe(w)}\n"

    out_digest.parent.mkdir(parents=True, exist_ok=True)
    out_digest.write_text(_ascii_safe(digest), encoding="utf-8", newline="\n")

    # Short summary for operator_brief (not the full digest)
    summary_bits = [
        f"Docs ingest: {used_files} file(s), ~{total_chars} chars from {docs_path}."
    ]
    if file_labels:
        shown = ", ".join(file_labels[:12])
        more = f" (+{len(file_labels) - 12} more)" if len(file_labels) > 12 else ""
        summary_bits.append(f"Files: {shown}{more}.")
    if warnings:
        summary_bits.append(f"Warnings: {len(warnings)} (see docs_digest.md).")
    summary_bits.append(
        "Use this documentation when mapping architecture and hunt_focus; "
        "prefer documented trust boundaries and input surfaces."
    )
    summary = _ascii_safe(" ".join(summary_bits))

    return {
        "files": used_files,
        "chars": total_chars,
        "warnings": warnings,
        "summary": summary,
        "digest_path": str(out_digest.resolve()),
        "file_labels": file_labels,
    }
