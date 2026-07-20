"""Agent-facing curated Ghidra tools (binary_re profile)."""

from __future__ import annotations

from typing import Any

from vulnforge.ghidra.client import GhidraClient, GhidraError

# Cap client-side scans when filtering imports (avoid dumping huge IAT tables).
_MAX_IMPORTS_SCAN = 2000
_IMPORT_CALLERS_LIMIT_CAP = 50


def _client(ctx: dict) -> GhidraClient:
    c = ctx.get("ghidra_client")
    # Duck-typed client (tests inject fakes; runtime uses GhidraClient)
    if c is not None and hasattr(c, "check_connection"):
        return c  # type: ignore[return-value]
    from vulnforge.ghidra.runtime import client_from_cfg

    cfg = ctx.get("cfg") or {}
    return client_from_cfg(cfg if isinstance(cfg, dict) else {})


def _cap_text(val: Any, max_chars: int) -> Any:
    if isinstance(val, str) and len(val) > max_chars:
        return val[: max_chars - 20] + "\n...[truncated]..."
    if isinstance(val, dict):
        # common keys holding large decomp text
        out = dict(val)
        for k in ("decompiled", "decompilation", "code", "text", "result"):
            if k in out and isinstance(out[k], str) and len(out[k]) > max_chars:
                out[k] = out[k][: max_chars - 20] + "\n...[truncated]..."
        return out
    return val


def _max_decomp(ctx: dict) -> int:
    cfg = ctx.get("cfg") or {}
    br = cfg.get("binary_re") if isinstance(cfg, dict) else {}
    if isinstance(br, dict) and br.get("max_decompile_chars"):
        return int(br["max_decompile_chars"])
    return 24000


def _max_page(ctx: dict) -> int:
    cfg = ctx.get("cfg") or {}
    br = cfg.get("binary_re") if isinstance(cfg, dict) else {}
    if isinstance(br, dict) and br.get("max_list_page"):
        return int(br["max_list_page"])
    return 100


def _ok(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data}


def _err(msg: str) -> dict[str, Any]:
    return {"ok": False, "error": msg}


def _as_list(raw: Any) -> list[Any]:
    """Normalize Fake/real MCP payloads into a list of items."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in (
            "imports",
            "exports",
            "functions",
            "items",
            "results",
            "data",
            "callers",
            "xrefs",
            "references",
        ):
            v = raw.get(key)
            if isinstance(v, list):
                return v
        # Single-record dict with name/address
        if any(k in raw for k in ("name", "symbol", "address", "from", "to")):
            return [raw]
        text = raw.get("text") or raw.get("result") or raw.get("raw")
        if isinstance(text, str) and text.strip():
            return [ln.strip() for ln in text.splitlines() if ln.strip()]
        return []
    if isinstance(raw, str):
        return [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return [raw]


def _item_name(item: Any) -> str:
    if item is None:
        return ""
    if isinstance(item, str):
        # "KERNEL32.DLL::memcpy" / "memcpy @ 0x401000" / bare name
        s = item.strip()
        if " @ " in s:
            s = s.split(" @ ", 1)[0].strip()
        if "::" in s:
            s = s.rsplit("::", 1)[-1].strip()
        if "!" in s:
            s = s.rsplit("!", 1)[-1].strip()
        return s
    if isinstance(item, dict):
        for k in ("name", "symbol", "import", "label", "function", "function_name"):
            v = item.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
    return str(item).strip()


def _item_address(item: Any) -> str:
    if item is None:
        return ""
    if isinstance(item, str):
        s = item.strip()
        if " @ " in s:
            return s.split(" @ ", 1)[-1].strip()
        # bare address-like string
        if s.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s):
            return s
        return ""
    if isinstance(item, dict):
        for k in (
            "address",
            "addr",
            "entry",
            "entry_point",
            "import_address",
            "thunk_address",
            "location",
        ):
            v = item.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
    return ""


def _xref_from_address(item: Any) -> str:
    """Extract the 'from' (caller site) address of an xref record."""
    if item is None:
        return ""
    if isinstance(item, str):
        s = item.strip()
        # "from 0x401000 to 0x402000" / "0x401000 -> 0x402000"
        lower = s.lower()
        if "from " in lower:
            after = s[lower.index("from ") + 5 :].strip()
            return after.split()[0].strip(" ,;")
        if "->" in s:
            return s.split("->", 1)[0].strip()
        if " @ " in s:
            return s.split(" @ ", 1)[-1].strip()
        return s
    if isinstance(item, dict):
        for k in (
            "from",
            "from_address",
            "fromAddress",
            "source",
            "source_address",
            "caller",
            "caller_address",
            "address",
            "addr",
        ):
            v = item.get(k)
            if v is not None and str(v).strip():
                # nested dict
                if isinstance(v, dict):
                    return _item_address(v) or _item_name(v)
                return str(v).strip()
    return ""


def _function_record(raw: Any) -> dict[str, str]:
    """Normalize get_function_by_address / callers entry to {name, address}."""
    if raw is None:
        return {"name": "", "address": ""}
    if isinstance(raw, str):
        name = _item_name(raw)
        addr = _item_address(raw)
        if not addr and name.lower().startswith("0x"):
            return {"name": "", "address": name}
        return {"name": name, "address": addr}
    if isinstance(raw, dict):
        # unwrap common wrappers
        for key in ("function", "data", "result"):
            inner = raw.get(key)
            if isinstance(inner, dict) and (
                inner.get("name") or inner.get("address") or inner.get("entry")
            ):
                return _function_record(inner)
        name = _item_name(raw)
        addr = _item_address(raw)
        return {"name": name, "address": addr}
    return {"name": str(raw), "address": ""}


def _not_in_function_hint(err: str) -> str:
    base = (err or "").strip() or "address not in a function"
    hint = (
        " Address may be an import thunk/IAT entry rather than a real function. "
        "Prefer ghidra_import_callers (symbol or import address) or "
        "ghidra_xrefs(direction=to) then decompile the caller functions."
    )
    low = base.lower()
    if "import_callers" in low or "not in a function" in low or "no function" in low:
        if "import_callers" in low:
            return base
        return base + hint
    # Always attach hint for function-resolution failures
    return base + hint


def ghidra_status(ctx: dict, **_kwargs: Any) -> dict[str, Any]:
    try:
        c = _client(ctx)
        conn = c.check_connection()
        ver = None
        try:
            ver = c.get_version()
        except GhidraError:
            pass
        return _ok({"connection": conn, "version": ver, "base_url": c.base_url})
    except GhidraError as e:
        return _err(str(e))


def ghidra_metadata(ctx: dict, **_kwargs: Any) -> dict[str, Any]:
    try:
        return _ok(_client(ctx).get_metadata())
    except GhidraError as e:
        return _err(str(e))


def ghidra_list_functions(
    ctx: dict,
    *,
    offset: int = 0,
    limit: int | None = None,
    filter: str | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    try:
        lim = int(limit) if limit is not None else _max_page(ctx)
        lim = max(1, min(lim, _max_page(ctx)))
        data = _client(ctx).list_functions(
            offset=int(offset or 0), limit=lim, filter_text=filter
        )
        return _ok(data)
    except GhidraError as e:
        return _err(str(e))


def ghidra_decompile(
    ctx: dict,
    *,
    name: str | None = None,
    address: str | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    target = (name or address or "").strip()
    if not target:
        return _err("name or address required")
    try:
        data = _client(ctx).decompile_function(target)
        return _ok(_cap_text(data, _max_decomp(ctx)))
    except GhidraError as e:
        return _err(str(e))


def ghidra_disassemble(
    ctx: dict,
    *,
    name: str | None = None,
    address: str | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    target = (name or address or "").strip()
    if not target:
        return _err("name or address required")
    try:
        data = _client(ctx).disassemble_function(target)
        return _ok(_cap_text(data, _max_decomp(ctx)))
    except GhidraError as e:
        msg = str(e)
        low = msg.lower()
        if any(
            t in low
            for t in (
                "not found",
                "no function",
                "not a function",
                "not in a function",
                "invalid",
                "unknown",
            )
        ):
            return _err(_not_in_function_hint(msg))
        return _err(msg)


def ghidra_xrefs(
    ctx: dict,
    *,
    address: str = "",
    direction: str = "to",
    **_kwargs: Any,
) -> dict[str, Any]:
    addr = str(address or "").strip()
    if not addr:
        return _err("address required")
    d = str(direction or "to").lower()
    try:
        c = _client(ctx)
        if d == "from":
            return _ok(c.get_xrefs_from(addr))
        if d == "both":
            return _ok({"to": c.get_xrefs_to(addr), "from": c.get_xrefs_from(addr)})
        return _ok(c.get_xrefs_to(addr))
    except GhidraError as e:
        return _err(str(e))


def _fetch_import_page(
    c: Any, *, offset: int, limit: int, filter_text: str | None = None
) -> Any:
    """Call list_imports; tolerate clients without filter_text kwarg."""
    try:
        if filter_text:
            return c.list_imports(
                offset=offset, limit=limit, filter_text=filter_text
            )
        return c.list_imports(offset=offset, limit=limit)
    except TypeError:
        return c.list_imports(offset=offset, limit=limit)


def ghidra_imports(
    ctx: dict,
    *,
    offset: int = 0,
    limit: int | None = None,
    filter: str | None = None,
    name_filter: str | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """List imports; optional case-insensitive name substring filter (client-side)."""
    filt = (filter or name_filter or _kwargs.get("name") or "").strip() or None
    try:
        lim = int(limit) if limit is not None else min(200, _max_page(ctx) * 2)
        lim = max(1, min(lim, max(_max_page(ctx) * 2, 200)))
        off = max(0, int(offset or 0))
        c = _client(ctx)

        if not filt:
            return _ok(_fetch_import_page(c, offset=off, limit=lim))

        # Client-side filter: page until we have enough matches or hit scan cap.
        needle = filt.lower()
        matched: list[Any] = []
        scanned = 0
        page_size = min(200, max(lim, 50))
        page_off = 0
        truncated = False
        while scanned < _MAX_IMPORTS_SCAN:
            batch_limit = min(page_size, _MAX_IMPORTS_SCAN - scanned)
            raw = _fetch_import_page(
                c, offset=page_off, limit=batch_limit, filter_text=filt
            )
            items = _as_list(raw)
            if not items:
                break
            for it in items:
                scanned += 1
                name = _item_name(it)
                if needle in name.lower():
                    matched.append(it)
                if scanned >= _MAX_IMPORTS_SCAN:
                    truncated = True
                    break
            if len(items) < batch_limit:
                break
            page_off += len(items)
            # If server already filtered and returned only matches, still page.
            if page_off > _MAX_IMPORTS_SCAN:
                truncated = True
                break

        page = matched[off : off + lim]
        return _ok(
            {
                "imports": page,
                "filter": filt,
                "offset": off,
                "limit": lim,
                "match_count": len(matched),
                "returned": len(page),
                "scanned": scanned,
                "scan_capped": truncated or scanned >= _MAX_IMPORTS_SCAN,
            }
        )
    except GhidraError as e:
        return _err(str(e))


def ghidra_exports(
    ctx: dict, *, offset: int = 0, limit: int | None = None, **_kwargs: Any
) -> dict[str, Any]:
    try:
        lim = int(limit) if limit is not None else min(200, _max_page(ctx) * 2)
        return _ok(_client(ctx).list_exports(offset=int(offset or 0), limit=lim))
    except GhidraError as e:
        return _err(str(e))


def ghidra_strings(
    ctx: dict,
    *,
    offset: int = 0,
    limit: int | None = None,
    filter: str | None = None,
    pattern: str | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    try:
        c = _client(ctx)
        if pattern:
            return _ok(
                c.search_memory_strings(
                    str(pattern), limit=int(limit or _max_page(ctx))
                )
            )
        lim = int(limit) if limit is not None else _max_page(ctx)
        return _ok(
            c.list_strings(offset=int(offset or 0), limit=lim, filter_text=filter)
        )
    except GhidraError as e:
        return _err(str(e))


def ghidra_call_graph(
    ctx: dict,
    *,
    name: str | None = None,
    address: str | None = None,
    mode: str = "both",
    **_kwargs: Any,
) -> dict[str, Any]:
    target = (name or address or "").strip()
    if not target:
        return _err("name or address required")
    m = str(mode or "both").lower()
    try:
        c = _client(ctx)
        if m == "callers":
            return _ok(c.get_function_callers(target))
        if m == "callees":
            return _ok(c.get_function_callees(target))
        if m == "graph":
            return _ok(c.get_function_call_graph(target))
        return _ok(
            {
                "callers": c.get_function_callers(target),
                "callees": c.get_function_callees(target),
            }
        )
    except GhidraError as e:
        return _err(str(e))


def ghidra_search_bytes(
    ctx: dict, *, pattern: str = "", limit: int = 20, **_kwargs: Any
) -> dict[str, Any]:
    pat = str(pattern or "").strip()
    if not pat:
        return _err("pattern required (e.g. hex bytes)")
    try:
        return _ok(
            _client(ctx).search_byte_patterns(pat, limit=max(1, min(int(limit), 50)))
        )
    except GhidraError as e:
        return _err(str(e))


def ghidra_function_at(
    ctx: dict, *, address: str = "", **_kwargs: Any
) -> dict[str, Any]:
    addr = str(address or "").strip()
    if not addr:
        return _err("address required")
    try:
        data = _client(ctx).get_function_by_address(addr)
        # Empty / not-found shaped responses
        if data is None or data == {} or data == []:
            return _err(
                _not_in_function_hint(f"no function contains address {addr}")
            )
        if isinstance(data, dict):
            err = data.get("error") or data.get("message")
            if err and not (_item_name(data) or _item_address(data)):
                return _err(_not_in_function_hint(str(err)))
            # explicit not-found flags
            if data.get("found") is False or data.get("ok") is False:
                return _err(
                    _not_in_function_hint(
                        str(err or f"no function contains address {addr}")
                    )
                )
        return _ok(data)
    except GhidraError as e:
        return _err(_not_in_function_hint(str(e)))


def _resolve_import(
    c: Any, *, symbol: str | None, address: str | None
) -> tuple[str, str, list[str]]:
    """
    Resolve import symbol/address.
    Returns (resolved_symbol, import_address, notes).
    """
    notes: list[str] = []
    sym = (symbol or "").strip()
    addr = (address or "").strip()

    if addr and not sym:
        # Best-effort: look up imports for a name near this address
        notes.append(f"using provided import address {addr}")
        return "", addr, notes

    if not sym:
        return "", addr, notes

    # Search imports by name (client-side filter)
    matched: list[Any] = []
    scanned = 0
    page_off = 0
    page_size = 200
    needle = sym.lower()
    while scanned < _MAX_IMPORTS_SCAN:
        try:
            raw = _fetch_import_page(
                c, offset=page_off, limit=page_size, filter_text=sym
            )
        except GhidraError as e:
            notes.append(f"list_imports failed: {e}")
            break
        items = _as_list(raw)
        if not items:
            break
        for it in items:
            scanned += 1
            name = _item_name(it)
            if needle == name.lower() or needle in name.lower():
                matched.append(it)
        if len(items) < page_size:
            break
        page_off += len(items)

    if not matched:
        notes.append(
            f"no import matching {sym!r} in scanned imports; "
            "using symbol as-is for callers/xrefs"
        )
        return sym, addr, notes

    # Prefer exact name match
    exact = [m for m in matched if _item_name(m).lower() == needle]
    pick = exact[0] if exact else matched[0]
    resolved_name = _item_name(pick) or sym
    resolved_addr = _item_address(pick) or addr
    if len(matched) > 1:
        notes.append(
            f"matched {len(matched)} imports for {sym!r}; using {resolved_name}"
            + (f" @ {resolved_addr}" if resolved_addr else "")
        )
    if addr and resolved_addr and addr.lower() != resolved_addr.lower():
        notes.append(
            f"provided address {addr} differs from import address {resolved_addr}; "
            "using import address"
        )
    return resolved_name, resolved_addr, notes


def _callers_from_function_callers(raw: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for it in _as_list(raw):
        rec = _function_record(it)
        if rec["name"] or rec["address"]:
            out.append(
                {
                    "name": rec["name"],
                    "address": rec["address"],
                    "xref_from": rec["address"],
                }
            )
    return out


def _callers_from_xrefs(c: Any, import_address: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    try:
        raw = c.get_xrefs_to(import_address)
    except GhidraError:
        return out
    for it in _as_list(raw):
        xref_from = _xref_from_address(it)
        if not xref_from:
            continue
        name = ""
        func_addr = ""
        try:
            frec = _function_record(c.get_function_by_address(xref_from))
            name = frec.get("name") or ""
            func_addr = frec.get("address") or ""
        except GhidraError:
            pass
        except Exception:
            pass
        out.append(
            {
                "name": name,
                "address": func_addr or xref_from,
                "xref_from": xref_from,
            }
        )
    return out


def ghidra_import_callers(
    ctx: dict,
    *,
    symbol: str | None = None,
    address: str | None = None,
    limit: int = 40,
    **_kwargs: Any,
) -> dict[str, Any]:
    """
    Resolve an import (by symbol and/or address) and list calling functions.

    Prefer this over decompiling IAT stubs: decompile CALLERS, not the import thunk.
    """
    sym_in = (symbol or _kwargs.get("name") or "").strip() or None
    addr_in = (address or "").strip() or None
    if not sym_in and not addr_in:
        return _err("symbol or address required")

    lim = max(1, min(int(limit or 40), _IMPORT_CALLERS_LIMIT_CAP))
    notes: list[str] = []

    try:
        c = _client(ctx)
        resolved_sym, resolved_addr, resolve_notes = _resolve_import(
            c, symbol=sym_in, address=addr_in
        )
        notes.extend(resolve_notes)

        callers: list[dict[str, str]] = []
        seen: set[str] = set()

        def _add(rows: list[dict[str, str]]) -> None:
            for r in rows:
                key = (r.get("address") or "").lower() or (r.get("name") or "").lower()
                if not key:
                    # still keep unique xref_from
                    key = (r.get("xref_from") or "").lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                callers.append(r)

        # 1) get_function_callers on symbol or address
        targets: list[str] = []
        if resolved_sym:
            targets.append(resolved_sym)
        if resolved_addr:
            targets.append(resolved_addr)
        if sym_in and sym_in not in targets:
            targets.append(sym_in)

        for t in targets:
            if not t or not hasattr(c, "get_function_callers"):
                continue
            try:
                raw = c.get_function_callers(t)
                got = _callers_from_function_callers(raw)
                if got:
                    _add(got)
                    notes.append(f"get_function_callers({t!r}) returned {len(got)}")
                    break
            except GhidraError as e:
                notes.append(f"get_function_callers({t!r}): {e}")
            except Exception as e:
                notes.append(f"get_function_callers({t!r}): {e}")

        # 2) xrefs_to(import address) → function_at(from)
        if resolved_addr:
            xref_rows = _callers_from_xrefs(c, resolved_addr)
            if xref_rows:
                before = len(callers)
                _add(xref_rows)
                notes.append(
                    f"get_xrefs_to({resolved_addr!r}) added "
                    f"{len(callers) - before} unique caller(s)"
                )
            elif not callers:
                notes.append(
                    f"get_xrefs_to({resolved_addr!r}) returned no xrefs"
                )
        elif not callers:
            notes.append(
                "no import address resolved; cannot fall back to xrefs_to. "
                "Pass address of the IAT/thunk entry or verify the symbol name."
            )

        page = callers[:lim]
        if not page:
            notes.append(
                "No callers found. The import may be unused, resolved dynamically, "
                "or xrefs may need re-analysis. Try ghidra_xrefs(direction=to) on "
                "the import address, or ghidra_imports with filter to confirm the symbol."
            )

        return _ok(
            {
                "symbol": resolved_sym or sym_in or "",
                "import_address": resolved_addr or addr_in or "",
                "callers": page,
                "caller_count": len(callers),
                "returned": len(page),
                "limit": lim,
                "notes": notes,
            }
        )
    except GhidraError as e:
        return _err(str(e))


# name → callable for dispatch
GHIDRA_TOOL_FUNCS: dict[str, Any] = {
    "ghidra_status": ghidra_status,
    "ghidra_metadata": ghidra_metadata,
    "ghidra_list_functions": ghidra_list_functions,
    "ghidra_decompile": ghidra_decompile,
    "ghidra_disassemble": ghidra_disassemble,
    "ghidra_xrefs": ghidra_xrefs,
    "ghidra_imports": ghidra_imports,
    "ghidra_import_callers": ghidra_import_callers,
    "ghidra_exports": ghidra_exports,
    "ghidra_strings": ghidra_strings,
    "ghidra_call_graph": ghidra_call_graph,
    "ghidra_search_bytes": ghidra_search_bytes,
    "ghidra_function_at": ghidra_function_at,
}
