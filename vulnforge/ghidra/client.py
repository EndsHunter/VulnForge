"""Read-only HTTP client for bethington/ghidra-mcp Ghidra plugin (default :8089).

Talks to the Java HTTP server directly (same surface the MCP bridge multiplexes).
Never calls write endpoints (rename, delete, scripts, etc.).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class GhidraError(RuntimeError):
    """Ghidra MCP HTTP failure."""


# Read-only / project-setup allowlist (import/analyze needed for lifecycle).
# Agents never call setup endpoints; only GhidraRuntime does.
_READ_ENDPOINTS = frozenset(
    {
        "check_connection",
        "get_version",
        "get_metadata",
        "get_function_count",
        "get_entry_points",
        "list_functions",
        "list_functions_enhanced",
        "decompile_function",
        "disassemble_function",
        "disassemble_bytes",
        "get_xrefs_to",
        "get_xrefs_from",
        "list_imports",
        "list_exports",
        "list_strings",
        "search_memory_strings",
        "get_function_callers",
        "get_function_callees",
        "get_function_call_graph",
        "get_function_by_address",
        "search_byte_patterns",
        "list_segments",
        "get_current_program_info",
        "list_open_programs",
        "list_analyzers",
    }
)

_SETUP_ENDPOINTS = frozenset(
    {
        "create_project",
        "open_project",
        "import_file",
        "load_program",
        "open_program",
        "run_analysis",
        "list_project_files",
        "switch_program",
    }
)

_ALLOWED = _READ_ENDPOINTS | _SETUP_ENDPOINTS


class GhidraClient:
    """Minimal HTTP client for GhidraMCP REST endpoints."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8089",
        *,
        timeout: float = 45.0,
        auth_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.auth_token = (auth_token or "").strip() or None

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json, text/plain, */*"}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    def _url(self, endpoint: str, params: dict | None = None) -> str:
        ep = endpoint.strip().lstrip("/")
        if ep not in _ALLOWED:
            raise GhidraError(f"endpoint not allowlisted: {ep}")
        url = f"{self.base_url}/{ep}"
        if params:
            q = urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None},
                doseq=True,
            )
            if q:
                url = f"{url}?{q}"
        return url

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: float | None = None,
    ) -> Any:
        method_u = method.upper()
        if method_u not in ("GET", "POST"):
            raise GhidraError(f"unsupported method: {method}")
        ep = endpoint.strip().lstrip("/")
        if ep not in _ALLOWED:
            raise GhidraError(f"endpoint not allowlisted: {ep}")
        # Agents must not hit setup; runtime uses allow_setup=True via private path
        url = self._url(ep, params if method_u == "GET" else None)
        data = None
        headers = self._headers()
        if method_u == "POST":
            body = json_body or {}
            if params and not body:
                # some endpoints take query + empty body
                url = self._url(ep, params)
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method_u)
        to = self.timeout if timeout is None else float(timeout)
        try:
            with urllib.request.urlopen(req, timeout=to) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                status = getattr(resp, "status", 200) or 200
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise GhidraError(f"HTTP {e.code}: {err_body[:500] or e.reason}") from e
        except urllib.error.URLError as e:
            raise GhidraError(f"connection failed: {e.reason}") from e
        except TimeoutError as e:
            raise GhidraError(f"timeout after {to}s") from e

        if status != 200:
            raise GhidraError(f"HTTP {status}: {raw[:500]}")
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> Any:
        text = (raw or "").strip()
        if not text:
            return {"ok": True, "raw": ""}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"ok": True, "text": text}

    # --- convenience read API -------------------------------------------------

    def check_connection(self) -> Any:
        return self.request("GET", "check_connection")

    def get_version(self) -> Any:
        return self.request("GET", "get_version")

    def get_metadata(self) -> Any:
        return self.request("GET", "get_metadata")

    def list_functions(
        self, *, offset: int = 0, limit: int = 100, filter_text: str | None = None
    ) -> Any:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if filter_text:
            params["filter"] = filter_text
        return self.request("GET", "list_functions", params=params)

    def decompile_function(self, name_or_address: str) -> Any:
        # bridge uses name or address query; try common param names
        try:
            return self.request(
                "GET", "decompile_function", params={"name": name_or_address}
            )
        except GhidraError:
            return self.request(
                "GET",
                "decompile_function",
                params={"address": name_or_address, "function": name_or_address},
            )

    def disassemble_function(self, name_or_address: str) -> Any:
        try:
            return self.request(
                "GET", "disassemble_function", params={"name": name_or_address}
            )
        except GhidraError:
            return self.request(
                "GET", "disassemble_function", params={"address": name_or_address}
            )

    def get_xrefs_to(self, address: str) -> Any:
        return self.request("GET", "get_xrefs_to", params={"address": address})

    def get_xrefs_from(self, address: str) -> Any:
        return self.request("GET", "get_xrefs_from", params={"address": address})

    def list_imports(
        self,
        *,
        offset: int = 0,
        limit: int = 200,
        filter_text: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if filter_text:
            # Some MCP builds accept filter/name; ignored harmlessly if unsupported.
            params["filter"] = filter_text
            params["name"] = filter_text
        return self.request("GET", "list_imports", params=params)

    def list_exports(self, *, offset: int = 0, limit: int = 200) -> Any:
        return self.request(
            "GET", "list_exports", params={"offset": offset, "limit": limit}
        )

    def list_strings(
        self, *, offset: int = 0, limit: int = 100, filter_text: str | None = None
    ) -> Any:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if filter_text:
            params["filter"] = filter_text
        return self.request("GET", "list_strings", params=params)

    def search_memory_strings(self, pattern: str, *, limit: int = 50) -> Any:
        return self.request(
            "GET",
            "search_memory_strings",
            params={"query": pattern, "limit": limit},
        )

    def get_function_callers(self, name_or_address: str) -> Any:
        return self.request(
            "GET", "get_function_callers", params={"name": name_or_address}
        )

    def get_function_callees(self, name_or_address: str) -> Any:
        return self.request(
            "GET", "get_function_callees", params={"name": name_or_address}
        )

    def get_function_call_graph(self, name_or_address: str) -> Any:
        return self.request(
            "GET",
            "get_function_call_graph",
            params={"name": name_or_address},
        )

    def get_function_by_address(self, address: str) -> Any:
        return self.request(
            "GET", "get_function_by_address", params={"address": address}
        )

    def search_byte_patterns(self, pattern: str, *, limit: int = 20) -> Any:
        return self.request(
            "GET",
            "search_byte_patterns",
            params={"pattern": pattern, "limit": limit},
        )

    def list_segments(self) -> Any:
        return self.request("GET", "list_segments")

    def get_entry_points(self) -> Any:
        return self.request("GET", "get_entry_points")

    # --- setup (runtime only) -------------------------------------------------

    def create_project(self, path: str, name: str) -> Any:
        # Headless API: parentDir + name (JSON body)
        return self.request(
            "POST",
            "create_project",
            json_body={"parentDir": path, "name": name},
            timeout=120,
        )

    def open_project(self, path: str) -> Any:
        return self.request(
            "POST", "open_project", json_body={"path": path}, timeout=120
        )

    def import_file(self, path: str, project_path: str | None = None) -> Any:
        # GUI-only on many builds; prefer load_program in headless.
        body: dict[str, Any] = {"file_path": path, "file": path, "path": path}
        if project_path:
            body["project"] = project_path
            body["parentDir"] = project_path
        return self.request("POST", "import_file", json_body=body, timeout=300)

    def load_program(self, path: str) -> Any:
        # Headless API: body field is "file" (absolute path)
        return self.request(
            "POST", "load_program", json_body={"file": path}, timeout=600
        )

    def run_analysis(self) -> Any:
        return self.request("POST", "run_analysis", json_body={}, timeout=600)

    def healthy(self) -> bool:
        try:
            self.check_connection()
            return True
        except GhidraError:
            return False
