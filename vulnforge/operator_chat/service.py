"""High-level operator chat turn handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.llm import LLMClient
from vulnforge.operator_chat import session as sess
from vulnforge.operator_chat.confirm import take_pending
from vulnforge.operator_chat.loop import run_operator_loop
from vulnforge.operator_chat.prompts import home_system, run_system
from vulnforge.operator_chat.summarize import tool_result_content
from vulnforge.operator_chat.tools_common import mutation_summary
from vulnforge.operator_chat import tools_home, tools_run
from vulnforge.ui.store import RunRef


def list_sessions(
    scope: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> list[dict[str, Any]]:
    return sess.list_sessions(scope, project_root=project_root, run_dir=run_dir)


def load_session(
    scope: str,
    session_id: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> Optional[dict[str, Any]]:
    return sess.load_session(scope, session_id, project_root=project_root, run_dir=run_dir)


def delete_session(
    scope: str,
    session_id: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> bool:
    return sess.delete_session(scope, session_id, project_root=project_root, run_dir=run_dir)


def handle_turn(
    *,
    scope: str,
    message: str,
    project_root: Path,
    runs_root: Path,
    cfg: dict[str, Any],
    session_id: Optional[str] = None,
    run: Optional[RunRef] = None,
    client: Any = None,
    max_tool_rounds: Optional[int] = None,
) -> dict[str, Any]:
    """Process one user message (or empty message not allowed)."""
    msg = (message or "").strip()
    if not msg:
        return {"ok": False, "error": "empty message"}

    run_dir = run.path if run else None
    if scope == "run" and run is None:
        return {"ok": False, "error": "run required for run scope"}

    data = None
    if session_id:
        data = sess.load_session(scope, session_id, project_root=project_root, run_dir=run_dir)
    if data is None:
        data = sess.create_session(
            scope,
            project_root=project_root,
            run_dir=run_dir,
            target_id=run.target_id if run else None,
            run_id=run.run_id if run else None,
        )

    own_client = False
    if client is None:
        client = LLMClient(cfg)
        own_client = True

    try:
        if scope == "home":
            system = home_system()
            tools = tools_home.schemas()

            def _dispatch(name: str, args: dict) -> dict:
                return tools_home.dispatch(
                    name,
                    args,
                    runs_root=runs_root,
                    project_root=project_root,
                    execute_mutations=False,
                )

            run_key = None
        else:
            assert run is not None
            system = run_system(
                target_id=run.target_id, run_id=run.run_id, run_path=str(run.path)
            )
            tools = tools_run.schemas()

            def _dispatch(name: str, args: dict) -> dict:
                return tools_run.dispatch(
                    name, args, run=run, execute_mutations=False
                )

            run_key = run.key

        history = list(data.get("messages") or [])
        # model history: store ui messages; loop slims them
        # Operator chat is unlimited by default (loop safety ceiling only).
        # Explicit max_tool_rounds is for tests / rare overrides — do not
        # inherit llm.max_tool_rounds from hunt/recon agent settings.
        rounds = max_tool_rounds  # None = unlimited

        result = run_operator_loop(
            client=client,
            system=system,
            history=history,
            user_message=msg,
            tools=tools,
            dispatch=_dispatch,
            max_rounds=rounds,
            session_id=str(data["id"]),
            scope=scope,
            run_key=run_key,
        )

        # persist: append new_ui messages
        stored = list(data.get("messages") or [])
        for m in result.get("messages") or []:
            stored.append(_persistable(m))
        data["messages"] = stored
        data["model_id"] = result.get("model_id")
        sess.save_session(data, project_root=project_root, run_dir=run_dir)

        return {
            "ok": bool(result.get("ok", True)),
            "session_id": data["id"],
            "messages": result.get("messages") or [],
            "pending_confirm": result.get("pending_confirm"),
            "ui_hints": result.get("ui_hints") or {},
            "error": result.get("error"),
            "model_id": result.get("model_id"),
        }
    finally:
        if own_client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


def confirm_pending(
    *,
    token: str,
    project_root: Path,
    runs_root: Path,
    cfg: dict[str, Any],
    scope: str,
    session_id: str,
    run: Optional[RunRef] = None,
    client: Any = None,
) -> dict[str, Any]:
    """Execute a pending mutation and ask the model for a short wrap-up."""
    pending = take_pending(token)
    if pending is None:
        return {"ok": False, "error": "invalid or expired confirm token"}
    if pending.session_id != session_id:
        return {"ok": False, "error": "token session mismatch"}
    if pending.scope != scope:
        return {"ok": False, "error": "token scope mismatch"}

    run_dir = run.path if run else None
    data = sess.load_session(scope, session_id, project_root=project_root, run_dir=run_dir)
    if data is None:
        return {"ok": False, "error": "session not found"}

    name = pending.tool_name
    args = dict(pending.arguments or {})

    if scope == "home":
        out = tools_home.dispatch(
            name,
            args,
            runs_root=runs_root,
            project_root=project_root,
            execute_mutations=True,
        )
    else:
        if run is None:
            return {"ok": False, "error": "run required"}
        out = tools_run.dispatch(name, args, run=run, execute_mutations=True)

    tool_ui = {
        "role": "tool",
        "name": name,
        "content": out,
        "confirmed": True,
    }
    wrap = (
        f"Confirmed action `{name}`: "
        f"{'ok' if out.get('ok') else 'failed'}. "
        f"{mutation_summary(name, args)}"
    )
    if isinstance(out, dict):
        if out.get("task_id"):
            wrap += f" task_id={out.get('task_id')}."
        if out.get("error"):
            wrap += f" error={out.get('error')}."
        if out.get("url"):
            wrap += f" url={out.get('url')}."

    # Optional short LLM wrap-up
    asst_text = wrap
    own_client = False
    if client is None:
        try:
            client = LLMClient(cfg)
            own_client = True
        except Exception:
            client = None
    if client is not None:
        try:
            messages = [
                {
                    "role": "system",
                    "content": "Summarize this operator action result in 2-4 short sentences. Be factual.",
                },
                {
                    "role": "user",
                    "content": f"Action {name} args={args}\nResult JSON:\n{tool_result_content(out)[:4000]}",
                },
            ]
            res = client.chat(messages, tools=None, temperature=0.2)
            if res.ok and res.content:
                asst_text = res.content.strip()
        except Exception:
            pass
        finally:
            if own_client and hasattr(client, "close"):
                try:
                    client.close()
                except Exception:
                    pass

    asst_ui = {"role": "assistant", "content": asst_text}
    stored = list(data.get("messages") or [])
    stored.append(_persistable(tool_ui))
    stored.append(_persistable(asst_ui))
    data["messages"] = stored
    sess.save_session(data, project_root=project_root, run_dir=run_dir)

    ui_hints: dict[str, Any] = {"refresh_run": True}
    if isinstance(out, dict) and (out.get("navigate") or out.get("url")):
        ui_hints["navigate"] = out.get("navigate") or out.get("url")

    return {
        "ok": True,
        "session_id": session_id,
        "messages": [tool_ui, asst_ui],
        "result": out,
        "pending_confirm": None,
        "ui_hints": ui_hints,
    }


def _persistable(m: dict[str, Any]) -> dict[str, Any]:
    """Strip huge blobs for disk."""
    out = dict(m)
    c = out.get("content")
    if isinstance(c, dict):
        # keep as dict but ensure serializable size via tool_result later if needed
        try:
            s = tool_result_content(c)
            if len(s) > 14000:
                out["content"] = {"ok": c.get("ok"), "truncated": True, "preview": s[:4000]}
        except Exception:
            out["content"] = {"ok": False, "error": "persist failed"}
    elif isinstance(c, str) and len(c) > 12000:
        out["content"] = c[:12000] + "…"
    out.pop("pending_confirm", None)
    return out
