from __future__ import annotations

import inspect
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
import typing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

LANES = ("read", "deferrable", "irreversible")
_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}


class UndolayerError(RuntimeError):
    pass


class Denied(UndolayerError):
    """The gateway refused the call (policy or a reviewer). Do not retry it another way."""

    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__("; ".join(payload.get("reasons") or [payload.get("error", "denied")]))


class ApprovalRequired(UndolayerError):
    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__(payload.get("message", "approval required"))


def _schema(fn: Callable) -> tuple[dict, list]:
    sig = inspect.signature(fn)
    hints = typing.get_type_hints(fn)
    props, required = {}, []
    for name, p in sig.parameters.items():
        t = typing.get_origin(hints.get(name)) or hints.get(name)
        props[name] = {"type": _JSON_TYPES.get(t, "string")}
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return props, required


class _Tool:
    def __init__(self, fn, lane, destinations, description):
        if lane not in LANES:
            raise ValueError(f"lane must be one of {LANES}")
        self.fn, self.lane, self.destinations = fn, lane, destinations or []
        self.name = fn.__name__
        self.description = (description or inspect.getdoc(fn) or self.name).strip().splitlines()[0]
        self.params, self.required = _schema(fn)


class Undolayer:
    """Owns a local tool server and an undolayer gateway process."""

    def __init__(self, config: str | None = None, state_dir: str | None = None, name: str = "app",
                 approver: Callable[[dict], bool] | None = None, approval_wait: str = "10m", binary: str | None = None,
                 reviewer: str | None = None, reviewer_key: str | None = None):
        self.name = name
        self.base_config = config
        self.approver = approver
        self.approval_wait = approval_wait if approver else ""
        # with [reviewers] configured, the approver's decisions are signed as this reviewer
        self.reviewer, self.reviewer_key = reviewer, reviewer_key
        self.binary = binary or os.environ.get("UNDOLAYER_BIN") or shutil.which("undolayer")
        if not self.binary:
            raise UndolayerError("undolayer binary not found (install it or set UNDOLAYER_BIN)")
        self.work = Path(tempfile.mkdtemp(prefix="undolayer-sdk-"))
        self.state_dir = state_dir or str(self.work / "state")
        self.tools: dict[str, _Tool] = {}
        self._gw = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------------ registration
    def tool(self, lane: str = "read", destinations: list[str] | None = None, description: str | None = None):
        def deco(fn):
            if self._gw is not None:
                raise UndolayerError("register tools before the first session")
            t = _Tool(fn, lane, destinations, description)
            self.tools[t.name] = t
            return fn
        return deco

    # ------------------------------------------------------------------ plumbing
    def _serve_tools(self) -> str:
        tools = self.tools

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                args = json.loads(self.rfile.read(n) or b"{}")
                t = tools.get(self.path.strip("/"))
                try:
                    if t is None:
                        raise KeyError(self.path)
                    body, code = json.dumps({"result": t.fn(**args)}, default=str).encode(), 200
                except Exception as e:  # noqa: BLE001  - the tool's own failure, reported to the agent
                    body, code = json.dumps({"error": f"{type(e).__name__}: {e}"}).encode(), 500
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def _start(self):
        with self._lock:
            if self._gw is not None:
                return
            url = self._serve_tools()
            reg = self.work / "registry"
            reg.mkdir(parents=True, exist_ok=True)
            actions = {t.name: {"kind": t.lane, "description": t.description,
                                "request": {"method": "POST", "path": "/" + t.name, "body": "$args"},
                                "params": t.params, "required": t.required, "destinations": t.destinations}
                       for t in self.tools.values()}
            (reg / f"{self.name}.json").write_text(json.dumps(
                {"tool": {"name": self.name, "base_url": url, "idempotency_header": ""}, "action": actions}))
            cfg: dict[str, Any] = {}
            if self.base_config:
                with open(self.base_config, "rb") as fh:
                    cfg = tomllib.load(fh)
            lines = [f'state_dir = {json.dumps(cfg.get("state_dir", self.state_dir))}']
            paths = list((cfg.get("registry") or {}).get("paths", [])) + [str(reg)]
            if self.base_config:  # keep the operator's other sections (workspace, sql, credentials, ...)
                base = Path(self.base_config).read_text()
                lines.append(_strip_sections(base, ("registry", "approvals")).replace(f'state_dir = {json.dumps(cfg.get("state_dir", ""))}', ""))
            lines += ["[registry]", f"paths = {json.dumps(paths)}"]
            if self.approval_wait:
                lines += ["[approvals]", f'wait = "{self.approval_wait}"']
            # Next to the operator's config, so its relative paths (workspace root, database) resolve the same.
            where = Path(self.base_config).resolve().parent if self.base_config else self.work
            self.config_path = where / f".undolayer-sdk-{os.getpid()}-{self.work.name}.toml"
            self.config_path.write_text("\n".join(lines) + "\n")
            self.state_dir = cfg.get("state_dir", self.state_dir)
            self._gw = _Gateway(self.binary, self.config_path)
            if self.approver:
                threading.Thread(target=self._review_loop, daemon=True).start()

    def _review_loop(self):
        decided = set()
        while not self._stop.is_set():
            try:
                out = subprocess.run([self.binary, "pending", "-c", str(self.config_path), "--json"],
                                     capture_output=True, text=True, timeout=30).stdout
                for p in json.loads(out or "null") or []:
                    commit = p.get("kind") == "commit"
                    key = (p["tx"], p["preview_hash"]) if commit else p["action"]["id"]
                    if key in decided:
                        continue
                    decided.add(key)
                    if commit:  # the whole transaction: e.g. a mass change over the budget
                        req = {"kind": "commit", "tx": p["tx"], "task": p["task"], "tool": "commit",
                               "args": p.get("totals") or {}, "reasons": p.get("reasons", []), "needs": p.get("needs", [])}
                    else:
                        a = p["action"]
                        req = {"kind": "action", "tx": p["tx"], "task": p["task"], "action_id": a["id"],
                               "tool": a["operation"], "args": a["args"], "reasons": p.get("reasons", []),
                               "needs": p.get("needs", [])}
                    try:
                        ok = bool(self.approver(req))
                    except Exception:  # noqa: BLE001  - a failing approver declines
                        ok = False
                    cmd = [self.binary, "approve", "-c", str(self.config_path), p["tx"]]
                    if self.reviewer and self.reviewer_key:
                        cmd += ["--as", self.reviewer, "--key", self.reviewer_key]
                    if commit:
                        cmd += ["--yes"] if ok else ["--decline"]
                    else:
                        cmd += ["--action", req["action_id"]] + ([] if ok else ["--decline"])
                    subprocess.run(cmd, capture_output=True, timeout=30)
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(0.2)

    # ------------------------------------------------------------------ sessions
    def session(self, task: str) -> "Session":
        """One unit of work. `task` is the user's request: destinations it does not name
        need approval."""
        self._start()
        return Session(self, task)

    def close(self):
        self._stop.set()
        if self._gw:
            self._gw.close()
            self._gw = None
        cp = getattr(self, "config_path", None)
        if cp is not None and cp.parent != self.work:
            cp.unlink(missing_ok=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _strip_sections(text: str, names: tuple) -> str:
    out, skip = [], False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            head = s.strip("[]").split(".")[0].strip()
            skip = head in names
        if not skip:
            out.append(line)
    return "\n".join(out)


class _Gateway:
    def __init__(self, binary, config):
        self.p = subprocess.Popen([binary, "serve", "-c", str(config)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True)
        self.n = 0
        self.lock = threading.Lock()
        self.rpc("initialize", {"protocolVersion": "2025-06-18"})

    def rpc(self, method, params):
        with self.lock:
            self.n += 1
            self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
            self.p.stdin.flush()
            line = self.p.stdout.readline()
        if not line:
            raise UndolayerError("the undolayer gateway exited")
        msg = json.loads(line)
        if "error" in msg:
            raise UndolayerError(msg["error"].get("message"))
        return msg["result"]

    def tool(self, name, args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        return r["structuredContent"], r["isError"]

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self.p.kill()


class Session:
    def __init__(self, ul: Undolayer, task: str):
        self.ul, self.task = ul, task
        res, err = ul._gw.tool("undolayer_begin", {"task": task})
        if err:
            raise UndolayerError(res)
        self.tx = res["tx"]
        self.done = False

    def call(self, tool: str, **args) -> Any:
        """Call a tool through the gateway. Reads return their result; held actions return
        {"held": True, ...} and take effect at commit; refused ones raise Denied."""
        if tool not in self.ul.tools:
            raise UndolayerError(f"unknown tool {tool}")
        return self._invoke(f"{self.ul.name}_{tool}", args)

    def builtin(self, tool: str, **args) -> Any:
        """Call one of the gateway's own tools, e.g. sql_execute, fs_write or shell_run,
        with the same staging, policy and errors as call()."""
        return self._invoke(tool, args)

    def _invoke(self, name: str, args: dict) -> Any:
        res, err = self.ul._gw.tool(name, args)
        if err:
            if res.get("denied"):
                raise Denied(res)
            if res.get("approval_required"):
                raise ApprovalRequired(res)
            raise UndolayerError(res.get("error") or res)
        r = res.get("result")
        if isinstance(r, dict) and "result" in r and set(r) <= {"result", "_redacted"}:
            return r["result"]
        if isinstance(r, dict) and "error" in r and len(r) == 1:
            raise UndolayerError(r["error"])
        return r

    def preview(self) -> dict:
        return self.ul._gw.tool("undolayer_preview", {})[0]

    def commit(self) -> dict:
        res, err = self.ul._gw.tool("undolayer_commit", {})
        if err:
            if res.get("approval_required"):
                raise ApprovalRequired(res)
            raise UndolayerError(res)
        self.done = True
        return res

    def rollback(self, reason: str = "rolled back by the application") -> dict:
        self.done = True
        return self.ul._gw.tool("undolayer_rollback", {"reason": reason})[0]

    # -------------------------------------------------------------- LLM function calling
    def openai_tools(self) -> list[dict]:
        """Tool schemas for OpenAI-style function calling (Chat Completions)."""
        return [{"type": "function", "function": {"name": t.name, "description": f"{t.description} [{t.lane}]",
                                                  "parameters": {"type": "object", "properties": t.params,
                                                                 "required": t.required}}}
                for t in self.ul.tools.values()]

    def handle(self, tool_calls) -> list[dict]:
        """Run the model's tool calls through the gateway; returns tool messages to append."""
        out = []
        for tc in tool_calls:
            fn = tc["function"] if isinstance(tc, dict) else tc.function
            name = fn["name"] if isinstance(fn, dict) else fn.name
            raw = fn["arguments"] if isinstance(fn, dict) else fn.arguments
            tid = tc["id"] if isinstance(tc, dict) else tc.id
            try:
                r = self.call(name, **(json.loads(raw) if isinstance(raw, str) else raw or {}))
                content = r.get("note") if isinstance(r, dict) and r.get("held") else r
            except Denied as e:
                content = {"refused": str(e), "guidance": "Do not try to achieve this another way; tell the user."}
            except UndolayerError as e:
                content = {"error": str(e)}
            out.append({"role": "tool", "tool_call_id": tid, "content": json.dumps(content, default=str)})
        return out

    def langchain_tools(self):
        """LangChain StructuredTools bound to this session (needs langchain-core)."""
        from langchain_core.tools import StructuredTool  # type: ignore
        tools = []
        for t in self.ul.tools.values():
            def run(_t=t, **kw):
                try:
                    return self.call(_t.name, **kw)
                except Denied as e:
                    return f"refused: {e}. Do not try another way; tell the user."
            tools.append(StructuredTool(name=t.name, description=f"{t.description} [{t.lane}]", func=run,
                                        args_schema={"type": "object", "properties": t.params, "required": t.required}))
        return tools

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.done:
            return False
        if exc_type is not None:
            self.rollback(f"exception in the application: {exc_type.__name__}")
            return False
        self.commit()
        return False
