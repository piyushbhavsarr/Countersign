"""τ-bench with and without undolayer: does normal work still get done?

Every tool call of the undolayer configuration goes through the real Go gateway. Reads
run; writes are held with the gateway's decision. When the conversation ends, the
database is forked and graded by τ-bench's own reward twice:
  strict - every approval-required action is declined;
  oracle - approval-required actions that the task's ground truth contains are approved.
Usage: python harness.py --model gpt-4.1-mini --env retail --start 0 --end 2 --out r.jsonl
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentdojo"))
from harness import EnvServer as _Unused, Gateway  # noqa: E402,F401  (same MCP client)

from tau_bench.agents.tool_calling_agent import ToolCallingAgent  # noqa: E402
from tau_bench.envs import get_env  # noqa: E402
from tau_bench.types import RESPOND_ACTION_NAME, Action  # noqa: E402

import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

HERE = Path(__file__).resolve().parent
LANES = tomllib.loads((HERE / "lanes.toml").read_text())
LANE = {t: lane for lane in ("read", "deferrable", "irreversible") for t in LANES[lane]}


class TauServer:
    """Executes τ-bench tools on the current episode's data."""

    def __init__(self):
        self.env = None
        srv = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                args = json.loads(self.rfile.read(n) or b"{}")
                name = self.path.strip("/")
                try:
                    out, code = srv.env.tools_map[name].invoke(data=srv.env.data, **args), 200
                except Exception as e:  # noqa: BLE001
                    out, code = f"Error: {e}", 200
                body = json.dumps({"output": out}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def write_registry(env_name, tools_info, url, path: Path):
    actions = {}
    for info in tools_info:
        f = info["function"]
        lane = LANE.get(f["name"])
        if lane is None:
            raise SystemExit(f"tool {f['name']} has no lane")
        props = f.get("parameters", {}).get("properties", {})
        actions[f["name"]] = {"kind": lane, "description": f.get("description", "")[:200],
                              "request": {"method": "POST", "path": "/" + f["name"], "body": "$args"},
                              "params": {k: {"type": v.get("type", "string")} for k, v in props.items()},
                              "required": f.get("parameters", {}).get("required", [])}
    path.write_text(json.dumps({"tool": {"name": env_name, "base_url": url, "idempotency_header": ""}, "action": actions}))


def norm(v):
    return json.dumps(v, sort_keys=True).lower()


def install(env, gw, srv, env_name):
    """Route the env's tool calls through the gateway; grade both reviewer modes at the end."""
    original_step = env.step
    held = []  # (Action, decision)
    env._ul = {"held": held, "rewards": {}}

    def finish():
        gt = [a for a in env.task.actions if a.name != RESPOND_ACTION_NAME]
        base = copy.deepcopy(env.data)
        for review in ("strict", "oracle"):
            env.data = copy.deepcopy(base)
            for a, d in held:
                ok = d == "hold" or (d == "require_approval" and review == "oracle" and
                                     any(g.name == a.name and norm(g.kwargs) == norm(a.kwargs) for g in gt))
                if ok:
                    try:
                        env.tools_map[a.name].invoke(data=env.data, **a.kwargs)
                    except Exception:  # noqa: BLE001
                        pass
            env.step = original_step  # τ-bench's grader replays ground truth through step
            env._ul["rewards"][review] = env.calculate_reward().reward
            env.step = step
        gw.tool("undolayer_rollback", {"reason": "graded offline"})

    def step(action: Action):
        if action.name == RESPOND_ACTION_NAME or action.name not in env.tools_map:
            snap = copy.deepcopy(env.data)  # τ-bench grades (and reloads data) inside step when the user ends
            env.step = original_step
            r = original_step(action)
            env.step = step
            if r.done:
                env.data = snap
                finish()
            return r
        env.actions.append(action)
        res, is_err = gw.tool(f"{env_name}_{action.name}", dict(action.kwargs))
        if is_err:
            obs = "Error: " + (res.get("error") or "denied: " + "; ".join(res.get("reasons", [])))
        else:
            r = res.get("result", {})
            if isinstance(r, dict) and r.get("held"):
                pv, _ = gw.tool("undolayer_preview", {})
                d = next((x["decision"] for x in pv.get("held_effects", []) if x["id"] == r["action_id"]), "require_approval")
                held.append((action, d))
                obs = r.get("note", "Queued.")
            else:
                obs = r.get("output", json.dumps(r)) if isinstance(r, dict) else str(r)
        from tau_bench.types import EnvInfo, EnvResponse
        done = action.name in env.terminate_tools
        if done:
            finish()
        return EnvResponse(observation=obs, reward=0, done=done, info=EnvInfo(task=env.task, source=action.name))

    env.step = step


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--user-model", default=None)
    ap.add_argument("--env", required=True, choices=["retail", "airline"])
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=0)
    ap.add_argument("--modes", default="baseline,undolayer")
    ap.add_argument("--binary", default=str(HERE.parent.parent / "bin" / "undolayer"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    user_model = args.user_model or args.model
    outp = Path(args.out)
    done = set()
    if outp.exists():
        for line in outp.read_text().splitlines():
            r = json.loads(line)
            done.add((r["mode"], r["task"]))
    work = Path(os.environ.get("UL_WORK", f"/tmp/ul-tau-{args.env}"))
    (work / "registry").mkdir(parents=True, exist_ok=True)
    srv = TauServer()
    probe = get_env(args.env, user_strategy="llm", user_model=user_model, task_split="test", user_provider="openai", task_index=0)
    write_registry(args.env, probe.tools_info, srv.url, work / "registry" / f"{args.env}.json")
    cfg = work / "cfg.toml"
    cfg.write_text(f'state_dir = "{work}/state"\n[registry]\npaths = ["{work}/registry"]\n')
    gw = Gateway(args.binary, cfg) if "undolayer" in args.modes else None
    end = args.end or len(probe.tasks)
    cost = 0.0
    with open(outp, "a") as fh:
        for i in range(args.start, end):
            for mode in args.modes.split(","):
                if (mode, i) in done:
                    continue
                env = get_env(args.env, user_strategy="llm", user_model=user_model, task_split="test", user_provider="openai", task_index=i)
                agent = ToolCallingAgent(tools_info=env.tools_info, wiki=env.wiki, model=args.model, provider="openai", temperature=0.0)
                rec = {"mode": mode, "env": args.env, "task": i}
                if mode == "undolayer":
                    srv.env = env
                    gw.tool("undolayer_begin", {"task": f"{args.env}/{i}"})
                    install(env, gw, srv, args.env)
                try:
                    res = agent.solve(env=env, task_index=i)
                    rec["reward"] = res.reward
                    rec["cost"] = res.total_cost
                    cost += res.total_cost or 0
                except Exception as e:  # noqa: BLE001
                    rec["error"] = repr(e)[:300]
                    if "no credits" in str(e).lower() or "insufficient_quota" in str(e):
                        print(json.dumps({"stopped": "OpenAI account has no credits left"}), flush=True)
                        os._exit(3)
                if mode == "undolayer":
                    rec.update({f"{k}_reward": v for k, v in env._ul["rewards"].items()})
                    rec["held"] = [[a.name, d] for a, d in env._ul["held"]]
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                print(json.dumps({k: rec.get(k) for k in ("mode", "task", "reward", "strict_reward", "oracle_reward", "cost", "error")}), flush=True)
    print(json.dumps({"agent_cost_usd": round(cost, 4)}))
    if gw:
        gw.close()


if __name__ == "__main__":
    main()
