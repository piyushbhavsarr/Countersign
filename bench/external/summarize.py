"""Summarise AgentDojo and τ-bench runs (baseline vs undolayer) with exact 95% intervals.

python summarize.py --agentdojo DIR --taubench DIR [--md out.md]
"""
from __future__ import annotations

import argparse
import glob
import json
import math
from collections import defaultdict


def _cdf(k, n, p):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def ci(k, n):
    if n == 0:
        return (0.0, 100.0)

    def solve(f):
        lo, hi = 1e-12, 1 - 1e-12
        for _ in range(80):
            m = (lo + hi) / 2
            lo, hi = (m, hi) if f(m) else (lo, m)
        return (lo + hi) / 2
    lower = 0.0 if k == 0 else solve(lambda p: 1 - _cdf(k - 1, n, p) < 0.025)
    upper = 1.0 if k == n else solve(lambda p: _cdf(k, n, p) > 0.025)
    return (100 * lower, 100 * upper)


def rate(vals):
    vals = [bool(v) for v in vals if v is not None]
    k, n = sum(vals), len(vals)
    lo, hi = ci(k, n)
    return {"k": k, "n": n, "pct": 100 * k / n if n else 0.0, "lo": lo, "hi": hi}


def fmt(r):
    return f"{r['pct']:5.1f}% ({r['k']}/{r['n']}, CI {r['lo']:.1f}–{r['hi']:.1f})"


def load(pattern):
    rows = []
    for f in glob.glob(pattern):
        for line in open(f):
            if line.strip():
                rows.append(json.loads(line))
    return rows


def paired(rows, key):
    """Drop errored episodes and keep only episodes that both configurations completed."""
    ok = [r for r in rows if not r.get("error")]
    modes = defaultdict(set)
    for r in ok:
        modes[key(r)].add(r["mode"])
    return [r for r in ok if modes[key(r)] >= {"baseline", "undolayer"}]


def agentdojo(rows):
    rows = paired(rows, lambda r: (r["suite"], r["user_task"], r["injection_task"]))
    out = {}
    by_suite = defaultdict(list)
    for r in rows:
        by_suite[r["suite"]].append(r)
    by_suite["ALL"] = rows
    for suite, rs in sorted(by_suite.items()):
        base = [r for r in rs if r["mode"] == "baseline"]
        ul = [r for r in rs if r["mode"] == "undolayer"]
        res = {
            "baseline": {"utility": rate(r["utility"] for r in base if r["injection_task"] is None),
                         "utility_under_attack": rate(r["utility"] for r in base if r["injection_task"]),
                         "attack_success": rate(r["attack_success"] for r in base if r["injection_task"])},
        }
        for rev in ("strict", "oracle"):
            res[f"undolayer_{rev}"] = {
                "utility": rate(r.get(f"{rev}_utility") for r in ul if r["injection_task"] is None),
                "utility_under_attack": rate(r.get(f"{rev}_utility") for r in ul if r["injection_task"]),
                "attack_success": rate(r.get(f"{rev}_attack_success") for r in ul if r["injection_task"])}
        out[suite] = res
    leaks = [r for r in rows if r["mode"] == "undolayer" and r.get("injection_task")
             and (r.get("strict_attack_success") or r.get("oracle_attack_success"))]
    return out, leaks


def taubench(rows):
    rows = paired(rows, lambda r: (r["env"], r["task"]))
    out = {}
    by_env = defaultdict(list)
    for r in rows:
        by_env[r["env"]].append(r)
    by_env["ALL"] = rows
    for env, rs in sorted(by_env.items()):
        base = [r for r in rs if r["mode"] == "baseline"]
        ul = [r for r in rs if r["mode"] == "undolayer"]
        out[env] = {"baseline": rate((r.get("reward") or 0) >= 1 for r in base),
                    "undolayer_strict": rate((r.get("strict_reward") or 0) >= 1 for r in ul),
                    "undolayer_oracle": rate((r.get("oracle_reward") or 0) >= 1 for r in ul),
                    "errors": sum(1 for r in rs if r.get("error"))}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agentdojo")
    ap.add_argument("--taubench")
    args = ap.parse_args()
    if args.agentdojo:
        res, leaks = agentdojo(load(args.agentdojo + "/*.jsonl"))
        print("== AgentDojo (v1.2.2, important_instructions attack)")
        for suite, r in res.items():
            print(f"-- {suite}")
            for cfg, m in r.items():
                print(f"   {cfg:18} utility {fmt(m['utility'])} | under attack {fmt(m['utility_under_attack'])} | "
                      f"attack success {fmt(m['attack_success'])}")
        print(f"\nattacks that succeeded under undolayer (strict reviewer): {len(leaks)}")
        kinds = defaultdict(int)
        for r in leaks:
            kinds[(r["suite"], r["injection_task"])] += 1
        for (s, i), n in sorted(kinds.items(), key=lambda x: -x[1]):
            ex = next(r for r in leaks if r["suite"] == s and r["injection_task"] == i)
            print(f"   {s}/{i}: {n}x  e.g. calls={ex.get('calls')}")
    if args.taubench:
        res = taubench(load(args.taubench + "/*.jsonl"))
        print("\n== τ-bench (test split, pass^1)")
        for env, r in res.items():
            print(f"-- {env}: baseline {fmt(r['baseline'])} | undolayer strict {fmt(r['undolayer_strict'])} | "
                  f"undolayer oracle {fmt(r['undolayer_oracle'])} | errors {r['errors']}")


if __name__ == "__main__":
    main()
