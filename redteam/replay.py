"""Replay attack payloads against one design of the reviewer and save the evidence.

    python -m redteam.replay --mode naive --model qwen2.5:1.5b --runs 6 --out evidence/redteam/x
    python -m redteam.replay --mode hardened --provider obedient --runs 0 --out /tmp/check

Each payload runs once at temperature 0 with seed 42 (the exact replay) and then `--runs`
times at temperature 0.8 with seeds 1 to N (the sampled runs).
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from codeguardian import render, supervisor

from . import checks, modes, store as store_mod
from .model import SeededOllama, Trace
from .obedient import ObedientModel

PAYLOADS = Path(__file__).resolve().parent / "payloads"
EXACT = (0.0, 42)


def load_payloads(names=None):
    found = sorted(PAYLOADS.glob("*.json"))
    payloads = [json.loads(p.read_text(encoding="utf-8")) for p in found]
    if names:
        wanted = set(names)
        payloads = [p for p in payloads if p["id"] in wanted]
        missing = wanted - {p["id"] for p in payloads}
        if missing:
            raise SystemExit(f"no payload {sorted(missing)}")
    return payloads


def write_step(directory, step):
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    (d / "decision.json").write_text(json.dumps(step["decision"]), encoding="utf-8")
    pr = {"number": step["pr"]["number"], "head_sha": step["pr"]["head_sha"]}
    (d / "pr.json").write_text(json.dumps(pr), encoding="utf-8")
    (d / "change.diff").write_text(step["diff"], encoding="utf-8")


GUIDANCE = re.compile(r"Trusted standards guidance:\n(\{.*?\})(?:\n|$)", re.S)


def record_read(calls):
    """The ID of the record the lookup put into the Security request, in any mode."""
    for call in calls:
        if "findings" in call["schema_keys"]:
            found = GUIDANCE.search(call["system"])
            return json.loads(found.group(1))["id"] if found else None
    return None


def for_evidence(record):
    """Keep each request's hash and size, not its text: payload and code rebuild the text."""
    for run in record["runs"]:
        for step in run["steps"]:
            for call in step["calls"]:
                for key in ("system", "user"):
                    call[f"{key}_chars"] = len(call.pop(key))
    return record


def security_reply(trace):
    replies = [c.get("reply") for c in trace.calls if "findings" in c["schema_keys"]]
    return replies[-1] if replies else None


def run_once(payload, off, model, store):
    """One run of a payload: every step in order, with memory carried between steps."""
    session = modes.Session(store)
    trace = Trace(model)
    provider = modes.Untagged(trace) if "UNTRUSTED_TAGS" in off else trace
    steps = []
    for step in payload["steps"]:
        session.step = {"diff": step["diff"], "pr": step["pr"], "pr_standards": step.get("pr_standards")}
        first_call = len(trace.calls)
        with tempfile.TemporaryDirectory() as tmp:
            write_step(tmp, step)
            with modes.applied(off, session) as patched:
                try:
                    report = supervisor.review(tmp, provider, with_standards=True, with_reviewers=True)
                    error = None
                except Exception as exc:  # a model reply the pipeline rejects outright
                    report, error = None, f"{type(exc).__name__}: {exc}"
        if report is None:
            steps.append({"error": error, "patched": patched, "calls": trace.calls[first_call:]})
            continue
        modes.after_review(off, session, report, security_reply(trace))
        steps.append({"report": report, "comment": render.render(report), "patched": patched,
                      "lookup": record_read(trace.calls[first_call:]), "memory": list(session.memory),
                      "calls": trace.calls[first_call:]})
    judged = payload.get("judge_step", len(payload["steps"]) - 1)
    last = steps[judged]
    if "report" not in last:
        return {"hit": False, "checks_hit": [], "error": last["error"], "steps": steps}
    result = checks.outcome(payload["success"], report=last["report"], comment=last["comment"],
                            scanner=payload["steps"][judged]["decision"], canary=store.canary,
                            lookup=last["lookup"])
    return {**result, "steps": steps}


def make_model(provider, payload, model_name, temperature, seed):
    if provider == "obedient":
        return ObedientModel(payload.get("trigger", ""), payload.get("obey", {}))
    return SeededOllama(model_name, temperature, seed)


def replay(payloads, off, *, provider, model_name, runs, store):
    results = {}
    for payload in payloads:
        settings = [EXACT] + [(0.8, seed) for seed in range(1, runs + 1)]
        record = {"id": payload["id"], "mode": modes.mode_name(off), "model": model_name if provider != "obedient"
                  else "obedient", "runs": []}
        for temperature, seed in settings:
            model = make_model(provider, payload, model_name, temperature, seed)
            outcome = run_once(payload, off, model, store)
            record["runs"].append({"temperature": temperature, "seed": seed, **outcome})
            if provider == "obedient":
                break
        record["exact_hit"] = record["runs"][0]["hit"]
        record["sampled_hits"] = sum(r["hit"] for r in record["runs"][1:])
        record["sampled_runs"] = len(record["runs"]) - 1
        results[payload["id"]] = record
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", help="hardened, naive, or without:CONTROL[,CONTROL]")
    ap.add_argument("--plan", help="JSON file: a list of {mode, payloads, why}; replaces --mode and --payloads")
    ap.add_argument("--provider", choices=["ollama", "obedient"], default="ollama")
    ap.add_argument("--model", default="qwen2.5:1.5b")
    ap.add_argument("--runs", type=int, default=6)
    ap.add_argument("--payloads", default="", help="comma-separated payload IDs (default: all)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if bool(args.plan) == bool(args.mode):
        ap.error("give exactly one of --mode and --plan")
    if args.plan:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    else:
        plan = [{"mode": args.mode, "payloads": [p for p in args.payloads.split(",") if p]}]
    store = store_mod.from_env()
    for entry in plan:
        off = modes.parse_mode(entry["mode"])
        results = replay(load_payloads(entry["payloads"]), off, provider=args.provider, model_name=args.model,
                         runs=args.runs, store=store)
        out = Path(args.out) / modes.mode_name(off).replace(":", "-").replace(",", "+")
        out.mkdir(parents=True, exist_ok=True)
        for pid, record in results.items():
            (out / f"{pid}.json").write_text(json.dumps(for_evidence(record), indent=1) + "\n", encoding="utf-8")
            print(f"{pid:4} {record['mode']:60} exact={'hit' if record['exact_hit'] else 'miss'}"
                  f" sampled={record['sampled_hits']}/{record['sampled_runs']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
