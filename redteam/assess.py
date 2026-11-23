"""Summarise replay evidence as a table and check it against the report's claims.

    python -m redteam.assess evidence/redteam/ci [--claims redteam/claims.json --model qwen2.5:1.5b --strict]

A claim says whether a payload should hit or miss in a mode. A payload counts as a hit
when any of its runs hit: the exact replay or a sampled run. Control payloads must miss in
every mode, claim or not, because a hit there means a check matches ordinary output.
"""

import argparse
import json
import sys
from pathlib import Path


def load(evidence):
    records = []
    for path in sorted(Path(evidence).glob("*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if "runs" in record:
            records.append(record)
    return records


def hit(record):
    return record["exact_hit"] or record["sampled_hits"] > 0


def table(records):
    lines = ["| Payload | Mode | Exact replay | Sampled runs |", "|---|---|---|---|"]
    for r in sorted(records, key=lambda r: (r["id"], r["mode"])):
        lines.append(f"| {r['id']} | {r['mode']} | {'hit' if r['exact_hit'] else 'miss'} | "
                     f"{r['sampled_hits']} of {r['sampled_runs']} |")
    return "\n".join(lines)


def broken_claims(records, claims, model):
    problems = []
    by_key = {(r["id"], r["mode"]): r for r in records}
    for r in records:
        if r["id"].startswith("C") and hit(r):
            problems.append(f"control {r['id']} hit in {r['mode']}")
    for pid, modes in claims.get(model, {}).items():
        for mode, want in modes.items():
            record = by_key.get((pid, mode))
            if record is None:
                problems.append(f"{pid} {mode}: no evidence")
            elif ("hit" if hit(record) else "miss") != want:
                problems.append(f"{pid} {mode}: claimed {want}, observed {'hit' if hit(record) else 'miss'}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("evidence")
    ap.add_argument("--claims", default="")
    ap.add_argument("--model", default="qwen2.5:1.5b")
    ap.add_argument("--strict", action="store_true", help="exit 1 when a claim or control breaks")
    args = ap.parse_args(argv)
    records = load(args.evidence)
    if not records:
        print("no evidence found", file=sys.stderr)
        return 1
    print(table(records))
    claims = json.loads(Path(args.claims).read_text(encoding="utf-8")) if args.claims else {}
    problems = broken_claims(records, claims, args.model)
    for p in problems:
        print(f"- BROKEN: {p}")
    if not problems:
        print("\nEvery claim and control held.")
    return 1 if problems and args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
