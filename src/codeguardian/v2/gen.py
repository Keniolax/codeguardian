"""A seeded generator of benign noise around the recorded chain, for the replay benchmark.

The noise copies the shapes of the chain's own records and changes their IDs, times and
a few fields. The same seed gives the same bytes.
"""

import copy
import json
import random
import statistics
import time as _time
from datetime import timedelta

from .schema import parse_ts

START = "2026-11-14T09:59:00Z"
SPAN_SECONDS = 1800
ACCOUNT = "111122223333"


def _uuid(rng):
    h = f"{rng.getrandbits(128):032x}"
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def _at(rng):
    t = parse_ts(START) + timedelta(microseconds=rng.randrange(SPAN_SECONDS * 1_000_000))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _swap_role(rec, name):
    ident = rec["userIdentity"]
    session = ident["arn"].rsplit("/", 1)[1]
    ident["arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/{name}/{session}"
    ident["sessionContext"]["sessionIssuer"]["arn"] = f"arn:aws:iam::{ACCOUNT}:role/{name}"
    ident["sessionContext"]["sessionIssuer"]["userName"] = name


def generate(chain_lines, n_noise, seed):
    """Returns NDJSON lines: the chain records plus n_noise benign records, by time."""
    rng = random.Random(seed)
    chain = [json.loads(line) for line in chain_lines if line.strip()]
    by_kind = {}
    for rec in chain:
        if rec.get("eventName") == "GetObject":
            bucket = rec["requestParameters"]["bucketName"]
            role = rec["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
            by_kind.setdefault((role, bucket), rec)
        elif rec.get("kind") == "Event" and rec.get("verb") == "get":
            by_kind["audit_get"] = rec
        elif rec.get("rule") == "Terminal shell in container" and "report-builder" in rec["output_fields"]["k8s.pod.name"]:
            by_kind["falco_shell"] = rec
        elif rec.get("eventName") == "PutRolePolicy":
            by_kind["iam_call"] = rec
    kb = by_kind[("sentinel-agent", "example-agent-kb")]
    control = by_kind[("finance-reports", "example-finance-records")]

    def kb_read():
        r = copy.deepcopy(kb)
        r["requestParameters"]["key"] = f"docs/page-{rng.randrange(5000)}.md"
        return r

    def control_read():
        r = copy.deepcopy(control)
        r["requestParameters"]["key"] = f"payroll/batch-{rng.randrange(5000)}.csv"
        return r

    def unknown_role_read():
        r = copy.deepcopy(kb)
        _swap_role(r, "legacy-batch")
        return r

    def iam_list():
        r = copy.deepcopy(by_kind["iam_call"])
        r["eventName"], r["requestParameters"], r["readOnly"] = "ListRoles", {}, True
        r["userAgent"] = "aws-cli/2.18.0 Python/3.12.6 Linux/6.5.0 exec-env/github-actions"
        return r

    def audit_get():
        r = copy.deepcopy(by_kind["audit_get"])
        r["verb"] = rng.choice(["get", "list", "watch"])
        r["objectRef"]["name"] = rng.choice(["sentinel-agent-7d9f", "report-builder-5c2b"])
        return r

    def frontend_shell():
        r = copy.deepcopy(by_kind["falco_shell"])
        r["output_fields"].update({"k8s.ns.name": "web", "k8s.pod.name": "frontend-6f8c", "container.name": "frontend"})
        r["hostname"] = "node-b"
        return r

    kinds = [(kb_read, 40), (audit_get, 25), (control_read, 15), (iam_list, 10), (unknown_role_read, 5),
             (frontend_shell, 5)]
    makers, weights = zip(*kinds)
    noise = []
    for _ in range(n_noise):
        rec = rng.choices(makers, weights)[0]()
        when = _at(rng)
        if "eventID" in rec:
            rec["eventID"], rec["eventTime"] = _uuid(rng), when[:19] + "Z"
        elif rec.get("kind") == "Event":
            rec["auditID"], rec["requestReceivedTimestamp"], rec["stageTimestamp"] = _uuid(rng), when, when
        else:
            rec["time"] = when
            rec["uuid"] = _uuid(rng)
        noise.append((when, rec))
    timed = [(parse_ts(r.get("eventTime") or r.get("stageTimestamp") or r.get("time")), n, r)
             for n, r in enumerate([*chain, *(r for _, r in noise)])]
    timed.sort(key=lambda x: (x[0], x[1]))
    return [json.dumps(r, separators=(",", ":")) + "\n" for _, _, r in timed]


def bench(pipeline, lines):
    """Process every line fully, one at a time, and time each. Pipeline time only."""
    per_event = []
    started = _time.perf_counter()
    for line in lines:
        t0 = _time.perf_counter()
        pipeline.process(json.loads(line))
        per_event.append(_time.perf_counter() - t0)
    total = _time.perf_counter() - started
    ms = sorted(x * 1000 for x in per_event)
    q = statistics.quantiles(ms, n=100, method="inclusive")
    return {"events": len(lines), "total_seconds": round(total, 3), "events_per_second": round(len(lines) / total, 1),
            "p50_ms": round(q[49], 3), "p95_ms": round(q[94], 3), "max_ms": round(ms[-1], 3)}
