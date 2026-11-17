"""The history of each finding in data time, rebuilt on read.

The journal holds every snapshot the model was given, the ones refused as older included,
because each says what held at its own time, and every IAM change record. Replaying them
in a scratch model, in the order of the times in their data, gives each posture and path
finding's status changes (opened, resolved, reopened), each with its time and the input
that caused it. The same inputs give the same history whatever order they arrived in, so
a path that opened and closed between two late records still shows.

A detection opens at its first record and never resolves; its history is that one entry.

Not in the history: a snapshot refused because another snapshot of the same collector
has the same time and other content (which one held is not known; both are marked), and
anything ingested before the journal existed.
"""

import json

from .pipeline import SNAPSHOT_ORDER, Pipeline
from .schema import FixedClock
from .store import Store


def inputs(store):
    """The journal in replay order: by data time, a snapshot before a change record at the
    same time (as the live model orders them), then by source or record ID."""
    groups = {}
    for s in store.snapshots(statuses=("applied", "older")):
        groups.setdefault(s["at"], {})[s["source"]] = json.loads(s["content"])
    out = [(at, 0, ",".join(sorted(g, key=SNAPSHOT_ORDER.index)), g) for at, g in groups.items()]
    out += [(c["time"], 1, c["event_id"], c["change"]) for c in store.model_changes()]
    return sorted(out, key=lambda x: x[:3])


def replay(store, rules, now):
    """Replay the journal into a new model in memory. Returns that model and the log of
    status changes: (finding ID, time, change, cause)."""
    scratch = Store()
    pipe = Pipeline(scratch, rules, FixedClock(now))
    pipe.recorder = []
    for at, kind, key, payload in inputs(store):
        if kind == 0:
            pipe.cause = ("snapshot", key, at)
            pipe.apply_snapshot(payload, at)
        else:
            pipe.cause = ("record", key, at)
            pipe.apply_change_record({"time": at, "event_id": key}, payload)
    return scratch, pipe.recorder


def history(store, rules, now):
    """Every finding with its status changes, oldest first."""
    scratch, log = replay(store, rules, now)
    out = {}
    for fid, at, change, cause in log:
        entry = out.setdefault(fid, {"finding": scratch.finding(fid), "changes": []})
        entry["changes"].append({"time": at, "change": change, "cause": cause})
    for f in store.findings(kind="detection"):
        evs = sorted((ev["time"], ev["event_id"]) for ev in (store.event(e) for e in f["events"]) if ev)
        time, eid = evs[0] if evs else (f["first_seen"], None)
        out[f["finding_id"]] = {"finding": f, "changes": [{"time": time, "change": "opened",
                                                           "cause": ("record", eid, time)}]}
    return sorted(out.values(), key=lambda e: (e["changes"][0]["time"], e["finding"]["rule_id"],
                                               e["finding"]["finding_id"]))
