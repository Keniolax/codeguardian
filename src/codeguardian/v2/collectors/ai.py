"""The declared AI inventory: which agents exist, where each runs, which model endpoint it
calls, which tools it has, and which data source each tool reads.

No standard export exists for this, so the format is our own and kept small:

    {"format": "codeguardian.ai-inventory/v1",
     "agents": [{"name": "...",
                 "runs_in": {"kind": "pod", "cluster": "...", "namespace": "...", "name": "..."},
                 "model": {"endpoint": "https://..."},
                 "tools": [{"name": "...", "reads": [{"kind": "s3_bucket", "name": "..."}]}]}]}

The inventory says what an agent is meant to do. Detection compares what it did against
this declaration, so the inventory is a claim by its owner, not proof of behaviour.
"""

from ..schema import entity_id
from . import Delta, need, read_json

SOURCE = "ai.inventory"
FORMAT = "codeguardian.ai-inventory/v1"


def _str(value):
    return isinstance(value, str) and value != ""


def load(path):
    data = read_json(path, "ai inventory")
    need(isinstance(data, dict) and data.get("format") == FORMAT, "ai inventory", f"format must be {FORMAT!r}")
    need(isinstance(data.get("agents"), list), "ai inventory", "agents must be a list")
    for a in data["agents"]:
        need(isinstance(a, dict) and _str(a.get("name")), "ai inventory", "an agent lacks a name")
        run = a.get("runs_in")
        need(isinstance(run, dict) and run.get("kind") == "pod"
             and all(_str(run.get(k)) for k in ("cluster", "namespace", "name")),
             "ai inventory", f"agent {a['name']!r}: runs_in must name a pod by cluster, namespace and name")
        need(isinstance(a.get("model"), dict) and _str(a["model"].get("endpoint")), "ai inventory",
             f"agent {a['name']!r}: model.endpoint is required")
        need(isinstance(a.get("tools"), list), "ai inventory", f"agent {a['name']!r}: tools must be a list")
        for t in a["tools"]:
            need(isinstance(t, dict) and _str(t.get("name")) and isinstance(t.get("reads"), list), "ai inventory",
                 f"agent {a['name']!r}: each tool needs a name and a reads list")
            for r in t["reads"]:
                need(isinstance(r, dict) and r.get("kind") == "s3_bucket" and _str(r.get("name")), "ai inventory",
                     f"tool {t['name']!r}: each data source must be an s3_bucket with a name")
    return data


def apply(store, data, at):
    delta, seen_e, seen_x = Delta(), set(), set()

    def ent(eid, etype, attrs):
        if store.upsert_entity(eid, etype, attrs, {}, SOURCE, at):
            delta.entity(eid, etype)
        seen_e.add(eid)

    def edge(etype, src, dst):
        xid, changed = store.upsert_edge(etype, src, dst, {}, SOURCE, at)
        if changed:
            delta.edge(etype)
        seen_x.add(xid)

    for a in data["agents"]:
        aid = entity_id("agent", a["name"])
        ent(aid, "agent", {"name": a["name"]})
        run = a["runs_in"]
        edge("contains", entity_id("pod", f"{run['cluster']}/{run['namespace']}/{run['name']}"), aid)
        mid = entity_id("model_endpoint", a["model"]["endpoint"])
        ent(mid, "model_endpoint", {"endpoint": a["model"]["endpoint"]})
        edge("uses_model", aid, mid)
        for t in a["tools"]:
            tid = entity_id("tool", f"{a['name']}/{t['name']}")
            ent(tid, "tool", {"name": t["name"], "agent": a["name"]})
            edge("can_call", aid, tid)
            for r in t["reads"]:
                edge("reads", tid, entity_id("s3_bucket", f"arn:aws:s3:::{r['name']}"))
    gone_e, gone_x = store.sweep(SOURCE, seen_e, seen_x, at)
    for eid, etype in gone_e:
        delta.entity(eid, etype)
    for _, etype in gone_x:
        delta.edge(etype)
    return delta
