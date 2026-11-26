"""Detection rules: a match on one event, then graph conditions on the model.

The event is joined to the model before any rule sees it: its actor and targets are
entity IDs or null. A rule cannot be evaluated when it needs an actor or a target the
pipeline could not resolve, or walks an edge whose collector has never run: "no such
edge" and "not looked at yet" look the same. That is counted and the record is held for
the next snapshot, never treated as a pass.
"""

from . import rules as R
from .schema import EDGE_MEANINGS, edge_sources, finding_id

UNEVALUABLE = "unevaluable"
CONTEXT_STEPS = (  # identity neighbourhood that lets findings meet in one incident
    ("runs_as", "out"), ("assumes", "out"), ("assumes", "in"), ("runs_as", "in"), ("contains", "out"),
)


def matches(rule, ev):
    m = rule["match"]
    if ev["source"] != m["source"] or ev["action"] not in m["actions"]:
        return False
    if "outcome" in m and ev["outcome"] != m["outcome"]:
        return False
    return all(R.check(c, ev["attrs"]) for c in m.get("attrs", []))


def context(store, nodes):
    """Two steps of identity edges around the actor: pod, service account, role, agent."""
    seen, frontier = set(nodes), set(nodes)
    for _ in range(2):
        nxt = set()
        for direction_edge, direction in CONTEXT_STEPS:
            nxt |= R.step(store, frontier, {"edge": direction_edge, "dir": direction})
        frontier = nxt - seen
        seen |= nxt
    return seen


def step_sources(step):
    """The collectors that write the edges one walk step can take. A step with a "to" type
    rests only on those that write its edge to that type: a walk from a pod to its agent
    does not wait for the GitHub export, which writes other contains edges."""
    pairs = None
    if "to" in step:
        far = 1 if step["dir"] == "out" else 0
        pairs = [p for p in EDGE_MEANINGS[step["edge"]][1] or () if p[far] == step["to"]] or None
    return edge_sources(step["edge"], pairs)


def sources_never_run(store, rule):
    """The collectors a rule's walks depend on that have never completed a snapshot."""
    needed = {name for w in rule.get("when", []) for step in w["walk"] for name in step_sources(step)}
    return sorted(n for n in needed if (store.source(n) or {}).get("last_success") is None)


def evaluate(store, rule, ev):
    """Returns a finding (without status or times), None, or UNEVALUABLE."""
    if not matches(rule, ev):
        return None
    m = rule["match"]
    uses_actor = "actor_type" in m or any(w["from"] == "actor" for w in rule.get("when", []))
    actor = ev["actor"]
    if uses_actor and actor is None:
        return UNEVALUABLE
    binds_targets = any(w["from"] == "targets" and "bind" in w for w in rule.get("when", []))
    if binds_targets and any(t is None for t in ev["targets"]):
        return UNEVALUABLE
    if sources_never_run(store, rule):
        return UNEVALUABLE
    actor_ent = store.entity(actor) if actor else None
    if "actor_type" in m and (actor_ent is None or actor_ent["type"] != m["actor_type"]):
        return None
    bound = {"actor": {actor} if actor else set(), "targets": {t for t in ev["targets"] if t}}
    for w in rule.get("when", []):
        reached = R.walk(store, bound[w["from"]], w["walk"])
        if "bind" in w:
            if not reached:
                return None
            bound[w["bind"]] = reached
        elif reached & bound[w["excludes"]]:
            return None
    primary = actor or (sorted(bound["targets"])[0] if bound["targets"] else ev["event_id"])
    path = sorted(bound["targets"])
    ents = set().union(*bound.values())
    ents |= context(store, bound["actor"])
    return {
        "finding_id": finding_id(rule["id"], primary, path), "kind": "detection", "rule_id": rule["id"],
        "rule_version": rule["version"], "severity": rule["severity"], "title": rule["title"],
        "primary_entity": primary, "entities": sorted(ents), "path": path, "events": [ev["event_id"]],
        "frameworks": rule["frameworks"], "notes": [],
    }
