"""Path rules: a fixed sequence of typed hops, walked depth-first from every live entity of
the start type. Each complete walk is one finding.

The rule loader caps a rule at MAX_HOPS hops, so every walk is bounded. A node is never
entered twice in one walk, so a rule whose hops lead back to a node it passed (out over
one edge type and back over another) cannot loop.
"""

from . import rules as R
from .policy import NOT_IN_DATA, action_matches
from .schema import finding_id


def _edge_ok(hop, edge):
    allows = hop.get("edge_allows")
    if not allows:
        return True
    patterns = edge["attrs"].get("actions", [])
    return all(any(action_matches(p, a) for p in patterns) for a in allows)


def _node_ok(store, hop, ent):
    if ent["type"] != hop["to"]:
        return False, set()
    if not all(R.check(c, ent["attrs"]) for c in hop.get("where", [])):
        return False, set()
    extra = set()
    for s in hop.get("require", []):
        found = R.step(store, {ent["id"]}, s)
        if not found:
            return False, set()
        extra |= found
    return True, extra


def evaluate(store, rule, now):
    hops, found = rule["hops"], []

    def dfs(node, i, nodes, edges, extra):
        if i == len(hops):
            found.append((list(nodes), list(edges), set(extra)))
            return
        hop = hops[i]
        for e in store.edges(node, hop["edge"], hop["dir"]):
            other = e["dst"] if hop["dir"] == "out" else e["src"]
            if other in nodes or not _edge_ok(hop, e):
                continue
            ent = store.entity(other)
            if ent is None:
                continue
            ok, more = _node_ok(store, hop, ent)
            if not ok:
                continue
            nodes.append(other)
            edges.append(e)
            dfs(other, i + 1, nodes, edges, extra | more)
            nodes.pop()
            edges.pop()

    for start in store.entities(rule["start"]):
        dfs(start["id"], 0, [start["id"]], [], set())

    out = []
    for nodes, edges, extra in found:
        notes = set()
        for e in edges:
            notes.update(e["attrs"].get("not_evaluated", []))
            if e["type"] == "has_permission":
                notes.add(NOT_IN_DATA)
            if store.is_stale(e, now):
                notes.add(f"stale: {e['type']} edge {e['src']} -> {e['dst']} not confirmed recently")
        for n in nodes + sorted(extra):
            ent = store.entity(n)
            if ent and store.is_stale(ent, now):
                notes.add(f"stale: {n} not confirmed recently")
            if ent and ent["type"] == "iam_role":
                notes.update(ent["attrs"].get("not_evaluated", []))
        primary = nodes[-1]
        out.append({
            "finding_id": finding_id(rule["id"], primary, nodes), "kind": "path", "rule_id": rule["id"],
            "rule_version": rule["version"], "severity": rule["severity"], "title": rule["title"],
            "primary_entity": primary, "entities": sorted(set(nodes) | extra), "path": nodes,
            "events": [], "frameworks": rule["frameworks"], "notes": sorted(notes),
        })
    return out
