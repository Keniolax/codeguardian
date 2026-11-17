"""Rules are data in TOML. This module loads them, refuses anything it does not understand,
and holds the small graph walk that all three rule kinds share.

A rule can name only typed attrs, never labels. Labels are free text from the
environment, so a rule that read them would let an attacker who can set a tag decide a
finding.

A path rule may cross an `exposes` edge only where NetworkPolicy does not deny a
connection from outside (the GATE condition). Such a path still matters when a policy
closes it, because the answer rests on the cluster's network plugin enforcing policy,
which the model cannot see. So the loader gives each gated rule a twin, `<id>-NP`, that
finds the same walk where the edge says denied, at low severity. A condition on that
attr of any other form is refused: it could read "not evaluated" as closed.
"""

import copy
import tomllib
from pathlib import Path

from .schema import EDGE_ATTRS, EDGE_TYPES, ENTITY_TYPES, EVENT_SOURCES, OUTCOMES, SEVERITIES

RULES_DIR = Path(__file__).parent / "rules"
MAX_HOPS = 10
OPS = ("eq", "ne", "nonempty", "empty", "in", "prefix")
KINDS = ("posture", "path", "detection")


GATE = {"attr": "ingress_from_outside", "op": "ne", "value": "denied"}
HELD_BACK = {"attr": "ingress_from_outside", "op": "eq", "value": "denied"}
SHADOW_SUFFIX = "-NP"
SHADOW_SEVERITY = "low"
SHADOW_NOTES = (
    "depends on the cluster's network plugin enforcing NetworkPolicy",
    "depends on the source address the pod sees for a connection from outside the cluster; a load balancer"
    " or the node may change it, and traffic from the pod's own node is always allowed",
)


class RuleError(ValueError):
    pass


def _need(cond, rule, message):
    if not cond:
        raise RuleError(f"rule {rule.get('id', '?')}: {message}")


def _is(value, collection):
    """Membership that refuses non-strings instead of raising TypeError on a list."""
    return isinstance(value, str) and value in collection


def _keys(obj, allowed, rule, where):
    _need(isinstance(obj, dict), rule, f"{where} must be a table")
    extra = set(obj) - set(allowed)
    _need(not extra, rule, f"unknown key(s) {sorted(extra)} in {where}")


def _cond(c, rule, etype=None, edge=None):
    _keys(c, ("attr", "op", "value"), rule, "condition")
    _need(_is(c.get("op"), OPS), rule, f"unknown op {c.get('op')!r}")
    _need(isinstance(c.get("attr"), str), rule, "condition needs attr")
    if etype is not None:
        _need(_is(c["attr"], ENTITY_TYPES[etype][2]), rule, f"entity type {etype} has no attr {c['attr']!r}")
    if edge is not None:
        _need(_is(c["attr"], EDGE_ATTRS.get(edge, ())), rule, f"edge type {edge} has no attr {c['attr']!r}")
    if c["op"] not in ("nonempty", "empty"):
        _need("value" in c, rule, f"op {c['op']} needs a value")
    if c["op"] == "in":
        _need(isinstance(c["value"], list), rule, "op in needs a list")


def _step(s, rule):
    _keys(s, ("edge", "dir", "to"), rule, "walk step")
    _need(_is(s.get("edge"), EDGE_TYPES), rule, f"unknown edge type {s.get('edge')!r}")
    _need(_is(s.get("dir"), ("out", "in")), rule, "dir must be out or in")
    if "to" in s:
        _need(_is(s["to"], ENTITY_TYPES), rule, f"unknown entity type {s['to']!r}")


def validate(rule):
    _need(isinstance(rule, dict), rule if isinstance(rule, dict) else {}, "not a table")
    common = ("id", "version", "kind", "severity", "title", "frameworks")
    for key in common:
        _need(key in rule, rule, f"missing {key}")
    _need(_is(rule["kind"], KINDS), rule, f"unknown kind {rule['kind']!r}")
    _need(isinstance(rule["version"], int), rule, "version must be an integer")
    _need(_is(rule["severity"], SEVERITIES), rule, f"unknown severity {rule['severity']!r}")
    _need(isinstance(rule["frameworks"], list) and all(isinstance(f, str) for f in rule["frameworks"]),
          rule, "frameworks must be a list of strings")
    kind = rule["kind"]
    if kind == "posture":
        _keys(rule, common + ("entity", "where"), rule, "rule")
        _need(_is(rule.get("entity"), ENTITY_TYPES), rule, f"unknown entity type {rule.get('entity')!r}")
        _need(isinstance(rule.get("where"), list) and rule["where"], rule, "where must be a non-empty list")
        for c in rule["where"]:
            _cond(c, rule, rule["entity"])
    elif kind == "path":
        _keys(rule, common + ("start", "hops", "notes"), rule, "rule")
        _need(isinstance(rule.get("notes", []), list) and all(isinstance(n, str) for n in rule.get("notes", [])),
              rule, "notes must be a list of strings")
        _need(_is(rule.get("start"), ENTITY_TYPES), rule, f"unknown start type {rule.get('start')!r}")
        _need(isinstance(rule.get("hops"), list) and rule["hops"], rule, "hops must be a non-empty list")
        _need(len(rule["hops"]) <= MAX_HOPS, rule, f"{len(rule['hops'])} hops; the limit is {MAX_HOPS}")
        for h in rule["hops"]:
            _keys(h, ("edge", "dir", "to", "where", "edge_where", "edge_allows", "require"), rule, "hop")
            _step({k: h[k] for k in ("edge", "dir", "to") if k in h}, rule)
            _need("to" in h, rule, "every hop needs a to type")
            for c in h.get("where", []):
                _cond(c, rule, h["to"])
            _need(isinstance(h.get("edge_where", []), list), rule, "edge_where must be a list")
            for c in h.get("edge_where", []):
                _cond(c, rule, edge=h["edge"])
                if c["attr"] == GATE["attr"]:
                    _need(c in (GATE, HELD_BACK), rule, f"{GATE['attr']} may be tested only as ne denied"
                          " or eq denied; another form could read not evaluated as closed")
            if "edge_allows" in h:
                _need(h["edge"] == "has_permission", rule, "edge_allows applies only to has_permission")
                _need(isinstance(h["edge_allows"], list) and h["edge_allows"], rule, "edge_allows must be a list")
            for s in h.get("require", []):
                _step(s, rule)
    else:
        _keys(rule, common + ("match", "when"), rule, "rule")
        m = rule.get("match")
        _keys(m, ("source", "actions", "outcome", "actor_type", "attrs"), rule, "match")
        _need(_is(m.get("source"), EVENT_SOURCES), rule, f"unknown source {m.get('source')!r}")
        _need(isinstance(m.get("actions"), list) and m["actions"], rule, "match.actions must be a non-empty list")
        if "outcome" in m:
            _need(_is(m["outcome"], OUTCOMES), rule, f"unknown outcome {m['outcome']!r}")
        if "actor_type" in m:
            _need(_is(m["actor_type"], ENTITY_TYPES), rule, f"unknown actor_type {m['actor_type']!r}")
        for c in m.get("attrs", []):
            _cond(c, rule)
        bound = {"actor", "targets"}
        for w in rule.get("when", []):
            _keys(w, ("from", "walk", "bind", "excludes"), rule, "when")
            _need(_is(w.get("from"), bound), rule, f"when.from {w.get('from')!r} is not bound yet")
            _need(isinstance(w.get("walk"), list) and w["walk"], rule, "when.walk must be a non-empty list")
            for s in w["walk"]:
                _step(s, rule)
            _need(("bind" in w) != ("excludes" in w), rule, "each when needs exactly one of bind or excludes")
            if "bind" in w:
                bound.add(w["bind"])
            else:
                _need(_is(w["excludes"], bound), rule, f"excludes {w['excludes']!r} is not bound")
    return rule


def shadow(rule):
    """The `-NP` twin of a path rule that one NetworkPolicy gate holds: the same walk where
    the gated edge says denied. None for a rule with no gate. A rule with two gates is
    refused, since which walks the twin should find is not defined for it."""
    if rule["kind"] != "path":
        return None
    gated = [n for n, h in enumerate(rule["hops"]) if GATE in h.get("edge_where", [])]
    if not gated:
        return None
    _need(len(gated) == 1, rule, f"{len(gated)} hops test {GATE['attr']}; its {SHADOW_SUFFIX} twin is not defined")
    hops = copy.deepcopy(rule["hops"])
    hop = hops[gated[0]]
    hop["edge_where"] = [HELD_BACK if c == GATE else c for c in hop["edge_where"]]
    return validate({
        "id": rule["id"] + SHADOW_SUFFIX, "version": rule["version"], "kind": "path", "severity": SHADOW_SEVERITY,
        "title": f"{rule['title']}, held back only by NetworkPolicy", "frameworks": [], "start": rule["start"],
        "hops": hops, "notes": [*rule.get("notes", []), *SHADOW_NOTES],
    })


def load_rules(directory=RULES_DIR):
    """Load and validate every rule file, and add each path rule's `-NP` twin after it.
    Any error stops the load."""
    rules, seen = [], set()
    files = sorted(Path(directory).glob("*.toml"))
    if not files:
        raise RuleError(f"no rule files in {directory}")
    for path in files:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise RuleError(f"{path.name}: {exc}") from exc
        if set(data) != {"rule"} or not isinstance(data["rule"], list):
            raise RuleError(f"{path.name}: expected only [[rule]] tables")
        for rule in data["rule"]:
            validate(rule)
            for r in (rule, shadow(rule)):
                if r is None:
                    continue
                if r["id"] in seen:
                    raise RuleError(f"{path.name}: duplicate rule id {r['id']}")
                seen.add(r["id"])
                rules.append(r)
    return rules


def check(cond, attrs):
    value = attrs.get(cond["attr"])
    op = cond["op"]
    if op == "eq":
        return value == cond["value"]
    if op == "ne":
        return value != cond["value"]
    if op == "nonempty":
        return bool(value)
    if op == "empty":
        return not value
    if op == "in":
        return value in cond["value"]
    if op == "prefix":
        return isinstance(value, str) and value.startswith(cond["value"])
    raise RuleError(f"unknown op {op!r}")


def step(store, nodes, s):
    """Follow one typed edge from a set of nodes. Only live entities are entered."""
    out = set()
    for node in nodes:
        for e in store.edges(node, s["edge"], s["dir"]):
            other = e["dst"] if s["dir"] == "out" else e["src"]
            ent = store.entity(other)
            if ent is None or ("to" in s and ent["type"] != s["to"]):
                continue
            out.add(other)
    return out


def walk(store, nodes, steps):
    current = set(nodes)
    for s in steps:
        current = step(store, current, s)
        if not current:
            break
    return current


def touched_types(rule):
    """Entity and edge types a rule can see, so a change elsewhere does not re-run it."""
    ents, edges = set(), set()
    if rule["kind"] == "posture":
        ents.add(rule["entity"])
    elif rule["kind"] == "path":
        ents.add(rule["start"])
        for h in rule["hops"]:
            edges.add(h["edge"])
            ents.add(h["to"])
            for s in h.get("require", []):
                edges.add(s["edge"])
                if "to" in s:
                    ents.add(s["to"])
    return ents, edges
