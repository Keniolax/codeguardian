"""ask: the model turns a plain-English question into a query; code checks the query and
runs it read-only.

The model sees the question and the query language, never the store. Its query is a JSON
document:

    {"find": "<entity type>",
     "where": [{"attr": "<typed attr>", "op": "eq|ne|nonempty|empty|in|prefix", "value": ...}],
     "related": [{"edge": "<edge type>", "dir": "out|in", "to": "<entity type>"}],
     "limit": 1-100}

"where" filters entities of the "find" type by their typed attrs (never labels).
"related" walks edges from each match; the answer is the entities the walk reaches.
Anything else in the document, or any unknown type, attr, op or edge, refuses the query.

The language tells the model what each edge type means and which entity types it joins.
An empty answer from a walk step that no edge in the model can take says nothing about
the data, so the answer names that step instead of reading as "none".
"""

import json

from . import rules as R
from .schema import EDGE_MEANINGS, EDGE_TYPES, ENTITY_TYPES

MAX_LIMIT = 100
KEYS = {"find", "where", "related", "limit"}

QUERY_SCHEMA = {
    "type": "object",
    "properties": {
        "find": {"type": "string", "enum": sorted(ENTITY_TYPES)},
        "where": {"type": "array", "items": {
            "type": "object",
            "properties": {"attr": {"type": "string"}, "op": {"type": "string", "enum": list(R.OPS)},
                           "value": {"anyOf": [{"type": "string"}, {"type": "boolean"}, {"type": "number"},
                                               {"type": "array", "items": {"type": "string"}}]}},
            "required": ["attr", "op"], "additionalProperties": False}},
        "related": {"type": "array", "items": {
            "type": "object",
            "properties": {"edge": {"type": "string", "enum": list(EDGE_TYPES)},
                           "dir": {"type": "string", "enum": ["out", "in"]},
                           "to": {"type": "string", "enum": sorted(ENTITY_TYPES)}},
            "required": ["edge", "dir"], "additionalProperties": False}},
        "limit": {"type": "integer"},
    },
    "required": ["find", "where", "related", "limit"],
    "additionalProperties": False,
}

ANSWER_SCHEMA = {"type": "object", "properties": {"query": QUERY_SCHEMA, "note": {"type": "string"}},
                 "required": ["query", "note"], "additionalProperties": False}

SYSTEM = """You translate a security analyst's question into one query for CodeGuardian.
You do not see the data and you cannot run anything. Return JSON with the query and a short
note on what it asks. Use only the entity types, attrs and edge types listed.
The steps in "related" form one chain: each step starts from the entities the step before
it reached, and the answer is where the last step ends. Each edge type joins the two
entity types listed for it, in that direction: walk "out" from its "from" type and "in"
from its "to" type. "where" filters only the "find" type, so start from the type whose
attrs the question names. Each answer row shows the entity the walk reached and the "find"
entity it started from, so a question about one type with a condition on another starts
from the type with the condition and walks to the type asked about."""


class QueryError(ValueError):
    pass


def _either(types):
    """Types in first-seen order, as "a or b"."""
    return " or ".join(dict.fromkeys(types))


def language():
    edges = {}
    for t in EDGE_TYPES:
        means, pairs = EDGE_MEANINGS[t]
        edges[t] = {"means": means, "from": _either(p[0] for p in pairs), "to": _either(p[1] for p in pairs)} \
            if pairs else {"means": means}
    return json.dumps({"entity_types": {t: list(v[2]) for t, v in ENTITY_TYPES.items()},
                       "edge_types": edges, "ops": list(R.OPS), "max_limit": MAX_LIMIT}, indent=1)


def check_query(q):
    """Validate a query document. Raises QueryError; never repairs or guesses."""
    if not isinstance(q, dict):
        raise QueryError("query is not a JSON object")
    extra = set(q) - KEYS
    if extra:
        raise QueryError(f"unknown query keys {sorted(extra)}")
    if not isinstance(q.get("find"), str) or q["find"] not in ENTITY_TYPES:
        raise QueryError(f"unknown entity type {q.get('find')!r}")
    where, related, limit = q.get("where", []), q.get("related", []), q.get("limit", 20)
    if not isinstance(where, list) or not isinstance(related, list):
        raise QueryError("where and related must be lists")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise QueryError(f"limit must be an integer from 1 to {MAX_LIMIT}")
    try:
        for c in where:
            R._cond(c, {"id": "query"}, q["find"])
        for s in related:
            R._step(s, {"id": "query"})
    except R.RuleError as exc:
        raise QueryError(str(exc)) from exc
    return {"find": q["find"], "where": where, "related": related, "limit": limit}


def run(store, q):
    """Run a checked query. It only reads: entities by type, and edges by node."""
    q = check_query(q)
    matches = [e for e in store.entities(q["find"]) if all(R.check(c, e["attrs"]) for c in q["where"])]
    rows = []
    for e in matches:
        reached = R.walk(store, {e["id"]}, q["related"]) if q["related"] else {e["id"]}
        for rid in sorted(reached):
            rows.append({"from": e["id"], "id": rid})
            if len(rows) >= q["limit"]:
                return {"query": q, "rows": rows, "truncated": True, "cannot_match": None}
    gap = None
    if not rows and q["related"]:
        gap = cannot_match(store, q)
    return {"query": q, "rows": rows, "truncated": False, "cannot_match": gap}


def cannot_match(store, q):
    """The first walk step that no live edge in the model can take from the type the walk
    is at, or None. A query with such a step finds nothing whatever the data holds."""
    at = q["find"]
    for s in q["related"]:
        etype, to = s["edge"], s.get("to")
        near, far = ("src", "dst") if s["dir"] == "out" else ("dst", "src")
        found = False
        for e in store.edges(etype=etype):
            a, b = store.entity(e[near]), store.entity(e[far])
            if a is None or b is None:
                continue
            if (at is None or a["type"] == at) and (to is None or b["type"] == to):
                found = True
                break
        if not found:
            src, dst = (at, to) if s["dir"] == "out" else (to, at)
            return {"edge": etype, "from": src or "any type", "to": dst or "any type",
                    "joins": EDGE_MEANINGS[etype][1]}
        at = to
    return None


def ask(store, question, provider):
    user = ("<question>\n" + str(question)[:2000] + "\n</question>\n\n<query_language>\n" + language()
            + "\n</query_language>")
    raw, meta = provider.complete_json(SYSTEM, user, ANSWER_SCHEMA)
    if not isinstance(raw, dict):
        raise QueryError("model answer is not a JSON object")
    result = run(store, raw.get("query"))
    note = raw.get("note") if isinstance(raw.get("note"), str) else ""
    result.update(note=note[:500], served_by=meta.get("served_by"))
    return result
