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
"""

import json

from . import rules as R
from .schema import EDGE_TYPES, ENTITY_TYPES

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
note on what it asks. Use only the entity types, attrs and edge types listed."""


class QueryError(ValueError):
    pass


def language():
    return json.dumps({"entity_types": {t: list(v[2]) for t, v in ENTITY_TYPES.items()},
                       "edge_types": list(EDGE_TYPES), "ops": list(R.OPS), "max_limit": MAX_LIMIT}, indent=1)


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
                return {"query": q, "rows": rows, "truncated": True}
    return {"query": q, "rows": rows, "truncated": False}


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
