"""ask: the model writes a query in a fixed language; code checks it and runs it read-only."""

import pytest

from codeguardian.v2.ask import QueryError, ask, check_query
from v2_helpers import FINANCE, ROLE, build, dump


class QueryModel:
    def __init__(self, query):
        self.query, self.calls = query, []

    def complete_json(self, system, user, schema):
        self.calls.append(user)
        return {"query": self.query, "note": "n"}, {"model": "stub", "served_by": "stub", "usage": {}}


def test_ask_runs_a_valid_query_read_only(tmp_path):
    store, _ = build(tmp_path)
    before = dump(store)
    model = QueryModel({"find": "s3_bucket", "where": [{"attr": "sensitive", "op": "eq", "value": True}],
                        "related": [{"edge": "has_permission", "dir": "in", "to": "iam_role"}], "limit": 10})
    result = ask(store, "Which roles can reach sensitive buckets?", model)
    assert {(r["from"], r["id"]) for r in result["rows"]} >= {(FINANCE, ROLE)}
    assert dump(store) == before
    # The model saw the question and the language, never the data.
    assert "sentinel-agent" not in model.calls[0] and "example-finance-records" not in model.calls[0]


@pytest.mark.parametrize("query", [
    "SELECT * FROM entities",
    ["find", "pod"],
    {"find": "pod", "where": [], "related": [], "limit": 10, "sql": "DROP TABLE entities"},
    {"find": "vm", "where": [], "related": [], "limit": 10},
    {"find": "pod", "where": [{"attr": "labels", "op": "nonempty"}], "related": [], "limit": 10},
    {"find": "pod", "where": [{"attr": "privileged", "op": "regex", "value": ".*"}], "related": [], "limit": 10},
    {"find": "pod", "where": [], "related": [{"edge": "peers_with", "dir": "out"}], "limit": 10},
    {"find": "pod", "where": [], "related": [], "limit": 100000},
    {"find": "pod", "where": "privileged", "related": [], "limit": 10},
])
def test_ask_refuses_malformed_and_out_of_schema_queries(tmp_path, query):
    store, _ = build(tmp_path)
    before = dump(store)
    with pytest.raises(QueryError):
        ask(store, "anything", QueryModel(query))
    assert dump(store) == before


def test_ask_query_language_is_checked_without_a_model():
    assert check_query({"find": "pod", "where": [{"attr": "privileged", "op": "eq", "value": True}],
                        "related": [], "limit": 5})["limit"] == 5
    with pytest.raises(QueryError):
        check_query({"find": "pod", "where": [], "related": [], "limit": 0})


def test_ask_limit_stops_the_answer(tmp_path):
    store, _ = build(tmp_path)
    result = ask(store, "all pods", QueryModel({"find": "pod", "where": [], "related": [], "limit": 2}))
    assert len(store.entities("pod")) == 4
    assert len(result["rows"]) == 2 and result["truncated"] is True
