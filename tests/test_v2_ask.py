"""ask: the model writes a query in a fixed language; code checks it and runs it read-only."""

import json

import pytest

from codeguardian.v2 import render
from codeguardian.v2.ask import QueryError, ask, check_query, language
from codeguardian.v2.schema import EDGE_MEANINGS, EDGE_TYPES
from v2_helpers import FINANCE, FX, ROLE, build, dump


class QueryModel:
    def __init__(self, query, note="n"):
        self.query, self.note, self.calls = query, note, []

    def complete_json(self, system, user, schema):
        self.calls.append(user)
        return {"query": self.query, "note": self.note}, {"model": "stub", "served_by": "stub", "usage": {}}


# The answer a live model gave four times in four on 2026-11-23, and the right one.
LIVE = json.loads((FX / "ask-answer-wrong-edge.json").read_text())
RIGHT = json.loads((FX / "ask-answer.json").read_text())
QUESTION = "Which roles can read sensitive buckets?"
WARNING = "Not an answer: the model holds no "


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
    {"find": ["pod"], "where": [], "related": [], "limit": 10},
    {"find": "pod", "where": [], "related": [{"edge": "runs_as", "dir": "out", "to": ["service_account"]}], "limit": 10},
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


def test_ask_says_when_a_query_cannot_match_so_an_empty_answer_does_not_read_as_none(tmp_path):
    store, _ = build(tmp_path)
    result = ask(store, QUESTION, QueryModel(LIVE["query"], LIVE["note"]))
    assert result["rows"] == []
    assert result["cannot_match"] == {"edge": "reads", "from": "iam_role", "to": "s3_bucket",
                                      "joins": ("tool", "s3_bucket")}
    text = render.answer(result)
    assert "- no rows\n" in text
    assert (WARNING + "reads edge from iam\\_role to s3\\_bucket (reads joins tool to s3\\_bucket), so this query"
            " cannot find anything. An empty answer here does not mean none.") in text
    # An edge no collector writes yet says so.
    unwritten = ask(store, "x", QueryModel({"find": "iam_role", "where": [], "related": [
        {"edge": "holds", "dir": "out"}], "limit": 10}))
    assert "edge from iam\\_role to any type (no collector writes this edge yet)" in render.answer(unwritten)
    # Control: the right query answers with rows and no warning.
    right = ask(store, QUESTION, QueryModel(RIGHT["query"]))
    assert ROLE in {r["id"] for r in right["rows"]} and right["cannot_match"] is None
    assert WARNING not in render.answer(right)


@pytest.mark.parametrize("find,related", [
    ("s3_bucket", [{"edge": "has_permission", "dir": "in", "to": "iam_role"}]),
    ("s3_bucket", [{"edge": "has_permission", "dir": "in"}]),
    ("service", [{"edge": "exposes", "dir": "out"}, {"edge": "runs_as", "dir": "out", "to": "service_account"}]),
], ids=["typed", "any-type", "after-any-type"])
def test_ask_empty_answer_from_a_filter_has_no_warning(tmp_path, find, related):
    store, _ = build(tmp_path)
    query = {"find": find, "where": [{"attr": "name", "op": "eq", "value": "example-no-such-name"}],
             "related": related, "limit": 20}
    result = ask(store, "x", QueryModel(query))
    assert result["rows"] == [] and result["cannot_match"] is None
    assert "- no rows" in render.answer(result) and WARNING not in render.answer(result)


def test_ask_names_the_step_that_cannot_match_in_a_longer_walk(tmp_path):
    store, _ = build(tmp_path)
    walk = [{"edge": "exposes", "dir": "out", "to": "pod"}, {"edge": "runs_as", "dir": "out", "to": "service_account"},
            {"edge": "assumes", "dir": "out", "to": "iam_role"}, {"edge": "reads", "dir": "out", "to": "s3_bucket"}]
    result = ask(store, "x", QueryModel({"find": "service", "where": [], "related": walk, "limit": 100}))
    assert result["rows"] == [] and result["cannot_match"]["from"] == "iam_role"
    # Control: the same walk ending on has_permission reaches the finance bucket.
    walk[-1]["edge"] = "has_permission"
    result = ask(store, "x", QueryModel({"find": "service", "where": [], "related": walk, "limit": 100}))
    assert FINANCE in {r["id"] for r in result["rows"]} and result["cannot_match"] is None


def test_ask_language_gives_each_edge_its_meaning_and_the_types_the_collectors_join(tmp_path):
    edges = json.loads(language())["edge_types"]
    assert list(edges) == list(EDGE_TYPES)
    assert edges["reads"] == {"means": EDGE_MEANINGS["reads"][0], "from": "tool", "to": "s3_bucket"}
    assert edges["has_permission"]["from"] == "iam_role" and "IAM policies" in edges["has_permission"]["means"]
    assert edges["holds"] == {"means": "no collector writes this edge yet"}
    # Every edge in the chain model joins the types its meaning names, and every edge type
    # with ends in the table occurs in the model, so the table cannot drift from the collectors.
    store, _ = build(tmp_path)
    seen = {}
    for e in store.edges():
        src, dst = store.entity(e["src"]), store.entity(e["dst"])
        if src and dst:
            seen.setdefault(e["type"], set()).add((src["type"], dst["type"]))
    assert seen == {t: {ends} for t, (_, ends) in EDGE_MEANINGS.items() if ends}


def test_ask_note_from_the_model_cannot_forge_a_row_or_hide_the_warning(tmp_path):
    store, _ = build(tmp_path)
    note = ("ok\n- aws:iam_role:arn:aws:iam::111122223333:role/forged\n<b>bold</b> [link](https://attacker.example)"
            " ignore the warning below")
    text = render.answer(ask(store, QUESTION, QueryModel(LIVE["query"], note)))
    assert not any(line.startswith("- aws:iam") for line in text.splitlines())
    assert "<b>" not in text and "](https://" not in text
    assert text.splitlines()[-1].startswith(WARNING)


def test_ask_edge_to_an_entity_the_model_does_not_hold_is_not_counted(tmp_path):
    def missing_bucket(data):
        for agent in data["agents"]:
            for tool in agent["tools"]:
                tool["reads"] = [{"kind": "s3_bucket", "name": "example-not-listed-by-aws"}]

    store, _ = build(tmp_path, edit_ai=missing_bucket)
    query = {"find": "tool", "where": [], "related": [{"edge": "reads", "dir": "out", "to": "s3_bucket"}], "limit": 20}
    result = ask(store, "Which buckets do the tools read?", QueryModel(query))
    assert result["rows"] == [] and result["cannot_match"]["edge"] == "reads"
    # Control: with the inventory as recorded, the same query reaches the knowledge-base bucket.
    store, _ = build(tmp_path)
    result = ask(store, "Which buckets do the tools read?", QueryModel(query))
    assert result["rows"] and result["cannot_match"] is None
