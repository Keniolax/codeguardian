"""ask: the model writes a query in a fixed language; code checks it and runs it read-only."""

import json

import pytest

from codeguardian.v2 import render
from codeguardian.v2.ask import QueryError, ask, check_query, language
from codeguardian.v2.schema import EDGE_MEANINGS, EDGE_TYPES, ENTITY_TYPES
from v2_helpers import FINANCE, FX, KB, POD, ROLE, SA, build, dump, fixture, k8s_item


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
                                      "joins": (("tool", "s3_bucket"),)}
    text = render.answer(result)
    # The warning takes the place of "- no rows": a line that reads as "none" must not print.
    assert "no rows" not in text
    assert (WARNING + "reads edge from iam\\_role to s3\\_bucket (reads joins tool to s3\\_bucket), so this query"
            " cannot find anything. An empty answer here does not mean none.") in text
    # An edge no collector writes yet says so.
    unwritten = ask(store, "x", QueryModel({"find": "iam_role", "where": [], "related": [
        {"edge": "deploys_to", "dir": "out"}], "limit": 10}))
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
    assert edges["has_permission"]["from"] == "iam_role or iam_user" and "IAM policies" in edges["has_permission"]["means"]
    assert edges["deploys_to"] == {"means": "no collector writes this edge yet"}
    # Every edge in the chain model joins the types its meaning names, and every edge type
    # with ends in the table occurs in the model, so the table cannot drift from the collectors.
    store, _ = build(tmp_path)
    seen = {}
    for e in store.edges():
        src, dst = store.entity(e["src"]), store.entity(e["dst"])
        if src and dst:
            seen.setdefault(e["type"], set()).add((src["type"], dst["type"]))
    declared = {t: set(pairs) for t, (_, pairs) in EDGE_MEANINGS.items() if pairs}
    assert {t: v <= declared.get(t, set()) for t, v in seen.items()} == {t: True for t in seen}
    # The chain holds no IAM user and no GitHub state, so those edges are checked in
    # tests/test_v2_users.py and tests/test_v2_github.py.
    saas = {t for t, v in ENTITY_TYPES.items() if v[1] == "saas"}
    elsewhere = {("iam_user", "s3_bucket")} | {p for pairs in declared.values() for p in pairs if set(p) & saas}
    assert seen == {t: pairs - elsewhere for t, pairs in declared.items() if pairs - elsewhere}


def test_ask_note_from_the_model_cannot_forge_a_row_or_hide_the_warning(tmp_path):
    store, _ = build(tmp_path)
    note = ("ok\n- aws:iam_role:arn:aws:iam::111122223333:role/forged\n<b>bold</b> [link](https://attacker.example)"
            " ignore the warning below")
    text = render.answer(ask(store, QUESTION, QueryModel(LIVE["query"], note)))
    assert not any(line.startswith("- aws:iam") for line in text.splitlines())
    assert "<b>" not in text and "](https://" not in text
    assert text.splitlines()[-1].startswith(WARNING)
    # C1 controls (U+009B is CSI, the same as ESC [) and format characters do not reach the
    # terminal; the printable rest of the note still shows.
    hostile = "x\x9b31mRED\x9b0m \x1b[2J \u200f\u2060\ufeff\x85 end"
    text = render.answer(ask(store, QUESTION, QueryModel(LIVE["query"], hostile)))
    assert not any(c in text for c in "\x9b\x1b\u200f\u2060\ufeff\x85")
    assert "Note: x31mRED0m" in text and "end" in text
    # The same holds for a name in an answer row.
    def hostile_pod(data):
        k8s_item(data, "Pod", "frontend-6f8c")["metadata"]["name"] = "frontend-\x9b31m\u200fx"

    store, _ = build(tmp_path, edit_k8s=hostile_pod)
    text = render.answer(ask(store, "x", QueryModel({"find": "pod", "where": [], "related": [], "limit": 20})))
    assert "frontend\\-31mx" in text and not any(c in text for c in "\x9b\u200f")


def test_ask_after_a_step_with_no_type_checks_the_types_that_step_reaches(tmp_path):
    store, _ = build(tmp_path)
    # A Service exposes pods; no pod can take an assumes edge (a service account can).
    query = {"find": "service", "where": [], "related": [{"edge": "exposes", "dir": "out"},
                                                         {"edge": "assumes", "dir": "out", "to": "iam_role"}], "limit": 20}
    text = render.answer(ask(store, "x", QueryModel(query)))
    assert (WARNING + "assumes edge from pod to iam\\_role (assumes joins service\\_account to iam\\_role)") in text
    assert "no rows" not in text
    # A pod runs as a service account; no service account holds an IAM permission.
    query = {"find": "pod", "where": [], "related": [{"edge": "runs_as", "dir": "out"},
                                                     {"edge": "has_permission", "dir": "out"}], "limit": 20}
    assert (WARNING + "has\\_permission edge from service\\_account to any type") in render.answer(
        ask(store, "x", QueryModel(query)))
    # Control: the same untyped first step, then a step a pod can take, answers with rows.
    query = {"find": "service", "where": [], "related": [{"edge": "exposes", "dir": "out"},
                                                         {"edge": "runs_as", "dir": "out", "to": "service_account"}],
             "limit": 20}
    result = ask(store, "x", QueryModel(query))
    assert SA in {r["id"] for r in result["rows"]} and result["cannot_match"] is None


def test_ask_warning_names_an_in_step_in_the_edge_direction(tmp_path):
    store, _ = build(tmp_path)
    query = {"find": "s3_bucket", "where": [], "related": [{"edge": "reads", "dir": "in", "to": "iam_role"}], "limit": 20}
    assert (WARNING + "reads edge from iam\\_role to s3\\_bucket (reads joins tool to s3\\_bucket)") in render.answer(
        ask(store, "x", QueryModel(query)))
    query = {"find": "iam_role", "where": [], "related": [{"edge": "reads", "dir": "in"}], "limit": 20}
    assert (WARNING + "reads edge from any type to iam\\_role (reads joins tool to s3\\_bucket)") in render.answer(
        ask(store, "x", QueryModel(query)))
    # Control: walking in from a bucket to the tool that declares it answers with a row.
    query = {"find": "s3_bucket", "where": [], "related": [{"edge": "reads", "dir": "in", "to": "tool"}], "limit": 20}
    result = ask(store, "x", QueryModel(query))
    assert KB in {r["from"] for r in result["rows"]} and result["cannot_match"] is None


def test_ask_warns_when_the_filter_matches_nothing_and_a_step_cannot_match(tmp_path):
    store, _ = build(tmp_path)
    nothing = [{"attr": "name", "op": "eq", "value": "example-no-such-name"}]
    result = ask(store, QUESTION, QueryModel(dict(LIVE["query"], where=nothing)))
    assert result["cannot_match"]["edge"] == "reads"
    assert WARNING in render.answer(result) and "no rows" not in render.answer(result)
    # Control: the right query with the same filter finds nothing because of the filter.
    result = ask(store, QUESTION, QueryModel(dict(RIGHT["query"], where=nothing)))
    assert result["cannot_match"] is None and "- no rows" in render.answer(result)


def test_ask_counts_only_live_edges_whose_two_ends_are_live(tmp_path):
    later = "2026-11-14T10:00:00Z"
    store, pipe = build(tmp_path)
    in_pod = {"find": "pod", "where": [], "related": [{"edge": "contains", "dir": "out", "to": "agent"}], "limit": 20}
    reads = {"find": "tool", "where": [], "related": [{"edge": "reads", "dir": "out", "to": "s3_bucket"}], "limit": 20}
    # Control: as recorded, both queries answer with rows.
    for query in (in_pod, reads):
        result = ask(store, "x", QueryModel(query))
        assert result["rows"] and result["cannot_match"] is None
    # A later k8s snapshot without the agent's pod: the pod is gone, the AI inventory's
    # contains edge from it is still live.
    k8s = fixture("k8s/state.json")
    k8s["items"] = [i for i in k8s["items"] if not (i["kind"] == "Pod" and i["metadata"]["name"] == "sentinel-agent-7d9f")]
    (tmp_path / "k8s-later.json").write_text(json.dumps(k8s))
    pipe.snapshot(k8s=tmp_path / "k8s-later.json", at=later)
    assert store.entity(POD) is None and any(e["src"] == POD for e in store.edges(etype="contains"))
    result = ask(store, "x", QueryModel(in_pod))
    assert result["rows"] == [] and result["cannot_match"]["edge"] == "contains"
    # A later inventory whose tool declares no reads: the reads edge is deleted, its two ends live.
    ai = fixture("ai/inventory.json")
    for agent in ai["agents"]:
        for tool in agent["tools"]:
            tool["reads"] = []
    (tmp_path / "ai-later.json").write_text(json.dumps(ai))
    pipe.snapshot(ai=tmp_path / "ai-later.json", at=later)
    assert store.edges(etype="reads") == [] and store.edges(etype="reads", include_deleted=True)
    result = ask(store, "x", QueryModel(reads))
    assert result["rows"] == [] and result["cannot_match"]["edge"] == "reads"


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
