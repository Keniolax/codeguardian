"""Answers that rest on a source whose facts may not hold now say so (slices 2e and 2f).

A collector that never ran, failed, is past its refresh period, or had a snapshot refused
as a conflict leaves the model holding old facts or none. `findings` names it. `reach`
(slice 1b), `ask` and a repeated snapshot name it too, in the same words, and exit 2, so
a script cannot read "no rows" or "already in the model" as "nothing has changed".
"""

import json
import re

import pytest

from codeguardian.cli import main as cli
from codeguardian.v2 import ask as ask_module
from codeguardian.v2 import render
from codeguardian.v2.ask import sources
from codeguardian.v2.explain import RecordedProvider
from codeguardian.v2.pipeline import Pipeline
from codeguardian.v2.render import COLLECTORS, safe
from codeguardian.v2.rules import load_rules
from codeguardian.v2.schema import EDGE_SOURCES, ENTITY_TYPES, TYPE_SOURCES, FixedClock
from codeguardian.v2.store import Store
from test_v2_netpol import LAYOUT
from test_v2_users import group, user, with_iam
from v2_helpers import AGENT, FX, NOW, POD, SA, SNAPSHOT_AT, build, chain, dump

FAILED_AT = "2026-11-14T10:10:00Z"
LATER = "2026-11-14T10:15:00Z"
AWS = ["--aws-iam", str(FX / "aws/iam.json"), "--aws-buckets", str(FX / "aws/s3-buckets.json"),
       "--aws-tags", str(FX / "aws/s3-tags.json")]
K8S = ["--k8s", str(FX / "k8s/state.json")]
AI = ["--ai", str(FX / "ai/inventory.json")]
AGENT_ROW = f"- {safe(AGENT)}"
POD_ROW = f"- {safe(POD)} (from {safe(AGENT)})"
NOT_EVALUATED = "note: the answer below rests on facts that may not hold now, so it counts as not evaluated"
AGENTS = {"find": "agent", "where": [], "related": [], "limit": 20}
AGENT_PODS = {"find": "agent", "where": [], "related": [{"edge": "contains", "dir": "in", "to": "pod"}], "limit": 20}
# case -> (the time `ask` treats as now, and the start of the note in the words `findings` uses)
NOT_CURRENT = {
    "failed": (NOW, "source k8s.state: FAILED at 2026-11-14T10:10:00.000000Z: "),
    "stale": ("2026-11-14T11:00:00Z", "source k8s.state: STALE, last good run 2026-11-14T09:55:00.000000Z,"
                                      " older than its refresh period of 1 h."),
    "conflict": (NOW, "k8s.state taken at 2026-11-14T09:55:00.000000Z: refused, another snapshot of k8s.state"
                      " with that time has other content"),
}


def _ingest(db, *args, at=SNAPSHOT_AT, now=NOW):
    return cli(["ingest", "--db", db, "--now", now, "--at", at, *args])


def _ask(tmp_path, db, query, now=NOW):
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"query": query, "note": "written by the test"}))
    return cli(["ask", "--db", db, "--now", now, "--question", "q", "--provider", "recorded", "--answer", str(answer)])


def _truncated(tmp_path, name="truncated.json"):
    path = tmp_path / name
    path.write_text('{"items": [')
    return ["--k8s", str(path)]


def _other_k8s(tmp_path):
    data = json.loads((FX / "k8s/state.json").read_text())
    data["items"].pop()
    path = tmp_path / "other-k8s.json"
    path.write_text(json.dumps(data))
    return ["--k8s", str(path)]


def _chain_db(tmp_path, capsys):
    db = str(tmp_path / "chain.db")
    assert _ingest(db, *AWS, *K8S, *AI) == 0
    capsys.readouterr()
    return db


# --- which sources an answer rests on ----------------------------------------------------------

def test_type_sources_name_the_collector_of_every_entity_and_edge_in_the_models(tmp_path):
    assert set(TYPE_SOURCES) == set(ENTITY_TYPES)
    assert all(n in COLLECTORS for names in (*TYPE_SOURCES.values(), *EDGE_SOURCES.values()) for n in names)
    chain_store, pipe = build(tmp_path, edit_iam=with_iam([user("dev", groups=["devs"])], [group("devs")]))
    for record in chain():
        pipe.process(record)
    course = Store()
    Pipeline(course, load_rules(), FixedClock(NOW), cluster="course").snapshot(k8s=LAYOUT, at=SNAPSHOT_AT)
    seen = set()
    for store in (chain_store, course):
        for e in store.entities():
            seen.add(e["type"])
            assert e["source"] in TYPE_SOURCES[e["type"]] or (e["source"] == "builtin"
                                                              and TYPE_SOURCES[e["type"]] == ()), e["id"]
        for x in store.edges():
            # "link" edges are recomputed from facts of the listed collectors; a CloudTrail
            # change record is confirmed by the next aws.state snapshot.
            listed = EDGE_SOURCES[x["type"]]
            assert x["source"] in listed or (x["source"] == "link" and listed) \
                or (x["source"] == "aws.cloudtrail" and "aws.state" in listed), x["id"]
    assert seen == set(ENTITY_TYPES)


def test_an_answer_rests_on_the_find_type_each_edge_and_each_step_end(monkeypatch):
    def q(find, *steps):
        return {"find": find, "where": [], "limit": 20,
                "related": [dict(zip(("edge", "dir", "to"), s)) for s in steps]}

    assert sources(q("internet")) == []
    assert sources(q("agent")) == ["ai.inventory"]
    # A step's far end counts: its "to" type, in the order findings lists the sources.
    assert sources(q("agent", ("contains", "in", "pod"))) == ["k8s.state", "ai.inventory"]
    # Without a "to", every type the edge joins at that end.
    assert sources(q("agent", ("contains", "in"))) == ["k8s.state", "ai.inventory"]
    # A "to" the edge does not join still counts; the walk rests on it.
    assert sources(q("agent", ("contains", "in", "s3_bucket"))) == ["aws.state", "ai.inventory"]
    # An edge no collector writes adds nothing.
    assert sources(q("internet", ("holds", "out"))) == []
    # The far end is the end the step walks to: "in" reaches the edge's source type.
    monkeypatch.setitem(ask_module.EDGE_SOURCES, "reads", ())
    assert sources(q("s3_bucket", ("reads", "in"))) == ["aws.state", "ai.inventory"]
    assert sources(q("tool", ("reads", "out"))) == ["aws.state", "ai.inventory"]
    assert sources(q("s3_bucket", ("reads", "out"))) == ["aws.state"]
    # An edge counts on its own: one written by a collector that writes neither end, as a
    # SaaS collector will write deploys_to (slice 4).
    monkeypatch.setitem(ask_module.EDGE_SOURCES, "reachable_from", ("ai.inventory",))
    assert sources(q("internet", ("reachable_from", "in", "service"))) == ["k8s.state", "ai.inventory"]


# --- ask ----------------------------------------------------------------------------------------

def test_ask_on_a_collector_that_never_ran_notes_it_and_exits_2(tmp_path, capsys):
    db = str(tmp_path / "no-ai.db")
    assert _ingest(db, *AWS, *K8S) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENTS) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "note: source ai.inventory: NEVER RUN. Nothing from it is in the model; findings do not cover it."
    assert out[1] == NOT_EVALUATED
    assert out[2].startswith("Query (written by recorded answer") and out[-1] == "- no rows"
    # Control: once the inventory ran, the same query gives the agent, no note, and exit 0.
    assert _ingest(db, *AI, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENTS) == 0
    out = capsys.readouterr().out
    assert out.startswith("Query (written by recorded answer") and "note: " not in out
    assert out.splitlines()[-1] == AGENT_ROW


@pytest.mark.parametrize("case", sorted(NOT_CURRENT))
def test_ask_notes_a_failed_stale_or_conflicting_source_it_rests_on_and_exits_2(tmp_path, capsys, case):
    now, words = NOT_CURRENT[case]
    db = _chain_db(tmp_path, capsys)
    if case == "failed":
        assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    elif case == "conflict":
        assert _ingest(db, *_other_k8s(tmp_path)) == 3
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS, now) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith(f"note: {words}"), out
    assert out[1] == NOT_EVALUATED
    assert out[2].startswith("Query (written by recorded answer")
    # The answer the model holds is still printed, under the note.
    assert out[-1] == POD_ROW
    # Control: a query that does not touch k8s.state gives no note and exit 0.
    assert _ask(tmp_path, db, AGENTS, now) == 0
    assert "note: " not in capsys.readouterr().out
    # Control: a good k8s snapshot taken later removes the note. A conflict older than the
    # snapshot the model holds is history.
    assert _ingest(db, *K8S, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS, now) == 0
    out = capsys.readouterr().out
    assert "note: " not in out and out.splitlines()[-1] == POD_ROW


def test_ask_note_and_findings_on_a_failed_source_cannot_forge_a_line(tmp_path, capsys):
    db = _chain_db(tmp_path, capsys)
    assert _ingest(db, *_truncated(tmp_path, "bad\n- k8s:pod:x\x1b[2J\x9b\u200f.json"), at=FAILED_AT) == 2
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS) == 2
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith("note: source k8s.state: FAILED at ") and lines[1] == NOT_EVALUATED
    assert lines[2].startswith("Query (written by recorded answer")
    assert not any(c in out for c in "\x1b\x9b\r\u200f") and "\n- k8s:pod:x" not in out
    # findings names the same failure on one line of its own. The note goes through safe()
    # in the words findings uses and through term() when ask prints it.
    listed = render.findings(Store(db), NOW)
    assert not any(c in listed for c in "\x1b\x9b\r\u200f") and "\n- k8s:pod:x" not in listed


def test_ask_refused_query_exits_2_with_nothing_on_stdout_even_from_a_failed_source(tmp_path, capsys):
    db = _chain_db(tmp_path, capsys)
    assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    capsys.readouterr()
    assert _ask(tmp_path, db, {**AGENT_PODS, "find": "bucket"}) == 2
    out = capsys.readouterr()
    assert out.out == "" and out.err.startswith("query refused: unknown entity type 'bucket'")
    # Control: the same query with a known type is answered, with the note.
    assert _ask(tmp_path, db, AGENT_PODS) == 2
    assert capsys.readouterr().out.startswith("note: source k8s.state: FAILED at ")


def test_ask_query_that_cannot_match_exits_2(tmp_path, capsys):
    db = _chain_db(tmp_path, capsys)
    args = ["ask", "--db", db, "--now", NOW, "--question", "Which roles can read sensitive buckets?",
            "--provider", "recorded", "--answer"]
    assert cli([*args, str(FX / "ask-answer-wrong-edge.json")]) == 2
    out = capsys.readouterr().out
    assert "Not an answer: the model holds no reads edge" in out and "note: " not in out
    # Control: the same question on the right edge is an answer from current sources.
    assert cli([*args, str(FX / "ask-answer.json")]) == 0
    assert "Not an answer" not in capsys.readouterr().out


# --- found by the review of 2026-11-25 ----------------------------------------------------------

IRSA_VERIFIED = {"find": "service_account", "where": [{"attr": "irsa_status", "op": "eq", "value": "trust verified"}],
                 "related": [], "limit": 20}
SA_BY_NAME = {"find": "service_account", "where": [{"attr": "name", "op": "eq", "value": "sentinel-agent"}],
              "related": [], "limit": 20}


def test_every_step_of_a_walk_adds_the_sources_of_its_far_end():
    # Which pods run an agent that can call this tool: the second step reaches pods.
    two_steps = {"find": "tool", "where": [], "limit": 20,
                 "related": [{"edge": "can_call", "dir": "in", "to": "agent"},
                             {"edge": "contains", "dir": "in", "to": "pod"}]}
    assert sources(two_steps) == ["k8s.state", "ai.inventory"]
    # Control: the first step alone rests on the AI inventory only.
    assert sources({**two_steps, "related": two_steps["related"][:1]}) == ["ai.inventory"]


def test_ask_filter_on_irsa_status_rests_on_the_aws_collector_too(tmp_path, capsys):
    # irsa_status says whether the role a service account names exists and trusts it. The
    # pipeline computes it from the AWS roles, so with none read "no rows" must not read as
    # "no service account can take a role".
    db = str(tmp_path / "no-aws.db")
    assert _ingest(db, *K8S, *AI) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, IRSA_VERIFIED) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "note: source aws.state: NEVER RUN. Nothing from it is in the model; findings do not cover it."
    assert out[1] == NOT_EVALUATED and out[-1] == "- no rows"
    # Control: a filter on an attr the k8s collector writes rests on k8s.state only.
    assert _ask(tmp_path, db, SA_BY_NAME) == 0
    out = capsys.readouterr().out
    assert "note: " not in out and out.splitlines()[-1] == f"- {safe(SA)}"
    # Control: once the AWS export ran, the same filter is an answer from current sources.
    assert _ingest(db, *AWS, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, IRSA_VERIFIED) == 0
    out = capsys.readouterr().out
    assert "note: " not in out and out.splitlines()[-1] == f"- {safe(SA)}"


def test_ask_names_every_source_it_rests_on_that_is_not_current(tmp_path, capsys):
    db = str(tmp_path / "no-ai.db")
    assert _ingest(db, *AWS, *K8S) == 0
    assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith(f"note: {NOT_CURRENT['failed'][1]}"), out
    assert out[1] == "note: source ai.inventory: NEVER RUN. Nothing from it is in the model; findings do not cover it."
    assert out[2] == NOT_EVALUATED
    # Control: once the inventory ran, only the failed k8s.state is named.
    assert _ingest(db, *AI, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith(f"note: {NOT_CURRENT['failed'][1]}") and out[1] == NOT_EVALUATED


def test_ask_names_every_reason_a_source_is_not_current(tmp_path, capsys):
    # A conflict at the time of the snapshot the model holds, then a failed export: two
    # reasons, two notes, as findings would list them.
    db = _chain_db(tmp_path, capsys)
    assert _ingest(db, *_other_k8s(tmp_path)) == 3
    assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith(f"note: {NOT_CURRENT['failed'][1]}"), out
    assert out[1].startswith(f"note: {NOT_CURRENT['conflict'][1]}")
    assert out[2] == NOT_EVALUATED
    # Control: a good snapshot taken later clears both; the conflict before it is history.
    assert _ingest(db, *K8S, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, AGENT_PODS) == 0
    assert "note: " not in capsys.readouterr().out


def test_ask_failed_model_call_is_no_answer_and_exits_2(tmp_path, capsys, monkeypatch):
    db = _chain_db(tmp_path, capsys)
    # A saved answer that is not JSON, and one that is not there: no answer, exit 2.
    broken = tmp_path / "broken.json"
    broken.write_text('{"query": ')
    for path in (broken, tmp_path / "missing.json"):
        assert cli(["ask", "--db", db, "--now", NOW, "--question", "q", "--provider", "recorded",
                    "--answer", str(path)]) == 2
        out = capsys.readouterr()
        assert out.out == "" and out.err.startswith("no answer: ") and out.err.count("\n") == 1
    # A model call that fails with hostile text in its error cannot forge a line.
    def failing(self, system, user, schema):
        raise RuntimeError("model down\n- k8s:pod:x\x1b[2J\x9b\u200f")

    monkeypatch.setattr(RecordedProvider, "complete_json", failing)
    assert _ask(tmp_path, db, AGENTS) == 2
    out = capsys.readouterr()
    assert out.out == "" and out.err.startswith("no answer: RuntimeError: model down") and out.err.count("\n") == 1
    assert not any(c in out.err for c in "\x1b\x9b\r\u200f") and "\n- k8s:pod:x" not in out.err
    monkeypatch.undo()
    # A usage error of ask exits 2 as well.
    assert cli(["ask", "--db", db, "--now", NOW, "--question", "q", "--provider", "recorded"]) == 2
    out = capsys.readouterr()
    assert out.out == "" and out.err == "codeguardian ask: error: --provider recorded needs --answer\n"
    # Control: a saved answer that reads is an answer from current sources.
    assert _ask(tmp_path, db, AGENTS) == 0
    assert capsys.readouterr().out.splitlines()[-1] == AGENT_ROW


def test_every_filter_of_a_query_adds_the_sources_of_its_attr(tmp_path, capsys):
    # irsa_status as the second filter: the answer still rests on the AWS roles.
    named_and_verified = {**IRSA_VERIFIED, "where": SA_BY_NAME["where"] + IRSA_VERIFIED["where"]}
    db = str(tmp_path / "no-aws.db")
    assert _ingest(db, *K8S, *AI) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, named_and_verified) == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "note: source aws.state: NEVER RUN. Nothing from it is in the model; findings do not cover it."
    assert out[1] == NOT_EVALUATED and out[-1] == "- no rows"
    # Control: once the AWS export ran, the same query is an answer from current sources.
    assert _ingest(db, *AWS, at=LATER) == 0
    capsys.readouterr()
    assert _ask(tmp_path, db, named_and_verified) == 0
    out = capsys.readouterr().out
    assert "note: " not in out and out.splitlines()[-1] == f"- {safe(SA)}"


# --- a snapshot sent again -----------------------------------------------------------------------

REPEAT = "k8s.state: this snapshot is already in the model; nothing changed"
AGAIN = "note: sending this snapshot again does not show that the facts of k8s.state still hold"
NONE_OPENED = "opened 0, resolved 0 findings"


def _model(db):
    store = Store(db)
    return {k: v for k, v in dump(store).items() if k != "counters"}, [tuple(r.values()) for r in store.snapshots()]


@pytest.mark.parametrize("case", sorted(NOT_CURRENT))
def test_repeat_of_a_source_that_is_not_current_notes_it_and_exits_2(tmp_path, capsys, case):
    now, words = NOT_CURRENT[case]
    db = _chain_db(tmp_path, capsys)
    if case == "failed":
        assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    elif case == "conflict":
        assert _ingest(db, *_other_k8s(tmp_path)) == 3
    capsys.readouterr()
    before = _model(db)
    # The snapshot the model holds, sent again.
    assert _ingest(db, *K8S, now=now) == 2
    out = capsys.readouterr()
    lines = out.out.splitlines()
    assert lines[0] == REPEAT
    assert lines[1].startswith(f"note: {words}"), lines
    assert lines[2:] == [AGAIN, NONE_OPENED]
    assert out.err == ""
    assert _model(db) == before
    # findings still names the same reason.
    assert words.rstrip(": ") in render.findings(Store(db), now)
    # Control: a good snapshot taken later, then sent again, is a repeat with no note.
    assert _ingest(db, *K8S, at=LATER, now=now) == 0
    capsys.readouterr()
    assert _ingest(db, *K8S, at=LATER, now=now) == 0
    assert capsys.readouterr().out.splitlines() == [REPEAT, NONE_OPENED]


def test_noted_repeat_exits_2_before_a_refusal_in_the_same_ingest(tmp_path, capsys):
    def setup(name, fail):
        db = str(tmp_path / f"{name}.db")
        assert _ingest(db, *AWS, *K8S) == 0
        assert _ingest(db, *AI, at=LATER) == 0
        if fail:
            assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
        capsys.readouterr()
        return db

    # One ingest: the k8s snapshot the model holds, sent again after a failed export, and an
    # AI inventory older than the one applied.
    db = setup("failed", True)
    assert _ingest(db, *K8S, *AI) == 2
    out = capsys.readouterr()
    lines = out.out.splitlines()
    assert lines[0] == REPEAT and lines[1].startswith("note: source k8s.state: FAILED at ")
    assert lines[2:] == [AGAIN, NONE_OPENED]
    assert out.err.startswith("snapshot refused: ai.inventory: ")
    # Control: with no failure the repeat has no note and the refusal's exit 3 stands.
    db = setup("ok", False)
    assert _ingest(db, *K8S, *AI) == 3
    out = capsys.readouterr()
    assert out.out.splitlines() == [REPEAT, NONE_OPENED] and out.err.startswith("snapshot refused: ai.inventory: ")


def _other_ai(tmp_path):
    data = json.loads((FX / "ai/inventory.json").read_text())
    data["agents"] = []
    path = tmp_path / "other-ai.json"
    path.write_text(json.dumps(data))
    return ["--ai", str(path)]


def _truncated_aws(tmp_path):
    path = tmp_path / "truncated-iam.json"
    path.write_text('{"Users": [')
    return ["--aws-iam", str(path), *AWS[2:]]


def test_repeat_names_every_source_and_every_reason_that_is_not_current(tmp_path, capsys):
    db = _chain_db(tmp_path, capsys)
    # A conflict for k8s.state and for ai.inventory at 09:55, then a failed export of
    # aws.state and k8s.state at 10:10: k8s.state is not current for two reasons.
    assert _ingest(db, *_other_k8s(tmp_path)) == 3
    assert _ingest(db, *_other_ai(tmp_path)) == 3
    assert _ingest(db, *_truncated_aws(tmp_path), *_truncated(tmp_path), at=FAILED_AT) == 2
    capsys.readouterr()
    before = _model(db)
    # One ingest sends again the three snapshots the model holds.
    assert _ingest(db, *AWS, *K8S, *AI) == 2
    out = capsys.readouterr()
    lines = out.out.splitlines()
    conflict = "taken at 2026-11-14T09:55:00.000000Z: refused, another snapshot of"
    expected = [
        ("aws.state", ["note: source aws.state: FAILED at 2026-11-14T10:10:00.000000Z: aws iam: "]),
        ("k8s.state", ["note: source k8s.state: FAILED at 2026-11-14T10:10:00.000000Z: k8s: ",
                       f"note: k8s.state {conflict} k8s.state "]),
        ("ai.inventory", [f"note: ai.inventory {conflict} ai.inventory "]),
    ]
    at = 0
    for name, notes in expected:
        assert lines[at] == f"{name}: this snapshot is already in the model; nothing changed", lines
        for i, words in enumerate(notes, at + 1):
            assert lines[i].startswith(words), lines
        at += len(notes) + 1
        assert lines[at] == f"note: sending this snapshot again does not show that the facts of {name} still hold"
        at += 1
    assert lines[at:] == [NONE_OPENED]
    assert out.err == ""
    assert _model(db) == before
    # Control: good snapshots taken later, then sent again, are repeats with no note.
    assert _ingest(db, *AWS, *K8S, *AI, at=LATER) == 0
    capsys.readouterr()
    assert _ingest(db, *AWS, *K8S, *AI, at=LATER) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"{name}: this snapshot is already in the model; nothing changed" for name, _ in expected] + [NONE_OPENED]


def test_ingest_help_names_every_code_ingest_exits_with(tmp_path, capsys):
    codes = set()
    db = _chain_db(tmp_path, capsys)
    codes.add(0)
    codes.add(_ingest(db, *K8S, at="2026-11-14T09:50:00Z"))  # older: refused
    codes.add(_ingest(db, *_truncated(tmp_path), at=FAILED_AT))  # failed
    before = _model(db)
    for refused in (["--aws-iam", AWS[1]], ["--outside-source", "198.51.100.0/40"]):
        with pytest.raises(SystemExit) as stop:
            _ingest(db, *refused)
        assert isinstance(stop.value.code, str)  # the interpreter prints it and exits 1
        codes.add(1)
    assert _model(db) == before
    with pytest.raises(SystemExit) as stop:
        _ingest(db, "--k8s")
    codes.add(stop.value.code)
    assert codes == {0, 1, 2, 3}
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli(["ingest", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    epilog = text[text.index("exit status: "):]
    assert re.findall(r"(?:status:|,) (\d) ", epilog) == ["0", "1", "2", "3"], epilog
    # Each code's words cover the ways out taken above: 2 is also argparse's code for a
    # command line it cannot read, as `ingest --k8s` with no value showed.
    parts = re.split(r"(?:status:|,) (\d) ", epilog)
    meaning = dict(zip(parts[1::2], parts[2::2]))
    assert "command line was not understood" in meaning["2"], epilog


def test_noted_repeat_is_named_when_another_collector_fails_in_the_same_ingest(tmp_path, capsys):
    db = _chain_db(tmp_path, capsys)
    assert _ingest(db, *_truncated(tmp_path), at=FAILED_AT) == 2
    broken_ai = tmp_path / "broken-ai.json"
    broken_ai.write_text('{"format": ')
    capsys.readouterr()
    # One ingest: the k8s snapshot the model holds, sent again after a failed export, and an
    # AI inventory that cannot be read.
    assert _ingest(db, *K8S, "--ai", str(broken_ai)) == 2
    out = capsys.readouterr()
    lines = out.out.splitlines()
    assert lines[0] == REPEAT and lines[1].startswith("note: source k8s.state: FAILED at ")
    assert lines[2:] == [AGAIN]
    assert out.err.startswith("collector failed: ai inventory: ")
    # Control: with no k8s failure, the repeat has no note; the AI failure still exits 2.
    db = str(tmp_path / "ok.db")
    assert _ingest(db, *AWS, *K8S, *AI) == 0
    capsys.readouterr()
    assert _ingest(db, *K8S, "--ai", str(broken_ai), at=SNAPSHOT_AT) == 2
    out = capsys.readouterr()
    assert out.out.splitlines() == [REPEAT] and out.err.startswith("collector failed: ai inventory: ")
