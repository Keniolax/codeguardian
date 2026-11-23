"""Version 2 building blocks: rules as data, collectors that fail loudly, the IAM resolver,
the store, and bounded path traversal."""

import json

import pytest

from codeguardian.v2 import paths, policy, render
from codeguardian.v2.collectors import CollectorError
from codeguardian.v2.collectors.events import ParseError, parse
from codeguardian.v2.rules import MAX_HOPS, RuleError, load_rules, validate
from codeguardian.v2.schema import FixedClock, edge_id, finding_id, ts
from codeguardian.v2.store import Store
from v2_helpers import FX, NOW, POD, ROLE, SA, SVC, build, chain, fixture

BASE = {"id": "T-1", "version": 1, "severity": "low", "title": "t", "frameworks": []}


# --- rules are data, and a bad rule stops the load ----------------------------------------------

@pytest.mark.parametrize("rule, message", [
    ({**BASE, "kind": "posture", "entity": "vm", "where": [{"attr": "x", "op": "eq", "value": 1}]}, "unknown entity type"),
    ({**BASE, "kind": "posture", "entity": "pod", "where": [{"attr": "colour", "op": "eq", "value": 1}]}, "has no attr"),
    ({**BASE, "kind": "posture", "entity": "pod", "where": [{"attr": "privileged", "op": "like", "value": 1}]}, "unknown op"),
    ({**BASE, "kind": "path", "start": "internet", "hops": [{"edge": "peers_with", "dir": "out", "to": "pod"}]}, "unknown edge type"),
    ({**BASE, "kind": "path", "start": "internet",
      "hops": [{"edge": "exposes", "dir": "out", "to": "pod"}] * (MAX_HOPS + 1)}, "limit"),
    ({**BASE, "kind": "detection", "match": {"source": "aws.cloudtrail", "actions": ["a"]},
      "when": [{"from": "agent", "walk": [{"edge": "contains", "dir": "out"}], "bind": "x"}]}, "not bound"),
    ({**BASE, "kind": "posture", "entity": "pod", "where": [{"attr": "privileged", "op": "eq", "value": True}],
      "labels": {"a": 1}}, "unknown key"),
])
def test_rule_validation_refuses_what_it_does_not_understand(rule, message):
    with pytest.raises(RuleError, match=message):
        validate(rule)


def test_rule_file_that_does_not_parse_fails_the_load(tmp_path):
    (tmp_path / "bad.toml").write_text("[[rule]]\nid = \n")
    with pytest.raises(RuleError):
        load_rules(tmp_path)


def test_shipped_rules_load():
    ids = [r["id"] for r in load_rules()]
    assert "PATH-AI-001" in ids and "DET-AI-001" in ids and len(ids) == len(set(ids))


# --- collectors fail loudly and leave stale facts, never a clean result ------------------------

@pytest.mark.parametrize("content", ["{}", "not json", json.dumps({"items": "nope"}),
                                     json.dumps({"items": [{"kind": "Pod", "metadata": {"name": "x"}}]})])
def test_bad_k8s_input_fails_loudly_and_marks_facts_stale(tmp_path, content):
    store, pipe = build(tmp_path)
    (path_finding,) = store.findings(status="open", rule_id="PATH-AI-001")
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    pipe.clock.set("2026-11-14T10:00:00Z")
    with pytest.raises(CollectorError):
        pipe.snapshot(k8s=bad, at="2026-11-14T10:00:00Z")
    assert store.source("k8s.state")["status"] == "failed"
    assert store.entity(POD) is not None  # nothing deleted
    assert store.is_stale(store.entity(POD), "2026-11-14T10:00:00Z")
    still = store.finding(path_finding["finding_id"])
    assert still["status"] == "open"  # not looking is not the same as safe
    assert any(n.startswith("stale:") for n in still["notes"])
    assert "FAILED" in render.findings(store, "2026-11-14T10:00:00Z")


def test_missing_bucket_tags_refuse_the_snapshot(tmp_path):
    with pytest.raises(CollectorError, match="tags were not collected"):
        build(tmp_path, edit_tags=lambda t: t.pop("example-finance-records"))


def test_first_run_failure_reports_failed_not_empty(tmp_path):
    store = Store()
    from codeguardian.v2.pipeline import Pipeline

    pipe = Pipeline(store, load_rules(), FixedClock(NOW))
    with pytest.raises(CollectorError):
        pipe.snapshot(k8s=tmp_path / "missing.json")
    out = render.findings(store, NOW)
    assert "k8s.state: FAILED" in out
    assert "aws.state: NEVER RUN" in out and "ai.inventory: NEVER RUN" in out


def test_source_past_its_refresh_period_is_shown_stale(tmp_path):
    store, _ = build(tmp_path)
    assert "k8s.state: ok" in render.findings(store, "2026-11-14T10:30:00Z")
    out = render.findings(store, "2026-11-16T10:30:00Z")
    assert "k8s.state: STALE" in out and "aws.state: STALE" in out


def test_facts_go_stale_after_the_refresh_period(tmp_path):
    store, _ = build(tmp_path)
    assert not store.is_stale(store.entity(POD), "2026-11-14T10:30:00Z")
    assert store.is_stale(store.entity(POD), "2026-11-14T11:00:00Z")  # k8s refresh is one hour
    assert not store.is_stale(store.entity(ROLE), "2026-11-14T11:00:00Z")  # AWS refresh is a day


def test_snapshot_that_no_longer_lists_a_pod_marks_it_deleted(tmp_path):
    store, pipe = build(tmp_path)
    data = fixture("k8s/state.json")
    data["items"] = [i for i in data["items"] if i["metadata"]["name"] != "sentinel-agent-7d9f"]
    p = tmp_path / "k8s2.json"
    p.write_text(json.dumps(data))
    pipe.snapshot(k8s=p, at="2026-11-14T10:00:00Z")
    assert store.entity(POD) is None and store.entity(POD, include_deleted=True)["deleted_at"]
    assert store.findings(status="resolved", rule_id="PATH-AI-001")


# --- the IAM resolver says what it did not evaluate --------------------------------------------

def _doc(*st):
    return {"Version": "2012-10-17", "Statement": list(st)}


def test_resolver_grants_from_allow_and_wildcards():
    grants, markers, admin, unknown = policy.resolve(
        [("inline:p", _doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::fin-*/*"}))],
        ["fin-a", "kb"])
    assert set(grants) == {"fin-a"} and grants["fin-a"]["scopes"] == ["objects"]
    assert markers == [] and not admin and unknown == []


def test_resolver_marks_condition_deny_notaction_and_boundary():
    grants, markers, _, _ = policy.resolve([("inline:p", _doc(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
        {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::fin/*"},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    ))], ["fin"], has_boundary=True)
    notes = grants["fin"]["not_evaluated"]
    assert any("Condition" in n for n in notes)
    assert any("Deny" in n for n in notes)
    assert any("boundary" in n for n in notes)
    assert any("NotAction" in m for m in markers) and any("Deny statements" in m for m in markers)


def test_skipped_statement_is_a_visible_finding_not_a_silent_deny(tmp_path):
    def not_action_grant(iam):
        role = next(r for r in iam["RoleDetailList"] if r["RoleName"] == "sentinel-agent")
        role["RolePolicyList"].append({"PolicyName": "all-but-iam", "PolicyDocument": _doc(
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::example-finance-records/*"})})

    store, _ = build(tmp_path, iam="aws/iam.json", edit_iam=not_action_grant)
    assert store.findings(status="open", rule_id="PATH-AI-001") == []  # the resolver cannot see this grant
    (marker,) = store.findings(status="open", rule_id="POST-IAM-003")
    assert marker["primary_entity"] == ROLE and any("NotAction" in n for n in marker["notes"])


def test_resolver_lists_unknown_documents():
    _, _, _, unknown = policy.resolve([("arn:aws:iam::111122223333:policy/x", None)], ["fin"])
    assert unknown == ["arn:aws:iam::111122223333:policy/x"]


def test_admin_wildcard_only_without_condition():
    star = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert policy.resolve([("p", _doc(star))], [])[2] is True
    assert policy.resolve([("p", _doc({**star, "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}))], [])[2] is False


# --- store and IDs ---------------------------------------------------------------------------

def test_upsert_keeps_first_seen_and_moves_last_seen():
    s = Store()
    s.upsert_entity(POD, "pod", {"name": "p"}, {}, "k8s.state", ts("2026-11-14T09:00:00Z"))
    changed = s.upsert_entity(POD, "pod", {"name": "p"}, {}, "k8s.state", ts("2026-11-14T10:00:00Z"))
    e = s.entity(POD)
    assert not changed
    assert (e["first_seen"], e["last_seen"]) == (ts("2026-11-14T09:00:00Z"), ts("2026-11-14T10:00:00Z"))


def test_ids_are_derived_from_data():
    assert edge_id("runs_as", POD, SA) == edge_id("runs_as", POD, SA) != edge_id("runs_as", SA, POD)
    assert finding_id("R", "x", ["a", "b"]) != finding_id("R", "x", ["b", "a"])


def test_unknown_entity_and_edge_types_are_refused():
    s = Store()
    with pytest.raises(ValueError):
        s.upsert_entity("x:vm:1", "vm", {}, {}, "t", ts(NOW))
    with pytest.raises(ValueError):
        s.upsert_edge("peers_with", "a", "b", {}, "t", ts(NOW))


# --- bounded traversal ------------------------------------------------------------------------

def test_path_walk_never_reenters_a_node(tmp_path):
    store, _ = build(tmp_path)
    rule = validate({**BASE, "kind": "path", "start": "service", "hops": [
        {"edge": "exposes", "dir": "out", "to": "pod"}, {"edge": "exposes", "dir": "in", "to": "service"}]})
    # Out to the pod and back over the same edge type would return to the start service.
    assert [f for f in paths.evaluate(store, rule, NOW) if f["path"][0] == SVC] == []
    second = "k8s:service:lab/agents/sentinel-agent-b"
    store.upsert_entity(second, "service", {"name": "b", "namespace": "agents"}, {}, "k8s.state", ts(NOW))
    store.upsert_edge("exposes", second, POD, {}, "k8s.state", ts(NOW))
    found = sorted(tuple(f["path"]) for f in paths.evaluate(store, rule, NOW) if POD in f["path"])
    assert found == [(SVC, POD, second), (second, POD, SVC)]


# --- correlation keys ---------------------------------------------------------------------

def test_internet_node_does_not_join_incidents():
    from codeguardian.v2 import correlate

    store = Store()
    at = ts("2026-11-14T10:00:00Z")

    def finding(fid, kind, entities):
        f = {"finding_id": fid, "kind": kind, "rule_id": "R", "rule_version": 1, "severity": "low", "title": "t",
             "primary_entity": entities[0], "entities": entities, "path": [], "events": [], "first_seen": at,
             "last_seen": at, "status": "open", "frameworks": [], "notes": []}
        store.put_finding(f)
        return f

    a = finding("a" * 32, "detection", ["net:internet:any", "k8s:pod:lab/x/a"])
    finding("c" * 32, "path", ["net:internet:any", "k8s:pod:lab/y/c"])
    inc_a = correlate.add_detection(store, a, at)
    b = finding("b" * 32, "detection", ["net:internet:any", "k8s:pod:lab/x/b"])
    inc_b = correlate.add_detection(store, b, at)
    assert inc_a["incident_id"] != inc_b["incident_id"]
    assert store.incident(inc_a["incident_id"])["finding_ids"] == ["a" * 32]


# --- event parsers ----------------------------------------------------------------------------

def test_parsers_normalise_three_formats():
    by_source = {}
    for raw in chain():
        ev, hints, _ = parse(raw, "lab")
        by_source.setdefault(ev["source"], ev)
    assert set(by_source) == {"aws.cloudtrail", "k8s.audit", "k8s.runtime"}
    assert by_source["k8s.runtime"]["time"] == "2026-11-14T10:01:12.481516Z"  # nanoseconds cut to micro
    assert by_source["k8s.audit"]["action"] == "k8s:pods:get"


def test_unknown_record_is_refused_not_guessed():
    with pytest.raises(ParseError):
        parse({"hello": "world"}, "lab")


# --- command line ------------------------------------------------------------------------------

def test_unknown_option_of_a_command_is_refused_with_exit_2(tmp_path, capsys):
    from codeguardian.cli import main as cli

    db = str(tmp_path / "m.db")
    with pytest.raises(SystemExit) as stop:
        cli(["findings", "--db", db, "--now", NOW, "--statuss", "open"])
    assert stop.value.code == 2
    assert "unrecognized arguments: --statuss open" in capsys.readouterr().err
    # Control: the same command without the unknown option answers.
    assert cli(["findings", "--db", db, "--now", NOW]) == 0
