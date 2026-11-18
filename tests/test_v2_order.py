"""Order (slice snapshot-order): snapshots and records arrive in any order, and the model,
the open findings and each finding's history must not depend on it. Each claim has a
control. Every test here must have a mutant in tests/mutants.py."""

import json
from itertools import permutations

from codeguardian.cli import main as cli
from codeguardian.v2 import render
from codeguardian.v2.collectors import CollectorError
from codeguardian.v2.history import history
from codeguardian.v2.pipeline import Pipeline
from codeguardian.v2.rules import load_rules
from codeguardian.v2.schema import FixedClock, ts
from codeguardian.v2.store import Store
from v2_helpers import (ACCT, FX, NOW, ROLE, SNAPSHOT_AT, build, dump, fixture, iam_event, k8s_item, open_rules,
                        role_entry)

RULES = load_rules()
BUCKETS, TAGS = FX / "aws" / "s3-buckets.json", FX / "aws" / "s3-tags.json"
LATER_AT = "2026-11-14T10:15:00Z"  # after the put, attach and detach; before the delete
EXPORT = f"arn:aws:iam::{ACCT}:policy/finance-export"
MODEL_TABLES = ("entities", "edges", "events", "findings", "incidents", "sources", "held", "model_changes")


def _record(name, n, time, **params):
    ev = iam_event("PutRolePolicy")
    ev.update(eventName=name, eventID=f"6f1c2a9e-0000-4000-8000-{n:012d}", eventTime=time,
              requestParameters={"roleName": "sentinel-agent", **params})
    return ev


def records():
    """The four IAM change records: the path opens at 10:00 and closes at 10:20."""
    return {"put": iam_event("PutRolePolicy"),  # 10:00, reports-read: s3:GetObject on example-*
            "attach": _record("AttachRolePolicy", 920, "2026-11-14T10:05:00Z", policyArn=EXPORT),
            "detach": _record("DetachRolePolicy", 921, "2026-11-14T10:10:00Z", policyArn=EXPORT),
            "delete": iam_event("DeleteRolePolicy")}  # 10:20


def later_iam(tmp_path, edit=None):
    """The AWS export at 10:15: the put has happened, the delete has not."""
    data = fixture("aws/iam.json")
    doc = json.loads(iam_event("PutRolePolicy")["requestParameters"]["policyDocument"])
    role_entry(data, "sentinel-agent")["RolePolicyList"].append({"PolicyName": "reports-read", "PolicyDocument": doc})
    if edit:
        edit(data)
    path = tmp_path / f"iam-later-{len(list(tmp_path.glob('iam-later-*')))}.json"
    path.write_text(json.dumps(data))
    return path


def stage1(**over):
    return {"aws": (FX / "aws" / "iam.json", BUCKETS, TAGS), "k8s": FX / "k8s" / "state.json",
            "ai": FX / "ai" / "inventory.json", "at": SNAPSHOT_AT, **over}


def fresh():
    store = Store()
    return store, Pipeline(store, RULES, FixedClock(NOW))


def feed(pipe, item):
    kind, payload = item
    if kind == "snapshot":
        return pipe.snapshot(**payload)
    return pipe.process(json.loads(json.dumps(payload)))


def live_model(store):
    """Live entities and edges with everything a rule or a person reads, times included."""
    ents = store.db.execute("SELECT id, type, attrs, labels, source, observed_at, last_seen FROM entities"
                            " WHERE deleted_at IS NULL ORDER BY id").fetchall()
    edges = store.db.execute("SELECT id, type, src, dst, attrs, source, observed_at, last_seen FROM edges"
                             " WHERE deleted_at IS NULL ORDER BY id").fetchall()
    return [tuple(r) for r in ents], [tuple(r) for r in edges]


def open_findings(store):
    """Open findings with every field. A posture or path finding's first and last seen say
    when this model found it, which depends on arrival; the history holds the data time."""
    out = []
    for f in store.findings(status="open"):
        if f["kind"] != "detection":
            f = {k: v for k, v in f.items() if k not in ("first_seen", "last_seen")}
        out.append(json.dumps(f, sort_keys=True))
    return sorted(out)


def changes_of(store):
    return {e["finding"]["finding_id"]: (e["finding"]["rule_id"], [(c["time"], c["change"], c["cause"][:2])
                                                                    for c in e["changes"]])
            for e in history(store, RULES, NOW)}


def path_history(store):
    return [v for v in changes_of(store).values() if v[0] == "PATH-AI-001"]


PUT_ID, DELETE_ID = iam_event("PutRolePolicy")["eventID"], iam_event("DeleteRolePolicy")["eventID"]


def _event_id(native):
    from codeguardian.v2.schema import event_id

    return event_id("aws.cloudtrail", native)


OPEN_TO_CLOSE = [("PATH-AI-001", [("2026-11-14T10:00:00.000000Z", "opened", ("record", _event_id(PUT_ID))),
                                  ("2026-11-14T10:20:00.000000Z", "resolved", ("record", _event_id(DELETE_ID)))])]


# --- must prove: every order ends the same --------------------------------------------------------

def test_every_order_of_two_snapshots_and_four_change_records_ends_the_same(tmp_path):
    items = [("S1", ("snapshot", stage1())), ("S2", ("snapshot", {"aws": (later_iam(tmp_path), BUCKETS, TAGS),
                                                                    "at": LATER_AT}))]
    items += [(name, ("record", r)) for name, r in records().items()]
    models, opens, histories = set(), set(), set()
    for order in permutations(items):
        store, pipe = fresh()
        for _, item in order:
            feed(pipe, item)
        models.add(json.dumps(live_model(store)))
        opens.add(json.dumps(open_findings(store)))
        h = changes_of(store)
        histories.add(json.dumps(h, sort_keys=True))
        # The history ends where the live model is: each posture and path finding it holds
        # last changed to the status the model shows now.
        for fid, (_, changes) in h.items():
            live = store.finding(fid)
            final = "resolved" if changes[-1][1] == "resolved" else "open"
            assert (live["status"] if live else "resolved") == final, ([n for n, _ in order], fid)
    assert (len(models), len(opens), len(histories)) == (1, 1, 1)  # 720 orders
    # What they all end in: S2 and the delete hold, the path was open from 10:00 to 10:20,
    # and the agent's role got new permissions (a detection that needs k8s and ai facts).
    assert [v for v in json.loads(histories.pop()).values() if v[0] == "PATH-AI-001"] == \
        [["PATH-AI-001", [list(c[:2]) + [list(c[2])] for c in OPEN_TO_CLOSE[0][1]]]]
    assert sorted(json.loads(f)["rule_id"] for f in json.loads(opens.pop())) == \
        ["DET-AI-002", "PATH-EXPOSED-001", "PATH-EXPOSED-001", "POST-IAM-001", "POST-K8S-001"]


def test_path_open_from_10_00_to_10_20_shows_in_the_history_when_the_delete_arrives_first(tmp_path):
    store, pipe = build(tmp_path, iam="aws/iam.json")
    pipe.process(iam_event("DeleteRolePolicy"))  # 10:20, arrives first
    pipe.process(iam_event("PutRolePolicy"))  # 10:00, arrives late and is superseded
    assert store.findings(rule_id="PATH-AI-001") == []  # the live model never held the path
    assert path_history(store) == OPEN_TO_CLOSE
    # Control: the delete alone. The path was never open, so the history holds none.
    (tmp_path / "c").mkdir()
    control, cpipe = build(tmp_path / "c", iam="aws/iam.json")
    cpipe.process(iam_event("DeleteRolePolicy"))
    assert path_history(control) == []


def test_replaying_everything_changes_nothing(tmp_path):
    later = {"aws": (later_iam(tmp_path), BUCKETS, TAGS), "at": LATER_AT}
    store, pipe = fresh()
    order = [("snapshot", later), ("record", records()["delete"]), ("snapshot", stage1()),
             ("record", records()["put"]), ("record", records()["attach"]), ("record", records()["detach"])]
    for item in order:
        feed(pipe, item)
    before, hist = dump(store), changes_of(store)
    journal = store.snapshots()
    results = [feed(pipe, item) for item in order]
    assert [r.get("unchanged") or r.get("status") for r in results] == [
        ["aws.state"], "duplicate", ["k8s.state", "ai.inventory"], "duplicate", "duplicate", "duplicate"]
    assert [x[:2] for x in results[2]["refused"]] == [("aws.state", "older")]  # still older, not in the model
    after = dump(store)
    assert {k: v for k, v in after.items() if k != "counters"} == {k: v for k, v in before.items() if k != "counters"}
    assert store.snapshots() == journal and changes_of(store) == hist
    # Control: a snapshot of the same time with other content is not a repeat.
    r = pipe.snapshot(aws=(later_iam(tmp_path, lambda d: d["RoleDetailList"].pop()), BUCKETS, TAGS), at=LATER_AT)
    assert r["unchanged"] == [] and [x[:2] for x in r["refused"]] == [("aws.state", "conflict")]


# --- snapshots are ordered ------------------------------------------------------------------------

def _tables(store):
    return {k: v for k, v in dump(store).items() if k in ("entities", "edges", "findings", "incidents")}


def test_snapshot_older_than_the_last_applied_is_refused_and_changes_nothing(tmp_path):
    later = {"aws": (later_iam(tmp_path), BUCKETS, TAGS), "at": LATER_AT}
    store, pipe = fresh()
    pipe.snapshot(**stage1(aws=None))
    pipe.snapshot(**later)
    before, sources = _tables(store), store.sources()
    r = pipe.snapshot(aws=(FX / "aws" / "iam.json", BUCKETS, TAGS), at=SNAPSHOT_AT)
    assert [x[:2] for x in r["refused"]] == [("aws.state", "older")]
    assert "older than the last applied snapshot of aws.state, taken at 2026-11-14T10:15:00.000000Z" in r["refused"][0][2]
    assert _tables(store) == before and store.sources() == sources
    assert "reports-read" in store.entity(ROLE)["attrs"]["inline_policies"]
    assert store.counters()["snapshot_older"] == 1
    assert "aws.state taken at 2026-11-14T09:55:00.000000Z: refused, older" in render.findings(store, NOW)
    # Control: the same two snapshots in time order. Both apply, and the later one holds.
    (tmp_path / "c").mkdir()
    cstore, cpipe = fresh()
    assert cpipe.snapshot(**stage1())["refused"] == []
    assert cpipe.snapshot(aws=(later_iam(tmp_path / "c"), BUCKETS, TAGS), at=LATER_AT)["refused"] == []
    assert "reports-read" in cstore.entity(ROLE)["attrs"]["inline_policies"]
    assert "Snapshots refused" not in render.findings(cstore, NOW)


def test_refusal_is_per_collector(tmp_path):
    store, pipe = fresh()
    pipe.snapshot(aws=(later_iam(tmp_path), BUCKETS, TAGS), at=LATER_AT)
    r = pipe.snapshot(**stage1())  # older for aws; the first k8s and ai snapshots
    assert [x[:2] for x in r["refused"]] == [("aws.state", "older")]
    assert {s["name"] for s in store.sources()} == {"aws.state", "k8s.state", "ai.inventory"}
    assert open_rules(store).count("PATH-AI-001") == 1  # S2's role with S1's pod and agent
    # Control: an AWS snapshot newer than the last one applies.
    r = pipe.snapshot(aws=(FX / "aws" / "iam.json", BUCKETS, TAGS), at="2026-11-14T10:25:00Z")
    assert r["refused"] == [] and "PATH-AI-001" not in open_rules(store)


def test_same_time_other_content_is_refused_and_marked_and_same_content_is_a_no_op(tmp_path):
    store, pipe = build(tmp_path, iam="aws/iam.json")
    before = _tables(store)
    same = pipe.snapshot(aws=(FX / "aws" / "iam.json", BUCKETS, TAGS), at=SNAPSHOT_AT)
    assert same["unchanged"] == ["aws.state"] and same["refused"] == []
    assert "Snapshots refused" not in render.findings(store, NOW)
    other = pipe.snapshot(aws=(later_iam(tmp_path), BUCKETS, TAGS), at=SNAPSHOT_AT)
    assert [x[:2] for x in other["refused"]] == [("aws.state", "conflict")]
    assert _tables(store) == before  # the model still holds the first snapshot
    assert store.counters()["snapshot_conflict"] == 1
    assert ("aws.state taken at 2026-11-14T09:55:00.000000Z: refused, another snapshot of aws.state with that time"
            " has other content; which one held is not known (not evaluated)") in render.findings(store, NOW)
    # The conflicting snapshot is not replayed into the history either.
    assert [s["status"] for s in store.snapshots() if s["source"] == "aws.state"] == ["applied", "conflict"]
    assert path_history(store) == []
    # A model written before the journal has a last snapshot time but no entry for it.
    # Other content at that time is still a conflict, not a newer snapshot.
    store, pipe = build(tmp_path, iam="aws/iam.json")
    store.db.execute("DELETE FROM snapshots")
    r = pipe.snapshot(aws=(later_iam(tmp_path), BUCKETS, TAGS), at=SNAPSHOT_AT)
    assert [x[:2] for x in r["refused"]] == [("aws.state", "conflict")]
    assert "reports-read" not in store.entity(ROLE)["attrs"]["inline_policies"]


def test_broken_snapshot_older_than_the_last_good_one_changes_nothing(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    states = set()
    for order in (("good", "bad"), ("bad", "good")):
        store, pipe = fresh()
        for which in order:
            try:
                if which == "good":
                    pipe.snapshot(k8s=FX / "k8s" / "state.json", at=SNAPSHOT_AT)
                else:
                    pipe.snapshot(k8s=bad, at="2026-11-14T09:50:00Z")
            except CollectorError as exc:
                assert ("older than the last applied snapshot" in str(exc)) == (order[0] == "good")
        states.add(json.dumps([store.sources(), live_model(store)]))
        assert store.source("k8s.state")["status"] == "ok"
    assert len(states) == 1
    db = str(tmp_path / "m.db")
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", SNAPSHOT_AT, "--k8s", str(FX / "k8s/state.json")]) == 0
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T09:50:00Z", "--k8s", str(bad)]) == 2
    assert "marked stale" not in capsys.readouterr().err
    # Control: a broken snapshot newer than the last good one marks the collector failed.
    store, pipe = fresh()
    pipe.snapshot(k8s=FX / "k8s" / "state.json", at=SNAPSHOT_AT)
    try:
        pipe.snapshot(k8s=bad, at=LATER_AT)
    except CollectorError as exc:
        assert "older than the last applied" not in str(exc)
    assert store.source("k8s.state")["status"] == "failed"
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", LATER_AT, "--k8s", str(bad)]) == 2
    assert "its facts are now marked stale" in capsys.readouterr().err


def test_newer_failed_export_still_stands_when_an_older_snapshot_arrives_after_it(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")

    def run(order):
        store, pipe = fresh()
        pipe.snapshot(k8s=FX / "k8s" / "state.json", at="2026-11-14T09:00:00Z")
        for which, at in order:
            try:
                pipe.snapshot(k8s=FX / "k8s" / "state.json" if which == "good" else bad, at=at)
            except CollectorError:
                pass
        return store

    # A good export at 09:55 and a broken one at 10:15, then the same two at one time.
    for good, broken in ((("good", SNAPSHOT_AT), ("bad", LATER_AT)), (("good", LATER_AT), ("bad", LATER_AT))):
        states = set()
        for order in ((good, broken), (broken, good)):
            store = run(order)
            s = store.source("k8s.state")
            assert (s["status"], s["last_success"]) == ("failed", ts(good[1])), order
            assert "- source k8s.state: FAILED at" in render.findings(store, NOW), order
            states.add(json.dumps([store.sources(), live_model(store), open_findings(store)]))
        assert len(states) == 1, good
    # Control: a good snapshot newer than the failure clears it.
    store = run((("bad", SNAPSHOT_AT), ("good", LATER_AT)))
    assert store.source("k8s.state")["status"] == "ok"
    assert "- source k8s.state: ok" in render.findings(store, NOW)


def test_snapshot_time_is_normalised_so_string_order_is_time_order(tmp_path):
    store, pipe = fresh()
    pipe.snapshot(ai=FX / "ai" / "inventory.json", at="2026-11-14T10:10:00Z")
    assert store.source("ai.inventory")["last_success"] == "2026-11-14T10:10:00.000000Z"
    # Half a second later. As given, ".5Z" sorts before "Z", so it would read as older.
    r = pipe.snapshot(ai=FX / "ai" / "inventory.json", at="2026-11-14T10:10:00.5Z")
    assert r["refused"] == [] and r["unchanged"] == []
    assert store.source("ai.inventory")["last_success"] == "2026-11-14T10:10:00.500000Z"
    # Control: the earlier time again is the same snapshot, a no-op.
    assert pipe.snapshot(ai=FX / "ai" / "inventory.json", at="2026-11-14T10:10:00Z")["unchanged"] == ["ai.inventory"]


def test_ingest_says_a_snapshot_was_refused_and_exits_3(tmp_path, capsys):
    db = str(tmp_path / "m.db")
    aws = ["--aws-iam", str(FX / "aws/iam.json"), "--aws-buckets", str(BUCKETS), "--aws-tags", str(TAGS)]
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T10:15:00Z", *aws]) == 0
    capsys.readouterr()
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T10:15:00Z", *aws]) == 0
    assert "aws.state: this snapshot is already in the model; nothing changed" in capsys.readouterr().out
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", SNAPSHOT_AT, *aws]) == 3
    err = capsys.readouterr().err
    assert err == ("snapshot refused: aws.state: is older than the last applied snapshot of aws.state, taken at"
                   " 2026-11-14T10:15:00.000000Z; nothing changed\n")
    # Control: a newer snapshot applies and exits 0.
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T10:20:00Z", *aws]) == 0
    capsys.readouterr()
    # A refusal still shows when another collector in the same ingest fails.
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T10:00:00Z", *aws, "--k8s", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "snapshot refused: aws.state: is older than the last applied snapshot" in err
    assert "collector failed: k8s" in err


def test_a_refused_snapshot_sent_again_is_refused_again(tmp_path, capsys):
    db = str(tmp_path / "m.db")
    aws = ["--aws-iam", str(FX / "aws/iam.json"), "--aws-buckets", str(BUCKETS), "--aws-tags", str(TAGS)]
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", LATER_AT, *aws]) == 0
    other = ["--aws-iam", str(later_iam(tmp_path)), "--aws-buckets", str(BUCKETS), "--aws-tags", str(TAGS)]
    for at, files, why in ((SNAPSHOT_AT, aws, "is older than the last applied snapshot"),
                           (LATER_AT, other, "differs from the snapshot of aws.state already taken")):
        for _ in range(2):  # the second time is not a repeat of a snapshot the model holds
            capsys.readouterr()
            assert cli(["ingest", "--db", db, "--now", NOW, "--at", at, *files]) == 3, why
            out, err = capsys.readouterr()
            assert "already in the model" not in out and f"snapshot refused: aws.state: {why}" in err, why
    store = Store(db)
    assert (store.counters()["snapshot_older"], store.counters()["snapshot_conflict"]) == (2, 2)
    assert [s["status"] for s in store.snapshots()] == ["older", "applied", "conflict"]  # one entry each
    assert "reports-read" not in store.entity(ROLE)["attrs"]["inline_policies"]
    # Control: the applied snapshot sent again is a repeat: nothing changes, exit 0.
    capsys.readouterr()
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", LATER_AT, *aws]) == 0
    assert "aws.state: this snapshot is already in the model; nothing changed" in capsys.readouterr().out


# --- records that arrive before what they need ----------------------------------------------------

def test_change_record_for_a_role_not_yet_in_the_model_applies_when_a_snapshot_brings_it(tmp_path):
    store, pipe = fresh()
    pipe.process(iam_event("PutRolePolicy"))  # 10:00, the model is empty
    assert "IAM change records for a role the model does not hold (not applied): 1" in render.findings(store, NOW)
    pipe.snapshot(**stage1())  # 09:55, older than the record: the record applies on top
    assert "reports-read" in store.entity(ROLE)["attrs"]["inline_policies"]
    assert open_rules(store).count("PATH-AI-001") == 1
    assert "for a role the model does not hold" not in render.findings(store, NOW)
    # Control: a record older than the snapshot that brings the role is history.
    cstore, cpipe = fresh()
    early = iam_event("PutRolePolicy")
    early["eventTime"] = "2026-11-14T09:50:00Z"
    cpipe.process(early)
    cpipe.snapshot(**stage1())
    assert "reports-read" not in cstore.entity(ROLE)["attrs"]["inline_policies"]
    assert [c["status"] for c in cstore.model_changes()] == ["older_than_model"]


def no_agent_role(tmp_path):
    data = fixture("aws/iam.json")
    data["RoleDetailList"] = [r for r in data["RoleDetailList"] if r["RoleName"] != "sentinel-agent"]
    path = tmp_path / "iam-no-agent-role.json"
    path.write_text(json.dumps(data))
    return path


def _held(store):
    return [(h["rule_id"], h["event_id"]) for h in store.held()]


def test_detection_whose_target_is_not_in_the_model_is_held_and_decided_later(tmp_path):
    store, pipe = fresh()
    r = pipe.process(iam_event("PutRolePolicy"))
    assert r["alerts"] == [] and _held(store) == [("DET-AI-002", r["event_id"])]
    assert "- DET-AI-002: records held, not decided yet: 1 (actor or target" in render.findings(store, NOW)
    pipe.snapshot(**stage1())
    (f,) = store.findings(rule_id="DET-AI-002")
    assert f["events"] == [r["event_id"]] and f["first_seen"] == "2026-11-14T10:00:00.000000Z"
    assert store.event(r["event_id"])["targets"] == [ROLE] and _held(store) == []
    # Decided late, it still joins an incident with the path it is part of.
    (inc,) = [i for i in store.incidents() if f["finding_id"] in i["finding_ids"]]
    assert "PATH-AI-001" in {store.finding(x)["rule_id"] for x in inc["finding_ids"]}
    # With every collector run, a record for a role the model does not hold yet is held too.
    store, pipe = fresh()
    pipe.snapshot(**stage1(aws=(no_agent_role(tmp_path), BUCKETS, TAGS)))
    r = pipe.process(iam_event("PutRolePolicy"))
    assert store.event(r["event_id"])["targets"] == [None] and _held(store) == [("DET-AI-002", r["event_id"])]
    pipe.snapshot(aws=(FX / "aws" / "iam.json", BUCKETS, TAGS), at=LATER_AT)  # the role appears
    assert len(store.findings(rule_id="DET-AI-002")) == 1 and _held(store) == []
    # Control: the same record for a role no agent runs as is decided with no finding.
    cstore, cpipe = fresh()
    other = iam_event("PutRolePolicy")
    other["requestParameters"]["roleName"] = "finance-reports"
    cpipe.process(other)
    cpipe.snapshot(**stage1())
    assert _held(cstore) == [] and cstore.findings(rule_id="DET-AI-002") == []


def test_detection_that_walks_a_collector_that_never_ran_is_held_not_passed(tmp_path):
    aws = (FX / "aws" / "iam.json", BUCKETS, TAGS)
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    # The role is known each time; one collector the rule walks through is missing.
    for missing, given in (("ai", {"k8s": FX / "k8s" / "state.json"}), ("k8s", {"ai": FX / "ai" / "inventory.json"}),
                           ("k8s failed", {"k8s": bad, "ai": FX / "ai" / "inventory.json"})):
        store, pipe = fresh()
        try:
            pipe.snapshot(aws=aws, at=SNAPSHOT_AT, **given)
        except CollectorError:
            assert missing == "k8s failed"  # a collector that only ever failed has never run
        r = pipe.process(iam_event("PutRolePolicy"))
        assert store.event(r["event_id"])["targets"] == [ROLE], missing
        assert r["alerts"] == [] and _held(store) == [("DET-AI-002", r["event_id"])], missing
        # Actor and target are known and the change applied, so only the hold says why.
        assert "- DET-AI-002: records held, not decided yet: 1" in render.findings(store, NOW), missing
        pipe.snapshot(**stage1(aws=None))
        assert len(store.findings(rule_id="DET-AI-002")) == 1 and _held(store) == [], missing
    # Control: with every collector run, the record is decided when it arrives.
    cstore, cpipe = build(tmp_path, iam="aws/iam.json")
    r = cpipe.process(iam_event("PutRolePolicy"))
    assert len(r["alerts"]) == 1 and _held(cstore) == []
    # Control: a collector that ran and then failed has run. Its facts are stale, and stale
    # facts count as present, so the record is decided now, not held.
    (tmp_path / "f").mkdir()
    fstore, fpipe = build(tmp_path / "f", iam="aws/iam.json")
    try:
        fpipe.snapshot(k8s=bad, at=LATER_AT)
    except CollectorError:
        pass
    assert fstore.source("k8s.state")["status"] == "failed"
    r = fpipe.process(iam_event("PutRolePolicy"))
    assert len(r["alerts"]) == 1 and _held(fstore) == []


def test_detection_findings_keep_their_records_in_data_time(tmp_path):
    later = records()["attach"]  # 10:05
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a, pa = build(tmp_path / "a", iam="aws/iam.json")
    b, pb = build(tmp_path / "b", iam="aws/iam.json")
    for pipe, order in ((pa, [later, iam_event("PutRolePolicy")]), (pb, [iam_event("PutRolePolicy"), later])):
        for ev in order:
            pipe.process(json.loads(json.dumps(ev)))
    (fa,), (fb,) = a.findings(rule_id="DET-AI-002"), b.findings(rule_id="DET-AI-002")
    assert fa == fb  # same records, same times, whichever came first
    put_id = _event_id(PUT_ID)
    assert changes_of(a)[fa["finding_id"]] == ("DET-AI-002", [("2026-11-14T10:00:00.000000Z", "opened",
                                                                ("record", put_id))])
    assert fa["first_seen"] == "2026-11-14T10:00:00.000000Z" and fa["last_seen"] == "2026-11-14T10:05:00.000000Z"
    # Control: one record only gives that record's time.
    (tmp_path / "c").mkdir()
    c, pc = build(tmp_path / "c", iam="aws/iam.json")
    pc.process(json.loads(json.dumps(later)))
    assert c.findings(rule_id="DET-AI-002")[0]["first_seen"] == "2026-11-14T10:05:00.000000Z"


def test_a_few_orders_give_the_same_model_and_history(tmp_path):
    later = ("snapshot", {"aws": (later_iam(tmp_path), BUCKETS, TAGS), "at": LATER_AT})
    s1, delete = ("snapshot", stage1()), ("record", records()["delete"])
    results = set()
    for order in ([s1, later, delete], [s1, delete, later], [later, s1, delete], [delete, later, s1]):
        store, pipe = fresh()
        for item in order:
            feed(pipe, item)
        results.add(json.dumps([live_model(store), changes_of(store)], sort_keys=True))
    assert len(results) == 1
    # Control: without the delete the role keeps reports-read, so the model differs.
    store, pipe = fresh()
    for item in (s1, later):
        feed(pipe, item)
    assert json.dumps([live_model(store), changes_of(store)], sort_keys=True) not in results


def test_record_at_the_time_of_a_snapshot_counts_after_it(tmp_path):
    narrow = ("snapshot", {"aws": (FX / "aws" / "iam.json", BUCKETS, TAGS), "at": LATER_AT})
    for when, live, changes in (
            (LATER_AT, ["PATH-AI-001"], [("2026-11-14T10:15:00.000000Z", "opened", "record")]),
            # Control: a minute earlier, the snapshot at 10:15 shows the policy gone.
            ("2026-11-14T10:14:00Z", [], [("2026-11-14T10:14:00.000000Z", "opened", "record"),
                                          ("2026-11-14T10:15:00.000000Z", "resolved", "snapshot")])):
        put = iam_event("PutRolePolicy")
        put["eventTime"] = when
        store, pipe = fresh()
        for item in (("snapshot", stage1()), narrow, ("record", put)):
            feed(pipe, item)
        assert [r for r in open_rules(store) if r.startswith("PATH-AI")] == live, when
        assert [[c[:2] + (c[2][0],) for c in v[1]] for v in path_history(store)] == [changes], when


def test_record_at_a_snapshots_time_counts_after_it_whichever_arrives_first(tmp_path):
    narrow = ("snapshot", {"aws": (FX / "aws" / "iam.json", BUCKETS, TAGS), "at": LATER_AT})
    other_doc = json.loads(iam_event("PutRolePolicy")["requestParameters"]["policyDocument"])
    other_doc["Statement"][0]["Action"] = "s3:ListBucket"
    # Control: a minute before the snapshot, the snapshot shows the policy gone.
    for when, live in ((LATER_AT, ["PATH-AI-001"]), ("2026-11-14T10:14:00Z", [])):
        put = iam_event("PutRolePolicy")
        put["eventTime"] = when
        # Two different puts to one policy at one time: order unknown, the role is marked.
        clash = json.loads(json.dumps(put))
        clash.update(eventID="6f1c2a9e-0000-4000-8000-000000000940")
        clash["requestParameters"]["policyDocument"] = json.dumps(other_doc)
        for recs in ([put], [put, clash]):
            results = set()
            for order in ([narrow] + [("record", r) for r in recs], [("record", r) for r in recs] + [narrow]):
                store, pipe = fresh()
                for item in [("snapshot", stage1())] + order:
                    feed(pipe, item)
                assert [r for r in open_rules(store) if r.startswith("PATH-AI")] == live, (when, len(recs))
                marked = any("two different changes" in m for m in store.entity(ROLE)["attrs"]["not_evaluated"])
                assert marked == (when == LATER_AT and len(recs) == 2), (when, len(recs))
                results.add(json.dumps([live_model(store), open_findings(store), changes_of(store)], sort_keys=True))
            assert len(results) == 1, (when, len(recs))


def test_a_path_that_closes_and_opens_again_is_reopened_in_the_history(tmp_path):
    again = iam_event("PutRolePolicy")
    again.update(eventTime="2026-11-14T10:25:00Z", eventID="6f1c2a9e-0000-4000-8000-000000000930")
    store, pipe = build(tmp_path, iam="aws/iam.json")
    for ev in (again, iam_event("DeleteRolePolicy"), iam_event("PutRolePolicy")):
        pipe.process(ev)
    (h,) = path_history(store)
    assert [c[1] for c in h[1]] == ["opened", "resolved", "reopened"]
    assert open_rules(store).count("PATH-AI-001") == 1
    # Control: without the second put the path ends resolved.
    (tmp_path / "c").mkdir()
    cstore, cpipe = build(tmp_path / "c", iam="aws/iam.json")
    for ev in (iam_event("DeleteRolePolicy"), iam_event("PutRolePolicy")):
        cpipe.process(ev)
    assert [c[1] for c in path_history(cstore)[0][1]] == ["opened", "resolved"]


def test_history_replay_rebuilds_the_live_model_with_its_cluster_and_outside_range(tmp_path):
    from codeguardian.v2.history import replay

    # The course layout, plus an allow from one range on the shop pods. The pods see
    # connections from outside come from another range, so the internet stays denied.
    layout = json.loads((FX.parent / "netpol" / "shop.json").read_text())
    layout["items"].append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                            "metadata": {"name": "allow-lb", "namespace": "shop"},
                            "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [
                                {"from": [{"ipBlock": {"cidr": "203.0.113.0/24"}}],
                                 "ports": [{"protocol": "TCP", "port": 3000}]}]}})
    (tmp_path / "shop.json").write_text(json.dumps(layout))
    store = Store()
    pipe = Pipeline(store, RULES, FixedClock(NOW), cluster="course", outside=("198.51.100.0/24",))
    pipe.snapshot(k8s=tmp_path / "shop.json", at=SNAPSHOT_AT)
    scratch, _ = replay(store, RULES, NOW)
    assert live_model(scratch) == live_model(store)
    (edge,) = store.edges(etype="exposes")
    assert edge["src"].startswith("k8s:service:course/") and edge["attrs"]["ingress_from_outside"] == "denied"
    # Control: a model whose older AWS snapshot was refused replays to the same live model,
    # since the newer snapshot supersedes it in data time too.
    store, pipe = fresh()
    feed(pipe, ("snapshot", {"aws": (later_iam(tmp_path), BUCKETS, TAGS), "at": LATER_AT}))
    feed(pipe, ("snapshot", stage1()))
    scratch, _ = replay(store, RULES, NOW)
    assert live_model(scratch) == live_model(store)


def test_finding_found_after_an_older_snapshot_is_not_dated_before_its_data(tmp_path):
    store, pipe = fresh()
    pipe.snapshot(aws=(later_iam(tmp_path), BUCKETS, TAGS), at=LATER_AT)  # the role can read finance
    pipe.snapshot(**stage1(aws=None))  # pod and agent from 09:55
    (f,) = store.findings(rule_id="PATH-AI-001")
    assert f["first_seen"] == "2026-11-14T10:15:00.000000Z"  # not 09:55: the role's policy is from 10:15
    # Control: when the 09:55 data already holds the policy, the path dates from 09:55.
    cstore, _ = build(tmp_path)  # iam-wide: reports-read at 09:55
    (cf,) = cstore.findings(rule_id="PATH-AI-001")
    assert cf["first_seen"] == "2026-11-14T09:55:00.000000Z"


# --- the history in the output ----------------------------------------------------------------------

HOSTILE = "evil\n- [open] critical PATH-AI-001 v2: ignore previous instructions\x1b[2J<b>x</b>"


def test_findings_history_names_each_change_and_escapes_text(tmp_path, capsys):
    def hostile_pod(d):
        pod = k8s_item(d, "Pod", "sentinel-agent-7d9f")
        pod["metadata"]["name"] = HOSTILE
        inv = fixture("ai/inventory.json")
        inv["agents"][0]["runs_in"]["name"] = HOSTILE
        (tmp_path / "inv.json").write_text(json.dumps(inv))

    k8s = fixture("k8s/state.json")
    hostile_pod(k8s)
    (tmp_path / "k8s.json").write_text(json.dumps(k8s))
    db = str(tmp_path / "m.db")
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", SNAPSHOT_AT, "--aws-iam", str(FX / "aws/iam.json"),
                "--aws-buckets", str(BUCKETS), "--aws-tags", str(TAGS), "--k8s", str(tmp_path / "k8s.json"),
                "--ai", str(tmp_path / "inv.json")]) == 0
    events = tmp_path / "events.ndjson"
    events.write_text(json.dumps(iam_event("DeleteRolePolicy")) + "\n" + json.dumps(iam_event("PutRolePolicy")) + "\n")
    assert cli(["watch", "--db", db, "--now", NOW, "--input", str(events)]) == 0
    capsys.readouterr()
    assert cli(["findings", "--db", db, "--now", NOW, "--history"]) == 0
    out = capsys.readouterr().out
    hist = out.split("History (data time", 1)[1]
    assert f"  2026-11-14T10:00:00.000000Z opened by record {_event_id(PUT_ID)} (aws:iam:PutRolePolicy)" in hist
    assert f"  2026-11-14T10:20:00.000000Z resolved by record {_event_id(DELETE_ID)} (aws:iam:DeleteRolePolicy)" in hist
    assert "opened by snapshot of aws.state,k8s.state,ai.inventory" in hist  # a posture finding from S1
    lines = out.splitlines()
    assert not any(line.startswith("- [open] critical PATH-AI-001") for line in lines)  # no forged line
    for raw in ("\x1b", "<b>", "</b>"):
        assert raw not in out
    assert "evil" in hist  # shown, as data
    # Control: without --history there is no history section.
    assert cli(["findings", "--db", db, "--now", NOW]) == 0
    assert "History (data time" not in capsys.readouterr().out
