"""Paths that only a NetworkPolicy closes (slice netpol-shadow), and reach's exit codes.

A path that a policy closes still rests on the cluster's network plugin enforcing policy,
which the model cannot see. So it gives a low-severity `-NP` finding of its own. Each
claim has a control: a case that differs in one fact and gives the other answer. Every
test here, and every parametrized case, must have a mutant in tests/mutants.py."""

import copy
import json

import pytest

from codeguardian.cli import main as cli
from codeguardian.v2 import render
from codeguardian.v2.pipeline import Pipeline
from codeguardian.v2.rules import RULES_DIR, SHADOW_NOTES, RuleError, load_rules, shadow, validate
from codeguardian.v2.schema import FixedClock, edge_id, ts
from codeguardian.v2.store import Store
from test_v2_netpol import DENY, EVERY, LAYOUT, SHOP, SHOP_SVC, allow
from v2_helpers import FINANCE, FX, NOW, POD, SNAPSHOT_AT, SVC, build, fixture, k8s_item

SUFFIX = ", held back only by NetworkPolicy"
UNREADABLE_TAGS = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}


def _tags_unreadable(tags):
    tags["example-finance-records"] = copy.deepcopy(UNREADABLE_TAGS)


# rule -> the fixture edits under which the chain gives that rule's path
CASES = {
    "PATH-AI-001": {},
    "PATH-AI-002": {"edit_tags": _tags_unreadable},
}


def _with(*items, edit=None):
    def run(data):
        data["items"].extend(copy.deepcopy(list(items)))
        if edit:
            edit(data)
    return run


def _chain(tmp_path, name, *items, **kw):
    d = tmp_path / name
    d.mkdir()
    return build(d, edit_k8s=_with(*items), **kw)


def _open(store, rule_id):
    return store.findings(status="open", rule_id=rule_id)


def _np(rule_id):
    return rule_id + "-NP"


def _snap(pipe, tmp_path, name, data, at):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data))
    pipe.snapshot(k8s=path, at=ts(at))  # as the CLI passes it


# --- the -NP finding --------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_policy_that_closes_the_path_gives_an_np_finding_instead(tmp_path, rule_id):
    store, _ = _chain(tmp_path, "denied", DENY, **CASES[rule_id])
    assert store.edge(edge_id("exposes", SVC, POD))["attrs"]["ingress_from_outside"] == "denied"
    assert _open(store, rule_id) == []
    (held,) = _open(store, _np(rule_id))
    # Control: without the policy the same walk is the open path, and there is no -NP finding.
    plain, _ = _chain(tmp_path, "plain", **CASES[rule_id])
    (path,) = _open(plain, rule_id)
    assert plain.findings(rule_id=_np(rule_id)) == []
    assert held["finding_id"] != path["finding_id"]
    assert (held["kind"], held["severity"], held["title"]) == ("path", "low", path["title"] + SUFFIX)
    assert (held["path"], held["primary_entity"], held["entities"]) == (path["path"], path["primary_entity"],
                                                                         path["entities"])
    assert set(SHADOW_NOTES) <= set(held["notes"])
    assert not set(SHADOW_NOTES) & set(path["notes"])
    assert "depends on the cluster's network plugin enforcing NetworkPolicy" in held["notes"]


def test_removing_and_restoring_the_policy_swaps_the_two_findings(tmp_path):
    store, pipe = build(tmp_path)
    (before,) = _open(store, "PATH-AI-001")
    plain = fixture("k8s/state.json")
    denied = copy.deepcopy(plain)
    denied["items"].append(copy.deepcopy(DENY))

    _snap(pipe, tmp_path, "denied", denied, "2026-11-14T10:00:00Z")
    (held,) = _open(store, "PATH-AI-001-NP")
    assert _open(store, "PATH-AI-001") == []
    assert store.finding(before["finding_id"])["status"] == "resolved"

    _snap(pipe, tmp_path, "plain", plain, "2026-11-14T10:05:00Z")
    (after,) = _open(store, "PATH-AI-001")
    assert _open(store, "PATH-AI-001-NP") == []
    assert store.finding(held["finding_id"])["status"] == "resolved"
    assert (after["finding_id"], after["first_seen"]) == (before["finding_id"], before["first_seen"])

    _snap(pipe, tmp_path, "denied-again", denied, "2026-11-14T10:10:00Z")
    (again,) = _open(store, "PATH-AI-001-NP")
    assert _open(store, "PATH-AI-001") == []
    assert (again["finding_id"], again["first_seen"]) == (held["finding_id"], held["first_seen"])
    assert again["last_seen"] == "2026-11-14T10:10:00.000000Z"


def test_policy_that_is_not_evaluated_keeps_the_open_path_and_gives_no_np_finding(tmp_path):
    def selecting(expr):
        return allow("p", EVERY, {"matchExpressions": [expr]})

    store, _ = _chain(tmp_path, "unknown", DENY, selecting({"key": "app", "operator": "Gt", "values": ["1"]}))
    assert store.edge(edge_id("exposes", SVC, POD))["attrs"]["ingress_from_outside"] == "not evaluated"
    (f,) = _open(store, "PATH-AI-001")
    assert any("operator 'Gt'" in n for n in f["notes"])
    assert store.findings(rule_id="PATH-AI-001-NP") == []
    # Control: the same allow with an operator that is read, and selects another pod.
    store, _ = _chain(tmp_path, "known", DENY, selecting({"key": "app", "operator": "In", "values": ["report-builder"]}))
    assert _open(store, "PATH-AI-001") == []
    assert len(_open(store, "PATH-AI-001-NP")) == 1


def test_np_finding_needs_every_other_hop_of_its_path(tmp_path):
    # The twin walks every other hop as its rule does: no sensitive bucket, no -NP finding.
    def internal(tags):
        tags["example-finance-records"]["TagSet"][0]["Value"] = "internal"

    store, _ = _chain(tmp_path, "internal", DENY, edit_tags=internal)
    assert store.findings(rule_id="PATH-AI-001-NP") == []
    assert store.entity(FINANCE)["attrs"]["sensitive"] is False
    # Control: the bucket tagged sensitive.
    store, _ = _chain(tmp_path, "sensitive", DENY)
    assert len(_open(store, "PATH-AI-001-NP")) == 1


DENY_FIXTURE = LAYOUT.parent / "agents-deny.json"


def test_findings_list_the_np_finding_and_the_swap_from_the_command_line(tmp_path, capsys):
    expected = fixture("k8s/state.json")
    expected["items"].append(copy.deepcopy(DENY))
    assert json.loads(DENY_FIXTURE.read_text()) == expected  # the chain's state plus one policy
    db, fx = str(tmp_path / "m.db"), FX
    aws = ["--aws-iam", str(fx / "aws/iam-wide.json"), "--aws-buckets", str(fx / "aws/s3-buckets.json"),
           "--aws-tags", str(fx / "aws/s3-tags.json"), "--ai", str(fx / "ai/inventory.json")]

    def ingest(k8s, at):
        assert cli(["ingest", "--db", db, "--now", NOW, "--at", at, "--k8s", str(k8s), *aws]) == 0
        assert cli(["findings", "--db", db, "--now", NOW]) == 0
        return [line for line in capsys.readouterr().out.splitlines() if "PATH-AI-001" in line]

    lines = ingest(DENY_FIXTURE, SNAPSHOT_AT)
    assert lines == ["- [open] low PATH-AI-001-NP v2: An AI agent reachable from the internet runs with an identity"
                     " that can read sensitive data, held back only by NetworkPolicy"]
    out = render.findings(Store(db), NOW)
    assert "  note: depends on the cluster's network plugin enforcing NetworkPolicy" in out.splitlines()
    # Control: the same state without the policy, taken later. The two findings swap.
    lines = ingest(fx / "k8s/state.json", "2026-11-14T10:00:00Z")
    assert sorted(line.split(":")[0] for line in lines) == ["- [open] critical PATH-AI-001 v2",
                                                             "- [resolved] low PATH-AI-001-NP v2"]


# --- the course layout: a pod with no agent, held back only by its namespace's policies -------

EXPOSED = "PATH-EXPOSED-001"
EXPOSED_TITLE = "A pod reachable from the internet through a Service"
INTERNET = "net:internet:any"
BOTH = ("default-deny-ingress", "allow-shop-clients")
SHOP_NO_POLICY = LAYOUT.parent / "shop-no-policy.json"


def _layout(drop=()):
    data = json.loads(LAYOUT.read_text())
    data["items"] = [i for i in data["items"] if not (i["kind"] == "NetworkPolicy" and i["metadata"]["name"] in drop)]
    return data


def _course_pipe():
    store = Store()
    return store, Pipeline(store, load_rules(), FixedClock(NOW), cluster="course")


def _open_paths(store):
    return sorted(f["rule_id"] for f in store.findings(status="open") if f["kind"] == "path")


def test_course_layout_gives_an_np_finding_for_the_shop_pod_and_no_open_path(tmp_path):
    store, pipe = _course_pipe()
    _snap(pipe, tmp_path, "layout", _layout(), SNAPSHOT_AT)
    assert store.edge(edge_id("exposes", SHOP_SVC, SHOP))["attrs"]["ingress_from_outside"] == "denied"
    assert _open_paths(store) == [_np(EXPOSED)]
    (held,) = _open(store, _np(EXPOSED))
    # Control: the same layout without its two policies gives the open path and no -NP finding.
    plain, pipe = _course_pipe()
    _snap(pipe, tmp_path, "open", _layout(drop=BOTH), SNAPSHOT_AT)
    assert _open_paths(plain) == [EXPOSED]
    (path,) = _open(plain, EXPOSED)
    assert plain.findings(rule_id=_np(EXPOSED)) == []
    assert held["path"] == path["path"] == [INTERNET, SHOP_SVC, SHOP]
    assert held["primary_entity"] == path["primary_entity"] == SHOP
    assert held["finding_id"] != path["finding_id"]
    assert (path["severity"], path["title"]) == ("medium", EXPOSED_TITLE)
    assert (held["severity"], held["title"]) == ("low", EXPOSED_TITLE + SUFFIX)
    assert set(SHADOW_NOTES) <= set(held["notes"])
    assert not set(SHADOW_NOTES) & set(path["notes"])


def test_removing_both_shop_policies_swaps_the_findings_and_restoring_them_swaps_back(tmp_path):
    store, pipe = _course_pipe()
    _snap(pipe, tmp_path, "open", _layout(drop=BOTH), SNAPSHOT_AT)
    (before,) = _open(store, EXPOSED)

    _snap(pipe, tmp_path, "layout", _layout(), "2026-11-14T10:00:00Z")
    (held,) = _open(store, _np(EXPOSED))
    assert _open(store, EXPOSED) == []
    assert store.finding(before["finding_id"])["status"] == "resolved"

    _snap(pipe, tmp_path, "open-again", _layout(drop=BOTH), "2026-11-14T10:05:00Z")
    (after,) = _open(store, EXPOSED)
    assert _open(store, _np(EXPOSED)) == []
    assert store.finding(held["finding_id"])["status"] == "resolved"
    assert (after["finding_id"], after["first_seen"]) == (before["finding_id"], before["first_seen"])

    _snap(pipe, tmp_path, "layout-again", _layout(), "2026-11-14T10:10:00Z")
    (again,) = _open(store, _np(EXPOSED))
    assert _open(store, EXPOSED) == []
    assert (again["finding_id"], again["first_seen"]) == (held["finding_id"], held["first_seen"])


def test_removing_only_the_default_deny_leaves_the_np_finding_and_no_open_path(tmp_path):
    # allow-shop-clients still selects the shop pod and admits only pods in namespaces
    # labelled access=shop, so a connection from outside stays denied and nothing swaps.
    store, pipe = _course_pipe()
    _snap(pipe, tmp_path, "layout", _layout(), SNAPSHOT_AT)
    (held,) = _open(store, _np(EXPOSED))
    _snap(pipe, tmp_path, "no-deny", _layout(drop=("default-deny-ingress",)), "2026-11-14T10:00:00Z")
    assert store.edge(edge_id("exposes", SHOP_SVC, SHOP))["attrs"] == {
        "ingress_from_outside": "denied", "network_policies": ["NetworkPolicy shop/allow-shop-clients"]}
    assert _open(store, EXPOSED) == []
    (still,) = _open(store, _np(EXPOSED))
    assert (still["finding_id"], still["first_seen"]) == (held["finding_id"], held["first_seen"])
    # Control: the same snapshot with the allow open to any source on TCP 3000 swaps them.
    data = _layout(drop=("default-deny-ingress",))
    del k8s_item(data, "NetworkPolicy", "allow-shop-clients")["spec"]["ingress"][0]["from"]
    _snap(pipe, tmp_path, "any-source", data, "2026-11-14T10:05:00Z")
    assert len(_open(store, EXPOSED)) == 1
    assert _open(store, _np(EXPOSED)) == []


def test_course_layout_policy_not_evaluated_keeps_the_open_path_and_gives_no_np_finding(tmp_path):
    def with_policy(name, operator, values):
        data = _layout()
        expr = {"key": "app", "operator": operator, "values": values}
        data["items"].append(allow("unknown", EVERY, {"matchExpressions": [expr]}, ns="shop"))
        store, pipe = _course_pipe()
        _snap(pipe, tmp_path, name, data, SNAPSHOT_AT)
        return store

    store = with_policy("unknown", "Gt", ["1"])
    assert store.edge(edge_id("exposes", SHOP_SVC, SHOP))["attrs"]["ingress_from_outside"] == "not evaluated"
    (f,) = _open(store, EXPOSED)
    assert any("operator 'Gt'" in n for n in f["notes"])
    assert store.findings(rule_id=_np(EXPOSED)) == []
    # Control: the same policy with an operator that is read, selecting another pod.
    store = with_policy("known", "In", ["other"])
    assert _open(store, EXPOSED) == []
    assert len(_open(store, _np(EXPOSED))) == 1


def test_findings_list_the_course_layout_np_finding_and_the_swap_from_the_command_line(tmp_path, capsys):
    expected = json.loads(LAYOUT.read_text())
    expected["items"] = [i for i in expected["items"] if i["kind"] != "NetworkPolicy"]
    assert json.loads(SHOP_NO_POLICY.read_text()) == expected  # the layout without its two policies
    db = str(tmp_path / "course.db")

    def ingest(k8s, at):
        assert cli(["ingest", "--db", db, "--now", NOW, "--at", at, "--cluster", "course", "--k8s", str(k8s)]) == 0
        assert cli(["findings", "--db", db, "--now", NOW]) == 0
        return sorted(line for line in capsys.readouterr().out.splitlines() if "PATH-" in line)

    assert ingest(LAYOUT, SNAPSHOT_AT) == [f"- [open] low {EXPOSED}-NP v1: {EXPOSED_TITLE}{SUFFIX}"]
    # Control: the layout without its two policies, taken later. The two findings swap.
    assert ingest(SHOP_NO_POLICY, "2026-11-14T10:00:00Z") == [f"- [open] medium {EXPOSED} v1: {EXPOSED_TITLE}",
                                                               f"- [resolved] low {EXPOSED}-NP v1: {EXPOSED_TITLE}{SUFFIX}"]


# --- the rule loader --------------------------------------------------------------------------

def _gated(*gates):
    hops = [{"edge": "reachable_from", "dir": "in", "to": "service"}]
    for n, gate in enumerate(gates):
        hop = {"edge": "exposes", "dir": "out" if n % 2 == 0 else "in", "to": "pod" if n % 2 == 0 else "service"}
        if gate is not None:
            hop["edge_where"] = [gate]
        hops.append(hop)
    return {"id": "T-1", "version": 3, "kind": "path", "severity": "high", "title": "t", "frameworks": [],
            "start": "internet", "hops": hops}


GATE = {"attr": "ingress_from_outside", "op": "ne", "value": "denied"}


def test_loader_gives_each_gated_path_rule_one_twin_after_it():
    rules = load_rules()
    ids = [r["id"] for r in rules]
    for base in ("PATH-AI-001", "PATH-AI-002", "PATH-EXPOSED-001"):
        assert ids[ids.index(base) + 1] == _np(base)
        rule, twin = rules[ids.index(base)], rules[ids.index(base) + 1]
        assert (twin["severity"], twin["version"], twin["frameworks"]) == ("low", rule["version"], [])
        flipped = copy.deepcopy(rule["hops"])
        flipped[1]["edge_where"] = [{"attr": "ingress_from_outside", "op": "eq", "value": "denied"}]
        assert twin["hops"] == flipped
    twin = shadow(validate(_gated(GATE)))
    assert twin["id"] == "T-1-NP" and twin["hops"][1]["edge_where"][0]["op"] == "eq"
    # Control: a path rule that does not test NetworkPolicy, and a posture rule, get none.
    assert shadow(validate(_gated(None))) is None
    assert not [r for r in rules if r["kind"] != "path" and r["id"].endswith("-NP")]
    assert len([i for i in ids if i.endswith("-NP")]) == len([r for r in rules if r["kind"] == "path"]) // 2


@pytest.mark.parametrize("form", ["eq-allowed", "in-allowed", "ne-not-evaluated", "nonempty"])
def test_loader_refuses_a_networkpolicy_test_that_could_read_not_evaluated_as_closed(form):
    bad = {"eq-allowed": {"op": "eq", "value": "allowed"}, "in-allowed": {"op": "in", "value": ["allowed"]},
           "ne-not-evaluated": {"op": "ne", "value": "not evaluated"}, "nonempty": {"op": "nonempty"}}[form]
    with pytest.raises(RuleError, match="may be tested only as ne denied or eq denied"):
        validate(_gated({"attr": "ingress_from_outside", **bad}))
    # On every hop that tests it, not only the first: here the second, walked into a Service.
    with pytest.raises(RuleError, match="may be tested only as ne denied or eq denied"):
        validate(_gated(None, {"attr": "ingress_from_outside", **bad}))
    # Control: the two forms that keep "not evaluated" open.
    validate(_gated(GATE))
    validate(_gated({"attr": "ingress_from_outside", "op": "eq", "value": "denied"}))


def test_loader_refuses_a_twin_for_a_rule_with_two_gates():
    with pytest.raises(RuleError, match="2 hops test ingress_from_outside"):
        shadow(validate(_gated(GATE, GATE)))
    # Control: two exposes hops, one of them gated.
    assert shadow(validate(_gated(GATE, None)))["id"] == "T-1-NP"


def test_loader_refuses_a_hand_written_rule_with_a_twin_id(tmp_path):
    text = (RULES_DIR / "paths.toml").read_text()
    clash = text + '\n[[rule]]\nid = "PATH-AI-001-NP"\nversion = 1\nkind = "posture"\nseverity = "low"\n' \
                   'title = "t"\nframeworks = []\nentity = "pod"\nwhere = [{ attr = "privileged", op = "eq", value = true }]\n'
    (tmp_path / "paths.toml").write_text(clash)
    with pytest.raises(RuleError, match="duplicate rule id PATH-AI-001-NP"):
        load_rules(tmp_path)
    # Control: the same rule under another ID loads.
    (tmp_path / "paths.toml").write_text(clash.replace('id = "PATH-AI-001-NP"', 'id = "POST-T-001"'))
    assert "POST-T-001" in [r["id"] for r in load_rules(tmp_path)]


# No shipped path rule has notes, frameworks or an `eq denied` gate, so these use rules
# written here: a test on the shipped files alone could not see these controls.
HELD = {"attr": "ingress_from_outside", "op": "eq", "value": "denied"}


def test_loader_refuses_path_rule_notes_that_are_not_a_list_of_strings():
    for notes in ("x", [1], ["x", None]):
        with pytest.raises(RuleError, match="notes must be a list of strings"):
            validate({**_gated(GATE), "notes": notes})
    # Control: a list of strings loads, and its twin gets it.
    assert shadow(validate({**_gated(GATE), "notes": ["x"]}))["notes"][0] == "x"


def test_twin_has_no_frameworks_even_when_its_rule_has_some():
    rule = validate({**_gated(GATE), "frameworks": ["ATT&CK T0000"]})
    assert shadow(rule)["frameworks"] == []
    # Control: the rule itself keeps its frameworks.
    assert rule["frameworks"] == ["ATT&CK T0000"]


def test_twin_carries_its_rule_notes_before_its_own_two():
    twin = shadow(validate({**_gated(GATE), "notes": ["n"]}))
    assert twin["notes"] == ["n", *SHADOW_NOTES]
    # Control: a rule with no notes gives a twin with only its two.
    assert shadow(validate(_gated(GATE)))["notes"] == list(SHADOW_NOTES)


def test_twin_starts_where_its_rule_starts():
    rule = validate({**_gated(GATE), "start": "service", "hops": [{"edge": "exposes", "dir": "out", "to": "pod",
                                                                    "edge_where": [GATE]}]})
    twin = shadow(rule)
    assert (twin["start"], twin["hops"]) == ("service", [{"edge": "exposes", "dir": "out", "to": "pod",
                                                          "edge_where": [HELD]}])
    # Control: a rule that starts at the internet gives a twin that starts there too.
    assert shadow(validate(_gated(GATE)))["start"] == "internet"


def test_only_a_ne_denied_gate_makes_a_twin():
    # A rule that already tests eq denied finds only held-back walks; a twin of it would be
    # a copy of the rule under another ID.
    assert shadow(validate(_gated(HELD))) is None
    # Only the ne denied hop counts as the gate: this rule has one, so it gets a twin.
    twin = shadow(validate(_gated(HELD, GATE)))
    assert [h.get("edge_where") for h in twin["hops"]] == [None, [HELD], [HELD]]
    # Control: the ne denied gate gives one.
    assert shadow(validate(_gated(GATE)))["hops"][1]["edge_where"] == [HELD]


# --- reach: one exit code per answer ----------------------------------------------------------

def _course(tmp_path, capsys, name, *extra, drop_policies=False):
    data = json.loads(LAYOUT.read_text())
    if drop_policies:
        data["items"] = [i for i in data["items"] if i["kind"] != "NetworkPolicy"]
    data["items"].extend(copy.deepcopy(list(extra)))
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data))
    db = str(tmp_path / f"{name}.db")
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", SNAPSHOT_AT, "--cluster", "course", "--k8s", str(path)]) == 0
    capsys.readouterr()
    return db


def _reach(db, src, dst="shop/shop-web-5d8f", port="3000"):
    return cli(["reach", "--db", db, "--now", NOW, "--from", src, "--to", dst, "--port", port])


def test_reach_exits_0_for_allowed(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    assert _reach(db, "client/client-7c4b") == 0
    assert capsys.readouterr().out.startswith("allowed: ")
    # Control: the same pods on a port no rule allows.
    assert _reach(db, "client/client-7c4b", port="3001") == 1
    assert capsys.readouterr().out.startswith("denied: ")


def test_reach_exits_1_for_denied(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    assert _reach(db, "outsider/outsider-2f9a") == 1
    assert capsys.readouterr().out.startswith("denied: ")
    # Control: the layout without its two policies.
    db = _course(tmp_path, capsys, "open", drop_policies=True)
    assert _reach(db, "outsider/outsider-2f9a") == 0


def test_reach_exits_2_for_not_evaluated(tmp_path, capsys):
    unknown = allow("unknown", EVERY, {"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]},
                    ns="shop")
    db = _course(tmp_path, capsys, "unknown", unknown)
    assert _reach(db, "outsider/outsider-2f9a") == 2
    out = capsys.readouterr().out
    assert out.startswith("not evaluated: ") and "operator 'Gt'" in out
    # Control: the same policy with an operator that is read, selecting another pod.
    known = allow("unknown", EVERY, {"matchExpressions": [{"key": "app", "operator": "In", "values": ["other"]}]},
                  ns="shop")
    db = _course(tmp_path, capsys, "known", known)
    assert _reach(db, "outsider/outsider-2f9a") == 1


def test_reach_exits_3_for_a_pod_not_in_the_model(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    capsys.readouterr()
    for src, dst in (("client/nobody", "shop/shop-web-5d8f"), ("client/client-7c4b", "shop/nobody"),
                     ("elsewhere/client-7c4b", "shop/shop-web-5d8f")):
        assert _reach(db, src, dst) == 3, (src, dst)
        out = capsys.readouterr()
        assert out.out == "" and "is not in the model" in out.err, (src, dst)
    # An empty model holds no pod at all.
    assert _reach(str(tmp_path / "empty.db"), "client/client-7c4b") == 3
    assert "is not in the model" in capsys.readouterr().err
    # A pod the last snapshot no longer lists is not in the model either.
    data = json.loads(LAYOUT.read_text())
    data["items"] = [i for i in data["items"] if i["metadata"]["name"] != "client-7c4b"]
    (tmp_path / "gone.json").write_text(json.dumps(data))
    assert cli(["ingest", "--db", db, "--now", NOW, "--at", "2026-11-14T10:00:00Z", "--cluster", "course",
                "--k8s", str(tmp_path / "gone.json")]) == 0
    capsys.readouterr()
    assert _reach(db, "client/client-7c4b") == 3
    # Control: a pod the model holds gets an answer.
    assert _reach(db, "outsider/outsider-2f9a") == 1


def test_reach_exits_3_when_the_model_cannot_be_read(tmp_path, capsys):
    (tmp_path / "junk.db").write_bytes(b"not a database, " * 64)
    for db in (str(tmp_path / "no-such-dir" / "m.db"), str(tmp_path / "junk.db")):
        assert _reach(db, "client/client-7c4b") == 3, db
        out = capsys.readouterr()
        assert out.out == "" and out.err.startswith("no answer: "), db
    # Control: a model that can be read gives an answer.
    assert _reach(_course(tmp_path, capsys, "layout"), "client/client-7c4b") == 0


def test_reach_usage_errors_exit_3_not_2(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    capsys.readouterr()
    for args in (["--port", "abc"], ["--port", "3000", "--protocol", "ICMP"], [], ["--port", "3000", "--bogus"],
                 ["--port", "3000", "--bo\x1b[2Jgus\nallowed: x"]):
        with pytest.raises(SystemExit) as exc:
            cli(["reach", "--db", db, "--now", NOW, "--from", "client/client-7c4b", "--to", "shop/shop-web-5d8f", *args])
        assert exc.value.code == 3, args
        out = capsys.readouterr()
        # The answer channel stays empty, and the option's text cannot forge a line.
        assert out.out == "" and "error:" in out.err, args
        assert "\x1b" not in out.err and "\nallowed" not in out.err, args
    # Control: the same command with a port gives the answer.
    assert _reach(db, "client/client-7c4b") == 0


# --- reach from Kubernetes facts that may not hold now ------------------------------------------

LATER = "2026-11-14T10:15:00Z"
# case -> (what happens after the course layout at 09:55, the time reach treats as now, and the
# start of the note, in the words `findings` uses)
NOT_CURRENT = {
    "failed": ("truncated", NOW, "source k8s.state: FAILED at 2026-11-14T10:10:00.000000Z: "),
    "stale": (None, "2026-11-14T11:00:00Z", "source k8s.state: STALE, last good run 2026-11-14T09:55:00.000000Z,"
                                            " older than its refresh period of 1 h."),
    "conflict": ("conflict", NOW, "k8s.state taken at 2026-11-14T09:55:00.000000Z: refused, another snapshot of"
                                  " k8s.state with that time has other content"),
}


def _ingest_course(db, path, at):
    return cli(["ingest", "--db", db, "--now", NOW, "--at", at, "--cluster", "course", "--k8s", str(path)])


@pytest.mark.parametrize("case", sorted(NOT_CURRENT))
def test_reach_from_a_failed_stale_or_conflicting_k8s_source_notes_it_and_exits_2(tmp_path, capsys, case):
    after, now, words = NOT_CURRENT[case]
    db = _course(tmp_path, capsys, "layout")
    if after == "truncated":
        (tmp_path / "truncated.json").write_text('{"items": [')
        assert _ingest_course(db, tmp_path / "truncated.json", "2026-11-14T10:10:00Z") == 2
    elif after == "conflict":
        assert _ingest_course(db, SHOP_NO_POLICY, SNAPSHOT_AT) == 3
    capsys.readouterr()
    # The model still holds the layout: client is allowed, outsider denied. Neither may stand.
    for src, old in (("client/client-7c4b", "allowed"), ("outsider/outsider-2f9a", "denied")):
        code = cli(["reach", "--db", db, "--now", now, "--from", src, "--to", "shop/shop-web-5d8f", "--port", "3000"])
        out = capsys.readouterr().out.splitlines()
        assert code == 2, (case, src)
        assert out[0].startswith(f"note: {words}"), (case, out)
        assert out[1].startswith("note: the answer below is the one the last good snapshot of k8s.state gives")
        assert out[2] == f"{old}: {src} -> shop/shop-web-5d8f on TCP 3000"
    # Control: a good snapshot taken later gives no note and each answer's own exit code. For a
    # conflict this also shows that one older than the snapshot the model holds is history.
    assert _ingest_course(db, LAYOUT, LATER) == 0
    capsys.readouterr()
    for src, code in (("client/client-7c4b", 0), ("outsider/outsider-2f9a", 1)):
        assert _reach(db, src) == code, (case, src)
        out = capsys.readouterr().out
        assert not out.startswith("note: ") and "k8s.state" not in out, (case, out)


def test_reach_is_not_marked_by_a_conflict_of_another_source(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    inventory = json.loads((FX / "ai/inventory.json").read_text())
    (tmp_path / "ai-1.json").write_text(json.dumps(inventory))
    inventory["agents"][0]["tools"].pop()
    (tmp_path / "ai-2.json").write_text(json.dumps(inventory))
    for name, code in (("ai-1.json", 0), ("ai-2.json", 3)):
        assert cli(["ingest", "--db", db, "--now", NOW, "--at", SNAPSHOT_AT, "--ai", str(tmp_path / name)]) == code
    capsys.readouterr()
    assert "ai.inventory taken at" in render.findings(Store(db), NOW)  # refused as a conflict
    for src, code in (("client/client-7c4b", 0), ("outsider/outsider-2f9a", 1)):
        assert _reach(db, src) == code, src
        assert not capsys.readouterr().out.startswith("note: "), src
    # Control: the same second snapshot of k8s.state is noted.
    assert _ingest_course(db, SHOP_NO_POLICY, SNAPSHOT_AT) == 3
    capsys.readouterr()
    assert _reach(db, "outsider/outsider-2f9a") == 2
    assert capsys.readouterr().out.startswith("note: k8s.state taken at ")


def test_reach_note_on_a_failed_source_cannot_forge_a_line(tmp_path, capsys):
    db = _course(tmp_path, capsys, "layout")
    bad = tmp_path / "bad\nallowed: client\x1b[2J\x9b\u200f.json"
    bad.write_text('{"items": [')
    assert _ingest_course(db, bad, "2026-11-14T10:10:00Z") == 2
    capsys.readouterr()
    assert _reach(db, "outsider/outsider-2f9a") == 2
    out = capsys.readouterr().out
    assert [line.split(":")[0] for line in out.splitlines()][:3] == ["note", "note", "denied"]
    assert not any(c in out for c in "\x1b\x9b\r\u200f") and "\nallowed" not in out
    # findings names the same failure on one line of its own.
    listed = render.findings(Store(db), NOW)
    assert not any(c in listed for c in "\x1b\x9b\r\u200f") and "\nallowed" not in listed
    assert len([line for line in listed.splitlines() if line.startswith("- source k8s.state: FAILED")]) == 1
    # Control: the same model after a good snapshot prints the answer alone.
    assert _ingest_course(db, LAYOUT, LATER) == 0
    capsys.readouterr()
    assert _reach(db, "outsider/outsider-2f9a") == 1
    assert capsys.readouterr().out.startswith("denied: ")


def test_reach_counts_a_snapshot_exactly_one_refresh_period_old_as_current(tmp_path, capsys):
    # One rule for the tie, as for stale facts: at exactly 1 h the snapshot is still current.
    db = _course(tmp_path, capsys, "layout")
    args = ["reach", "--db", db, "--from", "outsider/outsider-2f9a", "--to", "shop/shop-web-5d8f", "--port", "3000"]
    assert cli([*args, "--now", "2026-11-14T10:55:00Z"]) == 1
    assert capsys.readouterr().out.startswith("denied: ")
    # Control: one microsecond later it is stale.
    assert cli([*args, "--now", "2026-11-14T10:55:00.000001Z"]) == 2
    assert capsys.readouterr().out.startswith("note: source k8s.state: STALE, ")


def test_reach_notes_a_failed_source_when_the_old_answer_is_not_evaluated_too(tmp_path, capsys):
    unknown = allow("unknown", EVERY, {"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]},
                    ns="shop")
    db = _course(tmp_path, capsys, "unknown", unknown)
    # Control: before the failure the answer is not evaluated, with no note on the source.
    assert _reach(db, "outsider/outsider-2f9a") == 2
    assert capsys.readouterr().out.startswith("not evaluated: ")
    (tmp_path / "truncated.json").write_text('{"items": [')
    assert _ingest_course(db, tmp_path / "truncated.json", "2026-11-14T10:10:00Z") == 2
    capsys.readouterr()
    assert _reach(db, "outsider/outsider-2f9a") == 2
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("note: source k8s.state: FAILED at 2026-11-14T10:10:00.000000Z")
    assert out[2].startswith("not evaluated: outsider/outsider-2f9a -> ")


def test_reach_escapes_the_pod_names_it_prints(tmp_path, capsys):
    evil = "ev\x1b[2Jil\nallowed: x"
    data = json.loads(LAYOUT.read_text())
    pod = copy.deepcopy(k8s_item(data, "Pod", "outsider-2f9a"))
    pod["metadata"].update(name=evil, uid="00000000-0000-4000-8000-0000000000ee")
    db = _course(tmp_path, capsys, "evil", pod)
    assert _reach(db, f"outsider/{evil}") == 1
    out = capsys.readouterr().out
    assert out.startswith("denied: outsider/ev\\x1b[2Jil\\x0aallowed: x -> shop/shop-web-5d8f on TCP 3000\n")
    assert "\x1b" not in out and "\nallowed" not in out
    # Control: a plain name prints as it is.
    assert _reach(db, "outsider/outsider-2f9a") == 1
    assert capsys.readouterr().out.startswith("denied: outsider/outsider-2f9a -> shop/shop-web-5d8f on TCP 3000\n")


def test_findings_remove_characters_that_are_not_printable(tmp_path, capsys):
    # v1's safe() keeps C1 (U+0080 to U+009F; U+009B is CSI, as ESC [ is) and format
    # characters such as the right-to-left mark U+200F.
    name = "p\x9b31m\x9bq-\x85\u200f\u2060\ufeffx"
    hostile = allow(name, EVERY, {"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]}, ns="shop")
    db = _course(tmp_path, capsys, "c1", hostile)
    store = Store(db)
    for out in (render.findings(store, NOW), render.findings(store, NOW, history=[])):
        assert all(c.isprintable() or c == "\n" for c in out.replace("@\u200b", "@")), out
        # Control: the printable part of the name still shows, in the open path's note. NEL
        # (U+0085) is whitespace, so it folds into a space, as a newline does.
        assert "NetworkPolicy shop/p31mq\\- x" in out
