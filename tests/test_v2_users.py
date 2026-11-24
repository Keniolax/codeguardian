"""IAM users and groups: their permissions, posture findings, and a source line that names
what the model does not read. Users and groups are written by hand in the shape of
get-account-authorization-details, which leaves out a policy list when it is empty."""

import json
import os
import stat

import pytest

from codeguardian.v2 import render
from codeguardian.v2.collectors import CollectorError
from codeguardian.v2.schema import EDGE_MEANINGS
from codeguardian.v2.store import Store
from v2_helpers import ACCT, FINANCE, FX, KB, NOW, build

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_KB = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-agent-kb/*"}]}
READ_FINANCE = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-finance-records/*"}]}
BOUNDARY = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": f"arn:aws:iam::{ACCT}:policy/boundary"}


def user(name, groups=(), attached=(), inline=None, **extra):
    u = {"Path": "/", "UserName": name, "UserId": f"EXAMPLE-USER-{name.upper()}",
         "Arn": f"arn:aws:iam::{ACCT}:user/{name}", "CreateDate": "2026-09-01T12:00:00+00:00",
         "GroupList": list(groups), "Tags": [],
         "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in attached]}
    if inline:  # AWS sends UserPolicyList only when the user has an inline policy
        u["UserPolicyList"] = [{"PolicyName": n, "PolicyDocument": d} for n, d in inline.items()]
    u.update(extra)
    return u


def group(name, attached=(), inline=None):
    g = {"Path": "/", "GroupName": name, "GroupId": f"EXAMPLE-GROUP-{name.upper()}",
         "Arn": f"arn:aws:iam::{ACCT}:group/{name}", "CreateDate": "2026-09-01T12:00:00+00:00",
         "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in attached]}
    if inline:
        g["GroupPolicyList"] = [{"PolicyName": n, "PolicyDocument": d} for n, d in inline.items()]
    return g


def with_iam(users=(), groups=(), edit=None):
    def apply(data):
        data["UserDetailList"], data["GroupDetailList"] = list(users), list(groups)
        if edit:
            edit(data)
    return apply


def uid(name):
    return f"aws:iam_user:arn:aws:iam::{ACCT}:user/{name}"


def flagged(store, rule_id):
    return sorted(f["primary_entity"] for f in store.findings(status="open", rule_id=rule_id))


def grants(store, name):
    return sorted(e["dst"] for e in store.edges(uid(name), "has_permission"))


def aws_line(store):
    return next(line for line in render.sources(store, NOW) if line.startswith("- source aws.state"))


def test_user_with_administrator_access_opens_a_finding_and_a_scoped_user_does_not(tmp_path):
    store, _ = build(tmp_path, edit_iam=with_iam(users=[
        user("ops-admin", attached=[ADMIN]), user("kb-reader", inline={"read-kb": READ_KB})]))
    assert flagged(store, "POST-IAM-004") == [uid("ops-admin")]
    # A user's own grant on a bucket gives a has_permission edge, and only to that bucket.
    assert grants(store, "kb-reader") == [KB]
    assert FINANCE in grants(store, "ops-admin")
    # ask's language names this edge's ends as the collector writes them.
    assert ("iam_user", "s3_bucket") in EDGE_MEANINGS["has_permission"][1]


def test_group_policies_reach_their_members_and_no_one_else(tmp_path):
    store, _ = build(tmp_path, edit_iam=with_iam(
        users=[user("alice", groups=["admins"]), user("carol", groups=["finance-readers"]), user("bob")],
        groups=[group("admins", attached=[ADMIN]), group("finance-readers", inline={"read": READ_FINANCE})]))
    assert flagged(store, "POST-IAM-004") == [uid("alice")]
    assert grants(store, "carol") == [FINANCE]
    assert grants(store, "bob") == []


def test_user_in_a_group_the_model_does_not_hold_has_permissions_not_fully_known(tmp_path):
    store, _ = build(tmp_path, edit_iam=with_iam(
        users=[user("dave", groups=["ghost"]), user("erin", groups=["readers"])],
        groups=[group("readers", inline={"read": READ_KB})]))
    assert flagged(store, "POST-IAM-005") == [uid("dave")]
    assert grants(store, "erin") == [KB]


def test_user_with_a_permissions_boundary_is_marked_not_evaluated(tmp_path):
    store, _ = build(tmp_path, edit_iam=with_iam(users=[
        user("frank", inline={"read-kb": READ_KB}, PermissionsBoundary=BOUNDARY),
        user("kb-reader", inline={"read-kb": READ_KB})]))
    assert flagged(store, "POST-IAM-006") == [uid("frank")]


def test_user_entry_without_policy_lists_is_read_as_aws_sends_it(tmp_path):
    bare = user("ops-admin", attached=[ADMIN])
    assert "UserPolicyList" not in bare
    store, _ = build(tmp_path, edit_iam=with_iam(users=[bare]))
    assert store.entity(uid("ops-admin"))["attrs"]["inline_policies"] == {}
    # Control: a policy list that is there but is not a list refuses the snapshot.
    with pytest.raises(CollectorError):
        build(tmp_path, edit_iam=with_iam(users=[user("ops-admin", UserPolicyList="not a list")]))


@pytest.mark.parametrize("edit,note", [
    (with_iam(users=[user("ops-admin", attached=[ADMIN]), user("kb-reader")]),
     "; not evaluated: access keys of 2 IAM users \\(not in this export\\)."),
    (lambda d: d.pop("UserDetailList"), "; not evaluated: IAM users \\(not in the export\\)."),
    (with_iam(edit=lambda d: d.update(InstanceProfileList=[{"InstanceProfileName": "x"}])),
     "; not evaluated: 1 InstanceProfileList."),
    (with_iam(), None),
], ids=["access-keys", "no-user-list", "other-list", "nothing-unread"])
def test_source_line_names_what_the_model_does_not_read(tmp_path, edit, note):
    store, _ = build(tmp_path, edit_iam=edit)
    line = aws_line(store)
    assert line.startswith("- source aws.state: ok, last good run ")
    if note is None:
        assert "not evaluated" not in line
    else:
        assert line.endswith(note), line


def test_user_gone_from_the_next_snapshot_is_deleted_and_its_finding_resolves(tmp_path):
    later = "2026-11-14T10:20:00Z"

    def snapshot(store, pipe, users):
        data = json.loads((FX / "aws" / "iam-wide.json").read_text())
        with_iam(users=users)(data)
        path = tmp_path / "later-iam.json"
        path.write_text(json.dumps(data))
        pipe.clock.set(later)
        pipe.snapshot(aws=(path, FX / "aws" / "s3-buckets.json", FX / "aws" / "s3-tags.json"), at=later)

    admin = user("ops-admin", attached=[ADMIN])
    store, pipe = build(tmp_path, edit_iam=with_iam(users=[admin]))
    snapshot(store, pipe, [])
    assert store.entity(uid("ops-admin")) is None and flagged(store, "POST-IAM-004") == []
    assert [f["status"] for f in store.findings(rule_id="POST-IAM-004")] == ["resolved"]
    # Control: the same user in the next snapshot keeps the finding open.
    store, pipe = build(tmp_path, edit_iam=with_iam(users=[admin]))
    snapshot(store, pipe, [admin])
    assert flagged(store, "POST-IAM-004") == [uid("ops-admin")]


def test_user_arn_from_the_export_cannot_forge_a_finding_line(tmp_path):
    evil = user("evil", attached=[ADMIN], Arn=f"arn:aws:iam::{ACCT}:user/evil\n- [open] critical FORGED-001 v1: x")
    store, _ = build(tmp_path, edit_iam=with_iam(users=[evil]))
    text = render.findings(store, NOW)
    assert "POST-IAM-004" in text
    assert not any(line.startswith("- [open] critical FORGED") for line in text.splitlines())


def test_model_database_file_is_readable_by_its_owner_only(tmp_path, monkeypatch):
    new = tmp_path / "new.db"
    store = Store(str(new))
    store.set_setting("probe", "1")
    store.commit()
    for path in (new, tmp_path / "new.db-wal", tmp_path / "new.db-shm"):
        if path.exists():
            assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0, path
    assert stat.S_IMODE(os.stat(new).st_mode) == 0o600
    store.close()
    # A model file left readable by an older version is tightened when it is opened.
    old = tmp_path / "old.db"
    old.write_bytes(b"")
    os.chmod(old, 0o644)
    Store(str(old)).close()
    assert stat.S_IMODE(os.stat(old).st_mode) == 0o600
    # Control: a model in memory makes no file.
    monkeypatch.chdir(tmp_path)
    Store(":memory:").close()
    assert all(p.name.startswith(("new.db", "old.db")) for p in tmp_path.iterdir())
