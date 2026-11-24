"""AWS state from three exports:

- `aws iam get-account-authorization-details` (roles, users and groups, their inline and
  attached policies, and the managed policies with their versions),
- `aws s3api list-buckets`,
- a JSON object mapping each bucket name to its `aws s3api get-bucket-tagging` output.
  An untagged bucket is recorded as {"TagSet": []}. A bucket whose tags could not be read
  is recorded as {"Error": {"Code": ..., "Message": ...}}: it stays in the model with
  unknown sensitivity and a tags_error, which rules report. A missing entry means the
  tags were not collected at all, and the collector refuses the snapshot.

Bucket sensitivity comes from the tag `data-classification`.

A user's permissions are its own policies plus those of its groups. Access keys are not in
this export, so the source line says they were not read. Any other part of the IAM export
the collector does not read is named there too, so it cannot read as "no findings".
"""

import json
from urllib.parse import unquote

from .. import policy
from ..schema import entity_id
from . import CollectorError, Delta, need, read_json

SOURCE = "aws.state"
SENSITIVE_VALUES = {"sensitive", "restricted", "confidential"}


def decode_document(doc):
    """Policy documents arrive as objects (CLI), URL-encoded JSON (raw API) or JSON text
    (CloudTrail). Returns None when the document cannot be read."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, str):
        return None
    for text in (doc, unquote(doc)):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def load(iam_path, buckets_path, tags_path):
    iam = read_json(iam_path, "aws iam")
    need(isinstance(iam, dict) and isinstance(iam.get("RoleDetailList"), list)
         and isinstance(iam.get("Policies"), list), "aws iam",
         "expected get-account-authorization-details output with RoleDetailList and Policies")
    for r in iam["RoleDetailList"]:
        need(isinstance(r, dict) and isinstance(r.get("RoleName"), str) and isinstance(r.get("Arn"), str)
             and isinstance(r.get("RolePolicyList"), list) and isinstance(r.get("AttachedManagedPolicies"), list),
             "aws iam", "a role entry lacks RoleName, Arn, RolePolicyList or AttachedManagedPolicies")
    for p in iam["Policies"]:
        need(isinstance(p, dict) and isinstance(p.get("Arn"), str) and isinstance(p.get("PolicyVersionList"), list),
             "aws iam", "a policy entry lacks Arn or PolicyVersionList")
    # AWS leaves out a user's or group's policy list when it is empty.
    for key, name_key, pol_key in (("UserDetailList", "UserName", "UserPolicyList"),
                                   ("GroupDetailList", "GroupName", "GroupPolicyList")):
        if key not in iam:
            continue
        need(isinstance(iam[key], list), "aws iam", f"{key} is not a list")
        for e in iam[key]:
            need(isinstance(e, dict) and isinstance(e.get(name_key), str) and isinstance(e.get("Arn"), str)
                 and isinstance(e.get(pol_key, []), list) and isinstance(e.get("AttachedManagedPolicies", []), list)
                 and isinstance(e.get("GroupList", []), list)
                 and all(isinstance(g, str) for g in e.get("GroupList", [])),
                 "aws iam", f"an entry of {key} lacks {name_key} or Arn, or a policy or group list is not a list")
    buckets = read_json(buckets_path, "aws s3")
    need(isinstance(buckets, dict) and isinstance(buckets.get("Buckets"), list), "aws s3",
         "expected list-buckets output with Buckets")
    names = []
    for b in buckets["Buckets"]:
        need(isinstance(b, dict) and isinstance(b.get("Name"), str), "aws s3", "a bucket entry lacks Name")
        names.append(b["Name"])
    tags = read_json(tags_path, "aws s3 tags")
    need(isinstance(tags, dict), "aws s3 tags", "expected an object of bucket name to get-bucket-tagging output")
    for name in names:
        entry = tags.get(name)
        ok = isinstance(entry, dict) and (isinstance(entry.get("TagSet"), list) or (
            isinstance(entry.get("Error"), dict) and isinstance(entry["Error"].get("Code"), str)))
        need(ok, "aws s3 tags", f"no tagging output for bucket {name!r}; tags were not collected")
    return {"iam": iam, "buckets": names, "tags": tags}


def _tags(tag_list):
    return {str(t.get("Key")): str(t.get("Value")) for t in tag_list or [] if isinstance(t, dict)}


def _inline(policy_list):
    return {str(p.get("PolicyName")): decode_document(p.get("PolicyDocument")) for p in policy_list or []}


def _attached(policy_list):
    return sorted(str(p.get("PolicyArn")) for p in policy_list or [])


DERIVED = ("admin_wildcard", "unknown_policy_documents", "not_evaluated")


def _groups(store, entries, at, delta, seen, principals):
    for g in entries:
        gid = entity_id("iam_group", g["Arn"])
        attrs = {"name": g["GroupName"], "arn": g["Arn"], "inline_policies": _inline(g.get("GroupPolicyList")),
                 "attached_policies": _attached(g.get("AttachedManagedPolicies"))}
        if store.upsert_entity(gid, "iam_group", attrs, {}, SOURCE, at):
            delta.entity(gid, "iam_group")
        seen.add(gid)


def _users(store, entries, at, delta, seen, principals):
    for u in entries:
        uid = entity_id("iam_user", u["Arn"])
        attrs = {"name": u["UserName"], "arn": u["Arn"], "inline_policies": _inline(u.get("UserPolicyList")),
                 "attached_policies": _attached(u.get("AttachedManagedPolicies")),
                 "groups": sorted(u.get("GroupList", [])),
                 "permissions_boundary": (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")}
        old = store.entity(uid)
        if old:
            attrs.update({k: old["attrs"][k] for k in DERIVED if k in old["attrs"]})
        if store.upsert_entity(uid, "iam_user", attrs, {"tags": _tags(u.get("Tags"))}, SOURCE, at):
            delta.entity(uid, "iam_user")
        seen.add(uid)
        principals.append(uid)


# Parts of the IAM export beyond roles and policies, each with the code that reads it.
SECTIONS = (("GroupDetailList", _groups), ("UserDetailList", _users))
LABELS = {"UserDetailList": "IAM users", "GroupDetailList": "IAM groups"}


def unread(iam, read):
    """What the IAM export holds, or lacks, that the model does not read, for the source line."""
    out = [f"{LABELS[k]} (not in the export)" for k in ("UserDetailList", "GroupDetailList") if k not in iam]
    out += [f"{len(v)} {LABELS.get(k, k)}" for k, v in sorted(iam.items())
            if k not in read and isinstance(v, list) and v]
    users = len(iam.get("UserDetailList") or []) if "UserDetailList" in read else 0
    if users:
        out.append(f"access keys of {users} IAM user{'' if users == 1 else 's'} (not in this export)")
    return out


def apply(store, data, at):
    delta, seen_entities = Delta(), set()
    for name in data["buckets"]:
        entry = data["tags"][name]
        bid = entity_id("s3_bucket", f"arn:aws:s3:::{name}")
        if "Error" in entry:
            # Not read is not untagged: sensitivity is unknown, and the error says why.
            err = entry["Error"]
            tags, attrs = {}, {"name": name, "sensitive": None,
                               "tags_error": f"{err['Code']}: {str(err.get('Message', ''))[:200]}"}
        else:
            tags = _tags(entry["TagSet"])
            sensitive = tags.get("data-classification", "").strip().lower() in SENSITIVE_VALUES
            attrs = {"name": name, "sensitive": sensitive, "tags_error": None}
        if store.upsert_entity(bid, "s3_bucket", attrs, {"tags": tags}, SOURCE, at):
            delta.entity(bid, "s3_bucket")
        seen_entities.add(bid)
    for p in data["iam"]["Policies"]:
        default = next((v for v in p["PolicyVersionList"] if v.get("IsDefaultVersion")), None)
        doc = decode_document(default.get("Document")) if default else None
        pid = entity_id("iam_policy", p["Arn"])
        if store.upsert_entity(pid, "iam_policy", {"name": p.get("PolicyName", ""), "arn": p["Arn"], "document": doc},
                               {}, SOURCE, at):
            delta.entity(pid, "iam_policy")
        seen_entities.add(pid)
    roles = []
    for r in data["iam"]["RoleDetailList"]:
        rid = entity_id("iam_role", r["Arn"])
        inline = {str(p.get("PolicyName")): decode_document(p.get("PolicyDocument")) for p in r["RolePolicyList"]}
        attrs = {
            "name": r["RoleName"], "arn": r["Arn"],
            "inline_policies": inline,
            "attached_policies": sorted(str(p.get("PolicyArn")) for p in r["AttachedManagedPolicies"]),
            "permissions_boundary": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
            "trust_subjects": policy.trust_subjects(decode_document(r.get("AssumeRolePolicyDocument"))),
        }
        old = store.entity(rid)
        # Changes from CloudTrail newer than this snapshot are not in it yet: re-apply them
        # on top, in time order. Older ones, and their tombstones, the snapshot supersedes.
        # A change at the snapshot's own time counts after it, as when the snapshot arrives
        # first (Pipeline._apply_change), so the result does not depend on arrival order.
        pending = {k: e for k, e in (old["attrs"].get("policy_changes") or {}).items()
                   if e["time"] >= at} if old else {}
        for key, e in sorted(pending.items(), key=lambda kv: (kv[1]["time"], kv[0])):
            attrs = apply_policy_change(attrs, key, e)
        attrs["policy_changes"] = pending
        attrs["change_markers"] = [m for m in (old["attrs"].get("change_markers") or [])
                                   if m["time"] >= at] if old else []
        # Keep the derived attrs from the last resolve so an unchanged role is not a change.
        if old:
            for k in DERIVED:
                if k in old["attrs"]:
                    attrs[k] = old["attrs"][k]
        # The attrs then describe the time of the newest change applied, as they would had
        # the snapshot arrived first and the record after it.
        observed = max([at] + [e["time"] for e in pending.values()])
        if store.upsert_entity(rid, "iam_role", attrs, {"tags": _tags(r.get("Tags"))}, SOURCE, at, observed):
            delta.entity(rid, "iam_role")
        seen_entities.add(rid)
        roles.append((rid, observed, "aws.cloudtrail" if pending else SOURCE))
    read, users = {"RoleDetailList", "Policies"}, []
    for key, section in SECTIONS:
        if key in data["iam"]:
            section(store, data["iam"][key], at, delta, seen_entities, users)
            read.add(key)
    store.set_setting(f"unread:{SOURCE}", json.dumps(unread(data["iam"], read)))
    gone_entities, gone_edges = store.sweep(SOURCE, seen_entities, keep_edges(store), at)
    for eid, etype in gone_entities:
        delta.entity(eid, etype)
    for _, etype in gone_edges:
        delta.edge(etype)
    for rid, observed, source in roles:
        delta.merge(recompute_role(store, rid, observed, source))
    for uid in users:
        delta.merge(recompute_role(store, uid, at, SOURCE))
    return delta


def keep_edges(store):
    # has_permission edges are recomputed per role below, not swept by source.
    return {e["id"] for e in store.edges(etype="has_permission")}


def recompute_role(store, rid, at, source):
    """Rebuild one role's or user's has_permission edges from the policies the model holds.
    A user's groups add their policies; a group the model does not hold is an unknown
    document, so the user's permissions are marked not fully known."""
    delta = Delta()
    role = store.entity(rid)
    if role is None:
        return delta
    a = role["attrs"]
    pols = [(f"inline:{name}", doc) for name, doc in sorted(a.get("inline_policies", {}).items())]
    for arn in a.get("attached_policies", []):
        p = store.entity(entity_id("iam_policy", arn))
        pols.append((arn, p["attrs"].get("document") if p else None))
    for name in a.get("groups") or []:
        g = store.find_by_name("iam_group", name)
        if g is None:
            pols.append((f"group:{name}", None))
            continue
        pols += [(f"group:{name}:inline:{n}", d) for n, d in sorted((g["attrs"].get("inline_policies") or {}).items())]
        for arn in g["attrs"].get("attached_policies") or []:
            p = store.entity(entity_id("iam_policy", arn))
            pols.append((f"group:{name}:{arn}", p["attrs"].get("document") if p else None))
    buckets = {b["attrs"]["name"]: b["id"] for b in store.entities("s3_bucket")}
    grants, markers, admin, unknown = policy.resolve(pols, sorted(buckets), bool(a.get("permissions_boundary")))
    keep = set()
    for name, g in grants.items():
        xid, changed = store.upsert_edge("has_permission", rid, buckets[name], g, source, at)
        keep.add(xid)
        if changed:
            delta.edge("has_permission")
    for e in store.edges(rid, "has_permission"):
        if e["id"] not in keep and store.delete_edge(e["id"], at):
            delta.edge("has_permission")
    markers = sorted(set(markers) | {m["text"] for m in a.get("change_markers") or []})
    derived = {"admin_wildcard": admin, "unknown_policy_documents": unknown, "not_evaluated": markers}
    if any(a.get(k) != v for k, v in derived.items()):
        store.set_attrs(rid, {**a, **derived})
        delta.entity(rid, role["type"])
    return delta


CHANGE_OPS = {"PutRolePolicy": "put", "DeleteRolePolicy": "delete", "AttachRolePolicy": "attach",
              "DetachRolePolicy": "detach"}


def change_key(change):
    """The policy a CloudTrail change is about: inline policies by name, managed by ARN."""
    if change["op"] in ("PutRolePolicy", "DeleteRolePolicy"):
        return f"inline:{change['policy_name']}" if change.get("policy_name") else None
    return change.get("policy_arn") or None


def apply_policy_change(attrs, key, entry):
    """One policy change applied to a copy of the role's attrs. A delete or detach of a
    policy the role does not hold changes nothing here, but its entry stays as a
    tombstone, so an older put that arrives later is not applied."""
    inline = dict(attrs.get("inline_policies") or {})
    attached = set(attrs.get("attached_policies") or [])
    if entry["op"] == "put":
        inline[key[len("inline:"):]] = entry["doc"]
    elif entry["op"] == "delete":
        inline.pop(key[len("inline:"):], None)
    elif entry["op"] == "attach":
        attached.add(key)
    elif entry["op"] == "detach":
        attached.discard(key)
    return {**attrs, "inline_policies": inline, "attached_policies": sorted(attached)}


def role_id_from_arn(arn):
    """An assumed-role session ARN or a role ARN, as the role's entity ID."""
    if not isinstance(arn, str):
        return None
    if ":assumed-role/" in arn:
        # arn:aws:sts::ACCOUNT:assumed-role/NAME/SESSION -> arn:aws:iam::ACCOUNT:role/NAME
        head, _, rest = arn.partition(":assumed-role/")
        account = head.rsplit(":", 1)[-1]
        name = rest.split("/", 1)[0]
        return entity_id("iam_role", f"arn:aws:iam::{account}:role/{name}")
    if ":role/" in arn and arn.startswith("arn:aws:iam::"):
        return entity_id("iam_role", arn)
    return None


__all__ = ["CollectorError", "load", "apply", "recompute_role", "decode_document", "role_id_from_arn",
           "change_key", "apply_policy_change"]
