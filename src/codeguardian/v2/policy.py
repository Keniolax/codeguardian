"""A small IAM policy resolver that turns a role's identity policies into has_permission
edges to the S3 buckets the model knows.

What it handles: Allow statements; Action and Resource given as a string or a list; the
"*" and "?" wildcards (actions match without case, resources with case); S3 bucket and
object ARNs.

What it does not handle, and how each shows up instead of a silent allow or deny:
- Condition blocks: the grant is kept, and the edge says "Condition ... not evaluated".
- Deny statements: nothing is subtracted; every edge of the role says a Deny was not
  evaluated.
- NotAction, NotResource: the statement is skipped and the role carries a marker.
- Permissions boundaries: the role carries a marker, and so does every edge.
- A policy whose document the model does not hold: the role lists it as unknown.
- Never visible in this data at all: SCPs and RCPs, session policies, bucket policies and
  ACLs, and access points. Output that lists permissions says so.
"""

import re
from functools import lru_cache

S3_PREFIX = "arn:aws:s3:::"
NOT_IN_DATA = "SCPs, session policies and bucket policies are not in the data and were not evaluated"


@lru_cache(maxsize=4096)
def _glob(pattern, ignore_case):
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(rx, re.IGNORECASE if ignore_case else 0)


def action_matches(pattern, action):
    return _glob(pattern, True).fullmatch(action) is not None


def _list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _bucket_scope(resource, bucket):
    """Does a Resource pattern reach this bucket, and at what level?"""
    if resource == "*":
        return "bucket-and-objects"
    if not resource.startswith(S3_PREFIX):
        if _glob(resource, False).fullmatch(S3_PREFIX + bucket):
            return "bucket"
        return None
    rest = resource[len(S3_PREFIX):]
    # Bucket names cannot hold "/", so the part before the first "/" names the bucket.
    name, slash, key = rest.partition("/")
    if not _glob(name, False).fullmatch(bucket):
        return None
    if not slash:
        return "bucket"
    return "objects" if key == "*" else "objects-prefix"


def _could_be_s3(action):
    return action == "*" or action.lower().startswith("s3:") or action_matches(action, "s3:GetObject")


def statements(doc):
    st = doc.get("Statement", [])
    return [st] if isinstance(st, dict) else list(st)


def resolve(policies, buckets, has_boundary=False):
    """policies: list of (ref, document or None). buckets: bucket names.

    Returns (grants, role_markers, admin_wildcard, unknown). grants maps bucket name to
    {"actions", "resources", "policies", "scopes", "not_evaluated"} (sorted lists).
    """
    grants, markers, unknown, admin = {}, set(), [], False
    deny_refs = []
    if has_boundary:
        markers.add("permissions boundary not evaluated")
    for ref, doc in policies:
        if doc is None:
            unknown.append(ref)
            continue
        for n, st in enumerate(statements(doc)):
            where = f"{ref} statement {n}"
            if st.get("Effect") == "Deny":
                deny_refs.append(where)
                continue
            if st.get("Effect") != "Allow":
                markers.add(f"{where}: Effect {st.get('Effect')!r} not understood")
                continue
            if "NotAction" in st or "NotResource" in st:
                markers.add(f"{where}: NotAction/NotResource not evaluated")
                continue
            actions, resources = _list(st.get("Action")), _list(st.get("Resource"))
            conditional = "Condition" in st
            if "*" in actions and "*" in resources and not conditional:
                admin = True
            s3_actions = [a for a in actions if _could_be_s3(a)]
            if not s3_actions:
                continue
            for bucket in buckets:
                for res in resources:
                    scope = _bucket_scope(res, bucket)
                    if scope is None:
                        continue
                    g = grants.setdefault(bucket, {"actions": set(), "resources": set(), "policies": set(),
                                                   "scopes": set(), "not_evaluated": set()})
                    g["actions"].update(s3_actions)
                    g["resources"].add(res)
                    g["policies"].add(ref)
                    g["scopes"].add(scope)
                    if conditional:
                        g["not_evaluated"].add(f"Condition in {where} not evaluated")
    if deny_refs:
        markers.add("Deny statements not subtracted: " + ", ".join(deny_refs))
    for g in grants.values():
        if deny_refs:
            g["not_evaluated"].add("a Deny statement on the role was not evaluated")
        if has_boundary:
            g["not_evaluated"].add("permissions boundary not evaluated")
    out = {b: {k: sorted(v) for k, v in g.items()} for b, g in grants.items()}
    return out, sorted(markers), admin, sorted(unknown)


def trust_subjects(trust_doc):
    """Kubernetes service accounts a role's trust policy lets assume it through IRSA.

    Only Allow statements for sts:AssumeRoleWithWebIdentity with a Federated principal and
    a StringEquals or StringLike condition on an issuer's ":sub" key count. Anything else
    in the trust policy is not evaluated here.
    """
    subjects = []
    for st in statements(trust_doc or {}):
        if st.get("Effect") != "Allow":
            continue
        if not any(action_matches(a, "sts:AssumeRoleWithWebIdentity") for a in _list(st.get("Action"))):
            continue
        if not isinstance(st.get("Principal"), dict) or "Federated" not in st["Principal"]:
            continue
        for op in ("StringEquals", "StringLike"):
            for key, value in (st.get("Condition", {}).get(op) or {}).items():
                if key.endswith(":sub"):
                    subjects += [f"{op}:{v}" for v in _list(value)]
    return sorted(set(subjects))


def trusts_service_account(subjects, namespace, name):
    sub = f"system:serviceaccount:{namespace}:{name}"
    for s in subjects:
        op, _, value = s.partition(":")
        if op == "StringEquals" and value == sub:
            return True
        if op == "StringLike" and _glob(value, False).fullmatch(sub):
            return True
    return False
