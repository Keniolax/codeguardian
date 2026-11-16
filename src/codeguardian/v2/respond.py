"""Response is a fixed catalog. A plan is a list of catalog action IDs with typed
parameters, and each action renders the exact command or manifest for a person to review.

Nothing here runs anything: stage 1 has no code path that executes an action. Parameter
values come from the model of the environment, which an attacker can influence (a pod
name, a policy name), so every value must match a strict pattern before it is rendered,
and commands are shell-quoted as well.
"""

import re
import shlex

from .correlate import members

ROLE_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
POLICY_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
POLICY_ARN = re.compile(r"^arn:aws:iam::(aws|[0-9]{12}):policy/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,128}$")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
DNS_SUBDOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")

QUARANTINE_LABEL = "codeguardian.io/quarantine"

CATALOG = {
    "aws.iam.delete_role_policy": {
        "summary": "Delete an inline policy from an IAM role",
        "params": {"role_name": ROLE_NAME, "policy_name": POLICY_NAME},
    },
    "aws.iam.detach_role_policy": {
        "summary": "Detach a managed policy from an IAM role",
        "params": {"role_name": ROLE_NAME, "policy_arn": POLICY_ARN},
    },
    "k8s.isolate_pod": {
        "summary": "Cut all network traffic to and from one pod with a NetworkPolicy",
        "params": {"namespace": DNS_LABEL, "pod": DNS_SUBDOMAIN},
    },
}


class ActionError(ValueError):
    pass


def check_action(action_id, params):
    """Returns the action if its ID is in the catalog and every parameter is typed right."""
    spec = CATALOG.get(action_id)
    if spec is None:
        raise ActionError(f"action {action_id!r} is not in the catalog")
    if not isinstance(params, dict) or set(params) != set(spec["params"]):
        raise ActionError(f"{action_id}: parameters must be exactly {sorted(spec['params'])}")
    for name, pattern in spec["params"].items():
        if not isinstance(params[name], str) or not pattern.fullmatch(params[name]):
            raise ActionError(f"{action_id}: parameter {name} does not match its pattern")
    return {"action_id": action_id, "params": dict(params)}


def render(action):
    """The exact text a person would review and run themselves."""
    a = check_action(action["action_id"], action["params"])
    p = {k: shlex.quote(v) for k, v in a["params"].items()}
    if a["action_id"] == "aws.iam.delete_role_policy":
        return {"commands": [f"aws iam delete-role-policy --role-name {p['role_name']} --policy-name {p['policy_name']}"],
                "manifest": None,
                "note": "Save the policy first: aws iam get-role-policy with the same names."}
    if a["action_id"] == "aws.iam.detach_role_policy":
        return {"commands": [f"aws iam detach-role-policy --role-name {p['role_name']} --policy-arn {p['policy_arn']}"],
                "manifest": None, "note": "The policy itself is kept and can be attached again."}
    ns, pod = a["params"]["namespace"], a["params"]["pod"]
    manifest = (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: codeguardian-quarantine\n"
        f"  namespace: {ns}\n"
        "spec:\n"
        "  podSelector:\n"
        "    matchLabels:\n"
        f"      {QUARANTINE_LABEL}: \"true\"\n"
        "  policyTypes:\n"
        "  - Ingress\n"
        "  - Egress\n"
    )
    # Selecting by a label this plan sets, not by the pod's own labels, keeps text from
    # the environment out of the manifest.
    return {"commands": [f"kubectl label pod --namespace {p['namespace']} {p['pod']} {QUARANTINE_LABEL}=true --overwrite",
                         f"kubectl apply --namespace {p['namespace']} -f codeguardian-quarantine.yaml"],
            "manifest": manifest,
            "note": "Works only if the cluster's network plugin enforces NetworkPolicy. It denies all traffic,"
                    " including DNS, for the labelled pod in this namespace."}


def _grant_actions(store, role_id, bucket_id, reason):
    """Actions that remove each policy granting this role access to this bucket."""
    role = store.entity(role_id)
    if role is None:
        return []
    out = []
    for e in store.edges(role_id, "has_permission"):
        if e["dst"] != bucket_id:
            continue
        for ref in e["attrs"].get("policies", []):
            if ref.startswith("inline:"):
                out.append(("aws.iam.delete_role_policy", {"role_name": role["attrs"]["name"],
                                                           "policy_name": ref[len("inline:"):]}, reason))
            else:
                out.append(("aws.iam.detach_role_policy", {"role_name": role["attrs"]["name"], "policy_arn": ref},
                            reason))
    return out


def plan(store, incident):
    """A deterministic plan for an incident: remove the grants on open paths and on reads
    the agent had no declared reason for; isolate pods that had runtime or exec alerts."""
    wanted = []
    for f in members(store, incident):
        if f["status"] != "open":
            continue
        if f["kind"] == "path":
            nodes = f["path"]
            for a, b in zip(nodes, nodes[1:]):
                if a.startswith("aws:iam_role:") and b.startswith("aws:s3_bucket:"):
                    wanted += _grant_actions(store, a, b, f["finding_id"])
        elif f["rule_id"] == "DET-AI-001":
            for b in f["path"]:
                wanted += _grant_actions(store, f["primary_entity"], b, f["finding_id"])
        if f["kind"] == "detection" and f["rule_id"].startswith(("DET-RT-", "DET-K8S-")):
            pod_ids = sorted({e for e in [f["primary_entity"], *f["path"]] if e.startswith("k8s:pod:")})
            for pid in pod_ids:
                pod = store.entity(pid)
                if pod:
                    wanted.append(("k8s.isolate_pod", {"namespace": pod["attrs"]["namespace"],
                                                       "pod": pod["attrs"]["name"]}, f["finding_id"]))
    steps, seen, refused = [], {}, []
    for action_id, params, reason in wanted:
        key = (action_id, tuple(sorted(params.items())))
        if key in seen:
            if reason not in seen[key]["because"]:
                seen[key]["because"].append(reason)
            continue
        try:
            step = check_action(action_id, params)
        except ActionError as exc:
            refused.append({"action_id": action_id, "reason": str(exc), "because": reason})
            continue
        step["because"] = [reason]
        seen[key] = step
        steps.append(step)
    return {"incident_id": incident["incident_id"], "steps": steps, "refused": refused}


def incident_scope(store, incident):
    """What a model-proposed action may name: the roles, their policies and the pods in
    this incident. Anything else is dropped even if it is well typed."""
    roles, pods = {}, set()
    for f in members(store, incident):
        for eid in f["entities"]:
            ent = store.entity(eid)
            if ent and ent["type"] == "iam_role":
                roles[ent["attrs"]["name"]] = ent["attrs"]
            elif ent and ent["type"] == "pod":
                pods.add((ent["attrs"]["namespace"], ent["attrs"]["name"]))
    return roles, pods


def check_model_action(entry, scope):
    roles, pods = scope
    if not isinstance(entry, dict):
        raise ActionError("action entry is not an object")
    params = {}
    for p in entry.get("params") or []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or p["name"] in params:
            raise ActionError("params must be unique name/value pairs")
        params[p["name"]] = p.get("value")
    a = check_action(entry.get("action_id"), params)
    pr = a["params"]
    if a["action_id"] == "k8s.isolate_pod":
        if (pr["namespace"], pr["pod"]) not in pods:
            raise ActionError("k8s.isolate_pod names a pod outside this incident")
    else:
        role = roles.get(pr["role_name"])
        if role is None:
            raise ActionError(f"{a['action_id']} names a role outside this incident")
        if a["action_id"] == "aws.iam.delete_role_policy" and pr["policy_name"] not in role.get("inline_policies", {}):
            raise ActionError("delete_role_policy names an inline policy the role does not have")
        if a["action_id"] == "aws.iam.detach_role_policy" and pr["policy_arn"] not in role.get("attached_policies", []):
            raise ActionError("detach_role_policy names a policy the role does not have attached")
    return a
