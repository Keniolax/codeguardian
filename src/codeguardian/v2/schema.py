"""The fixed data contracts: entity and edge types, sources, IDs and time.

Every ID is derived from data, never from a counter, so two collectors that see the same
thing write the same ID and a replay gives the same IDs.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

DOMAINS = ("cloud", "kubernetes", "identity", "ai", "saas", "code")

# type -> (provider prefix of the ID, domain, typed attrs the rules may name)
ENTITY_TYPES = {
    "internet": ("net", "cloud", ()),
    "s3_bucket": ("aws", "cloud", ("name", "sensitive", "tags_error")),
    "iam_role": ("aws", "identity", ("name", "arn", "inline_policies", "attached_policies",
                                     "admin_wildcard", "unknown_policy_documents", "not_evaluated",
                                     "trust_subjects", "permissions_boundary", "policy_changes", "change_markers")),
    "iam_policy": ("aws", "identity", ("name", "arn", "document")),
    "iam_user": ("aws", "identity", ("name", "arn", "inline_policies", "attached_policies", "groups",
                                     "admin_wildcard", "unknown_policy_documents", "not_evaluated",
                                     "permissions_boundary")),
    "iam_group": ("aws", "identity", ("name", "arn", "inline_policies", "attached_policies")),
    "service": ("k8s", "kubernetes", ("name", "namespace", "service_type", "selector", "internet_facing", "ports")),
    "pod": ("k8s", "kubernetes", ("name", "namespace", "service_account", "privileged", "node", "pod_labels",
                                  "container_ports", "host_network")),
    "network_policy": ("k8s", "kubernetes", ("name", "namespace", "pod_selector", "policy_types", "ingress",
                                             "egress_rules")),
    "namespace": ("k8s", "kubernetes", ("name", "namespace_labels")),
    "service_account": ("k8s", "identity", ("name", "namespace", "irsa_role_arn", "irsa_status")),
    "agent": ("ai", "ai", ("name",)),
    "model_endpoint": ("ai", "ai", ("endpoint",)),
    "tool": ("ai", "ai", ("name", "agent")),
    # GitHub (slice 3). A repository's checks and Actions settings are None when the export
    # could not read them; not_evaluated says which parts and why.
    "github_account": ("github", "saas", ("name", "account_type", "repositories_listed")),
    "repository": ("github", "saas", ("name", "default_branch", "private", "archived", "ruleset_checks",
                                      "protection_checks", "default_branch_checks", "default_workflow_permissions",
                                      "actions_can_approve_pull_requests", "not_evaluated")),
    "ruleset": ("github", "saas", ("name", "ruleset_id", "source", "source_type", "target", "enforcement")),
    "workflow": ("github", "saas", ("name", "path", "state", "repository")),
    "deploy_key": ("github", "saas", ("name", "key_id", "read_only", "repository")),
    "actions_secret": ("github", "saas", ("name", "repository")),
}

EDGE_TYPES = ("contains", "runs_as", "assumes", "has_permission", "exposes", "reachable_from",
              "uses_model", "can_call", "holds", "reads", "deploys_to", "protects")

# edge type -> (what it means, the (source type, target type) pairs the collectors write
# it between, or None when no collector writes it yet). ask sends this to the model, so a
# query can name the edge that answers the question, not one whose name only sounds right.
EDGE_MEANINGS = {
    "contains": ("a pod runs an AI agent, from the AI inventory; a GitHub account owns a repository, or a"
                 " repository holds a workflow file, from the GitHub export",
                 (("pod", "agent"), ("github_account", "repository"), ("repository", "workflow"))),
    "runs_as": ("a pod runs as a Kubernetes service account", (("pod", "service_account"),)),
    "assumes": ("a service account can take an IAM role through IRSA", (("service_account", "iam_role"),)),
    "has_permission": ("the IAM policies of a role, or of a user and its groups, allow S3 actions on the"
                       " bucket, such as reading its objects; bucket policies and SCPs are not evaluated",
                       (("iam_role", "s3_bucket"), ("iam_user", "s3_bucket"))),
    "exposes": ("a Kubernetes Service sends traffic to a pod", (("service", "pod"),)),
    "reachable_from": ("a Service can be reached from the internet", (("service", "internet"),)),
    "uses_model": ("an AI agent calls a model endpoint", (("agent", "model_endpoint"),)),
    "can_call": ("an AI agent can call a tool", (("agent", "tool"),)),
    "reads": ("a bucket that an AI tool declares as its data source in the AI inventory; not an"
              " IAM permission and not a read seen in logs", (("tool", "s3_bucket"),)),
    "holds": ("a GitHub repository holds an Actions secret (its name only, never a value) or a deploy key",
              (("repository", "actions_secret"), ("repository", "deploy_key"))),
    "deploys_to": ("no collector writes this edge yet", None),
    "protects": ("a GitHub ruleset is configured for a repository, at the repository or the organisation level;"
                 " whether its rules require a status check on the default branch is on the repository",
                 (("ruleset", "repository"),)),
}

# edge type -> typed attrs a path rule may name in edge_where. exposes carries the
# NetworkPolicy answer for a connection from outside the cluster (see netpol.py).
EDGE_ATTRS = {
    "exposes": ("ingress_from_outside",),
}

# edge type -> the collectors whose snapshots write it. A detection that walks an edge
# whose collector has never run cannot tell "no such edge" from "not looked at yet".
EDGE_SOURCES = {
    "contains": ("ai.inventory", "github.state"),
    "uses_model": ("ai.inventory",),
    "can_call": ("ai.inventory",),
    "reads": ("ai.inventory",),
    "runs_as": ("k8s.state",),
    "exposes": ("k8s.state",),
    "reachable_from": ("k8s.state",),
    "assumes": ("aws.state", "k8s.state"),
    "has_permission": ("aws.state",),
    "holds": ("github.state",),
    "protects": ("github.state",),
}

# (edge type, source type, target type) -> the collectors that write the edge between those
# types, for an edge that more than one collector writes. A walk from a pod to its agent
# rests on the AI inventory, not on the GitHub export, though both write contains edges.
PAIR_SOURCES = {
    ("contains", "pod", "agent"): ("ai.inventory",),
    ("contains", "github_account", "repository"): ("github.state",),
    ("contains", "repository", "workflow"): ("github.state",),
}


def edge_sources(etype, pairs=None):
    """The collectors that write an edge type. Given the (source type, target type) pairs a
    walk can take, only those that write it between such types; no pair, no collector."""
    if pairs is None:
        return tuple(EDGE_SOURCES.get(etype, ()))
    names = []
    for src, dst in pairs:
        for name in PAIR_SOURCES.get((etype, src, dst), EDGE_SOURCES.get(etype, ())):
            if name not in names:
                names.append(name)
    return tuple(names)

# entity type -> the collectors whose snapshots write it. The internet node is built in, so
# it rests on none. ask names a source its answer rests on that is not current.
TYPE_SOURCES = {
    "internet": (),
    "s3_bucket": ("aws.state",),
    "iam_role": ("aws.state",),
    "iam_policy": ("aws.state",),
    "iam_user": ("aws.state",),
    "iam_group": ("aws.state",),
    "service": ("k8s.state",),
    "pod": ("k8s.state",),
    "network_policy": ("k8s.state",),
    "namespace": ("k8s.state",),
    "service_account": ("k8s.state",),
    "agent": ("ai.inventory",),
    "model_endpoint": ("ai.inventory",),
    "tool": ("ai.inventory",),
    "github_account": ("github.state",),
    "repository": ("github.state",),
    "ruleset": ("github.state",),
    "workflow": ("github.state",),
    "deploy_key": ("github.state",),
    "actions_secret": ("github.state",),
}

# (entity type, attr) -> the other collectors whose facts the pipeline computes the attr
# from. irsa_status says whether the IAM role a service account names exists and trusts
# it, so a filter on it rests on the AWS collector as well as on the k8s one.
ATTR_SOURCES = {
    ("service_account", "irsa_status"): ("aws.state",),
}

EVENT_SOURCES = {
    "aws.cloudtrail": "cloud",
    "k8s.audit": "kubernetes",
    "k8s.runtime": "kubernetes",
    "github.audit": "saas",
    "ai.agent_trace": "ai",
    "code.gate": "code",
}

# How long a fact stays fresh without its collector confirming it again. A fact written
# by an event is confirmed by the next AWS snapshot, so it shares the snapshot's period.
# "builtin" (the internet node) and "link" (edges recomputed from other facts whenever
# those change) do not expire on their own.
REFRESH_SECONDS = {
    "aws.state": 24 * 3600,
    "aws.cloudtrail": 24 * 3600,
    "k8s.state": 3600,
    "ai.inventory": 24 * 3600,
    "github.state": 24 * 3600,
    "builtin": None,
    "link": None,
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
OUTCOMES = ("success", "failure", "unknown")

INTERNET = "net:internet:any"


def entity_id(etype, native):
    provider = ENTITY_TYPES[etype][0]
    return f"{provider}:{etype}:{native}"


def _hash(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def edge_id(etype, src, dst):
    return _hash("edge", etype, src, dst)


def event_id(source, native):
    return _hash("event", source, native)


def raw_ref(raw):
    return _hash("raw", raw)


def finding_id(rule_id, primary, path):
    return _hash("finding", rule_id, primary, list(path))


def incident_id(first_finding, first_seen):
    return _hash("incident", first_finding, first_seen)


# --- time --------------------------------------------------------------------------------
# All times are stored as fixed-width UTC strings, so string order is time order.

TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def parse_ts(value):
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Falco writes nanoseconds; datetime holds microseconds.
        if "." in text:
            head, rest = text.split(".", 1)
            n = 0
            while n < len(rest) and rest[n].isdigit():
                n += 1
            frac, tz = rest[:n], rest[n:]
            text = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without a time zone: {value!r}")
    return dt.astimezone(timezone.utc)


def ts(value):
    return parse_ts(value).strftime(TS_FORMAT)


def shift(value, seconds):
    return ts(parse_ts(value) + timedelta(seconds=seconds))


def seconds_between(a, b):
    return (parse_ts(b) - parse_ts(a)).total_seconds()


class FixedClock:
    """The only clock the logic sees. Tests and replays set it; the CLI may pass --now."""

    def __init__(self, now):
        self.value = ts(now)

    def now(self):
        return self.value

    def set(self, now):
        self.value = ts(now)


class SystemClock:
    def now(self):
        return datetime.now(timezone.utc).strftime(TS_FORMAT)
