"""Kubernetes state from `kubectl get pods,services,serviceaccounts,networkpolicies -A -o json`.

That output does not name the cluster, so the caller passes it. Entity IDs are
`k8s:<type>:<cluster>/<namespace>/<name>`.

Reachability is deliberately narrow: a Service of type LoadBalancer with an assigned
address, no internal-scheme annotation and no source-range limit is internet-facing.
NodePort Services, Ingress objects and cloud security groups are not modelled. A
NetworkPolicy that selects an exposed pod is not evaluated; the exposes edge says so.
"""

from ..schema import INTERNET, entity_id
from . import Delta, need, read_json

SOURCE = "k8s.state"
IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
INTERNAL_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-scheme": {"internal"},
    "service.beta.kubernetes.io/aws-load-balancer-internal": {"true", "0.0.0.0/0"},
}
KINDS = ("Pod", "Service", "ServiceAccount", "NetworkPolicy")


def load(path):
    data = read_json(path, "k8s")
    need(isinstance(data, dict) and isinstance(data.get("items"), list), "k8s",
         "expected `kubectl get ... -o json` output with items")
    for item in data["items"]:
        md = item.get("metadata") if isinstance(item, dict) else None
        need(isinstance(md, dict) and isinstance(item.get("kind"), str) and isinstance(md.get("name"), str),
             "k8s", "an item lacks kind or metadata.name")
        if item["kind"] in KINDS:
            need(isinstance(md.get("namespace"), str), "k8s", f"{item['kind']} {md['name']!r} lacks a namespace")
            need(isinstance(item.get("spec", {}), dict), "k8s", f"{item['kind']} {md['name']!r} has a bad spec")
    return data


def _native(cluster, md):
    return f"{cluster}/{md['namespace']}/{md['name']}"


def _labels(md):
    return {"labels": dict(md.get("labels") or {}), "annotations": dict(md.get("annotations") or {})}


def _selects(selector, labels):
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _internet_facing(svc):
    spec, md = svc.get("spec") or {}, svc["metadata"]
    if spec.get("type") != "LoadBalancer":
        return False
    if not ((svc.get("status") or {}).get("loadBalancer") or {}).get("ingress"):
        return False
    ann = md.get("annotations") or {}
    for key, internal in INTERNAL_ANNOTATIONS.items():
        if str(ann.get(key, "")).lower() in internal:
            return False
    ranges = spec.get("loadBalancerSourceRanges") or []
    return not ranges or "0.0.0.0/0" in ranges


def apply(store, data, cluster, at):
    delta, seen_e, seen_x = Delta(), set(), set()

    def ent(eid, etype, attrs, labels):
        if store.upsert_entity(eid, etype, attrs, labels, SOURCE, at):
            delta.entity(eid, etype)
        seen_e.add(eid)

    def edge(etype, src, dst, attrs=None):
        xid, changed = store.upsert_edge(etype, src, dst, attrs or {}, SOURCE, at)
        if changed:
            delta.edge(etype)
        seen_x.add(xid)

    if store.upsert_entity(INTERNET, "internet", {}, {}, "builtin", at):
        delta.entity(INTERNET, "internet")
    items = [i for i in data["items"] if i["kind"] in KINDS]
    pods = []
    netpols = []
    for item in items:
        md, spec, kind = item["metadata"], item.get("spec") or {}, item["kind"]
        native = _native(cluster, md)
        if kind == "ServiceAccount":
            ann = md.get("annotations") or {}
            ent(entity_id("service_account", native), "service_account",
                {"name": md["name"], "namespace": md["namespace"], "irsa_role_arn": ann.get(IRSA_ANNOTATION)},
                _labels(md))
        elif kind == "Pod":
            containers = spec.get("containers") or []
            privileged = any(((c.get("securityContext") or {}).get("privileged") is True) for c in containers)
            sa = spec.get("serviceAccountName") or "default"
            pid = entity_id("pod", native)
            ent(pid, "pod", {"name": md["name"], "namespace": md["namespace"], "service_account": sa,
                             "privileged": privileged, "node": spec.get("nodeName"),
                             "pod_labels": dict(md.get("labels") or {})}, _labels(md))
            edge("runs_as", pid, entity_id("service_account", f"{cluster}/{md['namespace']}/{sa}"))
            pods.append((pid, md))
        elif kind == "NetworkPolicy":
            sel = (spec.get("podSelector") or {}).get("matchLabels") or {}
            ent(entity_id("network_policy", native), "network_policy",
                {"name": md["name"], "namespace": md["namespace"], "pod_selector": sel}, _labels(md))
            netpols.append((md["namespace"], md["name"], sel))
    for item in items:
        if item["kind"] != "Service":
            continue
        md, spec = item["metadata"], item.get("spec") or {}
        sid = entity_id("service", _native(cluster, md))
        selector = dict(spec.get("selector") or {})
        facing = _internet_facing(item)
        ent(sid, "service", {"name": md["name"], "namespace": md["namespace"], "service_type": spec.get("type"),
                             "selector": selector, "internet_facing": facing}, _labels(md))
        if facing:
            edge("reachable_from", sid, INTERNET)
        for pid, pmd in pods:
            plabels = pmd.get("labels") or {}
            if pmd["namespace"] == md["namespace"] and _selects(selector, plabels):
                # An empty podSelector selects every pod in the namespace.
                notes = sorted(f"NetworkPolicy {ns}/{name} not evaluated" for ns, name, sel in netpols
                               if ns == pmd["namespace"] and (not sel or _selects(sel, plabels)))
                edge("exposes", sid, pid, {"not_evaluated": notes} if notes else {})
    gone_e, gone_x = store.sweep(SOURCE, seen_e, seen_x, at)
    for eid, etype in gone_e:
        delta.entity(eid, etype)
    for _, etype in gone_x:
        delta.edge(etype)
    return delta
