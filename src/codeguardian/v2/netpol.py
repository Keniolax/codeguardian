"""NetworkPolicy ingress, evaluated as the Kubernetes reference defines it (networking.k8s.io/v1).

A pod is isolated for ingress when a policy in its namespace selects it and has Ingress in
its policyTypes (an empty or missing policyTypes means Ingress). An isolated pod accepts
a connection only if some rule of some such policy matches both its source and its port.
Policies only add allows, so the answer does not depend on their order.

Every answer is one of three: allowed, denied, or not evaluated. A construct this module
does not handle never counts as a deny. It gives "not evaluated" with a note, and the
callers keep a path open on "not evaluated". The logic is three-valued (Kleene): True,
False, and None for "not known".

What "from outside" means here: a connection whose source, as the pod sees it, is an
address in the outside range. By default that range is every IPv4 and IPv6 address. Only
an ipBlock (or a rule with no `from`) can match it, because podSelector and
namespaceSelector select pods, and an outside address is not a pod. What this cannot
know: whether the cluster's network plugin enforces NetworkPolicy at all (without one, a
policy has no effect), and which source address the pod sees. A load balancer or the
node may rewrite it, and the reference leaves open whether that happens before or after
the policy is applied. Traffic from the pod's own node is always allowed.

Egress rules are not evaluated. They cannot block a connection into a pod, because replies
to allowed ingress are allowed. For a pod-to-pod answer, a source pod that an egress
policy selects gives "not evaluated".
"""

import ipaddress

ALLOWED, DENIED, NOT_EVALUATED = "allowed", "denied", "not evaluated"
OUTSIDE = ("0.0.0.0/0", "::/0")
PEER_KEYS = {"podSelector", "namespaceSelector", "ipBlock"}
SELECTOR_KEYS = {"matchLabels", "matchExpressions"}
RULE_KEYS = {"from", "ports"}
PORT_KEYS = {"protocol", "port", "endPort"}
PROTOCOLS = ("TCP", "UDP", "SCTP")


def _and(*xs):
    if any(x is False for x in xs):
        return False
    return True if all(x is True for x in xs) else None


def _or(*xs):
    if any(x is True for x in xs):
        return True
    return False if all(x is False for x in xs) else None


def _not(x):
    return None if x is None else not x


def verdict(value):
    return {True: ALLOWED, False: DENIED}.get(value, NOT_EVALUATED)


def _clip(value, limit=60):
    return repr(value)[:limit]


# --- label selectors --------------------------------------------------------------------

def selects(selector, labels, what, notes):
    """Standard label selector semantics: an empty selector selects everything;
    matchLabels and matchExpressions are ANDed. labels is None when they are not known."""
    if not isinstance(selector, dict) or set(selector) - SELECTOR_KEYS:
        notes.add(f"{what}: selector {_clip(selector)} not evaluated")
        return None
    match = selector.get("matchLabels") or {}
    exprs = selector.get("matchExpressions") or []
    if not isinstance(match, dict) or not isinstance(exprs, list):
        notes.add(f"{what}: selector {_clip(selector)} not evaluated")
        return None
    if not match and not exprs:
        return True
    if labels is None:
        notes.add(f"{what}: labels not known; selector not evaluated")
        return None
    results = []
    for key, value in match.items():
        if not isinstance(value, str):
            notes.add(f"{what}: matchLabels value {_clip(value)} not evaluated")
            results.append(None)
        else:
            results.append(labels.get(key) == value)
    for req in exprs:
        results.append(_requirement(req, labels, what, notes))
    return _and(*results)


def _requirement(req, labels, what, notes):
    if not isinstance(req, dict):
        notes.add(f"{what}: matchExpressions entry {_clip(req)} not evaluated")
        return None
    key, op, values = req.get("key"), req.get("operator"), req.get("values") or []
    if not isinstance(key, str) or not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        notes.add(f"{what}: matchExpressions entry {_clip(req)} not evaluated")
        return None
    if op in ("In", "NotIn") and values:
        found = key in labels and labels[key] in values
        return found if op == "In" else not found
    if op in ("Exists", "DoesNotExist") and not values:
        return (key in labels) == (op == "Exists")
    notes.add(f"{what}: matchExpressions operator {_clip(op)} with {len(values)} values not evaluated")
    return None


# --- sources ------------------------------------------------------------------------------

def outside(cidrs=OUTSIDE):
    """The outside source: the address ranges a connection from outside may come from."""
    return {"kind": "outside", "cidrs": [ipaddress.ip_network(c, strict=False) for c in cidrs]}


def pod_source(pod, namespace_labels):
    return {"kind": "pod", "namespace": pod["namespace"], "labels": pod.get("pod_labels") or {},
            "namespace_labels": namespace_labels, "host_network": pod.get("host_network") is True}


def _ipblock(block, source, what, notes):
    if not isinstance(block, dict) or set(block) - {"cidr", "except"}:
        notes.add(f"{what}: ipBlock {_clip(block)} not evaluated")
        return None
    excepts = block.get("except") or []
    if not isinstance(excepts, list):
        notes.add(f"{what}: ipBlock except {_clip(excepts)} is not a list; not evaluated")
        return None
    raw = [block.get("cidr"), *excepts]
    try:
        if not all(isinstance(c, str) for c in raw):
            raise TypeError("a CIDR must be a string")
        net, *excepts = [ipaddress.ip_network(c, strict=False) for c in raw]
    except (TypeError, ValueError):
        notes.add(f"{what}: ipBlock {_clip(block)} is not a valid CIDR; not evaluated")
        return None
    if any(e.version != net.version or not e.subnet_of(net) for e in excepts):
        notes.add(f"{what}: ipBlock except outside its cidr; not evaluated")
        return None
    if source["kind"] == "pod":
        # Pod addresses change and are not in the model; whether a plugin matches them
        # against ipBlock also differs.
        notes.add(f"{what}: ipBlock against a pod's address not evaluated")
        return None
    for s in source["cidrs"]:
        if s.version != net.version or not s.overlaps(net):
            continue
        part = s if s.subnet_of(net) else net  # CIDRs that overlap are nested
        inside = [e for e in excepts if e.overlaps(part)]
        if any(part.subnet_of(e) for e in inside):
            continue
        if list(ipaddress.collapse_addresses(inside)) != [part]:
            return True  # some outside address is in the block and not excepted
    return False


def _peer(peer, policy_ns, source, what, notes):
    if not isinstance(peer, dict):
        notes.add(f"{what}: from entry {_clip(peer)} not evaluated")
        return None
    peer = {k: v for k, v in peer.items() if v is not None}
    if not peer or set(peer) - PEER_KEYS:
        notes.add(f"{what}: from entry {_clip(peer)} not evaluated")
        return None
    if "ipBlock" in peer:
        if len(peer) != 1:
            notes.add(f"{what}: ipBlock together with a selector is not valid; not evaluated")
            return None
        return _ipblock(peer["ipBlock"], source, what, notes)
    if source["kind"] == "outside":
        return False  # these select pods; an outside address is not a pod
    if "namespaceSelector" in peer:
        ns_ok = selects(peer["namespaceSelector"], source["namespace_labels"], f"{what} namespaceSelector", notes)
    else:
        ns_ok = source["namespace"] == policy_ns
    pod_ok = selects(peer["podSelector"], source["labels"], f"{what} podSelector", notes) if "podSelector" in peer \
        else True
    return _and(ns_ok, pod_ok)


# --- ports --------------------------------------------------------------------------------

def named_port(pod, name, protocol):
    hits = {p.get("port") for p in pod.get("container_ports") or []
            if p.get("name") == name and (p.get("protocol") or "TCP") == protocol}
    return hits.pop() if len(hits) == 1 else None


def _port(entry, target, protocol, pod, what, notes):
    if not isinstance(entry, dict) or set(entry) - PORT_KEYS:
        notes.add(f"{what}: port entry {_clip(entry)} not evaluated")
        return None
    if (entry.get("protocol") or "TCP") not in PROTOCOLS:
        notes.add(f"{what}: protocol {_clip(entry.get('protocol'))} not evaluated")
        return None
    if (entry.get("protocol") or "TCP") != protocol:
        return False
    port, end = entry.get("port"), entry.get("endPort")
    if port is None:
        if end is not None:
            notes.add(f"{what}: endPort without port is not valid; not evaluated")
            return None
        return True
    if isinstance(port, str):
        if end is not None:
            notes.add(f"{what}: endPort with a named port is not valid; not evaluated")
            return None
        number = named_port(pod, port, protocol)
        if number is None:
            notes.add(f"{what}: named port {_clip(port)} not found once on the pod; not evaluated")
            return None
        port = number
    if not isinstance(port, int) or isinstance(port, bool):
        notes.add(f"{what}: port {_clip(port)} not evaluated")
        return None
    if target is None:
        return None
    if end is None or target == port:
        return target == port
    if not isinstance(end, int) or isinstance(end, bool) or end < port:
        notes.add(f"{what}: endPort {_clip(end)} not evaluated")
        return None
    if port < target <= end:
        # A plugin without endPort support applies the rule to `port` alone.
        notes.add(f"{what}: endPort range {port}-{end} depends on the network plugin; not evaluated")
        return None
    return False


def _rule(rule, policy_ns, source, target, protocol, pod, what, notes):
    if not isinstance(rule, dict) or set(rule) - RULE_KEYS:
        notes.add(f"{what}: rule {_clip(rule)} not evaluated")
        return None
    peers, ports = rule.get("from") or [], rule.get("ports") or []
    if not isinstance(peers, list) or not isinstance(ports, list):
        notes.add(f"{what}: rule {_clip(rule)} not evaluated")
        return None
    from_ok = _or(*[_peer(p, policy_ns, source, what, notes) for p in peers]) if peers else True
    port_ok = _or(*[_port(p, target, protocol, pod, what, notes) for p in ports]) if ports else True
    return _and(from_ok, port_ok)


# --- policies -----------------------------------------------------------------------------

def _types(policy, direction, what, notes):
    types = policy.get("policy_types")
    if types is None or types == []:
        if direction == "Ingress":
            return True
        if not isinstance(policy.get("egress_rules"), int):
            notes.add(f"{what}: egress rules not known; policyTypes not evaluated")
            return None
        return policy["egress_rules"] > 0
    if not isinstance(types, list) or any(t not in ("Ingress", "Egress") for t in types):
        notes.add(f"{what}: policyTypes {_clip(types)} not evaluated")
        return None
    return direction in types


def _name(policy):
    return f"NetworkPolicy {policy.get('namespace')}/{policy.get('name')}"


def ingress(policies, pod, source, target, protocol="TCP"):
    """Whether `source` may connect to `pod` on `target` (a port number, or None when it is
    not known). Returns (answer, names of the policies that apply or may apply, notes)."""
    notes, applying = set(), []
    isolated, allows = [], []
    for p in policies:
        if p.get("namespace") != pod["namespace"]:
            continue
        what = _name(p)
        applies = _and(selects(p.get("pod_selector", {}), pod.get("pod_labels") or {}, what, notes),
                       _types(p, "Ingress", what, notes))
        if applies is False:
            continue
        applying.append(what)
        rules = p.get("ingress")
        if rules is None:
            rules = []
        if "ingress" not in p:
            # A model written before ingress rules were collected. Missing is not "no rules".
            notes.add(f"{what}: ingress rules not in the model; not evaluated")
            matched = None
        elif not isinstance(rules, list):
            notes.add(f"{what}: ingress {_clip(rules)} not evaluated")
            matched = None
        else:
            matched = _or(*[_rule(r, p["namespace"], source, target, protocol, pod, what, notes) for r in rules])
        isolated.append(applies)
        allows.append(_and(applies, matched))
    answer = _or(_not(_or(*isolated)), *allows)
    if answer is False and pod.get("host_network"):
        notes.add("the pod uses the host network; NetworkPolicy behaviour for it is not defined; not evaluated")
        answer = None
    if answer is False and source.get("host_network"):
        # The reference: a plugin may not tell a host-network pod from its node, and traffic
        # from the node a pod runs on is always allowed.
        notes.add("the source pod uses the host network; NetworkPolicy behaviour for it is not defined;"
                  " not evaluated")
        answer = None
    return answer, sorted(applying), notes


def service_ingress(policies, pod, service_ports, source):
    """Ingress from `source` through any port of a Service to one of its pods."""
    notes, answers, applying = set(), [], set()
    if not isinstance(service_ports, list) or not service_ports:
        return None, [], {"the Service lists no ports; ingress not evaluated"}
    for sp in service_ports:
        if not isinstance(sp, dict):
            notes.add(f"Service port {_clip(sp)} not evaluated")
            answers.append(None)
            continue
        protocol = sp.get("protocol") or "TCP"
        if protocol not in PROTOCOLS:
            notes.add(f"Service port protocol {_clip(protocol)} not evaluated")
            answers.append(None)
            continue
        target = sp.get("targetPort")
        if target is None:
            target = sp.get("port")  # an omitted targetPort is the same as port
        if isinstance(target, str):
            number = named_port(pod, target, protocol)
            if number is None:
                notes.add(f"Service targetPort {_clip(target)} not found once on the pod; port not known")
            target = number
        elif target is None:
            notes.add(f"Service port {_clip(sp)} has no port number; port not known")
        if target is not None and (not isinstance(target, int) or isinstance(target, bool)):
            notes.add(f"Service port {_clip(sp)} has no port number; port not known")
            target = None
        answer, names, more = ingress(policies, pod, source, target, protocol)
        answers.append(answer)
        applying.update(names)
        notes |= more
    return _or(*answers), sorted(applying), notes


def _egress_selects(policies, pod, notes):
    """Whether an egress policy selects the pod; its rules are not evaluated."""
    hits = []
    for p in policies:
        if p.get("namespace") != pod["namespace"]:
            continue
        what = _name(p)
        hit = _and(selects(p.get("pod_selector", {}), pod.get("pod_labels") or {}, what, notes),
                   _types(p, "Egress", what, notes))
        if hit is not False:
            notes.add(f"{what}: egress from the source pod not evaluated")
        hits.append(hit)
    return _or(*hits)


def pod_to_pod(store, src_id, dst_id, port, protocol="TCP"):
    """Whether pod src_id may open a connection to pod dst_id on a port, from the model.
    Returns (answer, notes)."""
    src, dst = store.entity(src_id), store.entity(dst_id)
    if src is None or dst is None or src["type"] != "pod" or dst["type"] != "pod":
        return NOT_EVALUATED, ["a pod is not in the model"]
    cluster = src_id.split(":", 2)[2].rsplit("/", 2)[0]
    if dst_id.split(":", 2)[2].rsplit("/", 2)[0] != cluster:
        return NOT_EVALUATED, ["the pods are in different clusters"]
    prefix = f"k8s:network_policy:{cluster}/"
    policies = [e["attrs"] for e in store.entities("network_policy") if e["id"].startswith(prefix)]
    ns = store.entity(f"k8s:namespace:{cluster}/{src['attrs']['namespace']}")
    source = pod_source(src["attrs"], ns["attrs"].get("namespace_labels") if ns else None)
    answer, _, notes = ingress(policies, dst["attrs"], source, port, protocol)
    egress_ok = True if _egress_selects(policies, src["attrs"], notes) is False else None
    return verdict(_and(answer, egress_ok)), sorted(notes)
