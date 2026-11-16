"""Parsers for three event formats, one record per line (NDJSON):

- CloudTrail records (the objects inside a trail file's "Records" array, as CloudWatch
  Logs and EventBridge deliver them one at a time),
- Kubernetes audit events (audit.k8s.io/v1 Event, as the log backend writes them),
- Falco alerts with json_output enabled.

A parser turns a record into a normalised event plus resolution hints. It does not look
at the model; the pipeline resolves the hints against it. Every string field is kept as
data, including fields an attacker can set, such as a CloudTrail userAgent.
"""

from ..schema import EVENT_SOURCES, entity_id, event_id, raw_ref, ts

MODEL_CHANGES = ("PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy")


class ParseError(ValueError):
    pass


def detect(raw):
    if not isinstance(raw, dict):
        raise ParseError("record is not a JSON object")
    if str(raw.get("apiVersion", "")).startswith("audit.k8s.io/") and raw.get("kind") == "Event":
        return "k8s.audit"
    if "rule" in raw and "output" in raw and "priority" in raw:
        return "k8s.runtime"
    if "eventSource" in raw and "eventName" in raw and "eventTime" in raw:
        return "aws.cloudtrail"
    raise ParseError("record is not CloudTrail, Kubernetes audit or Falco output")


def parse(raw, cluster):
    source = detect(raw)
    try:
        ev, hints, change = PARSERS[source](raw, cluster)
    except (KeyError, TypeError, ValueError) as exc:
        raise ParseError(f"{source} record: {exc}") from exc
    ev.update(source=source, domain=EVENT_SOURCES[source], raw_ref=raw_ref(raw),
              event_id=event_id(source, ev.pop("native_id")))
    return ev, hints, change


def _s(value, limit=2000):
    return None if value is None else str(value)[:limit]


def _cloudtrail(raw, cluster):
    if not raw.get("eventID"):
        raise ValueError("eventID missing")
    service = str(raw["eventSource"]).split(".", 1)[0]
    name = str(raw["eventName"])
    ident = raw.get("userIdentity") or {}
    issuer = ((ident.get("sessionContext") or {}).get("sessionIssuer") or {})
    actor = None
    if issuer.get("type") == "Role" and issuer.get("arn"):
        actor = ("arn", "iam_role", issuer["arn"])
    elif ident.get("type") == "AssumedRole" and ident.get("arn"):
        actor = ("session_arn", "iam_role", ident["arn"])
    req = raw.get("requestParameters") or {}
    targets = []
    if req.get("bucketName"):
        targets.append(("id", "s3_bucket", entity_id("s3_bucket", f"arn:aws:s3:::{req['bucketName']}")))
    if req.get("roleName"):
        targets.append(("name", "iam_role", str(req["roleName"])))
    outcome = "failure" if raw.get("errorCode") else "success"
    attrs = {
        "principal": _s(ident.get("arn")),
        "principal_type": _s(ident.get("type")),
        "source_ip": _s(raw.get("sourceIPAddress")),
        "user_agent": _s(raw.get("userAgent")),
        "region": _s(raw.get("awsRegion")),
        "event_type": _s(raw.get("eventType")),
        "error_code": _s(raw.get("errorCode")),
        "bucket": _s(req.get("bucketName")),
        "key": _s(req.get("key")),
        "role_name": _s(req.get("roleName")),
        "policy_name": _s(req.get("policyName")),
        "policy_arn": _s(req.get("policyArn")),
    }
    change = None
    # A failed call changed nothing, so it must not change the model either.
    if service == "iam" and name in MODEL_CHANGES and outcome == "success":
        change = {"op": name, "role_name": _s(req.get("roleName")), "policy_name": _s(req.get("policyName")),
                  "policy_arn": _s(req.get("policyArn")), "document": req.get("policyDocument")}
    ev = {"native_id": str(raw["eventID"]), "time": ts(raw["eventTime"]), "action": f"aws:{service}:{name}",
          "outcome": outcome, "attrs": {k: v for k, v in attrs.items() if v is not None}}
    return ev, {"actor": actor, "targets": targets}, change


K8S_RESOURCES = {"pods": "pod", "services": "service", "serviceaccounts": "service_account"}


def _k8s_audit(raw, cluster):
    if not raw.get("auditID"):
        raise ValueError("auditID missing")
    ref = raw.get("objectRef") or {}
    resource = str(ref.get("resource", ""))
    sub = ref.get("subresource")
    verb = str(raw.get("verb", ""))
    user = (raw.get("user") or {}).get("username", "")
    actor = None
    if user.startswith("system:serviceaccount:"):
        parts = user.split(":")
        if len(parts) == 4:
            actor = ("id", "service_account", entity_id("service_account", f"{cluster}/{parts[2]}/{parts[3]}"))
    targets = []
    if resource in K8S_RESOURCES and ref.get("namespace") and ref.get("name"):
        etype = K8S_RESOURCES[resource]
        targets.append(("id", etype, entity_id(etype, f"{cluster}/{ref['namespace']}/{ref['name']}")))
    code = (raw.get("responseStatus") or {}).get("code")
    outcome = "unknown" if not isinstance(code, int) else ("success" if code < 400 else "failure")
    attrs = {
        "user": _s(user), "source_ips": [str(i) for i in raw.get("sourceIPs") or []],
        "user_agent": _s(raw.get("userAgent")), "verb": verb, "resource": resource, "subresource": _s(sub),
        "namespace": _s(ref.get("namespace")), "name": _s(ref.get("name")),
        "request_uri": _s(raw.get("requestURI")),
        "decision": _s((raw.get("annotations") or {}).get("authorization.k8s.io/decision")),
    }
    ev = {"native_id": f"{raw['auditID']}/{raw.get('stage', '')}",
          "time": ts(raw.get("stageTimestamp") or raw["requestReceivedTimestamp"]),
          "action": f"k8s:{resource}{'/' + str(sub) if sub else ''}:{verb}", "outcome": outcome,
          "attrs": {k: v for k, v in attrs.items() if v is not None}}
    return ev, {"actor": actor, "targets": targets}, None


FALCO_FIELDS = ("proc.name", "proc.cmdline", "proc.pname", "fd.name", "user.name", "container.id",
                "container.name", "container.image.repository")


def _falco(raw, cluster):
    fields = raw.get("output_fields") or {}
    actor = None
    if fields.get("k8s.ns.name") and fields.get("k8s.pod.name"):
        actor = ("id", "pod", entity_id("pod", f"{cluster}/{fields['k8s.ns.name']}/{fields['k8s.pod.name']}"))
    attrs = {"rule": str(raw["rule"]), "priority": _s(raw.get("priority")), "hostname": _s(raw.get("hostname")),
             "tags": [str(t) for t in raw.get("tags") or []], "output": _s(raw.get("output"))}
    for f in FALCO_FIELDS:
        if fields.get(f) is not None:
            attrs[f] = _s(fields[f])
    # Falco alerts carry no ID in older versions; the record's own hash stands in for one.
    native = str(raw.get("uuid") or raw_ref(raw))
    ev = {"native_id": native, "time": ts(raw["time"]), "action": f"falco:{raw['rule']}", "outcome": "success",
          "attrs": {k: v for k, v in attrs.items() if v is not None}}
    return ev, {"actor": actor, "targets": []}, None


PARSERS = {"aws.cloudtrail": _cloudtrail, "k8s.audit": _k8s_audit, "k8s.runtime": _falco}
