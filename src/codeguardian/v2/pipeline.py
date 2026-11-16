"""The pipeline: snapshots and events both change the one model, and each change re-runs
only the rules that can see it.

Per event: parse, skip if already seen, resolve actor and targets against the model, store
the event, apply any model change it carries, re-run the affected posture and path rules,
run the detection rules for its action, and correlate what opened.
"""

from collections import Counter, defaultdict

from . import correlate, detect, netpol, paths, posture
from . import rules as R
from .collectors import CollectorError, Delta
from .collectors import ai as ai_collector
from .collectors import aws as aws_collector
from .collectors import k8s as k8s_collector
from .collectors.events import ParseError, parse
from .policy import trusts_service_account
from .schema import entity_id, finding_id


class Pipeline:
    def __init__(self, store, rules, clock, cluster="lab", outside=netpol.OUTSIDE):
        self.store, self.clock, self.cluster = store, clock, cluster
        self.outside = tuple(outside)  # address ranges a connection from outside may come from
        self.posture = [r for r in rules if r["kind"] == "posture"]
        self.paths = [r for r in rules if r["kind"] == "path"]
        self.detections = defaultdict(list)
        for r in rules:
            if r["kind"] == "detection":
                for action in r["match"]["actions"]:
                    self.detections[(r["match"]["source"], action)].append(r)
        self.touched = {r["id"]: R.touched_types(r) for r in rules}
        self.evals = Counter()  # rule ID -> evaluations, so tests can prove what re-ran

    # --- snapshots -----------------------------------------------------------------------

    def snapshot(self, aws=None, k8s=None, ai=None, at=None):
        """Run the given collectors. aws = (iam, buckets, tags) paths; k8s and ai are paths.

        A collector that fails is recorded as failed, so its facts read as stale, and the
        others still run. The errors are raised together at the end.
        """
        at = at or self.clock.now()
        delta, errors = Delta(), []
        jobs = []
        if aws is not None:
            jobs.append((aws_collector.SOURCE, lambda: aws_collector.apply(self.store, aws_collector.load(*aws), at)))
        if k8s is not None:
            jobs.append((k8s_collector.SOURCE,
                         lambda: k8s_collector.apply(self.store, k8s_collector.load(k8s), self.cluster, at,
                                                     self.outside)))
        if ai is not None:
            jobs.append((ai_collector.SOURCE, lambda: ai_collector.apply(self.store, ai_collector.load(ai), at)))
        for name, job in jobs:
            try:
                delta.merge(job())
            except CollectorError as exc:
                self.store.record_source(name, False, at, str(exc))
                errors.append(str(exc))
            else:
                self.store.record_source(name, True, at)
        delta.merge(self.link(at))
        changes = self.evaluate_all(at)
        self.store.commit()
        if errors:
            raise CollectorError("; ".join(errors))
        return changes

    def link(self, at):
        """IRSA: a service account assumes a role when its annotation names the role and
        the role's trust policy names the service account. Either alone is not enough."""
        delta, keep = Delta(), set()
        roles = self.store.entities("iam_role")
        for sa in self.store.entities("service_account"):
            a = sa["attrs"]
            arn = a.get("irsa_role_arn")
            trusting = [r for r in roles
                        if trusts_service_account(r["attrs"].get("trust_subjects", []), a["namespace"], a["name"])]
            linked = [r for r in trusting if r["attrs"]["arn"] == arn]
            if not arn:
                status = None
            elif not any(r["attrs"]["arn"] == arn for r in roles):
                status = "role not in model"
            elif not linked:
                status = "role trust policy does not name this service account"
            else:
                status = "trust verified"
            for role in linked:
                xid, changed = self.store.upsert_edge("assumes", sa["id"], role["id"], {"via": "irsa"}, "link", at)
                keep.add(xid)
                if changed:
                    delta.edge("assumes")
            if self.store.set_attrs(sa["id"], {**a, "irsa_status": status}):
                delta.entity(sa["id"], "service_account")
        for e in self.store.edges(etype="assumes"):
            if e["source"] == "link" and e["id"] not in keep and self.store.delete_edge(e["id"], at):
                delta.edge("assumes")
        return delta

    # --- rule evaluation -----------------------------------------------------------------

    def evaluate_all(self, at):
        changes = {"opened": [], "resolved": []}
        for rule in self.posture:
            for ent in self.store.entities(rule["entity"]):
                self._posture(rule, ent["id"], at, changes)
            for f in self.store.findings(status="open", rule_id=rule["id"]):
                if self.store.entity(f["primary_entity"]) is None:
                    self._resolve(f, at, changes)
        for rule in self.paths:
            self._path(rule, at, changes)
        return changes

    def evaluate_delta(self, delta, at):
        changes = {"opened": [], "resolved": []}
        if not delta:
            return changes
        for rule in self.posture:
            for eid, etype in delta.entities.items():
                if etype == rule["entity"]:
                    self._posture(rule, eid, at, changes)
        for rule in self.paths:
            ents, edges = self.touched[rule["id"]]
            if ents & delta.entity_types or edges & delta.edge_types:
                self._path(rule, at, changes)
        return changes

    def _posture(self, rule, eid, at, changes):
        self.evals[rule["id"]] += 1
        f = posture.evaluate(self.store, rule, self.store.entity(eid), self.clock.now())
        if f:
            self._open(f, at, changes)
        else:
            old = self.store.finding(finding_id(rule["id"], eid, []))
            if old and old["status"] == "open":
                self._resolve(old, at, changes)

    def _path(self, rule, at, changes):
        self.evals[rule["id"]] += 1
        produced = {f["finding_id"]: f for f in paths.evaluate(self.store, rule, self.clock.now())}
        for f in produced.values():
            self._open(f, at, changes)
        for old in self.store.findings(status="open", rule_id=rule["id"]):
            if old["finding_id"] not in produced:
                self._resolve(old, at, changes)

    def _open(self, f, at, changes, event=None):
        old = self.store.finding(f["finding_id"])
        was_open = bool(old and old["status"] == "open")
        events = list(old["events"]) if old else []
        for eid in f["events"]:
            if eid not in events:
                events.append(eid)
        f = {**f, "events": events, "status": "open",
             "first_seen": old["first_seen"] if old else at,
             "last_seen": max(at, old["last_seen"]) if old else at}
        self.store.put_finding(f)
        if not was_open:
            changes["opened"].append(f["finding_id"])
        return f, was_open

    def _resolve(self, f, at, changes):
        self.store.put_finding({**f, "status": "resolved", "last_seen": max(at, f["last_seen"])})
        changes["resolved"].append(f["finding_id"])

    # --- events --------------------------------------------------------------------------

    def _resolve_ref(self, hint):
        if hint is None:
            return None
        kind, etype, value = hint
        if kind == "id":
            eid = value
        elif kind == "arn":
            eid = entity_id(etype, value)
        elif kind == "session_arn":
            eid = aws_collector.role_id_from_arn(value)
        elif kind == "name":
            ent = self.store.find_by_name(etype, value)
            eid = ent["id"] if ent else None
        else:
            eid = None
        return eid if eid and self.store.entity(eid) else None

    def _apply_change(self, ev, change):
        """Apply what an IAM CloudTrail record says changed.

        CloudTrail delivers records out of order, so each policy keeps the time of its
        last applied change, deletes and detaches included. A record applies only if it
        is newer than the last change to that policy and not older than the snapshot that
        last confirmed the role. A record that cannot be ordered marks the role as not
        evaluated, so it is never dropped silently.

        The record holds a policy's document only for PutRolePolicy; AttachRolePolicy
        names an ARN, and the document is known only if the last snapshot held it."""
        role = self.store.find_by_name("iam_role", change["role_name"])
        if role is None:
            self.store.bump("model_change_role_not_in_model")
            return Delta()
        if ev["time"] < role["last_seen"]:
            # A snapshot taken after this record already shows its outcome.
            self.store.bump("model_change_older_than_model")
            return Delta()
        a = dict(role["attrs"])
        key = aws_collector.change_key(change)
        if key is None:
            return self._mark(role, a, ev, f"{change['op']} at {ev['time']} names no policy; not evaluated")
        entry = {"time": ev["time"], "op": aws_collector.CHANGE_OPS[change["op"]],
                 "doc": aws_collector.decode_document(change["document"]) if change["op"] == "PutRolePolicy" else None}
        changes = dict(a.get("policy_changes") or {})
        last = changes.get(key)
        if last and ev["time"] < last["time"]:
            # A newer change to this policy is already applied; this one is history.
            self.store.bump("model_change_superseded")
            return Delta()
        if last and ev["time"] == last["time"] and (last["op"], last["doc"]) != (entry["op"], entry["doc"]):
            return self._mark(role, a, ev, f"two different changes to {key} at {ev['time']}; order unknown, not evaluated")
        changes[key] = entry
        new = aws_collector.apply_policy_change(a, key, entry)
        new["policy_changes"] = changes
        delta = Delta()
        if self.store.set_attrs(role["id"], new, observed_at=ev["time"]):
            delta.entity(role["id"], "iam_role")
        self.store.bump("model_changes_applied")
        return delta.merge(aws_collector.recompute_role(self.store, role["id"], ev["time"], "aws.cloudtrail"))

    def _mark(self, role, a, ev, text):
        self.store.bump("model_change_not_evaluated")
        marks = list(a.get("change_markers") or []) + [{"time": ev["time"], "text": text}]
        delta = Delta()
        if self.store.set_attrs(role["id"], {**a, "change_markers": marks}, observed_at=ev["time"]):
            delta.entity(role["id"], "iam_role")
        return delta.merge(aws_collector.recompute_role(self.store, role["id"], ev["time"], "aws.cloudtrail"))

    def process(self, raw):
        """Process one record fully. Returns a summary of what it changed."""
        try:
            ev, hints, change = parse(raw, self.cluster)
        except ParseError as exc:
            self.store.bump("unparseable")
            self.store.commit()
            return {"status": "unparseable", "error": str(exc)}
        if self.store.has_event(ev["event_id"]):
            self.store.bump("duplicates")
            return {"status": "duplicate", "event_id": ev["event_id"]}
        ev["ingested_at"] = self.clock.now()
        ev["actor"] = self._resolve_ref(hints["actor"])
        ev["targets"] = [self._resolve_ref(t) for t in hints["targets"]]
        if hints["actor"] is not None and ev["actor"] is None:
            ev["attrs"]["actor_ref"] = str(hints["actor"][2])
        if ev["actor"] is None:
            self.store.bump("events_actor_null")
        if any(t is None for t in ev["targets"]):
            self.store.bump("events_target_unresolved")
        self.store.add_event(ev)
        self.store.bump("events")
        at = ev["time"]
        changes = {"opened": [], "resolved": []}
        if change:
            changes = self.evaluate_delta(self._apply_change(ev, change), at)
        alerts = []
        for rule in self.detections.get((ev["source"], ev["action"]), []):
            self.evals[rule["id"]] += 1
            f = detect.evaluate(self.store, rule, ev)
            if f == detect.UNEVALUABLE:
                self.store.bump(f"unevaluable:{rule['id']}")
                continue
            if f:
                f, was_open = self._open(f, at, changes)
                alerts.append(f["finding_id"])
                correlate.add_detection(self.store, f, at)
        for fid in changes["opened"]:
            f = self.store.finding(fid)
            if f["kind"] != "detection":
                correlate.add_state(self.store, f, at)
        self.store.commit()
        return {"status": "processed", "event_id": ev["event_id"], "action": ev["action"], "actor": ev["actor"],
                "opened": changes["opened"], "resolved": changes["resolved"], "alerts": alerts}
