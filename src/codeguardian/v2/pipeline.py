"""The pipeline: snapshots and events both change the one model, and each change re-runs
only the rules that can see it.

Per event: parse, skip if already seen, resolve actor and targets against the model, store
the event, apply any model change it carries, re-run the affected posture and path rules,
run the detection rules for its action, and correlate what opened.

Records arrive out of order, so each input is ordered by the time in its data:

- A snapshot older than the last one applied from the same collector is refused and
  changes nothing, even one that was applied before a newer one came. The last one
  applied, sent again, is a no-op. Other content at the time of a snapshot already
  taken is refused and marked.
- An IAM change record older than the snapshot that last confirmed its role is history;
  one for a role the model does not hold yet waits for a snapshot that brings the role.
- A detection that cannot be evaluated yet is held, and decided after the next snapshot.

Every snapshot and change record is kept in a journal, refused ones included, so the
history of each finding can be rebuilt in data time (history.py).
"""

import hashlib
import json
from collections import Counter, defaultdict

from . import correlate, detect, netpol, paths, posture
from . import rules as R
from .collectors import CollectorError, Delta
from .collectors import ai as ai_collector
from .collectors import aws as aws_collector
from .collectors import github as github_collector
from .collectors import k8s as k8s_collector
from .collectors.events import ParseError, parse
from .policy import trusts_service_account
from .schema import entity_id, finding_id, ts

SNAPSHOT_ORDER = (aws_collector.SOURCE, k8s_collector.SOURCE, ai_collector.SOURCE, github_collector.SOURCE)


def snapshot_content(source, data, cluster, outside):
    """What a snapshot is, for comparing two of them and replaying one: the collector's
    input, plus the settings that change what the k8s collector writes."""
    if source == k8s_collector.SOURCE:
        return {"data": data, "cluster": cluster, "outside": list(outside)}
    return {"data": data}


def digest(content):
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Pipeline:
    def __init__(self, store, rules, clock, cluster="lab", outside=netpol.OUTSIDE):
        self.store, self.clock, self.cluster = store, clock, cluster
        self.rules = rules
        self.by_id = {r["id"]: r for r in rules}
        self.outside = tuple(outside)  # address ranges a connection from outside may come from
        self.recorder = None  # a list while history.py replays the journal: (finding, time, change, cause)
        self.cause = None
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

    def snapshot(self, aws=None, k8s=None, ai=None, at=None, github=None):
        """Run the given collectors. aws = (iam, buckets, tags) paths; k8s, ai and github are paths.

        A collector that fails is recorded as failed, so its facts read as stale, and the
        others still run. The errors are raised together at the end, with the changes on
        the exception. Returns opened and resolved finding IDs, and the sources whose
        snapshot was refused (with the reason) or was already applied.
        """
        at = ts(at) if at else self.clock.now()
        loaded, errors = {}, []
        loaders = []
        if aws is not None:
            loaders.append((aws_collector.SOURCE, lambda: aws_collector.load(*aws)))
        if k8s is not None:
            loaders.append((k8s_collector.SOURCE, lambda: k8s_collector.load(k8s)))
        if ai is not None:
            loaders.append((ai_collector.SOURCE, lambda: ai_collector.load(ai)))
        if github is not None:
            loaders.append((github_collector.SOURCE, lambda: github_collector.load(github)))
        marked = False
        for name, load in loaders:
            try:
                loaded[name] = load()
            except CollectorError as exc:
                last = (self.store.source(name) or {}).get("last_success")
                if last is not None and at < last:
                    # Older than the last good snapshot: it could not change the model, so
                    # its failure does not make the newer facts stale either.
                    self.store.bump("snapshot_older_failed")
                    errors.append(f"{exc} (older than the last applied snapshot of {name}; nothing changed)")
                else:
                    self.store.record_source(name, False, at, str(exc))
                    errors.append(str(exc))
                    marked = True
        contents = {name: snapshot_content(name, data, self.cluster, self.outside) for name, data in loaded.items()}
        # A failed collector makes its facts stale, which the rules' notes must show.
        changes = self.apply_snapshot(contents, at, reevaluate=marked)
        self.store.commit()
        if errors:
            exc = CollectorError("; ".join(errors))
            exc.changes, exc.marked_stale = changes, marked
            raise exc
        return changes

    def _admit(self, source, at, content):
        """Whether a snapshot may change the model: apply, unchanged, older or conflict.

        A repeat is the last snapshot applied, sent again. A snapshot applied before a newer
        one is older now and is refused like any older one, though the journal holds its
        exact content: the model no longer holds it, so "unchanged" would tell a script its
        old export is current. The journal keeps one entry per snapshot (source, time and
        digest), so that refusal adds none, and every other snapshot that is not a repeat
        goes into it."""
        d = digest(content)
        same_time = self.store.snapshot_entries(source, at)
        health = self.store.source(source)
        last = health["last_success"] if health else None
        if at == last and any(e["digest"] == d and e["status"] == "applied" for e in same_time):
            self.store.bump("snapshot_unchanged")
            return "unchanged", None
        # A snapshot refused before is refused again for the same reason: it is not in the
        # model, so it must not read as a repeat of one that is.
        others = [e for e in same_time if e["digest"] != d]
        if any(e["digest"] == d and e["status"] == "applied" for e in same_time):
            # Applied before a newer one came, so older now, even when another snapshot
            # was refused at its time: the journal already holds it, and the model a newer one.
            others = []
        if others or (last is not None and at == last):
            # Two different snapshots of one collector at one time: which one holds is unknown.
            verdict, reason = "conflict", (f"differs from the snapshot of {source} already taken at {at};"
                                           " which one holds is not known")
        elif last is not None and at < last:
            verdict, reason = "older", f"is older than the last applied snapshot of {source}, taken at {last}"
        else:
            verdict, reason = "applied", None
        self.store.add_snapshot(source, at, d, verdict, self.clock.now(), json.dumps(content, sort_keys=True))
        if verdict != "applied":
            self.store.bump(f"snapshot_{verdict}")
        return verdict, reason

    def apply_snapshot(self, contents, at, reevaluate=False):
        """Apply snapshot contents (source -> snapshot_content) taken at one time."""
        changes = {"opened": [], "resolved": [], "refused": [], "unchanged": []}
        admitted = []
        for name in SNAPSHOT_ORDER:
            if name not in contents:
                continue
            verdict, reason = self._admit(name, at, contents[name])
            if verdict == "applied":
                admitted.append(name)
            elif verdict == "unchanged":
                changes["unchanged"].append(name)
            else:
                changes["refused"].append((name, verdict, reason))
        if not admitted and not reevaluate:
            return changes
        for name in admitted:
            content = contents[name]
            if name == aws_collector.SOURCE:
                aws_collector.apply(self.store, content["data"], at)
            elif name == k8s_collector.SOURCE:
                k8s_collector.apply(self.store, content["data"], content["cluster"], at, tuple(content["outside"]))
                # The cluster name in the model's pod IDs, the default of the commands that name
                # a pod. Only an applied snapshot sets it: a refused one changes nothing.
                self.store.set_setting("cluster", content["cluster"])
            elif name == github_collector.SOURCE:
                github_collector.apply(self.store, content["data"], at)
            else:
                ai_collector.apply(self.store, content["data"], at)
            self.store.record_source(name, True, at)
        if aws_collector.SOURCE in admitted:
            self._apply_pending()
        self.link(self._link_time(at))
        found = self.evaluate_all(self._model_time(at))
        changes["opened"], changes["resolved"] = found["opened"], found["resolved"]
        self._decide_held(changes)
        return changes

    def _model_time(self, at):
        """The time a re-evaluation is stamped with. After an older snapshot or record lands
        on a newer snapshot of another collector, the model mixes both, and a finding it
        shows is known only from the newer one: never date it earlier than its data."""
        times = [at] + [s["last_success"] for s in self.store.sources() if s["last_success"]]
        return max(times)

    def _link_time(self, at):
        """IRSA edges come from the role and the service account together, so they are as
        new as the newer of the two collectors' last snapshots."""
        times = [at] + [(self.store.source(n) or {}).get("last_success") for n in (aws_collector.SOURCE,
                                                                                   k8s_collector.SOURCE)]
        return max(t for t in times if t)

    def _apply_pending(self):
        """Change records that arrived before any snapshot held their role."""
        for c in self.store.model_changes(status="pending"):
            status, _ = self._apply_change({"time": c["time"], "event_id": c["event_id"]}, c["change"])
            if status != "pending":
                self.store.set_model_change_status(c["event_id"], status)
                self.store.bump("model_change_role_found_later")

    def _decide_held(self, changes):
        """Decide the detections that could not be evaluated when their record arrived, now
        that a snapshot may have brought what they need. A record is decided against the
        model as it is now, not as it was at the record's own time."""
        for h in self.store.held():
            ev = self.store.event(h["event_id"])
            rule = self.by_id.get(h["rule_id"])
            if ev is None or rule is None:
                continue
            actor = self._resolve_ref(h["hints"]["actor"])
            targets = [self._resolve_ref(t) for t in h["hints"]["targets"]]
            ev = {**ev, "actor": actor, "targets": targets}
            self.evals[rule["id"]] += 1
            f = detect.evaluate(self.store, rule, ev)
            if f == detect.UNEVALUABLE:
                continue
            self.store.set_event_refs(ev["event_id"], actor, targets)
            self.store.unhold(h["event_id"], h["rule_id"])
            self.store.bump("held_decided")
            if f:
                f, _ = self._open(f, ev["time"], changes)
                correlate.add_detection(self.store, f, ev["time"])

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
        added = [eid for eid in f["events"] if eid not in events]
        events += added
        first = old["first_seen"] if old else at
        if f["kind"] == "detection":
            # A detection's times are its records' times, whatever order they arrived in.
            # The list is kept in record time; records mostly arrive in order, so it is
            # sorted again only when a new record is older than the last one it holds.
            if old and old["events"] and added:
                times = self.store.event_times(added + old["events"][-1:])

                def key(eid):
                    return times.get(eid, ""), eid

                if min(map(key, added)) < key(old["events"][-1]):
                    times = self.store.event_times(events)
                    events.sort(key=key)
            first = min(first, at)
        f = {**f, "events": events, "status": "open", "first_seen": first,
             "last_seen": max(at, old["last_seen"]) if old else at}
        self.store.put_finding(f)
        if not was_open:
            changes["opened"].append(f["finding_id"])
            if self.recorder is not None:
                self.recorder.append((f["finding_id"], at, "reopened" if old else "opened", self.cause))
        return f, was_open

    def _resolve(self, f, at, changes):
        self.store.put_finding({**f, "status": "resolved", "last_seen": max(at, f["last_seen"])})
        changes["resolved"].append(f["finding_id"])
        if self.recorder is not None:
            self.recorder.append((f["finding_id"], at, "resolved", self.cause))

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
            # Kept, not dropped: a snapshot that brings the role applies it if it is newer.
            return "pending", Delta()
        if ev["time"] < role["last_seen"]:
            # A snapshot taken after this record already shows its outcome.
            self.store.bump("model_change_older_than_model")
            return "older_than_model", Delta()
        a = dict(role["attrs"])
        key = aws_collector.change_key(change)
        if key is None:
            return "not_evaluated", self._mark(role, a, ev, f"{change['op']} at {ev['time']} names no policy;"
                                                            " not evaluated")
        entry = {"time": ev["time"], "op": aws_collector.CHANGE_OPS[change["op"]],
                 "doc": aws_collector.decode_document(change["document"]) if change["op"] == "PutRolePolicy" else None}
        changes = dict(a.get("policy_changes") or {})
        last = changes.get(key)
        if last and ev["time"] < last["time"]:
            # A newer change to this policy is already applied; this one is history.
            self.store.bump("model_change_superseded")
            return "superseded", Delta()
        if last and ev["time"] == last["time"] and (last["op"], last["doc"]) != (entry["op"], entry["doc"]):
            return "not_evaluated", self._mark(role, a, ev, f"two different changes to {key} at {ev['time']};"
                                                            " order unknown, not evaluated")
        changes[key] = entry
        new = aws_collector.apply_policy_change(a, key, entry)
        new["policy_changes"] = changes
        delta = Delta()
        if self.store.set_attrs(role["id"], new, observed_at=ev["time"]):
            delta.entity(role["id"], "iam_role")
        self.store.bump("model_changes_applied")
        return "applied", delta.merge(aws_collector.recompute_role(self.store, role["id"], ev["time"],
                                                                   "aws.cloudtrail"))

    def apply_change_record(self, ev, change):
        """One IAM change record: journal it, apply it if its order allows, and re-run the
        rules it can affect. Returns the opened and resolved finding IDs."""
        status, delta = self._apply_change(ev, change)
        if status == "pending":
            self.store.bump("model_change_role_not_in_model")
        self.store.add_model_change(ev["event_id"], ev["time"], change, status)
        return self.evaluate_delta(delta, self._model_time(ev["time"]))

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
            self.cause = ev["event_id"]
            changes = self.apply_change_record(ev, change)
        alerts = []
        for rule in self.detections.get((ev["source"], ev["action"]), []):
            self.evals[rule["id"]] += 1
            f = detect.evaluate(self.store, rule, ev)
            if f == detect.UNEVALUABLE:
                self.store.bump(f"unevaluable:{rule['id']}")
                self.store.hold(ev["event_id"], rule["id"], hints)
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
