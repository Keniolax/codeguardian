"""SQLite store for the one model of the environment: entities, edges, events, findings,
incidents, and the health of each source.

A fact is never deleted because nobody looked. It is marked deleted only when a full
snapshot from its own collector no longer lists it, or when an event says it was removed.
Staleness is worked out on read from the source's last good run and refresh period, so a
collector that stops working makes its facts stale without any write.
"""

import json
import os
import sqlite3

from .schema import ENTITY_TYPES, EDGE_TYPES, REFRESH_SECONDS, edge_id, seconds_between

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, domain TEXT NOT NULL, attrs TEXT NOT NULL,
  labels TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, deleted_at TEXT);
CREATE INDEX IF NOT EXISTS entities_type ON entities(type);
CREATE TABLE IF NOT EXISTS edges (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
  attrs TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, deleted_at TEXT);
CREATE INDEX IF NOT EXISTS edges_src ON edges(src, type);
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst, type);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, time TEXT NOT NULL, ingested_at TEXT NOT NULL,
  source TEXT NOT NULL, domain TEXT NOT NULL, action TEXT NOT NULL, actor TEXT,
  targets TEXT NOT NULL, outcome TEXT NOT NULL, attrs TEXT NOT NULL, raw_ref TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_actor ON events(actor, time);
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY, kind TEXT NOT NULL, rule_id TEXT NOT NULL,
  rule_version INTEGER NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
  primary_entity TEXT NOT NULL, entities TEXT NOT NULL, path TEXT NOT NULL,
  events TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  status TEXT NOT NULL, frameworks TEXT NOT NULL, notes TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_rule ON findings(rule_id, status);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, finding_ids TEXT NOT NULL, entities TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY, status TEXT NOT NULL, last_success TEXT, last_attempt TEXT NOT NULL,
  error TEXT);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (
  source TEXT NOT NULL, at TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL,
  received_at TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY (source, at, digest));
CREATE TABLE IF NOT EXISTS model_changes (
  event_id TEXT PRIMARY KEY, time TEXT NOT NULL, change TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS held (
  event_id TEXT NOT NULL, rule_id TEXT NOT NULL, hints TEXT NOT NULL, PRIMARY KEY (event_id, rule_id));
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

_J = json.dumps


def _row(row, json_fields):
    if row is None:
        return None
    out = dict(row)
    for f in json_fields:
        out[f] = json.loads(out[f])
    return out


ENTITY_JSON = ("attrs", "labels")
EDGE_JSON = ("attrs",)
EVENT_JSON = ("targets", "attrs")
FINDING_JSON = ("entities", "path", "events", "frameworks", "notes")
INCIDENT_JSON = ("finding_ids", "entities")


class Store:
    def __init__(self, path=":memory:"):
        if str(path) != ":memory:":
            # The model holds the same real data as the export files, so it gets their mode.
            os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
            os.chmod(path, 0o600)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.close()

    # --- entities ------------------------------------------------------------------------

    def upsert_entity(self, eid, etype, attrs, labels, source, at, observed_at=None):
        """Write an entity. Returns True when anything a rule could see changed. observed_at
        is the time the attrs describe, when that is later than the snapshot (changes from
        records newer than the snapshot applied on top)."""
        observed_at = observed_at or at
        if etype not in ENTITY_TYPES:
            raise ValueError(f"unknown entity type {etype!r}")
        domain = ENTITY_TYPES[etype][1]
        old = self.entity(eid, include_deleted=True)
        a, lab = _J(attrs, sort_keys=True), _J(labels, sort_keys=True)
        if old is None:
            self.db.execute("INSERT INTO entities VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                            (eid, etype, domain, a, lab, source, observed_at, at, at))
            return True
        changed = (old["deleted_at"] is not None or _J(old["attrs"], sort_keys=True) != a
                   or _J(old["labels"], sort_keys=True) != lab)
        self.db.execute(
            "UPDATE entities SET attrs=?, labels=?, source=?, observed_at=?, last_seen=MAX(last_seen, ?),"
            " deleted_at=NULL WHERE id=?", (a, lab, source, observed_at, at, eid))
        return changed

    def set_attrs(self, eid, attrs, observed_at=None):
        """Change derived or event-applied attrs without claiming the collector saw it again."""
        a = _J(attrs, sort_keys=True)
        old = self.db.execute("SELECT attrs FROM entities WHERE id=?", (eid,)).fetchone()
        if old is None or old["attrs"] == a:
            return False
        self.db.execute("UPDATE entities SET attrs=?, observed_at=COALESCE(?, observed_at) WHERE id=?",
                        (a, observed_at, eid))
        return True

    def entity(self, eid, include_deleted=False):
        q = "SELECT * FROM entities WHERE id=?" + ("" if include_deleted else " AND deleted_at IS NULL")
        return _row(self.db.execute(q, (eid,)).fetchone(), ENTITY_JSON)

    def find_by_name(self, etype, name):
        """The one live entity of a type with this name. CloudTrail names a role only by its
        name; with more than one match (two accounts) the answer is None, not a guess."""
        rows = self.db.execute("SELECT * FROM entities WHERE type=? AND deleted_at IS NULL"
                               " AND json_extract(attrs, '$.name')=? LIMIT 2", (etype, name)).fetchall()
        return _row(rows[0], ENTITY_JSON) if len(rows) == 1 else None

    def entities(self, etype=None, source=None):
        q, args = "SELECT * FROM entities WHERE deleted_at IS NULL", []
        if etype:
            q, args = q + " AND type=?", args + [etype]
        if source:
            q, args = q + " AND source=?", args + [source]
        return [_row(r, ENTITY_JSON) for r in self.db.execute(q + " ORDER BY id", args)]

    def delete_entity(self, eid, at):
        """Mark an entity deleted. Its edges stay as they are: traversal only enters live
        entities, and another collector's edge to it is that collector's fact."""
        self.db.execute("UPDATE entities SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (at, eid))
        return []

    # --- edges ---------------------------------------------------------------------------

    def upsert_edge(self, etype, src, dst, attrs, source, at):
        if etype not in EDGE_TYPES:
            raise ValueError(f"unknown edge type {etype!r}")
        xid = edge_id(etype, src, dst)
        old = self.db.execute("SELECT attrs, deleted_at FROM edges WHERE id=?", (xid,)).fetchone()
        a = _J(attrs, sort_keys=True)
        if old is None:
            self.db.execute("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                            (xid, etype, src, dst, a, source, at, at, at))
            return xid, True
        changed = old["deleted_at"] is not None or old["attrs"] != a
        self.db.execute("UPDATE edges SET attrs=?, source=?, observed_at=?, last_seen=MAX(last_seen, ?),"
                        " deleted_at=NULL WHERE id=?", (a, source, at, at, xid))
        return xid, changed

    def delete_edge(self, xid, at):
        cur = self.db.execute("UPDATE edges SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (at, xid))
        return cur.rowcount > 0

    def edges(self, node=None, etype=None, direction="out", include_deleted=False):
        q, args = "SELECT * FROM edges WHERE 1=1", []
        if not include_deleted:
            q += " AND deleted_at IS NULL"
        if node is not None:
            q, args = q + (" AND src=?" if direction == "out" else " AND dst=?"), args + [node]
        if etype:
            q, args = q + " AND type=?", args + [etype]
        return [_row(r, EDGE_JSON) for r in self.db.execute(q + " ORDER BY id", args)]

    def edge(self, xid):
        return _row(self.db.execute("SELECT * FROM edges WHERE id=?", (xid,)).fetchone(), EDGE_JSON)

    def sweep(self, source, seen_entities, seen_edges, at):
        """After a full snapshot: what this source wrote before and did not list now is gone."""
        gone_entities, gone_edges = [], []
        for r in self.db.execute("SELECT id, type FROM entities WHERE source=? AND deleted_at IS NULL",
                                 (source,)).fetchall():
            if r["id"] not in seen_entities:
                gone_entities.append((r["id"], r["type"]))
        for eid, _ in gone_entities:
            gone_edges += self.delete_entity(eid, at)
        for r in self.db.execute("SELECT id, type FROM edges WHERE source=? AND deleted_at IS NULL",
                                 (source,)).fetchall():
            if r["id"] not in seen_edges:
                self.delete_edge(r["id"], at)
                gone_edges.append((r["id"], r["type"]))
        return gone_entities, gone_edges

    # --- sources and staleness -----------------------------------------------------------

    def record_source(self, name, ok, at, error=None):
        old = self.source(name)
        if ok and old and old["status"] == "failed" and old["last_attempt"] >= at:
            # An export at this time or later failed. This snapshot is older, so the failure
            # still stands and the facts stay stale, as they would had it arrived first.
            self.db.execute("UPDATE sources SET last_success=? WHERE name=?",
                            (max(at, old["last_success"] or at), name))
            return
        last_success = at if ok else (old["last_success"] if old else None)
        self.db.execute("INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?)",
                        (name, "ok" if ok else "failed", last_success, at, error))

    def source(self, name):
        r = self.db.execute("SELECT * FROM sources WHERE name=?", (name,)).fetchone()
        return dict(r) if r else None

    def sources(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM sources ORDER BY name")]

    def is_stale(self, fact, now):
        """A fact is stale when its collector failed, never ran, or has not confirmed it
        within the refresh period. Stale facts still count as present: not having looked
        must never read as safe."""
        source = fact["source"]
        period = REFRESH_SECONDS.get(source)
        if source in ("builtin", "link"):
            return False
        collector = "aws.state" if source == "aws.cloudtrail" else source
        health = self.source(collector)
        if health is None or health["status"] != "ok":
            return True
        return period is not None and seconds_between(fact["last_seen"], now) > period

    # --- events --------------------------------------------------------------------------

    def has_event(self, eid):
        return self.db.execute("SELECT 1 FROM events WHERE event_id=?", (eid,)).fetchone() is not None

    def add_event(self, ev):
        cur = self.db.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ev["event_id"], ev["time"], ev["ingested_at"], ev["source"], ev["domain"], ev["action"],
             ev["actor"], _J(ev["targets"]), ev["outcome"], _J(ev["attrs"], sort_keys=True), ev["raw_ref"]))
        return cur.rowcount > 0

    def event(self, eid):
        return _row(self.db.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone(), EVENT_JSON)

    def events_by_actor(self, actors, start, end):
        if not actors:
            return []
        marks = ",".join("?" * len(actors))
        rows = self.db.execute(f"SELECT * FROM events WHERE actor IN ({marks}) AND time>=? AND time<=?"
                               " ORDER BY time, event_id", [*actors, start, end])
        return [_row(r, EVENT_JSON) for r in rows]

    def event_times(self, eids):
        rows = self.db.execute("SELECT event_id, time FROM events WHERE event_id IN (SELECT value FROM json_each(?))",
                               (_J(list(eids)),))
        return {r["event_id"]: r["time"] for r in rows}

    def count_events(self):
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # --- findings ------------------------------------------------------------------------

    def finding(self, fid):
        return _row(self.db.execute("SELECT * FROM findings WHERE finding_id=?", (fid,)).fetchone(), FINDING_JSON)

    def findings(self, status=None, rule_id=None, kind=None):
        q, args = "SELECT * FROM findings WHERE 1=1", []
        for col, val in (("status", status), ("rule_id", rule_id), ("kind", kind)):
            if val:
                q, args = q + f" AND {col}=?", args + [val]
        return [_row(r, FINDING_JSON) for r in self.db.execute(q + " ORDER BY first_seen, finding_id", args)]

    def put_finding(self, f):
        self.db.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f["finding_id"], f["kind"], f["rule_id"], f["rule_version"], f["severity"], f["title"],
             f["primary_entity"], _J(f["entities"]), _J(f["path"]), _J(f["events"]), f["first_seen"],
             f["last_seen"], f["status"], _J(f["frameworks"]), _J(f["notes"])))

    # --- incidents -----------------------------------------------------------------------

    def incident(self, iid):
        return _row(self.db.execute("SELECT * FROM incidents WHERE incident_id=?", (iid,)).fetchone(),
                    INCIDENT_JSON)

    def incidents(self, status=None):
        q, args = "SELECT * FROM incidents", []
        if status:
            q, args = q + " WHERE status=?", [status]
        return [_row(r, INCIDENT_JSON) for r in self.db.execute(q + " ORDER BY first_seen, incident_id", args)]

    def put_incident(self, inc):
        self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?)",
                        (inc["incident_id"], _J(inc["finding_ids"]), _J(inc["entities"]),
                         inc["first_seen"], inc["last_seen"], inc["status"]))

    def drop_incident(self, iid):
        self.db.execute("DELETE FROM incidents WHERE incident_id=?", (iid,))

    # --- the journal: every snapshot and IAM change record, for the history ---------------

    def snapshot_entries(self, source, at):
        rows = self.db.execute("SELECT digest, status FROM snapshots WHERE source=? AND at=?", (source, at))
        return [dict(r) for r in rows]

    def add_snapshot(self, source, at, digest, status, received_at, content):
        self.db.execute("INSERT OR IGNORE INTO snapshots VALUES (?,?,?,?,?,?)",
                        (source, at, digest, status, received_at, content))

    def snapshots(self, statuses=None):
        rows = [dict(r) for r in self.db.execute("SELECT * FROM snapshots ORDER BY at, source, digest")]
        return [r for r in rows if statuses is None or r["status"] in statuses]

    def add_model_change(self, event_id, time, change, status):
        self.db.execute("INSERT OR IGNORE INTO model_changes VALUES (?,?,?,?)",
                        (event_id, time, _J(change, sort_keys=True), status))

    def set_model_change_status(self, event_id, status):
        self.db.execute("UPDATE model_changes SET status=? WHERE event_id=?", (status, event_id))

    def model_changes(self, status=None):
        q, args = "SELECT * FROM model_changes", []
        if status:
            q, args = q + " WHERE status=?", [status]
        return [_row(r, ("change",)) for r in self.db.execute(q + " ORDER BY time, event_id", args)]

    # --- detections held until the model holds what they need ------------------------------

    def hold(self, event_id, rule_id, hints):
        self.db.execute("INSERT OR IGNORE INTO held VALUES (?,?,?)", (event_id, rule_id, _J(hints)))

    def unhold(self, event_id, rule_id):
        self.db.execute("DELETE FROM held WHERE event_id=? AND rule_id=?", (event_id, rule_id))

    def held(self):
        rows = self.db.execute("SELECT held.event_id, held.rule_id, held.hints FROM held JOIN events"
                               " ON events.event_id = held.event_id ORDER BY events.time, held.event_id, held.rule_id")
        return [_row(r, ("hints",)) for r in rows]

    def set_event_refs(self, event_id, actor, targets):
        self.db.execute("UPDATE events SET actor=?, targets=? WHERE event_id=?", (actor, _J(targets), event_id))

    # --- counters ------------------------------------------------------------------------

    def bump(self, name, by=1):
        self.db.execute("INSERT INTO counters VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+?",
                        (name, by, by))

    def setting(self, name):
        r = self.db.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()
        return r["value"] if r else None

    def set_setting(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (name, value))

    def counters(self):
        return {r["name"]: r["value"] for r in self.db.execute("SELECT * FROM counters ORDER BY name")}
