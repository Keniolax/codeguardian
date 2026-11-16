"""Correlation: findings that share an entity, inside a time window, form one incident.

Detections carry event times. Posture and path findings describe the current state, so an
open one joins any open incident it shares an entity with, as long as the incident is
recent. The internet node is left out of the join key: every exposed service touches it,
so it would join unrelated findings.
"""

from .schema import incident_id, seconds_between, shift

WINDOW_SECONDS = 1800
HUB_TYPES = {"internet"}


def _key(entities):
    return {e for e in entities if e.split(":", 2)[1] not in HUB_TYPES}


def members(store, inc):
    return [f for f in (store.finding(fid) for fid in inc["finding_ids"]) if f]


def all_entities(store, inc):
    out = set()
    for f in members(store, inc):
        out |= _key(f["entities"])
    return out


def _shared(store, inc):
    counts = {}
    for f in members(store, inc):
        for e in _key(f["entities"]):
            counts[e] = counts.get(e, 0) + 1
    return sorted(e for e, n in counts.items() if n >= 2)


def _near(inc, at):
    return (seconds_between(inc["last_seen"], at) <= WINDOW_SECONDS
            and seconds_between(at, inc["first_seen"]) <= WINDOW_SECONDS)


def _save(store, inc):
    inc["entities"] = _shared(store, inc)
    store.put_incident(inc)
    return inc


def add_detection(store, finding, at):
    """Place a detection finding in an incident. Returns the incident."""
    key = _key(finding["entities"])
    hits = [i for i in store.incidents("open") if _near(i, at) and key & all_entities(store, i)]
    if not hits:
        inc = {"incident_id": incident_id(finding["finding_id"], at), "finding_ids": [finding["finding_id"]],
               "entities": [], "first_seen": at, "last_seen": at, "status": "open"}
    else:
        # A finding that touches two incidents joins them; the oldest keeps its ID.
        hits.sort(key=lambda i: (i["first_seen"], i["incident_id"]))
        inc = hits[0]
        for other in hits[1:]:
            inc["finding_ids"] += [f for f in other["finding_ids"] if f not in inc["finding_ids"]]
            inc["first_seen"] = min(inc["first_seen"], other["first_seen"])
            inc["last_seen"] = max(inc["last_seen"], other["last_seen"])
            store.drop_incident(other["incident_id"])
        if finding["finding_id"] not in inc["finding_ids"]:
            inc["finding_ids"].append(finding["finding_id"])
        inc["first_seen"] = min(inc["first_seen"], at)
        inc["last_seen"] = max(inc["last_seen"], at)
    # Pull in the open state findings this incident now touches.
    ents = all_entities(store, inc)
    for f in store.findings(status="open"):
        if f["kind"] != "detection" and f["finding_id"] not in inc["finding_ids"] and _key(f["entities"]) & ents:
            inc["finding_ids"].append(f["finding_id"])
    return _save(store, inc)


def add_state(store, finding, at):
    """A posture or path finding that just opened joins recent incidents it touches."""
    key = _key(finding["entities"])
    joined = []
    for inc in store.incidents("open"):
        if finding["finding_id"] in inc["finding_ids"] or not _near(inc, at):
            continue
        if key & all_entities(store, inc):
            inc["finding_ids"].append(finding["finding_id"])
            joined.append(_save(store, inc))
    return joined


def timeline(store, inc):
    """Events of the member findings, plus every event made by an entity the incident
    touches, inside the window around it."""
    seen, out = set(), []
    for f in members(store, inc):
        for eid in f["events"]:
            ev = store.event(eid)
            if ev and eid not in seen:
                seen.add(eid)
                out.append(ev)
    start, end = shift(inc["first_seen"], -WINDOW_SECONDS), shift(inc["last_seen"], WINDOW_SECONDS)
    for ev in store.events_by_actor(sorted(all_entities(store, inc)), start, end):
        if ev["event_id"] not in seen:
            seen.add(ev["event_id"])
            out.append(ev)
    return sorted(out, key=lambda e: (e["time"], e["event_id"]))
