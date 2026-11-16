"""Text output for people. Every string that came from the environment or the model goes
through v1's safe(), which escapes Markdown and HTML and breaks links and @-mentions.
Entity IDs are escaped too: they carry names an attacker may have chosen. Rule IDs,
hex IDs, severities and normalised times are produced by this code and printed as they are.

The one exception is a response plan's commands and manifest. Escaping would corrupt
them, so respond.py instead accepts only values that match strict patterns, and quotes
them for the shell.
"""

import json

from ..render import safe
from . import respond
from .schema import REFRESH_SECONDS, seconds_between
from .correlate import all_entities, members, timeline

COLLECTORS = ("aws.state", "k8s.state", "ai.inventory")
CHANGE_COUNTERS = {
    "model_change_role_not_in_model": "IAM change records for a role the model does not hold (not applied)",
    "model_change_not_evaluated": "IAM change records that could not be ordered (role marked not evaluated)",
    "model_change_superseded": "IAM change records older than a change already applied to the same policy",
    "model_change_older_than_model": "IAM change records older than the snapshot that confirmed the role",
}


def _list(values, limit=400):
    return ", ".join(safe(v, limit) for v in values) or "none"


def sources(store, now):
    """Every collector, including one that never ran or has not run lately: a source
    with no recent good run means the findings do not cover it."""
    lines = []
    for name in COLLECTORS:
        s = store.source(name)
        if s is None:
            lines.append(f"- source {name}: NEVER RUN. Nothing from it is in the model; findings do not cover it.")
        elif s["status"] != "ok":
            lines.append(f"- source {name}: FAILED at {s['last_attempt']}: {safe(s['error'] or '')}."
                         " Its facts are stale; results that depend on it are incomplete.")
        elif seconds_between(s["last_success"], now) > REFRESH_SECONDS[name]:
            lines.append(f"- source {name}: STALE, last good run {s['last_success']}, older than its refresh"
                         f" period of {REFRESH_SECONDS[name] // 3600} h.")
        else:
            lines.append(f"- source {name}: ok, last good run {s['last_success']}")
    return lines


def finding_lines(f):
    lines = [f"- [{f['status']}] {f['severity']} {f['rule_id']} v{int(f['rule_version'])}: {safe(f['title'], 300)}",
             f"  id {f['finding_id']}; primary {safe(f['primary_entity'], 300)}"]
    if f["path"]:
        lines.append(f"  path: {' -> '.join(safe(p, 300) for p in f['path'])}")
    if f["frameworks"]:
        lines.append(f"  frameworks: {_list(f['frameworks'])}")
    for n in f["notes"]:
        lines.append(f"  note: {safe(n, 400)}")
    lines.append(f"  first seen {f['first_seen']}, last seen {f['last_seen']}, events {len(f['events'])}")
    return lines


def findings(store, now, status=None):
    out = ["Sources:"] + sources(store, now) + ["", "Findings:"]
    rows = store.findings(status=status)
    for f in rows:
        out += finding_lines(f)
    if not rows:
        out.append("- none")
    counts = store.counters()
    skipped = {k: v for k, v in counts.items() if k.startswith("unevaluable:")}
    changes = {k: counts.get(k, 0) for k in CHANGE_COUNTERS}
    if skipped or counts.get("events_actor_null") or any(changes.values()):
        out += ["", "Not evaluated:"]
        out.append(f"- events whose actor was not resolved: {int(counts.get('events_actor_null', 0))}")
        for k, v in sorted(skipped.items()):
            out.append(f"- {safe(k.split(':', 1)[1])} could not evaluate {int(v)} events (actor not resolved)")
        for k, text in CHANGE_COUNTERS.items():
            if changes[k]:
                out.append(f"- {text}: {int(changes[k])}")
    return "\n".join(out) + "\n"


def event_line(ev):
    actor = safe(ev["actor"], 300) if ev["actor"] else "unresolved"
    ua = ev["attrs"].get("user_agent")
    extra = f"; user agent: {safe(ua, 300)}" if ua else ""
    return f"- {ev['time']} {safe(ev['action'], 200)} by {actor} ({ev['outcome']}){extra}"


def incident(store, inc):
    out = [f"Incident {inc['incident_id']} [{inc['status']}], {inc['first_seen']} to {inc['last_seen']}",
           f"Shared entities: {_list(inc['entities'], 300)}", "", "Findings:"]
    for f in members(store, inc):
        out += finding_lines(f)
    out += ["", "Entities (labels are text from the environment):"]
    for eid in sorted(all_entities(store, inc)):
        ent = store.entity(eid)
        if ent is None:
            continue
        flat = []
        for group, values in sorted(ent["labels"].items()):
            flat += [f"{group}.{k}={v}" for k, v in sorted(values.items())]
        out.append(f"- {safe(eid, 300)}" + (f": {_list(flat, 300)}" if flat else ""))
    out += ["", "Timeline:"] + [event_line(ev) for ev in timeline(store, inc)]
    return "\n".join(out) + "\n"


def incidents(store):
    rows = store.incidents()
    if not rows:
        return "No incidents.\n"
    return "\n".join(incident(store, i) for i in rows)


def plan(p):
    out = [f"Response plan for incident {p['incident_id']} (dry run: nothing has been executed)", ""]
    for n, step in enumerate(p["steps"], 1):
        r = respond.render(step)
        out.append(f"{n}. {step['action_id']}: {respond.CATALOG[step['action_id']]['summary']}")
        out.append(f"   because of: {_list(step.get('because', []))}")
        out += [f"   $ {c}" for c in r["commands"]]
        if r["manifest"]:
            out.append("   codeguardian-quarantine.yaml:")
            out += [f"     {line}" for line in r["manifest"].splitlines()]
        out.append(f"   note: {r['note']}")
    if not p["steps"]:
        out.append("No steps: no open finding in this incident has a catalog action.")
    for r in p["refused"]:
        out.append(f"- refused {safe(r['action_id'])}: {safe(r['reason'])}")
    return "\n".join(out) + "\n"


def explanation(result):
    out = [f"Explanation of incident {result['incident_id']} by {safe(result.get('served_by') or 'no model')}",
           "", safe(result["summary"], 1200), ""]
    for item in result["items"]:
        out.append(f"- {item['severity']} {item['rule_id']} [{item['status']}] {safe(item['title'], 300)}"
                   f" ({item['finding_id']})")
        if item["explained"]:
            out.append(f"  why it matters: {safe(item['explanation'])}")
            out.append(f"  next: {safe(item['next_step'])}")
        else:
            out.append("  not explained by the model")
    for a in result["actions"]:
        params = ", ".join(f"{k}={safe(v)}" for k, v in sorted(a["params"].items()))
        out.append(f"- model suggests {safe(a['action_id'])} ({params}); checked against the catalog, not executed")
    out.append(f"Entries dropped by validation: {len(result['dropped'])}. Findings come from rules; the model"
               " cannot add, close or change one.")
    return "\n".join(out) + "\n"


def answer(result):
    out = [f"Query (written by {safe(result.get('served_by') or 'no model')}, checked and run read-only):",
           safe(json.dumps(result["query"], sort_keys=True), 2000), f"Note: {safe(result.get('note', ''), 500)}", ""]
    out += [f"- {safe(r['id'], 300)}" + (f" (from {safe(r['from'], 300)})" if r["from"] != r["id"] else "")
            for r in result["rows"]] or ["- no rows"]
    if result["truncated"]:
        out.append("(stopped at the limit)")
    return "\n".join(out) + "\n"
