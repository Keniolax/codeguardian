"""Posture rules: conditions on one entity's typed attrs."""

from . import rules as R
from .schema import finding_id


def evaluate(store, rule, ent, now):
    """Returns the finding this entity raises under the rule, or None."""
    if ent is None or ent["type"] != rule["entity"]:
        return None
    if not all(R.check(c, ent["attrs"]) for c in rule["where"]):
        return None
    notes = [f"stale: {ent['id']} not confirmed recently"] if store.is_stale(ent, now) else []
    notes += ent["attrs"].get("not_evaluated", []) if ent["type"] == "iam_role" else []
    unknown = ent["attrs"].get("unknown_policy_documents") if ent["type"] == "iam_role" else None
    if unknown:
        notes.append("policy documents not in the model: " + ", ".join(unknown))
    return {
        "finding_id": finding_id(rule["id"], ent["id"], []), "kind": "posture", "rule_id": rule["id"],
        "rule_version": rule["version"], "severity": rule["severity"], "title": rule["title"],
        "primary_entity": ent["id"], "entities": [ent["id"]], "path": [], "events": [],
        "frameworks": rule["frameworks"], "notes": sorted(set(notes)),
    }
