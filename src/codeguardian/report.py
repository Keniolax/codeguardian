"""The report contract between the model and everything that touches GitHub.

The model returns judgements keyed by finding ID. This module checks that output and joins
it with the scanner findings. Scanner, rule, file and line always come from the scanner
artifact, never from the model, so the model can rank and explain findings but cannot
invent one, move one, or hide one.
"""

from .agents import ADVISORY_ROLES, ADVISORY_STATUSES, MAX_ADVISORY_NOTE

RISKS = ("critical", "high", "medium", "low", "info")

# JSON schema sent to the model as a structured-output format.
AGENT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "rank": {"type": "integer"},
                    "risk": {"type": "string", "enum": list(RISKS)},
                    "explanation": {"type": "string"},
                    "fix": {"type": "string"},
                    "likely_false_positive": {"type": "boolean"},
                },
                "required": ["finding_id", "rank", "risk", "explanation", "fix", "likely_false_positive"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "findings"],
    "additionalProperties": False,
}

MAX_SUMMARY = 1200
MAX_TEXT = 1500


class ReportError(ValueError):
    pass


def _text(value, limit):
    if not isinstance(value, str):
        raise ReportError("expected a string")
    return value.strip()[:limit]


def validate_agent_output(raw, findings):
    """Check the model's JSON and join it with the scanner findings.

    Returns (items, dropped). Entries that name an unknown or repeated finding ID are
    dropped and counted. Findings the model skipped are kept, marked unexplained.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
        raise ReportError("model output is not an object with a findings list")
    by_id = {f["id"]: f for f in findings}
    items, seen, dropped = [], set(), []
    for entry in raw["findings"]:
        try:
            fid = entry["finding_id"]
            if fid not in by_id or fid in seen:
                raise ReportError(f"unknown or repeated finding_id {fid!r}")
            risk = entry["risk"]
            if risk not in RISKS:
                raise ReportError(f"bad risk {risk!r}")
            rank = entry["rank"]
            if not isinstance(rank, int) or isinstance(rank, bool):
                raise ReportError("rank must be an integer")
            explanation, fix = _text(entry["explanation"], MAX_TEXT), _text(entry["fix"], MAX_TEXT)
            likely_fp, locked = bool(entry["likely_false_positive"]), False
            if by_id[fid].get("blocking"):
                # The model reads text the PR author wrote, so it may not lower or clear a
                # blocking finding. Only a reviewed entry in the suppressions file clears one.
                floor = by_id[fid].get("severity")
                if floor in RISKS and RISKS.index(risk) > RISKS.index(floor):
                    risk, locked = floor, True
                if likely_fp:
                    likely_fp, locked = False, True
            items.append({
                **by_id[fid],
                "rank": rank,
                "risk": risk,
                "explanation": explanation,
                "fix": fix,
                "likely_false_positive": likely_fp,
                "verdict_locked": locked,
                "explained": True,
            })
            seen.add(fid)
        except (KeyError, TypeError, ReportError) as exc:
            dropped.append(str(exc))
    for f in findings:
        if f["id"] not in seen:
            items.append({**f, "rank": 10_000, "risk": f["severity"], "explanation": "",
                          "fix": "", "likely_false_positive": False, "verdict_locked": False,
                          "explained": False})
    items.sort(key=lambda i: (i["rank"], RISKS.index(i["risk"]) if i["risk"] in RISKS else 9))
    for n, item in enumerate(items, 1):
        item["rank"] = n
    return items, dropped


def build_report(*, pr, gate_result, items, dropped, summary, model, served_by, usage):
    return {
        "version": 1,
        "pr": pr,
        "gate_result": gate_result,
        "summary": _text(summary or "", MAX_SUMMARY),
        "items": items,
        "dropped_model_entries": len(dropped),
        "model": model,
        "served_by": served_by,
        "usage": usage,
    }


def check_report(report):
    """Re-check a report file before posting it. The post job trusts nothing it downloads."""
    if not isinstance(report, dict) or report.get("version") != 1:
        raise ReportError("not a version 1 report")
    pr = report.get("pr") or {}
    if not isinstance(pr.get("number"), int) or isinstance(pr.get("number"), bool) or pr["number"] <= 0:
        raise ReportError("pr.number must be a positive integer")
    if not isinstance(report.get("items"), list):
        raise ReportError("items must be a list")
    for item in report["items"]:
        for key in ("scanner", "rule_id", "file", "title", "explanation", "fix", "risk"):
            if not isinstance(item.get(key), str):
                raise ReportError(f"item field {key} must be a string")
        if not isinstance(item.get("line"), int):
            raise ReportError("item line must be an integer")
        if item.get("blocking") and item.get("likely_false_positive"):
            raise ReportError("a blocking finding cannot be marked a likely false positive")
        floor = item.get("severity")
        if item.get("blocking") and floor in RISKS and item["risk"] in RISKS \
                and RISKS.index(item["risk"]) > RISKS.index(floor):
            raise ReportError("a blocking finding cannot be ranked below its scanner severity")
    advisories = report.get("advisories", {})
    if not isinstance(advisories, dict):
        raise ReportError("advisories must be an object")
    for role, result in advisories.items():
        if role not in ADVISORY_ROLES or not isinstance(result, dict) or result.keys() != {"status", "note", "served_by"}:
            raise ReportError("advisories must map known roles to results")
        status, note, model = result["status"], result["note"], result["served_by"]
        if not (isinstance(status, str) and status in ADVISORY_STATUSES
                and isinstance(note, str) and len(note) <= MAX_ADVISORY_NOTE
                and (status == "complete" or not note)
                and (model is None or isinstance(model, str))):
            raise ReportError("advisories contain an invalid result")
    return report
