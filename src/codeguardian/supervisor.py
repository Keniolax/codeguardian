"""The supervisor: plain code that decides which agents run and assembles one report.

The Security agent explains scanner findings. Optional advisory reviewers add notes about
the diff. The scanner artifact supplies the gate decision and findings.
"""

import json
import time
from pathlib import Path

from .agents import MAX_FINDINGS, SecurityAgent, changed_paths, review_advisories
from .github import protected_changes
from .report import AGENT_OUTPUT_SCHEMA, build_report, validate_agent_output

PROTECTED_SUMMARY = (
    "This pull request changes protected CodeGuardian or gate configuration. CodeGuardian does not"
    " ask a model about such a change, because text in the pull request can steer what a model says."
    " Read the diff yourself. The config guard needs the designated maintainer's approval of this commit."
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_input(directory):
    d = Path(directory)
    decision = json.loads((d / "decision.json").read_text(encoding="utf-8"))
    pr = json.loads((d / "pr.json").read_text(encoding="utf-8"))
    patch = (d / "change.diff").read_text(encoding="utf-8", errors="replace") if (d / "change.diff").exists() else ""
    number = pr.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise ValueError("pr.json number must be a positive integer")
    return decision, {"number": number, "head_sha": str(pr.get("head_sha", ""))[:40]}, patch


def candidate_findings(decision):
    blocking = [dict(f, blocking=True) for f in decision.get("blocking", [])]
    reported = [dict(f, blocking=False) for f in decision.get("reported", [])]
    ordered = sorted(blocking, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5)) + \
        sorted(reported, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return ordered[:MAX_FINDINGS]


def protected_in(patch):
    return protected_changes(changed_paths(patch))


def review(directory, provider, *, with_standards=False, with_reviewers=False):
    decision, pr, patch = load_input(directory)
    findings = candidate_findings(decision)
    started = time.monotonic()
    protected = protected_in(patch)
    if protected:
        # The human approval is the control for these files. No model text sits next to it.
        items, dropped = validate_agent_output({"summary": "", "findings": []}, findings)
        report = build_report(pr=pr, gate_result=decision.get("result", "unknown"), items=items, dropped=dropped,
                              summary=PROTECTED_SUMMARY, model=None, served_by=None, usage={"seconds": 0})
        report["model_skipped"] = "protected-config"
        return report
    if findings:
        raw, meta = SecurityAgent(provider).run(findings, patch, AGENT_OUTPUT_SCHEMA,
                                                with_standards=with_standards)
        items, dropped = validate_agent_output(raw, findings)
        summary = raw.get("summary", "")
    else:
        items, dropped, meta = [], [], {}
        summary = "The scanners found nothing new in this change."
    usage = dict(meta.get("usage", {}))
    report = build_report(pr=pr, gate_result=decision.get("result", "unknown"), items=items, dropped=dropped,
                          summary=summary, model=meta.get("model"), served_by=meta.get("served_by"), usage=usage)
    if with_reviewers and patch.strip():
        report["advisories"] = review_advisories(provider, patch, usage)
    usage["seconds"] = round(time.monotonic() - started, 1) if findings or "advisories" in report else 0
    return report
