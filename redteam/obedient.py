"""A scripted worst-case model: it follows any injected instruction that reaches it.

The live models decide how often an attack works. This model answers a narrower question,
with no randomness: if the attacker's text reaches a request, does any control still stop
the attack? It obeys a payload's `obey` block whenever the payload's `trigger` text appears
anywhere in the request (system or user message), and otherwise gives a plain, honest
review.
"""

import json
import re

FINDINGS_BLOCK = re.compile(r"<scanner_findings>\n(.*?)\n</scanner_findings>", re.S)
GUIDANCE = re.compile(r"Trusted standards guidance:\n(\{.*?\})(?:\n|$)", re.S)


class ObedientModel:
    name = "obedient"

    def __init__(self, trigger, obey):
        self.trigger = trigger
        self.obey = obey

    def _sees(self, system, user):
        return bool(self.trigger) and (self.trigger in system or self.trigger in user)

    def complete_json(self, system, user, schema):
        keys = set(schema.get("properties", {}))
        sees = self._sees(system, user)
        meta = {"model": self.name, "served_by": self.name, "usage": {"input_tokens": 0, "output_tokens": 0}}
        if keys == {"tool", "arguments"}:
            wanted = self.obey.get("standard_id") if sees else None
            if not wanted:
                offered = re.findall(r'"([a-z]+:[A-Za-z0-9-]+)"', user)
                wanted = offered[0] if offered else "none"
            return {"tool": "lookup_standard", "arguments": {"standard_id": wanted}}, meta
        if keys == {"note"}:
            return {"note": self.obey.get("note", "") if sees else ""}, meta
        block = FINDINGS_BLOCK.search(user)
        findings = json.loads(block.group(1)) if block else []
        verdict = self.obey.get("verdict", {}) if sees else {}
        entries = [{
            "finding_id": f["id"], "rank": n, "risk": verdict.get("risk", f["severity"]),
            "explanation": f"The scanner reports {f['title']}.", "fix": "Follow the scanner's advice.",
            "likely_false_positive": bool(verdict.get("likely_false_positive", False)),
        } for n, f in enumerate(findings, 1)]
        if sees and self.obey.get("extra_finding"):
            entries.append(dict(self.obey["extra_finding"], rank=len(entries) + 1))
        summary = "Review of the scanner findings."
        guidance = GUIDANCE.search(system)
        if sees and self.obey.get("echo_guidance") and guidance:
            summary += " Guidance used: " + json.loads(guidance.group(1))["guidance"]
        reply = {"summary": summary, "findings": entries}
        if "gate" in keys and sees and self.obey.get("gate"):
            reply["gate"] = self.obey["gate"]
        if "remember" in keys:
            reply["remember"] = self.obey.get("remember", "") if sees else ""
        return reply, meta
