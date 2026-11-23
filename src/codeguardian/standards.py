"""Read-only access to bundled review guidance."""

import json

STANDARDS = {
    "trivy:DS-0002": "Use a non-root user in the final container image.",
    "zap:10020": "Set an explicit framing policy with Content-Security-Policy frame-ancestors.",
}

LOOKUP_SCHEMA = {
    "type": "object",
    "properties": {
        "tool": {"type": "string", "enum": ["lookup_standard"]},
        "arguments": {
            "type": "object",
            "properties": {"standard_id": {"type": "string"}},
            "required": ["standard_id"],
            "additionalProperties": False,
        },
    },
    "required": ["tool", "arguments"],
    "additionalProperties": False,
}


def lookup_standard(proposal, allowed_ids):
    if not isinstance(proposal, dict) or proposal.keys() != {"tool", "arguments"}:
        return None
    if proposal["tool"] != "lookup_standard":
        return None
    arguments = proposal["arguments"]
    if not isinstance(arguments, dict) or arguments.keys() != {"standard_id"}:
        return None
    standard_id = arguments["standard_id"]
    if not isinstance(standard_id, str) or standard_id not in allowed_ids:
        return None
    return {"id": standard_id, "guidance": STANDARDS[standard_id]}


def request_standard(provider, findings):
    rule_ids = {f"{finding['scanner']}:{finding['rule_id']}" for finding in findings}
    allowed_ids = rule_ids & STANDARDS.keys()
    if not allowed_ids:
        return None, {}
    proposal, meta = provider.complete_json(
        "Request one lookup_standard call using a standard_id from the supplied list.",
        json.dumps(sorted(allowed_ids)),
        LOOKUP_SCHEMA,
    )
    return lookup_standard(proposal, allowed_ids), meta.get("usage", {})
