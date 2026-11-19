"""Turn a report into the Markdown comment posted on the pull request.

Both the scanner text and the model text can carry content an attacker wrote into the
pull request. Rendered as-is, it could add images that load an attacker's URL (leaking
data in the URL), links, HTML or @-mentions. So every untrusted string is escaped, and
only reference links on a short list of documentation hosts are kept.
"""

import re
from urllib.parse import urlparse

from .agents import ADVISORY_ROLES

MARKER = "<!-- codeguardian:report -->"

ALLOWED_LINK_HOSTS = {
    "semgrep.dev", "cwe.mitre.org", "owasp.org", "cheatsheetseries.owasp.org", "nvd.nist.gov",
    "www.cve.org", "avd.aquasec.com", "osv.dev", "github.com", "www.zaproxy.org", "zaproxy.org",
    "developer.mozilla.org",
}

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~>])")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def safe(text, limit=1500):
    """Escape untrusted text so GitHub renders it as plain words."""
    text = _CONTROL.sub("", str(text))[:limit]
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MD_SPECIAL.sub(r"\\\1", text)
    text = text.replace("@", "@\u200b")  # no mentions
    text = re.sub(r"(?i)(https?):/", "\\1:\u200b/", text)  # no autolinks
    text = re.sub(r"(?i)www\\\.", "www\u200b\\.", text)
    return " ".join(text.split())


def safe_link(url):
    try:
        parsed = urlparse(str(url))
    except ValueError:
        return ""
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_LINK_HOSTS:
        return ""
    if any(c in url for c in "()<> \"'"):
        return ""
    return f" ([reference]({url}))"


def render(report):
    items = report["items"]
    blocking = [i for i in items if i.get("blocking")]
    result = report.get("gate_result", "unknown")
    lines = [MARKER, "## CodeGuardian security review", ""]
    lines.append(f"**Gate:** {safe(result)}. **Findings:** {len(items)} ({len(blocking)} blocking).")
    if report.get("summary"):
        lines += ["", safe(report["summary"], 1200)]
    if items:
        lines += ["", "| # | Risk | Scanner | Rule | Where |", "|---|---|---|---|---|"]
        for i in items:
            where = f"{safe(i['file'], 200)}:{int(i['line'])}" if i["line"] else safe(i["file"], 200)
            lines.append(f"| {i['rank']} | {safe(i['risk'])}{' (blocking)' if i.get('blocking') else ''}"
                         f" | {safe(i['scanner'])} | {safe(i['rule_id'], 120)} | {where} |")
        lines.append("")
        for i in items:
            lines.append(f"**{i['rank']}. {safe(i['title'], 200)}**{safe_link(i.get('url', ''))}")
            if i.get("explained"):
                lines.append(f"- Why it matters: {safe(i['explanation'])}")
                lines.append(f"- Fix: {safe(i['fix'])}")
                if i.get("likely_false_positive"):
                    lines.append("- The reviewer thinks this may be a false positive. A person should confirm.")
            else:
                lines.append(f"- Scanner says: {safe(i.get('message', ''))}")
            lines.append("")
    advisories = report.get("advisories", {})
    advisory_lines = []
    for role in ADVISORY_ROLES:
        result = advisories.get(role)
        if result is None:
            continue
        if result["note"]:
            advisory_lines.append(f"- **{role}** {safe(result['note'])}")
        elif result["status"] == "refused":
            advisory_lines.append(f"- **{role}** The model declined the request. Advisory review stopped.")
        elif result["status"] == "unavailable":
            advisory_lines.append(f"- **{role}** The model request failed. Advisory review stopped.")
    if advisory_lines:
        lines += ["", "### Advisory review", "", *advisory_lines, ""]
    model = report.get("served_by") or report.get("model")
    lines.append(f"<sub>Scanner findings explained and ranked by {safe(model or 'no model (nothing to explain)')}."
                 f" Every finding comes from a scanner rule; the model cannot add one."
                 f" Entries dropped by validation: {int(report.get('dropped_model_entries', 0))}.</sub>")
    return "\n".join(lines) + "\n"
