"""Write the Week 14 and Week 17 architecture sources for Excaliflow."""

import json
import random
from pathlib import Path

random.seed(14)
CARBON, BLUE, PURPLE, EMERALD, AMBER, ROSE, CYAN = (
    "#171717", "#0070f3", "#7928ca", "#10b981", "#f59e0b", "#ef4444", "#06b6d4")
TINT = {BLUE: "#e6f0ff", PURPLE: "#f3e8ff", EMERALD: "#e7f8f2", AMBER: "#fff4e0", ROSE: "#fdecec",
        CYAN: "#e6f8fb", CARBON: "#f4f4f5"}
els = []


def base(kind, x, y, w, h, stroke, **kw):
    e = {"id": f"e{len(els)}", "type": kind, "x": x, "y": y, "width": w, "height": h, "angle": 0,
         "strokeColor": stroke, "backgroundColor": "transparent", "fillStyle": "solid", "strokeWidth": 2,
         "strokeStyle": "solid", "roughness": 1, "opacity": 100, "groupIds": [], "frameId": None,
         "roundness": None, "seed": random.randint(1, 2**31), "version": 1,
         "versionNonce": random.randint(1, 2**31), "isDeleted": False, "boundElements": [], "updated": 1,
         "link": None, "locked": False}
    e.update(kw)
    els.append(e)
    return e


def text(x, y, s, size=18, color=CARBON, align="left"):
    lines = s.split("\n")
    w = max(len(l) for l in lines) * size * 0.55
    h = len(lines) * size * 1.25
    if align == "center":
        x -= w / 2
    return base("text", x, y, w, h, color, strokeWidth=1, text=s, fontSize=size, fontFamily=2,
                textAlign=align, verticalAlign="top", baseline=size, containerId=None, originalText=s,
                lineHeight=1.25)


def box(x, y, w, h, color, title, sub=""):
    base("rectangle", x, y, w, h, color, backgroundColor=TINT[color], roundness={"type": 3})
    text(x + w / 2, y + 14, title, 18, CARBON, "center")
    if sub:
        text(x + w / 2, y + 42, sub, 14, "#404040", "center")
    return (x, y, w, h)


def zone(x, y, w, h, color, label):
    base("rectangle", x, y, w, h, color, strokeStyle="dashed", strokeWidth=1, roundness={"type": 3})
    text(x + 14, y + 10, label, 15, color)


def arrow(x1, y1, x2, y2, color="#525252", dashed=False):
    base("arrow", x1, y1, x2 - x1, y2 - y1, color, roundness={"type": 2},
         strokeStyle="dashed" if dashed else "solid", points=[[0, 0], [x2 - x1, y2 - y1]],
         lastCommittedPoint=None, startBinding=None, endBinding=None, startArrowhead=None,
         endArrowhead="arrow")


def write_diagram(filename, source):
    doc = {"type": "excalidraw", "version": 2, "source": source,
           "appState": {"gridSize": None, "viewBackgroundColor": "#ffffff"}, "elements": els, "files": {}}
    Path(__file__).with_name(filename).write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{filename}: {len(els)} elements")


text(40, 24, "CodeGuardian v1: a security gate and a Security agent", 28)
text(40, 64, "Blocks only what a pull request adds. The model explains and ranks findings; it cannot add, move or hide one.", 15, "#404040")

# Zone 1: pull_request workflow
zone(30, 100, 1140, 300, BLUE, "security-gate.yml  ·  on: pull_request  ·  runs PR code  ·  no secrets, read-only token")
box(50, 150, 150, 80, CARBON, "Pull request", "code + commits")
scanners = [("Semgrep", "SAST, --baseline-commit"), ("Gitleaks", "secrets, PR commits only"),
            ("Trivy", "SCA + config, base vs head"), ("ZAP", "passive DAST, built app")]
for i, (t, s) in enumerate(scanners):
    x = 260 + (i % 2) * 230
    y = 135 + (i // 2) * 120
    box(x, y, 210, 90, PURPLE, t, s)
arrow(200, 190, 258, 180)
arrow(200, 190, 258, 300)
box(780, 150, 210, 160, BLUE, "gate job", "new findings only\nrules, ignores and\nsuppressions read\nfrom the BASE commit\nscanner error = FAIL")
for y in (180, 300):
    arrow(700, y, 778, 230)
box(1010, 150, 150, 80, EMERALD, "check: gate", "required")
arrow(990, 190, 1008, 190)
text(790, 330, "artifact: findings + diff + PR number", 14, "#404040")

# Zone 2: workflow_run on main
zone(30, 430, 1140, 300, AMBER, "")
text(44, 700, "codeguardian.yml  ·  on: workflow_run from main  ·  never checks out PR code  ·  artifact treated as untrusted", 15, AMBER)
box(50, 530, 190, 90, CARBON, "prepare", "PR number is an integer\nhead SHA matches event")
arrow(880, 352, 150, 528, dashed=True)
box(300, 460, 230, 100, ROSE, "review", "Claude sonnet-5-5\nAPI key only, no tools\nstructured JSON output")
box(600, 460, 230, 100, CARBON, "validate", "drop unknown finding IDs\nlocation from scanner")
box(900, 460, 250, 100, CYAN, "post", "one PR comment\npull-requests: write only\nescape links, images, @")
box(300, 590, 230, 100, CYAN, "guard", "fails if PR edits .github/\n.gate/ or scanner config\nstatuses: write only")
box(600, 600, 250, 80, EMERALD, "status: config-guard", "required")
arrow(240, 565, 298, 515)
arrow(240, 585, 298, 635)
arrow(530, 510, 598, 510)
arrow(830, 510, 898, 510)
arrow(530, 640, 598, 640)

# Bottom: ruleset
box(300, 760, 600, 70, EMERALD, "main ruleset: merge needs both checks green", "no bypass actors")

write_diagram("architecture.excaliflow", "codeguardian week 14")

els.clear()
random.seed(17)

text(40, 25, "CodeGuardian Week 17", 32)
text(42, 71, "How PR data, model replies, and approvals move through the review", 17)

zone(30, 113, 1030, 134, BLUE, "Inputs to the trusted workflow")
box(56, 157, 287, 69, BLUE, "Gate artifact", "Scanner decision, findings, and diff")
box(386, 157, 287, 69, CARBON, "Workflow event", "PR number and expected head SHA")
box(752, 157, 282, 69, EMERALD, "GitHub review", "Reviewer, action, and reviewed SHA")

zone(30, 280, 670, 327, PURPLE, "")
text(44, 582, "Review job   ·   model step uses an API key", 15, PURPLE)
box(106, 323, 237, 82, PURPLE, "Security review", "Explains scanner findings")
box(386, 323, 287, 82, EMERALD, "Standards lookup", "One public record in scope")
box(56, 472, 287, 94, PURPLE, "Advisory review", "Quality, Test-Gap, Documentation\nOne request per role")
box(386, 472, 287, 94, BLUE, "Validated report", "Scanner owns the gate decision\nAdvisory notes stay separate")
arrow(196, 226, 196, 323)
arrow(105, 226, 82, 472)
arrow(386, 364, 343, 364)
arrow(279, 405, 421, 471)
arrow(343, 519, 386, 519)

zone(726, 280, 334, 327, EMERALD, "")
text(740, 582, "Guard job   ·   GitHub status token", 15, EMERALD)
box(752, 323, 282, 102, EMERALD, "Config guard", "Checks the designated reviewer,\naction, and current head")
box(752, 472, 282, 94, EMERALD, "Commit status", "Written to the checked SHA")
arrow(893, 226, 893, 323)
arrow(667, 226, 780, 323)
arrow(893, 425, 893, 472)

zone(30, 644, 670, 134, CYAN, "Post job   ·   GitHub pull-request token")
box(386, 686, 287, 70, CYAN, "PR comment", "Recheck the head and escape text")
arrow(530, 566, 530, 686)

write_diagram("week-17.excaliflow", "codeguardian week 17")
