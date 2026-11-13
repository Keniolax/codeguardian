"""The only code that holds a GitHub token. It runs in jobs that never call the model."""

import fnmatch
import json
import os
import urllib.request

from .render import MARKER

PROTECTED_PATHS = [
    ".github/*", ".gate/*", ".semgrepignore", ".gitleaks.toml", ".gitleaksignore",
    ".trivyignore", ".trivyignore.yaml", "trivy.yaml", ".zap/*",
]
APPROVAL_LABEL = "gate-change-approved"
GUARD_CONTEXT = "codeguardian/config-guard"


class GitHub:
    def __init__(self, repo, token=None, api=None, opener=None):
        if repo.count("/") != 1:
            raise ValueError("repo must be owner/name")
        self.repo = repo
        self.token = token or os.environ["GITHUB_TOKEN"]
        self.api = (api or os.environ.get("GITHUB_API_URL", "https://api.github.com")).rstrip("/")
        self.opener = opener or urllib.request.urlopen

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.api}{path}", data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        })
        with self.opener(req) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None

    def pull(self, number):
        return self.call("GET", f"/repos/{self.repo}/pulls/{int(number)}")


def verified_pull(gh, number, expected_head_sha):
    """Return the pull request only if it is open and still at the commit that was scanned."""
    pull = gh.pull(number)
    if pull.get("state") != "open":
        raise RuntimeError(f"pull request {number} is not open")
    if pull["head"]["sha"] != expected_head_sha:
        raise RuntimeError("pull request head moved since the scan; not posting a stale report")
    return pull


def post_report(gh, number, body):
    """Create or update the single CodeGuardian comment on the pull request."""
    page, existing = 1, None
    while page <= 10 and existing is None:
        comments = gh.call("GET", f"/repos/{gh.repo}/issues/{int(number)}/comments?per_page=100&page={page}")
        if not comments:
            break
        for c in comments:
            if c.get("body", "").startswith(MARKER) and c.get("user", {}).get("type") == "Bot":
                existing = c
                break
        page += 1
    if existing:
        return gh.call("PATCH", f"/repos/{gh.repo}/issues/comments/{int(existing['id'])}", {"body": body})
    return gh.call("POST", f"/repos/{gh.repo}/issues/{int(number)}/comments", {"body": body})


def protected_changes(filenames):
    return sorted(f for f in filenames if any(fnmatch.fnmatch(f, p) for p in PROTECTED_PATHS))


def guard(gh, number, head_sha):
    """Set a commit status that fails when the change edits the gate or its config.

    This runs from the base branch (workflow_run), so the pull request cannot change it.
    It covers the hole in any pull_request workflow: the change can edit the workflow that
    judges it. A maintainer can approve such a change with a label.
    """
    pull = verified_pull(gh, number, head_sha)
    files, page = [], 1
    while page <= 30:
        batch = gh.call("GET", f"/repos/{gh.repo}/pulls/{int(number)}/files?per_page=100&page={page}")
        if not batch:
            break
        files += [f["filename"] for f in batch]
        page += 1
    touched = protected_changes(files)
    approved = any(lbl.get("name") == APPROVAL_LABEL for lbl in pull.get("labels", []))
    if not touched:
        state, text = "success", "No gate or scanner config changed."
    elif approved:
        state, text = "success", f"Gate config changed ({len(touched)} files); approved by label."
    else:
        state, text = "failure", f"Changes gate config ({', '.join(touched)[:100]}); needs label {APPROVAL_LABEL}."
    gh.call("POST", f"/repos/{gh.repo}/statuses/{head_sha}",
            {"state": state, "context": GUARD_CONTEXT, "description": text[:140]})
    return state, touched
