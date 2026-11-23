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
CONFIG_APPROVAL = "Approve CodeGuardian config change"
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


def changed_paths(gh, number, expected_count):
    if type(expected_count) is not int or not 0 <= expected_count <= 3000:
        return None
    files = []
    for page in range(1, 31):
        batch = gh.call("GET", f"/repos/{gh.repo}/pulls/{int(number)}/files?per_page=100&page={page}")
        files.extend(batch)
        if len(batch) < 100:
            break
    names = {entry["filename"] for entry in files}
    if len(files) != expected_count or len(names) != expected_count:
        return None
    if any(entry.get("status") == "renamed" and not entry.get("previous_filename") for entry in files):
        return None
    return names | {entry["previous_filename"] for entry in files if entry.get("previous_filename")}


def config_approved(gh, number, head_sha, approver_id, pull):
    author = (pull.get("user") or {}).get("id")
    if approver_id is None or author is None or approver_id == author:
        return False
    decision = {}
    for page in range(1, 31):
        reviews = gh.call("GET", f"/repos/{gh.repo}/pulls/{int(number)}/reviews?per_page=100&page={page}")
        for review in reviews:
            user = review.get("user") or {}
            if (user.get("id") == approver_id and user.get("type") == "User"
                    and review.get("state") not in ("COMMENTED", "PENDING")):
                decision = review
        if len(reviews) < 100:
            return (decision.get("state") == "APPROVED"
                    and decision.get("commit_id") == head_sha
                    and (decision.get("body") or "").strip() == CONFIG_APPROVAL)
    return False


def guard(gh, number, head_sha, *, approver_id=None):
    """Check gate changes in the trusted workflow and write a status on the scanned commit."""
    pull = verified_pull(gh, number, head_sha)
    paths = changed_paths(gh, number, pull.get("changed_files"))
    touched = protected_changes(paths or ())
    if paths is None:
        state, text = "failure", "Could not verify the complete pull request file list."
    elif not touched:
        state, text = "success", "No gate or scanner config changed."
    elif config_approved(gh, number, head_sha, approver_id, pull):
        state, text = "success", f"Gate config changed ({len(touched)} paths). Approved for this commit."
    else:
        state, text = "failure", "Gate config changes need a maintainer review for this commit."
    live = verified_pull(gh, number, head_sha)
    if (live["base"]["sha"] != pull["base"]["sha"]
            or live.get("changed_files") != pull.get("changed_files")):
        raise RuntimeError("pull request base or file count changed during the guard check")
    gh.call("POST", f"/repos/{gh.repo}/statuses/{head_sha}",
            {"state": state, "context": GUARD_CONTEXT, "description": text[:140]})
    return state, touched
