"""Read-only snapshot export: runs the `aws`, `kubectl` and `gh` CLIs the person already has
and writes exactly the files the collectors read, plus a manifest.

Every command goes through run(), which refuses anything not on the READ_ONLY list and
passes an argument list, never a shell string. A `gh` call must be `gh api PATH` and
nothing more, with PATH on the GH_READS list: no option, so no -X, -f, -F, --input or
--method, and `gh api` sends a GET. Nothing here writes to AWS, Kubernetes or GitHub.

Missing knowledge must not read as safe:
- A bucket with no tags (NoSuchTagSet) is recorded as {"TagSet": []}.
- Any other failure on one bucket's tags (AccessDenied, throttling, a timeout, output
  that is not JSON) is recorded as {"Error": {...}} for that bucket. The collector turns
  that into "not evaluated", never into "untagged" and never into a missing bucket.
- A failure of the IAM, bucket-list or kubectl call stops the export with an error. The
  manifest is written last and records each file's SHA-256, so ingest refuses a partial
  or mixed set.
- GitHub: a failure of the account or repository list stops the export. Any failure of
  one call about one repository (a 403 or 404, a timeout, output that is not JSON, a list
  shorter than its total_count) is recorded as {"Error": {...}} for that part, and the
  collector shows it as not evaluated.

Real exports hold real account IDs and pod specs. Output is refused inside a git work
tree unless git ignores the path, and every file is created with mode 0600.
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

from ..v2.collectors.manifest import FILES, FORMAT, MANIFEST, sha256

# Namespaces are cluster-scoped; their labels decide a NetworkPolicy namespaceSelector.
K8S_KINDS = "pods,services,serviceaccounts,networkpolicies,namespaces"

# Command prefixes run() accepts. Each is a read: AWS operations named get- or list-,
# `kubectl get`, `kubectl config current-context` (reads the local kubeconfig only), and
# `git check-ignore` (reads the local repository only).
READ_ONLY = (
    ("aws", "iam", "get-account-authorization-details"),
    ("aws", "s3api", "list-buckets"),
    ("aws", "s3api", "get-bucket-tagging"),
    ("kubectl", "config", "current-context"),
    ("kubectl", "get", K8S_KINDS),
    ("git", "check-ignore"),
)

BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
AWS_ERROR = re.compile(r"An error occurred \(([A-Za-z0-9.]+)\)")
ACCOUNT = re.compile(r"^arn:aws[a-z-]*:iam::([0-9]{12}):")
TIMEOUT = 300
BUCKET_TIMEOUT = 60
# Pod specs can carry secrets in env values and in the last-applied annotation. The
# collector reads neither, so the export does not keep them.
DROP_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"


class ExportError(RuntimeError):
    pass


class CommandFailed(ExportError):
    def __init__(self, argv, code, stderr, error_code):
        self.argv, self.code, self.stderr, self.error_code = argv, code, stderr or "", error_code
        super().__init__(f"{' '.join(argv[:3])} failed ({error_code or f'exit {code}'}): {self.stderr.strip()[:300]}")


# GitHub: the REST paths `gh api` may GET, whole. A login, a repository name and an encoded
# branch name hold no "{", ":", "?", "&" or "/" of their own, so gh cannot fill in a
# placeholder and a name cannot add a query or a path segment.
_LOGIN = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
_REPO = r"(?!\.\.?/)[A-Za-z0-9._-]{1,100}"
_BRANCH = r"(?!\.\.?(?:\?|$))[A-Za-z0-9._~%-]{1,800}"
_PAGE = r"per_page=100&page=[1-9][0-9]{0,2}"
GH_READS = tuple(re.compile(p) for p in (
    rf"users/{_LOGIN}",
    r"user",
    rf"orgs/{_LOGIN}/repos\?type=all&{_PAGE}",
    rf"users/{_LOGIN}/repos\?type=owner&{_PAGE}",
    rf"user/repos\?affiliation=owner&{_PAGE}",
    rf"repos/{_LOGIN}/{_REPO}/rulesets\?includes_parents=true&{_PAGE}",
    rf"repos/{_LOGIN}/{_REPO}/rules/branches/{_BRANCH}\?{_PAGE}",
    rf"repos/{_LOGIN}/{_REPO}/branches/{_BRANCH}",
    rf"repos/{_LOGIN}/{_REPO}/actions/permissions/workflow",
    rf"repos/{_LOGIN}/{_REPO}/keys\?{_PAGE}",
    rf"repos/{_LOGIN}/{_REPO}/actions/secrets\?{_PAGE}",
    rf"repos/{_LOGIN}/{_REPO}/actions/workflows\?{_PAGE}",
))
LOGIN = re.compile(_LOGIN)
REPO_NAME = re.compile(r"(?!\.\.?$)[A-Za-z0-9._-]{1,100}")
HTTP_ERROR = re.compile(r"\(?HTTP ([0-9]{3})\)?")
GH_TIMEOUT = 60
PER_PAGE = 100
MAX_PAGES = 100


def allowed(argv):
    if tuple(argv[:2]) == ("gh", "api"):
        return len(argv) == 3 and any(p.fullmatch(argv[2]) for p in GH_READS)
    return any(tuple(argv[:len(p)]) == p for p in READ_ONLY)


def run(argv, timeout=TIMEOUT, cwd=None):
    argv = [str(a) for a in argv]
    if not allowed(argv):
        raise ExportError(f"refusing to run a command that is not on the read-only list: {argv[:3]}")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd)
    except FileNotFoundError as exc:
        raise ExportError(f"{argv[0]} is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandFailed(argv, None, f"no answer in {timeout} s", "Timeout") from exc
    if proc.returncode != 0:
        m = AWS_ERROR.search(proc.stderr or "")
        raise CommandFailed(argv, proc.returncode, proc.stderr, m.group(1) if m else None)
    return proc.stdout


def run_json(argv, what, timeout=TIMEOUT):
    out = run(argv, timeout)
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise ExportError(f"{what}: the output is not complete JSON ({exc})") from exc


def _git_root(path):
    for p in [path, *path.parents]:
        if (p / ".git").exists():
            return p
    return None


def prepare_output(out):
    """Create the directory (mode 0700) and refuse it inside a git work tree unless ignored."""
    out = Path(out).resolve()
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = _git_root(out)
    if root is not None:
        try:
            run(["git", "check-ignore", "-q", "--", str(out)], timeout=30, cwd=root)
        except ExportError as exc:
            if created:
                try:
                    out.rmdir()
                except OSError:
                    pass
            raise ExportError(f"{out} is inside the git work tree {root} and git does not ignore it;"
                              " an export holds real account data and must never be committed") from exc
    return out


def _write(out, files, manifest_name, manifest):
    """Write every file to a temporary name first, then move them into place, manifest last."""
    temps = []
    try:
        for name, data in [*files.items(), (manifest_name, None)]:
            if data is None:
                manifest["files"] = {n: sha256(d) for n, d in files.items()}
                data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=out)  # mkstemp creates mode 0600
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o600)
            temps.append((tmp, out / name))
        for tmp, final in temps:
            os.replace(tmp, final)
    finally:
        for tmp, _ in temps:
            if os.path.exists(tmp):
                os.unlink(tmp)


def _dump(obj):
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def account_id(iam):
    for key, arn_key in (("RoleDetailList", "Arn"), ("UserDetailList", "Arn"), ("GroupDetailList", "Arn"),
                         ("Policies", "Arn")):
        for item in iam.get(key) or []:
            m = ACCOUNT.match(str(item.get(arn_key, "")))
            if m:
                return m.group(1)
    return None


def _tags(bucket):
    name = bucket.get("Name")
    if not isinstance(name, str) or not BUCKET_NAME.fullmatch(name):
        return {"Error": {"Code": "InvalidBucketName", "Message": "the name was not passed to the CLI"}}
    argv = ["aws", "s3api", "get-bucket-tagging", "--bucket", name, "--output", "json"]
    region = bucket.get("BucketRegion")
    if isinstance(region, str) and REGION.fullmatch(region):
        argv += ["--region", region]
    try:
        data = run_json(argv, f"tags of {name}", BUCKET_TIMEOUT)
    except CommandFailed as exc:
        if exc.error_code == "NoSuchTagSet":
            return {"TagSet": []}
        return {"Error": {"Code": exc.error_code or "Failed", "Message": exc.stderr.strip()[:300]}}
    except ExportError as exc:
        return {"Error": {"Code": "BadOutput", "Message": str(exc)[:300]}}
    if not isinstance(data, dict) or not isinstance(data.get("TagSet"), list):
        return {"Error": {"Code": "BadOutput", "Message": "no TagSet list in the output"}}
    return {"TagSet": data["TagSet"]}


def export_aws(out, clock):
    out = prepare_output(out)
    iam = run_json(["aws", "iam", "get-account-authorization-details", "--output", "json"], "IAM")
    if not isinstance(iam, dict) or not isinstance(iam.get("RoleDetailList"), list):
        raise ExportError("IAM: the output has no RoleDetailList")
    buckets = run_json(["aws", "s3api", "list-buckets", "--output", "json"], "bucket list")
    if not isinstance(buckets, dict) or not isinstance(buckets.get("Buckets"), list):
        raise ExportError("bucket list: the output has no Buckets list")
    tags = {}
    for b in buckets["Buckets"]:
        tags[str(b.get("Name"))] = _tags(b)
    names = FILES["aws"]
    manifest = {"format": FORMAT, "kind": "aws", "exported_at": clock.now(), "account_id": account_id(iam),
                "not_evaluated": {n: t["Error"]["Code"] for n, t in sorted(tags.items()) if "Error" in t}}
    _write(out, {names["iam"]: _dump(iam), names["buckets"]: _dump(buckets), names["tags"]: _dump(tags)},
           MANIFEST["aws"], manifest)
    return manifest


def _strip(item):
    md = item.get("metadata") or {}
    (md.get("annotations") or {}).pop(DROP_ANNOTATION, None)
    spec = item.get("spec") or {}
    for group in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(group) or []:
            for env in c.get("env") or []:
                if "value" in env:
                    env["value"] = "<removed by export>"
    return item


def export_k8s(out, clock, cluster_name=None):
    out = prepare_output(out)
    context = run(["kubectl", "config", "current-context"], timeout=30).strip()
    if not context:
        raise ExportError("kubectl has no current context")
    # Pin the context just read, so a context switch during the export cannot mix clusters.
    data = run_json(["kubectl", "get", K8S_KINDS, "-A", "-o", "json", "--context", context], "kubectl")
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise ExportError("kubectl: the output has no items list")
    data["items"] = [_strip(i) for i in data["items"]]
    manifest = {"format": FORMAT, "kind": "k8s", "exported_at": clock.now(), "context": context,
                "cluster": cluster_name or context}
    _write(out, {FILES["k8s"]["k8s"]: _dump(data)}, MANIFEST["k8s"], manifest)
    return manifest


# --- GitHub --------------------------------------------------------------------------------

GH_PARTS = ("rulesets", "branch_rules", "branch", "workflow_permissions", "deploy_keys", "secrets", "workflows")
GH_FORMAT = "codeguardian.github-export/v1"


def _gh(path, what):
    return run_json(["gh", "api", path], what, GH_TIMEOUT)


def _pages(base, what, key=None):
    """Every page of a list. With key, each page is an object with total_count and a list
    under key, and the whole list must hold total_count items."""
    items, total = [], None
    for page in range(1, MAX_PAGES + 1):
        data = _gh(f"{base}per_page={PER_PAGE}&page={page}", what)
        if key is None:
            if not isinstance(data, list):
                raise ExportError(f"{what}: the answer is not a list")
            batch = data
        else:
            if not (isinstance(data, dict) and isinstance(data.get(key), list) and isinstance(data.get("total_count"), int)):
                raise ExportError(f"{what}: the answer has no total_count and {key} list")
            batch, total = data[key], data["total_count"]
        items += batch
        if len(batch) < PER_PAGE or (total is not None and len(items) >= total):
            break
    else:
        raise ExportError(f"{what}: more than {MAX_PAGES} pages")
    if key is None:
        return items
    if len(items) != total:
        raise ExportError(f"{what}: listed {len(items)} of {total}")
    return {"total_count": total, key: items}


def _object(path, what):
    data = _gh(path, what)
    if not isinstance(data, dict):
        raise ExportError(f"{what}: the answer is not an object")
    return data


def _part(fn):
    """One call about one repository. Any failure is that part's Error, never a gap."""
    try:
        return fn()
    except CommandFailed as exc:
        m = HTTP_ERROR.search(exc.stderr)
        code = f"HTTP {m.group(1)}" if m else (exc.error_code or "Failed")
        return {"Error": {"Code": code, "Message": exc.stderr.strip()[:300]}}
    except ExportError as exc:
        return {"Error": {"Code": "BadOutput", "Message": str(exc)[:300]}}


def _error(code, message):
    return {"Error": {"Code": code, "Message": message}}


def _branch_ok(branch):
    return isinstance(branch, str) and 0 < len(branch) <= 255 and branch not in (".", "..") and branch.isprintable()


def _drop_key(key):
    # A deploy key's public key is not needed, so the export does not keep it.
    return {k: v for k, v in key.items() if k != "key"} if isinstance(key, dict) else key


def _repository(repo):
    owner, name = repo["full_name"].split("/")
    entry = {"repository": repo}
    if not (LOGIN.fullmatch(owner) and REPO_NAME.fullmatch(name)):
        return {**entry, **{p: _error("InvalidName", "the name was not passed to the CLI") for p in GH_PARTS}}
    base, what = f"repos/{owner}/{name}/", repo["full_name"]
    entry["rulesets"] = _part(lambda: _pages(base + "rulesets?includes_parents=true&", f"{what} rulesets"))
    branch = repo.get("default_branch")
    if _branch_ok(branch):
        b = quote(branch, safe="")
        entry["branch_rules"] = _part(lambda: _pages(base + f"rules/branches/{b}?", f"{what} branch rules"))
        entry["branch"] = _part(lambda: _object(base + f"branches/{b}", f"{what} branch"))
    else:
        code = "NoDefaultBranch" if branch is None else "InvalidBranchName"
        entry["branch_rules"] = entry["branch"] = _error(code, "the default branch was not passed to the CLI")
    entry["workflow_permissions"] = _part(lambda: _object(base + "actions/permissions/workflow",
                                                          f"{what} workflow permissions"))
    entry["deploy_keys"] = _part(lambda: [_drop_key(k) for k in _pages(base + "keys?", f"{what} deploy keys")])
    entry["secrets"] = _part(lambda: _pages(base + "actions/secrets?", f"{what} secrets", "secrets"))
    entry["workflows"] = _part(lambda: _pages(base + "actions/workflows?", f"{what} workflows", "workflows"))
    return entry


def export_github(out, clock, owner):
    if not isinstance(owner, str) or not LOGIN.fullmatch(owner):
        raise ExportError("the owner is not a GitHub login (letters, digits and hyphens, up to 39)")
    out = prepare_output(out)
    acct = _object(f"users/{owner}", "account")
    login = acct.get("login")
    if acct.get("type") not in ("User", "Organization") or not isinstance(login, str) or login.lower() != owner.lower():
        raise ExportError("account: the answer is not the User or Organization asked for")
    if acct["type"] == "Organization":
        listing, base = "organization", f"orgs/{login}/repos?type=all&"
    else:
        try:
            me = _object("user", "authenticated user").get("login")
        except ExportError:
            me = None
        own = isinstance(me, str) and me.lower() == login.lower()
        listing, base = ("owner", "user/repos?affiliation=owner&") if own else ("public", f"users/{login}/repos?type=owner&")
    repos = _pages(base, "repository list")
    for r in repos:
        full = r.get("full_name") if isinstance(r, dict) else None
        if not isinstance(full, str) or full.count("/") != 1 or not all(full.split("/")) \
                or full.split("/")[0].lower() != login.lower():
            raise ExportError(f"repository list: an entry is not a repository of {login}")
    data = {"format": GH_FORMAT, "account": {k: acct.get(k) for k in ("login", "type", "public_repos")},
            "listing": listing, "repositories": [_repository(r) for r in repos]}
    not_evaluated = {}
    for e in data["repositories"]:
        bad = {p: e[p]["Error"]["Code"] for p in GH_PARTS if isinstance(e[p], dict) and set(e[p]) == {"Error"}}
        if bad:
            not_evaluated[e["repository"]["full_name"]] = bad
    manifest = {"format": FORMAT, "kind": "github", "exported_at": clock.now(), "owner": login, "listing": listing,
                "not_evaluated": not_evaluated}
    _write(out, {FILES["github"]["github"]: _dump(data)}, MANIFEST["github"], manifest)
    return manifest
