"""Read-only snapshot export: runs the `aws` and `kubectl` CLIs the person already has and
writes exactly the files the stage 1 collectors read, plus a manifest.

Every command goes through run(), which refuses anything not on the READ_ONLY list and
passes an argument list, never a shell string. Nothing here writes to AWS or Kubernetes.

Missing knowledge must not read as safe:
- A bucket with no tags (NoSuchTagSet) is recorded as {"TagSet": []}.
- Any other failure on one bucket's tags (AccessDenied, throttling, a timeout, output
  that is not JSON) is recorded as {"Error": {...}} for that bucket. The collector turns
  that into "not evaluated", never into "untagged" and never into a missing bucket.
- A failure of the IAM, bucket-list or kubectl call stops the export with an error. The
  manifest is written last and records each file's SHA-256, so ingest refuses a partial
  or mixed set.

Real exports hold real account IDs and pod specs. Output is refused inside a git work
tree unless git ignores the path, and every file is created with mode 0600.
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

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


def allowed(argv):
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
