"""The manifest an export writes next to its files, and its check at ingest.

An export is complete only if its manifest exists, names its files, and every file still
has the SHA-256 the manifest recorded. A file from a failed or half-written export, or
one edited by hand, does not match and is refused.
"""

import hashlib
import json
from pathlib import Path

from ..schema import ts
from . import CollectorError

FORMAT = "codeguardian.export/v1"
FILES = {
    "aws": {"iam": "iam.json", "buckets": "s3-buckets.json", "tags": "s3-tags.json"},
    "k8s": {"k8s": "k8s.json"},
    "github": {"github": "github.json"},
}
MANIFEST = {"aws": "aws-manifest.json", "k8s": "k8s-manifest.json", "github": "github-manifest.json"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read(directory, kind):
    """Returns (paths by role, manifest). Raises CollectorError if anything is off."""
    d = Path(directory)
    what = f"{kind} export in {d}"
    try:
        m = json.loads((d / MANIFEST[kind]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectorError(f"{what}: no readable {MANIFEST[kind]}: {exc}") from exc
    if not isinstance(m, dict) or m.get("format") != FORMAT or m.get("kind") != kind:
        raise CollectorError(f"{what}: {MANIFEST[kind]} is not a {FORMAT} {kind} manifest")
    try:
        m["exported_at"] = ts(m["exported_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CollectorError(f"{what}: manifest has no valid exported_at") from exc
    files = m.get("files")
    if not isinstance(files, dict) or set(files) != set(FILES[kind].values()):
        raise CollectorError(f"{what}: manifest must list exactly {sorted(FILES[kind].values())}")
    paths = {}
    for role, name in FILES[kind].items():
        try:
            data = (d / name).read_bytes()
        except OSError as exc:
            raise CollectorError(f"{what}: {name} is missing") from exc
        if sha256(data) != files[name]:
            raise CollectorError(f"{what}: {name} does not match the manifest; the export is incomplete or changed")
        paths[role] = d / name
    if kind == "k8s" and not isinstance(m.get("cluster"), str):
        raise CollectorError(f"{what}: manifest has no cluster name")
    if kind == "github":
        if not isinstance(m.get("owner"), str):
            raise CollectorError(f"{what}: manifest has no owner")
        ne = m.get("not_evaluated", {})
        if not (isinstance(ne, dict) and all(isinstance(v, dict) and all(isinstance(c, str) for c in v.values())
                                             for v in ne.values())):
            raise CollectorError(f"{what}: manifest not_evaluated is not a map of repository to part to code")
    return paths, m
