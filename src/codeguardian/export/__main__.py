"""python -m codeguardian.export {aws,k8s,github} --out DIR"""

import argparse
import sys

from ..v2.render import term
from ..v2.schema import FixedClock, SystemClock
from . import ExportError, export_aws, export_github, export_k8s


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m codeguardian.export",
                                 description="Take a read-only snapshot with the aws, kubectl or gh CLI.")
    sub = ap.add_subparsers(dest="kind", required=True)
    for kind in ("aws", "k8s", "github"):
        p = sub.add_parser(kind)
        p.add_argument("--out", default=f"exports/{kind}", help=f"output directory (default: exports/{kind})")
        p.add_argument("--now", help="RFC 3339 time to record as the export time; default: the system clock")
        if kind == "k8s":
            p.add_argument("--cluster-name", help="name for the cluster in entity IDs; default: the context name")
        if kind == "github":
            p.add_argument("--owner", required=True, help="the GitHub user or organisation whose repositories to read")
    a = ap.parse_args(argv)
    clock = FixedClock(a.now) if a.now else SystemClock()
    try:
        if a.kind == "aws":
            m = export_aws(a.out, clock)
            print(f"exported account {term(m['account_id'])} at {m['exported_at']} to {term(a.out)}")
            for name, code in m["not_evaluated"].items():
                print(f"tags not read for bucket {term(name)}: {term(code)}; it will show as not evaluated",
                      file=sys.stderr)
        elif a.kind == "github":
            m = export_github(a.out, clock, a.owner)
            print(f"exported GitHub account {term(m['owner'])} (listing: {m['listing']}) at {m['exported_at']}"
                  f" to {term(a.out)}")
            for repo, parts in sorted(m["not_evaluated"].items()):
                for part, code in sorted(parts.items()):
                    print(f"repository {term(repo)}: {part} not read: {term(code)}; it will show as not evaluated",
                          file=sys.stderr)
        else:
            m = export_k8s(a.out, clock, a.cluster_name)
            print(f"exported context {term(m['context'])} as cluster {term(m['cluster'])} at {m['exported_at']}"
                  f" to {term(a.out)}")
    except ExportError as exc:
        print(f"export failed: {term(exc, 1000)}", file=sys.stderr)
        print("no new file was written; an earlier export in that directory, if any, is unchanged", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
