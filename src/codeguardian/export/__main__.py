"""python -m codeguardian.export {aws,k8s} --out DIR"""

import argparse
import sys

from ..v2.schema import FixedClock, SystemClock
from . import ExportError, export_aws, export_k8s


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m codeguardian.export",
                                 description="Take a read-only snapshot with the aws or kubectl CLI.")
    sub = ap.add_subparsers(dest="kind", required=True)
    for kind in ("aws", "k8s"):
        p = sub.add_parser(kind)
        p.add_argument("--out", default=f"exports/{kind}", help="output directory (default: exports/%(prog)s)")
        p.add_argument("--now", help="RFC 3339 time to record as the export time; default: the system clock")
        if kind == "k8s":
            p.add_argument("--cluster-name", help="name for the cluster in entity IDs; default: the context name")
    a = ap.parse_args(argv)
    clock = FixedClock(a.now) if a.now else SystemClock()
    try:
        if a.kind == "aws":
            m = export_aws(a.out, clock)
            print(f"exported account {m['account_id']} at {m['exported_at']} to {a.out}")
            for name, code in m["not_evaluated"].items():
                print(f"tags not read for bucket {name}: {code}; it will show as not evaluated", file=sys.stderr)
        else:
            m = export_k8s(a.out, clock, a.cluster_name)
            print(f"exported context {m['context']} as cluster {m['cluster']} at {m['exported_at']} to {a.out}")
    except ExportError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        print("no new file was written; an earlier export in that directory, if any, is unchanged", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
