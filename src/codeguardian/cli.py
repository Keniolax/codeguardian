"""Command line: review (calls the model), post and guard (call GitHub). Never both."""

import argparse
import json
import re
import sys
from pathlib import Path

from .report import check_report

SHA = re.compile(r"^[0-9a-f]{40}$")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="codeguardian")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("review", help="explain and rank scanner findings with the model")
    p.add_argument("--input", required=True, help="directory with decision.json, pr.json, change.diff")
    p.add_argument("--out", required=True)
    p.add_argument("--provider", default="anthropic", choices=["anthropic", "ollama"])

    p = sub.add_parser("render", help="print the comment a report would produce")
    p.add_argument("--report", required=True)

    p = sub.add_parser("post", help="post or update the report comment on the pull request")
    p.add_argument("--report", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--head-sha", required=True, help="trusted head SHA from the workflow_run event")
    p.add_argument("--pr", type=int, help="trusted PR number; else taken from the report and verified")

    p = sub.add_parser("guard", help="set the config-guard commit status")
    p.add_argument("--repo", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--pr", type=int, required=True)

    from .v2 import cli as v2_cli

    v2_cli.add_subcommands(sub)

    a = ap.parse_args(argv)

    if a.cmd in v2_cli.COMMANDS:
        return v2_cli.run(a)

    if a.cmd == "review":
        from .providers import get_provider
        from .supervisor import review

        report = review(a.input, get_provider(a.provider))
        Path(a.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"{len(report['items'])} findings, {report['dropped_model_entries']} model entries dropped,"
              f" served by {report['served_by']}")
        return 0

    if a.cmd == "render":
        from .render import render

        sys.stdout.write(render(check_report(json.loads(Path(a.report).read_text(encoding="utf-8")))))
        return 0

    from .github import GitHub, guard, post_report, verified_pull

    if not SHA.match(a.head_sha):
        ap.error("--head-sha must be a 40-character hex SHA")
    gh = GitHub(a.repo)

    if a.cmd == "post":
        from .render import render

        report = check_report(json.loads(Path(a.report).read_text(encoding="utf-8")))
        number = a.pr or report["pr"]["number"]
        verified_pull(gh, number, a.head_sha)
        post_report(gh, number, render(report))
        print(f"posted report on pull request {number}")
        return 0

    if a.cmd == "guard":
        state, touched = guard(gh, a.pr, a.head_sha)
        print(f"config-guard {state}; protected files changed: {touched}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
