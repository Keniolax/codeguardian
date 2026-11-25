"""Command line for version 2: ingest, watch, findings, incidents, plan, explain, ask, reach, bench."""

import json
import platform
import sys
import tempfile
import time
from pathlib import Path

COMMANDS = ("ingest", "watch", "findings", "incidents", "plan", "explain", "ask", "reach", "bench")
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "chain"
# reach's exit codes. Nothing that is not an answer exits 0, 1 or 2, so a script cannot
# read a failure or "not evaluated" as an answer.
REACH_EXIT = {"allowed": 0, "denied": 1, "not evaluated": 2}
NO_ANSWER = 3


def add_subcommands(sub):
    def common(p):
        p.add_argument("--db", required=True, help="SQLite file holding the model")
        p.add_argument("--now", help="RFC 3339 time to treat as now (for recorded data); default: the system clock")
        p.add_argument("--cluster", help="Kubernetes cluster name used in entity IDs; default: the name the"
                                         " last k8s export recorded, else lab")
        return p

    p = common(sub.add_parser("ingest", help="read exported snapshots into the model"))
    p.add_argument("--aws-iam", help="aws iam get-account-authorization-details output")
    p.add_argument("--aws-buckets", help="aws s3api list-buckets output")
    p.add_argument("--aws-tags", help="bucket name -> get-bucket-tagging output")
    p.add_argument("--k8s", help="kubectl get pods,services,serviceaccounts,networkpolicies,namespaces -A -o json"
                                 " output")
    p.add_argument("--outside-source", action="append", metavar="CIDR",
                   help="an address range that a connection from outside the cluster may come from, as the pods"
                        " see it; repeat for more; default: every IPv4 and IPv6 address")
    p.add_argument("--ai", help="declared AI inventory")
    p.add_argument("--at", help="time the snapshot was taken (RFC 3339); default: now")
    p.add_argument("--aws-export", help="directory written by `python -m codeguardian.export aws`;"
                                        " its manifest gives the time")
    p.add_argument("--k8s-export", help="directory written by `python -m codeguardian.export k8s`;"
                                        " its manifest gives the time and the cluster name")

    p = common(sub.add_parser("watch", help="process events one by one as they arrive"))
    p.add_argument("--input", default="-", help="NDJSON file, or - for stdin")
    p.add_argument("--follow", action="store_true", help="keep reading a file as it grows")

    p = common(sub.add_parser("findings", help="list findings"))
    p.add_argument("--status", choices=["open", "resolved"])
    p.add_argument("--history", action="store_true",
                   help="also show each finding's status changes in data time, rebuilt from the journal")
    common(sub.add_parser("incidents", help="list incidents with their timelines"))
    p = common(sub.add_parser("plan", help="print the dry-run response plan for an incident"))
    p.add_argument("--incident", required=True, help="incident ID or a unique prefix of it")
    p = common(sub.add_parser("explain", help="ask the model to explain an incident"))
    p.add_argument("--incident", required=True)
    p.add_argument("--provider", default="anthropic", choices=["anthropic", "ollama", "recorded"])
    p.add_argument("--answer", help="with --provider recorded: a saved model answer to replay")

    p = common(sub.add_parser("ask", help="ask a question; the model writes a query, code checks and runs it",
                              epilog="exit status: 0 an answer from sources that are current, 2 no answer to act on"
                                     " (the query was refused or cannot match anything, or a note names a source"
                                     " the answer rests on that is not current)"))
    p.add_argument("--question", required=True)
    p.add_argument("--provider", default="anthropic", choices=["anthropic", "ollama", "recorded"])
    p.add_argument("--answer", help="with --provider recorded: a saved model answer to replay")

    p = common(sub.add_parser("reach", help="whether NetworkPolicy lets one pod connect to another",
                              epilog="exit status: 0 allowed, 1 denied, 2 not evaluated, 3 no answer (a pod or"
                                     " port the model does not hold, or a model that could not be read)"))
    p.error = _no_answer(p)
    p.add_argument("--from", dest="src", required=True, metavar="NAMESPACE/POD", help="the pod that connects")
    p.add_argument("--to", dest="dst", required=True, metavar="NAMESPACE/POD", help="the pod it connects to")
    p.add_argument("--port", type=_port_number, required=True, help="the port on the destination pod (1 to 65535)")
    p.add_argument("--protocol", default="TCP", choices=["TCP", "UDP", "SCTP"])

    p = sub.add_parser("bench", help="replay the chain mixed with seeded noise and time each event")
    p.add_argument("--events", type=int, default=10_000, help="noise events to add to the chain")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--fixtures", default=str(FIXTURES))
    p.add_argument("--db", help="SQLite file; default: a new file in a temporary directory")
    p.add_argument("--write-events", help="also save the generated NDJSON here")


def _no_answer(parser):
    """reach's usage errors exit NO_ANSWER, not argparse's 2, which means "not evaluated"."""
    def error(message):
        parser.print_usage(sys.stderr)
        parser.exit(NO_ANSWER, f"{parser.prog}: error: {message}\n")
    return error


def refuse_extra(a, extra):
    """An option no parser knows reaches the top-level parser, whose error exits 2. For
    reach that would read as "not evaluated", so reach exits NO_ANSWER instead."""
    if getattr(a, "cmd", None) == "reach":
        from .render import term

        print(f"codeguardian reach: error: unrecognized arguments: {term(' '.join(extra))}", file=sys.stderr)
        raise SystemExit(NO_ANSWER)


def _setup(a):
    from .pipeline import Pipeline
    from .rules import load_rules
    from .schema import FixedClock, SystemClock
    from .store import Store

    clock = FixedClock(a.now) if a.now else SystemClock()
    store = Store(a.db)
    cluster = a.cluster or store.setting("cluster") or "lab"
    return store, Pipeline(store, load_rules(), clock, cluster), clock


def _incident(store, ref):
    hits = [i for i in store.incidents() if i["incident_id"].startswith(ref)]
    if len(hits) != 1:
        raise SystemExit(f"no single incident matches {ref!r} ({len(hits)} match)")
    return hits[0]


def run(a):
    if a.cmd == "bench":
        return _bench(a)
    if a.cmd == "reach":
        return _reach(a)
    from . import render
    from .collectors import CollectorError

    store, pipe, clock = _setup(a)
    if a.cmd == "ingest":
        return _ingest(a, store, pipe, clock)
    if a.cmd == "watch":
        return _watch(a, store, pipe)
    if a.cmd == "findings":
        hist = None
        if a.history:
            from .history import history

            hist = history(store, pipe.rules, clock.now())
        sys.stdout.write(render.findings(store, clock.now(), a.status, hist))
        return 0
    if a.cmd == "incidents":
        sys.stdout.write(render.incidents(store))
        return 0
    if a.cmd == "plan":
        from .respond import plan

        sys.stdout.write(render.plan(plan(store, _incident(store, a.incident))))
        return 0
    if a.cmd in ("explain", "ask"):
        from .explain import RecordedProvider, explain

        if a.provider == "recorded":
            if not a.answer:
                raise SystemExit("--provider recorded needs --answer")
            provider = RecordedProvider(a.answer)
        else:
            from ..providers import get_provider

            provider = get_provider(a.provider)
        if a.cmd == "explain":
            sys.stdout.write(render.explanation(explain(store, _incident(store, a.incident), provider)))
            return 0
        from .ask import QueryError, ask, sources
        from .render import not_current, term

        try:
            result = ask(store, a.question, provider)
        except QueryError as exc:
            print(f"query refused: {term(exc)}", file=sys.stderr)
            return 2
        # An answer from facts that may not hold now is not one to act on: "no rows" from a
        # collector that never ran would read as "none".
        held = [line for name in sources(result["query"]) for line in not_current(store, name, clock.now())]
        for line in held:
            print(f"note: {term(line)}")
        if held:
            print("note: the answer below rests on facts that may not hold now, so it counts as not evaluated")
        sys.stdout.write(render.answer(result))
        # "Not an answer" (a query that cannot match anything) is not one to act on either.
        return 2 if held or result["cannot_match"] else 0
    return 1


def _ingest(a, store, pipe, clock):
    import ipaddress

    from .collectors import CollectorError, manifest
    from .render import term

    if a.outside_source:
        for cidr in a.outside_source:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise SystemExit(f"--outside-source {term(cidr)} is not an address range") from None
        pipe.outside = tuple(a.outside_source)

    aws = (a.aws_iam, a.aws_buckets, a.aws_tags)
    if any(aws) and not all(aws):
        raise SystemExit("--aws-iam, --aws-buckets and --aws-tags go together")
    if a.aws_export and any(aws):
        raise SystemExit("use --aws-export or the --aws-* files, not both")
    if a.k8s_export and a.k8s:
        raise SystemExit("use --k8s-export or --k8s, not both")
    jobs, errors = [], []
    for kind, directory, source in (("k8s", a.k8s_export, "k8s.state"), ("aws", a.aws_export, "aws.state")):
        if not directory:
            continue
        try:
            paths, m = manifest.read(directory, kind)
        except CollectorError as exc:
            store.record_source(source, False, clock.now(), str(exc))
            errors.append(str(exc))
            continue
        if kind == "k8s":
            if a.cluster and a.cluster != m["cluster"]:
                raise SystemExit(f"--cluster {a.cluster} does not match the export's cluster {m['cluster']}")
            pipe.cluster = m["cluster"]
            store.set_setting("cluster", m["cluster"])
            jobs.append({"k8s": paths["k8s"], "at": m["exported_at"]})
        else:
            jobs.append({"aws": (paths["iam"], paths["buckets"], paths["tags"]), "at": m["exported_at"]})
            print(f"AWS export of account {term(m.get('account_id'))} taken at {m['exported_at']}")
            for bucket, code in sorted((m.get("not_evaluated") or {}).items()):
                print(f"bucket {term(bucket)}: tags not read ({term(code)}); shown as not evaluated")
    typed = {"aws": aws if all(aws) else None, "k8s": a.k8s, "ai": a.ai}
    if any(typed.values()):
        jobs.append({**typed, "at": a.at and _ts(a.at)})
        if a.k8s:
            store.set_setting("cluster", pipe.cluster)
    opened = resolved = 0
    refused, stale = [], bool(errors)
    for job in jobs:
        try:
            changes = pipe.snapshot(**job)
        except CollectorError as exc:
            errors.append(str(exc))
            stale = stale or getattr(exc, "marked_stale", True)
            changes = getattr(exc, "changes", None) or {"opened": [], "resolved": [], "refused": [], "unchanged": []}
        opened, resolved = opened + len(changes["opened"]), resolved + len(changes["resolved"])
        refused += changes["refused"]
        for name in changes["unchanged"]:
            print(f"{name}: this snapshot is already in the model; nothing changed")
    store.commit()
    for name, verdict, reason in refused:
        print(f"snapshot refused: {name}: {term(reason)}; nothing changed", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"collector failed: {term(e, 1000)}", file=sys.stderr)
        if stale:
            print("its facts are now marked stale; nothing it wrote before was deleted", file=sys.stderr)
        return 2
    print(f"opened {opened}, resolved {resolved} findings")
    return 3 if refused else 0


def _port_number(text):
    import argparse

    value = int(text)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"{value} is not a port number (1 to 65535)")
    return value


def _reach(a):
    """Exit REACH_EXIT[answer], or NO_ANSWER with the reason on stderr when there is no
    answer to give. An error escaping here would exit 1, which reads as "denied"."""
    from .collectors.k8s import SOURCE as K8S
    from .netpol import pod_to_pod
    from .render import not_current, term
    from .schema import entity_id

    try:
        store, pipe, clock = _setup(a)
        ids = []
        for ref in (a.src, a.dst):
            if ref.count("/") != 1 or not all(ref.split("/")):
                print(f"no answer: {term(ref)}: give a pod as NAMESPACE/NAME", file=sys.stderr)
                return NO_ANSWER
            pid = entity_id("pod", f"{pipe.cluster}/{ref}")
            if store.entity(pid) is None:
                print(f"no answer: pod {term(ref)} is not in the model (cluster {term(pipe.cluster)})", file=sys.stderr)
                return NO_ANSWER
            ids.append(pid)
        answer, notes = pod_to_pod(store, ids[0], ids[1], a.port, a.protocol)
        # The model's Kubernetes facts may not hold now: reach still prints the answer the
        # last good snapshot gives, but exits as not evaluated, so a script never reads an
        # old "denied" as safe.
        held = not_current(store, K8S, clock.now())
    except Exception as exc:  # any failure is "no answer", never an answer
        print(f"no answer: {term(type(exc).__name__)}: {term(exc)}", file=sys.stderr)
        return NO_ANSWER
    for line in held:
        print(f"note: {term(line)}")
    if held:
        print("note: the answer below is the one the last good snapshot of k8s.state gives; it may not hold now,"
              " so it counts as not evaluated")
    print(f"{answer}: {term(a.src)} -> {term(a.dst)} on {a.protocol} {a.port}")
    for n in notes:
        print(f"  note: {term(n)}")
    print("  this assumes the cluster's network plugin enforces NetworkPolicy; the model cannot see that")
    code = REACH_EXIT.get(answer, NO_ANSWER)
    return REACH_EXIT["not evaluated"] if held and code != NO_ANSWER else code


def _ts(value):
    from .schema import ts

    return ts(value)


def _lines(path, follow):
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        while True:
            line = stream.readline()
            if line:
                yield line
            elif follow and path != "-":
                time.sleep(0.5)
            else:
                return
    finally:
        if stream is not sys.stdin:
            stream.close()


def _watch(a, store, pipe):
    from ..render import safe

    seen = dup = bad = 0
    try:
        for line in _lines(a.input, a.follow):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                bad += 1
                print(f"skipped a line that is not JSON: {exc}", file=sys.stderr)
                continue
            r = pipe.process(raw)
            seen += 1
            if r["status"] == "duplicate":
                dup += 1
                continue
            if r["status"] == "unparseable":
                bad += 1
                print(f"skipped a record: {safe(r['error'])}", file=sys.stderr)
                continue
            for verb in ("opened", "resolved", "alerts"):
                for fid in r[verb]:
                    f = store.finding(fid)
                    print(f"{safe(r['action'], 120)}: {verb[:-1] if verb == 'alerts' else verb} {f['rule_id']}"
                          f" {fid} {safe(f['title'], 160)}")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    print(f"records read {seen}, duplicates {dup}, skipped {bad}", file=sys.stderr)
    return 0


def _bench(a):
    from . import correlate
    from .gen import bench, generate
    from .pipeline import Pipeline
    from .rules import load_rules
    from .schema import FixedClock
    from .store import Store

    fx = Path(a.fixtures)
    lines = generate((fx / "events" / "chain.ndjson").read_text(encoding="utf-8").splitlines(), a.events, a.seed)
    if a.write_events:
        Path(a.write_events).write_text("".join(lines), encoding="utf-8")
    db = a.db or str(Path(tempfile.mkdtemp(prefix="codeguardian-bench-")) / "bench.db")
    store = Store(db)
    pipe = Pipeline(store, load_rules(), FixedClock("2026-11-14T10:30:00Z"))
    pipe.snapshot(aws=(fx / "aws" / "iam.json", fx / "aws" / "s3-buckets.json", fx / "aws" / "s3-tags.json"),
                  k8s=fx / "k8s" / "state.json", ai=fx / "ai" / "inventory.json", at="2026-11-14T09:00:00.000000Z")
    result = bench(pipe, lines)
    chain_incident = next((i for i in store.incidents()
                           if any(store.finding(f)["rule_id"] == "DET-AI-001" for f in i["finding_ids"])), None)
    result.update(
        seed=a.seed, noise_events=a.events, chain_events=len(lines) - a.events,
        store=f"SQLite file on disk ({db}), WAL, one commit per event",
        machine=f"{platform.machine()} {platform.processor() or ''} {platform.platform()}".strip(),
        python=platform.python_version(),
        path_findings={f["status"]: 1 for f in store.findings(rule_id="PATH-AI-001")},
        chain_incident_rules=sorted({store.finding(f)["rule_id"] for f in chain_incident["finding_ids"]})
        if chain_incident else [],
        chain_incident_timeline_events=len(correlate.timeline(store, chain_incident)) if chain_incident else 0,
        incidents=len(store.incidents()), counters=store.counters(),
        note="Pipeline time only. It does not include the source's own delivery delay; CloudTrail delivers"
             " records minutes after the call.",
    )
    print(json.dumps(result, indent=2))
    return 0
