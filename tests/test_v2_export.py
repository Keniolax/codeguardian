"""Snapshot export, tested only against fake `aws` and `kubectl` programs that replay
recorded output. Nothing here calls a real account or cluster: PATH holds only the fake
programs and the system directories, never the place a real CLI is installed."""

import ast
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from codeguardian import export
from codeguardian.cli import main as cli
from codeguardian.export.__main__ import main as export_main
from codeguardian.v2.store import Store
from v2_helpers import FINANCE, FX, ROLE, build, chain, decisions, fixture, iam_event

NOW = "2026-11-14T10:30:00Z"
AT = "2026-11-14T09:55:00Z"
FAKE = """#!{python}
import json, os, sys, time
name = os.path.basename(sys.argv[0])
argv = [name] + sys.argv[1:]
with open(os.environ["FAKE_CLI_LOG"], "a") as fh:
    fh.write(json.dumps(argv) + "\\n")
plan = json.load(open(os.environ["FAKE_CLI_PLAN"]))
r = plan.get(" ".join(argv))
if r is None:
    sys.stderr.write("fake: no recorded output for " + " ".join(argv) + "\\n")
    sys.exit(2)
time.sleep(r.get("sleep", 0))
sys.stdout.write(r.get("stdout", ""))
sys.stderr.write(r.get("stderr", ""))
sys.exit(r.get("code", 0))
"""
KUBECTL_GET = "kubectl get pods,services,serviceaccounts,networkpolicies -A -o json --context lab"
IAM = "aws iam get-account-authorization-details --output json"


def aws_error(code, op="GetBucketTagging", message="denied"):
    return {"code": 254, "stderr": f"\nAn error occurred ({code}) when calling the {op} operation: {message}\n"}


def tagging(bucket):
    return f"aws s3api get-bucket-tagging --bucket {bucket} --output json"


def recorded_plan(iam="aws/iam.json"):
    """What the real CLIs would print for the stage 1 chain data."""
    plan = {IAM: {"stdout": (FX / iam).read_text()},
            "aws s3api list-buckets --output json": {"stdout": (FX / "aws/s3-buckets.json").read_text()},
            "kubectl config current-context": {"stdout": "lab\n"},
            KUBECTL_GET: {"stdout": (FX / "k8s/state.json").read_text()}}
    for name, entry in fixture("aws/s3-tags.json").items():
        # The real CLI answers an untagged bucket with a NoSuchTagSet error, not an empty set.
        plan[tagging(name)] = ({"stdout": json.dumps(entry)} if entry["TagSet"]
                               else aws_error("NoSuchTagSet", message="The TagSet does not exist"))
    return plan


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    for name in ("aws", "kubectl"):
        p = bin_dir / name
        p.write_text(FAKE.format(python=sys.executable))
        p.chmod(0o755)
    log, plan_file = tmp_path / "cli.log", tmp_path / "plan.json"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin")
    monkeypatch.setenv("FAKE_CLI_LOG", str(log))
    monkeypatch.setenv("FAKE_CLI_PLAN", str(plan_file))

    def use(plan):
        plan_file.write_text(json.dumps(plan))
        return plan

    use.log = lambda: [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return use


def run_export(kind, out, *extra):
    return export_main([kind, "--out", str(out), "--now", AT, *extra])


def ingest(db, *args):
    return cli(["ingest", "--db", str(db), "--now", NOW, *args])


def replay_chain(db, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO((FX / "events" / "chain.ndjson").read_text()))
    assert cli(["watch", "--db", str(db), "--now", NOW]) == 0
    capsys.readouterr()


# --- the proof: export, ingest, replay gives the stage 1 result -------------------------------

def test_export_then_ingest_gives_the_same_findings_and_incident_as_the_fixtures(tmp_path, fake_cli, monkeypatch,
                                                                                capsys):
    fake_cli(recorded_plan())
    assert run_export("aws", tmp_path / "out" / "aws") == 0
    assert run_export("k8s", tmp_path / "out" / "k8s") == 0
    db = tmp_path / "m.db"
    assert ingest(db, "--aws-export", str(tmp_path / "out" / "aws"), "--k8s-export", str(tmp_path / "out" / "k8s"),
                  "--ai", str(FX / "ai/inventory.json"), "--at", AT) == 0
    replay_chain(db, monkeypatch, capsys)
    exported = Store(str(db))
    (tmp_path / "fx").mkdir()
    reference, pipe = build(tmp_path / "fx", iam="aws/iam.json")
    for ev in chain():
        pipe.process(ev)
    assert decisions(exported) == decisions(reference)
    assert {e["id"] for e in exported.entities()} == {e["id"] for e in reference.entities()}
    assert len(exported.incidents()) == 2
    # The manifest's time became the snapshot time; nobody typed --at for AWS or k8s.
    assert exported.source("aws.state")["last_success"] == "2026-11-14T09:55:00.000000Z"
    assert exported.setting("cluster") == "lab"


def test_every_command_the_export_ran_is_a_read(tmp_path, fake_cli):
    fake_cli(recorded_plan())
    assert run_export("aws", tmp_path / "a") == 0
    assert run_export("k8s", tmp_path / "k") == 0
    ran = fake_cli.log()
    assert len(ran) == 2 + 3 + 2  # IAM, bucket list, three buckets' tags, context, get
    for argv in ran:
        assert export.allowed(argv), argv
        assert _is_read(argv), argv


def _is_read(argv):
    if argv[0] == "aws":
        return argv[2].startswith(("get-", "list-", "describe-"))
    if argv[0] == "kubectl":
        return argv[1] == "get" or argv[1:3] == ["config", "current-context"]
    return argv[0] == "git" and argv[1] == "check-ignore"


def test_the_read_only_list_holds_only_reads():
    for prefix in export.READ_ONLY:
        assert _is_read(list(prefix) + ["x"] * 3), prefix


@pytest.mark.parametrize("argv", [
    ["aws", "iam", "put-role-policy", "--role-name", "x"],
    ["aws", "s3api", "put-bucket-tagging", "--bucket", "x"],
    ["kubectl", "delete", "pod", "x"],
    ["kubectl", "get", "secrets", "-A", "-o", "json"],
    ["sh", "-c", "aws iam list-roles"],
])
def test_run_refuses_any_command_that_is_not_a_listed_read(argv, fake_cli):
    # fake_cli puts only the fake programs on PATH, so even with this check removed (as the
    # mutation run does) no real CLI can be reached.
    fake_cli({})
    with pytest.raises(export.ExportError, match="read-only list"):
        export.run(argv)
    assert fake_cli.log() == []


def test_only_run_starts_a_process_and_never_through_a_shell():
    tree = ast.parse(Path(export.__file__).read_text())
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        uses = [n for n in ast.walk(fn) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                and n.value.id == "subprocess" and n.attr in ("run", "Popen", "call", "check_output", "check_call")]
        assert not uses or fn.name == "run", fn.name
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            pytest.fail("shell= is used")


# --- missing knowledge is not "safe" ----------------------------------------------------------

def test_access_denied_on_one_bucket_is_not_evaluated_not_untagged(tmp_path, fake_cli):
    plan = recorded_plan(iam="aws/iam-wide.json")
    plan[tagging("example-finance-records")] = aws_error("AccessDenied", message="Access Denied")
    fake_cli(plan)
    assert run_export("aws", tmp_path / "a") == 0
    m = json.loads((tmp_path / "a" / "aws-manifest.json").read_text())
    assert m["not_evaluated"] == {"example-finance-records": "AccessDenied"}
    db = tmp_path / "m.db"
    assert ingest(db, "--aws-export", str(tmp_path / "a"), "--k8s", str(FX / "k8s/state.json"),
                  "--ai", str(FX / "ai/inventory.json"), "--at", AT) == 0
    store = Store(str(db))
    bucket = store.entity(FINANCE)
    assert bucket is not None  # not dropped
    assert bucket["attrs"]["sensitive"] is None and bucket["attrs"]["tags_error"].startswith("AccessDenied")
    assert store.findings(status="open", rule_id="PATH-AI-001") == []
    (unknown_path,) = store.findings(status="open", rule_id="PATH-AI-002")
    assert unknown_path["primary_entity"] == FINANCE
    assert [f["primary_entity"] for f in store.findings(status="open", rule_id="POST-S3-001")] == [FINANCE]


@pytest.mark.parametrize("answer, code", [
    (aws_error("SlowDown", message="Please reduce your request rate."), "SlowDown"),
    ({"stdout": '{"TagSet": [{"Key": "data-classif'}, "BadOutput"),
    ({"code": 255, "stderr": "\nCould not connect to the endpoint URL\n"}, "Failed"),
    ({"sleep": 3, "stdout": "{}"}, "Timeout"),
])
def test_other_failures_on_a_bucket_are_not_evaluated(tmp_path, fake_cli, monkeypatch, answer, code):
    monkeypatch.setattr(export, "BUCKET_TIMEOUT", 1)
    plan = recorded_plan()
    plan[tagging("example-finance-records")] = answer
    fake_cli(plan)
    assert run_export("aws", tmp_path / "a") == 0
    tags = json.loads((tmp_path / "a" / "s3-tags.json").read_text())
    assert tags["example-finance-records"]["Error"]["Code"] == code
    assert tags["example-web-assets"] == {"TagSet": []}  # the NoSuchTagSet bucket is a known "no tags"


def _no_complete_export(out, kind):
    """Nothing at all was left behind: no data file, no manifest, no temporary file."""
    return not out.exists() or list(out.iterdir()) == []


@pytest.mark.parametrize("answer", [aws_error("AccessDenied", "GetAccountAuthorizationDetails"),
                                    {"stdout": '{"RoleDetailList": [{"RoleName": "sentinel'}],
                         ids=["iam-denied", "iam-truncated"])
def test_iam_failure_fails_the_export_and_leaves_no_file(tmp_path, fake_cli, capsys, answer):
    plan = recorded_plan()
    plan[IAM] = answer
    fake_cli(plan)
    out = tmp_path / "a"
    assert run_export("aws", out) == 2
    assert _no_complete_export(out, "aws")
    assert "export failed" in capsys.readouterr().err


def test_kubectl_failure_fails_the_export_and_leaves_no_file(tmp_path, fake_cli):
    plan = recorded_plan()
    # kubectl prints the kinds it could list and exits 1 for the one it could not. That
    # partial list must not pass as complete.
    partial = fixture("k8s/state.json")
    partial["items"] = [i for i in partial["items"] if i["kind"] == "Pod"]
    plan[KUBECTL_GET] = {"code": 1, "stdout": json.dumps(partial),
                         "stderr": 'Error from server (Forbidden): networkpolicies.networking.k8s.io is forbidden\n'}
    fake_cli(plan)
    out = tmp_path / "k"
    assert run_export("k8s", out) == 2
    assert _no_complete_export(out, "k8s")


def test_failed_export_leaves_an_earlier_export_whole(tmp_path, fake_cli):
    fake_cli(recorded_plan())
    out = tmp_path / "a"
    assert run_export("aws", out) == 0
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    plan = recorded_plan()
    plan["aws s3api list-buckets --output json"] = {"stdout": '{"Buckets": ['}
    fake_cli(plan)
    assert run_export("aws", out) == 2
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


def test_ingest_refuses_an_export_whose_file_changed(tmp_path, fake_cli, capsys):
    fake_cli(recorded_plan())
    out = tmp_path / "a"
    assert run_export("aws", out) == 0
    tags = out / "s3-tags.json"
    tags.write_text(tags.read_text().replace("sensitive", "public"))
    db = tmp_path / "m.db"
    assert ingest(db, "--aws-export", str(out)) == 2
    assert "does not match the manifest" in capsys.readouterr().err
    assert Store(str(db)).source("aws.state")["status"] == "failed"


# --- where the export goes --------------------------------------------------------------------

def test_files_are_private(tmp_path, fake_cli):
    fake_cli(recorded_plan())
    out = tmp_path / "a"
    assert run_export("aws", out) == 0
    for p in out.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p.name
    assert stat.S_IMODE(out.stat().st_mode) == 0o700


def test_export_refuses_a_path_git_would_commit(tmp_path, fake_cli):
    fake_cli(recorded_plan())
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    assert run_export("aws", repo / "snap") == 2
    assert not (repo / "snap").exists()
    (repo / ".gitignore").write_text("exports/\n")
    assert run_export("aws", repo / "exports" / "aws") == 0


def test_default_output_directory_is_ignored_here():
    root = Path(__file__).resolve().parents[1]
    r = subprocess.run(["git", "check-ignore", "-q", "--", "exports/aws/iam.json"], cwd=root)
    assert r.returncode == 0


def test_k8s_export_keeps_no_env_values_or_last_applied_config(tmp_path, fake_cli):
    state = fixture("k8s/state.json")
    pod = next(i for i in state["items"] if i["kind"] == "Pod")
    pod["spec"]["containers"][0]["env"] = [{"name": "DB_PASSWORD", "value": "example-not-a-secret"}]
    pod["metadata"].setdefault("annotations", {})[export.DROP_ANNOTATION] = '{"env": "example-not-a-secret"}'
    plan = recorded_plan()
    plan[KUBECTL_GET] = {"stdout": json.dumps(state)}
    fake_cli(plan)
    assert run_export("k8s", tmp_path / "k") == 0
    text = (tmp_path / "k" / "k8s.json").read_text()
    assert "example-not-a-secret" not in text and "DB_PASSWORD" in text


def test_cluster_name_comes_from_the_manifest(tmp_path, fake_cli):
    ctx = "arn:aws:eks:us-east-1:111122223333:cluster/lab"
    plan = recorded_plan()
    plan["kubectl config current-context"] = {"stdout": ctx + "\n"}
    plan[KUBECTL_GET.replace("--context lab", f"--context {ctx}")] = plan.pop(KUBECTL_GET)
    fake_cli(plan)
    assert run_export("k8s", tmp_path / "k", "--cluster-name", "lab") == 0
    m = json.loads((tmp_path / "k" / "k8s-manifest.json").read_text())
    assert (m["context"], m["cluster"]) == (ctx, "lab")


# --- two parked nits ------------------------------------------------------------------------------

def test_change_record_for_an_unknown_role_shows_in_findings(tmp_path):
    from codeguardian.v2 import render

    store, pipe = build(tmp_path, iam="aws/iam.json")
    ev = iam_event("PutRolePolicy")
    ev["requestParameters"]["roleName"] = "not-in-the-model"
    pipe.process(ev)
    assert "IAM change records for a role the model does not hold (not applied): 1" in render.findings(store, NOW)


def test_same_change_twice_at_the_same_time_counts_once_without_a_marker(tmp_path):
    # Two records with one timestamp and the same change to the same policy (a retried
    # call, for example) leave the same model whichever comes first, so there is no order
    # to lose and nothing to mark. Both records are kept as events, and detection sees both.
    store, pipe = build(tmp_path, iam="aws/iam.json")
    first = iam_event("PutRolePolicy")
    second = json.loads(json.dumps(first))
    second["eventID"] = "6f1c2a9e-0000-4000-8000-000000000999"
    pipe.process(first)
    pipe.process(second)
    assert store.count_events() == 2
    assert store.counters()["model_changes_applied"] == 2
    assert store.entity(ROLE)["attrs"]["change_markers"] == []
    assert store.findings(status="open", rule_id="POST-IAM-003") == []
    assert len(store.findings(status="open", rule_id="PATH-AI-001")) == 1


# --- names from the environment: never an option, never a broken or forged line ----------------

HOSTILE = ["--endpoint-url=http://203.0.113.9", "bad\nname", "x\nexported account forged at now to exports"]


def _with_hostile_buckets():
    plan = recorded_plan()
    buckets = fixture("aws/s3-buckets.json")
    buckets["Buckets"] += [{"Name": n, "CreationDate": "2026-09-01T12:00:00+00:00"} for n in HOSTILE]
    plan["aws s3api list-buckets --output json"] = {"stdout": json.dumps(buckets)}
    return plan


def test_bucket_names_that_are_not_valid_never_reach_the_cli(tmp_path, fake_cli):
    fake_cli(_with_hostile_buckets())
    assert run_export("aws", tmp_path / "a") == 0
    ran = [arg for argv in fake_cli.log() for arg in argv]
    for name in HOSTILE:
        assert name not in ran
        assert not any(name in arg for arg in ran)
    tags = json.loads((tmp_path / "a" / "s3-tags.json").read_text())
    for name in HOSTILE:
        assert tags[name]["Error"]["Code"] == "InvalidBucketName"
    m = json.loads((tmp_path / "a" / "aws-manifest.json").read_text())
    assert set(m["not_evaluated"]) == set(HOSTILE)


def _lines_are_clean(text):
    assert "\x1b" not in text and "‮" not in text
    assert not any(line.startswith("exported account forged") for line in text.splitlines())


def test_names_and_cli_errors_cannot_break_or_forge_a_terminal_line(tmp_path, fake_cli, capsys):
    fake_cli(_with_hostile_buckets())
    assert run_export("aws", tmp_path / "a") == 0
    out = capsys.readouterr()
    text = out.out + out.err
    _lines_are_clean(text)
    assert "bad\\x0aname" in text  # shown, escaped
    db = tmp_path / "m.db"
    assert ingest(db, "--aws-export", str(tmp_path / "a")) == 0
    out = capsys.readouterr()
    _lines_are_clean(out.out + out.err)
    assert "bad\\x0aname" in out.out
    plan = recorded_plan()
    plan["kubectl config current-context"] = {"stdout": "lab\n"}
    plan[KUBECTL_GET] = {"code": 1, "stderr": "error: \x1b[2Jdenied\nexported account forged at now to exports ‮\n"}
    fake_cli(plan)
    assert run_export("k8s", tmp_path / "k") == 2
    out = capsys.readouterr()
    _lines_are_clean(out.out + out.err)
    assert "\\x1b[2J" in out.err


def test_default_output_is_a_plain_directory_under_exports(tmp_path, fake_cli, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    fake_cli(recorded_plan())
    assert export_main(["aws", "--now", AT]) == 0
    assert export_main(["k8s", "--now", AT]) == 0
    assert (tmp_path / "exports" / "aws" / "aws-manifest.json").is_file()
    assert (tmp_path / "exports" / "k8s" / "k8s-manifest.json").is_file()
    assert sorted(p.name for p in (tmp_path / "exports").iterdir()) == ["aws", "k8s"]
    capsys.readouterr()
    with pytest.raises(SystemExit):
        export_main(["aws", "--help"])
    assert "(default: exports/aws)" in capsys.readouterr().out
