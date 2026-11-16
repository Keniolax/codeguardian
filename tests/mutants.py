"""Mutation run: remove one control at a time and check that the tests naming it fail.

Run from the repository root:  PYTHONPATH=src python tests/mutants.py

For each mutant the script replaces one exact snippet (it must occur exactly once), runs
each named test on its own, and restores the file. A mutant counts as caught only when
pytest exits with code 1 (tests failed). Exit code 2 or more means the mutant broke
collection or imports, which proves nothing, so it is reported as broken. The run fails
if any mutant survives or breaks, if the tree is not clean afterwards, or if a test whose
name starts with test_a_ to test_f_ has no mutant.
"""

import ast
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V2 = "src/codeguardian/v2/"
CHAIN = "tests/test_v2_chain.py"
CORE = "tests/test_v2_core.py"
ASK = "tests/test_v2_ask.py"


def T(name, file=CHAIN):
    return f"{file}::{name}"


MUTANTS = [
    # A: each step of the path is a control.
    ("internal load balancer treated as internet-facing", V2 + "collectors/k8s.py",
     '        if str(ann.get(key, "")).lower() in internal:\n            return False',
     '        if False:\n            return False',
     [T("test_a_each_edge_on_the_path_is_needed[reachable_from]")]),
    ("Service selector ignored", V2 + "collectors/k8s.py",
     "    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())",
     "    return bool(selector)",
     [T("test_a_each_edge_on_the_path_is_needed[exposes]")]),
    ("path hop require (agent on the pod) ignored", V2 + "paths.py",
     "        if not found:\n            return False, set()",
     "        if not found:\n            continue",
     [T("test_a_each_edge_on_the_path_is_needed[contains]")]),
    ("IRSA edge made without the annotation", V2 + "pipeline.py",
     '            linked = [r for r in trusting if r["attrs"]["arn"] == arn]',
     '            linked = trusting',
     [T("test_a_each_edge_on_the_path_is_needed[assumes]")]),
    ("IRSA edge made without the role trust policy", V2 + "pipeline.py",
     '            trusting = [r for r in roles\n                        if trusts_service_account(r["attrs"].get("trust_subjects", []), a["namespace"], a["name"])]',
     '            trusting = roles',
     [T("test_a_irsa_needs_the_role_trust_to_name_the_service_account")]),
    ("sensitive-bucket predicate removed from the path rule", V2 + "rules/paths.toml",
     'where = [{ attr = "sensitive", op = "eq", value = true }]\n', "",
     [T("test_a_each_edge_on_the_path_is_needed[has_permission]"), T("test_a_bucket_must_be_sensitive"),
      T("test_a_path_rule_crosses_domains_and_yields_one_finding")]),
    ("agent left out of the path finding's entities", V2 + "paths.py",
     "        extra |= found", "        pass",
     [T("test_a_path_rule_crosses_domains_and_yields_one_finding")]),
    ("cycle guard removed", V2 + "paths.py",
     "            if other in nodes or not _edge_ok(hop, e):", "            if not _edge_ok(hop, e):",
     [T("test_path_walk_never_reenters_a_node", CORE)]),
    ("hop limit removed", V2 + "rules.py",
     "        _need(len(rule[\"hops\"]) <= MAX_HOPS, rule, f\"{len(rule['hops'])} hops; the limit is {MAX_HOPS}\")\n", "",
     [T("test_rule_validation_refuses_what_it_does_not_understand[rule4-limit]", CORE)]),
    ("unknown edge type accepted by the rule loader", V2 + "rules.py",
     "    _need(s.get(\"edge\") in EDGE_TYPES, rule, f\"unknown edge type {s.get('edge')!r}\")\n", "",
     [T("test_rule_validation_refuses_what_it_does_not_understand[rule3-unknown edge type]", CORE)]),
    # B: the model follows events.
    ("PutRolePolicy not applied to the model", V2 + "pipeline.py",
     '            inline[change["policy_name"]] = aws_collector.decode_document(change["document"])',
     '            pass',
     [T("test_b_event_opens_the_path_and_its_reversal_resolves_the_same_finding"),
      T("test_b_unreadable_policy_document_is_marked_unknown")]),
    ("path finding no longer produced is not resolved", V2 + "pipeline.py",
     '            if old["finding_id"] not in produced:\n                self._resolve(old, at, changes)',
     '            if False:\n                self._resolve(old, at, changes)',
     [T("test_b_event_opens_the_path_and_its_reversal_resolves_the_same_finding"),
      T("test_b_attach_of_a_policy_the_model_holds_opens_and_detach_resolves")]),
    ("unknown policy document silently skipped", V2 + "policy.py",
     "        if doc is None:\n            unknown.append(ref)\n            continue",
     "        if doc is None:\n            continue",
     [T("test_b_attach_of_an_unknown_policy_is_marked_not_silent"),
      T("test_b_unreadable_policy_document_is_marked_unknown")]),
    ("failed CloudTrail call changes the model", V2 + "collectors/events.py",
     'if service == "iam" and name in MODEL_CHANGES and outcome == "success":',
     'if service == "iam" and name in MODEL_CHANGES:',
     [T("test_b_failed_call_does_not_change_the_model")]),
    ("event older than the snapshot applied", V2 + "pipeline.py",
     '        if ev["time"] < role["observed_at"]:', '        if False:',
     [T("test_b_event_older_than_the_snapshot_is_not_applied")]),
    # C: detection needs the graph.
    ("declared data sources not checked", V2 + "detect.py",
     '        elif reached & bound[w["excludes"]]:\n            return None',
     '        elif False:\n            return None',
     [T("test_c_same_event_raises_nothing_when_the_graph_declares_the_bucket"),
      T("test_e_chain_results_survive_a_noisy_replay")]),
    ("actor need not run an agent", V2 + "detect.py",
     "            if not reached:\n                return None", "            pass",
     [T("test_c_control_role_entitled_to_the_bucket_raises_nothing")]),
    ("event actor not joined to the model", V2 + "pipeline.py",
     '        ev["actor"] = self._resolve_ref(hints["actor"])', '        ev["actor"] = None',
     [T("test_c_agent_role_reading_an_undeclared_bucket_alerts")]),
    ("unresolved actor not counted as not evaluated", V2 + "detect.py",
     "    if uses_actor and actor is None:\n        return UNEVALUABLE",
     "    if False:\n        return UNEVALUABLE",
     [T("test_c_unresolved_actor_is_kept_and_counted_not_dropped")]),
    # D: correlation.
    ("findings never join an incident", V2 + "correlate.py",
     '    hits = [i for i in store.incidents("open") if _near(i, at) and key & all_entities(store, i)]',
     '    hits = []',
     [T("test_d_runtime_alert_and_cloud_events_join_one_incident")]),
    ("shared entity not required to join", V2 + "correlate.py",
     '    hits = [i for i in store.incidents("open") if _near(i, at) and key & all_entities(store, i)]',
     '    hits = [i for i in store.incidents("open") if _near(i, at)]',
     [T("test_d_unrelated_pod_alert_stays_in_its_own_incident")]),
    ("time window not checked", V2 + "correlate.py",
     "    return (seconds_between(inc[\"last_seen\"], at) <= WINDOW_SECONDS\n            and seconds_between(at, inc[\"first_seen\"]) <= WINDOW_SECONDS)",
     "    return True",
     [T("test_d_alert_outside_the_time_window_does_not_join")]),
    ("internet node used as a join key", V2 + "correlate.py",
     'HUB_TYPES = {"internet"}', "HUB_TYPES = set()",
     [T("test_internet_node_does_not_join_incidents", CORE)]),
    # E: real time.
    ("every model change re-runs every rule on every entity", V2 + "pipeline.py",
     '    def evaluate_delta(self, delta, at):\n        changes = {"opened": [], "resolved": []}\n        if not delta:\n            return changes\n',
     '    def evaluate_delta(self, delta, at):\n        return self.evaluate_all(at)\n',
     [T("test_e_event_reruns_only_the_rules_its_change_can_affect")]),
    ("posture rules re-run on entities the change did not touch", V2 + "pipeline.py",
     '            for eid, etype in delta.entities.items():\n                if etype == rule["entity"]:\n                    self._posture(rule, eid, at, changes)',
     '            if rule["entity"] in delta.entity_types:\n                for ent in self.store.entities(rule["entity"]):\n                    self._posture(rule, ent["id"], at, changes)',
     [T("test_e_event_reruns_only_the_rules_its_change_can_affect")]),
    ("duplicate events processed again", V2 + "pipeline.py",
     '        if self.store.has_event(ev["event_id"]):', '        if False:',
     [T("test_e_replaying_the_same_events_changes_nothing")]),
    ("a bad line stops watch", V2 + "cli.py",
     '                bad += 1\n                print(f"skipped a line that is not JSON: {exc}", file=sys.stderr)\n                continue',
     '                raise',
     [T("test_e_watch_processes_records_as_they_arrive_on_stdin")]),
    ("generator not seeded", V2 + "gen.py",
     "    rng = random.Random(seed)", "    rng = random.Random()",
     [T("test_e_generator_is_deterministic")]),
    # F: the model explains; response is a dry-run catalog.
    ("model's status applied to the store", V2 + "explain.py",
     '            texts[fid] = (_text(entry["explanation"], MAX_TEXT), _text(entry["next_step"], MAX_TEXT))',
     '            texts[fid] = (_text(entry["explanation"], MAX_TEXT), _text(entry["next_step"], MAX_TEXT))\n'
     '            if entry.get("status"):\n                store.put_finding({**stored[fid], "status": entry["status"]})',
     [T("test_f_model_answer_is_joined_by_id_and_cannot_change_anything"),
      T("test_f_planted_text_changes_no_finding_incident_or_plan")]),
    ("unknown finding ID not dropped", V2 + "explain.py",
     "            if fid not in stored or fid in texts:", "            if fid in texts:",
     [T("test_f_model_answer_is_joined_by_id_and_cannot_change_anything")]),
    ("action outside the catalog accepted", V2 + "respond.py",
     "    if spec is None:\n        raise ActionError(f\"action {action_id!r} is not in the catalog\")",
     "    if spec is None:\n        return {\"action_id\": action_id, \"params\": dict(params)}",
     [T("test_f_unknown_action_is_refused"), T("test_f_model_answer_is_joined_by_id_and_cannot_change_anything")]),
    ("model action may name a role outside the incident", V2 + "respond.py",
     '        if role is None:\n            raise ActionError(f"{a[\'action_id\']} names a role outside this incident")',
     '        if role is None:\n            return a',
     [T("test_f_model_answer_is_joined_by_id_and_cannot_change_anything")]),
    ("parameter patterns not checked", V2 + "respond.py",
     "        if not isinstance(params[name], str) or not pattern.fullmatch(params[name]):",
     "        if not isinstance(params[name], str):",
     [T("test_f_hostile_parameters_are_refused[params0]"), T("test_f_hostile_parameters_are_refused[params1]")]),
    ("extra parameters accepted", V2 + "respond.py",
     "    if not isinstance(params, dict) or set(params) != set(spec[\"params\"]):",
     "    if not isinstance(params, dict) or not set(spec[\"params\"]) <= set(params):",
     [T("test_f_hostile_parameters_are_refused[params2]")]),
    ("plan skips parameter checks", V2 + "respond.py",
     "            step = check_action(action_id, params)",
     "            step = {\"action_id\": action_id, \"params\": dict(params)}",
     [T("test_f_hostile_name_from_the_environment_never_reaches_a_plan")]),
    ("quarantine manifest selects by environment text", V2 + "respond.py",
     '        f"      {QUARANTINE_LABEL}: \\"true\\"\\n"', '        f"      app: {pod}\\n"',
     [T("test_f_plan_is_a_catalog_dry_run_with_exact_text")]),
    ("renderer does not escape", V2 + "render.py",
     "from ..render import safe\n", "def safe(text, limit=1500):\n    return str(text)[:limit]\n",
     [T("test_f_rendered_output_escapes_planted_and_model_text")]),
    ("a code path that runs a command", V2 + "respond.py",
     "import re\nimport shlex\n", "import re\nimport shlex\nimport subprocess\n",
     [T("test_f_no_code_path_executes_anything")]),
    ("logic reads the wall clock", V2 + "pipeline.py",
     '        ev["ingested_at"] = self.clock.now()',
     '        from datetime import datetime\n        ev["ingested_at"] = datetime.now().isoformat()',
     [T("test_f_logic_reads_time_only_from_the_data_or_the_injected_clock")]),
    # Collectors fail loudly; stale is not safe.
    ("collector failure recorded as success", V2 + "pipeline.py",
     "                self.store.record_source(name, False, at, str(exc))\n                errors.append(str(exc))",
     "                self.store.record_source(name, True, at)",
     [T("test_bad_k8s_input_fails_loudly_and_marks_facts_stale[{}]", CORE)]),
    ("failed source does not make facts stale", V2 + "store.py",
     '        if health is None or health["status"] != "ok":\n            return True',
     '        if health is None:\n            return True',
     [T("test_bad_k8s_input_fails_loudly_and_marks_facts_stale[not json]", CORE)]),
    ("k8s shape check removed, so a wrong file sweeps the model", V2 + "collectors/k8s.py",
     '    need(isinstance(data, dict) and isinstance(data.get("items"), list), "k8s",\n         "expected `kubectl get ... -o json` output with items")\n',
     '    data = data if isinstance(data, dict) and isinstance(data.get("items"), list) else {"items": []}\n',
     [T("test_bad_k8s_input_fails_loudly_and_marks_facts_stale[{}]", CORE)]),
    ("untagged buckets accepted", V2 + "collectors/aws.py",
     '        need(isinstance(tags.get(name), dict) and isinstance(tags[name].get("TagSet"), list), "aws s3 tags",\n'
     '             f"no tagging output for bucket {name!r}; tags were not collected")\n',
     '        tags.setdefault(name, {"TagSet": []})\n',
     [T("test_missing_bucket_tags_refuse_the_snapshot", CORE)]),
    # ask (stretch): the model's query is checked before it runs.
    ("ask accepts unknown query keys", V2 + "ask.py",
     "    if extra:\n        raise QueryError(f\"unknown query keys {sorted(extra)}\")", "    pass",
     [T("test_ask_refuses_malformed_and_out_of_schema_queries[query2]", ASK)]),
    ("ask skips the condition check", V2 + "ask.py",
     "        for c in where:\n            R._cond(c, {\"id\": \"query\"}, q[\"find\"])", "        pass",
     [T("test_ask_refuses_malformed_and_out_of_schema_queries[query4]", ASK),
      T("test_ask_refuses_malformed_and_out_of_schema_queries[query5]", ASK)]),
    ("resolver hides Condition", V2 + "policy.py",
     '                    if conditional:\n                        g["not_evaluated"].add(f"Condition in {where} not evaluated")',
     '                    pass',
     [T("test_resolver_marks_condition_deny_notaction_and_boundary", CORE)]),
]


def pytest(node):
    env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", node],
                          cwd=ROOT, env=env, capture_output=True, text=True).returncode


def chain_tests():
    tree = ast.parse((ROOT / CHAIN).read_text())
    return sorted(n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name[:7] in
                  {f"test_{c}_" for c in "abcdef"})


def tree_state():
    out = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
    digest = hashlib.sha256()
    for path in sorted((ROOT / "src").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(path.read_bytes())
    return out, digest.hexdigest()


def main():
    covered = {node.split("::", 1)[1].split("[", 1)[0] for *_, tests in MUTANTS for node in tests if node.startswith(CHAIN)}
    missing = [t for t in chain_tests() if t not in covered]
    if missing:
        print("tests with no mutant:", ", ".join(missing))
        return 1
    nodes = sorted({node for *_, tests in MUTANTS for node in tests})
    baseline = [n for n in nodes if pytest(n) != 0]
    if baseline:
        print("tests that fail before any mutation:", ", ".join(baseline))
        return 1
    start = tree_state()
    results = []
    for name, file, old, new, tests in MUTANTS:
        path = ROOT / file
        original = path.read_text(encoding="utf-8")
        if original.count(old) != 1:
            results.append((name, "-", f"ANCHOR NOT FOUND EXACTLY ONCE ({original.count(old)})"))
            continue
        try:
            path.write_text(original.replace(old, new), encoding="utf-8")
            for node in tests:
                code = pytest(node)
                verdict = "caught" if code == 1 else ("SURVIVED" if code == 0 else f"BROKEN (exit {code})")
                results.append((name, node.split("::", 1)[1], verdict))
        finally:
            path.write_text(original, encoding="utf-8")
    width = max(len(r[0]) for r in results)
    for name, node, verdict in results:
        print(f"{verdict:<10} {name:<{width}}  {node}")
    caught = sum(r[2] == "caught" for r in results)
    print(f"\n{len(MUTANTS)} mutants, {len(results)} mutant-test pairs, {caught} caught, "
          f"{len(results) - caught} not caught; {len(chain_tests())} A-F tests, all covered")
    if tree_state() != start:
        print("THE TREE CHANGED during the run")
        return 1
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
