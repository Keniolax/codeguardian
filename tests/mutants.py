"""Mutation run: remove one control at a time and check that the tests naming it fail.

Run from the repository root:  PYTHONPATH=src python tests/mutants.py

For each mutant the script replaces one exact snippet (it must occur exactly once), runs
each named test on its own, and restores the file. A mutant counts as caught only when
pytest exits with code 1 (tests failed). Exit code 2 or more means the mutant broke
collection or imports, which proves nothing, so it is reported as broken. The run fails
if any mutant survives or breaks, if the tree is not clean afterwards, or if a test whose
name starts with test_a_ to test_f_, or any test in the export, NetworkPolicy or order files,
has no mutant. In the NetworkPolicy and order files every parametrized case must also have a
mutant of its own.
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
EXP = "tests/test_v2_export.py"
EXPORT = "src/codeguardian/export/__init__.py"
NET = "tests/test_v2_netpol.py"
NP = V2 + "netpol.py"
K8S = V2 + "collectors/k8s.py"
ORDER = "tests/test_v2_order.py"
PL = V2 + "pipeline.py"
HIST = V2 + "history.py"


def T(name, file=CHAIN):
    return f"{file}::{name}"


DENY_TEST = "test_default_deny_removes_the_path_and_removing_it_brings_back_the_same_finding"
DENY_FORMS = ("empty-ingress-list", "empty-selector", "label-selector", "no-policy-types")
UNHANDLED_TEST = "test_construct_that_is_not_handled_keeps_the_path_open_with_a_note"
UNHANDLED = ("bad-cidr", "end-port", "host-network", "named-port", "unknown-operator", "unknown-peer",
             "unknown-policy-type", "ambiguous-named-port", "bad-end-port", "bad-except", "bad-ingress", "bad-rule",
             "bad-selector", "except-not-a-list", "ipblock-with-selector", "no-service-ports", "service-port-unknown",
             "unknown-protocol", "unknown-service-protocol")
EXPR_TEST = "test_match_expressions_select_pods_as_the_reference_says"
IPBLOCK_TEST = "test_ipblock_of_every_address_opens_the_path_and_excepting_the_source_range_closes_it"
PORT_TEST = "test_allow_on_another_port_or_protocol_does_not_open_the_path"
LAYOUT_TEST = "test_course_layout_client_reaches_the_shop_and_outsider_and_internet_do_not"
PEER_TEST = "test_pod_selector_alone_means_the_policy_namespace_and_both_selectors_must_match"
EVERY_ORDER = "test_every_order_of_two_snapshots_and_four_change_records_ends_the_same"
OLDER = "test_snapshot_older_than_the_last_applied_is_refused_and_changes_nothing"
PER_SOURCE = "test_refusal_is_per_collector"
SAME_TIME = "test_same_time_other_content_is_refused_and_marked_and_same_content_is_a_no_op"
REPLAY = "test_replaying_everything_changes_nothing"
NORMALISED = "test_snapshot_time_is_normalised_so_string_order_is_time_order"
INGEST = "test_ingest_says_a_snapshot_was_refused_and_exits_3"
PENDING = "test_change_record_for_a_role_not_yet_in_the_model_applies_when_a_snapshot_brings_it"
HELD = "test_detection_whose_target_is_not_in_the_model_is_held_and_decided_later"
NEVER_RAN = "test_detection_that_walks_a_collector_that_never_ran_is_held_not_passed"
DATA_TIME = "test_detection_findings_keep_their_records_in_data_time"
FEW_ORDERS = "test_a_few_orders_give_the_same_model_and_history"
AT_SNAPSHOT = "test_record_at_the_time_of_a_snapshot_counts_after_it"
REOPENED = "test_a_path_that_closes_and_opens_again_is_reopened_in_the_history"
REBUILDS = "test_history_replay_rebuilds_the_live_model_with_its_cluster_and_outside_range"
NOT_BEFORE = "test_finding_found_after_an_older_snapshot_is_not_dated_before_its_data"
LATE_DELETE = "test_path_open_from_10_00_to_10_20_shows_in_the_history_when_the_delete_arrives_first"
HIST_OUT = "test_findings_history_names_each_change_and_escapes_text"
BROKEN_OLDER = "test_broken_snapshot_older_than_the_last_good_one_changes_nothing"
AT_EITHER = "test_record_at_a_snapshots_time_counts_after_it_whichever_arrives_first"
NEWER_FAILURE = "test_newer_failed_export_still_stands_when_an_older_snapshot_arrives_after_it"
REFUSED_AGAIN = "test_a_refused_snapshot_sent_again_is_refused_again"


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
    ("edge_allows not checked", V2 + "paths.py",
     "    return all(any(action_matches(p, a) for p in patterns) for a in allows)", "    return True",
     [T("test_a_role_must_be_able_to_read_not_only_write_or_list")]),
    ("cycle guard removed", V2 + "paths.py",
     "            if other in nodes or not _edge_ok(hop, e):", "            if not _edge_ok(hop, e):",
     [T("test_path_walk_never_reenters_a_node", CORE)]),
    ("hop limit removed", V2 + "rules.py",
     "        _need(len(rule[\"hops\"]) <= MAX_HOPS, rule, f\"{len(rule['hops'])} hops; the limit is {MAX_HOPS}\")\n", "",
     [T("test_rule_validation_refuses_what_it_does_not_understand[rule4-limit]", CORE)]),
    ("unknown edge type accepted by the rule loader", V2 + "rules.py",
     "    _need(_is(s.get(\"edge\"), EDGE_TYPES), rule, f\"unknown edge type {s.get('edge')!r}\")\n", "",
     [T("test_rule_validation_refuses_what_it_does_not_understand[rule3-unknown edge type]", CORE)]),
    # B: the model follows events.
    ("PutRolePolicy not applied to the model", V2 + "collectors/aws.py",
     '        inline[key[len("inline:"):]] = entry["doc"]',
     '        pass',
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
     '        if ev["time"] < role["last_seen"]:', '        if False:',
     [T("test_b_event_older_than_the_snapshot_is_not_applied")]),
    ("delete and detach leave no tombstone for ordering", V2 + "pipeline.py",
     '        if last and ev["time"] < last["time"]:',
     '        if last and last["op"] in ("put", "attach") and ev["time"] < last["time"]:',
     [T("test_b_delete_then_late_put_ends_with_no_path_finding"), T("test_b_every_order_of_the_iam_changes_ends_the_same")]),
    ("changes ordered per role, not per policy", V2 + "pipeline.py",
     '        last = changes.get(key)',
     '        last = max(changes.values(), key=lambda e: e["time"], default=None)',
     [T("test_b_late_put_of_another_policy_still_applies")]),
    ("role-level time guard (the old bug)", V2 + "pipeline.py",
     '        if ev["time"] < role["last_seen"]:', '        if ev["time"] < role["observed_at"]:',
     [T("test_b_late_put_of_another_policy_still_applies"), T("test_b_every_order_of_the_iam_changes_ends_the_same")]),
    ("snapshot drops changes newer than itself", V2 + "collectors/aws.py",
     "            attrs = apply_policy_change(attrs, key, e)", "            pass",
     [T("test_b_snapshot_keeps_newer_event_changes_and_supersedes_older_ones")]),
    ("two changes at the same time applied in arrival order", V2 + "pipeline.py",
     "            return \"not_evaluated\", self._mark(role, a, ev, f\"two different changes to {key} at {ev['time']};\"\n"
     "                                                            \" order unknown, not evaluated\")",
     "            pass",
     [T("test_b_two_changes_at_the_same_time_are_marked_not_dropped")]),
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
    ("event outcome not checked", V2 + "detect.py",
     '    if "outcome" in m and ev["outcome"] != m["outcome"]:', "    if False:",
     [T("test_c_denied_read_raises_nothing_but_is_kept")]),
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
    ("path rule re-runs on every model change", V2 + "pipeline.py",
     '            if ents & delta.entity_types or edges & delta.edge_types:\n                self._path(rule, at, changes)',
     '            self._path(rule, at, changes)',
     [T("test_e_path_rule_reruns_only_when_a_type_it_follows_changes")]),
    ("posture rules re-run on entities the change did not touch", V2 + "pipeline.py",
     '            for eid, etype in delta.entities.items():\n                if etype == rule["entity"]:\n                    self._posture(rule, eid, at, changes)',
     '            if rule["entity"] in delta.entity_types:\n                for ent in self.store.entities(rule["entity"]):\n                    self._posture(rule, ent["id"], at, changes)',
     [T("test_e_event_reruns_only_the_rules_its_change_can_affect")]),
    ("duplicate events processed again", V2 + "pipeline.py",
     '        if self.store.has_event(ev["event_id"]):', '        if False:',
     [T("test_e_replaying_the_same_events_changes_nothing"),
      T("test_b_replay_after_out_of_order_changes_changes_nothing")]),
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
     [T("test_f_rendered_output_escapes_planted_and_model_text"),
      T("test_policy_names_and_selector_text_cannot_change_a_finding_or_forge_a_line", NET)]),
    ("a code path that runs a command", V2 + "respond.py",
     "import re\nimport shlex\n", "import re\nimport shlex\nimport subprocess\n",
     [T("test_f_no_code_path_executes_anything")]),
    ("logic reads the wall clock", V2 + "pipeline.py",
     '        ev["ingested_at"] = self.clock.now()',
     '        from datetime import datetime\n        ev["ingested_at"] = datetime.now().isoformat()',
     [T("test_f_logic_reads_time_only_from_the_data_or_the_injected_clock")]),
    ("model's action_id used before its type is checked", V2 + "respond.py",
     "    spec = CATALOG.get(action_id) if isinstance(action_id, str) else None",
     "    spec = CATALOG.get(action_id)",
     [T("test_f_model_values_of_the_wrong_type_are_dropped_not_fatal")]),
    # Collectors fail loudly; stale is not safe.
    ("collector failure recorded as success", V2 + "pipeline.py",
     "                    self.store.record_source(name, False, at, str(exc))\n                    errors.append(str(exc))",
     "                    self.store.record_source(name, True, at)",
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
     '        need(ok, "aws s3 tags", f"no tagging output for bucket {name!r}; tags were not collected")\n',
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
    ("ask uses the entity type before its type is checked", V2 + "ask.py",
     '    if not isinstance(q.get("find"), str) or q["find"] not in ENTITY_TYPES:',
     '    if q.get("find") not in ENTITY_TYPES:',
     [T("test_ask_refuses_malformed_and_out_of_schema_queries[query9]", ASK)]),
    ("skipped NotAction statement leaves no marker", V2 + "policy.py",
     '                markers.add(f"{where}: NotAction/NotResource not evaluated")', "                pass",
     [T("test_skipped_statement_is_a_visible_finding_not_a_silent_deny", CORE)]),
    ("source that never ran is not listed", V2 + "render.py",
     '        if s is None:\n            lines.append(f"- source {name}: NEVER RUN.',
     '        if s is None:\n            continue\n            lines.append(f"- source {name}: NEVER RUN.',
     [T("test_first_run_failure_reports_failed_not_empty", CORE)]),
    ("source past its refresh period shown as ok", V2 + "render.py",
     '        elif seconds_between(s["last_success"], now) > REFRESH_SECONDS[name]:',
     '        elif False:',
     [T("test_source_past_its_refresh_period_is_shown_stale", CORE)]),
    # Export: read-only, and missing knowledge is not safe.
    ("export runs commands that are not on the read-only list", EXPORT,
     "    if not allowed(argv):", "    if False:",
     [T(f"test_run_refuses_any_command_that_is_not_a_listed_read[argv{n}]", EXP) for n in range(5)]),
    ("failure on a bucket's tags recorded as no tags", EXPORT,
     '        return {"Error": {"Code": exc.error_code or "Failed", "Message": exc.stderr.strip()[:300]}}',
     '        return {"TagSet": []}',
     [T("test_access_denied_on_one_bucket_is_not_evaluated_not_untagged", EXP),
      T("test_other_failures_on_a_bucket_are_not_evaluated[answer0-SlowDown]", EXP),
      T("test_other_failures_on_a_bucket_are_not_evaluated[answer2-Failed]", EXP),
      T("test_other_failures_on_a_bucket_are_not_evaluated[answer3-Timeout]", EXP)]),
    ("bucket tags that are not JSON recorded as no tags", EXPORT,
     '        return {"Error": {"Code": "BadOutput", "Message": str(exc)[:300]}}', '        return {"TagSet": []}',
     [T("test_other_failures_on_a_bucket_are_not_evaluated[answer1-BadOutput]", EXP)]),
    ("IAM failure does not stop the export", EXPORT,
     '    iam = run_json(["aws", "iam", "get-account-authorization-details", "--output", "json"], "IAM")',
     '    try:\n        iam = run_json(["aws", "iam", "get-account-authorization-details", "--output", "json"], "IAM")\n'
     '    except ExportError:\n        iam = {"RoleDetailList": []}',
     [T("test_iam_failure_fails_the_export_and_leaves_no_file[iam-denied]", EXP),
      T("test_iam_failure_fails_the_export_and_leaves_no_file[iam-truncated]", EXP)]),
    ("output that is not JSON read as empty", EXPORT,
     '        raise ExportError(f"{what}: the output is not complete JSON ({exc})") from exc',
     '        return {"RoleDetailList": [], "Buckets": [], "items": [], "TagSet": []}',
     [T("test_iam_failure_fails_the_export_and_leaves_no_file[iam-truncated]", EXP),
      T("test_failed_export_leaves_an_earlier_export_whole", EXP)]),
    ("a command's exit status ignored", EXPORT,
     "    if proc.returncode != 0:", "    if False:",
     [T("test_kubectl_failure_fails_the_export_and_leaves_no_file", EXP)]),
    ("git work tree not checked", EXPORT, "    root = _git_root(out)", "    root = None",
     [T("test_export_refuses_a_path_git_would_commit", EXP)]),
    ("export files readable by others", EXPORT, "            os.chmod(tmp, 0o600)", "            os.chmod(tmp, 0o644)",
     [T("test_files_are_private", EXP)]),
    ("pod env values kept", EXPORT, '                    env["value"] = "<removed by export>"', "                    pass",
     [T("test_k8s_export_keeps_no_env_values_or_last_applied_config", EXP)]),
    ("a write command added to the read-only list", EXPORT,
     '    ("git", "check-ignore"),\n)', '    ("git", "check-ignore"),\n    ("aws", "iam", "put-role-policy"),\n)',
     [T("test_the_read_only_list_holds_only_reads", EXP)]),
    ("kubectl context not pinned", EXPORT,
     '["kubectl", "get", K8S_KINDS, "-A", "-o", "json", "--context", context]',
     '["kubectl", "get", K8S_KINDS, "-A", "-o", "json"]',
     [T("test_every_command_the_export_ran_is_a_read", EXP)]),
    ("a second place that starts a process", EXPORT,
     "    for p in [path, *path.parents]:",
     "    subprocess.run([\"true\"])\n    for p in [path, *path.parents]:",
     [T("test_only_run_starts_a_process_and_never_through_a_shell", EXP)]),
    ("cluster name override ignored", EXPORT,
     '"cluster": cluster_name or context}', '"cluster": context}',
     [T("test_cluster_name_comes_from_the_manifest", EXP)]),
    ("default export directory not ignored by git", ".gitignore", "exports/\n", "",
     [T("test_default_output_directory_is_ignored_here", EXP)]),
    ("bucket names not checked before they reach the CLI", EXPORT,
     'BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")', 'BUCKET_NAME = re.compile(r".*", re.S)',
     [T("test_bucket_names_that_are_not_valid_never_reach_the_cli", EXP)]),
    ("terminal output not escaped", V2 + "render.py",
     "        if c.isprintable():", "        if True:",
     [T("test_names_and_cli_errors_cannot_break_or_forge_a_terminal_line", EXP)]),
    ("default output directory not under exports/", "src/codeguardian/export/__main__.py",
     'default=f"exports/{kind}"', 'default="exports"',
     [T("test_default_output_is_a_plain_directory_under_exports", EXP)]),
    ("help text names the wrong default", "src/codeguardian/export/__main__.py",
     'help=f"output directory (default: exports/{kind})"', 'help="output directory (default: exports/%(prog)s)"',
     [T("test_default_output_is_a_plain_directory_under_exports", EXP)]),
    ("manifest hashes not checked at ingest", V2 + "collectors/manifest.py",
     "        if sha256(data) != files[name]:", "        if False:",
     [T("test_ingest_refuses_an_export_whose_file_changed", EXP)]),
    ("tags that could not be read ingested as untagged", V2 + "collectors/aws.py",
     '        entry = data["tags"][name]\n',
     '        entry = data["tags"][name] if "TagSet" in data["tags"][name] else {"TagSet": []}\n',
     [T("test_access_denied_on_one_bucket_is_not_evaluated_not_untagged", EXP)]),
    ("path rule for unknown sensitivity matches every bucket", V2 + "rules/paths.toml",
     'where = [{ attr = "tags_error", op = "nonempty" }]\n', "",
     [T("test_access_denied_on_one_bucket_is_not_evaluated_not_untagged", EXP)]),
    ("ingest ignores the manifest's time", V2 + "cli.py",
     '            jobs.append({"aws": (paths["iam"], paths["buckets"], paths["tags"]), "at": m["exported_at"]})',
     '            jobs.append({"aws": (paths["iam"], paths["buckets"], paths["tags"]), "at": None})',
     [T("test_export_then_ingest_gives_the_same_findings_and_incident_as_the_fixtures", EXP)]),
    ("ingest ignores the manifest's cluster name", V2 + "cli.py",
     '            store.set_setting("cluster", m["cluster"])\n', "",
     [T("test_export_then_ingest_gives_the_same_findings_and_incident_as_the_fixtures", EXP)]),
    ("records for a role not in the model not shown", V2 + "render.py",
     '    "model_change_role_not_in_model": "IAM change records for a role the model does not hold (not applied)",\n', "",
     [T("test_change_record_for_an_unknown_role_shows_in_findings", EXP)]),
    ("the same change twice at one time marked as a conflict", V2 + "pipeline.py",
     '        if last and ev["time"] == last["time"] and (last["op"], last["doc"]) != (entry["op"], entry["doc"]):',
     '        if last and ev["time"] == last["time"]:',
     [T("test_same_change_twice_at_the_same_time_counts_once_without_a_marker", EXP)]),
    ("resolver hides Condition", V2 + "policy.py",
     '                    if conditional:\n                        g["not_evaluated"].add(f"Condition in {where} not evaluated")',
     '                    pass',
     [T("test_resolver_marks_condition_deny_notaction_and_boundary", CORE)]),
    # NetworkPolicy (slice netpol): each check, and each "not evaluated" that must not read as a deny.
    ("a pod no policy selects is treated as isolated", NP,
     "    answer = _or(_not(_or(*isolated)), *allows)", "    answer = _or(*allows)",
     [T("test_chain_without_a_policy_keeps_its_one_path_finding", NET)]),
    ("exposes edge ignores NetworkPolicy", K8S,
     "                answer, names, notes = netpol.service_ingress(netpols, pattrs, ports, source)",
     "                answer, names, notes = True, [], set()",
     [T(f"{DENY_TEST}[{form}]", NET) for form in DENY_FORMS]),
    ("path rule ignores the edge condition", V2 + "paths.py",
     '    if not all(R.check(c, edge["attrs"]) for c in hop.get("edge_where", [])):\n        return False\n', "",
     [T(f"{DENY_TEST}[empty-selector]", NET)]),
    ("PATH-AI-001 drops its NetworkPolicy condition", V2 + "rules/paths.toml",
     '# keeps the path open.\nedge_where = [{ attr = "ingress_from_outside", op = "ne", value = "denied" }]\n',
     "# keeps the path open.\n",
     [T(f"{DENY_TEST}[empty-selector]", NET),
      T("test_allow_for_a_namespace_label_does_not_open_the_path_from_the_internet", NET)]),
    ("not evaluated closes the path as a deny would", V2 + "rules/paths.toml",
     '# keeps the path open.\nedge_where = [{ attr = "ingress_from_outside", op = "ne", value = "denied" }]',
     '# keeps the path open.\nedge_where = [{ attr = "ingress_from_outside", op = "eq", value = "allowed" }]',
     [T(f"{UNHANDLED_TEST}[{case}]", NET) for case in UNHANDLED]),
    ("an empty podSelector selects nothing", NP,
     "    if not match and not exprs:\n        return True", "    if not match and not exprs:\n        return False",
     [T(f"{DENY_TEST}[empty-selector]", NET)]),
    ("matchLabels never match", NP, "            results.append(labels.get(key) == value)",
     "            results.append(False)", [T(f"{DENY_TEST}[label-selector]", NET)]),
    ("matchLabels always match", NP, "            results.append(labels.get(key) == value)",
     "            results.append(True)", [T("test_policy_that_selects_another_pod_changes_nothing", NET)]),
    ("a policy with no policyTypes does not cover ingress", NP,
     '        if direction == "Ingress":\n            return True',
     '        if direction == "Ingress":\n            return False',
     [T(f"{DENY_TEST}[no-policy-types]", NET)]),
    ("an empty ingress list allows everything", NP,
     '            matched = _or(*[_rule(r, p["namespace"], source, target, protocol, pod, what, notes) for r in rules])',
     '            matched = _or(*[_rule(r, p["namespace"], source, target, protocol, pod, what, notes) for r in rules])'
     " if rules else True",
     [T(f"{DENY_TEST}[empty-ingress-list]", NET)]),
    ("pod and namespace selectors match outside traffic", NP,
     "        return False  # these select pods; an outside address is not a pod",
     "        return True  # these select pods; an outside address is not a pod",
     [T("test_allow_for_a_namespace_label_does_not_open_the_path_from_the_internet", NET)]),
    ("ipBlock except ignored", NP, "        inside = [e for e in excepts if e.overlaps(part)]", "        inside = []",
     [T(IPBLOCK_TEST, NET)]),
    ("ipBlock matches a source range it does not hold", NP,
     "        if s.version != net.version or not s.overlaps(net):\n            continue",
     "        if s.version != net.version:\n            continue", [T(IPBLOCK_TEST, NET)]),
    ("excepts checked one at a time, not together", NP,
     "        if list(ipaddress.collapse_addresses(inside)) != [part]:", "        if True:", [T(IPBLOCK_TEST, NET)]),
    ("outside range not passed to the collector", V2 + "pipeline.py",
     "snapshot_content(name, data, self.cluster, self.outside)",
     "snapshot_content(name, data, self.cluster, netpol.OUTSIDE)", [T(IPBLOCK_TEST, NET)]),
    ("rule ports not checked", NP,
     "    port_ok = _or(*[_port(p, target, protocol, pod, what, notes) for p in ports]) if ports else True",
     "    port_ok = True", [T(PORT_TEST, NET), T(LAYOUT_TEST, NET)]),
    ("rule protocol not checked", NP,
     '    if (entry.get("protocol") or "TCP") != protocol:\n        return False', "    if False:\n        return False",
     [T(PORT_TEST, NET), T(LAYOUT_TEST, NET)]),
    ("policy namespace not checked", NP,
     '    isolated, allows = [], []\n    for p in policies:\n        if p.get("namespace") != pod["namespace"]:',
     "    isolated, allows = [], []\n    for p in policies:\n        if False:",
     [T("test_policy_in_another_namespace_with_a_matching_selector_changes_nothing", NET)]),
    ("policyTypes ignored", NP, "    return direction in types", "    return True",
     [T("test_egress_only_policy_does_not_isolate_the_pod_for_ingress", NET)]),
    ("In read as NotIn", NP, '        return found if op == "In" else not found', "        return not found",
     [T(f"{EXPR_TEST}[in-selects]", NET), T(f"{EXPR_TEST}[in-other]", NET)]),
    ("NotIn read as In", NP, '        return found if op == "In" else not found', "        return found",
     [T(f"{EXPR_TEST}[notin-selects]", NET), T(f"{EXPR_TEST}[notin-other]", NET)]),
    ("NotIn requires the key to be present", NP, '        return found if op == "In" else not found',
     '        return found if op == "In" else (key in labels and not found)',
     [T(f"{EXPR_TEST}[notin-absent-key]", NET)]),
    ("Exists and DoesNotExist swapped", NP, '        return (key in labels) == (op == "Exists")',
     '        return (key in labels) != (op == "Exists")',
     [T(f"{EXPR_TEST}[exists]", NET), T(f"{EXPR_TEST}[doesnotexist]", NET)]),
    ("endPort range read as a deny", NP,
     'depends on the network plugin; not evaluated")\n        return None',
     'depends on the network plugin; not evaluated")\n        return False', [T(f"{UNHANDLED_TEST}[end-port]", NET)]),
    ("named port that cannot be resolved read as a deny", NP,
     'not found once on the pod; not evaluated")\n            return None',
     'not found once on the pod; not evaluated")\n            return False', [T(f"{UNHANDLED_TEST}[named-port]", NET)]),
    ("unknown operator read as no match", NP,
     'with {len(values)} values not evaluated")\n    return None',
     'with {len(values)} values not evaluated")\n    return False', [T(f"{UNHANDLED_TEST}[unknown-operator]", NET)]),
    ("unknown policyTypes read as not applying", NP,
     'notes.add(f"{what}: policyTypes {_clip(types)} not evaluated")\n        return None',
     'notes.add(f"{what}: policyTypes {_clip(types)} not evaluated")\n        return False',
     [T(f"{UNHANDLED_TEST}[unknown-policy-type]", NET)]),
    ("invalid ipBlock read as no match", NP,
     'is not a valid CIDR; not evaluated")\n        return None',
     'is not a valid CIDR; not evaluated")\n        return False', [T(f"{UNHANDLED_TEST}[bad-cidr]", NET)]),
    ("unknown from entry read as no match", NP,
     '    if not peer or set(peer) - PEER_KEYS:\n        notes.add(f"{what}: from entry {_clip(peer)} not evaluated")\n'
     "        return None",
     '    if not peer or set(peer) - PEER_KEYS:\n        notes.add(f"{what}: from entry {_clip(peer)} not evaluated")\n'
     "        return False", [T(f"{UNHANDLED_TEST}[unknown-peer]", NET)]),
    ("host-network pod read as denied", NP, '    if answer is False and pod.get("host_network"):', "    if False:",
     [T(f"{UNHANDLED_TEST}[host-network]", NET)]),
    ("namespace entities not written", K8S,
     '        if item["kind"] == NAMESPACE:\n            md = item["metadata"]', '        if False:\n            md = item["metadata"]',
     [T(LAYOUT_TEST, NET), T("test_k8s_export_lists_namespaces_and_ingest_keeps_their_labels", EXP)]),
    ("namespaceSelector ignored", NP,
     '        ns_ok = selects(peer["namespaceSelector"], source["namespace_labels"], f"{what} namespaceSelector", notes)',
     "        ns_ok = True", [T(LAYOUT_TEST, NET)]),
    ("named Service targetPort not resolved", NP,
     "            number = named_port(pod, target, protocol)\n            if number is None:\n"
     '                notes.add(f"Service targetPort',
     "            number = None\n            if number is None:\n"
     '                notes.add(f"Service targetPort', [T(LAYOUT_TEST, NET)]),
    ("a podSelector alone matches pods in every namespace", NP, '        ns_ok = source["namespace"] == policy_ns',
     "        ns_ok = True", [T(PEER_TEST, NET)]),
    ("namespaceSelector and podSelector in one entry ORed", NP, "    return _and(ns_ok, pod_ok)",
     "    return _or(ns_ok, pod_ok)", [T(PEER_TEST, NET)]),
    ("labels that are not known read as no match", NP,
     '        notes.add(f"{what}: labels not known; selector not evaluated")\n        return None',
     '        notes.add(f"{what}: labels not known; selector not evaluated")\n        return False',
     [T("test_namespace_labels_that_are_not_in_the_snapshot_read_as_not_evaluated", NET)]),
    ("egress policy on the source pod ignored", NP,
     '    egress_ok = True if _egress_selects(policies, src["attrs"], notes) is False else None',
     "    egress_ok = True", [T("test_egress_policy_on_the_source_pod_is_not_evaluated", NET)]),
    ("labels that are not a map accepted", K8S,
     "                need(isinstance(md.get(key) or {}, dict), \"k8s\", f\"{item['kind']} {md['name']!r} has bad {key}\")\n",
     "                pass\n", [T("test_labels_that_are_not_a_map_fail_the_snapshot_loudly", NET)]),
    ("--outside-source ignored", V2 + "cli.py", "        pipe.outside = tuple(a.outside_source)", "        pass",
     [T("test_ingest_takes_the_outside_range_from_the_command_line", NET)]),
    ("--outside-source not checked", V2 + "cli.py",
     '                raise SystemExit(f"--outside-source {term(cidr)} is not an address range") from None',
     "                pass", [T("test_ingest_takes_the_outside_range_from_the_command_line", NET)]),
    ("edge attrs not checked by the rule loader", V2 + "rules.py",
     "        _need(_is(c[\"attr\"], EDGE_ATTRS.get(edge, ())), rule, f\"edge type {edge} has no attr {c['attr']!r}\")",
     "        pass", [T("test_rule_loader_refuses_an_edge_attr_it_does_not_know", NET)]),
    ("reach prints notes without escaping", V2 + "cli.py", '        print(f"  note: {term(n)}")',
     '        print(f"  note: {n}")', [T("test_reach_prints_each_answer_and_escapes_policy_text", NET)]),
    ("reach swaps source and destination", V2 + "cli.py",
     "    answer, notes = pod_to_pod(store, ids[0], ids[1], a.port, a.protocol)",
     "    answer, notes = pod_to_pod(store, ids[1], ids[0], a.port, a.protocol)",
     [T("test_reach_prints_each_answer_and_escapes_policy_text", NET)]),
    ("export does not list namespaces", EXPORT,
     'K8S_KINDS = "pods,services,serviceaccounts,networkpolicies,namespaces"',
     'K8S_KINDS = "pods,services,serviceaccounts,networkpolicies"',
     [T("test_k8s_export_lists_namespaces_and_ingest_keeps_their_labels", EXP)]),
    # Found in review: guards that every test passed without, and faults the fixtures did not hold.
    ("ipBlock against a pod read as a deny", NP,
     'notes.add(f"{what}: ipBlock against a pod\'s address not evaluated")\n        return None',
     'notes.add(f"{what}: ipBlock against a pod\'s address not evaluated")\n        return False',
     [T("test_ipblock_against_a_pod_is_not_evaluated", NET)]),
    ("except outside its cidr read as a deny", NP,
     'notes.add(f"{what}: ipBlock except outside its cidr; not evaluated")\n        return None',
     'notes.add(f"{what}: ipBlock except outside its cidr; not evaluated")\n        return False',
     [T(f"{UNHANDLED_TEST}[bad-except]", NET)]),
    ("except that is not a list read as excepts", NP,
     '    if not isinstance(excepts, list):\n        notes.add(f"{what}: ipBlock except {_clip(excepts)} is not a list;'
     ' not evaluated")\n        return None\n', "", [T(f"{UNHANDLED_TEST}[except-not-a-list]", NET)]),
    ("source range inside a wider except not excepted", NP,
     "        if any(part.subnet_of(e) for e in inside):\n            continue\n", "", [T(IPBLOCK_TEST, NET)]),
    ("unknown target port read as a deny", NP, "    if target is None:\n        return None",
     "    if target is None:\n        return False", [T(f"{UNHANDLED_TEST}[service-port-unknown]", NET)]),
    ("target equal to port read as a deny when endPort is set", NP,
     "    if end is None or target == port:\n        return target == port",
     "    if end is None:\n        return target == port", [T(PORT_TEST, NET)]),
    ("target above an endPort range read as a match", NP, "    return False\n\n\ndef _rule(",
     "    return True\n\n\ndef _rule(", [T(PORT_TEST, NET)]),
    ("bad endPort read as a deny", NP,
     'notes.add(f"{what}: endPort {_clip(end)} not evaluated")\n        return None',
     'notes.add(f"{what}: endPort {_clip(end)} not evaluated")\n        return False',
     [T(f"{UNHANDLED_TEST}[bad-end-port]", NET)]),
    ("unknown rule protocol read as a deny", NP,
     'notes.add(f"{what}: protocol {_clip(entry.get(\'protocol\'))} not evaluated")\n        return None',
     'notes.add(f"{what}: protocol {_clip(entry.get(\'protocol\'))} not evaluated")\n        return False',
     [T(f"{UNHANDLED_TEST}[unknown-protocol]", NET)]),
    ("ipBlock together with a selector read as no match", NP,
     'with a selector is not valid; not evaluated")\n            return None',
     'with a selector is not valid; not evaluated")\n            return False',
     [T(f"{UNHANDLED_TEST}[ipblock-with-selector]", NET)]),
    ("malformed selector read as no match", NP,
     '        notes.add(f"{what}: selector {_clip(selector)} not evaluated")\n        return None\n    match =',
     '        notes.add(f"{what}: selector {_clip(selector)} not evaluated")\n        return False\n    match =',
     [T(f"{UNHANDLED_TEST}[bad-selector]", NET)]),
    ("ingress that is not a list read as no allow", NP,
     'notes.add(f"{what}: ingress {_clip(rules)} not evaluated")\n            matched = None',
     'notes.add(f"{what}: ingress {_clip(rules)} not evaluated")\n            matched = False',
     [T(f"{UNHANDLED_TEST}[bad-ingress]", NET)]),
    ("malformed rule read as no match", NP,
     '    if not isinstance(rule, dict) or set(rule) - RULE_KEYS:\n        notes.add(f"{what}: rule {_clip(rule)} not'
     ' evaluated")\n        return None',
     '    if not isinstance(rule, dict) or set(rule) - RULE_KEYS:\n        notes.add(f"{what}: rule {_clip(rule)} not'
     ' evaluated")\n        return False', [T(f"{UNHANDLED_TEST}[bad-rule]", NET)]),
    ("Service with no ports read as denied", NP,
     '        return None, [], {"the Service lists no ports; ingress not evaluated"}',
     '        return False, [], {"the Service lists no ports; ingress not evaluated"}',
     [T(f"{UNHANDLED_TEST}[no-service-ports]", NET)]),
    ("unknown Service protocol read as denied", NP,
     'notes.add(f"Service port protocol {_clip(protocol)} not evaluated")\n            answers.append(None)',
     'notes.add(f"Service port protocol {_clip(protocol)} not evaluated")\n            answers.append(False)',
     [T(f"{UNHANDLED_TEST}[unknown-service-protocol]", NET)]),
    ("every Service port must be allowed", NP, "    return _or(*answers), sorted(applying), notes",
     "    return _and(*answers), sorted(applying), notes", [T("test_one_allowed_service_port_opens_the_path", NET)]),
    ("omitted targetPort not read as the port", NP,
     '        if target is None:\n            target = sp.get("port")', '        if False:\n            target = sp.get("port")',
     [T(f"{UNHANDLED_TEST}[service-port-unknown]", NET), T("test_one_allowed_service_port_opens_the_path", NET)]),
    ("Service port with no port number gives no note", NP,
     '        elif target is None:\n            notes.add(f"Service port {_clip(sp)} has no port number; port not known")',
     "        elif target is None:\n            pass", [T(f"{UNHANDLED_TEST}[service-port-unknown]", NET)]),
    ("ambiguous named port takes any match", NP, "    return hits.pop() if len(hits) == 1 else None",
     "    return hits.pop() if hits else None", [T(f"{UNHANDLED_TEST}[ambiguous-named-port]", NET)]),
    ("host-network source pod read as denied", NP, '    if answer is False and source.get("host_network"):',
     "    if False:", [T("test_host_network_source_pod_is_not_evaluated", NET)]),
    ("source pod's host network not passed on", NP,
     '"namespace_labels": namespace_labels, "host_network": pod.get("host_network") is True}',
     '"namespace_labels": namespace_labels, "host_network": False}',
     [T("test_host_network_source_pod_is_not_evaluated", NET)]),
    ("policy rules missing from the model read as none", NP, '        if "ingress" not in p:', "        if False:",
     [T("test_policy_whose_rules_the_model_does_not_hold_is_not_evaluated", NET)]),
    ("egress rules of unknown shape read as none", NP,
     'policyTypes not evaluated")\n            return None', 'policyTypes not evaluated")\n            return False',
     [T("test_egress_policy_counts_only_when_it_may_select_the_source_pod", NET)]),
    ("collector records egress of unknown shape as none", K8S, "(0 if egress is None else None)}", "0}",
     [T("test_egress_policy_counts_only_when_it_may_select_the_source_pod", NET)]),
    ("egress policy in another namespace counts", NP,
     '    hits = []\n    for p in policies:\n        if p.get("namespace") != pod["namespace"]:',
     "    hits = []\n    for p in policies:\n        if False:",
     [T("test_egress_policy_counts_only_when_it_may_select_the_source_pod", NET)]),
    ("pods in different clusters compared", NP,
     '    if dst_id.split(":", 2)[2].rsplit("/", 2)[0] != cluster:', "    if False:",
     [T("test_pods_in_different_clusters_are_not_compared", NET)]),
    ("reach accepts a pod reference of any shape", V2 + "cli.py",
     '        if ref.count("/") != 1 or not all(ref.split("/")):', "        if False:",
     [T("test_reach_refuses_a_pod_or_port_it_cannot_name", NET)]),
    ("reach accepts any port number", V2 + "cli.py", "    if not 1 <= value <= 65535:", "    if False:",
     [T("test_reach_refuses_a_pod_or_port_it_cannot_name", NET)]),
    ("reach drops the network plugin caveat", V2 + "cli.py",
     '    print("  this assumes the cluster\'s network plugin enforces NetworkPolicy; the model cannot see that")\n', "",
     [T("test_reach_prints_each_answer_and_escapes_policy_text", NET)]),
    ("edge_where that is not a list accepted", V2 + "rules.py",
     '            _need(isinstance(h.get("edge_where", []), list), rule, "edge_where must be a list")\n', "",
     [T("test_rule_loader_refuses_an_edge_attr_it_does_not_know", NET)]),
    # Order (slice snapshot-order): each guard that keeps arrival order out of the model.
    ("snapshot older than the last applied one accepted", PL, "        elif last is not None and at < last:",
     "        elif False:", [T(OLDER, ORDER), T(PER_SOURCE, ORDER), T(EVERY_ORDER, ORDER)]),
    ("repeated snapshot not recognised", PL,
     '        if any(e["digest"] == d and e["status"] == "applied" for e in same_time):\n'
     '            self.store.bump("snapshot_unchanged")\n',
     "        if False:\n", [T(REPLAY, ORDER), T(SAME_TIME, ORDER), T(NORMALISED, ORDER), T(INGEST, ORDER)]),
    ("other content at the same time applied", PL, "        if others or (last is not None and at == last):",
     "        if False:", [T(SAME_TIME, ORDER), T(REPLAY, ORDER)]),
    # Review of slice 2: controls that had no test, and the faults it fixed.
    ("other content at the last applied time applied when the journal lacks it", PL,
     "        if others or (last is not None and at == last):", "        if others:", [T(SAME_TIME, ORDER)]),
    ("a refused snapshot sent again reads as already in the model", PL,
     '        if any(e["digest"] == d and e["status"] == "applied" for e in same_time):',
     '        if any(e["digest"] == d for e in same_time):', [T(REFUSED_AGAIN, ORDER), T(REPLAY, ORDER)]),
    ("a refused snapshot sent again conflicts with itself", PL,
     '        others = [e for e in same_time if e["digest"] != d]', "        others = same_time",
     [T(REFUSED_AGAIN, ORDER)]),
    ("a record at a snapshot's time dropped when the snapshot arrives after it", V2 + "collectors/aws.py",
     '                   if e["time"] >= at} if old else {}', '                   if e["time"] > at} if old else {}',
     [T(AT_EITHER, ORDER)]),
    ("a mark at a snapshot's time dropped when the snapshot arrives after it", V2 + "collectors/aws.py",
     '                                   if m["time"] >= at] if old else []',
     '                                   if m["time"] > at] if old else []', [T(AT_EITHER, ORDER)]),
    ("an older good snapshot clears a newer failure", V2 + "store.py",
     '        if ok and old and old["status"] == "failed" and old["last_attempt"] >= at:', "        if False:",
     [T(NEWER_FAILURE, ORDER)]),
    ("a good snapshot at the time of a failure clears it", V2 + "store.py",
     'old["last_attempt"] >= at:', 'old["last_attempt"] > at:', [T(NEWER_FAILURE, ORDER)]),
    ("a broken export at the time of the last good one ignored", PL,
     "                if last is not None and at < last:", "                if last is not None and at <= last:",
     [T(NEWER_FAILURE, ORDER)]),
    ("a held detection decided later joins no incident", PL,
     '                correlate.add_detection(self.store, f, ev["time"])', "                pass", [T(HELD, ORDER)]),
    ("held records alone do not show as not evaluated", V2 + "render.py",
     '    if held or counts.get("events_actor_null") or any(changes.values()):',
     '    if counts.get("events_actor_null") or any(changes.values()):', [T(NEVER_RAN, ORDER)]),
    ("a collector that ran and then failed counts as never run", V2 + "detect.py",
     '(store.source(n) or {}).get("last_success") is None)', '(store.source(n) or {}).get("status") != "ok")',
     [T(NEVER_RAN, ORDER)]),
    ("refusals not shown when another collector fails in the same ingest", V2 + "cli.py",
     '            changes = getattr(exc, "changes", None) or {',
     '            changes = None or {', [T(INGEST, ORDER)]),
    ("snapshot time not normalised", PL, "        at = ts(at) if at else self.clock.now()",
     "        at = at or self.clock.now()", [T(NORMALISED, ORDER)]),
    ("change records wait for no snapshot", PL, "        if aws_collector.SOURCE in admitted:\n            self._apply_pending()\n",
     "", [T(PENDING, ORDER)]),
    ("a waiting record that applied still counts as waiting", PL,
     '                self.store.set_model_change_status(c["event_id"], status)\n', "", [T(PENDING, ORDER)]),
    ("detection that cannot be evaluated not held", PL, '                self.store.hold(ev["event_id"], rule["id"], hints)\n',
     "", [T(HELD, ORDER), T(NEVER_RAN, ORDER)]),
    ("held detections never decided", PL, "        self._decide_held(changes)\n", "", [T(HELD, ORDER), T(NEVER_RAN, ORDER)]),
    ("decided record keeps its unresolved references", PL,
     '            self.store.set_event_refs(ev["event_id"], actor, targets)\n', "", [T(HELD, ORDER)]),
    ("decided record stays held", PL, '            self.store.unhold(h["event_id"], h["rule_id"])\n', "", [T(HELD, ORDER)]),
    ("unresolved target read as no match", V2 + "detect.py",
     '    if binds_targets and any(t is None for t in ev["targets"]):', "    if False:", [T(HELD, ORDER)]),
    ("collector that never ran read as no edge", V2 + "detect.py", "    if sources_never_run(store, rule):",
     "    if False:", [T(NEVER_RAN, ORDER)]),
    ("collector that only ever failed counts as run", V2 + "detect.py",
     '    return sorted(n for n in needed if (store.source(n) or {}).get("last_success") is None)',
     "    return sorted(n for n in needed if store.source(n) is None)", [T(NEVER_RAN, ORDER)]),
    ("contains edge needs no AI inventory", V2 + "schema.py", '    "contains": ("ai.inventory",),',
     '    "contains": (),', [T(NEVER_RAN, ORDER)]),
    ("service account edges need no k8s snapshot", V2 + "schema.py",
     '    "runs_as": ("k8s.state",),\n    "exposes": ("k8s.state",),\n    "reachable_from": ("k8s.state",),\n'
     '    "assumes": ("aws.state", "k8s.state"),',
     '    "runs_as": (),\n    "exposes": ("k8s.state",),\n    "reachable_from": ("k8s.state",),\n'
     '    "assumes": ("aws.state",),', [T(NEVER_RAN, ORDER)]),
    ("detection records kept in arrival order", PL, "                    events.sort(key=key)\n",
     "                    pass\n", [T(DATA_TIME, ORDER)]),
    ("detection records sorted only by when the first one arrived", PL,
     "                if min(map(key, added)) < key(old[\"events\"][-1]):", "                if False:",
     [T(DATA_TIME, ORDER)]),
    ("detection first seen is the first record to arrive", PL, "            first = min(first, at)\n", "",
     [T(DATA_TIME, ORDER)]),
    ("role dated to the snapshot when newer changes apply on top", V2 + "collectors/aws.py",
     '        observed = max([at] + [e["time"] for e in pending.values()])', "        observed = at",
     [T(FEW_ORDERS, ORDER)]),
    ("edges rebuilt from newer records credited to the snapshot", V2 + "collectors/aws.py",
     '"aws.cloudtrail" if pending else SOURCE', "SOURCE", [T(FEW_ORDERS, ORDER)]),
    ("IRSA edges dated by whichever snapshot came last", PL, "        self.link(self._link_time(at))",
     "        self.link(at)", [T(FEW_ORDERS, ORDER)]),
    ("findings dated by the input, not by the model", PL, "        return max(times)", "        return at",
     [T(NOT_BEFORE, ORDER)]),
    ("failed collector no longer re-evaluates", PL,
     "        changes = self.apply_snapshot(contents, at, reevaluate=marked)",
     "        changes = self.apply_snapshot(contents, at)", [T("test_bad_k8s_input_fails_loudly_and_marks_facts_stale[{}]", CORE)]),
    ("broken snapshot older than the last good one marks the collector failed", PL,
     "                if last is not None and at < last:", "                if False:", [T(BROKEN_OLDER, ORDER)]),
    ("ingest says facts went stale when none did", V2 + "cli.py",
     "        if stale:\n            print(", "        if True:\n            print(", [T(BROKEN_OLDER, ORDER)]),
    ("replay ignores the k8s snapshot's cluster", PL,
     'k8s_collector.apply(self.store, content["data"], content["cluster"], at, tuple(content["outside"]))',
     'k8s_collector.apply(self.store, content["data"], self.cluster, at, tuple(content["outside"]))',
     [T(REBUILDS, ORDER)]),
    ("replay ignores the outside range", PL,
     'k8s_collector.apply(self.store, content["data"], content["cluster"], at, tuple(content["outside"]))',
     'k8s_collector.apply(self.store, content["data"], content["cluster"], at, self.outside)',
     [T(REBUILDS, ORDER)]),
    ("reopened recorded as opened", PL, '"reopened" if old else "opened"', '"opened"', [T(REOPENED, ORDER)]),
    ("history leaves out snapshots refused as older", HIST,
     '    for s in store.snapshots(statuses=("applied", "older")):', '    for s in store.snapshots(statuses=("applied",)):',
     [T(FEW_ORDERS, ORDER)]),
    ("history replays a snapshot that conflicts", HIST,
     '    for s in store.snapshots(statuses=("applied", "older")):', "    for s in store.snapshots():", [T(SAME_TIME, ORDER)]),
    ("history replays a record before a snapshot of the same time", HIST, "    out = [(at, 0, ", "    out = [(at, 2, ",
     [T(AT_SNAPSHOT, ORDER)]),
    ("history leaves out change records", HIST,
     '    out += [(c["time"], 1, c["event_id"], c["change"]) for c in store.model_changes()]\n', "",
     [T(LATE_DELETE, ORDER)]),
    ("history records nothing", HIST, "    pipe.recorder = []\n", "", [T(LATE_DELETE, ORDER)]),
    ("history leaves out detections", HIST, '    for f in store.findings(kind="detection"):',
     "    for f in []:", [T(DATA_TIME, ORDER)]),
    ("refused snapshots not shown", V2 + "render.py",
     '    if refused:\n        out += ["", "Snapshots refused:"] + refused\n', "", [T(OLDER, ORDER), T(SAME_TIME, ORDER)]),
    ("held records not shown", V2 + "render.py", "        for rule_id, n in sorted(held.items()):",
     "        for rule_id, n in []:", [T(HELD, ORDER)]),
    ("records waiting for a role counted as ever, not now", V2 + "render.py",
     '    changes["model_change_role_not_in_model"] = len(store.model_changes(status="pending"))\n', "",
     [T(PENDING, ORDER)]),
    ("history path not escaped", V2 + "render.py",
     "            out.append(f\"  path: {' -> '.join(safe(p, 300) for p in f['path'])}\")",
     "            out.append(f\"  path: {' -> '.join(p for p in f['path'])}\")", [T(HIST_OUT, ORDER)]),
    ("findings --history ignored", V2 + "cli.py", "        if a.history:", "        if False:", [T(HIST_OUT, ORDER)]),
    ("ingest exits 0 after a refusal", V2 + "cli.py", "    return 3 if refused else 0", "    return 0",
     [T(INGEST, ORDER)]),
    # Week 17: the reviewer's tool scope and the two fixes found by the attack harness.
    ("standards lookup accepts an ID outside the review", "src/codeguardian/standards.py",
     "    if not isinstance(standard_id, str) or standard_id not in allowed_ids:",
     "    if not isinstance(standard_id, str):",
     ["tests/test_redteam.py::test_scope_check_alone_stops_the_exfiltration_when_the_tool_sees_the_pr"]),
    ("blocking finding takes the model's false-positive flag", "src/codeguardian/report.py",
     "                if likely_fp:\n                    likely_fp, locked = False, True",
     "                if False:\n                    likely_fp, locked = False, True",
     ["tests/test_codeguardian.py::test_model_cannot_lower_or_clear_a_blocking_finding",
      "tests/test_redteam.py::test_lock_keeps_the_scanner_verdict_and_says_so_in_the_comment"]),
    ("blocking finding takes the model's lower risk", "src/codeguardian/report.py",
     "                    risk, locked = floor, True",
     "                    locked = True",
     ["tests/test_codeguardian.py::test_model_cannot_lower_or_clear_a_blocking_finding",
      "tests/test_redteam.py::test_lock_keeps_the_scanner_verdict_and_says_so_in_the_comment"]),
    ("lock applied to reported findings too", "src/codeguardian/report.py",
     '            if by_id[fid].get("blocking"):',
     "            if True:",
     ["tests/test_codeguardian.py::test_model_may_still_flag_a_reported_finding_as_a_likely_false_positive"]),
    ("post accepts a cleared blocking finding", "src/codeguardian/report.py",
     '        if item.get("blocking") and item.get("likely_false_positive"):',
     "        if False:",
     ["tests/test_codeguardian.py::test_post_refuses_a_report_that_clears_a_blocking_finding[change0]"]),
    ("post accepts a blocking finding ranked below the scanner", "src/codeguardian/report.py",
     '        if item.get("blocking") and floor in RISKS and item["risk"] in RISKS \\',
     '        if False and floor in RISKS and item["risk"] in RISKS \\',
     ["tests/test_codeguardian.py::test_post_refuses_a_report_that_clears_a_blocking_finding[change1]"]),
    ("protected config PR still sent to the model", "src/codeguardian/supervisor.py",
     "    if protected:", "    if False:",
     ["tests/test_codeguardian.py::test_protected_config_change_gets_no_model_request[edit]",
      "tests/test_redteam.py::test_protected_config_pr_gets_no_model_request_and_says_why"]),
    ("rename counts only the new path", "src/codeguardian/agents.py",
     "            paths.update(m.groups())", "            paths.add(m.group(2))",
     ["tests/test_codeguardian.py::test_protected_config_change_gets_no_model_request[rename-out]"]),
]


def pytest(node):
    env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", node],
                          cwd=ROOT, env=env, capture_output=True, text=True).returncode


def chain_tests():
    """Tests that must each have a mutant: A to F in the chain file, and every export test."""
    out = []
    for file, keep in ((CHAIN, lambda n: n[:7] in {f"test_{c}_" for c in "abcdef"}), (EXP, lambda n: True),
                       (NET, lambda n: True), (ORDER, lambda n: True)):
        tree = ast.parse((ROOT / file).read_text())
        out += [(file, n.name) for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name.startswith("test_") and keep(n.name)]
    return sorted(out)


def tree_state():
    out = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
    digest = hashlib.sha256()
    for path in sorted((ROOT / "src").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(path.read_bytes())
    return out, digest.hexdigest()


def main():
    covered = {(node.split("::", 1)[0], node.split("::", 1)[1].split("[", 1)[0]) for *_, tests in MUTANTS
               for node in tests}
    missing = [f"{f}::{t}" for f, t in chain_tests() if (f, t) not in covered]
    if missing:
        print("tests with no mutant:", ", ".join(missing))
        return 1
    named = {node for *_, tests in MUTANTS for node in tests}
    env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
    collected = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", CHAIN,
                                NET, ORDER], cwd=ROOT, env=env, capture_output=True, text=True).stdout.split()
    loose = [n for n in collected if "[" in n and n.startswith((CHAIN, NET, ORDER)) and n not in named]
    for n in loose:
        print(f"parametrized case with no mutant of its own: {n}")
    if any(n.startswith((NET, ORDER)) for n in loose):
        return 1
    nodes = sorted(named)
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
          f"{len(results) - caught} not caught; {len(chain_tests())} A-F, export, NetworkPolicy and order tests,"
          " all covered")
    if tree_state() != start:
        print("THE TREE CHANGED during the run")
        return 1
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
