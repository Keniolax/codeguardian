"""GitHub state from the file `python -m codeguardian.export github` writes: one account,
its repositories, and for each repository the answers of seven GitHub REST calls, as the
API gives them (the GitHub REST reference, API version 2022-11-28):

    {"format": "codeguardian.github-export/v1",
     "account": {"login": "...", "type": "User" | "Organization", "public_repos": 3},
     "listing": "owner" | "public" | "organization",
     "repositories": [{"repository": <an entry of the repository list>,
                       "rulesets": <GET repos/O/R/rulesets>,
                       "branch_rules": <GET repos/O/R/rules/branches/BRANCH>,
                       "branch": <GET repos/O/R/branches/BRANCH>,
                       "workflow_permissions": <GET repos/O/R/actions/permissions/workflow>,
                       "deploy_keys": <GET repos/O/R/keys>,
                       "secrets": <GET repos/O/R/actions/secrets>,
                       "workflows": <GET repos/O/R/actions/workflows>}]}

BRANCH is the repository's default branch. A call that failed for one repository (a 403
or 404, a timeout, output that is not JSON) is recorded as {"Error": {"Code": ...,
"Message": ...}}. That part is "not evaluated": the repository's not_evaluated attr names
it, a finding opens, and the model keeps the facts it last read for that part, so a key
or a setting it could not read again does not read as removed. A missing part means it
was not collected, and the collector refuses the snapshot.

A status check is required on the default branch when an active ruleset rule of type
required_status_checks, or classic branch protection whose enforcement is not "off",
names at least one check. Rulesets in "evaluate" or "disabled" mode are not in the rules
answer, so they require nothing. Neither answer says who may bypass the rules.

Secrets are names only. The API never returns a value, and the export keeps none.
"""

import json

from ..schema import entity_id
from . import Delta, need, read_json

SOURCE = "github.state"
FORMAT = "codeguardian.github-export/v1"
LISTINGS = {
    "owner": None,
    "public": "private repositories of {login} (the token is not the account's own, so only public ones are listed)",
    "organization": "private repositories of {login} that the token cannot see (an organisation lists them only"
                    " to its members)",
}
ACCOUNT_TYPES = ("User", "Organization")
# Each part of a repository entry: what the not_evaluated note calls it.
PARTS = {
    "rulesets": "rulesets",
    "branch_rules": "ruleset rules of the default branch",
    "branch": "classic branch protection of the default branch",
    "workflow_permissions": "Actions workflow permissions",
    "deploy_keys": "deploy keys",
    "secrets": "Actions secrets",
    "workflows": "workflows",
}
ENFORCED = ("non_admins", "everyone")
NEVER_READ = ("bypass lists of rulesets and branch protection (not in this export)",
              "organisation and environment secrets (not in this export)")


def _str(value):
    return isinstance(value, str) and value != ""


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _error(part):
    return isinstance(part, dict) and set(part) == {"Error"} and isinstance(part["Error"], dict) \
        and isinstance(part["Error"].get("Code"), str)


def _unique(items, key, what):
    seen = set()
    for i in items:
        need(i[key] not in seen, "github", f"{what} lists {i[key]!r} twice")
        seen.add(i[key])


def _check_repo(entry, login, names):
    need(isinstance(entry, dict) and isinstance(entry.get("repository"), dict), "github",
         "a repository entry lacks its repository object")
    repo = entry["repository"]
    full = repo.get("full_name")
    need(_str(full) and full.count("/") == 1 and all(full.split("/")), "github",
         "a repository lacks a full_name of the form OWNER/NAME")
    need(full.split("/")[0].lower() == login.lower(), "github", f"{full!r} is not a repository of {login!r}")
    need(full.lower() not in names, "github", f"the repository list holds {full!r} twice")
    names.add(full.lower())
    need(repo.get("default_branch") is None or isinstance(repo["default_branch"], str), "github",
         f"{full!r}: default_branch is not a string")
    missing = [p for p in PARTS if p not in entry]
    need(not missing, "github", f"{full!r}: {', '.join(missing)} not collected")
    for part in PARTS:
        value = entry[part]
        if _error(value):
            continue
        what = f"{full!r}: {part}"
        if part == "rulesets":
            need(isinstance(value, list) and all(isinstance(r, dict) and _int(r.get("id")) and isinstance(r.get("name"), str)
                                                 and isinstance(r.get("source"), str) for r in value),
                 "github", f"{what} must be a list of rulesets with an id, a name and a source")
            _unique(value, "id", what)
        elif part == "branch_rules":
            need(isinstance(value, list) and all(isinstance(r, dict) and isinstance(r.get("type"), str) for r in value),
                 "github", f"{what} must be a list of rules with a type")
        elif part in ("branch", "workflow_permissions"):
            need(isinstance(value, dict), "github", f"{what} must be an object")
        elif part == "deploy_keys":
            need(isinstance(value, list) and all(isinstance(k, dict) and _int(k.get("id")) and isinstance(k.get("title"), str)
                                                 and isinstance(k.get("read_only"), bool) for k in value),
                 "github", f"{what} must be a list of keys with an id, a title and read_only")
            _unique(value, "id", what)
        else:
            key, field = ("secrets", "name") if part == "secrets" else ("workflows", "path")
            need(isinstance(value, dict) and _int(value.get("total_count")) and isinstance(value.get(key), list)
                 and all(isinstance(i, dict) and _str(i.get(field)) for i in value[key]),
                 "github", f"{what} must hold total_count and a list of {key} with a {field}")
            # One page of a longer list would read as the whole list.
            need(len(value[key]) == value["total_count"], "github",
                 f"{what} lists {len(value[key])} of {value['total_count']}; export every page")
            _unique(value[key], field, what)


def load(path):
    data = read_json(path, "github")
    need(isinstance(data, dict) and data.get("format") == FORMAT, "github", f"format must be {FORMAT!r}")
    acct = data.get("account")
    need(isinstance(acct, dict) and _str(acct.get("login")) and acct.get("type") in ACCOUNT_TYPES, "github",
         "the account needs a login and a type of User or Organization")
    need(data.get("listing") in LISTINGS, "github", f"listing must be one of {sorted(LISTINGS)}")
    # Only a user's own token lists its private repositories; an organisation's are listed as
    # far as the token can see them.
    need((data["listing"] == "organization") == (acct["type"] == "Organization"), "github",
         f"a listing of {data['listing']!r} does not fit an account of type {acct['type']!r}")
    need(isinstance(data.get("repositories"), list), "github", "repositories must be a list")
    names = set()
    for entry in data["repositories"]:
        _check_repo(entry, acct["login"], names)
    return data


def _note(notes, part, err):
    notes.append(f"{PARTS[part]}: not read ({err['Code']}); the model keeps what it last read, if anything")


def _checks_from_rules(rules, notes):
    """The status checks that active ruleset rules require on the default branch, or None."""
    out = []
    for r in rules:
        if r["type"] != "required_status_checks":
            continue
        params = r.get("parameters")
        checks = params.get("required_status_checks") if isinstance(params, dict) else None
        if not isinstance(checks, list) or not all(isinstance(c, dict) and isinstance(c.get("context"), str)
                                                   for c in checks):
            notes.append("a required_status_checks rule of the default branch has a form the collector does not read")
            return None
        out += [c["context"] for c in checks]
    return sorted(set(out))


def _checks_from_protection(branch, notes):
    """The status checks classic branch protection requires on the default branch, or None."""
    prot = branch.get("protection")
    if not isinstance(prot, dict):
        notes.append("classic branch protection of the default branch: not in the answer")
        return None
    if prot.get("enabled") is False:
        return []
    rsc = prot.get("required_status_checks")
    if rsc is None:
        return []
    level = rsc.get("enforcement_level") if isinstance(rsc, dict) else None
    contexts = rsc.get("contexts") if isinstance(rsc, dict) else None
    checks = rsc.get("checks", []) if isinstance(rsc, dict) else None
    if not (isinstance(contexts, list) and all(isinstance(c, str) for c in contexts) and isinstance(checks, list)
            and all(isinstance(c, dict) and isinstance(c.get("context"), str) for c in checks)):
        notes.append("required status checks of classic branch protection have a form the collector does not read")
        return None
    if level == "off":
        return []
    if level not in ENFORCED:
        notes.append(f"classic branch protection: enforcement level {json.dumps(level)} is not one the collector reads")
        return None
    return sorted(set(contexts) | {c["context"] for c in checks})


def _status(ruleset, protection):
    if ruleset or protection:
        return "required"
    if ruleset is None or protection is None:
        return "not evaluated"
    return "none"


def _workflow_permissions(wp, notes):
    perms, approve = wp.get("default_workflow_permissions"), wp.get("can_approve_pull_request_reviews")
    if perms not in ("read", "write"):
        notes.append(f"default workflow permissions {json.dumps(perms)[:80]} is not a value the collector reads")
        perms = None
    if not isinstance(approve, bool):
        notes.append("whether Actions may approve pull requests is not in the answer")
        approve = None
    return perms, approve


def _repo_attrs(entry, old):
    """The typed attrs of one repository, with a note for each part that is not evaluated.
    A part that could not be read keeps the value the model last held for it."""
    repo, notes = entry["repository"], []
    branch = repo.get("default_branch") or None
    attrs = {"name": repo["full_name"], "default_branch": branch,
             "private": repo.get("private") if isinstance(repo.get("private"), bool) else None,
             "archived": repo.get("archived") if isinstance(repo.get("archived"), bool) else None}
    for part in PARTS:
        if _error(entry[part]):
            _note(notes, part, entry[part]["Error"])
    if branch is None:
        notes.append("default branch: not in the repository list, so its rules and protection were not read")
        attrs["ruleset_checks"] = attrs["protection_checks"] = None
    else:
        attrs["ruleset_checks"] = old.get("ruleset_checks") if _error(entry["branch_rules"]) \
            else _checks_from_rules(entry["branch_rules"], notes)
        attrs["protection_checks"] = old.get("protection_checks") if _error(entry["branch"]) \
            else _checks_from_protection(entry["branch"], notes)
    attrs["default_branch_checks"] = _status(attrs["ruleset_checks"], attrs["protection_checks"])
    if _error(entry["workflow_permissions"]):
        perms, approve = old.get("default_workflow_permissions"), old.get("actions_can_approve_pull_requests")
    else:
        perms, approve = _workflow_permissions(entry["workflow_permissions"], notes)
    attrs["default_workflow_permissions"], attrs["actions_can_approve_pull_requests"] = perms, approve
    attrs["not_evaluated"] = sorted(set(notes))
    return attrs


# part -> (edge type, entity type of the far end, whether the edge points at the repository)
CHILDREN = {"rulesets": ("protects", "ruleset", True), "deploy_keys": ("holds", "deploy_key", False),
            "secrets": ("holds", "actions_secret", False), "workflows": ("contains", "workflow", False)}


def apply(store, data, at):
    delta, seen_e, seen_x = Delta(), set(), set()

    def ent(eid, etype, attrs, labels=None):
        if store.upsert_entity(eid, etype, attrs, labels or {}, SOURCE, at):
            delta.entity(eid, etype)
        seen_e.add(eid)

    def edge(etype, src, dst):
        xid, changed = store.upsert_edge(etype, src, dst, {}, SOURCE, at)
        if changed:
            delta.edge(etype)
        seen_x.add(xid)

    def keep(rid, part):
        """A part that could not be read: its entities and edges stay as the model holds
        them. They are not confirmed, so they go stale, but they are not deleted."""
        etype, child, incoming = CHILDREN[part]
        for e in store.edges(rid, etype, "in" if incoming else "out"):
            other = store.entity(e["src"] if incoming else e["dst"])
            if other is not None and other["type"] == child and other["source"] == SOURCE:
                seen_x.add(e["id"])
                seen_e.add(other["id"])

    acct = data["account"]
    login = acct["login"]
    aid = entity_id("github_account", login)
    ent(aid, "github_account", {"name": login, "account_type": acct["type"],
                                "repositories_listed": data["listing"]})
    listed = set()
    for entry in data["repositories"]:
        repo = entry["repository"]
        full = repo["full_name"]
        rid = entity_id("repository", full)
        listed.add(rid)
        attrs = _repo_attrs(entry, (store.entity(rid) or {}).get("attrs", {}))
        ent(rid, "repository", attrs, {"repository": {"description": str(repo.get("description") or "")}})
        edge("contains", aid, rid)
        for part in CHILDREN:
            if _error(entry[part]):
                keep(rid, part)
        if not _error(entry["rulesets"]):
            for r in entry["rulesets"]:
                sid = entity_id("ruleset", f"{r['source']}/{r['id']}")
                ent(sid, "ruleset", {"name": r["name"], "ruleset_id": r["id"], "source": r["source"],
                                     "source_type": r.get("source_type"), "target": r.get("target"),
                                     "enforcement": r.get("enforcement")})
                edge("protects", sid, rid)
        if not _error(entry["deploy_keys"]):
            for k in entry["deploy_keys"]:
                kid = entity_id("deploy_key", f"{full}/{k['id']}")
                ent(kid, "deploy_key", {"name": k["title"], "key_id": k["id"], "read_only": k["read_only"],
                                        "repository": full})
                edge("holds", rid, kid)
        if not _error(entry["secrets"]):
            for sec in entry["secrets"]["secrets"]:
                xid = entity_id("actions_secret", f"{full}/{sec['name']}")
                ent(xid, "actions_secret", {"name": sec["name"], "repository": full})
                edge("holds", rid, xid)
        if not _error(entry["workflows"]):
            for w in entry["workflows"]["workflows"]:
                wid = entity_id("workflow", f"{full}/{w['path']}")
                ent(wid, "workflow", {"name": str(w.get("name") or ""), "path": w["path"],
                                      "state": w.get("state") if isinstance(w.get("state"), str) else None,
                                      "repository": full})
                edge("contains", rid, wid)
    if data["listing"] != "owner":
        # This listing can leave out private repositories, so one the model holds and the
        # listing does not name is not known to be gone: it stays, unconfirmed.
        for e in store.edges(aid, "contains"):
            r = store.entity(e["dst"])
            if r is not None and r["type"] == "repository" and r["id"] not in listed and r["attrs"].get("private") is True:
                seen_x.add(e["id"])
                seen_e.add(r["id"])
                for part in CHILDREN:
                    keep(r["id"], part)
    store.set_setting(f"unread:{SOURCE}", json.dumps(unread(data)))
    gone_e, gone_x = store.sweep(SOURCE, seen_e, seen_x, at)
    for eid, etype in gone_e:
        delta.entity(eid, etype)
    for _, etype in gone_x:
        delta.edge(etype)
    return delta


def unread(data):
    """What the export did not read, for the source line."""
    out = []
    listed = LISTINGS[data["listing"]]
    if listed:
        out.append(listed.format(login=data["account"]["login"]))
    return out + list(NEVER_READ)
