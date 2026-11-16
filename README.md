# CodeGuardian

CodeGuardian reviews pull requests for security problems. A deterministic gate runs four
scanners and blocks the merge; a Security agent, backed by a Claude model, explains and
ranks what the scanners found in one pull-request comment. The model cannot add, move or
hide a finding. It can only explain the ones a scanner rule produced.

This is version 1 (week 14 of a security engineering course): the gate, a supervisor and
one Security agent. The repository under test is
[codeguardian-target](https://github.com/Keniolax/codeguardian-target), a pinned copy of
OWASP Juice Shop.

![Architecture](diagram/architecture.png)

## What it does

**The gate** (`security-gate.yml` in the target repository, on `pull_request`) runs Semgrep,
Gitleaks, Trivy and OWASP ZAP and fails on any finding the pull request adds. It reads its
rules, ignore lists and suppressions from the base commit, so a pull request cannot silence
itself. It has no secrets.

**CodeGuardian** (`codeguardian.yml`, on `workflow_run` from `main`) never checks out the
pull request. It treats the gate's artifact as untrusted data and splits the work so that
no job holds two credentials:

| Job | Holds | Does |
|---|---|---|
| prepare | read access to artifacts | checks the PR number is an integer and the head SHA matches the event |
| review | the Claude API key, no GitHub token | sends findings and the diff to the Security agent; no tools |
| post | `pull-requests: write`, no API key | re-checks the report, escapes it, updates one comment |
| guard | `statuses: write`, no API key | sets `codeguardian/config-guard`: fails if the PR edits `.github/` or `.gate/` without the `gate-change-approved` label |

The model returns JSON in a fixed schema (structured outputs), naming findings only by the
gate's finding ID. `report.py` drops any entry with an unknown ID and takes scanner, rule,
file and line from the scanner artifact. Findings the model skips still appear in the
report, marked unexplained. `render.py` escapes all text from the pull request and the model,
so a crafted diff cannot put an image, link, HTML or @-mention in the comment. Reference
links survive only for a short list of documentation hosts.

The default model is `claude-sonnet-5-5`, with server-side fallback on refusal; the report
names the model that answered. `OllamaProvider` runs the same agent on a local model.

## How to run it

In the target repository, open a pull request. The gate runs, then CodeGuardian comments.

The actions in `actions/` are used by the target repository's workflow, pinned by commit
SHA. They need the repository secret `ANTHROPIC_API_KEY`, and this repository's Actions
access set to the owner's repositories.

Locally:

```
python3.12 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-dev.lock
PYTHONPATH=src .venv/bin/python -m pytest -v
PYTHONPATH=src .venv/bin/python -m codeguardian review --input <gate-artifact-dir> --out report.json
PYTHONPATH=src .venv/bin/python -m codeguardian render --report report.json
```

Dependencies are hash-locked, and every release in the lock files is at least 14 days old.

## What was learned

Measured on the seeded pull requests in
[codeguardian-target](https://github.com/Keniolax/codeguardian-target#what-was-learned),
with `claude-sonnet-5-5` on 2026-11-13. The sample is small, and the explanations were
judged by the author, not by an independent reviewer.

| Version | Pull requests with findings | Findings | Wrong claims in explanations | Entries dropped | Model time per review |
|---|---|---|---|---|---|
| diff hunks of flagged files only | 6 | 8 | 3 | 0 | 4.5–8.0 s |
| whole diff and changed-file list (`08973b5`) | 5 | 6 | 0 | 0 | 3.8–6.6 s |

Every seeded finding was ranked first, and none was wrongly called a false positive. Model
cost for the whole week was about $0.10 (about 22,000 input and 5,000 output tokens).

- What the model sees decides what it gets right. With only the hunks of flagged files, it
  said twice that a route had no authentication check (the check was in `server.ts`, which
  it was not shown), and once that the diff was empty (a ZAP finding points at a URL, so no
  hunk was sent). Sending the whole diff, and telling the model to say "not shown" rather
  than "absent", removed all three errors.
- Let the model explain, not decide. The gate decides pass or fail from scanner rules
  alone. The model's output is joined to scanner findings by ID, so a wrong or injected
  answer can change the wording of a comment, not whether a finding exists.
- One job, one credential. The job that reads untrusted text and calls the model has no
  GitHub token; the job that writes to GitHub never calls the model. A stale-report check
  refused to post a report for a commit that was no longer the pull request's head.
- Escape everything that came from the pull request. A comment renderer that passes model
  text through could be made to load an attacker's image URL with data in it. The tests
  cover images, links, HTML and @-mentions.
- An approval control only works if the author of a change cannot grant it. Changes to
  `.gate/` need the `gate-change-approved` label, applied by a maintainer after review,
  never by the automation that opened the change.

## Version 2 (in progress)

Version 2 keeps one model of the environment in SQLite: entities such as pods, roles,
buckets and AI agents, and the edges between them, each with its source and time.
Posture, path and detection rules (TOML, in `src/codeguardian/v2/rules/`) all run on that
model. Stage 1 proves this on one recorded chain. An AI agent's pod is reachable from the
internet. Its service account assumes an IAM role, and a CI role then adds a policy that
lets the role read a bucket tagged sensitive. A shell opens in the pod, the pod's token
is read, and the role reads the bucket, which none of the agent's tools declares.

- Collectors read exported files: IAM authorization details, the bucket list and tags,
  `kubectl get -o json`, and a small declared AI inventory. A collector that cannot
  read its file fails; its facts become stale but still count. The output names any
  source that failed, never ran, or is past its refresh period.
- Events (CloudTrail, Kubernetes audit, Falco) are read one at a time from a file or
  stdin and joined to the model. `PutRolePolicy` and `DeleteRolePolicy` change the model
  at once. `AttachRolePolicy` carries only an ARN, so an unknown policy is marked.
- One path finding covers the chain; removing any one of its six edges removes it.
  The runtime alerts, the cloud events and the path finding form one incident. A shell
  in another pod on the same node stays in its own incident.
- A response plan uses a catalog of three actions and prints commands for a person to
  review. Nothing runs. `explain` and `ask` call a model through v1's `providers.py`;
  answers are joined by ID, and the model cannot open, close or change a finding.
- The IAM resolver reads Allow statements and wildcards only. Anything else (conditions,
  Deny, NotAction, boundaries, SCPs, bucket policies) is listed as not evaluated.

How to run it on the fixtures. `--now` and `--at` set the clock, because the data is
from 2026-11-14.

```
export PYTHONPATH=src
F=fixtures/chain
.venv/bin/python -m codeguardian ingest --db demo.db --now 2026-11-14T10:30:00Z --at 2026-11-14T09:55:00Z \
  --aws-iam $F/aws/iam.json --aws-buckets $F/aws/s3-buckets.json --aws-tags $F/aws/s3-tags.json \
  --k8s $F/k8s/state.json --ai $F/ai/inventory.json
head -n 9 $F/events/chain.ndjson | .venv/bin/python -m codeguardian watch --db demo.db --now 2026-11-14T10:30:00Z
.venv/bin/python -m codeguardian incidents --db demo.db --now 2026-11-14T10:30:00Z
.venv/bin/python -m codeguardian plan --db demo.db --now 2026-11-14T10:30:00Z --incident 83db1215
.venv/bin/python -m codeguardian explain --db demo.db --now 2026-11-14T10:30:00Z --incident 83db1215 \
  --provider recorded --answer $F/explain-answer.json
.venv/bin/python -m codeguardian ask --db demo.db --now 2026-11-14T10:30:00Z --question "Which roles can read sensitive buckets?" \
  --provider recorded --answer $F/ask-answer.json
tail -n 1 $F/events/chain.ndjson | .venv/bin/python -m codeguardian watch --db demo.db --now 2026-11-14T10:30:00Z
.venv/bin/python -m codeguardian findings --db demo.db --now 2026-11-14T10:30:00Z
.venv/bin/python -m codeguardian bench --events 10000 --seed 7
.venv/bin/python tests/mutants.py
```

The two recorded model answers are written by hand. `explain` and `ask` have not been run
against a live model.

Measured on 2026-11-15 at commit `616e1ce`:

- 109 tests pass (25 for v1, 84 for v2). The mutation run removes 52 controls one at a
  time and runs the tests that name each one: 62 mutant-test pairs, 55 distinct tests,
  all fail without their control. One case, a pod running as a different service
  account, has no mutant of its own; that edge is absent from the input itself.
- 10,010 events (the 10 chain records and 10,000 generated benign records, seed 7),
  each processed in full and committed to an SQLite file in WAL mode with
  `synchronous=NORMAL`, so there is no fsync per commit. Apple M1, macOS 26.6.2, Python
  3.12.14, three runs: 6,146 to 6,493 events per second; per event p50 0.10 ms, p95
  0.35 to 0.38 ms, max 5.6, 105.0 and 8.9 ms. The chain incident held the same seven
  rules as in a run without noise, and the path finding ended resolved.

The data is recorded, not live. The model holds 24 entities and 20 edges, and the noise
copies the chain's own record shapes, so these numbers do not predict speed on a real
account. They are pipeline time only; CloudTrail delivers a record minutes after the
call, and that delay is not included.

What was learned:

- An event changes the model only as far as the record shows. A guess about a policy
  the record does not carry would read as "safe", so the role is marked instead.
- A passing test can prove less than its name. The first test of "re-run only affected
  rules" still passed when the path rule re-ran on every change. The mutation run found
  this, and a second test now changes only types the path rule does not follow.
- Skipping a policy statement the resolver cannot read is a silent deny. A role with a
  skipped statement, a Deny or a boundary now gets a finding of its own.
- In correlation, the internet node touches every exposed service, so it is left out of
  the join key.
