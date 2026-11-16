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
