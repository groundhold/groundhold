# Reviewing a pull request

The gates run first and they run everything a machine can decide. This page is about
what is left after they pass — and about not spending a reviewer's attention on what
they already covered.

## What CI already checked (do not re-check by hand)

By the time a PR is green, these are proven, on both implementations where it applies:

| Checked | By |
|---|---|
| Conformance suite, Go runtime and Python reference | `ci.yml` → `make check` |
| Cross-implementation agreement on seeded random documents | `make differential`, a fresh seed per run |
| That the tests have teeth — every re-injected bug is caught | `ci.yml` → the mutation meter |
| That the public export is self-contained and passes standalone | `ci.yml` → export job |
| Published counts, links, verbs, and claims in docs | the doc gates in `make check` |
| Vulnerabilities, lint, leaked secrets | `security.yml` |
| Every commit signed off (DCO) | `dco.yml` |

If a reviewer finds themselves running the suite by hand, either the gate is missing or
the reviewer does not trust it — both are bugs, and the second one is worse.

## What only a person can decide

**1. Is the conformance case the RIGHT case?** A green suite proves the case passes,
never that it pins the intended behaviour. Read the case as a specification: does it
fail if the feature is removed? Does it assert the direction that matters, or the easy
one? A test that greps for a call, aims at a line that does not exist, or pins the
easy half of an asymmetric rule reads far stronger than it is.

**2. Is the fix at the mechanism or at the instance?** The question from D583: *does
the next author have to remember this?* A fix that repairs one call site and leaves the
shape intact will be re-found under a different number.

**3. Does the change widen a published claim?** A new flag, verdict, status, or enum
value that a document names — the schema, the vocabulary, the CLI help, the website —
is a claim, and this project holds every one of them with a gate. A PR that publishes a
new value without one is not finished, however green.

**4. Does the DESIGN entry say why, and does it re-litigate?** Entries are append-only.
A change that reverses a decision adds an entry arguing against the written rationale;
it never edits the old one, and it never silently contradicts it.

**5. Is the honesty direction right?** When the change decides what to do with missing
knowledge, the answer is `unknown` and a refusal, never a default that reads as
success. Most defects in this record are one of: a discarded error, a gate with an
empty subject, an absent thing treated as a fine thing.

**6. Does it belong to the project?** No new dependencies (stdlib + yaml). No raw
Terraform as a deliverable (D39). No LLM or network inside the verifier (D10). These
are settled and a PR does not reopen them by being useful.

## Merging

Squash, with the DESIGN entry number in the message when there is one. `main` is never
pushed directly: releases arrive as a branch and a pull request like any other change.
A contribution merged here is replayed upstream before the next sync, and the sync
refuses rather than overwriting commits it did not put there (D714) — so a merged pull
request is never quietly reverted by the following release.

## Repository protections in force

The repository is public (2026-08-13). These are enabled:

- Branch protection on `main`: required status checks (`gate`, `gitleaks`,
  `signed-off`), enforced on admins, no force pushes, no deletions. PR review is not
  yet required (solo maintainer — there is no second reviewer to require); add a
  CODEOWNER review requirement when a second maintainer joins.
- CodeQL runs on the public repo (first run: zero alerts); secret scanning and push
  protection are on; private vulnerability reporting is enabled; org-wide 2FA is
  required.
- Actions: "Require approval for all outside collaborators" — the D713 runner split
  keeps a fork's code off the self-hosted fleet, and this keeps it from running at all
  until a maintainer looks.
- Secrets: none available to `pull_request` runs. The canaries that hold cloud
  credentials trigger on `schedule`/`workflow_dispatch` only, and are stripped from the
  export.
- Pages deploys the docs site; Dependabot is a remaining follow-up.
