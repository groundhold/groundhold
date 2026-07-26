---
name: code-to-contract
description: Draft an InfrastructureContract by analyzing an application repository (DB drivers, queues, frameworks, env vars, deploy config). Everything inferred from code carries provenance inferred with a file citation; non-code factors (traffic, budget, compliance, vendor deals) are ASKED, never guessed. Use when the user points at an app repo and wants its infrastructure needs captured as a contract.
---

# Code to contract (D92)

The code is a witness, not an author. It can testify that the app
speaks postgres and reads REDIS_URL; it cannot testify how much
traffic production carries, what the budget is, or which law applies.
The draft separates what the code proves from what a human must say.

## The one failure mode this skill exists to prevent

**"Code mentions it" is not "production requires it."** Imports,
dormant adapters, test fixtures, local-dev defaults and optional
integrations all look like infrastructure dependencies. Guards:

1. **Every inferred capability cites its evidence** — exact files
   (driver import + the config that wires it + the runtime entrypoint
   that reaches it). Classify each dependency: `required` (on a
   runtime path), `optional` (feature-flagged/pluggable), `dev/test`
   (fixtures, docker-compose for local, CI-only), `unknown`. Only
   `required` becomes a capability; `optional`/`unknown` become
   QUESTIONS; `dev/test` is dropped with a note.
2. **Contradiction pass before drafting**: imports vs env vars vs
   Dockerfile/CI/deploy manifests vs runtime entrypoints. A dependency
   the code imports but no config wires, or an env var nothing reads,
   is a GAP to ask about — never a contract requirement.
3. **Never promote non-code factors from inference.** Scale, SLAs
   (rpo/rto), budget, regions/residency, exposure policy, compliance,
   org vendor commitments, team skills: ASK, and record the answers as
   `declared`. If the user cannot answer, the value enters
   `assumptions:` with `status: assumed`, a stated source, a
   confidence, and `affects:` listing the constraints resting on it.

## Procedure

1. Survey the repo: dependency manifests, config/env handling, deploy
   artifacts (Dockerfile, compose, CI, k8s), runtime entrypoints.
   Build the evidence table and PERSIST it as a survey document
   (spec/survey.md, `survey/v0.1`) at
   `.groundhold/survey/<commit-sha>.json` — pinned to the exact commit,
   one survey per repository. In a microservice system every repo
   gets its own survey (`repo.name` + `service` identify the
   witness); `groundhold survey <contract> --survey a.json --survey
   b.json` compares the whole set, and `--complete` is only passed
   when the set truly covers every consumer. The survey is also the
   drift watch: re-crawled in CI and compared to the published
   contract, exit 2 (`survey-drift`) means the code and the contract
   disagree about reality.
2. Run the contradiction pass; collect gaps and optional/unknowns
   into ONE batch of questions for the user, together with the
   non-code factors (traffic shape, budget, residency, compliance,
   RPO/RTO expectations). One round of questions, not an
   interrogation drip.
3. Map `required` dependencies to capability types via `spec/vocab/`
   (capability semantics only — engine.protocol, not instance tiers).
   Constraints from declared answers get `hard` for
   compliance/security/data-loss, `soft`/budget for preferences.
4. Draft to `.groundhold/<app>-draft.contract.yaml`;
   `bin/groundhold-go validate` must pass. Present with the evidence
   table and every assumption highlighted.
5. KISS: for each capability, name the constraint that needs it. A
   capability no constraint needs is deleted, not kept "just in case".

## Never

- Never emit a capability whose only evidence is an import or a
  test/dev artifact.
- Never fill a non-code factor silently — no invented budgets, no
  assumed regions without an assumption entry.
- Never publish: the draft stays in `.groundhold/` until the human
  reviews the evidence and moves it (D49; `groundhold publish` records
  the human actor).
