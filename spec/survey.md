# Code survey (D93)

The commit-pinned evidence table a code crawl produces: what an
application's code witnesses about its own infrastructure needs. The
survey is an AGENT-SIDE artifact (the code-to-contract skill's first
step, persisted); `groundhold survey` is the deterministic comparator
that checks it against a contract. The code is a witness, not an
author — a survey never becomes a contract, exactly as tf/pulumi state
never does (D53).

## Document: survey/v0.1

```json
{
  "apiVersion": "survey/v0.1",
  "kind": "CodeSurvey",
  "repo":    { "name": "orders-api", "remote": "…", "commit": "<sha>" },
  "service": "orders-api",
  "generatedAt": "2026-07-14T12:00:00Z",
  "findings": [
    {
      "dependency": "psycopg",
      "class": "required",
      "capabilityHint": "capability.database.relational",
      "evidence": ["app/db.py:12", "Dockerfile:8"],
      "note": "wired via DATABASE_URL, reached from the request path"
    }
  ]
}
```

- **Commit-pinned or invalid.** A survey without `repo.commit` does not
  load. Findings are true AT that commit only; the index never claims
  general knowledge about a moving repository (the tfstate lesson).
- `class`: `required` (on a runtime path: import + wiring + entrypoint)
  | `optional` (flagged/pluggable) | `dev-test` (fixtures, local-dev,
  CI-only) | `unknown`. Closed set; anything else is a load error.
- `capabilityHint` is a vocabulary capability type (`spec/vocab/`).
- `evidence` is mandatory and cites files — a finding that cannot say
  where it saw something is not a finding.
- **Multi-repo / microservices**: one survey per repository; a system
  is a SET of surveys handed to one comparison. `repo.name` +
  `service` identify the witness; nothing merges surveys implicitly.

## The comparator: `groundhold survey`

```
groundhold survey <contract.yaml> --survey <s.json> [--survey ...] [--complete]
```

Deterministic (no LLM, no network), like every runtime verb. Per
finding:

- `required` with a hint → **covered** when the contract has a
  capability of that type, else **uncovered** — drift.
- `required` without a hint, `optional`, `unknown` → **gap**: a
  question for a human, never silent drift.
- `dev-test` → **ignored** (recorded in the report, weightless).

Per contract capability: no `required` finding of its type across the
surveys → **unwitnessed** (information: absence of evidence is not
evidence of absence — another repo may be the consumer). Only under
`--complete` ("these surveys are the whole system") does unwitnessed
harden into **orphaned** — drift.

Exit 0 clean; exit 2 with `code: survey-drift` when any finding is
uncovered or (under `--complete`) any capability orphaned. Exit 1 on a
structurally invalid document. The report (stdout, JSON) carries
every row with its status — nothing is dropped silently.

CI shape: regenerate the survey on a PR (code-to-contract step 1),
run `groundhold survey` against the published contract; exit 2 means the
code and the contract disagree about reality — reconcile before merge.
