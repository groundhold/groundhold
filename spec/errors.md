# Error code registry (D64)

Machine-readable refusal codes. The `code` field is the CONTRACT:
scripts and agents route on it. `reasons[]` (verbatim prose) and the
`explain` object (emitted under `--explain`) are human/agent-facing
and MUST NOT be parsed for control flow.

Registry rules (mirror the event-type registry): additive-only; once
published a code is never reused, never changes meaning, never leaves
conformance — a misleading code is superseded by a new one and marked
reserved. One code per DISTINCT REMEDIATION: if two failures demand
the same next action, they share a code, wherever they were detected.

| code | exit | next action |
|---|---|---|
| `structural-error` | 1 | fix the document; it does not parse or validate |
| `not-executable` | 2 | fix the candidate (or contract): hard constraints are not satisfied |
| `nothing-to-change` | 2 | none — the world already converges (converge reports success) |
| `observation-required` | 2 | run `observe --record`, then retry (missing OR stale observation) |
| `reconcile-required` | 3/4 | run `resume` (pending receipts block, or an outcome just came back unknown) |
| `reconcile-pending` | 3 | retry `resume` later — the provider cannot answer yet |
| `provider-again-later` | 4 | wait for the backoff (honor `Retry-After` when present), then re-run the same verb — the provider throttled the mutation before it landed, so no reconcile is needed (D237). Distinct from `reconcile-required`: a pure rate-limit provably did not execute, whereas a 5xx/transport/live-403 may have landed and needs `resume` first |
| `horizon-action-required` | 2 | run the advised verb before the stated deadline — `horizon --within` projected a hard constraint's proof decaying (run `refresh`) or a live run's lease lapsing with a receipt unsettled (run `wait`/`resume`) inside the window. A future condition, not a present refusal |
| `consent-required` | 2 | add the explicit consent (contract autonomy entry or the named flag); nothing implicit unlocks it |
| `confirmation-required` | 2 | a human must confirm (interactive prompt, MCP token, --yes) |
| `read-set-mismatch` | 2 | use the exact documents the plan pinned, or re-seal |
| `stale-decision` | 3 | re-observe/re-plan: decision heads or pinned targets moved since sealing |
| `lease-conflict` | 3 | wait for the active lease or break it deliberately |
| `clock-regress` | 2/3 | fix the writer's clock; the ledger refuses backdated appends |
| `binding-conflict` | 2 | unadopt/retire first: the capability or providerId is already bound |
| `adoption-mismatch` | 2 | fix the candidate or the resource — adoption must not lie |
| `provider-refused` | 2 | the driver cannot honor the request; change the candidate implementation |
| `provider-permission-denied` | 2 | grant the acting identity the listed permissions, or apply as one that has them (D75 preflight). Raised ONLY on an AUTHORITATIVE negative: for an EXISTING resource, the resource's own testIamPermissions reports the permission absent (D80); otherwise the project surface attests it (a CRM-evaluated permission). A non-attesting surface's silence, or an unreadable resource surface, never raises this — that is `preflight-inconclusive` (D78) |
| `preflight-inconclusive` | 2 | the check could not run (enable the provider's IAM API, fix the token/scope, restore connectivity) OR the provider cannot attest some queried permissions (an allowlist omission — not a denial); without `--require-preflight` the apply proceeds loudly, the mutation itself being the authorization oracle (D75/D78) |
| `survey-drift` | 2 | reconcile the contract with the code survey (D93): add the capability the code now requires, or retire the one no repo witnesses; re-crawl if the survey is stale |
| `mapping-schema-drift` | 2 | re-author the schema-driven mapping against the live API schema: a mapped field changed type, lost an enum member, or vanished inside the mapped surface, so the engine refuses to reinterpret rather than misread it |
| `unsupported-operation` | 2 | not in this version's scope; consult the verb's documentation |
| `reference-invalid` | 2 | fix the candidate `$ref` (D226): unknown capability/output, kind mismatch (no coercion), malformed reference, dependency cycle, a producer this plan retires, or an ambiguous producer generation. A stale fold is `observation-required`, not this |
| `reference-unresolved` | 3/4 | a same-plan producer did not yield the referenced output as a satisfied, correctly-typed value (D226); the consumer is refused before mutating — inspect the producer receipt, then `resume`. A missing/kind-invalid output is a driver contract violation (re-plan); a producer still `unknown` resolves on `resume` |
| `unknown-operand` | 2 | the candidate declares an `implementation:` operand no driver reads (D26 is free-form, but a key the driver would silently drop is refused, not honored — the fail-closed rule the per-attribute allowlists already enforce): declare the operand under a key the driver consumes, or remove it. Only TOP-LEVEL keys are checked — a map-valued operand's arbitrary subkeys stay free |
| `apply-failed` | 4 | inspect the reason and receipts; re-plan (terminal provider failure) |
| `ledger-corrupted` | 5 | `groundhold repair` (D69): diagnose, then quarantine on fingerprint consent; nothing proceeds over corruption |
| `run-done` | 0 | none — the background run concluded successfully |
| `run-running` | 3 | none — wait; a writer holds a live lease and the run has not concluded (`wait <handle>` blocks until it does) |
| `run-stalled` | 3 | run `resume` — the writer's lease lapsed without concluding the run |
| `run-needs-reconcile` | 3 | run `resume` — the run concluded leaving receipts unsettled |
| `run-failed` | 4 | inspect the run's own refusal: this code reports the OUTCOME, the run's code says why. `wait`/`status` relay the run's exit code when it has one, else 4 |
| `run-unknown` | 3 | check the handle; a `registry-only` run was launched but never admitted (it may have died before its first event) — read its log |
| `wait-timeout` | 3 | re-run `wait` with a longer `--timeout`, or poll `status`; nothing was cancelled and no state changed — the run is unaffected |

The last seven are the background-run family (D229/D231). They report a run's
state rather than refusing an operation, which is why several are not failures —
`run-done` exits 0, exactly as `nothing-to-change` reports success. They belong
in this registry because they arrive in the same `code` field, on the same
routing contract, and travel further than the others: notification hooks receive
them (D231), so a consumer outside the CLI routes on them too.

Exit codes stay the coarse layer (D22, frozen); codes are the fine
layer. Coverage (D65): every JSON-emitting verb carries `code`;
`plan` on exit 2 additionally prints exactly ONE refusal object
(`{status, code?, reasons}`) to stdout — previously empty, so nothing
breaks, and the success document stays self-discriminating via its
top-level `plan` key; `verify`'s report carries
`code: not-executable` when it blocks. Prose (stderr, `reasons`)
remains verbatim and unparseable by contract.

## The advisory `next` (D230)

A refusal MAY carry an optional `next` object — the invocation-specific step that
would unblock this run, where the static remediation above is generic. It is
ADVISORY: nothing in the runtime reads it, the `code` stays the contract, and it
never changes control flow. Discriminated by `kind`:

- `command` — a runnable groundhold invocation: `argv[]` (argv[0] = `groundhold`,
  executable as-is), a `command` display string, `runnable: true` when no
  placeholders. Emitted only when EVERY required argument is known verbatim from
  the operator's own inputs — omit over guess; no fabricated values, no
  placeholders inside a runnable command.
- `edit` — a contract/candidate change a human must make (`edit.path`,
  `edit.pointer`, optional `edit.insert`). Never runnable, which preserves human
  gates (e.g. consent) structurally.
- `grant` — permissions to grant via the operator's own IAM tooling
  (`grant.principal`, sorted `grant.permissions`). Never a fabricated provider CLI.

Every `next` also carries `retry`: the operator's own invocation verbatim — what
to run after applying the fix. Agents route on `runnable`; humans copy `command`.
An unset `next` means no honest actionable step exists — the static remediation
stands. `groundhold explain <code>` stays static (it has no invocation context).
