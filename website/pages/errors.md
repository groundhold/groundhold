# Errors and exit codes

Every failure is **classifiable** (exit code + machine `code`),
**serializable** (JSON on stdout) and **replayable** (the ledger
reconstructs state through the same rules every writer obeyed).

The `code` field is the contract — route on it. `reasons[]` is
verbatim prose; `explain` (under `--explain`) is remediation text.
Neither is ever stable enough to parse, by design and by
documentation.

The full registry with remediation per code lives in
`spec/errors.md` in the repository — one code per
DISTINCT REMEDIATION, additive-only
with reserved semantics: once published a code never changes meaning.
Any code explains itself: `groundhold explain <code>`.

Highlights:

| code | you should |
|---|---|
| `not-executable` | fix the candidate — a hard constraint is unproven |
| `observation-required` | run `observe --record`, retry |
| `reconcile-required` | run `resume` |
| `consent-required` | add the contract autonomy entry or the named flag |
| `confirmation-required` | a human must confirm this exact decision |
| `stale-decision` | re-observe and re-plan |
| `clock-regress` | fix the writer's clock — the ledger never rewinds |
| `provider-permission-denied` | grant the acting identity the listed permissions (D75 preflight) |
| `preflight-inconclusive` | make the permission check runnable (enable the IAM API, fix token/scope) |
