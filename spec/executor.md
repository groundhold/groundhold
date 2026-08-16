# Executor v0 (D42)

Apply drives a Sealed Plan against a provider, gated by the ledger. The
rules are `internal/ledger` — the same code the D37 conformance scenarios
pin; what the scenarios prove is what apply obeys.

## Refuse-before-mutate preflight (in order)

1. **Read-set identity**: contract and candidate documents must hash to
   `reads.contractHash` / `reads.candidateHash`.
2. **Preconditions** (closed registry, D36) — `report-executable |
   no-assumed-basis | no-assumed-hard-basis | within-autonomy`, the same
   registry `spec/sealed-plan.md` publishes. `report-executable` is
   re-verified from the pinned documents; `no-assumed-basis` and
   `no-assumed-hard-basis` (D195: a HARD constraint may not seal on an
   assumed value) from the report; anything the executor cannot evaluate
   REFUSES fail-closed (`within-autonomy` in v0). A plan carrying a
   precondition outside the registry is refused for the same reason —
   the executor never skips what it cannot judge.
3. **Effect-model limit**: `create`, `update` (D46: update requires a
   binding, every listed change must classify as honorable in place) and
   `delete` (D47: the pinned target identity must match the current
   binding — exit 3 with "re-seal" otherwise). A delete marked
   `deposed: true` (D71) validates its pin against the FRESH deposed
   projection instead — an orphan's capability is by definition bound
   to its successor; an id no longer deposed refuses stale-decision.
3a. **Autonomy is an UNCONDITIONAL executor gate** (D47/D48): delete of
   a stateful capability under `autonomy.forbidden delete_stateful`
   refuses; a REPLACEMENT (create+delete of the same capability in one
   plan) of a stateful capability refuses without
   `autonomy.allow_replace_stateful` consent — a hand-authored plan
   cannot bypass compiler policy. Statefulness fails closed when the
   vocabulary is absent. A deposed delete (D71) of a stateful
   capability requires the same scoped consent — it is the destroy
   half of a replacement arriving late, checked NOW (compile AND
   apply), never remembered from the original replacement.
4. **Reconciliation**: pending operation receipts on any written
   capability refuse (resume (D57) is the first-class recovery path, not a rerun).
5. **Permission preflight** (D75, the first LIVE step): the union of the
   actions' `requiredPermissions` (the executor's own current derivation
   unioned with the plan's declared set — never trust only a possibly-stale
   sealed list) is checked against the acting identity via the provider's
   optional `Preflighter`, against the plan's PINNED `reads.provider.project`.
   It runs after every deterministic refusal and BEFORE lease acquisition — a
   doomed apply takes no lease and appends nothing — and is never re-checked
   (permission truth is not CAS-able). Missing permissions refuse
   `provider-permission-denied`; a check that cannot RUN (provider IAM API
   unreachable, token/scope) refuses `preflight-inconclusive` FAIL-CLOSED; a
   provider with no `Preflighter` SKIPS loudly (surfaced in the result)
   unless `--require-preflight`. Best-effort fail-fast, NOT an authorization
   proof: a refusal is trustworthy, a pass is evidence, not proof — IAM deny
   policies, conditional bindings, propagation lag, org policy, VPC-SC and
   OAuth scope can all diverge at call time, so mid-apply permission failure
   stays possible and write-ahead receipts remain the recovery story.
6. **Decision-heads CAS** (D41) — re-checked AGAIN under the lease before
   `apply.started`; a conflict between the two checks releases the lease
   and refuses.

## Execution and write-ahead discipline

```
lease.acquired(ttl, applyRunId)          -> fencing token
apply.started(token, applyRunId, plan)
per action, in dependency order:
  operation.receipt(pending)             <- BEFORE the provider call
  provider.Create(target, attrs, idempotencyKey)
  operation.receipt(succeeded|failed)
  binding.updated(token, FULL projection) # latest-body-wins: never partial
apply.finished(token) ; lease.released(token)
```

- Every apply-scoped event carries `applyRunId` =
  hash(planHash, evaluationTime) — a retry of the same logical run is
  recognizable; resume becomes queryable.
- On provider failure: terminal failed receipt → `apply.failed` →
  release → exit 4. The pending receipt was already durable, so a crash
  at any point leaves reconstructable intent.
- Receipts never store raw provider responses (secrets).
- `unknown` receipt status is NOT terminal: it keeps the operation
  pending until reconciled or explicitly adopted.
- Update receipts carry a VERIFIABLE target shape (D72): the pinned
  bound identity (`targetProviderId`) and the exact desired values
  (`changes: [{path, to}]`) — so resume can conclude a lost update
  against measured reality. Resume concludes creates (binding),
  deletes (tombstone) and updates (generation bump, identity
  survives); an update receipt without the pin predates D72 and
  refuses by name (unsupported-operation, reconcile manually). A
  reconciler concludes an update `succeeded` only when every desired
  value is measurable and equal; a mismatch stays `unknown` — the
  patch may still be in flight, and reconciliation never guesses.

### Intra-plan output references (D226/D275)

- A succeeded create's terminal receipt carries `outputs`: the driver's raw
  result filtered through its typed `OutputsFor` contract — only declared
  names, every declared name present, every value matching its declared kind
  (string, or list of non-empty strings; no coercion). A missing or
  wrong-kinded DECLARED output demotes the outcome to `unknown` at
  receipt-write time: the driver broke its own contract and nothing
  downstream may start on it. A driver without the `OutputProducer`
  interface receipts no outputs, which is not an error.
- An action carrying `references` resolves each one from the producer's
  receipted outputs of the SAME run, BEFORE its own write-ahead intent. Any
  resolution failure (producer receipt absent, output missing, kind
  mismatch) refuses with `reference-unresolved`: no intent is written, no
  driver call is made — earlier actions' receipts and bindings are already
  durable, and nothing is pending for this action.
- A ref-consumer's driver `Validate` is DEFERRED from the upfront
  refuse-before-mutate pass to resolution time — still before its intent.
  Its operand values do not exist up front, and the executor never passes a
  placeholder: a made-up operand would make Validate's answer a lie. The
  cost is honest: a refusal for a ref-consumer surfaces mid-run, after its
  producers (which are exactly its dependencies) are durable.
- A reference to a capability the plan does NOT create but the ledger BINDS
  folds at COMPILE (D283): `observe` records a bound resource's declared
  outputs as `outputs.<name>` observations, and a FRESH one (TTL against the
  explicit `--at`, N1; future-dated refused) becomes a literal in the
  action's `folds` — part of the sealed decision, in the plan hash. Absent
  or stale refuses `observation-required`; a producer this same plan
  DELETES refuses (`ref-producer-retiring`); never a symbolic fallback,
  never the candidate's old literal. A fold-only consumer validates UP
  FRONT on the folded literals.
- Apply re-judges every fold PRE-LEASE against the replayed ledger at its
  own `--at`: the backing `outputs.<name>` record must still exist, still
  carry the folded value (a moved value means the seal rests on superseded
  knowledge), and still be within TTL. Any miss is the stale-plan class
  (exit 3): re-observe + re-seal, never a silent apply of a decayed literal.

## Exit codes

```
0 applied   1 structural   2 refused (preconditions / read-set)
3 refused (stale plan or lease conflict)   4 failed mid-flight
5 corrupted ledger
```

3 vs 2 matters operationally: stale means re-seal, refusal means fix the
documents. The JSON result carries machine-readable reasons either way.

## Ledger file (v0)

Append-only JSONL, one event per line. `flock` + `fsync` around each
append (never held during provider calls); a torn final line is
CORRUPTION (exit 5), never auto-truncated — `groundhold repair` (D69,
spec/state-model.md) is the explicit two-step path back. On start,
apply REPLAYS the file through the ledger rules;
any replay rejection = corruption. Single-writer per environment is a
documented v0 assumption; a real backend implements the same D31
interface. Replay validates schema, hashes, chain and lease/receipt
invariants — it must NOT re-run contract verification of historical
events with today's code (spec evolution would make old ledgers
unreadable); validators are versioned per event apiVersion.

## Time

Evaluation time is an explicit input (`--at`), like forecast (D40):
event timestamps and TTL arithmetic are deterministic and
conformance-testable. Known v0 limitation, recorded deliberately:
production lease liveness cannot ultimately trust caller-supplied time —
a real backend issues its own monotonic clock for coordination while
evaluation time stays declared. The two roles must not be conflated.

## Provider interface

Core: `Name / Validate / Create(capability, environment, attributes,
implementation, idempotencyKey, generation) / Observe / ClassifyChange /
Update / Delete` (grown through D43-D48). Optional capabilities:
`Discoverer.List` (D52), `Reconciler.Reconcile` (D57, read-only),
`Prober.Probe` (D59, never implicit),
`Preflighter.CheckPermissions` (D75, read-only, the only live IAM call).
The pure permission TABLE is
`provider.PermissionsFor(name, service, operation, attrs)` (D75, per-service
D76) — core, deterministic, keyed by (provider, SERVICE, operation) and
attribute-aware (a public Cloud Run service needs IAM permissions a private
one does not); it feeds the compiler and never touches the network.

**Multi-service dispatch (D76).** A driver that fulfils several services
(the GCP driver: `cloudsql`, `cloudrun`, `gcs`) dispatches on the SERVICE
token — the API family, not the capability TYPE (a `database.relational` may
be Cloud SQL or AlloyDB). Every method takes `service` explicitly; the driver
routes with a closed switch that FAILS CLOSED on unknown or empty — never a
default service, since an influenceable string silently routing into the wrong
API is a confused-deputy. The service is sourced from the hash-pinned plan
target (and the binding, for retirement); apply cross-checks the target
service against the candidate and refuses a mismatch, so a hand-edited plan
cannot re-route a capability into the wrong builder. Per-service sub-drivers
each own their providerId parser (charset-validated, D73) and refuse a
providerId whose service token disagrees with the dispatched service. The fake provider is fully
deterministic (ids derive from idempotency keys — deterministic names
outlive request-dedup windows) with per-key failure injection for
conformance. The GCP driver is an adapter, not a redesign; it
implements the core plus all optional capabilities (Discoverer,
Reconciler, Prober — D65).
