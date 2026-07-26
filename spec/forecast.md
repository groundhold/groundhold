# Forecast v0 (D40)

The plan/preview/dry-run equivalent. A **deterministic forecast from
declared inputs** — the name signals epistemic humility, not probability:
same inputs, same output, byte for byte.

Terraform's `plan` conflates four questions; Groundhold keeps them separate:

| question | answered by |
|---|---|
| is it allowed? | `verify` (four-valued verdicts) |
| what exactly executes? | the Sealed Plan (binding, not advisory) |
| what would change in the world? | **`forecast`** |
| is the plan still current? | decision-heads CAS (D41) |

## Function

```
forecast(sealed plan,
         candidate            # hash-checked against reads.candidateHash
         bindings,            # capability -> provider identity
         observations,        # world facts with observedAt + ttl
         decision heads,      # ledger snapshot (D41)
         evaluationTime)      # EXPLICIT input — freshness never reads
                              # the wall clock
  -> Forecast document
```

`observe` is the only step that touches the network, and only emits
Observation documents. A future `preview --refresh` is a documented
composition of `observe + forecast` — never a new semantic phase.

## Effects (closed set, D19 discipline)

```
will-create | will-update | will-replace | will-delete | will-adopt |
no-effect | unknown | unforecastable | stale-plan
```

`unknown` = not predictable from these inputs; `unforecastable` = this
class of effect cannot be predicted by this forecaster — the same
distinction verdicts make between `unknown` and `unverifiable` (D6).

## Unknown-reason registry (separately versioned)

Emitted today: `missing-observation | stale-observation |
unsupported-effect-model`, plus `target-identity-mismatch` (carried on
stale-plan effects). Reserved for future providers/effects (defined,
never yet emitted): `provider-computed | provider-defaulted |
write-only | cross-resource-effect | eventual-consistency-window |
requires-provider-validation`. The effect `unforecastable` is likewise
reserved in the closed effect set.

This is "known after apply" made systematic and explained: the forecast
declares WHY it does not know, and policy can gate on ignorance
("more than N unknown predictions requires a human").

## Fidelity levels

```
L0  verify                      no world contact — permission only
L1  forecast (cached inputs)    no world contact
L2  observe --record, then L1   read-only world contact
L3  provider validate-only      control-plane contact, inside apply
    ("preflight")               preflight — no mutation
L4  apply                       mutation
```

## Document

```yaml
apiVersion: forecast/v0
kind: Forecast
forecast:
  plan: "sha256:..."            # hash of the forecasted plan
  contract: orders-dev
  evaluationTime: "2026-07-11T12:00:00Z"
  freshPlan: true               # CAS vs the DECLARED heads (see the last section)
  actions:
    - id: a-create-orders-db
      capability: orders-db
      operation: create
      effect: will-create
      attributes:               # desired values with provenance carried
        - { path: engine.protocol, desired: postgresql/16.4, basis: declared }
        - { path: cost.monthly, desired: 210.5 EUR, basis: inferred }
      # or, when not predictable:
      # effect: unknown
      # reason: unsupported-effect-model
  rollup: { willCreate: 1, unknown: 0, ... }
```

Canonical domain `groundhold/canon/v1:forecast` is reserved.

## Attribute predictions (D45)

With bindings and observations supplied (from `--ledger` replay or
files — the natural pipe is `observe > obs.json; forecast
--observations obs.json`), every desired attribute gets a prediction
from the four-valued set, the D3/D6 discipline at prediction level:

```
match | differ | unknown | unverifiable
```

- comparison is canonical scalar equality (D25: 300s matches 5m) —
  no ad hoc comparison modes; set/compatibility semantics belong in a
  future vocabulary-declared comparator registry, `exact` by default
- a kind mismatch between desired and observed (money where a duration
  is desired) is `unverifiable` — calling it differ would be false
  precision, calling it unknown loses the D3 distinction
- a stale observation (`observedAt + ttl < evaluationTime`) is
  `unknown / stale-observation`; missing → `unknown /
  missing-observation`
- predictions carry the current value, the observation's age and its
  `derivation` (D44) — config-intent may produce `match`; whether that
  evidence suffices is policy's decision, not the forecaster's

**Action effects with bindings**: `create` on an UNBOUND capability →
`will-create`; `create` on a BOUND capability → `no-effect` — the
executor would 409-continue and change nothing, so that is the honest
forecast OF THE ACTION; drift screams at attribute level and in the
rollup (`driftingAttributes`, `unknownAttributes`,
`unverifiableAttributes`), and acting on it is a re-plan decision.

## Implementation scope (explicit, not silent)

`will-create` (including D48 replacement-creates: a generation-stamped
create on a bound capability will-creates — the name differs, no 409
continuation), `will-update` (D46), `will-delete` (D47: pinned target
must match the binding — a mismatch forecasts `stale-plan /
target-identity-mismatch`, the same answer apply would give) and
`no-effect` are live; `will-replace`/`will-adopt` stay reserved by the
closed set — unmodeled operations forecast `unknown /
unsupported-effect-model`, never a guess.

## A preview against declared inputs — NOT a gate

Forecast reads NOTHING from the world (D40); every head, binding and
observation is a DECLARED input. Two consequences a caller must not
misread:

- **`freshPlan` is freshness against the DECLARED decision heads, not
  against reality.** The decision-heads CAS compares the plan's pinned
  heads to the heads you supply via `--ledger` (the replayed
  `DecisionHeads`) or `--heads`. Supply NEITHER and the head set is
  empty, so every cap defaults to `genesis`: a greenfield plan (pinned at
  genesis) then correctly reads `freshPlan: true`, but a plan pinned at
  genesis whose real world has since MOVED also reads `true` — forecast
  cannot tell "no history" from "history not supplied." So `freshPlan:
  true` means *fresh against the world you declared*; to assess freshness
  against real history, supply `--ledger`. The forecaster does not read
  the world to find out, by design.

- **The exit code is not an all-clear.** `forecast` exits 0 whenever it
  produced a well-formed prediction — including one full of `stale-plan`
  effects, `driftingAttributes`, `unknownAttributes` or
  `unverifiableAttributes`. The risk lives in the JSON body, never in the
  exit channel; an agent must READ the rollup, not gate on `forecast &&
  apply`. The ENFORCING gates — the decision-heads CAS, the staleness
  re-check under lease, the permission preflight — run in `apply` and
  `converge`, which refuse a stale or unproven plan before any mutation.
  Forecast is the preview; apply is the gate.
