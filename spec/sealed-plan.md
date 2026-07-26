# Sealed Plan IR v0 (D28, D29, D33, D36)

A sealed plan is the artifact between "candidate verified" and "apply":
a decision record of exactly what will be executed, under exactly which
assumptions. Apply is a CAS against the ledger (D28); the plan is what
gets compared.

## Document

```yaml
apiVersion: plan/v0
kind: SealedPlan
plan:
  contract: orders-production
  environment: production

  # D28: the FULL read-set — everything the planner looked at
  reads:
    contractHash: "sha256:..."
    candidateHash: "sha256:..."
    heads: { orders-db: genesis }        # DECISION head per capability
                                         # (D41); "genesis" = no history
    vocabularies: { capability.database.relational: "0.1" }   # optional
    toolchain: { compiler: groundhold-go/0.1.0, spec: contract/v0.1 }
    pricingCatalog: gcp-eu-2026-07       # optional
    provider: { name: gcp, project: acme-prod, region: europe-west1 }

  # write-set: every written capability MUST have its head pinned in
  # reads.heads — you cannot write what you did not read
  writes: [orders-db]

  actions:
    - id: a-create-primary
      capability: orders-db              # must be in writes
      operation: create                  # closed set, below
      target: cloudsql.instance/primary
      idempotencyKey: orders-db-create-7f3a   # D29
      dependsOn: []                      # action ids; graph must be acyclic
      risk:                              # D33: full vector, per action
        reversibility: R2                # R0..R4
        dataLoss: none                   # none | possible | certain
        downtime: none
        securityExposure: none
        costDelta: { amount: 912, currency: EUR }
        identityReplacement: false
      requiredPermissions:               # D75: provider perms this action needs
        - cloudsql.instances.create      #   (sorted, deduped; quiet reads
        - cloudsql.instances.get         #    included — instances.get polls +
                                         #    classifies 409)

  witnessed:                             # D177 (optional): capabilities VERIFIED
    - capability: gitops-root            #   but NOT authored — a witness the
      provider: k8s                      #   provider can only observe (no write
      service: argocd-application        #   lens). Recorded explicitly, never
      reason: not-authorable             #   silent; DISJOINT from writes.

  preconditions:                         # closed registry; MUST include
    - type: report-executable            #   report-executable
```

## Rules (fail-closed, D19)

- **Operations**: `create | update | replace | delete | adopt | noop`.
- **Update actions carry a reviewed change-set** (D46): a non-empty
  `changes: [{path, from, to, caveat?}]` list. from/to are denormalized
  audit fields; the executor patches from the hash-pinned candidate,
  scoped by the listed paths — never an implicit diff at apply time.
- **Replacement creates carry their reason** (D48): a create with
  `targetGeneration` >= 2 and a `replaces: {providerId, generation,
  because: [...]}` block is one leg of a create-before-destroy
  composition — the paired delete dependsOn it. (Emitted by the
  compiler and consumed by apply's consent gate; load-time validation
  of this shape is not yet enforced — a future rule.)
- **Delete actions pin the exact identity they destroy** (D47):
  `targetProviderId` + `targetGeneration` are required, and apply
  compares them against the CURRENT binding — a rebind between seal and
  apply cannot redirect a delete.
- **Deposed deletes are marked** (D71): a delete with `deposed: true`
  targets an ORPHAN of a failed replacement, whose capability is bound
  to the successor — so apply validates the pin against the fresh
  deposed projection instead of the binding. Emitted by
  `plan --deposed`; the same identity+generation pinning applies.
- **Actions** form an acyclic dependency graph; `dependsOn` references
  must resolve (D11); action ids are unique; every action carries an
  idempotency key and a complete risk vector.
- **writes ⊆ keys(reads.heads)** — a plan that mutates a capability whose
  head it did not pin is unsealed by definition.
- **Actions carry `requiredPermissions`** (D75): the deterministic provider
  permission set the action's driver call sequence needs — sorted, deduped,
  from `provider.PermissionsFor`, quiet reads included (omitting one produces
  a false PASS). Optional and additive, so pre-D75 plans stay loadable. The
  compiler DERIVES it and makes no network call; the executor preflights the
  UNION (its own current derivation ∪ the declared list — never trusting a
  possibly-stale sealed list alone) against the acting identity before the
  lease and before any mutation.
- **Actions may carry `references`** (D226): intra-plan output references,
  `[{slot, producerAction, capability, output, kind}]`, sorted by slot. Only
  this SYMBOLIC structure enters the plan hash — never a runtime value — so
  the plan stays restart-stable. Each reference also appears as a
  `dependsOn` edge on the producer's create, and the consumer's idempotency
  key folds every producer's key (a producer replace re-keys the consumer,
  so a receipt minted against a dead producer cannot be reused). Resolution
  semantics live in `spec/executor.md` (D275).
- **Actions may carry `folds`** (D283): references to ALREADY-BOUND
  producers, resolved at compile from a fresh `outputs.<name>` observation
  into `[{slot, capability, output, value, observedAt, ttlSeconds}]`,
  sorted by slot. Unlike a symbolic reference, the folded LITERAL is part
  of the sealed decision and enters the plan hash — a new observation
  yields a new plan — and apply re-checks the backing observation
  (existence, same value, TTL at its own `--at`) pre-lease.
- **Preconditions** come from the closed registry
  `report-executable | no-assumed-basis | no-assumed-hard-basis |
  within-autonomy` and MUST include `report-executable`: a plan that does
  not require verification to pass contradicts the thesis.
  `no-assumed-hard-basis` (D195) is emitted when the contract sets
  `autonomy.no_assumed_hard_basis: true`; the executor refuses if any HARD
  constraint's satisfied/violated verdict rests on an `assumed` value —
  the opt-in that makes D5's "policy can gate on satisfied-but-assumed"
  reachable (the verifier itself still only reports the basis).
- The plan carries **no timestamp** — sealing is recorded by the
  `plan.sealed` ledger event, which does (separation of artifact and
  occurrence, D35).

## Identity

`groundhold/canon/v1:plan` over the raw canonical tree — like events (D35),
not like contracts (D34): a sealed plan records a decision; normalizing
it would re-open it.

## Apply semantics (informative, v0)

1. Check preconditions (verification report for the pinned hashes must
   satisfy each).
2. Acquire leases + fencing tokens for `writes` (D29).
3. CAS: `current_heads(writes) == reads.heads`, and re-check the rest of
   the read-set (toolchain, vocab versions, provider identity).
4. Execute actions in dependency order, recording operation receipts.
5. Append `apply.finished` / `apply.failed`; release leases.
Any CAS mismatch invalidates the plan: re-verify, re-seal. Autonomy
policy gates on the per-action risk vectors (D33).
