# Brownfield onboarding (D52)

Adopting infrastructure Groundhold did not create. Reality is the first
author, never the authority: discovery reports what IS; a human decides
what OUGHT to be; adoption verifies the two agree before any binding is
written; a `claim` stamps our authorship on the resource; and the
converged no-op run AFTER that claim proves the takeover.

## discover

Read-only enumeration through the driver's optional `Discoverer`
capability. Never writes the ledger, never mutates the cloud. Output is
a `DiscoveryDocument` (`apiVersion: discovery/v0`): provider, scope,
evaluation time, and per resource its canonical providerId, vocabulary
type, reverse-mapped observations (same pure mapping Observe uses) and
a MECHANICAL candidate skeleton. The document hashes under
`groundhold/canon/v1:discovery` (raw tree, like events — it records what
enumeration saw); drafts and adoptions cite that hash as their
provenance root.

## drafting (authoring boundary, D49)

Contracts drafted from a discovery carry an assumption
`{status: observed, source: "discovery <hash> at <ts>"}` on every
reality-derived constraint — the observed-not-intent marker. A human
resolves each marker: confirmed intent (marker removed) or accident of
reality (constraint removed). Tier, disk, flags are accidents;
residency, exposure, recovery are usually intent.

## adopt

`adopt <contract> <candidate> --ledger L --map cap=providerId
[--discovery file]` — a deterministic gate that mutates the LEDGER,
never the cloud:

- the candidate must verify executable against the contract;
- every candidate-declared attribute needs a LIVE observation that
  agrees (`equals` under the no-coercion scalar rules): a differing
  value, an unobservable attribute or an incomparable pair each refuse
  — adoption must not lie, and unknown never passes as a match;
- no double adoption: a bound capability refuses, a providerId bound to
  another capability refuses;
- gates passed: under a lease (fencing tokens, D29) write
  `binding.updated` with the SAME body shape apply writes — resources
  `[{id, type, providerId, generation: 1, origin: "adopted",
  adoptedFromDiscoveryHash?}]` — then `observation.recorded` with the
  observations the adoption was decided on. No new event type: adoption
  is a binding mutation, distinguishable by `origin`, and projections
  must not care who bound a capability.

Adopted names are opaque: replacement names derive from (project,
environment, capability, generation) — a foreign `-g2` suffix is never
parsed as Groundhold lineage.

## proof of takeover

Takeover is TWO acts, and this section used to describe only the second.

`adopt` binds the resource in the ledger and deliberately touches nothing in
the cloud. So the resource still carries no authorship stamp, and the first
`converge` after an adoption plans a **claim** — the D52 operation whose whole
job is to stamp authorship on an adopted resource. That planned claim is the
takeover proceeding, not a draft that fails to match reality.

Run it (`converge … --yes`, or apply the claim), and then:

`converge` (D51) must report **converged** without executing anything.
An adoption without the no-op proof is a binding, not a takeover.

Measured end to end on the reference provider (D1246):

    adopt                     -> adopted (binds the ledger, never the cloud)
    converge (no --yes)       -> REFUSED confirmation-required; plan: claim <target>
    converge --yes            -> CONVERGED (verified against observed reality)
    converge                  -> CONVERGED (already matches on every attribute
                                            this run can compare — D1242)

The distinction matters because the rule "a planned change means the draft is
wrong" is true of attribute mismatches and FALSE of the claim: no amount of
redrafting removes a missing authorship stamp, so an operator who applies that
rule to the claim loops forever on a correct draft.

## unadopt

Reverses a mistaken adoption: removes the BINDING (resources `[]`,
prior identity recorded verbatim in `unadopted`), never the resource.
Contrast retirement (D47), which destroys. The released identity can be
adopted again.

## terraform / pulumi import (D53)

`hints <state-file> [--format auto|tfstate|pulumi]` — a PURE
translation (no cloud calls, no ledger writes) of terraform state v4 or
a pulumi checkpoint into an `AdoptionHints` document: per resource its
address (tf address / pulumi URN), suggested vocabulary type, canonical
providerId and `expected` attributes. Hints are NEVER a contract and
never observations:

- `expected` values carry no derivation claim — they exist to be
  verified against live discovery; live observations win every
  disagreement (state stores normalized, coerced, provider-defaulted
  values; semantics break before ID mappings do);
- values cross from state into hints only through the explicit per-path
  mapping (the same enum tables the API observe mapper uses — one
  translation table, two consumers); secrets and implementation noise
  (tiers, disks, flags) are structurally excluded by the allowlist;
- pulumi OUTPUTS feed the mapping (the last state pulumi saw), not
  inputs (desires);
- data sources, composite children (google_sql_user rides along with
  its instance) and unmapped resource types become diagnostics, never
  silent drops; an unrecognizable document is an error, never a guess;
- the hints document is deliberately NOT canonically hashed: hints are
  untrusted throwaway input. Auditability comes from source
  serial/lineage; drafts cite the DISCOVERY hash, not hints.

**Scope, stated rather than left to be inferred (D572).** `hints` translates ONE
capability today — `capability.database.relational` — from six resource types:

- terraform: `google_sql_database_instance`, and `google_sql_database` /
  `google_sql_user`, which ride along with their instance as diagnostics;
- pulumi: `gcp:sql/databaseInstance:DatabaseInstance`, and
  `gcp:sql/database:Database` / `gcp:sql/user:User`, likewise.

Everything else — every AWS, Azure and Kubernetes type, and every other GCP service —
comes back as a named `skipped` diagnostic. That is the promised behaviour for an
unmapped type, not a failure, but it means a state file from another cloud yields an
empty `hints` array. Widening the table is per-service work of the same kind as a
vocabulary mapping: derived from the driver, never guessed, because a wrong hint is
worse than an absent one. A test holds this list to the code, so a type added without
a line here fails the build.

Migration is the same onboarding path with a head start: hints →
discover live → compare expected vs observed (disagreements surface as
state drift found during migration) → draft → adopt → `converge --yes`
to execute the claim → converged no-op proof. The claim is not optional
and not a sign of a bad draft; see §proof of takeover.
## Recovering a lost or missing ledger

The ledger holds the authoritative bindings — which live resource each capability
is. It is not a cache: lose it and `converge` can no longer see what exists, so it
plans to CREATE every capability. Two safeguards, and the recovery:

- **Keep the ledger durable.** It is state, not scratch — commit it beside the
  contract and candidate (never leave it under `/tmp`). Treat it like Terraform
  state: losing it is an incident.
- **The lost-ledger advisory (D251).** When `converge` sees a plan that is
  ENTIRELY creates across several capabilities and an empty ledger, it warns:
  this is either a first deployment or a lost/wrong ledger, and applying against
  already-existing infrastructure would create duplicates. A first deploy is
  fine; otherwise stop and rebuild state.
- **Rebuild with discover + adopt.** `discover --provider <p>` lists live
  resources (providerId + reverse-mapped observations). For each capability, bind
  its resource: `adopt <contract> <candidate> --ledger L --provider <p> --at <t>
  --map cap=providerId`. adopt confirms the DECLARED attributes against live
  observation and refuses on a mismatch — so if the deployed reality diverged from
  the candidate (a different region tier, a toggled flag), adopt a candidate that
  matches REALITY, then let `converge` carry the delta. A capability that
  legitimately spans several resources (addon sets, per-model grants) is a known
  gap: the binding is one-providerId-per-capability today.
