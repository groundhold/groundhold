# State Model v0 (D27–D33, D35)

No mutable state file. State is three separated concerns — a decision
ledger, bindings, and observations — none of them a snapshot of the world.

## 1. Decision ledger

An append-only, content-addressed log of events. The ledger is the ONLY
write path: everything else (bindings, lease status, current heads) is a
deterministic projection of it.

### Event envelope

```yaml
apiVersion: state/v0
kind: LedgerEvent
event:
  type: lease.acquired            # from the closed registry below
  environment: production
  capabilities: [orders-db]       # affected capability ids = head keys
  occurredAt: "2026-07-11T09:00:00Z"   # RFC3339 UTC, ALWAYS quoted
  actor: { id: runtime-eu1, type: runtime }   # type: human|agent|runtime
  body: { ... }                   # type-specific payload
  # optional:
  prev: { orders-db: "sha256:..." }   # per-capability previous heads
  fencingToken: 7                 # required for mutation events under lease
  idempotencyKey: "..."           # dedup key for at-least-once producers
  # sig: { ... }                  # optional detached signature — §8 (D102)
```

**Authorship (D74).** `groundhold publish` is the producer of
`contract.published`: it appends the contract's canonical hash under a
named HUMAN actor, so the decision chain records *who approved* a
contract, not only that the runtime executed it. It advances decision
heads (a plan seals against the published head) and takes no lease — a
decision event is not a mutation. Authorship is self-asserted, not
authenticated: the ledger evidences that an actor *claimed* to publish,
per writer trust (see the boundary in §1 below and SECURITY.md).
`candidate.verified` and `plan.sealed` remain producer-less in v0 —
verification and sealing are pure read-only functions; recording them is
future scope.

### Event type registry (closed set, fail-closed — D19)

```
contract.published    candidate.verified    plan.sealed
apply.started         apply.finished        apply.failed
observation.recorded  violation.detected    violation.resolved
probe.failed          binding.updated       lease.acquired
lease.renewed         lease.released        lease.broken
operation.receipt     ownership.claimed     converge.started
converge.phase.entered  converge.finished   converge.failed
```

`ownership.claimed` (D140) stamps a takeover's authorship; the four `converge.*`
markers (D229) are run-scoped lifecycle events — lease-free, neither mutations nor
decisions — that let `status`/`wait` speak the converge tree. Both implementations
and `spec/state.schema.json` carry this same set: it is fail-closed on every side,
so a type known to one and not another makes a valid ledger unreadable (D338).

### Chain verification and its boundary (C2, D69, D70)

Replay VERIFIES the chain: every event's `prev` must pin the current
head of each capability it lists, or the ledger is corrupt (exit 5) —
a tampered, reordered or dropped line is refused, never replayed into
a silently different projection.

**Repair (D69)** is the explicit path back from corruption — a torn
line, a broken chain, or a pre-D67 fork (two writers that both won a
lease). `groundhold repair` is a READ-ONLY diagnosis: findings with line
numbers and kinds, the length of the valid prefix, and a sha256
fingerprint of the exact bytes examined. `--quarantine --fingerprint
<fp>` executes the cut under two-step consent: the corrupt file is
RENAMED aside (history preserved verbatim, never deleted, never
rewritten) and the original path gets the valid prefix back. Everything
after the cut may have mutated the cloud, so the remediation is
re-observation of reality (discover/observe/adopt) — a forked ledger
cannot be patched into truth; reality is the authority. Run repair
with writers stopped: the file backend locks the inode and repair
swaps the name.

Keeping the valid prefix is safe BECAUSE every action gate is
freshness- or reconciliation-gated: prefix observations go stale
(plan refuses, re-observe), prefix leases TTL-expire, prefix pending
receipts block apply until resumed. One boundary the operator owns:
the restored prefix REWINDS decision heads, so a plan sealed before
the corruption can pass CAS again — treat every pre-repair sealed
plan as void; re-observe and re-seal (the repair result says so).

**The tail boundary and its anchor (D70).** An event is chain-protected
once a SUCCESSOR pins its hash. The LAST line of a ledger has no
successor yet, so an edit or drop of it is not detectable by the chain
alone. `groundhold anchor` closes this from OUTSIDE the file: it emits
`(events: N, head: hash of line N)` — the normative pair — plus a
manifest over the ordered event hashes (the complete forest guard,
D185) and the per-capability heads, for the operator to
store on a medium the ledger's writer cannot touch (git remote, object
store, printed page). `anchor --check` re-replays and verifies the
ledger still EXTENDS the anchored prefix, positionally: shorter is
`truncated`, a different hash at position N is `diverged`, both exit 5.
Enforcement is opt-in but reaches the EXECUTION path: place the anchor at
`<ledger>.anchor` and `apply`/`resume`/`publish` verify it after replay,
before any provider call — a truncated or rewritten tail refuses
(exit 5) instead of mutating. No anchor file means no enforcement.
The residual boundary, still stated honestly: events appended after
the last anchor are unprotected until re-anchored; an attacker who can
replace both the ledger and the anchor is outside the threat model;
and the anchor is tamper-EVIDENCE, not truth — a legitimate writer can
still append false, well-formed events (signatures, §8, prove
authorship, not truthfulness).
Per-capability chains alone do not totally order unrelated capability
streams: the log is a per-capability FOREST, so the positional anchor
hash witnesses only the sub-chain owning the last line (D182/D185). The
anchor therefore also records a MANIFEST — a domain-separated hash over
the ordered list of every event hash, seeded by the archived baseHead —
and `--check` recomputes it over the anchored prefix. A count-preserving
rewrite of ANY interior event (an independent capability's tail, even
behind a tail that has grown past the anchor) moves a line hash and
diverges the manifest, though the positional Head still matches. The
per-capability heads the anchor carries are a narrower secondary check
(the whole-ledger tip case) and the fallback for a manifest-less anchor.

### Event identity

`groundhold/canon/v1:event` + canonical JSON of the **raw document tree**
(sorted keys, NUMSTR numbers — spec/canonicalization.md). Deliberately NO
semantic normalization, unlike contracts (D34): a contract states meaning,
so identity follows meaning; an event records what was said, and
normalizing history would falsify it (D35).

### Heads and CAS (D28, D31, D41)

Two head streams per capability:

- **full head** — hash of the last event of ANY type listing the
  capability. Serializes the log: append-level CAS checks it.
- **decision head** — advanced only by *decision* events:
  `contract.published`, `candidate.verified`, `plan.sealed`,
  `binding.updated`, `apply.*`. *Knowledge* events
  (`observation.recorded`, `violation.detected`, `violation.resolved`,
  `probe.failed`, `operation.receipt`)
  and *coordination* events (`lease.*`) are audit-chained but
  decision-head-neutral (D41): learning something about the world, or
  lease churn, must not invalidate anyone's sealed plan.

The backend interface is the spec:

```
append(event, expected_heads, idempotency_key) -> new_heads | CONFLICT
query(capability_id | contract_id | type | time_range) -> events
current_heads(capability_ids) -> {capability_id: hash}        # full
decision_heads(capability_ids) -> {capability_id: hash}
```

`append` succeeds only if, for every capability in `event.capabilities`,
the current FULL head equals `expected_heads[capability]` (absent =
"must be genesis"). A sealed plan pins DECISION heads in its read-set
(D28); apply and forecast CAS-check those. Git may mirror the ledger for
review/audit; it is never the concurrency substrate (D31).

## 2. Leases and fencing (D29)

A lease over a capability is created by `lease.acquired`, kept alive by
`lease.renewed`, ended by `lease.released` / `lease.broken` / TTL expiry.

**Fencing tokens derive from ledger history**: the token of a new lease is
`max(previous tokens for that capability) + 1`. Any replica can validate a
mutation without a coordinator. Mutation events (`apply.*`,
`binding.updated`) MUST carry `fencingToken` equal to the token of the
currently active lease for every affected capability; the backend rejects
stale tokens — a paused-and-resumed worker cannot write history.

### Mutation type registry (closed set — D599)

```
apply.started    apply.finished    apply.failed    binding.updated
```

Every other type in the event registry is NON-mutating: it takes no lease and is
appended with no fencing token. `ownership.claimed` is an authorship stamp (§1),
the four `converge.*` markers are run-scoped lifecycle (D229), the `lease.*`
family is coordination with its own rules, and observations, violations and
receipts are knowledge. A mutating type left out of this set would be appended
with no lease and no token — a silent fail-open in D29 — so both implementations
publish the split as an explicit PAIR of sets that must cover the event registry
exactly, and a gate compares all three artefacts.

Agreeing on the event-type registry is not sufficient and D338 was not the end of
it: D599 found the two implementations holding the same 21 types and disagreeing
about whether `ownership.claimed` is one of these four.

**One mutation, one lease (D633).** A fencing token is a per-capability counter, so
two leases over disjoint capability sets can carry the same number. A mutation must
therefore be covered by a SINGLE lease: every affected capability must be under the
same lease, not merely under some lease whose token happens to match. Without that, a
holder of `{a, b}` could write into `{b, c}` the moment an unrelated worker acquired
`{c}` and was handed the same token. Lease identity is a fold-time fact — recomputed on
every replay, never carried on the wire — so this changes no token arithmetic and no
existing document.

**Leases are cooperative, not authorising.** Actor identity is self-asserted (see
SECURITY.md), and no lease verb consults it: any writer inside the trust boundary can
renew, release or break any lease. The fence defends against STALENESS — a
paused-and-resumed worker cannot write history — never against impersonation. What
those interferences can do is bounded in the safe direction: a foreign renewal or
release can only DENY (the holder's next mutation refuses as stale); none of them lets
a writer append under another's fence. The real boundaries are the write path itself
and event signatures (§8).

**Breaking a lease requires reconciliation**: every `operation.receipt`
recorded under the lease must reach a terminal status (or be explicitly
adopted by the breaker) before `lease.broken` is accepted. Cloud
operations outlive processes; a broken lease must not orphan them.

## 3. Bindings (D27)

The only irreducible state: capability identity in the provider's world.
A projection of `binding.updated` events — the latest event's body wins.

```yaml
capability: orders-db
environment: production
provider:
  name: gcp
  project: acme-prod
  region: europe-west1
resources:
  - id: primary
    type: cloudsql.instance
    providerId: "acme-prod:europe-west1:orders-db-7f3a"
    generation: 3
lineage:
  aliases: []          # prior capability ids after renames
  replaces: []         # providerIds this resource replaced
  tombstones:          # STRUCTURED identity of retired resources (D47)
    - providerId: "acme-prod:europe-west1:orders-db-7f3a"
      resourceType: cloudsql.instance
      generation: 3
      deletedAt: "2026-07-11T19:10:00Z"
      deletionOperationId: "op-..."
adopted: false         # true when imported rather than created
```

No attribute caching. What cannot be re-read from the provider later is
captured at write time as an observation or operation receipt.

## 4. Observations (D27, D32)

```yaml
kind: Observation
capability: orders-db
path: network.publicExposure
value: false
source: provider-api        # provider-api | probe | manual
derivation: measured        # config-intent | measured | platform-invariant (D44/D759)
                            # quality, mirroring candidate provenance (D5)
observedAt: "2026-07-11T09:00:00Z"
ttlSeconds: 3600
```

Observers never fabricate a measurement from intent (D44): a
config-derived fact carries `derivation: config-intent`, and what can
only be measured (an RPO under PITR, an RTO) is left to probes — with a
diagnostic, not a guess.

**Reserved wiring namespace (D286)**: a path under `outputs.` is a typed
OUTPUT of a bound resource (D226/D283) — an identity one capability hands
another (a subnet set, a role ARN), recorded by `observe` like any other
reading. It is carried on the SAME event stream but folds into its OWN
projection, never the semantic observations, because it answers a different
question: an output says *what to reference*, an observation says *what is
true of a constraint*. Counted together, a freshly re-read identity makes a
capability look observed when nothing it declares was checked — a fail-open
consumers hit three ways at once (the reconcile's "has this ever been
observed?" test, proof-decay detection, and the console's evidence
freshness). The vocabulary MUST NOT declare an attribute in this namespace;
the runtime enforces the reservation.

**Freshness rule**: at evaluation time T, an observation is usable iff
`observedAt + ttlSeconds >= T`. A stale observation makes the attribute
`unknown` — which blocks hard constraints (D6). The remediation carve-out
is policy, not a verifier exception: `unknown` MAY permit narrowly-scoped,
monotonically risk-reducing remediation, NEVER destructive or
exposure-increasing changes (D32).

**Unreadable capability (D242)**: a capability whose PRIMARY read fails this
run (a transient 429/503/5xx, a transport drop, a malformed body) is
*unreadable* — the observe run does NOT abort. It continues with the other
capabilities, records NO observation for the failed one (a read failure is
never an observation — D59, and never a fabricated value), marks the result
`partial`, and lists the capability under `unreadable`. Its evidence then
stays absent or stale, which verify resolves to `unknown` and the freshness
gate above turns into `observation-required` — the same fail-closed path a
never-observed attribute takes. observe stays exit 0 (a read verb that
reported reality, including the part it could not read); enforcement is
downstream, so a partial observe can never be laundered into "verified". The
transient-vs-structural class of the failure is diagnostic text only (no
machine consumer routes on it today); if one ever does, a typed
`provider.ObserveError` detected with `errors.As` at the run boundary adds it
with no driver-signature churn. Note a deliberate consequence of the TTL
contract: a capability unreadable NOW but with prior observations still
inside TTL verifies against that evidence — correct, since inventing an
invalidation from a failed read would itself fabricate knowledge; shorten
TTLs if staleness tolerance is too loose, never fabricate.

## 5. Operation receipts (D29)

```yaml
kind: OperationReceipt
operationId: "op-1a2b3c"        # provider's operation id
idempotencyKey: "..."
capability: orders-db
target: "acme-prod:europe-west1:orders-db-7f3a"
startedAt: "2026-07-11T09:00:00Z"
lastSeenAt: "2026-07-11T09:05:00Z"
status: pending                 # pending | succeeded | failed | unknown | retryable
```

Recorded as `operation.receipt` events. Reconciliation before lease-break
(section 2) operates on these. `unknown` is NOT a terminal status: an
operation with an `unknown` receipt stays pending until a terminal
receipt lands or a breaker explicitly adopts it — a provider timeout is
not a failure, it may be a success with a lost response. `retryable`
(D241) DOES conclude the intent and clears pending, like `succeeded` and
`failed`, but is neither: it records that the provider throttled the
mutation before it could land (`provider-again-later`), so the resource
provably does not exist and the verb may be safely re-attempted — no
reconcile is needed. Only a pure rate-limit produces it; a 5xx, transport
error, or live 403 stays `unknown` (may have landed).

## 6. Risk vector (D33)

`plan.sealed` bodies carry independent risk dimensions, not a single
scalar: `{reversibility: R0..R4, dataLoss, downtime, securityExposure,
costDelta, identityReplacement}`. Autonomy policy and lease strictness
gate on the vector.

## 7. Conformance scenarios (D37)

The rules above are executable: `groundhold scenario <file>` runs a
deterministic engine with a **logical clock** (no wall time; concurrency
is interleaved steps) and both implementations must produce identical
step results (`conformance/cases/concurrency.yaml`).

Step forms: `{tick: N}`, `{append: {...}, expectedHeads?: {...}}`,
`{checkHeads: {...}}` — `"@N"` references the hash of step N's event.
Statuses: `ok | conflict | rejected` for appends (conflict = CAS mismatch,
the mechanism working, not an error), `fresh | stale` for head checks.
The apply runtime (D42) obeys these same rules — they are spec, not
plumbing; the executor drives the very code the scenarios pin.

## 8. Event signatures (D102)

Opt-in, detached, additive. A writer armed with `--sign-key` attaches a
top-level `sig` sibling of `event` in every persisted line:

```yaml
sig:
  alg: ed25519
  pub: "<32-byte public key, lowercase hex>"
  sig: "<64-byte signature, lowercase hex>"
  ledger: "sha256:<genesis event hash>"   # which ledger this attests (D134)
```

What is signed is the domain-separated message
`"groundhold/sig/v2:" + ledgerId + ":" + hash_event(doc)`, never raw line
bytes — canonicalization is the cross-implementation truth, byte
layouts are not. The `sig` key is **excluded from `hash_event`** (a
signature attests identity, it is not part of it), so signed and
unsigned copies of one event share one hash, the prev-chain is
unaffected, and unsigned history stays valid forever.

**Ledger identity (D134).** `ledgerId` is the canonical hash of the
ledger's FIRST event — self-establishing, no configuration; the genesis
line's own signature uses its own hash (computable because the hash
excludes `sig`). Verifiers pin every signature's claim to the stream's
actual genesis, so a signed event cannot be presented as attesting a
different ledger's history even under a shared key. Stated honestly:
this is a **lineage** id — forks grown from one genesis share it; the
anchor's positional head is what tells branches apart. A ledger
re-genesised after total corruption gets a NEW identity, and old
capsules/anchors refuse against it — which is the correct answer.

Verification is armed with `--trust <hex-pub>` — **repeatable** (D133):
the receiver names a SET of keys, and every line must carry a verifying
signature by any key in the set, exact match. An unsigned,
foreign-signed or non-verifying line refuses on the corruption channel
(exit 5) — the same evidence class as a broken hash chain. `export`,
the handover surface, enforces the identical rule.

**Rotation is receiver policy, not ledger history (D133).** Start
signing with the new key; receivers trust both during the overlap and
drop the old key when they choose. Revocation is "I no longer accept
this key" — a change to the receiver's set, never an event the ledger
gets a vote in. This keeps authenticity policy separate from canonical
history: capsules and old anchors are untouched by a rotation.

**Anchored trust (D135).** An anchor emitted by a process armed with
`--trust` embeds the policy it ACTUALLY verified (`trust: {scheme,
keys, from}` — never emitted unverified: an armed emit refuses at
replay first). Any path that loads an anchor — `anchor --check`, the
execution-path enforcement beside the ledger, `capsule --check` — arms
signature verification from it automatically: a receiver who forgets
`--trust` is still protected, and signature-stripping refuses on the
artifact the receiver already holds. When both CLI flags and the
anchor carry policy they must AGREE; a disagreement refuses loudly —
no silent union, no precedence.

**`--trust-from <event-hash>`** pins where signing became mandatory for
ledgers that predate D102: lines before the named event may be
unsigned; from it (**inclusive** — a tolerant boundary would be a
sliding one) every line must verify. The hash is the receiver's
out-of-band knowledge, so the boundary cannot be slid by an attacker,
and it is evaluated against the actual input being verified (a file, a
fold, a capsule) — an input that lacks the boundary refuses, otherwise
truncation would erase the obligation to be signed.

Honest threat model: a verified file proves *these events, in this
order, were authored by the holder of this key*. It does not prove
freshness or completeness — a signer can withhold a newer suffix;
countering omission is the anchor's job (D70), held off-host and
checked positionally. When `sig` is present it must be well-formed
(fail-closed at load); `groundhold keygen` mints the seed file and prints
the public half.

## 9. Snapshots (D137)

`groundhold snapshot --ledger <f>` is the file backend's compaction valve
— and a snapshot is **not a cached fold**: it is a signed receipt of a
verified prefix plus an audit index into archived history.

- The rotation replays the FULL ledger first, under whatever anchors
  and trust are armed — a snapshot of corrupt or untrusted history is
  impossible by construction. The receipt (`verifiedUnder`) records
  what the replay enforced: `mode: filesystem` (no trust armed, plain
  file trust said out loud) or `mode: trust` with the key set and any
  `--trust-from` boundary it honored.
- The snapshot document carries every projection the replay
  reconstructs, the chain position (`baseEvents`, `baseHead`), the
  ledger identity (D134), the content hash of the file it archived
  (`archive.sha256`) and `previousSnapshotHash` (audit reconstruction
  follows hashes, never filenames). `attest` reports whether the
  archive still matches that hash, `repair` turns a mismatch into a
  verdict and `export` refuses to stream from it (D646); the snapshot
  does not get to nominate WHICH file satisfies its own hash — only
  the directory may differ. With `--sign-key` armed it carries
  a detached signature (domain `groundhold/snapshot/v1`, message binds
  the ledger identity); under `--trust` an unsigned snapshot REFUSES —
  otherwise compaction would be a signature-stripping laundry.
- The compacted prefix is ARCHIVED (`<ledger>.archive.<N>`), never
  deleted; superseded snapshot documents archive too. Positions stay
  ABSOLUTE: export indices keep their meaning, tail-era anchors keep
  verifying, an anchor strictly inside the compacted prefix refuses
  toward the archive. A `--trust-from` boundary compacted into the
  archive is honored via the receipt — only when it names EXACTLY the
  armed boundary.
- Capsules refuse for capabilities whose chain begins in the archive
  (a capsule is the subchain from genesis) — emit from the archive
  file instead.
- What a snapshot family proves without a key is CONSISTENT, not
  AUTHENTIC (D646). The sidecar, the archive and the tail are checked
  against each other, which catches truncation, bit rot, a partial
  copy and single-field tampering — every one of those leaves the
  family disagreeing with itself. It does not catch an attacker with
  write access to the directory: they can re-fold, recompute the
  chain and rewrite every co-located hash, because all of those
  documents are theirs to author. Authenticity needs a witness the
  attacker does not hold — an anchor copied OFF-HOST (which also arms
  trust, D135) or `--sign-key`/`--trust`. State this to operators
  plainly rather than implying the sidecar defends itself.

- Crash recovery: the snapshot activates BEFORE the file moves, so the
  one interruptible window fails LOUD on the next replay (chain
  mismatch naming the pending archive step) — never a silently-empty
  ledger; the pre-rotation file is complete in the archive throughout.
- Correctness is pinned by an equivalence property over the ENTIRE
  fold: `fold(prefix + tail) == fold(snapshot(prefix)) + tail` — a
  projection added without snapshot support fails that test loudly.

## 10. Not in v0

Backend implementations (the interface is the spec), reconciler mode
(D30: Groundhold is gated apply + re-verification), archive GC (archives
are append-only audit material; pruning them is an operator decision
outside the runtime), cross-environment references.
