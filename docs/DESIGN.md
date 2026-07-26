# Design decisions (v0.1)

Record of decisions and their rationale. Change a decision → add an entry,
don't rewrite history.

## D1. Three documents, not one
Contract (what must be true) / Implementation Candidate (what the planner
proposes) / Plan IR (how to execute). The separation *is* the thesis:
probabilistic proposal, deterministic verification, sealed execution.

## D2. Schema over syntax
The language is semantics + verifier, not grammar. Machine format is
JSON/YAML validated by JSON Schema; humans get rendered views. A custom
grammar is a v1+ luxury, and agents emit JSON more reliably than any DSL.

## D3. Typed scalars with units
`duration`, `money(currency)`, `percent`, `bytes`, `protocol`, `bool`,
`number`, `string`, `list`. Comparisons across kinds (or currencies) are
refused → verdict `unverifiable`. This catches a whole class of LLM emission
errors at the type level. No coercion, ever.

## D4. Closed operator set, no expression language
`equals, not-equals, lte, gte, in, not-in, exists, absent, compatible-with,
subset-of`. Complexity is expressed as multiple constraints, not one clever
expression. Expressions are where HCL's analyzability died.

## D5. Provenance as a value type
`declared | inferred | assumed | unknown` + source + confidence. Verdicts
propagate the basis they rest on, so policy can gate on "satisfied, but on an
assumed value". This is the core adaptation to probabilistic authorship.

## D6. Four-valued verdicts
`satisfied | violated | unknown | unverifiable`. `unknown` ≠ `violated`:
the first means "not proven", the second "proven false". Hard constraints
block on both. The system must never collapse unknown into a boolean.

## D7. Constraints declare their verification method
`static | provider-api | probe`. An RTO ≤ 30m constraint is *honest*: it can
only ever be `unknown` until a restore test measures it. This prevents
confidence theater at the schema level.

## D8. capability.requirements are sugar for hard constraints
Normalized at load into `req-<cap>-<path>` constraints. One evaluation path
in the verifier, no special cases.

## D9. Conformance suite defines semantics
`conformance/cases/*.yaml` is the language-independent definition of behavior.
The Python implementation is a *reference*, not the source of truth. The Go
runtime must pass the identical suite.

## D10. Vertical slice strategy
Four capability types, one provider first (GCP), full loop before breadth.
The vocabulary file per capability type is the real type system and the
place where 20 years of ops experience is the moat: deciding which
attributes are capability semantics vs implementation noise.

## D11. Stable IDs everywhere
Constraints, capabilities, assumptions, outcomes. Future approvals, comments,
selective invalidation and the decision ledger all hang off these IDs.

## D12. Environment constraints (meta)
Reference implementation is Python (stdlib + PyYAML) because the initial
development sandbox had no Go toolchain and no network. This is consistent
with spec-first: the conformance suite makes the Go port mechanical.

## Open questions
- **Authoring-boundary trust & authority model** (raised 2026-07-13; design
  track, consult in flight). Execution is hardened, but everything LEFT of a
  sealed contract/candidate — the proposing agent, the voice track, the
  multi-agent consult — is where context poisoning lands. Two threats: (A) a
  careless/malicious natural-language input ("let it all go to hell!" from a
  non-technical person) steering an agent toward a destructive proposal; (B) no
  formal authority model for agent "discussions" — today one agent synthesizes
  advisors (two independent reviewers) and holds the deciding vote, a single point of
  poisoning with no vote-weighting, no who-said-what provenance, no enforced
  escalation of disagreement. The stance is settled even if the mechanism is
  not: authority lives in the deterministic artifacts + typed human consent,
  NEVER in anyone's context or vote; a poisoned proposal is bounded by the
  consent gates + least-privilege + sealed-plan hash + anchored ledger, not by
  assuming proposals are clean; natural language must never become a mutation
  without passing through a typed contract + consent. To design: a voice
  taxonomy (advisory | machine-deciding | human-deciding — no advisory output
  ever mutates), proposal/decision provenance extending D74 authorship into the
  ledger, and a disagreement-escalation rule (advisor conflict on an
  irreversible decision MUST surface to a human). Candidate future Dxx +
  threat-model spec doc; parts buildable now (authorship on proposals,
  escalation rule), parts genuine research (agent-layer poisoning defenses).
- Canonicalization rules for hashing contracts/candidates (key order, unit
  normalization) — needed before Sealed Plan IR.
- Should `budget` remain a separate block or fold into `constraints.hard`?
  (Currently sugar with severity default hard.)
- Vocabulary governance: how do community PRs extend vocab without breaking
  verification? Likely: vocab versioning + `unknown_path` verdict flag.
- How does a candidate carry implementation detail (`implementation:` block)
  that the verifier ignores but the compiler consumes? *(resolved: D26)*

## D13. Working name: Groundhold
Rationale: a "ground hold" is how firmly an anchor holds the seabed — the
thesis in a word. Evidence HELD to observed reality, loose ends tied off,
claims grounded in what is actually true. Coined and distinctive (cleared
against package registries, handles, and domains — not a common descriptive
word). CLI `groundhold`, schema URIs `groundhold://`. Brand decision
(working name vs. registered mark) settles at trademark clearance; the spec
name and the company name need not be the same.

## D14. Membership operators refuse incomparable operands
`in`, `not-in`, `subset-of` follow the no-coercion rule (D3): if no element
of the list is comparable with the tested value (same kind; same currency
for money), the verdict is `unverifiable`, never a silent false. Mixed-kind
lists are allowed as long as at least one comparable element exists; an
empty list is degenerate and therefore unverifiable. Closes a hole where a
duration tested against a list of numbers came back `violated` ("proven
false") for what is really a typing error in one of the documents.

## D15. Byte units follow IEC/SI
`KiB/MiB/GiB/TiB` are 1024-based, `KB/MB/GB/TB` are 1000-based. Decided
before any contract uses bytes, so the change is free; pinned by
conformance so the Go port cannot diverge. (The initial reference
implementation used 1024 under SI names — the classic trap.)

## D16. Objectives with no observed value are unknown
An objective (`minimize`/`maximize`) whose path is not declared by the
candidate yields `unknown`, not `satisfied` — there is nothing to score.
Objectives stay soft, so this never blocks; it just stops the report from
claiming an observation it does not have.

## D17. Candidates bind to contracts by id
`verify` checks `candidate.contract` against the contract id; a mismatch
is a blocking reason (executable: false) while still producing the full
verdict list for diagnosis. Version + hash pinning arrives with Sealed
Plan IR (canonicalization is a prerequisite).

## D18. Verify twice: candidate claims, then compiled artifact
Verdicts over a candidate prove consistency of the *declaration* with the
contract — not properties of infrastructure. The candidate is a self-report
by a probabilistic author. The compiler must therefore re-derive capability
attributes from its own output (`.tf.json`, via the vocabulary mappings)
and run verification again on the derived attributes. Claim-check before
compilation, artifact-check after it, probes after deploy. Without the
middle check, confidence theater does not disappear — it moves one level
down, from HCL into candidate YAML.

## D19. Structural validity is fail-fast
Loading parses constraint values eagerly: an ill-typed value in the
contract itself is a `ContractError`, not a runtime verdict. `unverifiable`
is reserved for contract↔candidate mismatches discovered during
verification. Invalid severity, dangling references, out-of-range
confidence: all load errors. Fail-open defaults are forbidden — anything
the loader does not recognize is refused, not silently non-gating.
(Recorded now; the eager value parse lands with the loader rework.)

## D20. On conflict, loader + conformance suite win over the JSON Schema
The reference loader enforces validity and the suite pins it (D9). The
JSON Schema is a projection for editors and tooling, currently unenforced
(no jsonschema dependency allowed); where they disagree, the schema is
the bug and gets fixed to match.

## D21. Lists are sequences
`equals` on lists compares position by position — `[a, b]` does not equal
`[b, a]`. Set semantics are expressed explicitly with `subset-of` (in both
directions if equality-as-sets is meant). Silent set-coercion would be
another flavor of the coercion D3 forbids.

## D22. Conformance binds to the CLI, not to a library
The runner drives any implementation through its command line
(`--impl "<cmd>"`): `<cmd> verify <contract> <candidate> --json`. Frozen
by the suite: the JSON report shape, exit codes (0 executable,
1 structural error, 2 not executable) and the stderr prefixes
`contract error:` / `candidate error:` for load rejections. This is what
makes a port verifiable on its own binary — same cases, same interface,
no shared code with the reference.

## D23. The vocabulary is an optional, strengthening input
Vocabularies are versioned documents passed in explicitly (`--vocab <dir>`,
a `vocab:` block in a conformance case) — never hardcoded knowledge.
Without one, loading and verification behave exactly as before. With one:
candidate values on vocabulary paths are kind- and enum-checked at load
(fail-fast, D19), and every verdict carries `pathInVocabulary` so policy
can gate on constraints that stepped outside the type system. Paths
outside the vocabulary stay legal — rejecting them would close the door
on extension vocabularies before the governance model exists (open
question). With no vocabulary for a capability type, the flag is null:
no claim either way, consistent with D6.

## D24. Go starts at the compiler, not at the end
The original roadmap ported everything to Go last — meaning compiler,
Sealed Plan IR and probes would be written twice. Reordered: the Python
verifier stays as the reference (two independent implementations passing
one suite is the strongest proof that semantics live in the cases, D9);
the Go verifier is ported next as the skeleton of the Go codebase,
measured by the existing `conformance-cli`; everything from the compiler
onward is born in Go and written once. Canonicalization and hashing in
particular must have a single birthplace — byte-identical hashes across
two languages are a classic divergence trap, and the Sealed Plan hash is
the heart of production trust. Prerequisite: canonicalization rules
decided before the Go compiler work begins.

## D25. Equality is canonical, not lexical
`equals` and the membership operators compare canonical values, so `[5m]`
equals `[300s]` inside a list exactly as `5m` equals `300s` outside one.
Found by the Go port: the Python reference compared list elements as whole
Scalar dataclasses (raw spelling included), making equality depend on
notation — but only inside lists. Exactly the class of unpinned divergence
a second implementation exists to surface (D9, D24).

## D26. The candidate `implementation:` block is free-form
Provider detail (tiers, disk types, flags) rides in an unstructured
`implementation:` object per capability: the verifier ignores it, the
compiler consumes it. No schema is imposed before the compiler exists —
and D18 already guarantees the block is never the source of truth, since
the compiler re-derives capability attributes from its own output.
Resolves the open question from v0.1; specified in
`spec/candidate.schema.json`. Tightened while specifying: a candidate
must declare `apiVersion` and name its `contract` at load time.

## D27. State is three separated concerns, none of them a snapshot
(D27–D33 shaped by team brainstorm + external design review, 2026-07-11.)
No mutable state file. Instead: (a) a **decision ledger** — append-only,
content-addressed log of events (contract published, candidate verified,
plan sealed, apply start/end, probe outcomes, violations); (b) **bindings**
— capability-id → provider resource identity plus lineage (account/
project/region, generation, aliases for renames, tombstones, partial/
adopted/deposed resources) but never an attribute cache; (c)
**observations** — facts about the world with timestamp + TTL. A stale
observation degrades the verdict to `unknown`, which blocks hard
constraints: freshness is part of the type system, and drift is "contract
violation detected", not "state mismatch". Attributes are re-derived from
provider APIs; what cannot be re-read later is captured as an observation
or operation receipt at write time, never as trusted cache.

## D28. Optimistic concurrency; a sealed plan pins its full read-set
No global locks — Terraform's whole-state-file lock is the anti-pattern.
A sealed plan pins everything it *read*, not just what it mutates:
contract hash, candidate hash, ledger heads for affected capability ids,
vocabulary versions, compiler version, pricing catalog version, provider
identity (account/project/region/role). Apply is a CAS: execute only if
those heads are unchanged; otherwise the plan is invalidated — re-verify,
re-seal. Nobody holds a lock while thinking.

## D29. Execution leases carry fencing tokens; operations get receipts
Mutation requires a short lease per capability-id (TTL + heartbeat,
auto-expiry, breakable with an audit event). TTL alone is unsafe: a paused
process can lose its lease, resume, and append a stale "apply succeeded".
Every lease issues a monotonically increasing fencing token; every ledger
append and binding update rejects stale tokens. Cloud operations outlive
processes, so every provider mutation records an **operation receipt**
(provider operation id, idempotency key, target, status) — and breaking a
lease REQUIRES reconciling in-flight operations first.

## D30. Groundhold is gated apply + continuous re-verification, not a reconciler
Explicitly not a Crossplane-style controller loop fighting for ownership.
Execution is sealed and gated; afterwards probes re-verify outcomes
continuously, and a violation is a ledger event that policy responds to
(per the contract's autonomy block). Choosing one semantics keeps the
state layer honest; a reconciliation mode, if ever, is a separate layer.

## D31. The ledger is an interface; git is a mirror, never the substrate
Backend semantics are the spec: `append(event, expected_heads,
idempotency_key) → new_heads`, `query(...)`, `current_heads(keys)`.
Git is acceptable as an append-only mirror and human review surface, but
not as the concurrency substrate — no conditional append, awkward leases,
force-push becomes a correctness concern. Any backend (including a git
one) must obey the interface semantics; git does not get to shape them.

## D32. `unknown` blocks execution; remediation needs an explicit carve-out
If observations are stale because a provider API is down, a plan that
would *restore* encryption must not be blocked by the same rule that
blocks a risky change. Policy semantics: `unknown` blocks normal
execution; it MAY permit narrowly-scoped remediation that monotonically
reduces risk; it NEVER permits destructive or exposure-increasing changes.
The carve-out is policy, evaluated deterministically — not a verifier
exception (D6 stands).

## D33. Risk is multi-dimensional; reversibility is one axis
R0–R4 reversibility is not blast radius. A sealed plan carries independent
risk dimensions: reversibility, data loss, downtime, security exposure,
cost delta, resource identity replacement. Autonomy policy and lease
strictness gate on the vector, not on a single scalar.

## D34. Identity is the hash of the semantic model
`sha256` over domain-separated canonical JSON of the *parsed model* — not
source bytes (spec/canonicalization.md). `5m` and `300s` hash identically:
D25 extended from equality to identity. Constraints, capabilities and
attributes sort by their stable ids (D11), so reordering a document does
not change what it is; requirements sugar normalizes before hashing (D8),
so sugar and its explicit form are the same contract. All numbers render
as strings (shortest fixed-point round-trip) — cross-language float
formatting is the classic divergence trap, and the whole point is that
two implementations produce byte-identical hashes. Domain registry:
`groundhold/canon/v1:{contract,candidate,plan,event,observation,binding,report}`.

## D35. State Model v0: events are records, not specifications
Concrete v0 shapes for D27–D33 live in spec/state-model.md and
spec/state.schema.json. Three decisions worth naming: (1) **the ledger is
the only write path** — bindings and lease status are projections of
events, there is no second mutable store. (2) **Event identity hashes the
raw canonical tree** with NO semantic normalization, unlike contracts
(D34): a contract states meaning, so identity follows meaning; an event
records what was said, and normalizing history would falsify it.
(3) **Fencing tokens derive from ledger history** (max prior token per
capability + 1), so any replica validates a mutation without a
coordinator. Event types are a closed, fail-closed registry (D19).

## D36. Sealed Plan IR v0: a plan is a decision record
spec/sealed-plan.md. A sealed plan pins its FULL read-set (D28) —
contract/candidate hashes, ledger heads, toolchain and vocabulary
versions, provider identity — and **writes ⊆ pinned heads**: you cannot
write what you did not read. Actions form an acyclic dependency graph
with per-action idempotency keys (D29) and the D33 risk vector.
Preconditions are a closed registry and MUST include
`report-executable` — a plan that does not require verification to pass
contradicts the thesis. Plan identity hashes the raw canonical tree
(like events, D35): a sealed plan records a decision; normalizing it
would re-open it. The plan carries no timestamp — sealing is recorded
by the `plan.sealed` ledger event.

## D37. Concurrency semantics are conformance-tested, deterministically
The ledger/lease/fencing rules of D28–D29 are pinned by scenario cases
(conformance/cases/concurrency.yaml) run by a deterministic engine with a
logical clock — no wall time, no threads; concurrency is modeled as
interleaved steps, so every race is reproducible. Both implementations
ship the engine (`groundhold scenario`), and the future apply runtime must
obey the same rules: stale-plan rejection, fencing and receipt
reconciliation are spec, not runtime plumbing. Statuses distinguish
`conflict` (CAS mismatch — the mechanism working) from `rejected`
(rule violation); collapsing them would hide which safety layer fired.

## D38. Differential testing: the implementations must be indistinguishable
`make differential` (conformance/differential.py) generates seeded random
contracts, candidates, events, plans and concurrency scenarios and drives
both implementations through their CLIs: byte-identical hashes, equal
exit codes, equal verification reports and scenario results. Two fields
are presentation, not semantics, and are excluded: `reason` and
`observed`. Everything else diverging is a bug in one of the runtimes or
a hole in the spec. Conformance cases pin known behaviors; differential
testing hunts unknown ones — D25 was found by hand, this finds its
siblings wholesale. Known blind spot: YAML re-serialization sorts mapping
keys, so document-order-dependent behavior is not exercised.

## D39. Standalone runtime: no coupling to external IaC toolchains
The compiler targets the Sealed Plan IR (D36), not Terraform; the
executor will speak provider APIs directly. `.tf.json` is demoted from
compiler output to an optional export format for interop and review —
never on the execution path. Rationale: Terraform-as-executor would
reintroduce the mutable state file Groundhold exists to eliminate (the
ephemeral-state-from-bindings bridge was considered and rejected), add
version coupling to provider plugins, and put a second source of truth
between the sealed plan and reality. Bindings + ledger + receipts
(D27–D29) already carry everything an executor needs. The dependency
discipline extends down: two YAML libraries are the only third-party
code in both runtimes, and it stays that way.

## D40. Forecast: the preview stage is a deterministic prediction
(D40–D41 shaped by brainstorm + external design review, 2026-07-11.)
The plan/preview/dry-run equivalent is `forecast` — a PURE function:
(sealed plan, candidate hash-checked against reads.candidateHash,
bindings, observations, decision heads, evaluationTime) → predicted
effects per action. Terraform conflates permission, diff, freshness and
execution into one command; Groundhold keeps them separate — verify answers
"allowed?", forecast answers "what would change?", CAS answers "still
current?". Effects are a closed set (`will-create | will-update |
will-replace | will-delete | will-adopt | no-effect | unknown |
unforecastable | stale-plan`) with a separately versioned registry of
unknown-reason codes (provider-computed, provider-defaulted, stale
observation, cross-resource-effect, ...) — "known after apply" made
systematic and explained. evaluationTime is an explicit input: TTL
freshness must not read the wall clock. `observe` is the only step that
touches the network and only emits Observation documents; a future
`preview --refresh` is a documented composition of observe + forecast,
never a new semantic phase. Name deliberately signals epistemic
humility; docs say "deterministic forecast from declared inputs" —
`preflight` stays reserved for provider validate-only checks inside
apply. spec/forecast.md is normative.

## D41. Knowledge and coordination do not invalidate decisions
Found in review: `observation.recorded` advanced capability heads, so
learning something about the world after sealing a plan made the plan
stale — absurd. Ledger events partition into **decisions**
(contract.published, candidate.verified, plan.sealed, binding.updated,
apply.*), **knowledge** (observation.recorded, violation.detected,
operation.receipt) and **coordination** (lease.*). Sealed plans pin and
apply/forecast CAS-check the DECISION heads; knowledge and coordination
events stay in the audit chain (full heads, append-level CAS) but do not
invalidate anyone's plan. Fresh observations feed the forecast; material
world changes are the business of preconditions and policy (D32), not of
CAS. The fencing set (D29) is unchanged.

## D42. Executor v0: one rules implementation, write-ahead intent
(Shaped by brainstorm + external design review, 2026-07-11.)
The apply engine and the D37 scenario engine drive the SAME rules code
(internal/ledger) — what the conformance scenarios pin is what apply
obeys. Apply is refuse-before-mutate (spec/executor.md): read-set
identity, re-verified preconditions (non-evaluable ones refuse,
fail-closed), the v0 create-only limit, pending-receipt reconciliation
and a decision-heads CAS that is re-checked under the lease. Execution
follows write-ahead discipline: the pending operation.receipt is durable
BEFORE the provider call, so every crash point leaves reconstructable
intent; every apply-scoped event carries applyRunId derived from
(planHash, evaluationTime). Bindings are written per action as FULL
projections — one-binding-at-the-end would recreate Terraform's worst
partial-apply ambiguity. Exit codes: 3 = stale/conflict (re-seal),
4 = failed mid-flight, 5 = corrupted ledger — automation pages
differently for "bad plan" and "history cannot be trusted". Known,
deliberate v0 limits: caller-supplied evaluation time also drives lease
liveness (a real backend must issue its own coordination clock), the
JSONL ledger is single-writer with flock+fsync, resume is refusal-only.
Replay validators are versioned per event apiVersion — never re-judge
history with today's code.

## D43. GCP driver: pure mapping core, narrow auth, refuse what you cannot honor
(Shaped by brainstorm + external design review with live doc checks,
2026-07-11.) The Cloud SQL driver keeps D39's discipline — plain REST,
stdlib-only RS256 auth as a deliberately NARROW adapter (service-account
keys and metadata server; explicitly not ADC, no gcloud shell-out).
Request building is a pure function pinned by golden tests; the network
shell is httptest-covered. Idempotency = deterministic instance names
from (project, environment, capability) — never candidateHash; ownership
labels at creation; 409 is idempotent continuation ONLY when labels
match, because binding someone else's database is a decision, not a
conflict handler. The mapping rule: a semantic attribute the driver
cannot honor REFUSES in preflight (multi-regional, unencrypted, unknown
paths, publicExposure=false without an explicit prepared private-network
link) — silently dropping an attribute that satisfied a constraint would
fake compliance. DONE is not success (the error field decides); lost
responses and poll timeouts are `unknown` with the real operation name
for reconciliation. Review also fixed the provider interface: unknown is
a first-class CreateResult status, and receipts pair by intent id with
the provider's real operation name in the terminal body.

## D44. Observe: facts carry their derivation; never fabricate a measurement from intent
(Shaped by brainstorm + external design review, 2026-07-11.) `groundhold
observe` reads BOUND resources (bindings from ledger replay or a file —
observe only what we own; discovery is a future explicit mode and never
auto-binds) and reverse-maps provider responses to semantic attributes
through a PURE function pinned by golden tests. Honesty rules: absent
fields emit NOTHING, never a zero-value default; unknown enums skip the
path with a diagnostic; Observations gain a `derivation` field
(`config-intent | measured`) mirroring candidate provenance (D5), so
policy can distinguish evidence quality. `network.publicExposure=false`
requires BOTH config intent (ipv4 disabled, no authorized networks, no
Data API exposure) AND observed state (no PRIMARY address) — either
surface saying "exposed" wins. `recovery.rpo` is emitted only where
honestly derivable (daily backups without PITR → 24h worst case,
config-intent); PITR implies a better RPO but its VALUE is a probe's
job — a diagnostic says so instead. One `observation.recorded` event per
capability per run (knowledge events, decision-head-neutral per D41).
TTLs are layered: per-source defaults, slow for immutable-ish facts,
fast for security posture, with a blunt override flag. Review also
canonicalized providerId as `project:region:name` — the driver had two
formats.

## D45. Forecast consumes observations; predictions are four-valued
(Shaped by brainstorm + external design review, 2026-07-11.) Attribute
predictions form a closed set — `match | differ | unknown |
unverifiable` — the D3/D6 discipline reappearing at prediction level:
a kind mismatch between desired and observed is unverifiable (differ
would be false precision, unknown would lose the distinction).
Comparison is canonical scalar equality (D25), no ad hoc comparison
modes. Freshness degrades stale observations to
unknown/stale-observation; derivation (D44) is carried through, never
gated on — config-intent may produce match, and whether that evidence
suffices is policy's call. Effect of `create` on a BOUND capability is
`no-effect`: the executor would 409-continue and change nothing, so
that is the honest forecast OF THE ACTION — drift is attribute-level
information made loud in rollups, not a new effect status (the closed
set stays closed). When observations compete for a path, newer
observedAt wins; on a tie, measured beats config-intent. The ledger
gains Observations and BoundProviderIDs projections — apply writes,
observe records, forecast reads: one file, whole loop.

## D46. Update: reviewed change-sets, transition-dependent mutability
(Shaped by brainstorm + external design review, 2026-07-11.) The
compiler classifies bound capabilities against FRESH observations — the
staleness gate lives at compile time, because sealing a change-set
derived from stale knowledge contradicts the read-set's honesty (D28):
missing, stale or incomparable observations refuse with "re-observe
first", never guess. An update action carries an explicit
`changes: [{path, from, to, caveat?}]` list — a sealed plan is a
decision record (D36), so the change-set is reviewable; from/to are
denormalized audit fields, and the patch source of truth stays the
hash-pinned candidate scoped by path. Mutability is TRANSITION-dependent
provider knowledge: `ClassifyChange(path, current, desired, impl) →
mutable | immutable | unsupported | caveated` (removing public exposure
needs a prepared network; adding it does not). Refusals: converged world
→ "nothing to change" (a plan exists to change things — no noop-only
plans); immutable drift → a replacement diagnosis, never a paper
will-replace plan (replace lands with retirement/tombstone semantics).
One update action per capability with max-risk aggregation (downtime:
possible — Cloud SQL patches can restart). The GCP patch is built pure:
only changed paths, nested objects merged from the CURRENT instance so
siblings survive, settings.settingsVersion pinned — a version conflict
is a provider-side concurrent change ("re-observe and re-seal"), never a
blind retry. Ownership labels re-checked before every patch. Binding
generation increments on update; identity survives.

## D47. Retirement is explicit; deletes pin their target; autonomy gates in the executor
(Shaped by brainstorm + external design review, 2026-07-11.)
Terraform's absence-means-destroy is the footgun this design refuses: a
capability retires by declaring `state: retired` in the versioned,
hash-pinned contract — reviewed like any other change, kept until
tombstoned everywhere (removal later is metadata cleanup, never destroy
intent). Contradictions load-fail: retired + requirements, constraints
targeting retired capabilities. Statefulness is vocabulary knowledge
(`stateful: true`) and FAILS CLOSED — an absent vocabulary cannot prove
statelessness. The `autonomy.forbidden delete_stateful` bezpiecznik from
the very first example contract is finally live, at BOTH layers: the
compiler refuses to seal, and the executor gates unconditionally against
the pinned contract — a hand-authored plan cannot bypass policy. Delete
actions pin the exact identity they destroy (`targetProviderId` +
`targetGeneration`), and apply compares against the current binding — a
rebind between seal and apply cannot redirect a delete. Tombstones are
structured (`{providerId, resourceType, generation, deletedAt,
deletionOperationId}`), appended to lineage, and the capability becomes
unbound-with-history. GCP: `deletionProtectionEnabled` defaults ON
(databases are stateful; opting out is a reviewed, hash-pinned
`implementation.deletion_protection: false`), and delete REFUSES while
protection is on — lifting it is an explicit prior step, never
auto-disabled. Delete risk: R4, dataLoss certain when stateful, downtime
certain, identityReplacement true. Replace stays a reserved operation:
create-before-destroy will be a plan-level composition (create new
generation + delete old with dependsOn), pending a name-generation
discriminator. Retention modes (retain, final-backup-then-delete) are
named and deferred — never hidden in provider defaults.

## D48. Replace is a composition; stateful replacement needs scoped consent
(Shaped by brainstorm + external design review, 2026-07-11.)
Create-before-destroy lives in the EXISTING action DAG: immutable drift
compiles to a-create-<cap>-gN+1 plus a-delete-<cap>-gN with dependsOn —
the atomic `replace` operation stays reserved, no new executor
semantics. The replacement create names WHAT it replaces and WHY
(`replaces: {providerId, generation, because: [immutable from/to]}`) —
reviewers see the reason, never a bare create/delete pair. Names gain a
generation discriminator only from g2 up (`slug-gN-hash(…|gN)`), so
generation 1 keeps every existing binding valid and old/new instances
coexist; the slug truncates under the 98-char limit, never the
uniqueness suffix. STATEFUL replacement requires explicit, scoped,
hash-pinned contract consent (`autonomy.allow_replace_stateful: [cap]`)
— risk vectors screaming dataLoss certain is not enough; a region typo
must not quietly propose "create empty DB, delete old DB" (data
migration is out of scope; the successor is EMPTY and the plan says so).
The consent gate is enforced at compile AND unconditionally in the
executor. Delete legs act on the PINNED identity, never the binding
projection — which the replacement-create in the same run has already
moved; the post-delete binding keeps the survivor and tombstones the old
resource, with lineage.replaces on the successor. Delete receipts carry
targetProviderId/targetGeneration so a failed replacement-delete leaves
the orphan DISCOVERABLE (a full deposed-resource projection is future
work). Cutover between the legs is the application's concern in v0; a
future health/cutover step is an explicit inserted action, not hidden
delete semantics.

## D49. The authoring boundary is productive, not hidden
(Shaped by brainstorm + external design review, 2026-07-11, triggered by
the founder's "seriously, 4-5 files for one database?".) Groundhold's files
have different OWNERS and lifecycles — intent, proposal, sealed
decision, runtime evidence, vocabulary — which is conceptually better
than Terraform's "it's all the program", but felt heavy because a human
was hand-authoring across the ownership boundary. The fix is division
of labor, not fewer concepts: the human writes/reviews the CONTRACT
(one file, top of the repo); the AGENT emits the candidate (the
emission skill); the runtime emits plan/ledger/observations (workdir
convention: generated artifacts live in a .groundhold/-style directory);
porcelain stitches the lifecycle. Multi-document YAML was considered
and REJECTED: one file would mean the agent rewrites the human's file
on every re-emission and review diffs would mix intent with proposal.
The agent MAY draft contracts from prose — a contract is not sacred
because a human typed it; it is sacred because it is the reviewed
authority: the agent proposes, the human publishes. A future porcelain
verb must never hide: verifier refusals, unknown/unverifiable on hard
constraints, stale observations, the full risk vector, delete target
identities, stateful consents, CAS conflicts, pending receipts — and
`--yes` only skips prompts for already-permitted actions, NEVER
supplies missing consent (the terraform -auto-approve cautionary tale).
The emission skill's never-list: no HCL; never weaken constraints to
make verification pass; never add destructive consents; never convert
unknown into assumed; never silently pick weaker
security/residency/recovery or higher cost; never mutate the human's
contract while regenerating a candidate; never auto-bind.

## D50. MCP: the lifecycle as gated tools; apply is a structural two-step
(Shaped by brainstorm + external design review, 2026-07-11.) The MCP
server is a THIN adapter over the D22-frozen CLI protocol — stdlib-only
JSON-RPC over stdio, isolated in one package, explicit protocol version,
fail-closed on unknown required fields, golden transcript tests; no
dependency until protocol drift becomes real. Tools map 1:1 to plumbing
(verify/plan/forecast/observe/hash); a converge tool arrives only after
the porcelain exists and is trusted. Inline YAML is DRAFT-ONLY: it
materializes under the workdir and returns {path, hash, draft: true} —
nothing seals or applies from inline content. Apply is read-only by
default (GROUNDHOLD_MCP_ALLOW_APPLY gates its existence) and structurally
two-step: the first call returns confirmation_required with the plan
hash, risk vectors, delete targets and a short-lived single-use token;
the second call must present that token with the SAME plan hash. The
token proves a human saw this exact sealed decision — it never supplies
missing consent, and the executor gates stay authoritative. MCP client
prompts are OUTSIDE Groundhold's trust boundary and are never relied on.
Forward plan (order): MCP → converge porcelain → brownfield onboarding
(observe → draft-intent-INFERRED-from-reality with observed-not-intent
markers — reality is the first author, never the authority; adopt
bindings, converge-as-no-op proves takeover) → terraform/pulumi import
(tfstate = adoption hints + observations, NEVER a contract) → ledger
exporters (violation.detected → alerting, apply/delete → SIEM audit;
pulled ahead of identity vocab because they prove ledger-as-event-source
cheaply) → identity capability types (SSO/SAML/OAuth) → voice track
(whisper → draft-contract; a mind-changing narrator is just another
probabilistic author, and later statements supersede earlier ones).

## D51. Converge: the porcelain verb — hides keystrokes, never information
One verb stitches verify → plan → forecast → confirm → apply → observe →
convergence check over the D22-frozen protocol by exec'ing our own
binary; no lifecycle logic is duplicated and every child refusal passes
through verbatim with its exit code (refused/stale/failed/corrupted).
Three porcelain semantics, inherited from the D49/D50 consultations:
(1) "nothing to change" is SUCCESS for converge (exit 0, "converged") —
the plumbing refuses to seal a no-op plan, but a converged world is the
porcelain's goal, not an error. (2) The staleness refusal is woven, not
surfaced: observe is read-only (L2, D40), so converge may run it and
re-plan exactly once before giving up. (3) Double friction for
destruction: --yes skips prompts for already-permitted actions only; a
plan carrying dataLoss=certain or identityReplacement additionally
requires --allow-data-loss (non-interactive) or typing "delete"
(interactive) — while contract consents keep gating below, at compile
AND apply. --json is non-interactive by definition: the confirm gate
refuses rather than prompting into a JSON stream. After apply, converge
records observations and re-plans as a best-effort convergence proof:
"converged — verified against observed reality" when the second compile
says nothing-to-change; honest "inconclusive" when observations do not
cover every attribute. Pinned by conformance/cases/converge.yaml
(multi-run cases: the second run proves convergence against the ledger
the first one wrote, instead of hand-forging event hash chains).

## D52. Brownfield onboarding: reality is the first author, never the authority
(Shaped by external design review, 2026-07-12; spec/onboarding.md.)
Four phases. DISCOVER: read-only enumeration via an optional driver
capability (Discoverer.List), reverse-mapped through the same pure
observation mapping Observe uses, emitting a DiscoveryDocument with a
canonical hash (domain groundhold/canon/v1:discovery, raw tree like events
— it records what enumeration SAW; pinned cross-language). DRAFT
(authoring boundary, D49): reality-derived constraints carry
observed-not-intent assumption markers citing the discovery hash; a
human resolves every marker — confirmed intent or deleted accident.
ADOPT: a deterministic gate that mutates the ledger, never the cloud —
candidate must verify executable; every declared attribute needs a LIVE
observation that agrees under no-coercion equals (differing,
unobservable or incomparable each refuse: adoption must not lie, and
unknown never passes as a match); no double adoption in either
direction; then, under a lease, binding.updated with the SAME body
shape apply writes plus origin: "adopted" and an optional
adoptedFromDiscoveryHash — a field, not a new event type: adoption is a
binding mutation and projections must not care who bound a capability.
PROVE: converge must report "converged" without executing anything; an
adoption without the no-op proof is a binding, not a takeover. Review
verdicts folded in: no confirmation prompt (ledger-only mutation behind
strict gates, and reversible); UNADOPT added as the eraser — removes
the binding (resources [], prior identity recorded verbatim), never the
resource, in contrast to D47 retirement; hard refuse over any
--tolerate-drift (binding to something known not to satisfy the
contract poisons ownership); adopted names are opaque — replacement
names derive from (project, environment, capability, generation), so a
foreign -gN is never parsed as lineage. Terraform/pulumi import builds
on top later: state files parse into adoption HINTS (mapping
suggestions + expected attributes), never a contract — state stores
normalized, coerced, provider-defaulted values; semantics break before
ID mappings do, and live observations win every disagreement.

## D53. State import: terraform/pulumi state parses into hints, never a contract
(spec/onboarding.md §import; shaped by the D52 external review's trap
list.) `groundhold hints <state-file>` is a PURE translation — no cloud
calls, no ledger writes — of terraform state v4 or a pulumi checkpoint
into an AdoptionHints document: per resource the tf address / pulumi
URN, a suggested vocabulary type, the canonical providerId for adopt
--map, and `expected` attributes. The label is "expected", not
"observed": state stores normalized, coerced, provider-defaulted
values, so hint values carry no derivation claim and exist to be
verified against live discovery — the observation is the authority, the
hint is the claim being audited, and every disagreement surfaces as
state drift found during migration. Values cross from state into hints
only through an explicit per-path allowlist that reuses the SAME enum
tables as the API observe mapper (one translation table, two consumers,
no drift); secrets (sql user passwords live in tfstate!) and
implementation noise (tiers, disks, flags) are structurally excluded —
pinned by a conformance golden asserting the secret never appears in
the output. Pulumi OUTPUTS feed the mapping (the last state pulumi
saw), never inputs (desires). Data sources, composite children
(google_sql_user rides along with its instance) and unmapped types
become diagnostics, never silent drops; an unrecognizable document is
an error, never a guess. deletion_protection=false in state becomes a
NOTE — Groundhold defaults protection on, and that behavior change must be
a conscious migration choice. The hints document is deliberately NOT
canonically hashed: hints are untrusted throwaway input; auditability
comes from source serial/lineage, and drafts cite the DISCOVERY hash.
Review verdicts folded in (external review, 2026-07-12): identity is
cross-checked — when state carries connection_name or self_link, they
must AGREE with the composed project:region:name; disagreement refuses
the hint with a diagnostic (a mis-seeded adoption is worse than no
suggestion, and the importer never guesses which field is right); and
the allowlist is guarded by an adversarial regression fixture — secret-
looking fields on the mapped resource itself (root_password,
server_ca_cert, psc attachments, private IPs) must never appear in the
output, so future allowlist expansion trips the wire before it leaks.
Merge-blocker list from the review, all pinned: hints never influence
adoption acceptance over live observe; non-allowlisted values never
cross; pulumi inputs never used; identity disagreement never silently
normalized; PITR/deletion-protection semantics never fabricated into
stronger guarantees.

## D54. Ledger exporters + audit: the ledger is the event source
(spec/export.md.) Two verbs. EXPORT is a deterministic, stateless fold
of the ledger to stdout — same ledger + same cursor = byte-identical
output; ndjson or CloudEvents 1.0; transport belongs to the operator
(pipe to vector/fluentbit/curl — D39: the runtime never talks to
third-party tools, so there is nothing to integrate and nothing to be
locked into). The cursor is a plain line index (the ledger is
append-only; the operator persists it); the canonical event hash rides
as the record id, so at-least-once delivery dedupes consumer-side.
CloudEvents mapping principles: source is the authority
(groundhold://<env>/ledger), never a file path; time is occurredAt
VERBATIM — decision time, never export time, because re-exporting must
not re-date history; data is the raw event — the exporter never
editorializes, consumers filter. AUDIT makes violation.detected real:
it evaluates subject constraints against RECORDED REALITY (latest
observations projection) — verify asks "does the proposal satisfy the
contract", audit asks "does the world still". Four-valued verdicts
survive: missing or stale observations are unknown (never collapsed
into satisfied — a stale fact is not a fact), incomparable ones
unverifiable. The alerting bar: hard constraints violated or unknown
count as violations, exit 2, and with --record each appends a
violation.detected knowledge event whose body is alert-complete
(constraint, severity, verdict, reason, required op+value, observed
value+time+derivation, contract id+version) — no consumer ever needs
to re-read the ledger to act. Review verdict folded in (external
review, 2026-07-12): ledger writes happen on TRANSITIONS only —
re-emitting while a violation persists would make polling frequency
ledger semantics and pile identical unresolved violations up as
duplicate facts in an append-only log. violation.detected appends when
a verdict newly fails or changes between violated and unknown;
violation.resolved (new event type, both registries) appends on return
to satisfied; the recorded alarm state is a ledger projection keyed by
(capability, constraint), and the heartbeat lives in the command
itself — exit 2 plus full verdicts on stdout, every run. Together:
observe records facts, audit judges them, export streams the
judgments — drift becomes an alert without Groundhold knowing which
alerting system exists.

## D55. Identity vocabularies: SSO and OAuth-client as capability types
(Shaped by external design review, 2026-07-12.) Two types, and
deliberately not three: SAML and OIDC are different protocols but the
SAME buyer-facing capability — federated single sign-on — so
capability.identity.sso carries federation.protocol as an attribute
(exactly the engine.protocol move from databases; splitting types would
overfit implementation detail into the taxonomy).
capability.identity.oauth-client models a client registration's attack
surface: grant types (contracts typically require grants.implicit
false), PKCE, client.authentication enum (none = public client, usually
forbidden server-side), redirect discipline (exactMatch, wildcards),
token lifetimes and asymmetric signing, refresh-token
issuance/rotation/lifetime, audience restriction, scopes.granted
constrained with subset-of against an allowlist (the list operators
finally earn their keep), secret.maxAge (semantic only where rotation is
platform-ENFORCED — a note in the vocabulary marks the probe
obligation). Both stateful: true — SSO because user/group assignments
and session continuity are state and retiring a sign-on surface locks
people out; oauth-client because issued credentials and the
registration carry revocation and continuity state (review's phrasing).
Nothing identity-specific entered the verifier: the vocabulary IS the
feature, which is the whole point of the vocabulary design. Registries
extended in both implementations + contract.schema.json; verification
pinned by dual conformance cases (green SSO contract, undeclared MFA
blocks as unknown, implicit-grant + public-client + scope-overreach
violations, enum violation refused at load). Vendor names, certificate
schedules, consent-screen text: implementation noise, deliberately
absent.

## D56. Coordination clock: writers inject time, the ledger enforces order
(Shaped by external design review, 2026-07-12.) Replay used to set the
logical clock from each event's occurredAt UNCONDITIONALLY — a
backdated event mid-history rewound the clock and could resurrect an
expired lease. The rule now: wall time is injected by writers; the
ledger enforces monotonic order. NEW appends with occurredAt behind the
ledger's maximum are rejected (writer clock skew is a coordination
conflict — refuse, never rewind); EXISTING history replays leniently
(tolerated, never re-judged, clock advances with max and never
regresses). Reject-on-append preserves the invariant going forward
without breaking a single existing ledger. Pinned by a case where an
11:00 writer is refused after a 12:00 event and a 13:00 writer is then
accepted — the refusal is about order, not about the writer.

## D57. Resume: the blessed recovery path — reconciliation never guesses
(Shaped by external design review, 2026-07-12; the review's blockers
all pinned.) After an unknown outcome, the pending receipt makes every
apply refuse (D29) — and the only unblock used to be a hand-written
lease.broken{adoptReceipts}, which is an audit trail, not a recovery
path. `groundhold resume` is the verb: for each pending receipt it asks
the provider what ACTUALLY happened via a new optional Reconciler
capability — STRICTLY READ-ONLY, a reconciler that mutates is a bug —
then writes the terminal receipt and completes the interrupted
projection: a concluded create gets its binding, a concluded delete its
tombstone, each causally linked (reconciledFrom, resumeRunId) to the
receipt it concluded. Resume is a fenced writer under its OWN lease,
never an adoption of the dead run's. still-unknown stays pending and
exits 3 — the provider's silence is not evidence. v0 concludes creates
and deletes; pending updates refuse (no verifiable target shape yet).
Not-found discipline from the review: for a create, 404 may mean
failed OR not-yet-visible — without the operation record it stays
unknown; for a delete, 404 is success ONLY because it is tied to the
receipt's pinned target. Deterministic names are part of provider
SEMANTICS now, not a GCP implementation detail: a driver whose Create
derives identity from the idempotency key can answer existence
questions long after the original response was lost. Receipts carry
operation and generation so resume can key behavior without inference.

## D58. Deposed: the orphans of failed replacements are first-class
(Shaped by external design review, 2026-07-12.) When create-before-
destroy dies between the successor's create and the predecessor's
delete, the old resource survives unbound and alive — invisible to
every projection that only reads current bindings. The deposed
computation ACCUMULATES over full history (replaced identities ever
mentioned in lineage.replaces minus identities ever tombstoned) — a
later binding-body overwrite that drops the lineage block must not
hide an orphan. `groundhold deposed --ledger` lists them; the review's
boundary is pinned: an id owned by a PENDING delete is resume's
territory, excluded from the default list (it must not invite manual
cleanup of something an outstanding reconciliation may own) and shown
by --all as status pending-delete. Cleanup stays deliberate in v0: a
future plan can compile a pinned delete for a deposed id; nothing is
cleaned automatically.

## D59. Outcome probes: claims become measurements
(Shaped by external design review, 2026-07-12.) `groundhold probe` runs
provider-side measurements that prove OUTCOMES — a connection attempt,
a restore test — through an optional Prober capability. Probe results
feed the SAME observation stream as everything else (derivation
"measured", source "probe", plus method/evidence/probeRunId metadata):
verify and audit are untouched, which was the review's first verdict —
the distinction that matters is measured-reality vs config-intent vs
claim, not probe vs non-probe. A probe crash is probe.failed (new
event type, both registries), NEVER an observation: no reality was
measured. Probes never run implicitly (not from converge, not from
observe) and intrusive ones (a restore test costs money and touches
scratch resources) run only under DOUBLE consent: the operator's
--allow-intrusive AND the contract's autonomy.allow_intrusive_probes —
a typo must not authorize a restore test. The lifecycle story that
fell out: a hard verify.method:probe constraint blocks builds — that
IS the founding thesis (you may not deploy what you cannot prove) and
it stays; the enforcement home for probe constraints is AUDIT against
measured reality, entering the contract by VERSION once the capability
is bound. Adopt's mismatch gate now skips values with provenance
"assumed" — an assumed value claims an assumption, not reality (D5);
probes prove it after adoption. Pinned end to end by
probe-closes-the-thesis-loop: adopt v1 → audit v2 alarms (rto
unknown, violation.detected) → non-intrusive probe leaves rto alone →
doubly-consented restore-test measures 35m → audit judges satisfied
and emits violation.resolved. A claim became a measurement.

## D60. Breadth vocabularies: three more type systems, zero engine changes
capability.storage.object (durability enum, retention as duration,
versioning, exposure; stateful — objects ARE the data),
capability.network.private (ingress.public, egress.restricted,
flowLogs, private interconnect; stateful — attached workloads and
addresses are continuity state), capability.workload.container
(replicas.minimum as the capacity FLOOR, signed image provenance, TLS,
exposure; the FIRST stateless: true vocabulary). Stateless finally
exercises the delete-policy branch that fail-closed defaults kept
hidden: a workload's retirement compiles a delete DESPITE
autonomy.forbidden delete_stateful, because the vocabulary proves
statelessness — pinned by a Go plan case, alongside dual verdict cases
for all three vocabularies. CPU/memory requests stayed OUT of the
workload vocabulary (capacity tuning is implementation noise; the
capacity FLOOR is availability semantics). Image digests belong to the
CANDIDATE, never the vocabulary.

## D61. Voice track: the runtime never hears the meeting
Voice is the cheapest way to AUTHOR intent; Groundhold is what makes
authored intent safe to execute. The pipeline: audio → Whisper (or a
platform transcript API) → transcript with speaker turns →
transcript-to-contract skill (facts with speaker+turn attribution;
supersession — the LAST statement wins, with authority caveats;
contradictions and gaps are findings; banter is not intent) → draft →
HUMAN REVIEW (the D49 boundary) → the normal verified path. A misheard
word can only ever produce a wrong draft that review catches, never a
wrong apply — the confirm gates (converge prompt, MCP two-step token,
--allow-data-loss) are structurally outside the transcript's reach.
Platform integrations (Zoom/Teams/Meet/Slack) reduce to one adapter
shape — produce {turns: [{speaker, at, text}]} — documented in
docs/VOICE_TRACK.md; no platform logic ever touches contracts, and
outbound notification is already generic (export → CloudEvents).
No runtime code: the entire track lives left of the authoring
boundary, in .claude/skills/transcript-to-contract.

## D62. Pre-launch review round: eleven findings, nine fixed, all pinned
A three-lens internal review (executor-side correctness, spec-implementation
consistency, quantitative inventory) before opening the code. Fixed and
pinned: (1) lease.broken{adoptReceipts} cleared pending but not
pendingBody — phantom receipts let resume re-conclude settled
operations and clobber live bindings; (2) terminal-unknown receipts
never refreshed the stored body, so resume lost providerOperation — its
PRIMARY authority — across a process restart (the only situation resume
exists for); (3) converge's verify gate was fail-open for unexpected
exit codes: a signal-killed verify subprocess let an unverified
candidate reach apply; (4) observation recency compared observedAt
LEXICOGRAPHICALLY — an RFC3339 offset form let an older observation
beat a newer one, feeding audit outdated reality; (5) a REJECTED event
advanced the coordination clock before rules ran, and commit ran before
hashing — junk appends poisoned the clock and unhashable events left
half-applied state (now: reject-check, rules, HASH, then commit+clock);
(6) adopt had no pending-receipt gate and resume's create-conclusion
overwrote bindings unconditionally — now adopt refuses over in-flight
operations and resume surfaces an ORPHANED concluded create loudly
instead of clobbering a rebound capability; (7) converge routed plan
refusals by substring over stderr that embeds user-controlled ids — a
capability named into the marker text spoofed "converged"; now the
compiler exports full sentinel texts and converge matches them as
first-line prefixes with exit-code guards; (8) converge mapped unknown
apply exit codes to refused/2 ("nothing was mutated") when a
signal-killed apply may have mutated — now failed/4; (10) importer
count/for_each instances produced duplicate addresses with
nondeterministic order — now index_key-suffixed; (11) refuse paths in
resume/probe discarded already-written events, claiming a clean ledger
that had new lines. Deferred with eyes open: (9) apply's failure path
ignores append errors after the primary failure — a persisted event can
cite an unpersisted prev hash; replay tolerates it (no prev
verification), so it is a latent audit-integrity gap scheduled with the
backend work, not a correctness hole today. Sixteen doc-drift
discrepancies from the consistency audit all corrected (stale provider
interface, forecast reason registry marked emitted-vs-reserved,
canonicalization documenting state:retired, missing schema enum
entries, README/CLAUDE counters). Inventory at review time: ~10k Go
LOC + 1.5k Python reference, 19 CLI verbs, 154 conformance cases
(97 dual / 57 Go-only), 61 prior decisions, 6 vocabularies, 4 provider
interfaces, 16 event types, 5 canonical domains, zero dependencies
beyond yaml in both implementations.

## D63. Two repos: the public one is an EXPORT, not a fork
The working repo stays private (strategy docs, session context,
integration runbooks with internal hosts, business planning); the
public repo is produced by scripts/export-public.sh — a one-way,
deterministic export with three properties. WHITELIST, never
blocklist: a path crosses only because it is named, so an internal
document cannot leak by being forgotten. STANDALONE GATE: the exported
tree must pass `make check` on its own, proving no hidden dependency
on the private tree (caught immediately that the Makefile builds the
binary from source — nothing precompiled crosses). NEGATIVE-SPACE
AUDIT: the exporter greps the result for internal markers (hosts,
project names, plan documents) and refuses to publish on any hit —
which promptly caught compiled Python bytecode embedding private
filesystem paths; build artifacts are now stripped before the audit.
The public history starts fresh at "Initial import (D62)": the private
history contains session context and internal paths and is not
sanitizable retroactively. Until launch the private repo is canonical
and exports are one-way; at launch the public repo becomes the
development repo and the private one keeps only strategy. Public tree
carries LICENSE (Apache 2.0: spec/conformance/ref) + LICENSE-runtime
(MPL 2.0: go/), CONTRIBUTING (conformance-first with the
pending-conformance ramp), GOVERNANCE (the never-relicense promise,
trademark = conformance claim), SECURITY (the no-telemetry and
consent-gate boundaries spelled out as researcher scope).

## D64. Machine error codes: one code per remediation, prose never parsed
(Shaped by external design review, 2026-07-12.) Every JSON-emitting
verb's refusal now carries `code` — a flat kebab slug from the closed
registry in spec/errors.md (numeric codes need lookup tables and make
agent traces worse; slash namespaces invite prefix parsing). The
granularity rule is the review's: one code per DISTINCT REMEDIATION —
a code answers "what should an automated caller do next", so missing
and stale observations share observation-required, and apply's
unknown outcome shares reconcile-required with the pending-receipts
refusal (both mean: run resume). Eighteen codes at launch, additive-
only with reserved semantics exactly like the event-type registry:
once published a code is never reused, never changes meaning, never
leaves conformance. `code` is the CONTRACT; `reasons[]` stays verbatim
prose and `--explain` attaches {summary, remediation} from the
registry under an explicitly non-contractual field — documented so
consumers never match on prose. Converge lifts the child verb's code
out of its JSON (childCode) so porcelain refusals stay routable.
Pinned by code expectations on the flagship refusal cases
(consent-required, confirmation-required, reconcile-required/pending,
clock-regress, binding-conflict, adoption-mismatch) and accompanied by
spec/outputs.schema.json — JSON Schema for every verb's output shape
(additive-only; unknown fields tolerated) — and CI examples
(examples/ci/) wiring verify as the PR gate and audit --explain as the
scheduled drift gate.

## D65. The deferred list, emptied: code ready means nothing left
The owner's bar: nothing deferred. Every open item from the D62/D64
rounds closed or reclassified as deliberate v0 scope. CLOSED: (1)
D62 #9 — failure-path append errors in apply now escalate to CORRUPTED
and STOP writing, because persisting event B after event A's persist
failed would put a hash in the file citing an event the file does not
contain; trailing best-effort releases (nothing appended after them)
are annotated as safe. (2) The GCP driver implements Prober — the
fourth and last optional interface: network.publicExposure by ACTUAL
TCP handshake (an allocated-but-filtered address is a probe FAILURE,
never a concluded value — the path may exist, the packet died today),
and recovery.rto by an intrusive restore-test: latest successful
backup restored into a deterministic scratch instance at the SOURCE
tier (an RTO measured on a toy tier would be a lie), timed to DONE,
rounded UP (optimism is fabrication), scratch deleted with a loud
failure entry if cleanup fails — it costs money. No backup to restore
is a failure naming the fact, never a value. (3) Replay performance is
MEASURED, not guessed: ~10 microseconds per event, linear — 1k events
15ms, 10k 115ms, 50k 481ms (BenchmarkReplay, pinned in the repo). The
file backend's comfortable range is tens of thousands of events;
snapshots (D33) activate when a deployment outgrows it. (4) Machine
codes now cover plan and verify (externally reviewed as additive-safe):
plan on exit 2 prints exactly ONE refusal object to stdout —
previously empty, so no consumer breaks, and the success document
stays self-discriminating via its top-level plan key; verify's report
carries not-executable when it blocks (dual-implemented); converge
routes on the child's stdout CODE now, retiring stderr sentinel
matching entirely. RECLASSIFIED as scope, not debt: the file+flock
backend (a deliberate extension point; protocol
designed in D27-D33) and single-driver breadth (vertical slice, D10).

## D66. Canonical numbers: JSON-safe range, identical Go/Python, restart-stable
(Adversarial pre-launch review, correctness finding C3.) The old NUMSTR
diverged: Python routed integers through float() (silently rounding
>2^53 — a coercion the invariants forbid), Go's shortest-float differed
from Python's, and Go was unstable across a JSON replay round-trip (an
in-process int hashed differently after unmarshal→float64→normalize),
producing spurious StaleDecision across restart. The differential
harness never saw it — it drew only small ints and low-precision
floats. Fix: a canonical document may not carry a number whose integral
magnitude reaches 2^53; beyond that a JSON round-trip is lossy so the
hash would depend on whether the value passed through JSON. Both
implementations refuse such a value at LOAD — a raw document integer
(docio.CheckSafeNumbers / _check_safe_numbers) OR a scalar whose parsed
magnitude crosses the line (a byte count, duration-ms, percent, money
amount — guarded in scalars.Parse) — as a structural error, never a
verdict, so the two implementations reject at the same point with the
same exit code. Fractional NUMSTR now runs the identical
shortest-fixed-point loop in both languages. This makes NUMSTR total
and deterministic on every value that survives load. The differential
generator now draws across the 2^53 boundary and sub-1e-17 floats;
pinned by dual load-error cases (raw integer, scalar percent).
Documented limit: integers ≥ 2^53 are encoded as strings (untouched by
NUMSTR). This is the reference implementation actually specifying a
determinism invariant the runtime alone could not have pinned — the
value of two implementations, exactly as D9 intended.

## D67. Lease acquisition is linearizable: the file backend is now correct under concurrency
(Adversarial pre-launch review, CRITICAL finding — confirmed four times
independently and by external design review.) The old writer held flock
only for a single line write, replayed without a lock, and validated
lease/fencing against its own stale in-memory snapshot with
expectedHeads=nil (CAS skipped) — though spec/state-model.md §1 requires
append to CAS full heads. Two concurrent apply/adopt/resume/probe
processes could both acquire the SAME fencing token, both mutate the
cloud, and then brick the ledger on the next replay (exit 5 forever, no
repair path). Fix (Writer.commitUnderLock): the persisted append now
holds a file lock across replay → rule-check against FRESH state →
token allocation from the fresh maxToken → append → fsync — never across
provider calls. Lease acquisition is thereby atomic: the second writer
re-replays under the lock, sees the winner's active lease, and is
rejected; fencing tokens are never duplicated and the ledger cannot
fork. apply reads the fresh binding projection (w.lw.Led) for the
create-before-destroy survivor, not its stale preflight snapshot.
Proven by a deterministic unit test (two writers from the same empty
replay; the second lease MUST reject — no timing dependence) and a
40-iteration concurrent stress run (0 double-applies, 0 forks, 0 bricks;
loser always refused with lease-conflict). Cost: every append now
re-replays the file under the lock — O(history) per append, ~10µs/event
(D65), so a 7-event apply over a 10k-event ledger spends ~0.8s in
replay. Acceptable for the file backend at its documented scale; it is
another reason snapshots (D33) and a real backend are the growth path.
Default replay stays fail-closed on a duplicate lease (a pre-existing
fork must not be silently tolerated after cloud mutation); a diagnostic
repair verb is future work.

## D68. The hash chain is verified, not merely written
(Adversarial review, finding C2.) `prev` was written by every writer and
read by nobody: spec/executor.md claimed "replay validates hashes,
chain" — it did not. A hand-edited, reordered or truncated line replayed
clean and silently changed the projections that gate deletes. Replay now
verifies the chain (verifyPrev): each event's prev must pin the current
head of every capability it lists; an event without prev is corruption
(the runtime always writes it). The verification immediately caught a
REAL bug it was built to catch: observe.recordEvent built its event from
a STALE in-memory ledger and wrote prev=genesis after an adopt's own
commits — forging a broken chain in every adopt. observe now goes
through the linearizable writer (D67) like everything else. Conformance
seeds are stitched by the runner (seed_ledger folds prev with the same
hash_event both implementations use), so manual seeds carry a valid
chain exactly as the runtime would write; the decision-head literals
they pin were recomputed. Boundary, stated honestly in
spec/state-model.md: an event is chain-protected once a SUCCESSOR pins
its hash, so the LAST line has no chain protection — full tail
tamper-evidence needs an external anchor (signed head/witness/co-signing
backend), which is future work and is no longer claimed as done.

## D69. Repair: diagnosis is free, the cut is consented, history is never rewritten
Closes D67's future work. A ledger that replays fail-closed — torn
line, broken chain, or a pre-D67 fork where two writers both won a
lease — needed a path back that was not "hand-edit the file". `groundhold
repair` default mode is a READ-ONLY tolerant fold: it verifies chain
and rules line by line, records every deviation as a finding (kind,
line, detail, remediation) instead of stopping at the first, reports
the longest clean prefix and a sha256 fingerprint of the exact bytes
examined. Chain verification stays meaningful past a rule-rejected
event because the file RECORDED it: its hash advances the heads its
successors pinned. `--quarantine --fingerprint <fp>` is two-step
consent (the MCP-apply pattern): under the file lock, only if the file
still matches the fingerprint the operator saw, the corrupt file is
RENAMED aside — preserved verbatim, never deleted, never rewritten —
and the original path gets the valid prefix back. The external review
question "when is keeping the prefix WORSE than starting empty?" has a
structural answer here: every action gate is freshness- or
reconciliation-gated (stale observations refuse plans, leases expire,
pending receipts block apply), so the prefix cannot authorize action
without re-observation. The one boundary that survives is stated in
the repair output itself: the restored prefix rewinds decision heads,
so plans sealed pre-corruption pass CAS again — every pre-repair
sealed plan is void, re-observe and re-seal. A forked ledger is never
patched into truth; reality is the authority, and the remediation
says discover/observe/adopt, not trust.

## D70. The tail anchor: the last line's witness lives outside the file
Closes D68's boundary. The chain protects an event once a successor
pins its hash; the last line has no successor, so dropping or
rewriting it is invisible to replay — pinned by a conformance case
that CUTS the tail and shows replay stays clean while the anchor
catches it. `groundhold anchor` emits (events: N, head: hash of line N)
plus per-capability heads; the operator stores it on a medium the
ledger's writer cannot touch. `anchor --check` verifies the ledger
still EXTENDS the anchored prefix POSITIONALLY (external review:
"current head equals anchored head somewhere" would miss
drop-and-append games; the hash must sit at exactly line N): shorter =
truncated, different hash at N = diverged, both exit 5. Deliberately
NOT claimed: events after the last anchor are unprotected until
re-anchored; an attacker who replaces both ledger and anchor wins;
the anchor is tamper-evidence, not truth — a legitimate writer can
still append false, well-formed events (signatures stay reserved).
Per-capability heads ride along as a consistency assertion only — a
mismatch with a matching positional head means an implementation bug,
never tampering.

## D71. Deposed deletes: the orphan's pin comes from history, its consent from now
Closes the session-notes deferral. `deposed` listed the orphans of
failed replacements (D58) but offered no blessed cleanup — the normal
delete action validates its pin against the CURRENT binding, and an
orphan's capability is by definition bound to its successor. `plan
--deposed` compiles one pinned delete per deposed identity: providerId
from the replaced-set, generation from a new ledger projection that
remembers what each id held when last bound (never a guess), `deposed:
true` marking the action so apply validates the pin against the FRESH
deposed projection — replaced, not tombstoned, no in-flight delete —
and refuses stale-decision otherwise. Consent mirrors replacement, in
both gates (compile AND apply): the orphan is the destroy half of a
replacement arriving late, so deleting a stateful one requires the
same scoped allow_replace_stateful — checked NOW, because consent
granted for the original replacement and revoked since must not carry
over (pinned by deposed-plan-checks-consent-now-not-then). On success
the tombstone drains the deposed list and the successor's binding
survives untouched; pending-delete ids stay resume's territory.

## D72. Updates conclude: the receipt carries what "done" means
Closes D57's v0 boundary ("a pending UPDATE has no verifiable target
shape yet") by giving it one: update receipts now pin the bound
identity (targetProviderId) and the exact desired values (changes:
[{path, to}]) from the hash-pinned candidate. Resume concludes an
update exactly as apply would have: identity survives, generation
increments, binding rewritten under the resume lease — guarded by the
fresh projection (a capability rebound while the update hung surfaces
loudly as a not-the-live-binding reason, never a clobber). The GCP
reconciler's authority ladder gains a measurement rung: operation
record when the name survived; otherwise ownership labels, then every
desired value compared against the live reverse mapping — succeeded
only when ALL are measurable and equal; a mismatch stays unknown
because a patch may still be in flight, and reconciliation never
guesses failed. Receipts written before D72 have no pin and refuse by
name (unsupported-operation, reconcile manually) — an honest edge,
pinned by resume-refuses-a-legacy-update-receipt.

## D73. Second adversarial review round: seven correctness/security fixes
Four independent reviewers (correctness, security, bad-habits,
GDPR/SOC2/ISO compliance) plus four micro-reviews swept the
D69–D72 code and the runtime around it. Confirmed and FIXED, each
pinned:
(1) **Orphaned-lease deadlock (F1, high).** commitUnderLock (D67)
re-replayed under the lock but never advanced the fresh ledger's clock
to THIS write's `--at`, so lease expiry was judged against the last
persisted `occurredAt`. A crash after `lease.acquired` before
`lease.released` deadlocked every future writer — no new event could
advance the clock past the TTL, since the acquire itself was the
rejected event, falsifying apply's "the lease expires by TTL" claim.
Fix: `fresh.Clock = w.Clock` before the rules run. (2) **Deposed delete
of a live resource (F2, high).** `Deposed()` reported "replaced, not
tombstoned" without excluding currently-bound ids, so an orphan
re-adopted (which resume explicitly recommends) still surfaced as
deposed and `plan --deposed` would seal a delete of the LIVE resource.
Fix: exclude any providerId bound under any capability; key the
generation/pending projections by (capability, id), not id alone (F7).
(3) **deletion_protection fail-open.** A non-bool `deletion_protection`
(a quoted "true", a number) dropped through `v.(bool)` to false,
silently DISABLING protection — a typo yielding the opposite of intent,
against the fail-closed invariant. Fix: a present-but-non-bool is a
structural refusal; only a real bool opts out. (4) **resume read stale
state / lost identity (F3/F4).** resume's create/delete conclusions read
the entry-time ledger, not the fresh post-append projection, so with two
pending receipts a concluded delete could clobber a just-concluded
create's binding; its delete binding also dropped the `provider` name
and prior lineage, regressing retirement's identity pinning. Fix: read
`w.Led` throughout; carry provider + lineage forward like apply.
(5) **Cross-project measurement (D72).** The update reconciler validated
ownership against the driver's project but then measured desired values
against the receipt's project component — a forged
`other-project:region:name` could redirect the read. Fix: measure
against the ownership-validated project, never the receipt's. (6)
**Unvalidated providerId in API paths.** GCP providerIds (which enter via
adopt/hints/ledger) were split and interpolated into REST paths with no
charset check or escaping — a component with `/` or `..` could rewrite
the request. Fix: every component bounded to the GCP identifier charset
before use. (7) **MCP hardening.** `plan --out` wrote any absolute path
(arbitrary file write) — now confined to the workspace; positional path
args beginning with `-` are refused (argument injection into the frozen
CLI); an ignored `crypto/rand` error could have issued an all-zero
confirmation token — now fail-closed. Plus defense-in-depth and honesty:
ledger/plan/quarantine/draft files are `0o600` (were world-readable on
the documented shared hosts); quarantine swaps the valid prefix in by
atomic rename, never a truncating in-place write; the anchor rejects a
malformed zero-event/non-genesis-head document instead of rubber-
stamping any ledger; the consent predicates (statefulOf,
forbidsDeleteStateful, allowsReplaceStateful), previously duplicated
byte-for-byte in the compiler and executor — the exact drift this
project exists to prevent — now live in one `policy` package; and the
MCP two-step's docs no longer claim it "proves a human saw" the
decision (it pins the plan hash; it does not authenticate a human).
DEFERRED as stated boundaries, not defects (compliance review, all
honestly scoped in the spec): the ledger's authenticity is OS file
permissions plus a recomputable hash chain (signatures reserved,
tamper-EVIDENCE not prevention); anchor enforcement stays opt-in
(out-of-band, not on the apply path); decision-event authorship
(contract.published producer, `publish --record`) and a voice-track
privacy note are pre-launch documentation/scope items; the file backend
reads whole ledgers into memory (snapshots are the growth path, D33).

## D74. Closing the review's decision list: authorship, anchor teeth, honest docs
The compliance review left a short list of items classified as
"boundary or scope, not defect". Rather than carry them to launch, each
is closed. (1) **Authorship on the ledger.** `groundhold publish` is the
producer the registry lacked for `contract.published`: it appends the
contract's canonical hash under a NAMED human actor (Writer gains an
ActorType; publish sets human), so the audit chain answers "who
approved this contract", not only "the runtime executed it". It refuses
without `--actor` — unattributed authorship is not authorship — advances
decision heads (a plan seals against the published head) and takes no
lease. Authorship stays self-asserted, not authenticated; that boundary
is now stated where the claim is made, not only in the spec.
(2) **The anchor grows teeth on the execution path.** D70 shipped
`anchor`/`anchor --check` as an out-of-band verb; it is now ENFORCED
opt-in: place `<ledger>.anchor` and apply/resume/publish verify the
replayed ledger still extends it after replay, before any provider call
— a truncated or rewritten tail refuses (exit 5) instead of mutating.
No file means no enforcement, so the opt-in nature is preserved while
the tail boundary becomes actionable, not just diagnosable. (3) **Honest
docs.** The MCP two-step no longer claims to "prove a human saw" a
decision (it pins the plan hash; it does not authenticate a human);
SECURITY.md states the trust boundary plainly (ledger authenticity =
file permissions + a recomputable chain; actor identity self-asserted;
no in-process SoD) and routes reports through GitHub private advisories;
the README license paragraph now matches the shipped LICENSE files
(Apache-2.0 spec/SDK, MPL-2.0 runtime) instead of "undecided"; and the
voice track carries a privacy section (a transcript is personal data;
prefer pseudonymous attribution; the transcript never enters the ledger;
the adopter is the controller), mirrored in the transcript-to-contract
skill. (4) **A pathological ledger refuses, never OOMs.** The whole-file
read is capped (512 MiB, far above the documented tens-of-thousands-of-
events range) with a clear "activate snapshots (D33)" refusal. Plus the
coverage the "pinned or not done" rule demanded: the D72 GCP update
reconciler (measure/mismatch/cross-project-safety), the deposed-delete
forecast branch, EnforceAnchor, publish, and the repair finding-kinds
are now pinned by cases or unit tests; a swallowed lease-release error
in resume is surfaced; and the update reconciler's "not observable"
refusal now names the probe-only cause instead of a bare "reconcile
manually". Nothing from the two review rounds remains open as a defect;
what remains are deliberately-scoped v0 boundaries (event signatures, a
real backend, single-driver breadth), each stated honestly in the spec.

## D75. Permission preflight: the plan declares the access it needs, the executor proves the identity has it before mutating
The failure this closes: an apply that discovers a missing IAM permission
MID-flight, after some resources already exist — the partial-mutation the
whole project fights. Two independent reviewers confirmed the shape and
sharpened it. Split on the determinism boundary (like plan-declares-outcomes /
probe-measures): the compiler DERIVES, the executor DIALS.

**Deterministic half (in the hashed plan).** Each action carries
`requiredPermissions` — the full provider permission set its driver call
sequence needs, sorted and deduped, from `provider.PermissionsFor(name,
operation)`. The table is a PURE package function keyed by provider NAME (not
a live instance) so the compiler resolves it uniformly whether the provider
comes from the candidate (create/update) or the binding (delete/retire/
deposed — the path everyone forgets; emitted in both Compile and
CompileDeposed). Quiet reads are in the table — a gcp create needs
`cloudsql.instances.get` for 409 classification and operation polling, not
just `.create` — because an OMITTED permission produces a false PASS, the
dangerous direction. The compiler makes NO network call: derivation-only at
plan time is a closed decision, same register as D39's "no Terraform on the
execution path". The field is optional/additive, so pre-D75 plans stay
loadable; the compiler is Go-only (D24), so the derivation is pinned by an
`impl: go` case (plan-emits-required-permissions-for-gcp-create). Python only
loads/validates the field; hashing is free (canon hashes the raw tree).

**Live half (executor, not hashed).** A new OPTIONAL provider capability
`Preflighter.CheckPermissions(project, perms) -> (missing, err)`. A new
refuse-before-mutate step runs after every deterministic refusal and BEFORE
lease acquisition — a doomed apply takes no lease and appends nothing — and is
never re-checked under the lease (permission truth is not CAS-able; holding
the coordination lease across a hangable network call buys nothing). It checks
the UNION of the executor's own current derivation and the plan's declared set
(never trust a possibly-stale sealed list alone), against the plan's PINNED
`reads.provider.project` (which also catches a credential/project mismatch for
free). GCP uses `cloudresourcemanager.projects.testIamPermissions` — a SECOND
API that must be enabled, distinct from Cloud SQL Admin.

**Two codes, because two remediations** (both reviewers, one-code-per-
remediation): `provider-permission-denied` when the check RAN and returned
missing permissions (grant them); `preflight-inconclusive` when the check
could not run at all — CRM API disabled, token/scope, connectivity (make it
runnable, or skip). Folding them would send an agent granting permissions when
the real fix is enabling an API.

**Missing capability skips LOUDLY, not fail-closed** (the one place the two
reviewers disagreed). A driver without `Preflighter` proceeds with a
surfaced `preflight: {status: skipped}` in the result — refusing would make
"optional" a lie, force every future driver (including clouds with no
testIamPermissions equivalent) to implement it, and regress setups that apply
fine today. `--require-preflight` is the additive, consent-shaped opt-in for
operators who want strictness (then absent capability refuses
`preflight-inconclusive`). A check that ERRORS still fails closed — the driver
claimed it could answer and couldn't, and a broken token fails mid-apply
anyway.

**Honesty, stated everywhere the feature is described.** A preflight refusal
is trustworthy; a preflight pass is EVIDENCE, not proof. testIamPermissions
cannot see IAM deny policies, conditional bindings (evaluated against request
context that differs at mutation time), propagation lag, OAuth scope limits,
org policy, VPC-SC perimeters, quota/billing, or Shared-VPC host-project
permissions. Mid-apply permission failure stays possible; write-ahead receipts
remain the recovery story. The word "eliminates partial-mutation risk" appears
nowhere.

Rejected alternatives: a live `preconditions` type (preconditions are
re-verified deterministically from pinned documents — a live member would be
the first non-deterministic entry in a closed deterministic registry); a
`preflight.checked` ledger event (a refusal appends nothing, like every other
refusal — no state.schema or event-registry change); dialing IAM at `plan`
time (the compiler never dials). Pinned by the conformance case above and by
go/internal/apply + go/internal/gcp tests (missing / check-error / skip /
require / pass, and the testIamPermissions request/parse over httptest).

## D76. Multi-service dispatch: the driver routes on the service token, fails closed on unknown
The GCP driver was hardcoded to Cloud SQL; a real stack needs breadth. First
real-cloud dogfooding (deploy fe+be+db) hit the wall: groundhold could stand up
the database and nothing else. Two independent reviewers were consulted; a key
correction from one shaped the design.

**The dispatch key is the SERVICE, not the capability type.** The type
(`capability.database.relational`) underdetermines the builder — it may be
Cloud SQL today, AlloyDB tomorrow; the service (`cloudsql`/`cloudrun`/`gcs`) is
which API family fulfils it. The service is already a schema'd candidate field,
already read by the compiler, already hash-pinned into the plan action's target
(`gcp.cloudsql/app-db`), the binding (`resources[0].type`) and the receipt —
so the dispatch information already travels with the identity through every
persistence surface; it just never reached the driver. Every Provider method
now takes `service` explicitly; the driver dispatches with a closed switch that
**fails closed on unknown or empty — never a default service** (an
attacker-influenceable string that silently routes into Cloud SQL would be a
confused-deputy, the exact D73 pattern). This is how mature engines work
(Terraform's resource registry, Pulumi's resource token, Crossplane's GVK
reconcilers): dispatch on a trusted type token, never inference from body
fields.

**Sourcing is the sealed decision, not a spoofable field.** The service comes
from the hash-pinned plan target and, for retirement/deposed (which have no
candidate extras), a new `Inputs.BindingServices` projection from the binding —
closing a latent bug where a retirement plan's target was `unbound/cap` and the
delete could not dispatch. On create/update apply cross-checks the target
service against the candidate's declared service and refuses a mismatch
(`provider-refused`) — a hand-edited plan cannot re-route a database candidate
into the Cloud Run builder. The compiler derives the service from the contract-
side record and refuses a `gcp` capability that names no service, rather than
sealing a plan with an empty permission list.

**Permissions become per-service and attribute-aware.**
`PermissionsFor(provider, service, operation, attrs)` keys on the same service
token. Cloud Run's set includes the DISTINCT `run.operations.get` (the v2 LRO
poll, where Cloud SQL's `instances.get` sufficed) and, iff
`network.publicExposure=true`, the IAM read-modify-write pair
(`get/setIamPolicy`) needed to grant `allUsers` the invoker role — because
including them unconditionally false-refuses private deployers while omitting
them false-PASSes public ones (D75's dangerous direction). attrs come from the
hash-pinned candidate, so the derivation stays deterministic. Pinned by
`plan-emits-cloudrun-permissions-public`/`-private` (impl: go — the compiler is
Go-only). Cloud SQL behavior is byte-identical; the network shells for Cloud
Run and GCS are the next slices (their sub-drivers refuse "not wired yet" until
then, fail-closed).

## D77. GCS driver + the driver authoring pattern, extracted
The third GCP service (Cloud Storage, `capability.storage.object`), same pure/
shell pattern as D43/D76: `BuildGCSCreateRequest` maps the vocabulary to a
bucket insert, golden-tested, refusing what GCS cannot honor (single-zone
durability, unencrypted). Uniform bucket-level access is the secure baseline;
`publicAccessPrevention: enforced` blocks every public path for a private
bucket, relaxed to `inherited` only when the contract asks for exposure (the
anonymous-read IAM grant is the network-shell's job, like Cloud Run's invoker).
storage.object is STATEFUL, so retirement/replacement ride the existing
delete_stateful / allow_replace_stateful gates with no special-casing — the
vocabulary's `stateful: true` drives it. Permission rows added per-service
(D76), attribute-aware for public buckets.

Three drivers built to one pattern is the point at which it stops being a
coincidence and becomes a contract: extracted into `spec/providers/AUTHORING.md`
(pure core + network shell; the build/test/validate/secure/conform disciplines;
a security checklist drawn verbatim from the D76 review's real findings —
service-token dispatch, providerId charset + cross-project + cross-service
guards, ownership three-valued, mutation honesty under D29, IAM version-3
read-modify-write append-only) and a `provider.CertifyDriver` harness (the
network-free battery every driver must pass: fail-closed dispatch, well-formed
permission tables). A driver — including a community one — is done when it
passes certification and its own golden/httptest suites.

The GCS network shell (create/observe/delete + public-bucket IAM) landed next,
reusing the reviewed Cloud Run IAM helpers (`appendMember`/`hasMember`/
`isDomainRestricted`/`sameProject`) so the security logic is shared, not
duplicated. A two-reviewer pass on the mutating code found and
fixed: pre-delete `Unmarshal` errors are now refusals (a truncated read could
have left `IsLocked` at its zero value); delete carries `ifMetagenerationMatch`
to close the ownership/retention TOCTOU; the 409-continue path checks location
as well as prevention; `publicAccessPrevention` is always emitted explicitly by
the builder so an idempotent retry of our own bucket never reads as drift; and
observe treats `publicExposure` as a diagnostic (never a measured `false`) when
uniform bucket-level access is off, because object ACLs can then expose data the
bucket IAM policy never mentions, and now emits `retention.minimum` so a
retention contract can verify from recorded reality.

Validated on real cloud (a real GCP project, 2026-07-12): a public Cloud Run
service ran the full create/observe/converge/retire loop, and two bugs invisible
to the golden/httptest suites surfaced only against live GCP and were fixed +
pinned. (1) Cloud Run v2 `getIamPolicy` is a GET with the policy version as a
query param; the driver used POST, which hits no route and returns an HTML 404 —
the fake test server had accepted any method, so the httptest now asserts GET.
(2) The D76 cross-project guard `sameProject` refused every observe: observe and
discover build the driver with no pinned project (the project rides in each
providerId), so the guard now no-ops on an empty pin and only bites when a
project IS pinned (apply/converge, where the D75 preflight was checked against
it). GCS itself was exercised through the D75 preflight, which refused it before
any mutation (`provider-permission-denied`, missing `storage.buckets.get`) — the
acting identity genuinely lacked the permission, so refuse-before-mutate held.

Two GCS-shaped residuals are documented rather than papered over. (1) Bucket
names are a GLOBAL, region-less namespace, so a name collision could in
principle be a bucket in another project; ownership rests on the labels (only
the owner can set them) plus the project-derived deterministic name plus the
location check — strong in practice, but not the project-scoped URL that Cloud
SQL/Run enjoy. (2) `buckets.get` returns the bucket's own PAP, not an org-policy
that ENFORCES it above the bucket, so a stale `allUsers` binding under
org-enforced PAP reads as public here — a FALSE POSITIVE (the safe direction for
a privacy constraint; the false negative is the dangerous one, and the UBLA gate
closes it). Reading effective org-policy is a backlog item.

## D78. Preflight honesty: a provider's negative signal is a verdict only from an attesting surface

D75 shipped with a hidden assumption its own header half-stated: "a refusal is
trustworthy, a pass is evidence." A real-cloud run (a real GCP project, 2026-07-12)
disproved the first half. The permission preflight calls
`cloudresourcemanager projects.testIamPermissions` and treated ANY queried
permission the response did not echo back as missing → a hard
`provider-permission-denied` that blocks the apply even without
`--require-preflight`. But that CRM surface has an allowlist and SILENTLY OMITS
resource-scoped permissions: an identity that was **Owner** on the project (it
held `resourcemanager.projects.setIamPolicy`; a real `buckets.get` returned 200;
resource-level `buckets:testIamPermissions` granted `storage.buckets.get`/
`getIamPolicy`/`setIamPolicy`) was reported by the project surface as LACKING
exactly those, while `storage.buckets.create`/`delete`/`list` came back. Groundhold
told a fully-authorized user they lacked access and refused a valid apply.
Google's own docs say `testIamPermissions` is "not intended for authorization
checking." So the negative was never authoritative; the code collapsed a
three-valued signal (held / denied / not-attested) into a boolean — the exact
sin invariant #1 forbids in verdicts, replicated in the executor.

The fix is doctrinal, not a patch. **A provider signal groundhold gates on carries
an authority class, and a non-authoritative negative may never become a hard,
user-facing assertion.** The corrected rule (a correction to D75, which stands
otherwise — do not rewrite it): a pass is evidence; a negative is a verdict only
from a surface that ATTESTS it evaluates that permission at that scope; an
omission from a non-attesting surface is a hint, i.e. `unknown`. Concretely,
`Preflighter.CheckPermissions` now returns `(denied, unattested)`: a pure
`crmAttests(permission)` table (only `cloudsql.`/`run.` — the prefixes we have
positive evidence the project surface evaluates; everything else, including
`storage.`, defaults unattested) partitions the not-returned set. The executor
hard-refuses only on `denied`; `unattested` (and a check that could not run) is
`preflight-inconclusive` — under `--require-preflight` it blocks, otherwise the
apply proceeds loudly and the mutation itself is the authorization oracle, with
write-ahead receipts recovering a real mid-apply denial exactly as before. The
asymmetry decides every ambiguous row: a wrong `unattested` costs one lost
fast-fail (recoverable); a wrong `denied` is a lie (trust-destroying) — so the
table defaults to unattested and a drift canary watches the dangerous direction
of each row (CRM must keep attesting a known-granted `cloudsql.*`; it may start
attesting `storage.*`, a safe upgrade). Cloud SQL fast-fail is fully preserved;
genuine total-lack-of-authorization on a `storage` create now surfaces at the
create call (a clean 403, nothing mutated) rather than as a preflight lie.

This is the fourth instance of the house pattern — probe.failed is never an
observation (D59), GCS `publicExposure` is a diagnostic when org policy is
invisible (D77), a lost mutation response is `unknown` not failed (D29) — named
here so a fifth is not rediscovered by a production incident: a signal groundhold
does not fully trust degrades to `unknown`, never to a false assertion. The
authoritative resource-level check for existing resources (bucket/service
`testIamPermissions`, which would restore a trustworthy negative for
update/delete/adopt) is the natural next slice; until then those degrade to
inconclusive — the safe direction.

## D79. The live-integration canary: a scheduled watchdog for provider drift

Every suite groundhold runs pins what it SENDS — golden requests, httptest
exchanges, conformance verdicts. None can see the provider change its mind.
Three bugs this cycle proved the gap, each invisible until a real apply: Cloud
SQL's default edition flipped (rejecting a once-valid tier); Cloud Run v2
`getIamPolicy` is a GET not a POST; project-level `testIamPermissions` omits
resource-scoped permissions (D78). The canary closes the loop D78 promised ("a
drift canary watches the dangerous direction of each row"): `scripts/canary-gcp.sh`
+ `.github/workflows/canary-gcp.yml` run the real converge loop and the D78
drift assertions against a throwaway project on a schedule, and go red when GCP
moves before a customer hits it. It is the sibling of the interactive, human-
driven `scripts/integration-gcp.sh`, not a replacement — the confirmations that
make that script safe for a human are exactly what a scheduled job must not have.

Three design commitments carry the honesty of the rest of the system into CI.
(1) The drift assertions run with raw curl, NOT the groundhold binary — that
independence is what lets the exit code separate a provider change (a raw
assertion fails) from a groundhold regression (assertions pass, a converge loop
fails) from infra flake (the control probe itself fails): 10 / 20 / 30, each a
distinct incident class in a machine `result.jsonl`. (2) Each assertion names
the drift DIRECTION it guards, and the two directions are asymmetric exactly as
D78 argued: CRM ceasing to attest `cloudsql.`/`run.` is red (the "denied" rows
would resume lying); CRM starting to attest `storage.buckets.get` is a
`promote-available` notice, never red (current behavior stays correct, the row
can simply be upgraded). (3) Self-cleaning is three independent layers — a
raw-API sweep of `groundhold-`labelled canary resources at start, a per-mode
concurrency group so the sweep never races a live run, and a `trap ... EXIT`
retire+sweep — none trusting groundhold's own correctness, because a groundhold bug
must never leak a paid resource. Auth is Workload Identity Federation, never a
long-lived key: a fork cannot mint the token (attribute-bound to repo + default
branch), and nothing in the repo config is secret.

The canary earned its keep on its first heavy run: the Cloud SQL loop caught GCP
rejecting `db-perf-optimized-N-2` under an ENTERPRISE default (the edition had
flipped AGAIN since D78's ENTERPRISE_PLUS observation). That surfaced a real
driver gap — the Cloud SQL builder read `tier` but silently dropped `edition`,
so groundhold could not pin the pair GCP validates against. Fixed in the same
slice: `implementation.edition` is now honored (ENTERPRISE | ENTERPRISE_PLUS,
unknown values refused, absent leaves GCP's default), so the canary pins edition
AND tier and the (a)-class assertion is precise. The fast loops (Cloud Run +
GCS) and the drift assertions were validated green end to end against
a real GCP project; the sql loop after the edition fix likewise. This is the same
principle the whole system rests on, pushed one layer out: don't assume the
provider is what it was — observe it, and fail honestly when it moved.

## D80. Resource-level preflight: the authoritative negative D78 could only defer

D78 made the preflight honest by refusing to call a project-surface omission a
denial — but it paid for that honesty with fast-fail: for `storage.` and any
non-CRM-attested permission, a genuine lack now degrades to inconclusive and is
only caught at the mutation. D78 named the fix and D80 lands it: for an action on
an EXISTING resource (a pinned `targetProviderId` — update/delete/deposed), the
resource's OWN `testIamPermissions` surface evaluates the permission at exactly
the scope the mutation will authorize against, so its negative IS authoritative
(proven live: it grants `storage.buckets.get`/`getIamPolicy`/`setIamPolicy` the
project surface silently omits). The optional `ResourcePreflighter` interface
carries it; `scopedPreflight` in the executor routes each action by scope — an
existing resource to its resource check, a create (and any no-resource-surface
service) to the project check — and aggregates. Cloud SQL has no per-resource
IAM surface, so it returns `ErrNoResourceSurface` and falls back to the project
check, where `cloudsql.*` is CRM-attested and the negative is authoritative
anyway — no fast-fail lost there.

Two boundaries are held honestly. A resource-level negative on a 200 is a
denial; a surface that cannot be read (404, network) is an ERROR, mapped to
inconclusive, NEVER a denial — a missing resource is drift, not a permission
verdict, and reporting it as denied would resurrect exactly the D78 lie in a new
place. And the method drift the getIamPolicy incident taught is designed in from
the start rather than discovered in production: verified live and pinned by
httptest, GCS uses `GET /iam/testPermissions` while Cloud Run v2 uses `POST
:testIamPermissions` — the same verb, two methods, because the provider is
inconsistent and the only defense is to check reality. The full slice
(interface, driver checks, scoped routing, six httptest/unit cases covering
authoritative denial, no-surface fallback, unreadable-is-inconclusive,
cross-project refusal, and per-service method) was validated green end to end
against a real GCP project through the canary's create+retire loop.

## D81. Driver hardening pass: the meta-lesson is consistency

Before building drivers for more services (and providers), a two-reviewer
adversarial sweep over the three GCP drivers surfaced ~25
findings — and the dominant pattern was not novel bugs but INCONSISTENCY: a fix
proven and pinned for one service (GCS) had silently not been applied to the
others (Cloud Run, Cloud SQL). Ignored `json.Unmarshal` errors on a pre-delete
read, an empty operation name reported as synchronous success, a 5xx on a
mutation collapsed to `failed` instead of `unknown` (D29), a DONE operation with
a non-empty error OBJECT but empty errors ARRAY falling through to success — each
was correct in one driver and wrong in another. The hardening, across batches:
pre-delete/observe unmarshal checked everywhere; empty-op → unknown on every
create/update/delete; 5xx → unknown via a shared `mutationResult`; any non-nil
operation error → failed; a three-valued public-exposure confirm (a 200
setIamPolicy contradicted only by a failed CONFIRM read is `unknown`, not
`failed`); non-bool deletion protection refused; Cloud SQL labels sanitized
identically on write and every read; a resource-testIamPermissions parse failure
inconclusive, never all-denied; fractional port/replicas refused rather than
truncated below a declared minimum; GCS retention rounded UP; Cloud Run
serviceId capped at 49 and `invokerIamDisabled` read as a public mode (both
verified against the live discovery doc); the intrusive RTO probe gated on
`sameProject` + an ownership label before spending, and its scratch instance
copying the source edition (D79); Cloud SQL 409 verifying the immutable region
and binding the LIVE region not the request's; the project id charset-validated
before interpolation; Cloud Run delete carrying the pre-read etag (TOCTOU);
`image.signedProvenance` made observable so it can converge; the reconcile path's
transient operation-read left `unknown` rather than guessing a verdict by name.
Every fix pinned by a test. The through-line — apply a lesson to ALL services,
not the one where it was found — is exactly what the authoring procedure (below)
exists to enforce so the fourth, fifth and sixth drivers don't relearn it.

## D82. GCS cross-project ownership: labels are forgeable in a global namespace

Cloud SQL and Cloud Run put the project in the REST path, so an operation cannot
touch another project's resource. GCS bucket names are a GLOBAL, region-less
namespace and groundhold's names are deterministic (a pure function of project +
environment + capability), so an attacker who knows the naming can pre-create our
exact bucket name in THEIR project, label it with our `groundhold-capability`/
`groundhold-environment` (they own it — they can set any label), and match its
location and PAP. Our create then hits 409, finds an "ours"-by-labels bucket, and
would bind it — future application writes land in the attacker's bucket. Labels
are therefore NOT proof of ownership cross-project; the authority is the live
`projectNumber`, which the attacker cannot forge. Create's 409-continue and
delete now resolve our project's number once via CRM (cached) and refuse a bucket
whose `projectNumber` differs. Observe is deliberately EXEMPT: it runs with no
pinned project (the project rides in the providerId, which `sameProject` guards)
and has no number to resolve — the same read-path shape D78 taught, caught in
review before it shipped. The new dependency is declared honestly:
`resourcemanager.projects.get` joins the GCS permission rows (and `crmAttests`),
pinned by conformance. Validated live.

## D83. VPC driver: the first multi-resource capability

capability.network.private (a GCP VPC) is the fourth service and the first whose
ONE capability maps to SEVERAL provider resources: a Compute network (custom
mode), a regional subnetwork, and — when egress.restricted — a default-deny
egress firewall. Two things the single-resource drivers never faced, both
designed with an adversarial review against the authoring battery. (1) The
create is a THREE-PHASE state machine, and the honesty rule is that the
providerId (`vpc:project:region:network`) is attached the moment the NETWORK
exists, so a partial — network without its subnet, or subnet without the egress
firewall the contract requires — is `failed`/`unknown` WITH the id (bindable,
retire-able), never `succeeded`; only all-present-and-matching is success. The
region rides in the providerId because Observe cannot re-derive the subnet's
name (a separate hash) and finds it instead THROUGH the network's `subnetworks[]`
links + the ownership marker. (2) VPC resources have NO labels, so ownership is a
marker PARSED (not substring-matched) out of the resource `description` —
`groundhold:capability=X;environment=Y` — three-valued at the call site exactly like
the label checks. Operations poll global- or regional-scoped; delete runs in
reverse (firewalls, then subnets, then network), each ours-by-marker, and a
dependency conflict (attached VMs, peerings) is data-loss friction surfaced,
never forced. Two residuals are documented, not hidden: Compute has no delete CAS
precondition (the pre-read→delete window is a TOCTOU the API cannot close), and
`description` is as mutable as a label — the marker is no weaker than labels, and
no stronger. Every Compute path was verified against the live discovery doc
before coding; the full create/observe/converge/retire loop was validated green
end to end on a real GCP project (network + regional subnet, global + regional
operations, reverse-order retire) on the first real-cloud run.

## D84. Cloud Functions: a second service under one capability, no new vocab

The fifth GCP service and the first proof of D76's "one capability TYPE, many
services" at the workload layer: Cloud Functions Gen2 is a SERVICE
(`cloudfunctions`) under the EXISTING `capability.workload.container`, not a new
`capability.workload.function`. Both consults landed firmly on
this: by the semantics-vs-noise test, a function's source/runtime/no-image shape
is implementation noise; what an org contracts — residency, exposure, capacity
floor, TLS, cost — is the same stateless-workload surface Cloud Run fulfils, and
all eight container attributes map cleanly with ZERO new attributes (a new vocab
would enshrine packaging as semantics). Two honest refusals hold the line: an
event-driven trigger is candidate wiring, not a contract attribute, so v0
handles HTTP functions and REFUSES an event trigger (fail-closed until an
eventing capability is decided on its own merits — a future `invocation.protocol`
if that need ever appears); and `image.signedProvenance` is REFUSED because the
driver cannot honestly enforce equivalent provenance for a function in v0 —
refuse rather than claim a gate. Function names are letters-and-hyphens only
(Gen2 ids forbid digits, verified live), so the deterministic hash tail is
encoded as letters. The shell reuses the reviewed Cloud Run IAM helpers: public
exposure is the same TWO gates (ingressSettings ALLOW_ALL AND an allUsers invoker
binding on the function's BACKING Cloud Run service), and the Gen2 LRO uses the
google.longrunning `{done,error}` shape, not the `{status:DONE}` of Compute/Cloud
SQL (verified live — the getIamPolicy lesson applied). An adversarial review
caught six issues, the top two the exact D81 pattern of a fix proven for one
service silently missing from another: the 409-continue skipped Cloud Run's
ingress-mismatch guard (a mismatched existing function reported succeeded), and
observe missed `invokerIamDisabled` on the backing service (a world-invocable
function measured private) — both fixed and pinned, plus a cross-project pin on
the backing-service IAM mutation, DELETE-404 idempotency, and the operation id
carried on every terminal poll. HONEST STATUS: code + review + gates (179/179
conformance, 178/0 differential) complete; LIVE validation on a real GCP project is
BLOCKED because that project's billing account went delinquent (all writes
denied) — flagged not-live-validated, to run when billing is restored, exactly
as AWS/Azure will be until their credentials are wired.

## D85. Agnosticism is a place: the contract is portable, the deployment is not

Before adding a second provider (AWS), a core-agnosticism audit (grep + a
thorough read) confirmed with evidence what the thesis promises: the verifier,
type system (contract/vocab/scalars), canonicalization, state model, ledger and
sealed-plan IR are genuinely provider-NEUTRAL, and `providerId` is opaque in
every core package (no core code parses `project:region:name` — only the driver
does). Ownership (labels vs tags vs description markers) is fully delegated to
the driver; nothing in the core assumes it. This is the honest, load-bearing
claim: **agnosticism lives in the contract, not in a shared abstraction layer.**
groundhold does NOT promise "write once, run identically on any cloud" — the lie
every multi-cloud tool tells. It promises: declare agnostically what must be
TRUE; each cloud's driver either honors it deterministically or REFUSES honestly
(refuse-before-mutate); the contract is portable, the fulfillment is not, and a
semantic mismatch surfaces as a refusal, never a silent approximation.

The seams where neutral meets specific are deliberate and named, not accidents.
`classifyProvider` picks a driver by the candidate's provider name; the executor
builds the driver by name; `PermissionsFor(providerName, service, op, attrs)` is
a pure, name-keyed table in the shared package — an ACCEPTABLE seam, not a leak,
because it must be callable at COMPILE time from the provider name alone (the
compiler embeds requiredPermissions into the sealed plan without instantiating a
live driver). A new provider adds a `case "aws":` arm; if permission tables ever
multiply enough to warrant it, they can migrate to a driver method, at the cost
of that compile-without-a-driver property. The service-gate was made
provider-neutral here: `if prov != "" && prov != "fake" && svc == ""` refuses
any non-fake provider that names no service — never a hardcoded `prov == "gcp"`
(the old form, an AWS candidate would have slipped past it).

Two generalizations are DEFERRED to the AWS work, on record so the IR is not
frozen by accident. (1) The plan's `reads.Provider` block is `{Name, Project}` —
GCP-shaped; D28 says the pinned identity is account/project/region/role. AWS's
create-time scope is account+region, which has no home there. Verified: because
the plan is hashed as a marshaled map and the fields are `omitempty`, adding
`Region`/`Account` (or a driver-owned `Scope` map) is ADDITIVE and hash-safe —
existing GCP plans leave them empty, so their hashes are unchanged; only AWS
plans carry them. So this is deferred, not risky. (2) `internal/importer`
(tf/pulumi hints, D53) imports `internal/gcp` and composes the GCP providerId
shape; containment is confirmed (only `cmd/groundhold` imports it, and it is the
only core package importing a driver). When AWS tfstate import is wanted, the
state→hints mapping becomes a driver capability (an `Importer` interface or a
name-keyed registry) so the importer dispatches by name without importing each
driver — not needed for AWS create/observe/deploy, only for importing existing
AWS state.

The falsification-test discipline this makes explicit: a vocabulary attribute
must map cleanly to at least TWO real providers, or it is secretly
provider-shaped. AWS is the test — as RDS/S3/ECS land, every existing vocab
attribute that will not map is a GCP-shaped attribute to surface and fix, never
to paper over; each vocab gains its `aws.*` mappings as proof of two-provider
generality (the Cloud Functions consult already enforced this by demanding the
aws.lambda mapping before accepting an attribute).

## D86. AWS driver family: the falsification test, passed on three protocols

AWS is the two-provider proof D85 demanded. Four services now fulfil the SAME
vocabularies Google fulfils, through a standalone SigV4 signer (golden-tested
against AWS's official `get-vanilla` vector) and THREE distinct wire protocols:
S3 (REST-XML), RDS + EC2/VPC (Query-XML), ECS (JSON with `X-Amz-Target`). The
capability parity is complete: database.relational (RDS ↔ Cloud SQL),
storage.object (S3 ↔ GCS), workload.container (ECS ↔ Cloud Run/Functions),
network.private (VPC ↔ Compute VPC). Every service was proven live on the owner
sandbox account (create → observe → converge → retire), and RDS end-to-end
(create polled to `available`, observe, delete) under the harness's own gated
live roundtrip.

The lessons were driver-shaped, not thesis-shaped, which is the point: S3 requires
`x-amz-content-sha256` signed and `Content-MD5` on config PUTs; RDS/ECS/VPC are
multi-resource with server-assigned ids (unlike the deterministic-name services),
so a lost create response there genuinely loses the handle; the D82 squat defense
that GCS needed a project-number check for, AWS answers directly via
`BucketAlreadyOwnedByYou` vs `BucketAlreadyExists`. Ownership is tags (sanitized
identically write==read), the AWS analogue of GCS labels and the VPC
description-marker. Topology (peering, transit gateways, NAT, route tables, load
balancers, autoscaling) is deliberately NOT modeled — it is not capability
semantics; `interconnect.private` is honestly REFUSED, never faked. The vocab
files needed ZERO change: their `aws.*` mappings were present from D60, so
agnosticism was proven, not retrofitted.

Three adversarial review rounds found ~30 driver bugs, nearly all
the same class — an ambiguous "may have landed" branch collapsing four-valued
honesty (dropped providerId on 5xx/already-exists, garbled-200 as not-found, 3xx
as success, batch `<unsuccessful>` ignored, no-creds mislabeled unknown). D81's
meta-lesson held: each bug had a sibling path in the same file that already did it
right. That observation is what made D87 possible.

## D87. The adversarial honesty harness: mechanize the meta-lesson

Three review rounds finding the same consistency-class bug is a signal that the
class is MECHANICALLY detectable. `internal/certifynet` is the weapon: a
record-then-perturb transport fuzzer that certifies the four-valued honesty
invariants for ANY driver without a per-driver expectation table (which would
merely re-encode the driver's own bugs in a second language). It runs an
operation once against the driver's own golden happy server, records the request
trace, then replays it injecting ONE adversarial fault per request (500,
dropped-connection, garbled-200, empty-body, foreign-tag) and asserts only
LAW-DERIVED shape invariants: an ambiguous outcome on a mutation the driver sent
must be `unknown` and must preserve the providerId wherever it is knowable; a
foreign-tag on a pre-mutation ownership read must be REFUSED with no subsequent
mutation.

The design (a parallel critique from two independent reviewers, both adversarial) turned on three
distinctions that keep the oracle honest rather than merely strict. (1) A
request's ROLE — read vs opaque-mutation vs body-consuming-mutation — is a
structural protocol fact, not a verdict: a garbled body is ambiguous only where
the driver parses it (ECS RegisterTaskDefinition's arn), not where success is
status-only (an S3 PUT). (2) The providerId is knowable-before-create only for
deterministic (chosen) names; for server-assigned ids (AWS `vpc-…`) a lost create
response honestly loses the handle until the id-yielding call succeeds — so
pid-preservation is required only where the id is actually known. (3) The
ownership gate is a PRE-mutation read; poisoning a post-mutation poll that merely
echoes the tag is not a violation. Getting these right is the difference between a
harness that catches bugs and one that generates false accusations.

On its first run it found a systematic bug all three manual rounds had missed:
EVERY AWS driver's delete returned `unknown` WITHOUT the providerId on a
5xx/dropped-connection — the exact D81 class, on the one path the reviews had not
walked. Fixed across S3/RDS/ECS/VPC. What fault injection provably CANNOT catch is
named in the package doc and left to the golden tests, the (planned) metamorphic
write/read round-trip, and live runs: semantic field mis-mapping, silent missing
steps, poll-loop false-success on a plausible-but-wrong 200, TOCTOU. The harness
proves "the driver did not lie about an ambiguous wire outcome"; it does not prove
"the driver asked the cloud the right question." That boundary is the honest part.

## D88. Deepening is mostly the thesis working: the sub-entity audit

The natural next ask after breadth is depth — "cover all the sub-entities of each
service." Taken literally that means CRUD over every provider sub-resource: Cloud
SQL databases/users/replicas, S3 lifecycle/replication/object-lock/logging, Cloud
Run revisions/traffic/concurrency, VPC routes/peering/NAT/DNS. Most of that is
precisely the topology and implementation detail D85 refuses. So the first move was
not to implement — it was to AUDIT, with the two-provider falsification test as the
hard gate and two independent reviewers as adversarial classifiers alongside a first-party pass.

All three converged on the uncomfortable, correct verdict: ~80% of "sub-entities"
are buckets B (topology/impl noise — parameter groups, storage tiers, route tables,
revisions, concurrency) or C (a DIFFERENT capability — database users are
identity/access, event notifications are eventing, service accounts are identity).
The drivers are already near the right depth; the apparent shallowness is the
thesis working, not a gap. The genuinely capability-semantic remainder was small —
four attributes that a compliance author would legitimately constrain and that map
cleanly to BOTH clouds:

- `retention.maximum` (storage) — data minimization, the ceiling dual of
  `retention.minimum`. GCS lifecycle Delete-by-age / S3 lifecycle Expiration.
- `encryption.customerManagedKeys` (database + storage) — CMEK/KMS vs the provider
  default; the key id is `implementation:` detail, never a capability path.
- `retention.locked` (storage) — WORM; presupposes `retention.minimum`.
- `encryption.inTransit` (database) — TLS enforced, not merely permitted.

The load-bearing discipline was the refusal rule: **honor an attribute in the same
create/update call the driver already makes, or REFUSE that cloud loudly — never
create a second tracked resource to satisfy it.** The moment a vocab attribute needs
the driver to manage a second binding, it is topology wearing a semantic costume,
and it re-imports Terraform's dependency-ordered resource graph into a system whose
whole architecture (one binding per capability, one ledger identity — D39/D85)
exists to refuse that graph. Three attributes hit that wall and were refused on one
cloud each, honestly, in both the vocab mapping and the driver error (the precedent
is S3 already refusing `retention.minimum`):

- `encryption.inTransit` on RDS — enforcing TLS needs a DB parameter group (a
  separate binding). Refused; probe-only. Cloud SQL honors it via `sslMode`.
- `retention.locked` on S3 — Object Lock is create-time-only and its retention is a
  separate call the idempotent 409-continue path cannot re-assert, so it would
  half-apply. Refused. GCS honors it via a one-way `lockRetentionPolicy` on the SAME
  bucket (metageneration CAS, `isLocked` confirmed from the response).
- `encryption.customerManagedKeys` on RDS — create honors it (`KmsKeyId`), but
  OBSERVE cannot: an encrypted instance always reports a `KmsKeyId`, and a customer
  key is indistinguishable from the account-default `aws/rds` key without a
  second-service KMS `DescribeKey`. Observe emits a diagnostic, never a false
  measured value.

That last case has an honest consequence, not a bug: an RDS instance with
`customerManagedKeys` as a HARD constraint will not converge — observe returns no
value, the verdict is `unknown`, and `unknown` on a hard constraint blocks (the
four-valued model working exactly as designed). A future KMS-`DescribeKey` probe
closes it. The general shape holds: where a cloud cannot honor or cannot honestly
measure an attribute, the system refuses or reports `unknown` — it never pretends.
An asymmetric vocabulary (one provider honors, another refuses loudly) is the
correct outcome, not a defect; the attribute is still portable, the deployment is
not (D85).

## D89. Presentation is a thesis-carrying layer: the state vocabulary

Terraform can be red/green because its semantics are binary. Ours are not, and
the presentation layer is where a four-valued model goes to die: color unknown
red and you have visually collapsed it into failure; color it green and you have
lied. The whole architecture refuses to collapse `unknown` into a boolean —
spec/presentation.md exists so the last mile cannot betray that refusal. The
prime rule is stated there in exactly those terms, plus its social corollary:
a refusal (exit 2) must never look like a failure, because an operator who
learns that the gate "errors" learns to resent and bypass the gate. REFUSED
renders blue, calm, authoritative — the guard, not the accident.

The banner vocabulary is a closed set (PROVEN, CONVERGED, VIOLATED, INVALID,
BLOCKED, STALE, REFUSED <code>, DIED, CORRUPTED) mapped by (exit, code, verdict
rollup) with explicit precedence — exit codes alone cannot pick it, because
verify-with-a-violation and verify-with-an-unknown both exit 2 as
`not-executable`. An independent review (micro format) contributed four accepted
corrections: exit 1 must not fall under VIOLATED (an operator would read "the
infrastructure broke a rule" when the input did not parse — hence INVALID);
REFUSED must carry its machine code adjacent because exit 2 is heterogeneous
and the codes already exist (D64 — zero new semantics, pure surfacing); PROVEN
vs CONVERGED is an epistemic distinction, not synonyms under one green; and the
ASCII fallback for unverifiable is NA, never `-` (reads as skipped/neutral).
Row glyphs are shape-first (✓ ✗ ? ∅) so meaning survives NO_COLOR and CI;
`?` vs `∅` split by next action: gather evidence vs change the question.
Provenance renders as brightness, not color — green-but-dim is exactly the
message "satisfied, standing on sand".

The second half of the decision: teaching in passing. The vocabulary files
already carry a human description and a verification note for every path —
the glossary exists, the renderer just never joined to it. The join happens
at friction only (violated/unknown/unverifiable rows, the banner's culprit):
the user who is blocked by RTO learns what RTO is and why configuration cannot
prove it, at the exact moment they care, and satisfied rows stay terse because
explaining the happy path teaches skimming. `explain` extends from error codes
to vocab terms; consoles tooltip from the same files. One glossary, no drift.
The system teaches paths, not constraint ids — ids are author-chosen and
opaque, and nothing tries to rescue `c-x17`.

Nothing semantic moves: verifier, exit codes, machine codes, JSON outputs all
untouched. Banners and glyphs are explicitly not a machine interface.
Implementation lands as a single render package used by every verb (today each
verb prints its own prose, and there is no color anywhere) — conformance can
pin banner words and glyph fallbacks once that package exists.

## D90. Banner rollout: green is a claim, silence is honest, stderr is prose

Extending D89 from `verify` to every verb forced two decisions the spec had left
implicit. First: what is the green word for verbs whose success is not an
epistemic claim? The answer (an independent micro-review, accepted with corrections) is a
three-tier green — epistemic (PROVEN for verify/audit, CONVERGED for converge),
executional (APPLIED for apply; SEALED for plan — a reviewer advised against SEALED
unless the artifact is "genuinely locked, authorized, immutable", which is
precisely what a hash-pinned Sealed Plan is, so the word stays), and procedural
OK for ledger-writing verbs (publish/adopt/unadopt/resume/repair/anchor). The
harder half of the decision is where green is BANNED: product verbs (hash,
export, hints, scenario, discover, forecast, deposed, explain) print no success
banner because their stdout is the deliverable and OK reads as part of the
product — and probe/observe stay silent for a sharper reason: a green word
there would claim the world is healthy when the verb only claims a measurement
was recorded. Success silence beats generic reassurance; the green vocabulary
must stay smaller than the failure vocabulary or success banners become a
second API.

Second: the channel. Verbs with a human stdout (text verify, converge) end it
with the banner; verbs with machine stdout (JSON/ndjson/product) emit one final
banner line on stderr — the prose channel, already unparseable by contract. A
zero exit with a stderr banner is normal. Machines keep routing on exit codes
and `code` fields; nothing about this is parseable.

Implementation: one central emitter in main (a named-return-side state:
verb, last machine code seen in printResult, hard-verdict rollup where the
verb has verdicts), because exit codes alone cannot pick VIOLATED vs BLOCKED
— verify and audit contribute their rollups. converge renders its own banner
in finish(), its single exit point, where the refusal code is in hand
(REFUSED must carry its code — bare REFUSED over-normalizes a heterogeneous
exit 2). The Python reference mirrors the same rules for its four verbs.
Conformance untouched (187/187 both impls), differential clean — nothing
semantic moved.

## D91. Verdicts name what they are about

A verify verdict carried the constraint id but not the constraint's subject and
path — so any downstream projection (the console, an agent) that wanted to join
"this verdict" to "that observation" had to either reload the contract or parse
the reason prose, and prose is unparseable by contract. Additive fix: every
verdict now carries `subject` and `path` (outputs.schema.json documents them,
both implementations emit them, differential pins their cross-impl identity).
The immediate consumer is the console's evidence-freshness join
(verdict → latest observation per (capability, path)); the general principle is
that machine consumers get join keys as fields, never as prose to mine.

## D92. Vendor selection is a bake-off, not an oracle

The ask was seductive: analyze the app's code, pick the optimal cloud, design
the architecture, mind cost and HA, keep it KISS. The design answer is that
every piece of it already has a home on one side or the other of the D49
authorship boundary, and none of it goes inside the runtime. Two new skills:

**code-to-contract** turns a repository into a contract DRAFT. The code is a
witness, not an author — it can testify the app speaks postgres and reads
REDIS_URL, not what the budget or the law is. The one failure mode the skill
is built around (independent review): "code mentions it" is not "production requires
it" — imports, dormant adapters, test fixtures and local-dev defaults all look
like dependencies. Guards: every inferred capability cites its evidence chain
(import + wiring config + runtime entrypoint) and only runtime-path
dependencies become capabilities; a contradiction pass (imports vs env vars vs
deploy manifests) turns conflicts into questions, not requirements; non-code
factors (traffic, budget, residency, compliance, vendor deals, team skills)
are asked once and recorded as declared, or enter assumptions: with confidence.

**bake-off** answers "which cloud" without an opinion: one candidate per
vendor WITH A DRIVER FAMILY (gcp, aws today; azure is honestly `unsupported`,
never mocked), verify + forecast on each, eligibility classified from the
verdicts (eligible / ineligible / blocked, deterministic reasons, eliminated
candidates stay visible), and a report split into hard gates / decision
drivers / non-differentiators / unknowns-and-probes. An independent reviewer contributed the
noise ban-list (feature counts, market share, ecosystem adjectives, benchmarks
untied to the workload, cost deltas inside the forecast's own uncertainty) and
the classification split; the human-picks rule was non-negotiable on our side:
the runtime may gate eligibility, the agent may summarize trade-offs, only the
human chooses — or amends the contract. KISS stays an authoring discipline
(each capability must name the constraint that needs it), never a runtime
feature. Honest refusals (D88) flip from annoyance to signal here: a vendor
refusing retention.locked IS the comparison.

The report ships as report.md for humans and report.json with a pinned shape —
the projection-ready artifact for the console and MCP agents (the console's
bake-off view is a next slice; the shape is stable from day one so it can
ingest without renegotiation). The missing piece for a three-way bake-off is
the Azure driver family — the D86 falsification pattern applies unchanged.

## D93. The survey: an encyclopedia is a cache, so it obeys the freshness rules

The ask was a RAG knowledge base of "key code findings" for the architecture
designer, built by a crawler. Two refusals shaped the answer. First: an index
of findings about code is a CACHE of observations, and this project exists
because caches of observations (tfstate) drift from reality and then lie —
so the survey is commit-pinned or it does not load (`repo.commit` mandatory;
findings are true AT a sha, never in general). Second: no embeddings. The
findings an architect needs are structural (dependency → evidence chain →
required|optional|dev-test|unknown), the agent already has exact-match access
to the code, and a vector layer would put approximation where exactness is
free. Structured index, full stop; embeddings return only if someone shows a
query the structure cannot answer.

What made the encyclopedia worth building is that it has a JOB: code↔contract
drift. spec/survey.md defines survey/v0.1 (the code-to-contract skill's
evidence table, persisted at .groundhold/survey/<sha>.json, one survey per repo —
multi-repo/microservice systems hand a SET of surveys to one comparison), and
`groundhold survey` is the deterministic comparator — the D53 hints precedent: an
external witness in, a report out, never a contract. Coverage rules encode the
project's epistemics: required+hint → covered/uncovered (uncovered is drift,
code survey-drift, exit 2); required without a hint, optional, unknown → gap
(a question, never silent drift); dev-test → ignored but reported. The other
direction is four-valued honesty applied to repos: a capability no survey
witnesses is UNWITNESSED information — another repo may be the consumer — and
hardens into orphaned drift only under an explicit --complete ("these surveys
are the whole system"). Absence of evidence is not evidence of absence unless
someone signs for completeness. Nine conformance cases pin all of it; the CI
shape is re-crawl on PR, compare against the published contract, exit 2 blocks
the merge until code and contract agree about reality again. Console
projection + a console_survey MCP tool are the declared next console slice.

## D94. Messaging topic: the residency lie and encryption-by-alias

The messaging.topic driver landed on BOTH clouds as a symmetric slice (AWS SNS,
GCP Pub/Sub), the fifth capability type proving D85/D86. A topic is a fan-out
publish address that holds nothing the author owns (subscribers own their
copies), so the vocab is deliberately thin — encryption/CMEK, residency,
exposure, managed, cost. Two decisions were load-bearing:

- **Pub/Sub residency is a message-storage policy, NOT the API host.** Pub/Sub is
  GLOBAL by default; a residency contract "satisfied" by a global topic would be
  a compliance lie. So create ALWAYS pins
  `messageStoragePolicy.allowedPersistenceRegions=[region]`, and observe REFUSES
  to report `location.region` for a topic with no storage policy (a diagnostic:
  "GLOBAL — no residency guarantee"), and refuses a multi-region policy (cannot
  map to one region). A global topic must never look like it satisfies residency.

- **SNS has no SSE without a KMS key.** `encryption.atRest=true` without CMEK is
  honored via the AWS-managed alias `alias/aws/sns` — genuine provider-default
  at-rest encryption, not a refusal. `customerManagedKeys=true` requires a real
  customer key (`implementation.kms_key_id`) and refuses both a missing key and
  `alias/aws/sns` (the managed key is not customer-managed). Unlike RDS, observe
  distinguishes them RELIABLY: SNS echoes the KmsMasterKeyId verbatim, so
  `alias/aws/sns` reads as provider-default and any other value as a CMEK — no
  second-service lookup needed. `encryption.atRest=false` is honestly honorable
  (SNS is unencrypted by default), unlike S3/GCS which always encrypt.

Public exposure is a second gate on each cloud: an SNS resource policy with
`Principal:"*"` for `sns:Publish` / an allUsers `roles/pubsub.publisher` IAM
binding (version-3 read-modify-write-confirm, the same honesty as Cloud Run/GCS).
Ownership is tags (SNS, at CreateTopic birth) / labels (Pub/Sub); a topic name is
account/project-scoped, so there is no S3-style global-namespace squat concern.
The usual D29/D87 honesty holds: deterministic names (so the pid is always
knowable), ambiguous mutation -> `unknown` WITH the pid, foreign/untagged ->
refuse (SNS untagged -> `unknown` reconcile, mirroring S3), 3xx never success.
In-place update stays unwired (topics are conservative/stateful); the four-valued
model does the rest.

## D95. Messaging queue: the constitutive composite, and one binding across an asymmetry

`capability.messaging.queue` (a durable backlog: submit, one consumer processes
each, destructively) lands on SQS and Pub/Sub. AWS maps it to a single SQS queue.
GCP has no standalone queue: a pull backlog is a Pub/Sub SUBSCRIPTION, which cannot
exist without a topic. That would be two resources for one capability — the exact
shape D88 forbids for an ATTRIBUTE. The resolution is the ECS precedent (D86,
`BuildECSRequests`: cluster→task-def→service under one binding): a CAPABILITY may
be a fixed, provider-specific resource SEQUENCE created/observed/retired atomically
under one ledger identity. So the GCP queue is a subscription (the providerId) plus
a CONSTITUTIVE backing topic, created in the same apply, retired in reverse. It is
not topology in a costume because the author never names or varies the topic — its
existence is a fixed consequence of "a queue on Pub/Sub," exactly as an ECS service
implies a task definition. The rule, stated: an attribute may never add a resource;
a capability may be a fixed composite. The partial-create honesty is the ECS one —
the deterministic pid rides from the first mutation, so a topic-landed-subscription-
lost outcome is unknown-with-pid, never succeeded.

Ordering and exactly-once are create-time-immutable on both clouds (SQS encodes
them in the `.fifo` name; Pub/Sub in immutable subscription flags), so a change to
either classifies as a replacement (D48) — and both capabilities are `stateful`, so
that replacement destroys in-flight data and needs `allow_replace_stateful` consent.
CMEK-without-a-key and residency (message-storage-policy, never the API region, D94)
carry the same honest refusals as the topic.

Honest limitation, recorded not hidden: `PermissionsFor` is keyed by (provider,
SERVICE, operation) — Pub/Sub is the first API family serving TWO capabilities
(queue and topic) under one service token, so the permission arm distinguishes them
by an ATTRS HEURISTIC (a queue is inferred from a queue-only attribute:
retention.minimum / delivery.guarantee / ordering.enabled). A degenerate queue that
declares none of those would emit the topic permission set — an omitted
`subscriptions.create`, i.e. the false-PASS direction the preflight exists to avoid,
bounded to a degraded preflight (create then fails honestly at runtime), never a
wrong outcome. The robust fix — distinct `pubsub-queue` / `pubsub-topic` service
tokens (as SQS/SNS already are), or plumbing the capability type into the target so
the permission key is exact — is a deferred hardening, tracked, not shipped as a
silent gap.

## D96. AWS in-place update: ClassifyChange + Update, dispatched per service

The AWS driver returned "not wired" for both `ClassifyChange` and `Update` — a
parity gap with GCP (D46), which meant every AWS drift compiled to a replacement
(D48) even when the provider could patch it in place. Closed by making both verbs
DISPATCH on the SERVICE token, exactly as Create/Observe/Delete already do (D76):
s3/sns/sqs/rds are wired; ecs/vpc stay honestly "unsupported" (mostly-immutable
resources — a silent "mutable" would be the dangerous lie).

`ClassifyChange` is PURE (no network): it returns mutable | immutable |
unsupported | caveated per path. What is create-time-only is immutable — an S3
bucket region/durability, an SNS/SQS region, an SQS FIFO name (`.fifo`, D48), an
RDS engine/version (a migration); what a re-assertable sub-resource PUT or a
Modify call can change is mutable — S3 versioning/lifecycle/default-encryption/
exposure, SNS policy+KMS, SQS retention/policy/SSE, RDS PubliclyAccessible/
BackupRetentionPeriod. RDS `availability.class` is `caveated` (a Multi-AZ
conversion is a brief failover, and the modify is async); `multi-regional` has no
single-instance mapping, so it is `unsupported`. Anything a service fixes at the
platform (S3 always-on at-rest encryption, RDS storage encryption + its KMS key)
is `unsupported` — never a false "mutable" that would seal an impossible patch.

`Update` re-checks ownership (tags) BEFORE mutating, then re-issues ONLY the
changed paths (the `changes` list), sourcing desired values from the SAME create
builders (`BuildS3Requests`/`BuildSNSCreate`/`BuildSQSCreate`) so an update and a
create speak identical XML/attributes and make identical encryption/exposure
choices. The "off" transitions a create never emits are handled explicitly:
versioning Suspended, default SSE-S3, a removed public policy (DELETE ?policy,
NoSuchBucketPolicy = already-private), SQS SSE cleared. Honesty is the D29/D87
discipline the create/delete paths already keep: a transport error or 5xx is
`unknown` WITH the providerId (the patch may have landed); a 4xx/3xx is `failed`
(a redirect is never success); an unreadable ownership tag read is `unknown`, a
mismatch/untagged resource is refused. RDS modifications are asynchronous
(ApplyImmediately), so an accepted 200 is success with the landed state left to a
later observe/converge — mirroring the accepted-delete precedent.

Pinned by two conformance cases (the AWS analogues of the Cloud SQL pair):
`aws-s3-plan-emits-update-for-mutable-drift` (versioning drift → one update
action) and `aws-s3-plan-refuses-immutable-drift` (region drift → consent-
required replacement), plus per-path ClassifyChange unit tests and httptest
Update tests (ownership re-check, patch, and every honesty branch) for all four
services. The update PermissionsFor arms (D75) were already present.

## D97. Secret handle: the thin capability, and the residency crown

`capability.secret` is deliberately the thinnest vocabulary yet: location.region,
network.publicExposure, encryption.atRest (const true), encryption.customerManagedKeys,
service.managed, cost.monthly — and nothing else. Everything a secret manager also
does is refused by construction, not by omission: the **value** is data supplied out
of band (never a declared attribute — groundhold creates a versionless handle and never
writes a version); **rotation** is the producer's job; **access** is IAM; **expiry**
and **retention** are lifecycle policy. Each has an explicit refusal in the builder so
a candidate that smuggles one in fails at compile, loudly, rather than silently
dropping it.

The crown is residency. Secret Manager (like Pub/Sub messageStoragePolicy) defaults to
AUTOMATIC, global replication — which carries **no** single-region guarantee. A
residency-honest create therefore refuses a missing location.region and pins a
`userManaged` replica in that region (with optional CMEK). Symmetrically, observe on an
automatic-replication secret refuses to report location.region at all and emits a
residency diagnostic — reading back a region we did not pin would be a residency lie.
Ownership is labels (groundhold-capability/groundhold-environment); a 409 continues only if
the existing secret is ours; delete pre-reads and refuses a foreign handle. GCP driver
first (internal/gcp/secretmanager*.go), D87 honesty-harness certified (create opaque —
name deterministic, response body not consumed — so the probe classifies mutations
RoleMutateOpaque). AWS Secrets Manager follows the same shape (internal/aws/
secretsmanager*.go) with the crown INVERTED: Secrets Manager is regional by
construction, so residency is honest with nothing to pin — observe reports the
region unconditionally (GCP must pin a userManaged replica or refuse the region).
CreateSecret is issued with no SecretString (the versionless handle); the name is
the idempotency key so create is opaque. Azure completes the 3-cloud symmetry
(internal/azure/secret_kv*.go) with the sharpest honesty wrinkle: Azure has NO
value-less secret handle — a Key Vault secret is a data-plane object that requires
a value on write. So the binding is the VAULT itself (Microsoft.KeyVault/vaults, a
constitutive parent carrying residency/exposure/encryption); the value is supplied
out of band and groundhold never writes it (the reserved secret name is surfaced in
the create result, never created). One honest one-cloud refusal:
encryption.customerManagedKeys on an Azure secret — Key Vault IS the key service,
so a vault's secret storage has no customer-CMK knob to set; the driver refuses and
says why rather than pretend. The three clouds thus provision the same thing — an
encrypted, in-region, exposure-controlled HOME for a secret whose value arrives out
of band — by three different resources (GCP Secret, AWS Secret, Azure Key Vault),
which is exactly the provider-agnostic thesis (D85) holding under real asymmetry.

## D98. Pub/Sub token-split: closing D95's deferred gap, and the latent dispatch bug it hid

D95 recorded an honest limitation: `PermissionsFor` guessed queue-vs-topic from an
attrs heuristic because Pub/Sub was the first API family serving two capabilities
under one `pubsub` service token, and called the robust fix (distinct tokens) a
deferred hardening "bounded to a degraded preflight, never a wrong outcome."

That assessment was incomplete. The same one-token conflation ran deeper than the
permission table: the GCP DRIVER decided queue-vs-topic by comparing its
`capability` argument to the literal string `"capability.messaging.queue"`
(driver.go Validate/Create/Observe, update.go Delete). But that argument is the
capability's ID, not its type — through the real apply path it is whatever the
author named the capability (e.g. `orders`), and the driver ALSO uses it as the
ownership label (`sanitizeLabel(capability)`). So a genuine Pub/Sub queue with a
normal id would be built as a TOPIC: a queue-exclusive attribute (delivery.guarantee)
would be refused by the topic builder, and a degenerate queue would silently become a
topic. It was masked because the honesty/unit tests passed the type string AS the
capability argument (conflating id and type), the metamorphic tests called the
internal `createPubSubQueue` directly, and no conformance case ran a full
pubsub-queue create through apply (GCP messaging is not live).

The fix is D95's own named robust option: distinct `pubsub-queue` / `pubsub-topic`
service tokens, exactly as AWS SNS/SQS and Azure servicebusqueue/servicebustopic
already are. The candidate declares the token; the compiler encodes it in the plan
target (`gcp.pubsub-queue/<capID>`); `serviceOf` recovers it at apply; the driver
and `PermissionsFor` both dispatch on the SERVICE token — the same signal, no guess,
no id/type conflation. The attrs heuristic (`isMessagingQueueAttrs`) is deleted.
Ownership labels are now the capability id, as everywhere else. A regression test
(`pubsub_dispatch_test.go`) validates a queue-exclusive attr through the queue token
and refuses it through the topic token, so the class cannot silently return. The
lesson generalizes: when one provider API serves two capabilities, split the service
token at the boundary — never discriminate on an argument whose meaning differs
between the test path and the apply path.

## D99. Azure: the third cloud, and the parent-resource inversion

Azure is the third provider — parity work: the same vocabularies, honored or
refused per Azure's shape. Auth is simpler than GCP (one ARM base, an AAD bearer
token from GROUNDHOLD_AZURE_ACCESS_TOKEN, JSON PUT + provisioningState polling); the
hard part is structural. Azure INVERTS the other two clouds: AWS and GCP put
capability semantics on the leaf resource you bind (the S3 bucket, the GCS bucket),
but Azure puts them on the PARENT — versioning, retention, CMK and exposure live on
the storage ACCOUNT; TLS, CMK and public access live on the SQL logical SERVER;
scaling and ingress live on the Container Apps ENVIRONMENT. Every mapping turns on
one question: is that parent CONSTITUTIVE (we create, name, tag, and retire it — the
pubsub-topic / ECS-cluster precedent, one binding) or IMPL-PROVIDED (the GCP-project
precedent — verify-or-refuse, never mutate someone else's resource)? The answer,
held as a line: constitutive for the storage account, the SQL server, the ACA
environment; impl-provided for the subscription and resource group, always. Sharing
a parent you did not create would convert every "honored" attribute into a silent
mutation of another team's account — the one move the whole system exists to refuse.

The first service is VNet (network.private) — the cleanest map. The binding is one
virtualNetworks resource with an inline subnet, plus a constitutive NSG (created
first when egress is restricted, referenced by the subnet) — the multi-resource
one-binding composite. location.region and egress.restricted (an NSG
DenyInternetOutbound rule + the subnet's defaultOutboundAccess=false) are honored;
ingress.public=true is refused (a fresh VNet has no gateway — private by
construction, the AWS/GCP posture); interconnect.private is refused as everywhere.
And flowLogs.enabled is REFUSED on Azure specifically: Azure flow logs are a
networkWatchers/flowLogs resource hanging off a subscription-level Network Watcher
singleton that ALSO requires a storage account destination — an attribute that would
add two resources, one subscription-scoped. GCP honors flow logs inline on the
subnet; Azure structurally cannot, so it refuses loudly rather than smuggling in
hidden infrastructure (the RDS-inTransit / S3-Object-Lock precedent).

Two forward risks the port must carry. Azure SQL Database speaks TDS only and is
evergreen (no version to pin), so it would refuse every postgresql/mysql contract
in the existing corpus — database.relational will map to PostgreSQL/MySQL Flexible
Server instead, with Azure SQL DB a later second service (D76). And the sharpest
one: Azure Policy's Modify / DeployIfNotExists effects ACCEPT a non-compliant create
and then MUTATE the resource minutes later (flip publicNetworkAccess, append tags) —
after the receipt is written and the post-create verify has passed. On AWS and GCP
org policy REJECTS the create (an error we refuse on); on Azure it drifts reality
out from under a receipt with no human in the loop. The D75 stance already fits — a
passing verify is evidence at time T, not proof — and a delayed re-observe on Azure
creates is the mitigation to add when the port goes live (no creds here yet, so the
Azure drivers are code + honesty-harness certified, never claimed live-proven).

## D100. Cache: the managed in-memory sibling of the relational database

`capability.cache.keyvalue` is the sixth capability domain and the fifth stateful
one — a managed in-memory key-value cache whose clean 3-cloud twin is Redis (GCP
Memorystore, AWS ElastiCache, Azure Cache for Redis). It is deliberately modelled
as the sibling of `capability.database.relational`, not a new shape: a managed
stateful data service carries residency (location.region), the same encryption
trio (atRest, inTransit, customerManagedKeys), availability.class, engine.protocol,
service.managed and cost.monthly. What a cache is NOT is the point — memory size,
node/instance type, shard/cluster count, replica count, and eviction policy
(maxmemory-policy) are all sizing/tuning, exactly the "instance tiers, disk types,
flags" the vocabulary discipline (D85/D60) rejects; they ride under
`implementation:` and the verifier ignores them.

Two honest boundaries drawn at the vocabulary, not discovered at apply: (1)
`engine.protocol` names redis/N as the tested 3-cloud path, but memcached has no
managed Azure twin, so a memcached candidate is an honest one-cloud GAP (refused on
Azure), never a silent two-cloud capability — the same stance as CMK on an Azure
secret (D97). (2) `availability.class = multi-regional` has no single managed Redis
primitive (it is app-level active/active or cross-region replication topology) and
is refused, never faked. `recovery.rpo` (snapshot/persistence cadence) is a real
feature but tier-gated and engine-specific across the three clouds, so it is
DEFERRED to a later slice with per-cloud refusals rather than shipped as a ledger
promise the driver cannot keep. `stateful: true` is the conservative-honest call: a
cache is softer than a database (its working set is reconstructible), but destroying
a production cache flushes it into a cold-start herd on the origin, so it earns
delete friction (D47). This entry is the design slice — vocab + dual conformance
cases; the GCP/AWS/Azure drivers follow, agnostic and symmetric, each with the full
builder/refusal/roundtrip/honesty-probe/CertifyDriver/metamorphic battery.

## D101. DNS zone: the authoritative envelope, records are data

`capability.dns.zone` is the seventh capability domain and the second thin,
"envelope" capability (after the secret, D97): a managed authoritative DNS zone
whose 3-cloud twin is GCP Cloud DNS, AWS Route 53, and Azure DNS. The discipline
that shapes it is the same one that shapes the secret: the RECORDS
(A/AAAA/CNAME/MX/TXT/…) are DATA, supplied out of band, never a declared
attribute. groundhold provisions the zone — its domain, its public/private reach,
whether it is DNSSEC-signed — and the record set is the operator's or app's to
fill, exactly as a secret's value or an object's bytes are. A vocabulary that
declared records would be a config-management tool smuggled into an
infrastructure contract; the refusal is the product.

The domain is the zone's identity (zone.domain), so a contract can require a
candidate be authoritative for exactly example.com. network.publicExposure is
genuine capability semantics that maps to DIFFERENT provider shapes — a flag on
GCP (visibility) and AWS (PrivateZone), but a SEPARATE resource type on Azure
(Microsoft.Network/dnsZones for public vs privateDnsZones for private), so the
Azure driver will dispatch the resource type on the exposure bit (a shape the
messaging/servicebus split already proved). Two honest boundaries stated at the
vocabulary: location.region is ABSENT — DNS is a global control plane, there is
no residency knob (a private zone's network associations are topology, carried
under implementation); and dnssec.enabled is a real security attribute, but on a
cloud whose DNSSEC needs an out-of-band key ceremony (Route 53's KMS-backed KSK)
a driver may honestly REFUSE it in v0 rather than half-configure — an honest
one-cloud gap, the same stance taken for RDS TLS enforcement and Azure secret
CMK. stateful: true because a zone owns records and IS the authority for a
domain; destroying it breaks resolution and loses the record set. This entry is
the design slice — vocab + a dual conformance case; the Cloud DNS / Route 53 /
Azure DNS drivers follow, agnostic and symmetric, each with the full battery.
(Numbered D101: D100 is the concurrent cache domain; the two merge adjacent.)

## D94. Verdicts name how they can be proven

Additive, the D91 pattern again: verdicts carry `verifyMethod` (static |
provider-api | probe). The consumer is the assumption-debt projection — the
discharging action for an unknown (run a probe vs record an observation vs
ask a human to declare) must be a field, never prose to mine. Both
implementations emit it; differential pins the identity.

## D102. Event signatures: authorship as a checkable property, opt-in and detached

The ledger's hash chain proves internal consistency — that nobody edited the
middle of the file — but not authorship: anyone who can write the file can
regenerate a perfectly consistent chain. For a single-host ledger that is
fine (filesystem trust is the boundary anyway). It stops being fine the
moment a ledger CROSSES a boundary: exported to a central console, handed to
an auditor, cited as evidence. That crossing is where "who said this?"
becomes a real question, and it is the foundation Evidence Capsules need.

Design, three commitments:

1. **Detached, excluded from identity.** The signature lives as a top-level
   `sig` sibling of `event`; `hash_event` strips it. A signature attests an
   event's identity — making it part of the identity would be circular
   (sign-then-hash) or fragile (hash-then-sign over mutated bytes). Signed
   and unsigned copies of one event share one hash, so the prev-chain, the
   anchors, and every existing projection are untouched. Pinned by a dual
   literal hash case; envelope well-formedness fail-closed at load (dual).

2. **Sign the canonical hash, not the line.** The message is
   `"groundhold/sig/v1:" + hash_event(doc)` — domain-separated so no other
   ed25519 use of the key can be replayed as an event attestation, and
   canonical so the attestation survives any byte-level re-serialization.
   Signing raw JSON lines would have made the Python and Go
   implementations' whitespace an attack surface.

3. **All-or-nothing trust.** `--trust <pub>` means "this whole file is
   authored by this key": an unsigned line under trust is tamper evidence
   (else stripping envelopes would be a working attack), a foreign valid
   signature is someone else's ledger, and both refuse on the corruption
   channel (exit 5), export included — the handover surface enforces what
   replay enforces. No per-line policy, no partial credit. Unsigned
   history without `--trust` owes nothing: signing is opt-in per process
   (`--sign-key`), and one choke point (commitUnderLock) signs every verb.

Honest threat model, stated in the spec: a verified file proves authorship
and order, not freshness or completeness — a signer can withhold a suffix.
Omission is countered by the D70 anchor held off-host, not by signatures.
`groundhold keygen` refuses to overwrite an existing key file: a signing
identity clobbered silently would orphan every signature it ever made.

## D103. Evidence capsules: proof that travels

The ledger's guarantees stop at the filesystem: to believe an export you must
trust the host it came from. D102 gave events authorship; this gives them
LEGS. An evidence capsule is a self-contained document — one capability's
event subchain verbatim, genesis to tip, plus the tip hash — verifiable by a
receiver with no ledger, no groundhold deployment and no trust in the sender's
filesystem: replay the prev[capability] linkage, recompute the hashes, check
the D102 signatures under --trust, and pin the tip against an anchor held
off-host (--check). spec/capsule.md; `groundhold capsule` emit/--verify.

Decisions worth recording:

- **The anchor's per-capability heads are what make subchains portable.**
  A capsule cannot carry the whole ledger (that is just "send the file"),
  and a bare subchain cannot prove it is the LATEST one. The D70 anchor
  already pins `heads[capability]` — so a receiver holding the anchor can
  verify a single capability's chain without any other capability's events.
  Multi-capability events travel verbatim: their other-cap prev entries are
  opaque here but integrity-bound (the event hash covers them), so they
  cannot be doctored without breaking the carried chain.
- **Emit replays first.** Cutting a subchain from an unvalidated file would
  launder corruption into a portable, official-looking document. The emitter
  enforces the same --trust it was armed with; a capability with no events
  refuses — an empty proof is a lie shaped like a document.
- **Omission is the anchor's job, stated out loud.** A verified capsule
  proves "this history, in this order, said this, as of asOf" — never "and
  nothing newer exists". The stale-capsule conformance case pins the honest
  failure: capsule cut, history advanced, anchor refreshed, --check refuses.
  Verification without --check still passes but reports anchorChecked:false
  — proving less and saying so, per the honesty rule.
- **asOf is recomputed, not believed** — a capsule claiming a different time
  than its tip event's occurredAt refuses. Refusals are corruption-class
  (exit 5), operator errors (unknown capability, malformed inputs) exit 1.

## D104. Authorization: a grant is a named role, never an inline policy

`capability.authorization.grant` is the tenth capability domain and the second half
of the IAM story D125 opened: there we built the principal (who a workload is),
here we grant it access (what it may do). It is the FIRST relational capability.
Every domain before it describes ONE resource's own attributes; a grant COMPOSES
two other subjects — a principal and a scope — into a binding, whose 3-cloud twin is
the GCP IAM policy binding, the AWS IAM role-policy attachment, and the Azure RBAC
role assignment. That composition is the design problem this entry resolves.

The resolution turns on invariant #4 (closed operator set: no expression language).
Authorization is where that pressure is sharpest, because the cloud-native form of a
grant is a POLICY DOCUMENT — actions, resources, conditions, effects, which is an
expression language with logical connectives by another name. So the domain admits
authorization ONLY as a reference to a NAMED role the provider already defines
(roles/storage.objectViewer, an AmazonS3ReadOnlyAccess policy ARN, the "Reader"
role), and the vocabulary describes the grant's VERIFIABLE SEMANTIC PROPERTIES
rather than its contents: access.scope (breadth — resource vs account) and
access.privileged (whether the role confers administrative power). Those two are
exactly what a least-privilege review checks, and both are statically verifiable
against a named role without interpreting a policy body. Authoring a CUSTOM role —
a permission set — is a different capability, deliberately deferred, and is where
the expression-language pressure would reappear; keeping it out preserves the
invariant. The relational operands the binding needs at apply time — the principal's
handle, and for a resource-scoped grant the scope resource id — ride in the free-form
implementation block (D26); the vocabulary carries the semantics, the impl carries
the concrete handles. v0 references a principal by handle; cross-capability
composition (a grant naming an identity declared in the same contract) is noted, not
built.

Two honesty moments the domain surfaces. access.scope=resource is REFUSED on AWS —
a managed-policy attachment is principal-scoped with the resource set inside the
policy, so resource-scoping there needs the inline policy v0 excludes; account is the
honest AWS breadth, an honest one-cloud gap. And access.privileged is measured at
observe by classifying grant.role against a curated set of well-known privileged
roles per cloud; a role OUTSIDE that set is left UNVERIFIABLE, not guessed — the
four-valued verdict is the honest answer to "is this custom role privileged?", where
a fabricated boolean would be a lie. stateful: false: a grant holds no data and
removing it loses none (it narrows access, re-grantable); the risk a grant carries is
on CREATE (privilege escalation), which access.privileged makes visible, not on
delete. This entry is the design slice — vocab + two dual conformance cases; the GCP
IAM binding / AWS role-policy attachment / Azure role assignment drivers follow, each
with the full battery. (Numbered D104: D124 encryption-key and D125 workload-identity
are the concurrent IAM-adjacent domains; they merge in order.)

## D105. Custom role: a permission set is data, not an expression language

`capability.authorization.role` is the eleventh capability domain and the definition
side of authorization: D104 assigns a role to a principal, this DEFINES one. It is
the domain where invariant #4 (closed operator set — no expression language in
constraints) is under the most pressure, because a role's cloud-native form is often
a policy document: actions, resources, conditions, effects, logical connectives — an
expression language by any name. The resolution is the entry's whole point. A role is
admitted as a flat SET OF NAMED PERMISSIONS and nothing more. A set of permission
strings has no connectives, no interpolation, no conditions — it is data, exactly
like capability.identity.oauth-client's scopes.granted (D55), and groundhold already
types it: role.permissions is a `list` attribute, and the existing `subset-of`
operator makes `role.permissions subset-of <allowlist>` a real, deterministic
least-privilege guarantee — the role grants ONLY approved permissions, proven
statically. What is REFUSED is precisely what reintroduces the expression language:
resource scoping inside the policy (that belongs to the grant's scope, D104),
conditions, Deny/notActions, effects. Deferring them is not a limitation to apologize
for; it is what lets a custom role be a first-class verifiable contract subject
instead of an opaque blob.

Two derived safety semantics ride alongside the raw set, because a contract author
often wants a guarantee without enumerating an allowlist. access.mutating is true iff
any permission is a write/create/update/delete action (a read-only role is a common
least-privilege target); access.privileged is true iff the set confers IAM/admin
CONTROL — the power to grant further access (setIamPolicy, iam:*, a wildcard), the
sharpest escalation signal. Both are DERIVED deterministically from the action verbs
by the driver, which refuses a candidate that declares a false read-only or
unprivileged claim, and leaves access.privileged UNVERIFIABLE for a set it cannot
classify (never guessed — the four-valued answer). The 3-cloud twin builds the same
flat set into each native form: a GCP custom role's includedPermissions, an AWS
customer-managed policy's single Allow statement (Resource "*"), an Azure custom
roleDefinition's permissions[].actions — and each refuses the non-flat extras.
stateful: false: a role holds no data and is re-creatable from its set; the risk is
on DEFINITION (an over-broad set), which the attributes make visible, not on delete.
This entry is the design slice — vocab + two dual conformance cases (a least-privilege
subset-of that passes and an over-permissioned one that violates, so the guarantee
demonstrably has teeth); the GCP custom role / AWS customer policy / Azure custom
roleDefinition drivers follow, each with the full battery. (Numbered D105: the concurrent IAM-adjacent domains are D124 encryption-key,
D125 workload-identity, and D104 authorization-grant; they merge in order.)

## D106. Metric alert: one metric, one threshold — compound logic is refused

`capability.monitoring.alert` is the twelfth capability domain and the first
OBSERVABILITY one: every capability before it provisions a resource that DOES
something; an alert watches one. The 3-cloud twin is the GCP Monitoring alerting
policy, the AWS CloudWatch alarm, and the Azure Monitor metric alert, and the
vertical slice is deliberately ONE metric crossing ONE threshold. That
single-condition shape is not merely simplicity — it is invariant #4 once more. A
COMPOUND alert (several conditions joined by AND/OR) is a logical expression, and the
domain refuses it the same way the authorization domains (D104/D105) refused inline
policy: complexity is more alerts, never a boolean expression inside one. Anomaly
detection and dynamic thresholds are refused too — there is no static threshold to
verify, so the honest treatment is a probe, not a config assertion.

The verifiable core is small and universal: alert.metric (which metric), alert.threshold
(a plain number the metric must cross — the unit is the metric's), alert.comparison (a
closed enum, above or below), and alert.notify — the safety property that catches the
single most common alerting misconfiguration, an alert that fires but tells nobody.
notify=true requires a concrete channel (implementation.notification_channel); the
driver refuses notify=true with no channel rather than creating a silent alert that
claims to notify. The notification TARGET itself — a channel, an SNS topic, an action
group — is a separate resource the alert REFERENCES via the implementation block, not
one it owns; a future slice may let an alert reference a capability.messaging.topic
declared in the same contract (the SNS twin is already a capability), noted, not built.
stateful: false — an alert holds no data and is re-creatable from its definition; the
risk it carries is the silent one, which alert.notify makes visible, not deletion.
This entry is the design slice — vocab + two dual conformance cases; the GCP alerting
policy / AWS CloudWatch alarm / Azure metric alert drivers follow, each with the full
battery. (Numbered D106: D102–D105 are the concurrent IAM/authorization domains; they
merge in order.)

## D107. Dashboard: a set of charted metrics, not an arbitrary canvas

`capability.monitoring.dashboard` is the thirteenth capability domain and the
observability sibling of the metric alert (D106): an alert watches a metric and
fires, a dashboard displays metrics for a human to read. The 3-cloud twin is the GCP
Monitoring dashboard, the AWS CloudWatch dashboard, and the Azure Portal dashboard,
and the domain's whole design problem is that a dashboard's cloud-native form is a
free-form LAYOUT of widgets — positions, chart types, text panels, log queries — the
same free-form content category as a policy document (D105) or an alert's compound
condition (D106). So the vocabulary admits a dashboard as a flat SET of metrics to
chart (dashboard.metrics, a `list`, verifiable with subset-of exactly as a custom
role's permission set is), each rendered as one auto-laid-out widget, and describes
the one property a contract actually wants to guarantee: that the dashboard is NOT
EMPTY. dashboard.widgetCount is that safety semantic — an empty dashboard, created but
never populated, is a common mistake, so a contract asserts widgetCount gte 1; the
count is derived from the metric set and the driver refuses a declared count that
contradicts the metrics it was given (the same false-claim refusal as
access.mutating). Rich custom widget authoring — hand-placed tiles, text/markdown,
log-query widgets, templating variables — is REFUSED, the boundary the authorization
and alert domains already drew: a dashboard here is "these metrics, charted",
auto-laid-out, not an arbitrary canvas, and the free-form layout is data, out of
scope. stateful: false — a dashboard is a display artifact, re-creatable from its
metric set; the risk it carries is emptiness, which widgetCount makes visible, not
deletion. This entry is the design slice — vocab + two dual conformance cases (a
non-empty scoped dashboard that passes and an empty one that violates, so the
guarantee has teeth); the GCP / AWS / Azure dashboard drivers follow, each
auto-generating one chart widget per metric, with the full battery. (Numbered D107:
D102–D106 are the concurrent IAM/authorization/monitoring domains; they merge in
order.)

## D108. Uptime check: honest per-cloud gaps in protocol and period

`capability.monitoring.uptime` is the fourteenth capability domain and the third
observability one, alongside the alert (D106) and the dashboard (D107): an alert
watches an internal metric, a dashboard displays metrics, an uptime check probes a
service FROM OUTSIDE to answer "is it reachable?". The 3-cloud twin is the GCP
Monitoring uptime check, the AWS Route 53 health check, and the Azure Application
Insights availability test. The verifiable core is small and universal — what is
probed (check.target), how (check.protocol), the path (check.path), and how often
(check.period) — but the domain earns its place as a showcase of HONEST PER-CLOUD
GAPS, because the three clouds disagree sharply on two axes and the honest answer to
that disagreement is a refusal, not a coercion. Protocol: GCP and Route 53 probe
HTTP/HTTPS/TCP, but an Azure availability test is HTTP(S)-only, so check.protocol=tcp
is refused on Azure. Period: Route 53 permits only a 10s or 30s interval, GCP permits
60s/300s/600s/900s, and Azure permits 300s/600s/900s — so a check.period the target
cloud cannot honor is refused there rather than silently rounded to the nearest
allowed value (a round would make the verifier's "period lte 30s" pass while the real
check fired every 60s — a lie). A contract asking for a 30s HTTPS check is satisfiable
on GCP and Route 53 and refused on Azure, and both outcomes are correct. check.path is
refused for a tcp check (a bare port connect has no path). The alert ON failure is a
separate capability.monitoring.alert (D106) that references the check — v0 keeps the
probe and the alert apart, composition deferred. stateful: false — a check is a probe
config, re-creatable; the risk it carries is being too infrequent to catch an outage,
which check.period makes visible, not deletion. This entry is the design slice — vocab
+ two dual conformance cases; the GCP uptime check / Route 53 health check / Azure
availability test drivers follow, each enforcing its own allowed periods and
protocols, with the full battery. (Numbered D108: D102–D107 are the concurrent

## D109. Log-based metric: an opaque filter, a verifiable identity and kind

`capability.monitoring.logmetric` is the fifteenth capability domain and the fourth
observability one, after the alert (D106), the dashboard (D107) and the uptime check
(D108): where those watch, display and probe, a log-based metric MANUFACTURES a metric
out of logs — count the ERROR lines, extract the latency field. The primary 3-cloud
twin is the GCP Cloud Logging log-based metric and the AWS CloudWatch Logs metric
filter, both of which turn a log filter into a continuous metric stream. Azure has no
continuous metric-from-logs primitive, and rather than fake one the domain names the
honest realization: an Azure scheduled query rule that EVALUATES the same query on a
schedule instead of streaming — a genuine per-cloud shape difference stated, not hidden,
the same posture the uptime domain took toward Azure's HTTP-only availability tests.

The design turn is how the filter is treated. A log filter is a query expression, and
interpreting it — offering operators, connectives, sub-conditions over it — would be the
expression language invariant #4 forbids. So groundhold treats the filter as OPAQUE DATA:
metric.filter is a string it passes straight through to the provider and never parses,
and a contract can only pin it with equals ("the metric filters exactly this query").
What groundhold does verify is the metric's IDENTITY (metric.name) and its KIND
(metric.kind, a closed counter|gauge enum), because that is what a contract actually
wants to guarantee — that an error-count metric exists and that it counts rather than
silently measures the wrong thing. gauge extracts a value from a field, which field is
implementation detail (implementation.value_field, required for gauge); the log source
(a log group on AWS, a Log Analytics scope on Azure) is topology in the implementation
block, not capability semantics. The alert or dashboard built ON the metric is a
separate capability (D106/D107) that references it by name — v0 keeps manufacture and
consumption apart. stateful: false — the rule owns nothing durable; historical points
age out of the metric store. This entry is the design slice — vocab + two dual
conformance cases; the GCP log metric / AWS metric filter / Azure scheduled query rule
drivers follow, each with the full battery. (Numbered D109: D102–D108 are the concurrent
IAM/authorization/monitoring domains; they merge in order.)

## D110. Container image registry: two honest per-cloud gaps

`capability.registry.image` is the sixteenth capability domain, the first outside the
IAM/authorization/observability run — a managed container image registry, whose 3-cloud
twin is GCP Artifact Registry, AWS ECR, and Azure Container Registry. A registry is a
managed stateful data service (it holds image layers), so it reuses the storage family's
residency / exposure / customer-key attributes verbatim — the cross-vocabulary
consistency the project prizes — and adds one supply-chain semantic of its own:
immutable.tags, the guarantee that a pushed tag (v1.2.3) can never be silently repointed
at different bytes. That guarantee is the domain's reason to exist beyond "another
managed resource", and a dual case proves it has teeth (a mutable-tags registry violates
immutable.tags equals true).

The domain earns its place as a clean two-gap showcase. A public registry
(network.publicExposure=true) is REFUSED on AWS, because an ECR private registry cannot
be made public — public pull is AWS's separate ECR Public service, a different resource,
so honoring public here would bind the wrong thing. And immutable.tags is REFUSED on
Azure, because ACR has no registry-level tag-immutability toggle (immutability there is
per-repository policy), where GCP Artifact Registry (dockerConfig.immutableTags) and AWS
ECR (imageTagMutability) both expose it as a flag. A contract asking for a public,
immutable-tag registry is honored on whichever cloud supports each and refused on the
one that does not — the same honest-gap posture memcached (cache, D100) and Azure's
HTTP-only availability tests (uptime, D108) took. stateful: true is literal: destroying a
registry loses its image layers and can break every deployment that pulls from it. This
entry is the design slice — vocab + two dual conformance cases; the Artifact Registry /
ECR / ACR drivers follow, agnostic and symmetric, each with the full battery. (Numbered
D110: D102–D109 are the concurrent IAM/authorization/monitoring domains; they merge in
order.)

## D111. Filesystem: the managed network file share, one honest per-cloud gap

The breadth track's sibling to storage.object (D60) and the cache/DNS domains
(D100/D101): a managed, regional NETWORK FILE SHARE — GCP Filestore, AWS EFS,
Azure Files. Same stateful residency/encryption/availability spine as the other
data services, but the medium is a mounted POSIX/SMB filesystem, so it adds a
`protocol` scalar and refuses the same implementation noise (capacity GiB,
throughput mode, performance/service tier, mount-target topology). One boundary
is stated honestly at the vocabulary rather than faked — a per-cloud gap the
driver enforces as a build-time refusal:

  protocol smb/N is REFUSED on GCP (Filestore, NFS-only) and AWS (EFS,
  NFSv4.1-only) — neither has a managed SMB filesystem (that is AWS FSx for
  Windows, and GCP has no twin). SMB is an Azure-only capability; nfs/N is the
  3-cloud path. The same one-cloud-gap stance as memcached on the cache domain.

Azure Files does NOT force a second gap: because Azure puts a file share under a
storage account (the D99 Blob pattern), the driver creates that account as a
constitutive composite (account + fileServices/default + share, one binding) —
so it honors BOTH smb and nfs (NFS via a Premium FileStorage account) AND
customer-managed keys (account Key Vault encryption covers the share). Filestore
and EFS carry CMK on the filesystem itself (kmsKeyName / KmsKeyId).

network.publicExposure is deliberately ABSENT in v0.1: EFS and Filestore are
VPC-private always, while Azure Files is reachable through a public account
endpoint gated at the account (not the share), so no honest uniform bool exists
at the share level — deferred to a later slice with per-cloud honesty rather than
a promise the ledger cannot keep. availability.class is a closed enum
[zonal, regional] uniform across the three (Filestore tier, EFS OneZone vs
Standard, Azure LRS vs ZRS). This entry is the design slice — vocab + two dual
conformance cases (a full verify and the enum-guard); the Filestore / EFS / Azure
Files drivers follow, agnostic and symmetric, each with the full battery.

## D112. NoSQL database: the managed document store, one honest per-cloud gap

The breadth track's managed NoSQL document/key-value database — AWS DynamoDB,
Azure Cosmos DB, GCP Firestore (a NAMED database; Firestore now supports multiple
named databases per project, so it is a first-class creatable resource, no longer
one-per-project). The stateful sibling of database.relational and cache.keyvalue,
so it carries the same residency/encryption/durability spine and refuses the same
implementation noise (partition-key schema, secondary indexes, throughput/RU/RCU
capacity, TTL). Two boundaries are stated honestly at the vocabulary:

  1. deletion.protection=true is REFUSED on Azure Cosmos DB — Cosmos has no
     account-level deletion-protection property; deletion is guarded by a SEPARATE
     Microsoft.Authorization management lock, out of this single resource's scope.
     DynamoDB (DeletionProtectionEnabled) and Firestore (deleteProtectionState)
     carry it as a flag on the resource itself. The characteristic per-cloud gap,
     the same stance taken for SMB on the filesystem domain.
  2. availability.class=multi-regional is refused in v0 across ALL three (global
     tables / multi-region writes / multi-region locations are a heavier
     multi-resource setup) — an honest "not yet", uniform, never a single-region
     database pretending to span regions. regional is the 3-cloud path.

The consistency model is deliberately ABSENT: the three expose fundamentally
different knobs (DynamoDB per-read eventual/strong, Cosmos five levels, Firestore
strong), so no honest uniform enum exists yet. Firestore is the interesting
driver: its Database resource carries NO labels, so ownership is CONTENT-ADDRESSED
(the deterministic databaseId, a hash of project|environment|capability, is the
proof a resource is ours — the same tagless-ownership discipline as a
content-addressed store). This entry is the design slice — vocab + two dual
conformance cases (a full verify and the enum-guard); the DynamoDB / Cosmos DB /
Firestore drivers follow, agnostic and symmetric, each with the full battery.

## D113. Search index: the managed search service, an honest two-cloud twin

A managed full-text search service — AWS OpenSearch Service and Azure AI Search.
This is the first deliberately TWO-CLOUD breadth domain: GCP has no managed
search-service twin (Vertex AI Search is an ML/RAG product, not an operable
search cluster), so a gcp candidate is REFUSED by fail-closed dispatch (the gcp
driver has no search service token), never a faked third mapping. The
agnostic+symmetric discipline (memory: every domain on all clouds where the twin
exists) is honored precisely by NOT manufacturing a GCP mapping that would lie —
the same stance as memcached (no Azure twin) and SES (no GCP twin), applied at
the domain level. Residency, exposure, availability.class [zonal, regional] and
at-rest/in-transit/customer-managed encryption are the capability; node type,
shard/replica/partition counts, index schema and analyzers are implementation
noise. encryption.atRest and encryption.inTransit are true-only (both twins are
always-encrypted / TLS-only; false is refused, never a silent downgrade).
availability.class maps to OpenSearch zone-awareness and to the Azure SKU floor
(Standard + >=3 replicas is zone-redundant; Basic is single). engine.protocol is
deliberately absent — OpenSearch exposes opensearch/N but Azure AI Search is a
proprietary engine with no compatible protocol version, so there is no honest
uniform value. This entry is the design slice — vocab + two dual conformance
cases (a full verify and the enum-guard); the OpenSearch and AI Search drivers
follow, each with the full battery.

## D114. Streaming pipe: the managed record stream, an honest two-cloud twin

A managed record STREAM — a partitioned, ordered, replayable append log with a
retention window — AWS Kinesis Data Streams and Azure Event Hubs. Distinct from
capability.messaging.topic (D60): a topic is fan-out pub/sub (deliver-then-gone);
a stream is a durable log consumers read at their own offset within a retention
window. Like search (D113), this is deliberately TWO-CLOUD: GCP has no clean
managed streaming twin — Pub/Sub Lite (the closest) is deprecated, and Managed
Service for Apache Kafka is a different Kafka-cluster model, not a single stream
resource — so a gcp candidate is refused by fail-closed dispatch, never a faked
third mapping. Residency, retention.window (a replay guarantee, not sizing),
availability.class [zonal, regional] and customer-managed encryption are the
capability; shard/partition count, throughput/capacity mode and consumer
registrations are implementation noise. availability.class carries a per-cloud
honesty nuance stated at the vocabulary: zonal is honored only on Azure (a
non-zone-redundant namespace); on AWS it is REFUSED, because a Kinesis stream is
always regionally/multi-AZ replicated and a zonal claim would misrepresent it —
the driver refuses rather than silently upgrading. Azure Event Hubs is a
namespace+entity composite (the servicebus D-shape): the namespace carries the
SKU / zone-redundancy / CMK, the event hub carries partitions and retention. This
entry is the design slice — vocab + two dual conformance cases (a full verify and
the enum-guard); the Kinesis and Event Hubs drivers follow, each with the full
battery.

## D115. Managed Kafka: a genuine three-cloud twin, restoring symmetry

A managed Apache Kafka cluster — the wire protocol is Kafka, so unmodified Kafka
tooling connects. After two honest two-cloud domains (search D113, streaming
D114), this restores full 3-cloud symmetry: AWS MSK, GCP Managed Service for
Apache Kafka (GA 2024), and Azure Event Hubs with the Kafka endpoint enabled.
Deliberately distinct from both neighbours: messaging.topic (D60) is provider-
native pub/sub, and streaming.pipe (D114) is a provider-native record stream —
messaging.kafka is specifically "a Kafka broker my existing Kafka clients talk
to". Residency, engine.protocol (kafka/N — the version honored where exposed:
MSK KafkaVersion; managed-and-validated on GCP/Azure), availability.class
[zonal, regional], in-transit TLS (true-only, all three enforce it) and
customer-managed encryption are the capability; broker count, instance sizing,
storage volume and client-auth mechanism are implementation noise. availability.
class carries the same per-cloud honesty nuance as streaming: zonal is honored
only on Azure (a non-zone-redundant namespace); on MSK and GCP Managed Kafka —
both always multi-AZ — it is refused rather than silently upgraded. The three
drivers span all three protocol shapes: MSK is a REST-JSON control plane with a
server-assigned cluster ARN recovered by the deterministic name; GCP Managed
Kafka is an LRO create keyed on a deterministic clusterId with label ownership;
Azure Event Hubs Kafka is a single namespace with kafkaEnabled (a lighter cousin
of the streaming composite). This entry is the design slice — vocab + two dual
conformance cases (a full verify and the enum-guard); the drivers follow, each
with the full battery.

## D116. WAF policy: a managed edge firewall, opaque rules by construction

A managed Web Application Firewall policy — AWS WAFv2 (a CLOUDFRONT-scope WebACL),
Azure Front Door WAF policy, and GCP Cloud Armor security policy: a genuine
three-cloud L7 security twin. The design point is invariant #4 (closed operator
set) made concrete: a WAF is exactly the kind of resource that tempts a rule
expression language, and the vocabulary refuses it. policy.mode
[prevention, detection], managed.ruleset (the provider's OWASP/common baseline)
and bot.protection (managed bot/adaptive-protection) are the capability — each a
mode or a boolean "is this managed rule set on". The actual rule DEFINITIONS,
rate-limit thresholds, IP lists and priorities are OPAQUE config carried under
`implementation:`, passed through and never parsed. location.region is absent:
this slice is the edge/global policy (the dns.zone stance) — a regional WAF is a
later slice. stateful is FALSE — a WAF policy holds no data, so retirement carries
no D47 data-loss friction. The three drivers span three ownership models: WAFv2 is
a JSON control plane with a server-assigned Id + LockToken recovered by the
deterministic name via ListWebACLs (tag ownership); Front Door WAF is an ARM PUT
(tag ownership); Cloud Armor is a compute global-operation LRO whose securityPolicy
carries no labels, so ownership is a DESCRIPTION MARKER (the tagless-content
discipline again, here in a description field rather than a name). This entry is
the design slice — vocab + two dual conformance cases (a full verify and the
enum-guard); the drivers follow, each with the full battery.

## D117. Managed TLS certificate: an honest two-cloud twin, the key excluded

A managed, auto-renewed TLS certificate — AWS ACM (a public certificate) and GCP
Certificate Manager (a managed certificate). Like search (D113) and streaming
(D114), a deliberately TWO-CLOUD domain: Azure has no MANAGEMENT-PLANE managed-cert
twin — Key Vault certificates are data-plane (the vault.azure.net endpoint, a
different auth surface than the ARM bearer token this runtime speaks) and App
Service managed certs are coupled to a plan — so an azure candidate is refused by
fail-closed dispatch, never faked. The domain, validation.method [dns, email] and
auto.renew are the capability; SANs and key algorithm are implementation detail.
Two boundaries are stated honestly at the vocabulary: validation.method=email is
honored only on AWS ACM (GCP Certificate Manager validates via DNS authorization
or the attached load balancer, never email); and auto.renew is true-only — a
managed certificate auto-renews by definition, and false (a manually-renewed /
imported cert) is a self-managed cert out of scope, with the further constraint
that auto-renewal REQUIRES dns validation (an email-validated ACM cert cannot
auto-renew). The certificate's PRIVATE KEY is never a groundhold concern (secrets
structurally excluded, D53): groundhold declares "a valid, auto-renewed cert for this
domain exists", and the key material stays with the provider. Both drivers use the
server-assigned-id pattern: ACM is a JSON control plane whose CertificateArn is
recovered by a deterministic IdempotencyToken + domain/tag match; Certificate
Manager is an LRO keyed on a deterministic certificateId with label ownership.
This entry is the design slice — vocab + two dual conformance cases (a full verify
and the enum-guard); the ACM and Certificate Manager drivers follow.

## D118. CDN distribution: an edge resource, cache behaviors opaque

A managed CDN distribution — AWS CloudFront and Azure CDN. Like search (D113),
streaming (D114) and certificate (D117), a deliberately TWO-CLOUD domain: GCP
Cloud CDN is not a standalone resource — it is a FLAG (enableCdn) on a backend
service, coupled to a load balancer and URL map — so it cannot be modelled as a
single edge resource, and a gcp candidate is refused by fail-closed dispatch. The
invariant-#4 discipline recurs (as it did for WAF): a CDN's cache behaviors — path
patterns, TTLs, header/cookie forwarding, geo restrictions, custom error pages —
are exactly the kind of thing that tempts an expression language, and the
vocabulary refuses. It exposes only origin.domain and viewer.protocol
[https-only, redirect-to-https, allow-all]; everything else is opaque config under
`implementation:`. location.region is absent (edge/global, the dns.zone stance),
and the edge TLS certificate is a SEPARATE capability (D117) referenced by impl,
not inlined. viewer.protocol carries a per-cloud nuance: redirect-to-https is
native on CloudFront but refused on Azure classic CDN (a redirect needs a
Standard-profile delivery rule, out of this single-endpoint slice) — refused, not
silently downgraded. The drivers: CloudFront is a REST-XML global control plane
with a server-assigned Id + CallerReference idempotency + ETag concurrency, whose
delete surfaces (never forces) the disable-before-delete precondition; Azure CDN is
a profile+endpoint composite (the servicebus shape). stateful is false — a CDN
holds a cache, not data. This entry is the design slice — vocab + two dual
conformance cases (a full verify and the enum-guard); the drivers follow.

## D119. HTTP API gateway: a routable front door, routes opaque

A managed HTTP API gateway — AWS API Gateway v2 (an HTTP/WebSocket API) and Azure
API Management. Like search (D113), streaming (D114), certificate (D117) and cdn
(D118), a deliberately TWO-CLOUD domain: GCP API Gateway is not a single resource —
a serving gateway is an api + apiConfig + gateway chain, and the apiConfig requires
an OpenAPI document (opaque, out of the single-resource model) — so a gcp candidate
is refused by fail-closed dispatch. The invariant-#4 discipline recurs (as for WAF
and CDN): a gateway's routes, integrations, authorizers, request/response mappings
and rate limits are exactly what tempts an expression language, and the vocabulary
refuses — it exposes only location.region and protocol [http, websocket]. protocol
carries a per-cloud nuance: websocket is a first-class apigatewayv2 API on AWS but
refused on Azure APIM (no service-level websocket primitive) — refused, not
silently downgraded. The custom-domain TLS certificate is a SEPARATE capability
(D117). stateful is false — a gateway holds routing config, not data. The drivers:
apigatewayv2 is a clean REST-JSON control plane with a server-assigned ApiId and
inline tags; APIM is an ARM PUT (a Consumption-tier service, publisher email/name
required). This entry is the design slice — vocab + two dual conformance cases (a
full verify and the enum-guard); the drivers follow.

## D120. Container job: run-to-completion, the AWS gap this time

A managed run-to-completion container job — GCP Cloud Run Jobs and Azure Container
Apps Jobs. Distinct from capability.workload.container (D60), which is a
long-running SERVICE: a job runs a task and exits. Like the other honest two-cloud
domains, but the gap is on the AWS side this time: AWS has no standalone managed-job
resource — Batch is a job-definition + queue + compute-environment composite and an
ECS RunTask is an ephemeral action, neither a single durable job resource — so an
aws candidate is refused by fail-closed dispatch. Image, trigger.type
[manual, schedule] and timeout are the capability; the cron expression, env vars,
command/args, resource limits, retry count and (on Azure) the managed-environment
substrate are opaque implementation config (invariant #4). trigger.type carries the
per-cloud nuance: schedule is a native Container Apps Jobs trigger but refused on
Cloud Run Jobs (native jobs are manual-run; scheduling needs a separate Cloud
Scheduler resource, out of the single-resource scope) — refused, not silently
dropped. stateful is false — a job holds execution config, not data. The drivers:
Cloud Run Jobs is an LRO keyed on a deterministic jobId with label ownership (the
cloudrun-service shape); Container Apps Jobs is an ARM PUT into a required managed
environment, with tag ownership. This entry is the design slice — vocab + two dual
conformance cases (a full verify and the enum-guard); the drivers follow.

## D121. Machine identity: a three-cloud twin, the key excluded, no forced enum

A managed machine identity — GCP service account, AWS IAM role, and Azure
user-assigned managed identity. A genuine THREE-CLOUD twin (restoring symmetry after
a run of honest two-cloud domains). Two design points. First, D53 (secrets excluded)
draws the one honest boundary: key.exportable is a bool and true — a downloadable
long-lived private key — is REFUSED on all three, because a private key is a secret
groundhold must never manage; the keyless path (workload identity / an assumed role / a
managed identity) is the only one this capability provisions, and it is the secure
default anyway. Second, this is the first domain with NO natural closed enum — a
machine identity has nothing like a database's availability class or a WAF's mode.
Rather than force a synthetic enum (which would itself be a small lie), the two dual
conformance cases are a full verify plus a KIND-MISMATCH load error: the type system
(key.exportable declared as a non-bool refuses at load, D19) stands in for the
enum-guard. The enum-guard is a convention, not a law. This domain is IDENTITY, not
authorization: what the identity may DO — its trust policy, attached roles, policy
bindings — is opaque config under `implementation:` (invariant #4). location is
absent (identities are global/project/account principals; an Azure managed identity's
region is impl topology). The three drivers span three shapes: GCP is a synchronous
serviceAccounts.create with DESCRIPTION-marker ownership (SAs carry no labels); AWS
is a global Query-protocol CreateRole with tag ownership; Azure is an ARM PUT of a
userAssignedIdentity with tag ownership. All three ship in this slice — vocab, the
two dual conformance cases, and the three drivers with D87 honesty harnesses and D75
permission arms.

## D122. Data warehouse: an honest two-cloud twin, the admin credential excluded

A managed analytics warehouse — GCP BigQuery (a dataset) and AWS Redshift Serverless
(a namespace + workgroup). Deliberately TWO-CLOUD, not three, and the boundary is
principled, not cosmetic: the closest Azure analogue, a Synapse workspace, cannot be
created without a SQL administrator PASSWORD — a secret groundhold must never manage or
transit (D53) — and a pre-existing ADLS Gen2 storage substrate. There is no keyless
create path, so Azure is refused at DISPATCH (no service token, fail-closed) and the
refusal is the honest answer (the D120 container-job two-cloud precedent). BigQuery
and Redshift Serverless both create with IAM auth alone; neither is handed a
credential.

Three design points. First, it is a stateful data service (tables and rows ARE the
data), so `stateful: true` and retirement is deletion-gated (D47) exactly like
storage.object and registry.image — and both drivers refuse to silently drop data:
BigQuery deletes WITHOUT deleteContents (a non-empty dataset refuses), Redshift takes
no final snapshot only because the D47/`--allow-data-loss` gate upstream already
authorized the loss. Second, TWO honest per-cloud gaps the vocabulary surfaces rather
than smooths: network.publicExposure is honored on AWS (a workgroup's
publiclyAccessible flag is genuine network reachability) and REFUSED on GCP (a
BigQuery dataset has no network boundary — it is reached through the global
bigquery.googleapis.com endpoint and gated by IAM, so mapping it to an allUsers grant
would answer a different question); and there is no natural closed enum on a warehouse
resource (BigQuery editions are reservation-level, Redshift base capacity is sizing
noise), so the enum-guard dual conformance case is a KIND-MISMATCH load error (D121
precedent) — the type system stands in for the enum-guard. Third, the shapes differ:
BigQuery is a synchronous datasets.insert with LABEL ownership (project-scoped, no D82
squat concern); Redshift Serverless is a COMPOSITE under one binding — CreateNamespace
(data + CMK) then an async CreateWorkgroup (compute + publiclyAccessible) polled to
AVAILABLE, TAG ownership read via ListTagsForResource against the live ARN. Both ship
with a D87 honesty harness and D75 permission arms; customer-managed-key ids and
compute sizing are opaque impl (invariant #4).

## D123. Scheduler: the thin-envelope stance, targets and payloads excluded

A managed cron / scheduled trigger — GCP Cloud Scheduler (a job) and AWS EventBridge
Scheduler (a schedule). Deliberately TWO-CLOUD: Azure has no clean single-resource
managed-cron primitive (a Logic App Recurrence trigger and an Automation runbook
schedule are different shapes — an app / a runbook plus a separate schedule object),
so a scheduler is refused at dispatch rather than mapped onto a resource that means
something else (the D120 / D122 precedent).

The interesting decision is what the vocabulary REFUSES to model. A scheduler is
mostly opaque plumbing: its cron expression, timezone, target (topic / queue /
function / HTTP endpoint), payload, retry policy and dead-letter config are all
implementation detail (invariant #4), and several — an HTTP target's auth header, a
request payload — are secrets groundhold must never manage (D53). Rather than dress that
up as rich capability semantics, v0.1 keeps exactly two attributes that an
organization can meaningfully require and a driver can verify: location.region and
schedule.enabled (is the trigger armed or paused). This is the same thin-envelope
stance as capability.identity.serviceaccount (D121) and capability.dns.zone (records
are data) — and, like D121, there is no natural closed enum, so the enum-guard dual
case is a KIND-MISMATCH load error (schedule.enabled is bool; a non-bool refuses).

Both drivers require the target from the impl block (Cloud Scheduler:
pubsub_topic or http_uri; EventBridge Scheduler: target_arn + invoker role_arn) and
NEVER set a payload/input — that is where a secret would hide. Ownership on BOTH is the
DESCRIPTION marker (reusing the D82 marker idea), because a Cloud Scheduler job has no
labels field and EventBridge Scheduler's Description is the cleaner handle than the
ARN-in-path tag API — a rare case where the two clouds land on the SAME ownership
mechanism. The one asymmetry is schedule.enabled: EventBridge takes State
(ENABLED|DISABLED) at create, while Cloud Scheduler creates ENABLED and a paused job is
a second jobs.pause call (unknown-with-pid on a lost outcome, D29). stateful:false — a
scheduler holds no data, so retirement stops a trigger without the D47 data-loss gate.
Both ship with a D87 honesty harness and D75 permission arms (the AWS create carries
iam:PassRole for the invoker role).

## D124. Encryption key: rotation is honest for a key, refused for a secret

`capability.key.encryption` is the eighth capability domain, and it exists partly
to make a point the secret domain (D97) set up. There, rotation.enabled was
REFUSED: a secret is a store for a value the credential PRODUCER mints, so
rotation — minting a fresh value — is the producer's job, not the store's, and a
store that claimed to rotate would lie. A KMS key inverts every clause of that
argument. The service GENERATES the key material, holds it in an HSM or vault it
never exports, and rotates it on a schedule the service itself enforces. So
rotation.period is HONORED here — a real, verifiable duration mapping to Cloud
KMS's rotationPeriod, AWS KMS's automatic rotation, and Azure Key Vault's rotation
policy — where the same idea was refused for a secret. Same word, opposite
treatment, and both are honest, because the thing that rotates is different:
managed key material versus an out-of-band credential value. That contrast is the
domain's reason to exist as much as the capability itself.

The 3-cloud twin is Cloud KMS, AWS KMS, and Azure Key Vault keys, and two of the
three are CONSTITUTIVE COMPOSITES (D89): a Cloud KMS key needs a keyRing, and an
Azure key needs a vault, so those drivers create ring/vault + key under one
binding (AWS KMS is a single key). protection.level (software | hsm) is mapped
honestly per cloud, and it forces one of the honest one-cloud gaps the vocabulary
exists to surface: AWS KMS is ALWAYS HSM-backed, so protection.level=software is
refused there rather than faked. The key MATERIAL is never a declared attribute —
a KMS key is never exported, so declaring its bytes is the same category error as
declaring a secret's value or a zone's records; v0 is the symmetric encryption key
(the CMK that every other capability's encryption.customerManagedKeys references),
with asymmetric/signing purposes deferred. stateful: true is not conservative here
but literal — destroying a key makes everything it encrypted unrecoverable, the
sharpest data loss the system models. This entry is the design slice — vocab + two
dual conformance cases; the Cloud KMS / AWS KMS / Azure Key Vault drivers follow.
(Renumbered from D102 to D124 on rebase: master's D102 is Event signatures.
This domain was authored alongside the D100/D101 cache and DNS work and merges later.)

## D126. VPN gateway: the gateway is thin, the tunnel is the secret

A managed site-to-site VPN gateway — AWS VPN Gateway (a virtual private gateway) and
GCP Cloud VPN (an HA VPN gateway). Honest two-cloud (Azure's VirtualNetworkGateway is a
heavier composite — an honest gap here, a later slice). Unlike an L7 load balancer, a
VPN gateway IS a single resource, so the resource model is clean; the design tension is
what the vocabulary is allowed to say about it. Almost everything that makes a VPN work
lives on the TUNNELS hanging off the gateway — the peer address, the IKE/IPsec
parameters, the BGP session and ASN, and above all the PRE-SHARED KEY — and the PSK is a
secret groundhold must never set or read (D53) while the rest is opaque tunnel config
(invariant #4). So this is a thin-envelope capability, the D121 / D123 precedent: what
an organization can meaningfully require of the gateway itself is its residency and its
IP stack, and the vocabulary says exactly that and no more.

The one honest per-cloud gap is ip.stack, which is also the domain's natural closed
enum (so the enum-guard dual case is a real enum violation, not a kind-mismatch): GCP's
HA VPN gateway carries a stackType (IPV4_ONLY / IPV4_IPV6), so ipv4 and dual-stack are
both honored; an AWS virtual private gateway is IPv4-only at the gateway level (IPv6
over a VPN is a per-connection concern there), so dual-stack is refused rather than
faked. The drivers differ in shape: AWS is an EC2 Query CreateVpnGateway with a
SERVER-ASSIGNED id (so a lost create is unknown WITHOUT a pid, honest — the DeterministicID:
false posture the VPC driver established) and tag ownership; GCP is a regional compute
LRO vpnGateways.insert with a DETERMINISTIC name (pid known before the response) and
DESCRIPTION-marker ownership (HA VPN gateways have no labels), created into an
implementation.network substrate. stateful:true is the dependency cliff, not stored
bytes (as with network.private): destroying an in-use gateway breaks every tunnel and
route through it, and a re-created AWS gateway gets a new id that breaks the peer's
config — conservative-honest retirement (D47). Both ship a D87 honesty harness and D75
permission arms; neither touches a tunnel, a connection, or a pre-shared key.

## D127. Backup vault: the retention guarantee, not the backup plan

A managed backup vault — AWS Backup (a backup vault) and GCP Backup and DR (a backup
vault). Honest two-cloud, and a deliberate relief after the thin vpn/scheduler domains:
a backup vault has real, compliance-grade capability semantics an organization actually
audits — where recovery points live, how long they are guaranteed to be kept, and
whether that guarantee is IMMUTABLE. The line the vocabulary draws is between the VAULT
(its retention guarantee — the capability) and the backup PLANS, schedules and resource
selections that populate it (opaque impl, invariant #4). retention.minimum is a real
duration, retention.lockMode is the natural closed enum (governance | compliance), and
encryption.customerManagedKeys carries a customer-key reference (never key material).

The two clouds enforce retention very differently, and the vocabulary states the seams
rather than smoothing them. GCP's enforced retention is immutable BY CONSTRUCTION — it
can be increased, never decreased or removed — so it is compliance-only: retention.
lockMode=governance is REFUSED on GCP (there is no admin-changeable mode), as is
encryption.customerManagedKeys=true (a Backup and DR vault uses Google-managed
encryption; CMEK is not a vault-level capability in v0), and retention.minimum is
REQUIRED (the API mandates it at create). AWS is the mirror image: a vault exists
without any retention, and the guarantee is added by a Backup Vault Lock — compliance
(ChangeableForDays omitted, immediately immutable) vs governance (a changeable grace
window). So the SAME lockMode enum drives an irreversible WORM commitment on AWS and is
constrained to compliance on GCP. Both honor encryption via a customer key where they
can (AWS EncryptionKeyArn; GCP refuses). The drivers differ in shape: AWS is REST-JSON
with tag ownership read via ListTags (the ARN pre-encoded into the path so the wire and
the SigV4 canonical URI agree — the one place this domain touches an ARN-in-path), plus
a second PutBackupVaultLockConfiguration call; GCP is a googleapis LRO with label
ownership. stateful:true is literal here — a vault HOLDS recovery points, so destroying
it is the sharpest data loss the system models, and a compliance-locked or
still-populated vault REFUSES deletion (recovery points age out, never force-deleted) —
D47 with teeth. Both ship a D87 honesty harness and D75 permission arms. AWS Backup is
reachable in the sandbox account but was not live-run this cycle; GCP Backup and DR was
code + honesty-harness certified — flagged, not claimed proven.

## D128. GCS in-place update: closing the object-storage update asymmetry

A depth slice, not a new domain: the object-storage capability had an asymmetry the
agnostic-symmetric discipline forbids — S3 (D86) could honor an in-place UPDATE for its
mutable attributes, but GCS (D77) refused every change with "update is not wired yet",
so the SAME contract edit was a patch on one cloud and a hard refusal on the other. This
closes it: GCS now classifies changes and patches versioning.enabled in place, exactly
as S3 does, so capability.storage.object behaves the same on both clouds.

The mechanism mirrors the S3 path deliberately. ClassifyChange gains a per-service arm
(classifyGCSChange) that speaks the same four-valued language: versioning.enabled is
mutable (a clean buckets.patch), location and durability class are immutable (create-
time-only — a change is a replacement the compiler refuses with consent-required, never
a paper patch), and the exposure/CMEK/retention paths are honestly "unsupported" —
patchable in principle but not wired in THIS slice, an honest boundary rather than a
silent claim of mutability. The patch itself re-reads ownership labels, refuses a
cross-project bucket (D82), and rides the live metageneration as ifMetagenerationMatch
so a concurrent change surfaces as a 412 conflict instead of a lost update — the same
CAS discipline the create and delete paths already use. Two conformance cases pin the
plan-level behavior symmetrically with the S3 pair: mutable versioning drift compiles to
one update action carrying exactly that path; region drift refuses at plan. The gap was
invisible until stated as an asymmetry; naming it is what made it a bug.

## D129. Pub/Sub in-place update: the second update asymmetry, revoke edition

A depth slice continuing D128's theme: the messaging.topic capability had the same
asymmetry object-storage did. SNS (D94) could honor an in-place UPDATE of its mutable
attributes — chiefly network.publicExposure — but its GCP twin Pub/Sub refused every
change with "update is not wired yet," so the identical contract edit was a patch on
AWS and a hard refusal on GCP. This closes it: Pub/Sub now classifies changes and
patches network.publicExposure in place, so capability.messaging.topic behaves the same
on both clouds.

The mechanism is the exposure grant/revoke, and the revoke direction is the new bit
worth recording. Public exposure on a Pub/Sub topic is an allUsers roles/pubsub.publisher
IAM binding; the create path already granted it (setTopicPublic). Turning a public topic
private needs the inverse, so this slice adds removeMember — the revoke twin of the
shared appendMember — which drops an UNCONDITIONAL member from a role's binding and
drops the binding entirely if it empties, leaving conditional bindings untouched (they
never granted the member unconditionally, per hasMember). setTopicPrivate does the
version-3 read-modify-write with the etag as its CAS, then re-reads to confirm the topic
is no longer public — the same confirm-or-unknown discipline (D29) the grant uses, so a
lost setIamPolicy is unknown, never a false "succeeded". ClassifyChange gains a
per-service arm (classifyPubSubChange) speaking the four-valued language: publicExposure
is mutable, while encryption.customerManagedKeys and residency (messageStoragePolicy) are
patchable in principle but honestly "unsupported" — not wired in THIS slice — rather than
silently claimed. A pubsub topic is global, so unlike a regional S3/GCS bucket it has no
clean create-time-immutable capability attribute; the single plan-level conformance case
pins the mutable path, and driver tests cover both grant and revoke plus the foreign-
owner refusal. Two clouds, one behavior — the asymmetry named in D128 was not a
one-off, and removeMember is now available for the next exposure-update the pattern needs.

## D130. Pub/Sub queue update: stating the missing CAS instead of faking one

The third update-asymmetry slice (after D128 GCS and D129 Pub/Sub topic): SQS (D95)
could honor an in-place UPDATE of its mutable attributes, but its GCP twin — a Pub/Sub
SUBSCRIPTION — refused every change. This closes it for retention.minimum, so
capability.messaging.queue behaves the same on both clouds: a bound subscription whose
message-retention has drifted below the contract's floor compiles to one update action,
patched via subscriptions.patch with an updateMask, honoring the same 600s..2678400s
envelope the create path enforces (never clamping a data-loss floor — refused if out of
range, symmetric with create).

The design point worth recording is what this slice does NOT have. Every prior in-place
update rode a concurrency precondition — Cloud SQL's settingsVersion, GCS's
metageneration, the IAM etag on the exposure grants — so a concurrent change surfaces as
a conflict, not a lost update. A Pub/Sub subscription has NO such token: UpdateSubscription
exposes no etag, version, or generation. The honest response is to state that, not to
fake a precondition the API does not offer. updatePubSubQueue re-reads ownership labels
immediately before the patch to keep the TOCTOU window minimal, and the code and this
entry say plainly that a concurrent retention change is last-write-wins because the
provider gives nothing to compare against. That is more honest than inventing a
client-side check that could not actually be atomic — the same discipline the verifier
applies to `unknown`: when you cannot prove it, say so rather than assert a comfortable
falsehood. classifyPubSubQueueChange marks retention.minimum mutable, delivery/ordering
immutable (a create-time type — a replacement), and exposure/CMEK/residency honestly
"unsupported" (patchable in principle, not wired this slice). The exposure path is
deferred deliberately: its revoke needs the removeMember helper D129 introduced, and
folding that in here would collide with that slice — so it waits until the two land.

## D131. Secret update: the same attribute, mutable on one cloud, immutable on the other

The fourth and last update-asymmetry slice, completing the set: every capability domain
where an AWS driver could honor an in-place UPDATE now has its GCP twin doing the same.
AWS Secrets Manager (D97) updated in place; GCP Secret Manager refused. This closes it
for network.publicExposure — a grant or revoke of the allUsers secretAccessor IAM
binding, with the IAM etag as the CAS.

The point worth recording is a genuine per-cloud divergence the four-valued classifier
captures faithfully. ASM classifies encryption.customerManagedKeys as MUTABLE — you can
patch a secret's KmsKeyId. A GCP secret cannot: its CMEK lives inside the create-time
REPLICATION policy, which is immutable, so the same attribute is a REPLACEMENT, not a
patch. classifySecretChange therefore returns immutable for encryption.customerManagedKeys
where classifyASMChange returns mutable — and both are correct, because ClassifyChange is
PURE PER-PROVIDER knowledge (D46), not a shared table pretending the clouds agree. A
lesser design would have picked one answer and lied on one cloud; the honest one lets
each driver tell the truth about its own resource, and the compiler routes accordingly
(a replacement asks for consent, a patch does not).

Two implementation notes. The revoke is INLINED (setSecretPrivate filters allUsers/
allAuthenticatedUsers from the policy and drops emptied bindings) rather than calling the
shared removeMember introduced in D129 — deliberately, so this slice does not collide
with that one before both land; the duplication is a few lines and can be unified when
they merge. And the CAS is real here (unlike D130's Pub/Sub subscription): Secret
Manager's getIamPolicy returns an etag that setIamPolicy round-trips, so a concurrent
policy change is a conflict, not a lost update — the confirm-or-unknown discipline (D29)
applies to the revoke's re-read. With this, the update-asymmetry sweep that ran across
D128-D131 is done: gcs, pubsub-topic, pubsub-queue, and secret all match their AWS twins.

## D132. Capsules say how they hash

An independent pre-freeze review of D103 flagged the one thing that gets expensive
after GA: a capsule that does not name its own algebra. Verbatim events plus
a head hash are only verifiable if both sides agree on the hash algorithm
and the canonicalization version — an agreement that was implicit (this
binary, today). Implicit agreements rot silently.

capsule/v0.1 now carries `eventHashAlg: sha256` and
`canonicalization: groundhold/canon/v1`, and the verifier EXACT-MATCHES both:
a capsule declaring an algebra this verifier does not implement is refused
loudly (exit 5), and one that omits the declaration is refused too —
"not verifiable, only guessable, and this verifier does not guess". No
tolerant fallback for undeclared capsules: v0.1 is pre-freeze and private,
there is no legacy fleet to appease, and starting strict is free today
while starting lax is unfixable later. When a canon/v2 or a new hash ever
exists, old verifiers refuse new capsules BY NAME instead of misreading
them — the version pin pattern (console ingest, D-earlier) applied to the
proof document itself.

## D133. Key rotation is receiver policy, not ledger history

D102 shipped with a deliberate cliff: one `--trust` key, forever. An independent
review named the failure modes — unsigned genesis era, old-key prefix after
a rotation, no revocation story. Two shapes competed for the fix.

In-ledger delegation (a `signing.rotated` event signed by the outgoing key,
replay walks eras) has the better story on paper: the old key is provably
dead after event N. But it pushes signing STATE into canonical history:
rotation events need a capability lane that does not exist, and a
one-capability capsule cannot walk eras it does not carry — the capsule
shape would have to grow signing metadata. Authenticity policy would be
coupled to event history everywhere. A reviewer, asked to be decisive: do not.

Shipped instead — trust stays where the anchors already live, with the
receiver:

- **`--trust` is repeatable**: a set of keys, any-of per line, exact match.
  Rotation is operational: sign with the new key, receivers trust both
  during the overlap, drop the old one when they choose. Revocation is "I
  no longer accept this key from my anchored view forward" — a receiver's
  decision, not something the ledger proves. This is the same trust class
  as the D70 anchor: local policy bounding what a remote history can claim.
- **`--trust-from <event-hash>`** answers the unsigned-prefix problem
  without weakening anything: the receiver pins (out-of-band, unslidable)
  the event where signing became mandatory; before it, tolerated era; from
  it, INCLUSIVE, every line must verify. The boundary is evaluated against
  the actual input being verified — a file, an export fold, a capsule —
  and an input lacking the boundary refuses, else truncation would erase
  the obligation. `--trust-from` without `--trust` is a refused
  contradiction (a boundary with no keys to enforce past it).
- One `TrustChecker` per verification STREAM (replay, fold, capsule)
  carries the reached-boundary state; the key set is process config. The
  distinction matters: trust is global intent, "have I passed the boundary"
  is a property of what is being read.

Cost, stated: a stolen old key verifies for as long as receivers keep it in
their set. Accepted — the window is receiver-controlled and anchor-bounded,
and the alternative bought precision by ossifying capsule and event shapes
pre-GA. If epoch precision is ever needed, it arrives as receiver-side
config ("key X valid for events N..M"), never as in-ledger delegation.

## D134. Signatures name the ledger they attest

A D102 signature bound a key to an event; it did not bind either to a
LEDGER. The same raw event signed once verified verbatim in any file that
contained it — mostly harmless within one deployment (the prev-chain rejects
splices), but wrong the moment one key signs several tenants' ledgers and a
capsule travels: "signed by our key" is not "from our ledger".

The fix is an identity the system already had without naming it: the
canonical hash of the FIRST event. Self-establishing (no config, no nonce
ceremony), computable even for the genesis line's own signature because the
event hash excludes `sig`. The envelope carries the claim (`ledger:`), the
signed message binds it (`groundhold/sig/v2:<ledgerId>:<eventHash>` — v2
because D102's v1 never shipped anywhere), and every verification stream
pins claims to the genesis it can see: replay and full-from-top export folds
know their line 1; capsules and `--since` folds hold claims mutually
consistent and REPORT the claimed id (`claimedLedger`) for the receiver to
compare — with `--check`, against the anchor's new `ledgerId`, mechanically.
Envelope hygiene per review: lowercase hex only, `sha256:` prefix mandatory,
missing claim refused at load (both implementations, dual case).

Stated limits, per an independent review: the genesis hash is a LINEAGE id — forks
grown from one genesis share it, and the anchor's positional head is what
tells branches apart. A ledger re-genesised after total corruption gets a
new identity and old artifacts refuse against it: correct, not regrettable.

## D135. The anchor carries the trust policy

D102's honest gap: verification was opt-in per invocation. A receiver who
forgot --trust got a clean replay of a signature-stripped file — the
downgrade attack was one forgotten flag away. The rejected fix (an in-ledger
"signatures required" marker) would have put authenticity policy back into
canonical history, which D133 had just deliberately kept out.

The shipped fix reuses the one artifact the receiver already holds and
already checks: the anchor. `groundhold anchor` embeds the policy the emitting
process ACTUALLY verified (`trust: {scheme, keys, from}`) — structurally a
receipt, never a wish: emitting with --trust armed over a ledger that does
not satisfy it refuses at replay, before any anchor exists (pinned by
anchor-trust-is-a-receipt-of-verification). Every path that loads an anchor
arms the policy automatically: `anchor --check`, `capsule --check`, and the
execution-path enforcement beside the ledger — so apply/resume/publish over
a stripped ledger refuse with no flags given (pinned end to end). The
policy names its signature scheme; a key set silently applied to an
incompatible future scheme would be ambiguity, not security.

Conflict rule, on a reviewer's confirmation: when both CLI flags and the anchor
carry policy, they must agree — a disagreement refuses loudly. CLI-overrides
-with-a-warning was rejected by name: an override path is a downgrade path
wearing operator clothes. Changing the policy is a deliberate act: re-emit
the anchor under the new flags against a ledger that satisfies them.

## D136. CONVERGED is earned by the check, not by the apply

The fresh-eyes quickstart walk (same day) surfaced a contradiction the
banner rule permitted: a converge whose post-apply check reported
"convergence check inconclusive (observations do not cover every
attribute)" still bannered CONVERGED, because the banner was f(exit, code)
and converge's green word was unconditional. The prose said "I could not
verify"; the banner said "verified fixed point". D89's own rule — a green
state never claims more than was checked — decided it.

Converge's result now carries `convergence: verified | inconclusive |
unverified` (additive machine field), and the green word splits on it:
CONVERGED only when the check verified the fixed point (or the no-op path
proved it outright); APPLIED otherwise — true, and exactly as much as was
proven. APPLIED was already in the closed banner vocabulary, so no new
word. Status stays "applied" (the pinned machine contract is untouched);
the distinction lives in the new field and the banner. Pinned by
converge-inconclusive-check-banners-applied plus banner/convergence
assertions strengthening the existing full-loop case.

## D137. Snapshots are receipts, not caches

Every "(D33)" breadcrumb that said "activate snapshots when you outgrow the
file" pointed at a design that never existed — D33 is the risk vector. This
is that design, built with the trust machinery that now exists (D70 anchors,
D102/D134 signatures, D133/D135 receiver policy) instead of before it, which
turned out to be the right accident of ordering.

The framing that survived independent review: a snapshot is NOT cached fold
state. It is **a signed receipt of a verified prefix plus an audit index
into archived history**. Every design choice falls out of that sentence:

- **Replay-verify first, then rotate.** The rotation replays the full
  ledger under whatever anchors/trust are armed; `verifiedUnder` records
  what was enforced (`filesystem` — no trust, said out loud — or the key
  set and boundary). A snapshot of corrupt or untrusted history cannot
  exist; a trust-carrying one is a receipt of verification that happened.
- **The archive is bound, not implied.** The snapshot pins the sha256 of
  the file it replaced and chains `previousSnapshotHash`; superseded
  snapshot documents archive rather than vanish. Audit reconstruction
  follows hashes — filenames and operator memory were the reviewer's named
  failure mode.
- **Positions stay absolute.** `baseEvents`/`baseHead` offset the fold, so
  export cursors keep meaning, tail-era anchors verify unchanged, and an
  anchor strictly inside the prefix refuses toward the archive. The anchor
  cut at rotation additionally pins `snapshotHash` — a receiver detects a
  swapped fold, not only a rewritten tail.
- **Trust survives compaction without weakening.** Unsigned snapshot under
  --trust refuses (compaction must not be a signature-stripping laundry);
  the tail's signatures keep claiming the ledger identity the snapshot
  carries; a --trust-from boundary now in the archive is honored via the
  receipt, and ONLY when it names exactly the armed boundary.
- **Crash order favors loud.** Snapshot activates before the file moves:
  the one interruptible window fails at the next replay with a chain
  mismatch naming the pending archive step. The alternative order
  (archive first) had a silently-empty-ledger window — rejected for that
  one property, against the reviewer's aesthetic preference and with the
  recovery matrix they demanded.
- **State is state.** Active leases and pending receipts snapshot like
  everything else — refusing to compact a busy system would deny the valve
  exactly where it is needed. The equivalence property pins ALL of it:
  fold(prefix+tail) == fold(snapshot(prefix))+tail over the entire struct,
  unexported projections included, so a future projection added without
  snapshot support fails a test instead of losing state silently.

Deliberately out: reading archives transparently (capsules refuse toward
the archive by name), archive GC (audit material; pruning is the
operator's decision), per-capability subchain metadata in the snapshot
(bloat until a consumer exists).

## D138. Snapshots hardened: two hostile reviews and a fuzz

D137 shipped, then earned a randomized equivalence fuzz and two independent
adversarial reviews (crypto/trust lens, state/IO lens) plus an independent
spec-drift pass. What they found, and what changed — every fix pinned:

- **The fuzz caught two on day one**: replay left the lazily-initialized
  projections (violationState, pendingBody, replaced/tombstoned, lastGen)
  as empty-vs-nil noise that drowned real drift — now canonicalized after
  the fold; and a coupled lazy init in accumulateLineage panicked once
  canonEmpty could null one map of a pair. Randomized histories with
  stacked cuts, whole-struct DeepEqual — the D38 idea turned inward.
- **Rotate held no lock** (both reviewers, critical): a concurrent append
  between the fold, the archive hash and the renames was a silent lost
  write. Rotate now takes the same LOCK_EX commitUnderLock does, derives
  the fold and the archive hash from ONE buffer, copies the outgoing
  sidecar to its archive (never a rename that leaves the live path
  briefly absent), fsyncs the directory after each rename (POSIX does not
  order rename durability), and creates the fresh tail with O_EXCL so a
  racing writer's recreate is never truncated.
- **BuildAnchor was snapshot-blind** (both, high): counting only the tail
  it produced an anchor that failed its own check after a second rotation
  and broke capsule --check. Now absolute (TotalEvents/headAtTip/LedgerId)
  and it pins the fold hash, so a standalone `groundhold anchor` on a
  compacted ledger detects a later swap too.
- **anchor.SnapshotHash was write-only** (both, high): a doctored sidecar
  preserving baseHead/heads but rewriting a projection passed every check.
  CheckAnchor now compares it against the fold the replay seeded from — the
  swapped-fold refusal the spec always promised.
- **export drifted from replay** (all three reviews): --since compared the
  absolute cursor against the raw tail index (silently dropping events
  after compaction); it streamed records to stdout before the trust gate
  (leaking unverified data on a refusal); and it never credited a
  compacted --trust-from boundary. Now buffered-until-verified, absolute
  --since, tail-continuity checked, boundary seeded from the receipt.
- **verifiedUnder was informational** (independent review, critical): a signed fold of
  filesystem-verified history could carry a forged `from` and seed the
  boundary. Seeding now requires mode:"trust". The snapshot sig also pins
  its alg (it lives outside the hash), and an armed-trust rotation without
  a signing key refuses up front instead of writing a self-poisoning fold.
- **repair was snapshot-blind** (IO, serious): it diagnosed a healthy
  compacted tail as chain-broken and steered the operator to quarantine —
  which truncates the healthy tail to zero. It now seeds from the snapshot
  before diagnosing.
- Minor: sameKeySet is true multiset equality; the outgoing-sidecar and
  ledger archives both refuse to overwrite.

The framing held under fire: a snapshot is a signed receipt of a verified
prefix, and every finding was a place the code treated it as a cache. The
latent BuildSnapshot/SeedLedger map aliasing (safe today — Rotate marshals
immediately, seeds come from fresh JSON) is left documented, not deep-copied:
a real second consumer is the trigger to change it, not speculation.

## D139. attest: provenance as facts the console can project

The console knew nothing of the trust surface (D102/D134 signatures, D70/D135
anchors, D137 snapshots) because `export` carries only the inner event block,
never the top-level `sig`, and anchors/snapshots are off-stream sidecars. The
console has no verifier and must never grow one — so groundhold must ESTABLISH
the provenance facts and the console only shows them, exactly the survey/
bakeoff pattern.

`groundhold attest --ledger <f>` emits an IntegrityReport/v0.1: ledger identity
(D134), compaction shape (total/tail/base, D137), signature coverage over the
tail, snapshot-receipt facts, and the anchor's POSITIONAL status. It is
deterministic and read-only.

The honesty line, sharpened by independent review, is the whole point: attest
reports PRESENCE and SELF-CONSISTENCY, never trust. Every counted signature
verifies against ITS OWN claimed key and this ledger's identity — the math,
no policy — so a present-but-invalid envelope is `envelopePresentButInvalid`,
its own fact, NEVER laundered into a coverage number. The field names refuse
the confusion by construction (`selfVerified`, not `signed`/`valid`); the
snapshot's receipt claim (`receiptMode`) is kept distinct from what attest
checked now (`signatureSelfVerifies`, `ledgerIdMatches`); the anchor reports
`status: verified|truncated|diverged`, a re-check, not decoration. Whether a
self-verifying key is one you TRUST is the operator's `--trust` decision on
the reading verbs, and it appears nowhere in the report — because the console
that projects it has no verifier and must not imply one. What the panel may
say: "envelopes self-verify for N/M events, keys observed K, anchor extends,
snapshot receipt present." What it may never say: trusted, authentic,
verified, secure. The tail-only scope is explicit (`archivedBase` counts the
compacted events attest did not re-inspect), so a compaction never lets a
coverage number quietly claim the whole history.

Deliberately NOT added: an `attest --trust` mode emitting a verification
verdict. It would put a trust decision into a static document the console
projects, reintroducing the exact confusion the presence/verdict split
removes. Trust verification stays live, on the reading verbs, where the
operator arms the policy.

## D140. claim: converged-no-op is not proof of takeover until ownership is stamped

Two independent pre-implementation reviews found the same hole
in the D52 brownfield loop: `adopt` binds the ledger and proves reality matches
the contract, then `converge` reports "converged" on a no-op — and that no-op
was taken as proof of takeover. But the no-op proof is READ-ONLY. It never
stamped groundhold's authorship on the object. So a resource adopted from
Terraform still carries TF's ownership markers (or none), and the FIRST later
drift hits the driver's own "not ours" guard (`update.go`: refuse to patch a
resource whose ownership labels do not match) — with `terraform state rm`
already run, no writer on earth will repair it. The object has a contract, a
binding, and no author. It is the exact inversion of "adoption must not lie",
invisible until governance is needed.

`claim` closes it. A binding whose resource `origin` is `adopted` and that has
not been claimed compiles to a one-time `claim` action — even when there is no
semantic diff, which is precisely the case a bare no-op hid. Apply dispatches
it to the driver's optional `Claimer`, which stamps driver-native ownership
(labels/tags, or a Kubernetes server-side-apply field-manager takeover), and
records `ownership.claimed`. Only then does the next compile see the binding as
claimed and fall to a genuine no-op — so a converged result now means BOTH
reality matches AND groundhold owns the object. The claim orders before any update
or delete in the same run (you must own a thing to patch or destroy it).

Three lines hold the design honest. (1) adopt stays LEDGER-ONLY: it cannot
mutate the cloud (D52), so ownership transfer cannot live in adopt — it is a
sealed-plan effect executed by apply, gated on `origin: adopted`, never a
silent side effect of binding. (2) It is OPT-IN per driver via the `Claimer`
interface: a driver that cannot take ownership emits no claim and keeps its old
behaviour, so the change is inert for every provider until its driver opts in
(Kubernetes first, the clouds to follow — the takeover procedure is uniform
across providers, so the fix is too). (3) The claim is idempotent and loses no
data — the safest write — so it needs no `--allow-data-loss` friction.

This changes the takeover proof, so the existing conformance case
`onboarding-full-loop-proves-takeover` is STRENGTHENED, not weakened (N5): the
first converge now APPLIES the claim ("applied"), and a second converge proves
the converged-and-owned state ("converged"). A new case pins that
`ownership.claimed` reaches the audit stream. The competing-reconciler gate
(refuse to adopt what ArgoCD/Helm continuously owns) is the same review's
sibling fix, landed alongside.

## D141. Pairing + gentle crawl: context is discovered read-only, never owned, and the console never initiates it

Two directions the runtime has long implied — "pair a provider, then crawl it
gently for context" across clouds/clusters/DBs/blob/repos — land as a RUNTIME
capability that leaves every invariant intact. Discovering is not owning
(odkrywać ≠ posiadać, D52): a crawl builds CONTEXT, binds nothing, promotes no
candidate, writes no ledger event.

Pairing is a machine-local REGISTRY of credential REFERENCES, never secrets.
A pairing records `{provider, scope, credentialRef, pairedAt}` where
credentialRef is a POINTER — an env-var name, a kubeconfig path+context, an aws
profile, a gcloud config — resolved on the crawling host at crawl time, exactly
as the cloud drivers already source credentials (never persisting the value).
It lives in `.groundhold/pairings.yaml`, not the ledger (D52: discovery never
writes the ledger; and a host-local pointer is false everywhere but that host).
Secrets are structurally excluded, the D53 discipline: the type has nowhere to
put a secret value.

This split is load-bearing, so it bounds scope. DELEGATED-credential providers
(gcp/aws/azure/k8s) have an external holder — a profile, a kubeconfig — so the
reference scheme is honest. OAUTH providers (github/slack/jira/notion/linear)
have no external holder: an interactive pairing would MINT a refresh token that
exists only because groundhold created it, and "crawl it later" forces groundhold to
custody that secret — reintroducing exactly what the design excludes, plus a
rotation/revocation responsibility a pre-launch, stdlib-only runtime must not
take on. They also are not infrastructure and have no Discoverer. OAuth
providers are therefore DEFERRED until a custodian that is not groundhold exists;
the pairing model admits only delegated-credential kinds today.

The crawl is `groundhold crawl`, a time-sensitive verb (N1: `--at` required), and
it sits exactly where `discover`/`observe`/`probe` sit — OUTSIDE the
deterministic verifier (#6). It reuses the read-only Discoverer per (provider,
scope), stamps each resource with its ACTUAL fetch time (distinct from the run's
declared `--at`, so a slow crawl never looks uniformly fresh), and emits a
ContextDocument whose identity hashes CONTENT only — the operational timing of
gentleness (backoff, jitter, retry counts) never enters identity, the D102
sig-exclusion instinct applied to the crawl.

Gentleness is a first-class, injected-clock scheduler (`internal/pace`), not
sleeps in a loop: per-provider token bucket, exponential backoff with full
jitter on 429/5xx (an explicit `Retry-After` always wins), zero retries on
401/403 (a pairing problem, refused loudly by name, never hammered), a
per-provider circuit breaker, and a global request budget. Partiality is a
FIRST-CLASS VISIBLE outcome: a budget stop, a tripped breaker, or an
unreachable scope marks that scope `incomplete` in the document with the reason
— never a silently truncated list that misrepresents "crawled everything" (the
four-valued honesty: an uncrawled scope is unknown, not absent).

The read-only console's one rule survives untouched: it never initiates a
crawl. A provider tile PROJECTS the pairing registry and the last crawl's
status, and when unpaired shows the exact `groundhold pair …` / `groundhold crawl …`
recipe — display, not a write. Anything that mutates goes through groundhold
itself, never through the console. Console-side interactive OAuth would demand
a write-channel that breaks the one-way arrow; it is deferred with the OAuth
providers, not smuggled in as a POST.

## D142. posture: the proactive classifier — five honest states, remediation on a plate

groundhold should not wait to be asked. A regular sweep across every credentialed
surface should say, unprompted: this resource was created outside your control,
this one drifted, this proof went stale — and hand you the exact command to fix
each. `groundhold posture` is that verb, and it is a THIN deterministic fold, not a
new engine: it composes the crawl (D141), the ledger's projections, and audit
(D54) into a PostureDocument, adding no verdict of its own beyond classifying
the ones groundhold already computed.

Every resource lands in exactly one of five states — the four-valued discipline
plus an explicit fifth. MANAGED-OK: bound, every hard verdict satisfied at --at,
evidence fresh. DRIFTED: bound, a hard constraint violated at --at. SHADOW:
discovered by the sweep, under no binding — created outside groundhold's control.
DECAYED: bound, no violation, but a backing proof outlived its own ttl (we no
longer know). UNKNOWN: a hard verdict is unverifiable, or the scope was
incomplete — the honest fifth value, never collapsed into the others. Precedence
for a bound capability is drifted > unverifiable-unknown > decayed > ok: a fresh
violation outranks a stale sibling, and "ok" is earned by a fresh satisfied
verdict, never by silence. A shadow count is exact only when every crawl scope
was complete; an incomplete scope demotes it to a labelled lower bound — presence
in an incomplete scope is still presence, but absence it can never prove.

The classification lives in the runtime (`internal/posture`), a pure fold with
no network and no clock — the --at is the clock (N1). The console computes
nothing; it projects, as always. The document is derived like the
ContextDocument and hashed over its CLASSIFICATION content alone (the --at, the
prose reasons and the remediation text never enter identity), so two runs that
reach the same conclusion hash identically.

Remediation rides on the row, emitted by the runtime and displayed by the
console — the D141 one-way-arrow precedent. SHADOW → adopt (discover, then adopt
under a contract). DRIFTED → converge, with the friction flag NEVER pre-baked (a
data-loss converge names the flag; the human types it). DECAYED → refresh then
re-audit. The subtle one is deleting a shadow resource: groundhold deliberately
cannot delete what it does not manage (D47 pins delete targets from bindings), so
the honest path is adopt-then-retire — adopt under a minimal contract, declare
state: retired, converge, and the delete flows through every existing gate. A
provider-native delete is named as a fact (it leaves no tombstone, no receipt),
never recommended. Crucially, no new ledger event type is introduced: shadow
findings do not enter the ledger (D52 — discovery never narrates groundhold's
history), and drift/decay already enter via audit --record's transitions.

Slice 1 (shipped) is the pure classifier + the verb, offline: `posture --ledger
--at [--crawl <doc>] [--contract ...]` folds a prior crawl + ledger + audit into
the document, exit 2 on shadow or drift. The five classes are pinned on the fake
provider. Deferred: the live sweep + console panels (slice 2), --refresh's paced
re-observe before the audit (slice 3, the freshness agent), and vanished-by-
absence drift (a bound id missing from a complete covering scope — needs
provider-specific scope coverage). Open, flagged not resolved: whether exit 2
should include decayed by default — an operator-culture call, not a correctness
one; today it does not.

## D143. restore: the evidence-that-travels machinery is a disaster-recovery system

The trust machinery built for capsules — D70 anchors, D102 signatures, D103
per-capability subchains, D134 ledger-identity, D135 anchor trust policy — turns
out to be, unmodified, a backup-and-restore system. The anchor is already a
backup MANIFEST (its `heads` a table of contents, `events` a totality check,
`ledgerId` the identity, `trust` the policy); a backup is that anchor stored
off-host plus one capsule per capability it names. Restore is replaying that set
back into a ledger and refusing anything the anchor cannot vouch for.

`groundhold restore --out <ledger> --check <anchor.json> <capsule.json>...` is a
deterministic pipeline where every step is a refusal point. It verifies each
capsule with the EXISTING VerifyCapsule (no reimplemented math — linkage,
recomputed head, anchor-head match, D102/D134 trust). It arms the anchor as a
manifest: the capsules' capability set must equal `anchor.heads` (a missing
capability is an incomplete backup — refuse), the deduped event count must equal
`anchor.events`, the genesis named by `ledgerId` must be present. It dedupes
multi-capability events by canonical hash, then LINEARIZES deterministically —
Kahn over the per-capability `prev` edges, tie-broken by (occurredAt, eventHash),
the genesis pinned to line 1 — because per-capability chains carry no total order
across streams, so the restored file is a canonical linearization, not the
original interleave. It writes the ledger only after a clean re-replay, then cuts
a fresh anchor recording `restoredFrom`. The pinned property: for every
capability, `fold(original)[cap] == fold(restore(capsules(original)))[cap]`.

Four-valued honesty runs through it. A tampered, dropped, stale or forked capsule
refuses the WHOLE restore (exit 5, corruption-class) rather than write a silently
partial state — the disaster after the disaster. What is provably NOT restorable
is said out loud: secrets (structurally excluded, D53 — which is exactly why
capsules can travel), live provider state (restored observations are stale by
their own timestamps, so the D75 freshness gate refuses a plan until re-observed
— the DR safety net for free), the physical interleave, and anything after the
last anchor (backup cadence is anchor cadence). Slice 1 is single-source,
fake-testable, refuse-loudly. Deferred: merge (restore accepting multiple capsules
per capability — prefix-extends proven by replay, forks refused, never guessed),
`--partial` with per-capability `unknown`, the `groundhold backup` emitter + the
content-addressed documents layer, and 4D correlation (which stays OUTSIDE the
verifier: claimed time is not checkable, cross-capability order does not exist,
and an incident grouping is a hypothesis, not a verdict).

## D144. react + the change-feed capability: event-driven is a provisioned opt-in, never a daemon

The polling crawl (D141) has a latency floor: a resource created outside control
is seen on the next sweep, not the moment it appears. The event-driven path
closes that gap without betraying the no-daemon doctrine, because the daemon it
needs already exists and is owned by the cloud: EventBridge, Pub/Sub, Event Grid.
groundhold never runs the listener; the cloud's bus is the listener, and — the key
refinement — groundhold PROVISIONS that bus as a governed resource. Declaring
`capability.observability.changefeed` in a contract makes groundhold stand up the
feed (an EventBridge rule on CloudTrail, a Cloud Asset Inventory feed to
Pub/Sub, an Event Grid subscription to a queue), so the opt-in from polling to
real-time is a contract line, not manual cloud surgery. The feed is infrastructure
squarely in groundhold's mandate; the compute that drains it and runs react is
operator glue (app deployment, out of scope — the honest infra/deployment line).

`groundhold react` is the ingress: a stateless verb, invocation-shaped exactly like
cron `posture` except its trigger is a change event instead of a clock. It maps
ONE event to (provider, scope) COORDINATES ONLY — no byte of the payload becomes
a fact, so a forged or replayed event can at worst trigger one paced, read-only
re-list of an already-PAIRED scope (the pairing is the consent; an event cannot
conjure credentials). The insight that keeps it small: don't build incremental
posture — the classifier is a free pure fold — build incremental CRAWL. react
re-lists just the changed scope and SPLICES that block into the last full crawl,
recomputing the content hash; posture then reclassifies the whole estate. No new
document type, no delta-merge in the console. The spliced document reaches the
console's existing SSE seam through ordinary ingest, and the new shadow resource
is on screen in seconds.

The honesty is doctrine. The event feed is a LATENCY optimisation, never a
source of truth: feeds drop, duplicate and reorder, so the periodic crawl remains
the completeness backstop and every event-spliced document is superseded by the
next full sweep. Arrival is non-deterministic; the reaction is deterministic
given (envelope, base-context, --at), and sits with discover/crawl/observe
outside the verifier — nothing enters the verification core. The changefeed
capability is minimal by design (v0.1: `feed.target` — where events land — plus
service.managed; coverage/filter grammar deferred because the three clouds'
grammars diverge sharply and react filters downstream anyway). react slice 1 is
fake-testable end to end; the three cloud feed drivers land create/observe/delete
with golden tests, their D75 permission tables, and honest deferrals (each feed
references an existing target queue/topic — that target's own lifecycle is a
separate capability, D26).

## D145 — Cloud takeover claim (closing the Q5 orphan gap for cloud adoption)

The claim effect (D140) closed the false-takeover bug for k8s but left it live for
the cloud drivers, which did not implement `provider.Claimer`. So an adopted cloud
resource was never claimed: adopt binds it, converge sees no semantic diff and
reports converged (a READ-ONLY proof), the operator runs `terraform state rm` — and
a later real drift finds no groundhold ownership marker, the driver refuses "not ours",
and the resource is orphaned (a contract + binding with zero writers). Q5.

GCP now opts into Claimer. `Claim` dispatches per service (D76, fail-closed):

- **Cloud SQL (the proven path):** a READ-MODIFY-WRITE label patch. It GETs the
  instance, MERGES `groundhold-capability`/`groundhold-environment` into the existing
  `userLabels`, and patches back the UNION with `settingsVersion` — additive, so the
  operator's TF-applied labels survive (a full-map patch would clobber them, metadata
  data-loss). Four-valued on the wire: an ambiguous outcome is `unknown` WITH the
  providerId, a settingsVersion conflict or a vanished instance is a clean `failed`,
  `ownership.claimed` is recorded ONLY after a confirmed 2xx + DONE operation.
- **Every other service refuses HONESTLY (`failed`).** A failed claim makes apply exit
  4 and stop, so the converge never reaches the takeover signal the operator waits for
  before `terraform state rm`. The resource stays TF-owned and TF-written — refusing to
  claim is refusing to certify takeover, which is exactly the truth for a resource
  groundhold cannot yet stamp. No orphan.

The interface is type-level, so once GCP is a Claimer the compiler emits `claim` for
EVERY adopted GCP capability. Adopted non-Cloud-SQL resources that previously reported
a silent converged-no-op now fail apply loudly. That is the latent bug surfacing, not a
regression: the new behavior fails CLOSED (operator keeps Terraform), strictly safer
than the old silent success. D10 is honored by proving two mechanisms end to end — the
Cloud SQL additive patch and the honest refuse — with the remaining label-bearing
GCP services (they carry the same `groundhold-*` labels) as follow-ups that ride the
same two shapes. `PermissionsFor(gcp, cloudsql, "claim")` declares the get+update
the patch makes (D75).

All three clouds now opt into Claimer, each with its flagship (most-adopted)
service as the proven real-claim path and every other service honest-refusing:

- **AWS — rds.** `AddTagsToResource` is additive SERVER-side, so unlike the other
  two it needs NO read-modify-write — the merge cannot clobber the operator's tags.
  A `DescribeDBInstances` pre-read is only an existence check so a vanished instance
  fails cleanly. Stamps the same `groundhold-*` tags the create builder applies, keyed
  on the `arn:aws:rds:…:db:<id>` ARN completed from the cached STS account.
  `PermissionsFor(aws, rds, "claim") = {rds:AddTagsToResource, rds:DescribeDBInstances}`.
- **Azure — flexpostgres.** ARM `tags` is a full-map PATCH, so claim does the same
  read-modify-write as GCP: GET the resource, merge groundhold's ownership tags into the
  existing map, PATCH the union. `PermissionsFor(azure, flexpostgres, "claim") =
  {…/flexibleServers/read, …/flexibleServers/write}`.

The blast-radius property holds per cloud: making AWS or Azure a Claimer flips
`claim` emission for ALL their adopted capabilities, so adopted non-flagship
resources that previously reported a silent converged-no-op now fail apply closed
(the latent Q5 bug surfacing, strictly safer). Wiring each additional service's real
claim (the tag/label-markable ones ride the flagship's shape; name/identity-markable
ones like IAM roles or Route 53 zones stay honest-refuse) is incremental and safe.

### D145 breadth — claim wired across the tag/label-markable services

Following the flagship slice, the real claim was broadened to every service that
marks ownership with a tag/label (the name/identity-markable ones — IAM roles,
Route 53 zones, GCP dashboards/description-markers, Azure RBAC — stay honest-refuse
by design, so their adoption stops at converge and never orphans):

- **AWS**: a generic `claimByARN` via the Resource Groups Tagging API
  (`TagResources`, server-side additive merge — no read-modify-write, and it avoids
  S3's full-map `PutBucketTagging` clobber) covers s3/sqs/sns/dynamodb/ecr/efs/
  opensearch/kinesis/elasticache/acm/cloudwatch/backupvault/apigateway/cloudfront/
  vpc/vpngateway/kms; rds + secretsmanager use their native tag API (ARN carries a
  server suffix). ecs/msk/waf/redshiftserverless carry a server-assigned ARN
  (UUID/suffix/cluster path) the providerId does not, so their claim first READS the
  authoritative ARN (ecs DescribeServices, msk ListClustersV2, waf ListWebACLs,
  redshift-serverless GetWorkgroup) — four-valued (unreadable → unknown+pid, vanished
  → failed) — then stamps via the same additive RGT path.
- **GCP**: per-service read-modify-write label merge (labels are a full-map field,
  so the union is mandatory) across gcs/pubsub/secretmanager/bigquery/clouddns/
  artifactregistry/cloudkms/monitoring/uptime and the LRO-patch services
  (memorystore/filestore/managedkafka/certmanager/cloudfunctions/backupvault/
  cloudrun/cloudrunjobs). Shapes vary (immediate vs `updateMask` vs wrapped body vs
  `userLabels`); all four-valued.
- **Azure**: ONE generic `claimARMTags` (GET → merge tags → PATCH the union) covers
  all 25 tag-bearing ARM services — the only per-service work is turning the
  providerId into the ARM resource URL; composites (blob→storage account,
  servicebus→namespace, eventhubs→namespace, keyvaultkey→vault) target the parent
  that carries the tag.

`PermissionsFor` centralizes the claim footprints in three per-cloud maps
(`{aws,gcp,azure}ClaimPerms`) dispatched at the top of the function: AWS is
`tag:TagResources` + the service tag action; GCP is get+update (+operations.get for
LRO); Azure is uniformly the resource-type read+write. A service absent from its
map is not claimable and declares no claim permissions — matching the driver's
honest refuse.

## D146 — Community extensibility: collectors, not out-of-process drivers

The question was how to let third parties extend groundhold without polluting the
stdlib-only core. The banked hypothesis was out-of-process live drivers (TF's
plugin model). A reviewer + skeptic consult REJECTED it on three fatal grounds:

- **The trust boundary would move onto the deterministic verifier.** `Observe` is
  the input to the verifier (invariant #6). An out-of-process community driver that
  returns a fabricated `measured` observation makes the deterministic verdict a
  deterministic lie. A conformance kit certifies a binary on fixtures once; it
  cannot bind its PRODUCTION behavior against a live cloud. "Honesty enforced by a
  kit" over live output is a category error.
- **Security, unmitigable.** Pairing (D141) hands the subprocess the operator's
  live credentials and a mutating executor; Go cannot sandbox it. Community drivers
  = a credential-exfiltration + prod-mutation vector. The D53 output scan is
  irrelevant here — the danger is the driver's side effects, not its return values.
- **Premature / frozen.** The `Provider` interface is still churning (Claimer,
  Enumerator, ServiceLister, CompetingManagers are recent). Publishing a versioned
  driver contract now freezes an unfinished interface in a pre-launch, no-GA project.

The endorsed alternative — already most of the way built — is the **collector**
(spec/collector.md): a witness-side tool that runs out-of-band at the vantage, holds
its OWN scoped credentials (never groundhold's paired creds), and emits a signed
evidence capsule (D103) the core imports and RE-VERIFIES (recomputing `asOf`, never
believing the collector's clock). The trust boundary stays a signature the operator
chose to trust (`--trust`), the credential blast radius does not grow, and the
verifier stays deterministic over evidence — not over an untrusted binary's output.

New this slice: `groundhold certify-capsule` (internal/collector) — the collector's
self-certification gate AND the core's import-time check. It composes VerifyCapsule's
structural/signature/linkage proof with the honesty SHAPE a third party is not
trusted to have satisfied: a D53 **secrets scan** at the boundary (secret-named
fields/paths + signatured values — PEM/AKIA/bearer/JWT), the derivation vocabulary
(measured|config-intent), and freshness discipline (observedAt present, nothing past
`asOf`). Rejected is corruption-class (exit 5). The scan is a safety net, not a
guarantee (it cannot catch an unsignatured plaintext secret at a benign path), so
the contract still requires structural exclusion; certification is evidence, not
proof (D75 stance). Out-of-process drivers stay parked behind the skeptic's
falsifier: a kit mechanism that constrains a driver's PRODUCTION Observe against
ground truth without the core itself observing — which, if it cannot be built,
keeps community drivers incompatible with the deterministic-verification thesis.

## D147 — EKS cluster substrate (capability.cluster.kubernetes, slice 1: observe)

The first full-platform reference target (an Acme-style EU SaaS on AWS EKS) justified
the long-parked cluster-substrate slice (D10 — no longer speculative). A new
capability TYPE, capability.cluster.kubernetes, governs the managed cluster ITSELF —
distinct from capability.cluster.namespace (in-cluster governance) and
capability.workload.container (what runs on it). What an org contracts about a
control plane: residency (location.region), version currency (cluster.version,
governed for EOL/CVE/compliance), API-server exposure (network.apiExposure —
public|private|mixed, a security guardrail), secrets encryption (encryption.secrets),
and node HA topology (availability.class). Instance types, AMIs, addon versions,
node counts beyond a floor are implementation noise. STATEFUL: a cluster holds etcd
and hosts bound workloads, so the delete/replace gates bind it like a database.

One TYPE, many services (D76): aws.eks / gcp.gke / azure.aks / Talos all fulfil it.

Slice 1 is OBSERVE-only (reality is the first author): the AWS eks driver reverse-maps
DescribeCluster to the governed attributes and discoverEKS (ListClusters) surfaces a
cluster for adoption — so groundhold can WITNESS, AUDIT, and ADOPT a cluster stood up by
eksctl/Terraform, and VERIFY residency=EU, version currency, private exposure, and
secrets encryption, before it can author one. availability.class is a node-group
attribute observed in slice 2 (a diagnostic names the honest omission). The mutating
methods refuse-closed honestly via the driver default ("not wired yet"); provisioning
the composite (cluster + node groups + IAM roles + OIDC provider) is slice 2. Vocab
dual-registered (Go + Python), pinned by two conformance cases (exposure enum
satisfied + out-of-enum load error); golden httptest for observe/discover.

### D147 slice 2 — EKS provisioning composite (author, not just witness)

The cluster substrate can now be PROVISIONED, not only observed. Following the ALB
composite pattern, `BuildEKS` maps the vocab attributes to the CreateCluster shape
and takes the placement OPERANDS from the implementation block (D26): clusterRoleArn,
subnetIds (>=2), nodeRoleArn, nodeGroup{instanceTypes, min<=desired<=max}, and
kmsKeyArn iff encryption.secrets — the IAM roles / VPC / KMS are separate capabilities,
passed in, not authored here. `createEKS` provisions in dependency order — CreateCluster
→ poll DescribeCluster to ACTIVE → CreateNodegroup → poll to ACTIVE — and `deleteEKS`
tears down in REVERSE (node group, then cluster), each ownership-tag-gated. observeEKS
now derives availability.class from the node group's subnet AZ spread (multi-AZ →
regional). claim tags the deterministic cluster ARN (no describe needed).

Four-valued is exact: once the cluster is ACTIVE, every later ambiguity carries the
providerId as `unknown` (a half-provisioned cluster to reconcile, never a silent
`failed` implying nothing landed); a cluster-level FAILED during the poll is `failed`
WITH the pid (the object exists); a foreign cluster refuses. In-place cluster update
(version/endpoint) stays slice 3 — ClassifyChange returns `unsupported` with an honest
reason rather than replace a stateful cluster. This makes groundhold the AUTHOR of an EKS
control plane + node group — the substrate under a Acme-style EU platform — with
the residency, exposure and encryption posture verified deterministically.

### D147 slice 3 — EKS in-place update (the drift-repair loop closes)

The cluster can now EVOLVE in place, not only be created and destroyed —
ClassifyChange returns `mutable` for cluster.version (UpdateClusterVersion) and
network.apiExposure (UpdateClusterConfig), where slice 2 returned `unsupported`.
`updateEKS` re-checks ownership tags, then applies the changed paths SEQUENTIALLY
(EKS permits one update at a time), each an LRO polled via DescribeUpdate to
`Successful`. Four-valued: a transport error / 5xx / no-update-id is `unknown` WITH
the providerId (may have landed); a `Failed`/`Cancelled` update is `failed` WITH the
pid; a timeout is `unknown`. A foreign cluster refuses before any patch.

encryption.secrets stays `unsupported` — EKS can only ENABLE it (one-way) and never
disable, so groundhold refuses the change rather than replace a stateful cluster;
availability.class stays a node-group property. `PermissionsFor(aws, eks, "update")`
adds eks:DescribeUpdate (the poll). With observe (slice 1), provisioning (slice 2)
and in-place update (slice 3), the full posture loop closes for the EKS substrate:
groundhold can witness, author, and repair drift on the cluster under an EU platform,
with residency/exposure/encryption verified deterministically at each step.

## D148 — SES outbound email (capability.email.sending)

The first driver of the Acme reference build: authenticated outbound email, the
side of the product whose invoices and statutory demands (the Egzekutor, Directive
2011/7) MUST be deliverable and whose bounces MUST return to the record. New capability
TYPE capability.email.sending governs: location.region (residency), authentication.dkim
(Easy DKIM signing — the posture that keeps statutory mail out of spam), bounce.tracked
(a configuration-set event destination captures BOUNCE+COMPLAINT to a durable sink),
service.managed. The sending domain, bounce SNS topic and configuration-set name are
operator OPERANDS (impl block, D26) — a domain is an identity the operator owns, a
bounce topic is a separate capability (messaging.topic). STATELESS.

The aws ses-sending driver (SESv2) is a composite: CreateEmailIdentity (Easy DKIM) +
CreateConfigurationSet + CreateConfigurationSetEventDestination (bounce/complaint -> SNS).
observe/create/update/delete/adopt/claim + discover (ListEmailIdentities, DOMAIN
identities only). Four-valued: once the identity exists, every subsequent composite
failure is unknown WITH the providerId (a sender claiming tracking with no sink, to
reconcile), never a silent half-provision; create does NOT block on DKIM Status==SUCCESS
(the DNS records are the operator's to publish) — observe reports the status honestly.
Update wires both mutable paths (DKIM signing, bounce tracking). Claim tags the
deterministic identity ARN. One TYPE, many services (D76): a future gcp/azure/postmark
sender fulfils it. The inbound deal-mailbox pipeline is a separate capability
(capability.email.inbound), the next slice.

## D149 — EKS addons + Pod Identity (capability.cluster.addon, capability.identity.podidentity)

The two drivers that make the EKS substrate USABLE by a real workload, and the
sharpest test of the author-vs-witness boundary (Acme D2): what couples to cloud
identity AT CLUSTER BIRTH is groundhold's; what a GitOps controller reconciles later is
ArgoCD's. Managed addons (vpc-cni, coredns, kube-proxy, aws-ebs-csi-driver) and EKS
Pod Identity associations sit on groundhold's side because they bind the cluster to AWS
IAM before any app is deployed — an ALB controller / ESO / Karpenter installed by Helm
does not.

capability.cluster.addon: addon.name, addon.version, service.managed — STATELESS.
The aws eks-addon driver (CreateAddon/DescribeAddon/UpdateAddon/DeleteAddon) is
keyed on (clusterName, addonName), both OPERANDS. version and apiExposure-equivalent
are MUTABLE (UpdateAddon LRO), so a version bump repairs in place rather than replace.
Four-valued on the create/poll: transport/5xx/DEGRADED mid-create is unknown WITH the
providerId; a CREATE_FAILED is failed WITH the pid; a foreign addon refuses.

capability.identity.podidentity: workload.namespace, workload.serviceAccount,
service.managed — STATELESS. The aws eks-podidentity driver
(CreatePodIdentityAssociation/DescribePodIdentityAssociation/DeletePodIdentity-
Association) binds a k8s service account to an IAM role — the coupling that lets a pod
assume a role with no static keys. The role ARN is the operator's OPERAND (a separate
identity capability owns the role). No in-place update path (an association is
(cluster, ns, sa, role) — a role change is a replace); claim is honest-refuse
(association IDs carry a server suffix, deferred). Both discoverers registered so the
proactive posture sees them. B1/B2 of the Acme gap: without Pod Identity the P0 data
drivers are dead in the runtime, so this was the biggest concession.

## D150 — Bedrock inference profiles (capability.ai.inference) and the EU-residency verifier trap

The AI substrate for Acme, and the cleanest demonstration that residency is verified
DETERMINISTICALLY with zero engine change. capability.ai.inference:
location.region, inference.destinationRegions (kind:list — the cross-region routing an
inference profile permits), model.provider, model.access (a MANUAL GATE — Bedrock model
access is granted in-console, not via API), service.managed — STATELESS.

The D1 rule: the driver OBSERVES a profile's inference.destinationRegions (network in
observe, allowed — not the verifier, #6); the contract asserts
`destinationRegions subset-of [EU allowlist]` with the EXISTING closed operator. An
inference profile that can route to eu-south-2 (outside the EU-residency allowlist) is
caught as `violated` — and a violated hard constraint is NON-EXECUTABLE, so the plan
refuses. Two conformance cases pin it: ai-inference-eu-residency-satisfied
(executable:true, satisfied) and ai-inference-eu-south-2-trap-caught-deterministically
(executable:false, violated). No org/SCP machinery, no landing-zone — the residency
guarantee is a subset-of over an observed list.

The aws bedrock driver (CreateInferenceProfile/GetInferenceProfile/DeleteInference-
Profile/ListInferenceProfiles) reads destinationRegions from models[].modelArn (the
region is ARN index 3). model.access is a manual gate: the driver OBSERVES access state
and honest-refuses Create when access is not granted — it never fakes the gate.

## D151 — Cost budgets (capability.cost.budget)

An EU platform that must not surprise its founders needs a provisioned cost guardrail.
capability.cost.budget: budget.limit (kind:money), budget.period (enum daily|monthly|
quarterly|annually), alert.threshold (number percent), service.managed — STATELESS.
The aws budgets driver (ModifyBudget/DescribeBudget via budgets.amazonaws.com) is
GLOBAL (us-east-1, account-scoped) — added to isGlobalService. Ownership is the
DETERMINISTIC budget name (name-keyed, no tag ARN), so claim is honest-refuse.
budget.limit and alert.threshold are MUTABLE (ModifyBudget). Four-valued as every
driver. PermissionsFor: budgets:ModifyBudget (create/update/delete), budgets:ViewBudget
(read).

## D152 — Aurora PostgreSQL Serverless v2 (aurora on capability.database.relational)

The P0 datastore for Acme: HA PostgreSQL that scales to the founder-stage load without
a fixed instance bill. NOT a new capability TYPE — Aurora fulfils the existing
capability.database.relational as a distinct SERVICE (D76, one TYPE many services),
reusing RDSBaseURL (no aws.go change). The aws aurora driver is a COMPOSITE:
CreateDBCluster (Aurora PostgreSQL, serverless v2 scaling) + CreateDBInstance (writer,
optional reader) in dependency order. providerId aurora:<region>:<clusterId>.

Operands (impl block, D26): subnetGroupName (req), serverlessMinACU/serverlessMaxACU
(req — the scaling floor/ceiling), kmsKeyArn (iff encryption.atRest),
vpcSecurityGroupIds, deletion_protection. Four-valued: once the cluster exists, a
member-instance failure is unknown WITH the pid (a cluster with no writer, to
reconcile), never a silent half-provision. ModifyDBCluster/ModifyDBInstance for the
mutable paths; DeleteDBInstance-before-DeleteDBCluster on retire. Claim tags the
DETERMINISTIC cluster ARN (arn:aws:rds:<region>:<account>:cluster:<id>) via the generic
RGT path. PermissionsFor uses the RDS API family (Create/Modify/Delete DBCluster+
DBInstance + DescribeDBClusters). This closes the Acme P0 data driver set alongside
D149 Pod Identity.

## D153 — AWS Backup Plan (capability.backup.plan)

The DR-policy layer over the D-vault: a plan is the SCHEDULE (cadence + retention +
selection + optional cross-region copy), the vault is the STORE. New capability TYPE
capability.backup.plan — STATELESS (a plan is a schedule, not a store; deleting it
stops future backups but does not erase recovery points already written to the vault,
which age out under the vault's own retention/lock — the sharp contrast with
capability.backup.vault's stateful:true). Attributes: schedule.frequency (duration —
the RPO determinant, first-class so it composes with `recovery point objective <= Xh`
with no coercion; the exact cron is the operand), retention.duration, copy.crossRegion,
copy.destinationRegion (first-class residency: an EU-only contract catches a non-EU DR
copy), location.region. Target vault ARN + backup IAM role + resource selection are
operands (D26). The aws backupplan driver reuses the vault's API host (backupBase /
backupCall — no aws.go change): composite CreateBackupPlan + CreateBackupSelection (a
plan with no selection backs up nothing). Four-valued: a lost create response is unknown
WITHOUT the pid (server-assigned id; CreatorRequestId idempotates the retry, discover
reconciles by tags); a failed selection after the plan exists is unknown WITH the pid.
Claim is honest-refuse (the BackupPlanId is a server handle, no account in the pid —
matches eks-podidentity).

## D154 — CloudTrail audit trail (capability.audit.trail)

The audit record an EU platform's compliance is written against, and P2 gate before
prod. New capability TYPE capability.audit.trail — STATEFUL (the trail holds the audit
mechanism; delivered log OBJECTS live in the operand S3 bucket, so DeleteTrail ends the
record but does not erase past logs — stated, not hidden). Attributes: location.region
(home region), scope.multiRegion, integrity.logValidation (the cryptographic proof the
log was not tampered with — the compliance keystone), encryption.customerManagedKeys,
delivery.assured (GetTrailStatus IsLogging — a standing-but-silent trail is caught),
service.managed, cost.monthly. Destination bucket, KMS key, SNS topic, CloudWatch Logs
group are operands. The aws cloudtrail driver (region-scoped JSON, package-level base-URL
override) is a composite: CreateTrail + StartLogging (a trail that is not logging is
dead). In-place update wires scope.multiRegion / integrity.logValidation / CMK via
UpdateTrail and delivery.assured via StartLogging/StopLogging; region is immutable
(replacement). Four-valued: once CreateTrail lands, a failed StartLogging is unknown WITH
the pid (a standing-but-not-logging trail to reconcile). A conformance case pins that a
trail without log-file validation is violated (non-executable) and an unstated
delivery.assured verifies unknown (never a fabricated false).

## D155 — S3 Cross-Region Replication (replication on capability.storage.object)

Multi-region DR for object storage, and the third proof that residency is verified
DETERMINISTICALLY by observing the fact (the D1/Bedrock pattern), not trusting a
declaration. Two attributes added to capability.storage.object: replication.enabled
(bool) and replication.destinationRegion (string). The destination replica bucket is a
SEPARATE storage.object capability in another region (D3 multi-capability); its ARN and
the replication IAM role are operands. The residency substance: an S3 bucket ARN carries
NO region, so the driver OBSERVES the destination region via GetBucketLocation on the
replica named in the LIVE replication rule (never from the operand — measured, not
declared); the contract asserts `replication.destinationRegion in [EU allowlist]` with
the existing membership operator. A replica in us-east-1 is caught as violated
(non-executable) before any data leaves the EU. CRR presupposes versioning — the build
honest-refuses replication.enabled without versioning.enabled (the retention.locked
presupposition pattern). PutBucketReplication runs after versioning in the create
composite (four-valued via the shared s3Step); both replication paths are mutable
(PutBucketReplication / DeleteBucketReplication when off). One IAM action
(s3:PutReplicationConfiguration) authorises both the PUT and the DELETE.

## D156 — VPC NAT egress (egress.internet on capability.network.private, B4 slice 1)

The networking substrate that makes the EKS cluster FUNCTIONAL: without an egress road,
nodes in private subnets cannot bootstrap (no ECR pulls, no STS/EC2 API). Design (a review
brainstorm): zero new capability TYPEs, one enum on the existing capability.network.private
— `egress.internet: none | nat | direct` — the road axis, kept ORTHOGONAL to the existing
egress.restricted (the destination-discipline axis the driver previously, wrongly,
conflated with "no route"). Route tables, IGW, EIP, NAT-per-AZ, CIDRs are realization
operands (D26), not vocab. The aws vpc driver's slice 1 builds the `nat` road as an
ordered composite: public subnet → IGW+attach → EIP → NAT gateway (poll to available) →
public route table (0.0.0.0/0→IGW) → private route table (0.0.0.0/0→NAT), every step
ownership-tagged, every failure unknown WITH the pid, teardown in reverse dependency
order. Observe derives egress.internet from the route tables (measured); ingress.public
stays false for the nat shape (the IGW serves only the NAT's public subnet, not the
workload path); egress.restricted becomes road-derived config-intent with a diag that no
SG audit ran this slice. `direct` and in-place road changes are honest-refused (future
slices) rather than faked — in particular egress.internet stays classify:unsupported (no
in-place updater this slice), never mutable-without-an-updater. Slices 2/3
(serviceAccess.private + VPC endpoints; baseline SG operands + hard ingress.public
verification) follow.

### D151/D152 correction — mutable classify must have a wired in-place updater

Wiring the four D149–D152 drivers surfaced a latent gap in the shipped D151/D152 code:
budgets (budget.limit / alert.threshold) and aurora (engine.protocol / recovery.rpo /
network.publicExposure) classified those paths as `mutable`, but no updateBudget /
updateAurora existed and no Update-switch arm dispatched them — a mutable drift would
emit an update action that hit the Update `default` and failed at apply. `make check`
missed it (no conformance case drives those services through the update executor). Fixed:
updateBudget (ModifyBudget for the limit; UpdateNotification, keyed on the live old
threshold, for the alert) and updateAurora (ModifyDBCluster for version/RPO,
ModifyDBInstance per member for public exposure; availability.class honest-refused as an
added-reader resource), both ownership-tag/​name gated and four-valued, plus their Update
arms. The invariant this makes explicit: a `mutable` classification is a PROMISE the
service can honor the change in place — it must always have a wired updater, or it is not
mutable.

## D157 — VPC endpoints / private service access (serviceAccess.private, B4 slice 2)

The second VPC networking slice: provider-API traffic stays on the private backbone
instead of egressing to the public internet — the EU-path guarantee (§1/§2) and a NAT
cost cut. One new bool on capability.network.private, `serviceAccess.private`, the same
posture genus as the existing interconnect.private (twin: VPC endpoints / Private Google
Access / Private Link). The endpoint SET is a driver-known operand (gateway endpoint for
s3; interface endpoints for ecr.api, ecr.dkr, sts, secretsmanager, logs, sqs,
bedrock-runtime, kms), overridable via impl.vpc_endpoints; interface-vs-gateway is
mechanics, not vocab. Observe is a SET-COVERAGE check: DescribeVpcEndpoints (only
`available` endpoints count), serviceAccess.private=true iff observed ⊇ the required set,
else measured false + a diag naming the missing ones (never unknown from a readable
sweep). Classify stays unsupported (endpoints provisioned at create; no in-place updater
this slice — never mutable-without-an-updater). Backward compatible: a contract without
the attribute builds no endpoints.

## D158 — SES inbound / the deal mailbox (capability.email.inbound)

The core product path (module M1): brand mail arrives, the AI parser drafts a deal. New
capability TYPE capability.email.inbound — STATELESS (receipt rule set/rules are
configuration; raw mail lands in the operand S3 bucket). Attributes: location.region
(residency), spam.filtered (the receipt rule scans for spam/virus verdict),
delivery.sink (mail is delivered to a durable sink AND our rule set is the ACTIVE one —
an inactive rule receives nothing, so delivery.sink is "assured"-like), service.managed.
Recipient domain, rule-set/rule names, S3 bucket, SNS topic, MX record are operands /
separate capabilities. The aws ses-inbound driver (SES v1 receiving Query protocol,
reusing the SESv2 host) is a composite: CreateReceiptRuleSet + CreateReceiptRule (S3
action + ScanEnabled) + SetActiveReceiptRuleSet. Four-valued: once the rule lands, a
failed SetActiveReceiptRuleSet is unknown WITH the pid (a standing-but-inactive rule that
receives nothing — reconcile), mirroring CloudTrail StartLogging. Ownership is the
deterministic (pv-prefixed) rule-set + rule name (receipt rules carry no tags — claim
honest-refuses; the name-as-marker weakness is documented). In-place update wires
spam.filtered / delivery.sink via UpdateReceiptRule; region is unsupported. SES allows
one active rule set per account+region — inherent, appropriate for a dedicated receiving
domain.

## D159 — S3 Object Lock (WORM) at bucket birth

The Egzekutor's legal demands need write-once-read-many storage that even an admin cannot
shorten. The shipped S3 driver REFUSED retention.minimum/retention.locked (Object Lock is
create-time-only and the 409-continue path could not re-assert it). Now that groundhold
controls the create from zero, both ride the bucket's birth: retention.minimum → a
DefaultRetention floor (duration→whole days), retention.locked → COMPLIANCE mode (a hard
WORM even root cannot shorten) vs GOVERNANCE (min-only, override with permission), the
bucket born with `x-amz-bucket-object-lock-enabled: true`. Presuppositions honest-refused:
locked-without-a-floor, and Object-Lock-without-versioning (Object Lock requires
versioning — the same shape as the CRR presupposition). s3Req gained a Headers carrier for
the create-time header; create order is create→versioning→object-lock→replication→
lifecycle→encryption. Classify is immutable (Object Lock enablement is create-time-only
and irreversible, and a COMPLIANCE floor cannot be shortened — a change is a consented
replacement of the stateful bucket, never a fake in-place patch). CRR (D155) is untouched
and coexists (both presuppose versioning).

## D160 — SQS dead-letter reliability + ECR scan-on-push (D4 posture attributes)

Two supply-side posture bools the platform requires. capability.messaging.queue gains
`reliability.deadLetter` — "messages unprocessed after N attempts are captured to a DLQ,
not lost"; the DLQ target ARN + maxReceiveCount are operands (D26), the RedrivePolicy
rides in the existing SetQueueAttributes plumbing. capability.registry.image gains
`security.scanOnPush` — "images are vulnerability-scanned on every push"
(imageScanningConfiguration.scanOnPush). Both are mutable WITH a wired updater
(SetQueueAttributes / PutImageScanningConfiguration) — the mutable-must-have-an-updater
rule from D151/D152. ECR additionally gained its first classify/update wiring (previously
default-unsupported), so scan-on-push and tag-mutability now repair in place.

## D161 — Acme platform contract: groundhold's first real project (end-to-end proof)

examples/acme/ is the first contract groundhold authors for a real platform (acme.example, EU
SaaS). platform.contract.yaml declares the substrate groundhold OWNS — 14 capabilities
(network with NAT+private-endpoints, private HA EKS, Aurora Sv2 with CMK, S3 with CRR,
an Object-Lock audit store, SES in/out, Bedrock EU inference, KMS, CloudTrail, a budget,
SQS with a DLQ, a backup plan, ECR with scan-on-push) — and NOT the application layer
(Karpenter, the ALB controller, External Secrets, ArgoCD apps, observability are
GitOps-owned, per author-vs-witness). ~45 hard constraints; every EU-residency one is a
closed-operator membership/subset check (`in` / `subset-of` over the EU allowlist), so a
config that would route data outside the EU is caught at plan, before apply — the D1 rule
replacing org/SCP with a deterministic verifier. Proven end-to-end: `verify` → PROVEN
(42/42 satisfied), `plan` → SEALED (14 create actions with per-action permissions and
risk). The residency guardrail is demonstrated by a trap variant (CRR to eu-west-2/London
+ Bedrock to us-east-1) → verify VIOLATED, plan REFUSED (exit 2). This closes the Acme
platform-substrate coverage: the deployment now waits only on our go, not on missing
drivers.

## D162 — VPC baseline security group + hard ingress.public verification (B4 slice 3)

The third VPC slice makes ingress.public a MEASURED posture, not a route-only guess. A
security group's rules are D26 operands (closed operator set #4 — the WAF precedent:
rules opaque, posture a flag), so no SG capability TYPE and no rule vocab. The vpc driver
authors a baseline SG (default: intra-VPC ingress only, never 0.0.0.0/0; overridable via
impl.baseline_sg_ingress) tagged for ownership, and REFUSES at build any rule that opens
the world while ingress.public is required false. Observe reduces ingress.public from TWO
OR-combined doors, both measured: the route door (a direct IGW default route on the
workload path — a NAT road keeps it false) and the SG door (ANY SG in the VPC with a
0.0.0.0/0 or ::/0 ingress rule). An open rule is definitive → ingress.public=true even if
routes are clean — the trap. An unreadable SG sweep falls back to the route door + a diag
(never a false claim of closure). Author-vs-witness: groundhold owns the baseline SG OBJECT
but tolerates controller-appended rules (no auto-revoke — a converge would otherwise fight
the ALB/EKS controller); a posture-breaking foreign rule is WITNESSED (observe returns
true, flipping the verdict to violated on a plate), never silently removed. Classify stays
unsupported (no updateVPC this slice — never mutable-without-an-updater).

## D163 — SES production access as a manual-gate (sending.productionAccess)

SES accounts start sandboxed; leaving the sandbox is a human console request, not an API
call — and for Acme the sandbox exit is a legal-deliverability gate (dunning mail must
arrive). New observe-only bool on capability.email.sending: sending.productionAccess,
mapped to SESv2 GetAccount ProductionAccessEnabled. The driver OBSERVES the gate and never
sets it: create does not touch it (not a presupposition, not refused), classify is
unsupported ("manual-gate — not a patch API; groundhold observes, does not provision"). A
contract asserting productionAccess=true against a sandboxed account verifies violated →
plan refuses until a human opens the gate. The same honest shape as Bedrock model.access
(D150): groundhold tells the truth about a gate it cannot open, never fakes it. Zero
shared-file changes — the observe/classify dispatch already existed.

## D164 — CloudWatch Logs retention (capability.monitoring.logs)

AWS-native log retention (VPC flow logs, EKS control-plane) is a compliance + cost posture
Acme requires. New capability TYPE capability.monitoring.logs — STATEFUL (a log group
holds logs; delete loses history, D47 friction). Attributes: location.region,
retention.days (kind:duration — retention is first-class time semantics, so a contract
writes `retention.days gte 90d` with no coercion; the driver maps duration→whole days and
REFUSES any value outside CloudWatch's fixed allowed set, never rounding to a neighbour),
encryption.customerManagedKeys, service.managed, cost.monthly. The aws cwlogs driver
reuses the awslogfilter API host (logs.<region>, Logs_20140328; no aws.go change):
CreateLogGroup + PutRetentionPolicy (+ AssociateKmsKey iff CMK). CMK observe is honest-true
(CloudWatch exposes kmsKeyId only for a customer key — cleaner than Aurora's ambiguity).
retention.days and CMK are mutable WITH wired updaters (PutRetentionPolicy /
Associate-Disassociate KMS); region immutable. Claim is tag-based (the log-group ARN is
buildable). retention.days required at create (a group with no policy never expires).

## D165 — GuardDuty threat detection (capability.security.threatdetection)

The platform threat-detection posture (Acme §7: GuardDuty + EKS Protection). New
capability TYPE capability.security.threatdetection — STATELESS (the detector is a posture
switch + config; findings live in the service, delete is a posture change not a store
loss). Attributes: location.region, detection.enabled, protection.kubernetes,
protection.malware, service.managed, cost.monthly. findingPublishingFrequency is an
operand. The aws guardduty driver (REST, package-level base-URL override) handles the
account+region SINGLETON: create pre-reads via ListDetectors — no detector → CreateDetector
(Features for EKS/malware); ours (tags) → converge via UpdateDetector; FOREIGN → honest
refuse ("the account already has a detector not groundhold-managed"). Four-valued: a lost
create before the id lands → unknown (ListDetectors reconciles the singleton); an
UpdateDetector failure on a standing detector → unknown WITH the pid. All protection.*
paths are mutable WITH a wired updater. Claim is tag-based (deterministic detector ARN).

### D161 extended — Acme platform contract now covers the optional closures

The Acme platform contract (examples/acme/) grew from 14 to 16 capabilities: added the
GuardDuty detector and the CloudWatch Logs retention group, plus the SES
sending.productionAccess manual-gate constraint and the baseline-SG-backed ingress.public.
Re-proven end-to-end: verify PROVEN (48/48 satisfied, 3 rest on inferred values), plan
SEALED (16 create actions). The platform-substrate coverage for acme.example is now complete —
network (NAT + private endpoints + baseline SG), private HA EKS, Aurora, S3 (CRR + Object
Lock), SES in/out (with the prod-access gate), Bedrock EU, KMS, CloudTrail, GuardDuty, log
retention, budgets, SQS + DLQ, backup plan, ECR scan.

## D166 — GCP posture parity (billingbudget, logbucket, auditlogs, scc, vertexai)

Parity wave 1a (D76: one TYPE, many services): the AWS-only posture capabilities now
have GCP services, so the same contract can bake-off across clouds. Five new GCP drivers,
each new files, honest per-cloud mapping (never a faked attribute):
- **billingbudget** (cost.budget) → Cloud Billing Budget. budget.limit/period/alert all
  mutable via one budgets.patch; `daily` honest-refused (GCP calendarPeriod is
  MONTH/QUARTER/YEAR only); ownership by deterministic displayName (no labels).
- **logbucket** (monitoring.logs) → Cloud Logging bucket. retention.days (duration→days,
  rounds UP) + CMEK mutable via updateMask; ownership by description marker (like
  logmetric); STATEFUL, locked-bucket delete refused.
- **auditlogs** (audit.trail) → a Cloud Logging export SINK filtered to
  cloudaudit.googleapis.com. The honest divergence from CloudTrail: `integrity.logValidation`
  has NO GCP equivalent → REFUSED at build, never faked; `location.region`/CMEK live on the
  destination operand (omitted on observe with a diag); `scope.multiRegion` honored (GCP
  audit is project-global), `delivery.assured` mutable (sink disabled toggle).
- **scc** (security.threatdetection) → Security Command Center securityCenterServices
  modules (event-threat-detection / container-threat-detection / VM-threat-detection). A
  label-less per-parent SINGLETON with no ownership marker → groundhold is documented as its
  configurator, not exclusive owner; STANDARD tier refuses the threat modules; regional
  location refused (SCC is global); protection.* mutable via intendedEnablementState patch.
- **vertexai** (ai.inference) → Vertex AI endpoint. The D1 residency rule cross-cloud:
  destinationRegions is MEASURED from the server-returned resource name (not the pid's
  claimed location), and the "global" endpoint measures as ["global"] — a non-EU sentinel
  the existing subset-of constraint catches as violated. model.access is a manual-gate
  (Model Garden console terms). All routing immutable (a new endpoint, not a patch —
  parity with Bedrock, so no updater).

make check 386/386, differential 0. Azure posture parity (wave 1b) and the remaining waves
(attribute extensions, cluster family, backup/email) follow.

## D167 — Azure posture parity (consumptionbudget, loganalytics, activitylog, defender, azureopenai)

Parity wave 1b (D76): the five posture capabilities now have Azure services, completing the
three-cloud posture parity (AWS + GCP + Azure) that closes wave 1. Five new Azure drivers,
honest per-cloud mapping:
- **consumptionbudget** (cost.budget) → Microsoft.Consumption/budgets. limit/period/threshold
  mutable via full PUT; `daily` refused (Azure timeGrain is Monthly/Quarterly/Annually — same
  as GCP); currency verified-or-refused against the subscription billing currency (the D99
  account-scope trap, no coercion); name-marker ownership (proxy resource, no tags).
- **loganalytics** (monitoring.logs) → Microsoft.OperationalInsights/workspaces. retention.days
  (duration→days, [30,730], refuses out-of-range) mutable via updater; CMK honest-refused (a
  dedicated-cluster feature, not a standalone-workspace property — like Redis CMK D100). This
  is the FIRST Azure service with a real in-place updater — Azure's Update dispatch changed
  from an unconditional "not wired" stub to a service switch.
- **activitylog** (audit.trail) → a subscription-scope Microsoft.Insights/diagnosticSettings
  exporting the Activity Log — the twin of the GCP sink. integrity.logValidation REFUSED (no
  Azure equivalent, never faked); scope.multiRegion honored (Activity Log is subscription-
  global); location/CMK live on the destination operand (omit on observe); delivery.assured
  mutable.
- **defender** (security.threatdetection) → Microsoft.Security/pricings plan singletons
  (Servers→detection.enabled, Containers→protection.kubernetes, Storage on-upload malware→
  protection.malware — one attribute per distinct plan, no overlap). Config-not-owner (no tags
  → claim honest-refuse); regional location refused (subscription-scoped); protection.* mutable.
  Discovery emits the posture singleton always (pricings always exist), so a disabled Defender
  is surfaced — the posture doctrine (D142), a per-cloud divergence from GuardDuty's
  return-nothing-when-absent.
- **azureopenai** (ai.inference) → Microsoft.CognitiveServices/accounts (kind=OpenAI). The D1
  residency rule cross-cloud: destinationRegions MEASURED from the live deployment skus —
  regional→[region], GlobalStandard→["global"], DataZone→["datazone-<zone>"], the trap value
  winning the union — so a global/data-zone deployment is caught as violated by the existing
  subset-of. model.access is a manual-gate; routing immutable (no updater, like Bedrock/Vertex);
  claimable (the account bears tags).

make check 386/386, differential 0. Wave 1 (posture TYPEs × 3 clouds) complete; waves 2-4
(attribute extensions, cluster family, backup/email) follow.

## D168 — GCP attribute parity (Cloud NAT+PGA, GCS dual-region+lock, Pub/Sub DLQ, AR scan)

Parity wave 2a (D76): the new attributes AWS drivers grew (D156-D160) now have GCP honoring
on the EXISTING GCP drivers. Honest per-cloud mapping, backward compatible:
- **vpc** — egress.internet=nat → a Cloud Router carrying a Cloud NAT (`direct` honest-refused:
  a per-instance external IP is not a VPC-layer property); serviceAccess.private → the subnet's
  privateIpGoogleAccess (Private Google Access — the direct twin of VPC endpoints). Both
  provisioned at create, classify unsupported (parity with the AWS vpc slices, no updater).
- **gcs** — retention.minimum/retention.locked were already honored (retentionPolicy +
  lockRetentionPolicy WORM). Added replication: GCS has NO S3-style CRR to an arbitrary region,
  so replication.enabled maps HONESTLY to a configurable dual-region bucket
  (customPlacementConfig.dataLocations = the region pair) with turbo replication (rpo=
  ASYNC_TURBO); replication.destinationRegion is the same-continent peer region, MEASURED from
  customPlacementConfig (never trusted from the declared value). Create-time (insert-only) →
  immutable, a change is a replacement. The divergence from S3 (a peer pair, not a directional
  replica) is documented, not faked.
- **pubsub-queue** — reliability.deadLetter → the subscription's deadLetterPolicy
  (deadLetterTopic + maxDeliveryAttempts operands); mutable via subscriptions.patch WITH a wired
  updater (set builds from operands, clear is patch-to-empty) — parity with the SQS RedrivePolicy.
- **artifactregistry** — security.scanOnPush → the PROJECT-level Container Scanning API
  (containerscanning.googleapis.com via Service Usage), NOT a per-repo field like ECR. Enabled at
  create, MEASURED from the API state (observe attaches a diagnostic that it is a project posture);
  classify unsupported — a per-repo patch that toggled a project-wide API would change scanning for
  every repo, a blast radius a repo-scoped update must not own. No per-repo scanOnPush is faked.

make check 386/386, differential 0. Azure attribute parity (wave 2b) follows.

## D169 — Azure attribute parity (NAT Gateway+service endpoints, Blob replication+immutability, Service Bus DLQ, ACR scan)

Parity wave 2b (D76): the new attributes now have Azure honoring on the EXISTING Azure
drivers, completing wave 2 (attribute extensions × GCP + Azure). Honest per-cloud mapping:
- **vnet** — egress.internet=nat → a NAT Gateway + Standard public IP attached to the subnet
  (`direct` refused: per-instance public IP, not a VNet-layer property); serviceAccess.private →
  subnet service endpoints (canonical set CognitiveServices/ContainerRegistry/KeyVault/ServiceBus/
  Sql/Storage). Both create-time, classify unsupported (parity with AWS/GCP vpc, no updater).
- **blob** — retention.minimum/retention.locked were already honored (container immutability policy
  + WORM lock). Added replication: object replication policy (the two-account dance — write the
  policy on BOTH destination and source, matching policyId/ruleId), CLOSER to S3 CRR than GCS
  (directional to another account); replication.destinationRegion MEASURED from the destination
  account's location (never trusted from the declared value); presupposes versioning + change feed.
  Classify immutable (no in-place updater — object replication is reconfigurable but classified
  immutable to honor the no-mutable-without-updater rule; a change is a consented replacement).
- **servicebusqueue** — reliability.deadLetter → the queue's maxDeliveryCount +
  deadLetteringOnMessageExpiration. The honest divergence: Azure's $DeadLetterQueue is BUILT IN and
  always present (unlike SQS/Pub-Sub's separate target), so the signal is the toggle, not the target's
  existence; the operand is max_delivery_count, not an ARN/topic. Mutable WITH a wired updater —
  the first extra Azure updater after wave 1b.
- **acr** — security.scanOnPush → Microsoft Defender for Containers
  (Microsoft.Security/pricings/Containers), a SUBSCRIPTION posture (not a per-registry field). ACR
  does NOT enable it (that is the defender driver's job, D167) — it OBSERVES the truth from the
  Defender pricing (reusing the defender driver's getDefenderPricing, same package) and honest-refuses
  a create that asks scanOnPush=true, directing to capability.security.threatdetection. Classify
  unsupported. The sharpest of the three clouds: ECR per-repo, GCP project-API, Azure a separate
  driver's subscription posture — each mapped to what the cloud actually does.

make check 386/386, differential 0. Wave 2 (attribute extensions × 3 clouds) complete; waves 3
(cluster family GKE/AKS) and 4 (backup.plan, email.sending) follow.

## D170 — GCP cluster family (GKE, GKE addons, Workload Identity)

Parity wave 3a (D76): the Kubernetes-cluster substrate now has GCP services — the heaviest
wave (the AWS EKS family was three slices), built as full loops:
- **gke** (cluster.kubernetes) → a GKE cluster (container.googleapis.com, LRO). apiExposure
  maps to privateClusterConfig.enablePrivateEndpoint + masterAuthorizedNetworks (private/mixed/
  public); encryption.secrets → databaseEncryption CMEK; availability.class → zonal (location=
  zone) vs regional (location=region), multi-regional honest-refused (no GKE primitive).
  cluster.version + apiExposure are in-place mutable WITH a wired updater; region/availability
  immutable, encryption unsupported. Four-valued partial composite: after the create LRO the
  cluster health is re-read — control-plane-up-but-node-pool-unhealthy → unknown WITH the pid.
  Ownership by resourceLabels.
- **gke-addon** (cluster.addon) → a FLAG in the cluster's addonsConfig (SetAddonsConfig), NOT a
  separately versioned package like EKS managed addons. addon.name maps to the addonsConfig
  field (with per-addon toggle-polarity: legacy `disabled:false` vs newer `enabled:true`, mapped
  explicitly so nothing is silently inverted); addon.version is honest-refused (GKE addons track
  the cluster version). Enable=create, disable=delete; structural ownership (no marker → claim
  honest-refuse).
- **gke-workloadidentity** (identity.podidentity) → a read-modify-write on the GSA's own IAM
  policy granting roles/iam.workloadIdentityUser to member
  serviceAccount:<pool>.svc.id.goog[<ns>/<ksa>] — the iambinding RMW+etag pattern, not a
  standalone resource. Content-addressed ownership (touches only its own member, foreign-refuse);
  etag conflict → unknown WITH the pid + reconcile hint (never a blind retry); replace-only
  (a namespace/ksa/gsa change is a different member) → immutable, no updater. Discoverer reverses
  every workloadIdentityUser member of the WI form.

make check 386/386, differential 0. Azure cluster family (wave 3b: AKS) follows, then wave 4.

## D171 — Azure cluster family (AKS, AKS addons, Workload Identity)

Parity wave 3b (D76): completes the Kubernetes-cluster substrate across all three clouds
(AWS EKS + GCP GKE + Azure AKS).
- **aks** (cluster.kubernetes) → Microsoft.ContainerService/managedClusters (LRO). apiExposure →
  apiServerAccessProfile (enablePrivateCluster=private / authorizedIPRanges=mixed / public);
  encryption.secrets → securityProfile.azureKeyVaultKms; availability.class → system pool
  availabilityZones (zonal/regional), multi-regional honest-refused. cluster.version +
  apiExposure(mixed↔public) mutable WITH updater; enablePrivateCluster is genuinely immutable
  (a private↔public conversion is refused at apply, never a silent no-op); region/availability
  immutable, encryption unsupported. Four-valued partial composite (control-plane-up + pool-not-
  Succeeded → unknown WITH pid). Claimable (ARM tags).
- **aks-addon** (cluster.addon) → managedCluster addonProfiles (a PUT read-modify-write that
  preserves the operator's other cluster fields). Uniform enabled polarity (simpler than GKE's
  mixed toggles); addon.version honest-refused (tracks the cluster version); enable=create,
  disable=delete; claim honest-refuse (structural, no marker).
- **aks-workloadidentity** (identity.podidentity) → a federatedIdentityCredential (a REAL ARM
  sub-resource under a UAMI: PUT/GET/DELETE), subject=system:serviceaccount:<ns>:<sa>,
  issuer=the AKS OIDC issuer, audience=api://AzureADTokenExchange. The divergence across clouds:
  EKS uses a tagged association resource, GCP a content-addressed IAM-policy member, Azure a
  deterministically-named ARM sub-resource matched on content (subject+issuer+audience) — all
  three replace-only/immutable, claim honest-refuse. Discoverer nests UAMI→FIC.

make check 386/386, differential 0. Wave 3 (cluster family × 3 clouds) complete; only wave 4
(backup.plan, email.sending — email.inbound has no GCP/Azure analog) remains.

## D172 — Backup plan + email sending parity, and the completion of the cross-cloud program

Parity wave 4 (final, D76): backup.plan and email.sending gain their non-AWS services,
closing the four-wave AWS->GCP/Azure parity program (D166-D172).
- **gcp backupplan** (backup.plan) → Backup and DR backupPlans (reusing the vault shell's
  backupdr base/LRO/label-ownership). schedule.frequency → StandardSchedule (HOURLY N /
  DAILY / WEEKLY); retention.duration → backupRetentionDays; both mutable via one masked
  patch. Claimable by labels (claimBackupPlanGCP, the exact sibling of claimBackupVault).
- **azure backuppolicy** (backup.plan) → DataProtection backupVaults/backupPolicies (chosen
  over legacy RecoveryServices for its workload-uniform declarative policyRules). Synchronous
  PUT; ownership by deterministic name (claim honest-refuse); location verified against the
  substrate vault (the D99 trap). schedule/retention mutable via full-PUT updater.
- **azure acsemail** (email.sending) → Communication/emailServices + a DKIM domain
  sub-resource. location.region maps to properties.dataLocation (the residency string — the
  resource itself is global), immutable; authentication.dkim → the domain's DKIM verification
  state, mutable (add/remove domain); claimable by ARM tags.

**The honest divergence that runs through the whole program: cross-region backup copy.**
AWS Backup expresses DR copy IN the plan (a Rule CopyAction -> destination-vault ARN, so
copy.destinationRegion is a first-class plan attribute). NEITHER GCP Backup-and-DR NOR Azure
DataProtection can express cross-region copy in a policy — it is a vault-redundancy setting on
both. So both non-AWS drivers HONEST-REFUSE copy.crossRegion=true / copy.destinationRegion at
build (pointing at capability.backup.vault) and observe copy.crossRegion=false as a measured
fact. groundhold never fabricates a DR posture the cloud cannot deliver.

**Deliberate, confirmed parity gaps (not missing work — no clean analog):**
- **email.inbound** stays AWS-only (SES receiving -> S3 + SNS). GCP and Azure have no managed
  inbound-mail-to-storage pipeline; a contract requiring capability.email.inbound is only
  fulfillable on AWS, by design.
- **email.sending** is AWS (SES) + Azure (ACS Email); GCP has no first-party transactional
  email service. A GCP email-sending contract is unfulfillable — an honest gap, surfaced rather
  than faked with a third-party shim.

These gaps are the point of the bake-off (D92): the deterministic verifier tells an agent when
a cloud CANNOT satisfy a contract (a real capability gap) versus when a driver is simply not yet
written. A machine-checked parity matrix (a spec artifact whose cells are proven against the
driver certify sets, so it can never drift or over-claim) is the natural next spec addition;
it is deferred deliberately rather than hand-authored with guessed cells, since a parity map
that lies is worse than none.

Service counts after the program: AWS 47, GCP 42, Azure 40 certified services. make check
386/386, differential 0.

## D173 — The machine-verified cross-cloud parity matrix (CertifyParity + spec/parity.yaml)

After the four-wave parity program (D166-D172), the question "which cloud can fulfil which
capability, and where is a cloud a structural dead end" was answered only in prose (D172). A
hand-authored matrix would drift and could over-claim — a parity map that lies is worse than
none. So the matrix is made a PROVEN artifact, the third iteration of the ServiceLister/
CertifyDiscoverability pattern.

**CapabilityMapper + CertifyParity.** Each driver implements the optional
`ServiceCapabilities() map[string]string` (SERVICE token -> the capability TYPE it fulfils;
D76 one-TYPE-many-services, so rds and aurora both map to capability.database.relational). The
maps were authored token-by-token against each driver's REAL `ResourceType` emissions (129
tokens; Azure's inconsistent ResourceType — some threaded through variables — traced to their
call-site literals rather than guessed). `provider.CertifyParity` (run in every driver's certify
test) asserts the map is a TOTAL, PHANTOM-FREE projection of the certified service set: every
certified service declares exactly one well-formed capability, and the map claims no service the
dispatch does not know.

**spec/parity.yaml — generated, gap-vs-unbuilt, byte-proven.** `go/internal/parity` generates
the matrix: a row per vocab TYPE, each (TYPE, cloud) cell exactly one of `fulfilled: [tokens]`
(from the driver maps), `gap: {class, reason}` (a STRUCTURAL claim the cloud has no such
service — closed class set {no-native-service, not-capability-shaped, policy-refused}), or
`unbuilt: true` (DERIVED — no token, no gap; a fact about groundhold, not the cloud). Nobody ever
writes "unbuilt" — that removes a whole class of lie. Only structural gaps are authored
(go/internal/parity/gaps.go), and TestParityMatrix proves every one is REAL (a gap some token
actually fulfils fails the gate), every map value is a real vocab TYPE, and the committed
spec/parity.yaml equals the regeneration byte-for-byte (a stale file fails `make check`;
regenerate with `make parity`). Verified: tampering a cell fails the gate; restoring passes.

**What the matrix reveals (honestly).** 50 capability TYPEs x 3 clouds = 150 cells: 122
fulfilled, 3 structural gaps (email.sending on GCP — no first-party transactional email;
email.inbound on GCP and Azure — no managed inbound-mail-to-storage), 25 unbuilt. The unbuilt
cells are an honest roadmap (vpn.gateway on Azure, search.index on GCP, and all-unbuilt rows like
dns.record / cluster.namespace / identity.sso / compute.quota that NO cloud driver fulfils yet)
— never a verdict on the cloud. This is exactly the input the bake-off (D92) needs: a
deterministic answer to "can cloud X fulfil capability Y" that distinguishes a structural dead
end from a missing driver.

The load-bearing follow-on (making ServiceCapabilities the dispatch's own confused-capability
gate — requirePair(service, capability) so Validate("rds", "capability.cache.keyvalue") refuses
— and a `groundhold parity` CLI + candidate-emission gate feeding the bake-off) is deferred as a
scoped D-slice: the matrix now EXISTS and cannot lie; making it GOVERN runtime behavior is the
next step.

## D174 — The parity matrix governs: `groundhold parity` + the confused-capability gate

D173 built the matrix and proved it cannot lie. D174 makes it LOAD-BEARING — the
matrix now drives runtime behavior and feeds the bake-off, closing the loop the earlier
brainstorm identified.

**`groundhold parity [capability.type] [--json]`.** A read-only, deterministic query
over the live drivers' ServiceCapabilities() maps + the authored gaps: for each
cloud, does it FULFIL a capability (with which service tokens), STRUCTURALLY cannot
(a gap + class + reason), or simply lack a driver (unbuilt)? This is the
gap-vs-unbuilt answer the bake-off (D92) needs — a structural dead end and a missing
driver are different verdicts. The bake-off skill now runs a parity precheck before
emitting candidates (a vendor with a gap on a required capability is ineligible up
front with the honest reason; an unbuilt cell is a roadmap note, not an exclusion),
and the stale "azure: no driver family" line is corrected — all three clouds now have
full families.

**The confused-capability gate.** A reviewer's insight #5 — that the parity map should
govern dispatch, not be parallel bookkeeping — was RIGHT, but its specific mechanism
(a requirePair in the driver's dispatch) does not fit: the driver's Validate receives
the LOCAL capability id (an ownership label), not the capability TYPE, so a driver
cannot check type↔service agreement. Tracing the real data flow found the correct
layer: candidate compile, where the contract's TYPE and the candidate's (provider,
service) are both in hand. `parity.CheckBinding` refuses a candidate whose declared
service does not fulfil its declared TYPE (e.g. binding `capability.database.relational`
to aws `s3`), wired into `groundhold plan` after the candidate loads. Deterministic,
network-free, and Go-only (the Python reference has no drivers — so this is a driver
battery like CertifyDriver, tested by `internal/parity` unit tests, NOT a dual
conformance case that would diverge). Verified: a confused binding refuses at plan
with a precise message; the coherent candidate still SEALs; make check 386/386,
differential 0.

This is the honest correction the "measure the real flow, don't follow the sketch"
discipline produces: the deeper idea (the matrix closes the confused-capability hole)
survives, placed where the interface actually supports it.

## D175 — GitOps reconciliation witness (capability.gitops.application) — vendor-agnostic

The app-layer expansion begins where the author-vs-witness doctrine says it must: groundhold
WITNESSES the GitOps controller, never becomes it. The bootstrap paradox (who deploys the
deployer) is resolved honestly — groundhold does not install or drive the controller (the
`helm install` stays app-layer / human / CI); it asserts, four-valued, that the controller
is present and its root application is synced + healthy. If the controller is absent,
observe yields nothing and a hard constraint is unknown/unverifiable — never a fake pass.

**Controller-AGNOSTIC by construction — no vendor privileged.** New capability TYPE
capability.gitops.application (STATELESS — a reconciliation status, not a store). Its enums
are the COMMON DENOMINATOR every GitOps controller exposes: sync.status
{synced, drifted, unknown} (the drift axis — is live == git?) and health.status
{healthy, progressing, degraded, unknown} (the failure axis — are the managed resources up?),
plus source.repoURL and service.managed. Every controller is an EQUAL, pluggable mapping onto
these neutral enums. Two ship as first citizens, deliberately NOT one:
- **ArgoCD** (argoproj.io/v1alpha1 Application) via lens k8s.gitops.argocdStatus (Synced->synced,
  OutOfSync->drifted, Degraded/Missing->degraded, Suspended->unknown).
- **Flux** (kustomize.toolkit.fluxcd.io/v1 Kustomization) via lens k8s.gitops.fluxStatus (the
  Ready/Reconciling conditions -> the SAME neutral enums).
A golden test proves both controllers, with entirely different status shapes, project onto the
identical neutral values — the vendor-agnosticism is asserted, not claimed. A third controller
(Fleet, Jenkins X) is just another mapping + lens, never a code change to the vocabulary or the
engine. This is the k8s analog of the cloud parity matrix (D173), on the GitOps-controller axis.

**Reuses the schema-mapping path (learn-from-API-contract), no hand-coded twin.** Each
controller is a mapping document + one small reviewed normalising lens — the normalisation
(a conditional value mapping) is exactly what the op/lens split reserves the lens for
(invariant #4). Observe-only: neither mapping has a write lens — groundhold never authors the
Application/Kustomization. The mapped-surface drift fingerprint is left blank (a loud
"drift UNCHECKED" diagnostic on a live read) pending vendoring each controller's CRD schema —
honest, not a fabricated pin. Discoverability is enforced (both tokens are serviceDiscoverers
keys, so a live cluster's GitOps roots are crawlable/posture-visible).

make check 389/389 (+3 dual cases: synced+healthy satisfied, drifted violated, enum-violation
load-error), differential 0. Next app-layer slices: the AUTHOR half (the cloud-identity coupling
the controller needs — Pod Identity/IRSA for its service accounts, which the existing
podidentity primitives already express) and a Acme app-layer contract asserting the controller
is coupled + synced.

## D176 — The AUTHOR half of couple+witness: the GitOps controller's Pod Identity coupling

D175 built the WITNESS half (observe the controller). D176 is the AUTHOR half: groundhold
AUTHORS the cloud-identity coupling the GitOps controller needs at cluster birth — the Pod
Identity associations binding the controller's Kubernetes service accounts to IAM roles, so
its pods reach the cloud (repo credentials, image pulls) WITHOUT static keys. This is exactly
"coupling with cloud identity at cluster birth" the author-vs-witness doctrine assigns to
groundhold — and it needs NO new driver: the coupling is the existing neutral
capability.identity.podidentity (D149/D170/D171), so the AUTHOR half is a COMPOSED CONTRACT,
not speculative new machinery.

examples/acme/gitops-coupling.contract.yaml declares one podidentity per controller service
account that needs cloud access (argocd-repo-server, argocd-application-controller). Proven:
verify PROVEN (4/4), plan SEALED with exactly two create actions
(eks:CreatePodIdentityAssociation + iam:PassRole) — the real coupling authoring. Cloud- AND
controller-AGNOSTIC: the SAME contract is fulfilled by an AWS candidate (eks-podidentity) and a
GCP candidate (gke-workloadidentity), each planning two authored couplings with no contract
change; a Flux controller's service accounts (source-controller/kustomize-controller) are the
identical shape. No vendor privileged on either axis.

**A real gap surfaced (measure the flow, don't assume).** Composing the witness
(capability.gitops.application) INTO the authored coupling plan revealed that the compiler emits
a spurious `create` for an observe-only WITNESS capability — groundhold would try to author the
ArgoCD Application it must never author (the k8s mapping is not writeSafe, so the create would
refuse at apply, and the plan lies until then). The compiler does not yet respect author-vs-witness
for verify-only capabilities. The precise fix — a capability whose provider cannot author it is
VERIFIED-NEVER-ACTIONED (no create/update/delete action, its constraints still checked) — is the
next slice: it touches binding, converge and apply (a never-created capability has no providerId),
so it earns its own conformance-case-first treatment rather than a rushed tail-end change. Until
then the coupling contract stays purely authored, and the witness is a separate groundhold
verify/observe concern (D175). make check 389/389, differential 0.

## D177 — The compiler respects author-vs-witness: the `witnessed` block

D176 surfaced the gap and deferred the fix (conformance-case-first, not a rushed tail-end
change): the compiler emitted a spurious `create` for an observe-only WITNESS capability. This
slice closes it. A capability whose provider *cannot author it* is now **VERIFIED-NEVER-ACTIONED**:
its constraints are still checked (it is read, D28), but it produces no create/update/delete
action, and the plan records it explicitly in a new `witnessed` block instead of staying silent.

**Why an explicit list, not silent no-action** (a reviewer's correction). A signed, sealed plan
(D102) must be omission-resistant: "groundhold deliberately did not author this, and here is why"
is a fact the plan asserts, not an absence a reader must infer. So the IR carries
`witnessed: [{capability, provider, service, reason}]`, DISJOINT from `writes`. Both loaders
enforce it (go/internal/plan/plan.go, ref/groundholdlib/plan.py): each entry well-formed, its
capability has a pinned head (verified => read), and it is NOT in writes (a witness mutates
nothing — being in writes would be a lie). The IR shape and its hash are DUAL even though the
emission is Go-only.

**How the compiler decides.** author-vs-witness is a provider property, not a per-mapping guess.
go/internal/provider/authorability.go adds `CanAuthor(providerName, service)` over a witness-predicate
registry; the k8s driver registers its predicate (mappings.go init): a k8s service is a witness iff
its embedded mapping is not `writeSafe()` (no write lens on any mapped attribute). The compiler
(compiler.go) gates per capability: `witness := prov != "" && prov != "fake" && svc != "" &&
!provider.CanAuthor(prov, svc)` — a witness is appended to `witnessed` and skipped for action
emission; writes are filtered to exclude it. Downstream is safe by construction: posture, refresh
and converge all iterate `in.Bindings`, and a witness is verified from the read-set, never bound,
so it is never mistaken for something to reconcile.

**Proven.** conformance/cases/sealed-plan.yaml pins the IR (a plan carrying a witnessed capability
loads and hashes; a witnessed capability that also appears in writes is a load error). A new
`impl: go` case (conformance/cases/update.yaml, gitops-witness-capability-is-not-authored) pins the
COMPILATION: a mixed candidate — an authored aws eks-podidentity coupling next to an observe-only
k8s argocd-application — plans a create for the coupling and NO create for the witness (asserted via
`expect.absentActions`). examples/acme/gitops-coupling now expresses the full couple+witness pattern
in ONE contract: two authored Pod Identity couplings + one witnessed controller, verify PROVEN 6/6,
plan SEALED with two creates and the controller in `witnessed`. spec/sealed-plan.md documents the
block. make check 392/392, differential 0.

## D178 — Strong-Kleene semantics for list & membership comparison (two fixes)

An adversarial review of the verifier core (the highest-stakes code — a correctness bug here
refutes the thesis) plus an adversarial consult on the semantics surfaced a fail-OPEN and a
fail-CLOSED, both in list/membership comparison, both DUAL (Go + Python identical, so the
differential fuzzer never caught them — both impls agreed on the wrong answer).

**The fail-open (thesis-refuting).** `equals`/`not-equals` on two lists recursed element-wise
but SILENTLY returned "not equal" when two elements were cross-kind or cross-currency. A HARD
constraint `backup.windows not-equals ["1h"]` (list of duration) against candidate `[3600]`
(list of number) returned **satisfied** — the incomparable elements were coerced into a definite
verdict. It should be **unverifiable** and block. The scalar form of this trap was already pinned
(`not-equals-across-kinds-is-unverifiable-not-true`); the list form was neither defended nor pinned.

**The fail-open's sibling in membership.** `in`/`subset-of` used "skip non-comparable elements,
refuse only if NONE comparable". So `zonal not-in ["2h", "regional"]` — a comparable non-match
(`zonal != regional`, F) plus an ill-typed element (`zonal` vs `2h` duration, ⊥) — skipped the ⊥
and returned "not found" → `not-in` **satisfied**. Membership is a disjunction; `F ∨ ⊥ = ⊥`, so the
verdict must be unverifiable — the skipped element could have been the match.

**The design (one reviewer's framing, another's algorithm).** Every atomic comparison between incomparable
scalars is ⊥ (no truth value); every composite — list equals, in, subset-of — is the strong-Kleene
three-valued combination of atomic comparisons plus structural facts (length). A definite verdict is
returned **iff it is entailed by structure + well-typed comparisons alone (stable under every
resolution of the ⊥ atoms)**; otherwise unverifiable. This is sound (a definite verdict never rests
on a coerced ill-typed comparison — F dominates ⊥ in a conjunction, T dominates ⊥ in a disjunction),
monotone (refining a ⊥ can never flip a definite verdict), order-independent (Kleene ∧/∨ commute →
determinism for free), and uniform (equals/in/subset from one rule; Kleene negation keeps ⊥ at ⊥, so
hard `not-equals`/`not-in` can never fail open).

**The first fix was too eager (fail-CLOSED regression).** The initial patch guarded the whole common
prefix for comparability *before* deciding equality, so `[number 1] equals [duration 1, duration 2]`
raised unverifiable — but the lists have different LENGTHS, a definite inequality that compares no
element. Kleene returns **violated** there. A false unverifiable needlessly blocks a hard constraint;
that is a real cost, not free safety. `listEqual` now checks length first (a definite F), short-
circuits on any well-typed definite element mismatch (F dominates), and returns unverifiable only when
every position is equal-or-ill-typed with at least one ⊥.

Preserves every prior case (the D14 "no comparable element / empty list → unverifiable" stance falls
out of "no definite match and nothing well-typed"). Five new cases pin the algebra
(list cross-kind → unverifiable both directions; length-mismatch → definite; F-dominates-⊥;
mixed-membership → unverifiable). Both impls, make check 399/399, differential 0.

## D179 — The canonicalizer collided all sub-1e-17 floats (injectivity break)

The hash+fold foundation review found a TOP-severity, DUAL defect (identical in Go and Python, so
the differential fuzzer structurally could not catch it — both impls agreed on the wrong answer).
The number canonicalizer (`numStrFloat` / `_num_str`) renders a fractional as the shortest
fixed-point decimal that round-trips in `p ∈ [1,17]`. For any non-integral magnitude below ~1e-17
NO `p` round-trips, so control fell to a branch commented "unreachable" that emitted
`"0.00000000000000000"` — a LOSSY, non-round-tripping string. It was not unreachable: every value
in (0, ~1e-17) hit it. So `1e-18`, `1e-20`, `2e-20`, `5e-320` all canonicalized to the SAME string.
Two structurally-distinct documents hashed IDENTICALLY (a collision), and the canonical form was a
false statement (it claimed the number was 0). Confirmed live: `hash(contract value 1e-18) ==
hash(contract value 1e-20)` in both impls. This breaks content-addressed identity — the property
every signature, capsule, sealed plan and anchor rests on.

The fix is fail-closed refusal, exactly as the >2^53 upper bound (D66): a value with no lossless
fixed-point form has no canonical form, so it is refused, never coerced to a false one. Encode tiny
values as strings. Three coordinated points keep BOTH impls consistent across every command:

1. **canonical `numStrFloat` / `_num_str`** — the authoritative injectivity guard: the "unreachable"
   branch now returns an error. This covers the raw-document hash path (event bodies etc. that
   bypass scalar parsing).
2. **scalar `safeNum` / `_safe_num`** — a lower bound mirroring the upper: a tiny non-integral scalar
   VALUE is refused at LOAD, so a tiny constraint/attribute value is a structural error in both
   impls (like >2^53), never a verify verdict computed against a bogus canonical form.
3. **`verify.Verify` returns an error** — the free-form implementation block (D26) is not validated
   at load, so a tiny float there only surfaces when verify computes the candidate hash. Go used to
   SWALLOW that error (`, _`) and emit a report with an empty candidateHash — a dishonest identity;
   the reference impl crashed uncaught. Both now refuse cleanly ("candidate error", exit 1). This
   asymmetry was invisible until the canonicalizer stopped colliding tiny floats.

Four new cases/tests pin it (sub-1e-17 hash-refusal, scalar-value load-error, and a Go unit test for
the verify-time refusal the conformance library runner cannot express); the differential fuzzer
already generates 1e-30/1e-20 and now agrees (both refuse). make check 401/401, differential 0.

## D180 — Write-ahead ordering: the durable binding precedes the pending-clearing receipt

The executor audit (a Go-only layer with no differential safety net) found a crash-window orphan.
For a successful mutation the executor wrote the terminal `operation.receipt{succeeded}` — which
CLEARS the pending intent in the fold — BEFORE the `binding.updated`. A crash in that gap left the
resource created, the pending set empty, and no binding: resume finds nothing pending, the compiler
reads no binding and re-plans a `create` → a double-create (or a permanent leak). The write-ahead
guarantee is supposed to hold at the LEDGER level; here it rested only on provider idempotency (the
stable idemKey re-issues, so a D29-honoring provider returns the existing resource) — which breaks if
the candidate changed before recovery, the provider does not key on it, or no recovery apply runs.

The fix reorders both writers (internal/apply and internal/resume): the durable state —
`binding.updated` (or `ownership.claimed` for a claim) — is written FIRST, then the pending-clearing
terminal receipt. A crash between them now leaves the receipt PENDING, and the next resume reconciles
it against the already-written binding (idempotent, `cur == verdict.ProviderID`), never an orphan. The
failure/`unknown` path is unchanged: there is no state to write first, and an `unknown` outcome must
KEEP its pending intent (only a succeeded receipt clears it). Resume's rebind-ORPHAN paths (the
concluded resource can't take the binding because a concurrent run rebound the capability) still write
the terminal receipt before continuing — the operation concluded, so its pending intent must clear,
even though no binding is projected.

This changes the event ORDER a handful of conformance cases pin (`operation.receipt, binding.updated`
where they read `binding.updated, operation.receipt`). Those cases encoded the buggy order; they are
corrected here, not weakened — the write-ahead invariant is the point. A regression test
(apply/preflight_test.go, alongside the D-fix lost-update test) and the existing resume cases pin the
new order. make check green, differential 0.

## D181 — Driver observe honesty: no fabricated measured observation

A four-cloud adversarial audit of the OBSERVE / reverse-mapping path — the boundary where a
provider API response becomes typed Observations that feed the DETERMINISTIC verifier. Here a
fabricated observation is not a wrong value, it is a FALSE VERDICT the runtime then trusts and acts
on (the collector fail-open class, D-collector, at the driver level). Two fabrication shapes surfaced;
GCP was clean (presence-gated reads, safe-direction flags, correct derivation tags throughout).

**Absent optional field → measured zero-value (the false-PASS shape).** A reverse-mapping read a field
the API OMITS for whole resource classes and emitted the zero value as `measured`:
- Azure ACR / Service Bus / Postgres Flex: `network.publicExposure = PublicNetworkAccess == "Enabled"`.
  publicNetworkAccess is a Premium-only control; ARM omits it for Basic/Standard resources, which are
  ALWAYS public — so absent decoded to a measured `false`, and a no-public-exposure hard constraint
  falsely PASSED on an always-public registry/namespace. Fixed with the switch-with-default the
  vault/redis observers already use: Enabled→true, Disabled→false, absent→no observation + diagnostic.
- AWS MSK `encryption.inTransit`: read off the Provisioned block, which a SERVERLESS cluster (returned
  by the same ListClustersV2) does not carry → absent ClientBroker fabricated `false` on a cluster that
  mandates TLS. Emit only when the field is present.
- k8s Flux witness `sync`/`health`: a k8s condition status is THREE-valued (True|False|Unknown), but
  the lens treated it as boolean — Ready=Unknown (a reconcile in flight) fell to a measured
  `drifted`/`degraded`, so a hard gitops constraint verified VIOLATED when the honest verdict is
  unknown. Mirror the ArgoCD twin: Unknown/future → neutral `unknown`.

**Managed key reported as a customer key (the false-BYOK shape).** Several drivers emitted
`encryption.customerManagedKeys=true` whenever a KMS key was present — but the AWS-managed default key
(alias `aws/<service>`) is not customer-managed, so this false-certifies a BYOK / independently-
revocable-key compliance control on adoption. Where the API reports the managed default as a
distinguishable ALIAS (SQS `alias/aws/sqs`, Kinesis `alias/aws/kinesis`), exclude it (a new
isAWSManagedKMSKey helper). Where it reports an opaque key ARN indistinguishable from a customer key
(DynamoDB, MSK), REFUSE to observe CMEK entirely and emit a diagnostic — exactly as RDS already does,
because distinguishing them needs a second KMS DescribeKey (KeyManager) lookup. The k8s reverseGrant
`grant.role="/"` from an empty roleRef is guarded the same way.

The golden tests never caught these because they only round-trip groundhold-CREATED resources (always a
customer key, always the present field), so the omission/managed-key responses were never exercised.
New/updated tests pin the honest behavior (ACR absent case; DynamoDB/MSK CMEK as unobservable +
diagnostic; Flux Ready=Unknown). make check green.

## D182 — The tail anchor witnesses the whole forest, not just the last line's chain

An adversarial audit of the ledger hash chain surfaced a gap between what the tail anchor (D70)
PROMISES and what it CHECKS. The doctrine reads "the chain protects an event once a successor pins its
hash — only the LAST line is unprotected, so the anchor covers it." That is true only for a single
linear chain. The groundhold ledger is a per-capability FOREST: each event's `prev` pins only the heads of
the capabilities that event LISTS (`BuildDoc`), and `verifyPrev` checks only those — there is no global
previous-event link. So an event's "successor" is the next event on the SAME capability, and the last
event of EVERY capability is unprotected, not just the file's last line.

`BuildAnchor` already recorded the per-capability `heads`/`decisionHeads`, but `CheckAnchor` verified
ONLY the single positional `Head` (the hash at line N) — and the struct comment rationalized the heads
as "a consistency assertion; a mismatch means an implementation bug, not tampering." Concretely: honest
file `[A1, B1, A2, B2, A3]` anchored at the tip (Head = hash(A3)). An attacker rewrites the interior
`B2` → `B2'` (a different binding body), keeping `prev[B] = hash(B1)` valid and leaving A1/A2/A3
byte-identical. Replay succeeds (B2' pins B's current head); the line count is still 5; position-5 is
still hash(A3) because A's chain is independent of B — so the armed anchor VERIFIED a forged fold. Every
capability except the one owning the last line had an unprotected tail even with the anchor armed,
directly contradicting the anchor's stated guarantee.

Fix: when the anchor covers the whole current ledger (`a.Events == led.TotalEvents()` — the state
`groundhold anchor` always emits, and the state `EnforceAnchor` sees before the mutation's own appends),
`CheckAnchor` now verifies the recorded per-capability `heads`/`decisionHeads` against the replayed fold
and diverges on any mismatch. No false positives: both sides are the fold over the identical event
sequence. When a tail has grown PAST the anchor (`a.Events < TotalEvents`) the recorded heads are for an
earlier prefix and cannot be compared to the current tip — the positional check stands and the honest
boundary is restated (re-anchor at the tip to witness every capability). A test pins the forest rewrite
(fails before the fix: Head matched → verified). The complete root-cause fix — a global previous-event
link so the positional Head transitively commits to the whole forest — is a foundational change to event
identity (every pinned event hash moves) and is flagged for consultation, not taken unilaterally.

## D183 — Snapshot compaction must carry the claimed (authorship) projection

The same audit found a silent projection loss across the compaction boundary. `ownership.claimed`
(D140 takeover authorship) is the one fold that lives ONLY in the `claimed` map — the claim event
touches no binding body — and it was the one `Ledger` projection with no mirror field in the `Snapshot`
struct. `BuildSnapshot` never serialized it and `SeedLedger` never restored it, so a compaction whose
prefix contained the `ownership.claimed` event produced a seeded ledger with `claimed == nil`.

The consequence is a broken converged-no-op (D52/D137): `AdoptedCapabilities` reads `origin:"adopted"`
from the binding (preserved) and stays true, but `ClaimedCapabilities` now reads false, so the compiler's
`if Adopted[cap] && !Claimed[cap]` re-emits a one-time `claim` action against an already-owned resource —
a real cloud write — on every post-compaction run, and each further compaction that swallows the latest
claim resurrects it. The snapshot-equivalence fuzz missed it because neither the fixed fixture nor
`buildRandomHistory` ever emitted an `ownership.claimed` event, so both the full fold and the seeded fold
stayed `nil` and the whole-struct `reflect.DeepEqual` passed vacuously.

Fix: add `Claimed map[string]bool` to `Snapshot`, populate it in `BuildSnapshot` (canon-empty → nil), and
restore it in `SeedLedger`; add an `ownership.claimed` step (under a lease, D29 fencing) to the fuzz
history so the equivalence property actually exercises the projection. Fails before the fix (`field
claimed drifts`). make check green.

## D184 — Diagnose must refuse an unreadable snapshot, not fold the tail from genesis

`repair`'s `Diagnose` seeds from the snapshot exactly as `ReplayFile` does so a healthy COMPACTED tail
(whose line 1 pins the snapshot heads, not genesis) is not mis-called chain-broken. But where `ReplayFile`
treats a snapshot-load error as a hard refusal (`if err != nil { return nil, err }`), `Diagnose` guarded on
`serr == nil && snap != nil` and, on a malformed/corrupt snapshot sidecar, silently proceeded with `New()`
(genesis heads) — and never ran `VerifySnapshotTrust`. Against genesis, the compacted tail's every line
reports `chain-broken` from line 1, `ValidPrefixLines` collapses to 0, and the remediation tells the
operator to `--quarantine`, which truncates the ENTIRE healthy tail. A corrupt snapshot beside a healthy
ledger thus turned a diagnosis into a destructive recommendation. Fix: `Diagnose` surfaces a
snapshot-load/trust error as its own finding and refuses to judge the tail against genesis — the same
fail-closed posture as the replay path.

## D185 — The anchor manifest completely closes the forest gap (superseding D182's tip-only guard)

D182 taught the anchor to verify per-capability heads, but only when it covers the whole current ledger
(`a.Events == TotalEvents`); a tail grown past the anchor left an independent capability's interior tail
unwitnessed. Deciding how to close that residual COMPLETELY, two directions were weighed with two
independent reviewers, then a read-only scope of the actual code settled it.

The first candidate — a GLOBAL previous-event link (`prevEvent` = hash of the immediately-preceding file
event, making the log one linear chain so the positional Head transitively commits to everything) — is
what both advisors first recommended ("integrity should be structural, not anchor-side bookkeeping"). The
scope then surfaced a fundamental incompatibility neither had fully traced: the ledger's per-capability
FOREST is load-bearing for two core features. Evidence capsules (D103) are per-capability subchains that
verify STANDALONE — `VerifyCapsule` walks only `prev[cap]`, and a global `prevEvent` points at other
capabilities' events the capsule does not carry (opaque, unverifiable). DR restore (D-restore)
reconstructs a ledger by topo-sorting per-capability `prev` edges — it CANNOT recover the original global
interleave, so it cannot reproduce original `prevEvent` values; it already cuts a fresh anchor and says
so. A required linear `prevEvent` therefore fights the architecture: carried in event identity it breaks
capsule/restore verbatim-carry and signatures (and forces a full conformance rehash); excluded from
identity it is no longer an integrity link and needs the anchor to commit to it anyway.

Following that through lands on the simpler, complete fix: the anchor records a MANIFEST — a
domain-separated hash (`groundhold/anchor/v1:manifest`) over the ORDERED list of every live event hash,
seeded by the archived `BaseHead`. `CheckAnchor` recomputes it over the anchored prefix
(`EventHashes[:a.Events-BaseEvents]`) and diverges on any mismatch. Because it commits to every line's
hash in order — not just the last line's sub-chain — it catches a count-preserving rewrite of ANY
interior event regardless of which capability owns the tip, AND regardless of whether the tail has grown
past the anchor (it recomputes over the prefix, so `a.Events < TotalEvents` is fully verifiable). It costs
NOTHING elsewhere: event identity is unchanged, so no conformance hash moves, Python is untouched (it has
no anchor), and capsules/restore are unaffected (they never read the anchor's manifest; restore already
cuts a fresh one). It is doctrine-consistent: the anchor was always the designated external witness for
beyond-chain integrity — this makes it deliver what it promised instead of fighting the forest. The
manifest check is gated on an unchanged compaction position (`a.BaseEvents == led.BaseEvents`); a further
compaction moves the archive boundary and the positional/snapshot checks own that verdict. The D182
tip-only heads check stays as a narrower secondary diagnostic and the fallback for a manifest-less
anchor. A test pins the residual case (interior forest rewrite behind a grown tail): fails before the fix
(`verified`, LedgerEvents 4 > AnchorEvents 3), diverges after. make check 402/402 green.

## D186 — The compiler dispatches ClassifyChange per capability, not by map order

An adversarial audit of the compiler + sealed plan (seven hunt classes traced clean: false-converged,
staleness completeness, immutable misclassification, consent-gate bypass, idempotency-key collision,
witness misclassification, seal integrity, deposed cleanup) surfaced one real defect: a nondeterminism at
the driver-selection boundary. `classifyProvider` picked the change-classification driver by ranging the
candidate's `Extras` MAP and returning the first provider it saw — Go map iteration is randomized — and
that single driver was then used by `classifyBound` for EVERY bound capability regardless of its actual
provider. The compiler's core guarantee is "pure, deterministic, byte-identical plans"; this broke it for
any MIXED-provider candidate, a supported shape (the authorability doctrine explicitly allows "aws
podidentity + k8s witness" in one candidate).

Concretely: a candidate binding an aws `eks-podidentity` capability (drifted) alongside a k8s witness. If
map order handed back the k8s driver, `k8s.ClassifyChange("eks-podidentity", …)` returns `unsupported`,
which `classifyBound` maps to a hard error → the whole compile REFUSES; if it handed back the aws driver,
the same inputs compile a valid plan. Same contract/candidate/ledger, different outcome across runs.
Fail-safe in the realistic case (a spurious refusal, never a bad mutation — a non-matching driver returns
`unsupported`), but a narrow dangerous window exists where two clouds share a service token (aws+gcp both
have `loadbalancer`/`backupplan`): the wrong driver could return a genuine but wrong mutable/immutable
verdict instead of refusing.

Fix: replace the single `Inputs.Provider` with `Inputs.Providers` (a name→driver map) and dispatch
`ClassifyChange` and the claim-gating `Claimer` assertion through `providerFor(prov)` keyed by each
capability's OWN provider name — exactly how the compiler already resolves `PermissionsFor` and
`CanAuthor`. The CLI builds the map with one entry per distinct declared provider (deterministic; a
name-keyed lookup has no iteration-order dependence). A compiler test pins per-capability dispatch: two
drifted capabilities bound to different providers must each carry their own driver's classification note;
before the fix a single shared driver stamped both with one note (fails: both `from-pa`). make check
402/402 green.

## D187 — The capsule verifier normalizes numbers; a JSON-decoded proof with a fencingToken must verify

An adversarial audit of the "evidence that travels" layer — capsule emit/verify (D103), ed25519 detached
signatures + the trust set (D102/D135), and DR restore/merge — found the FORGERY axis fully closed:
`VerifyCapsule` recomputes every event hash from the raw bytes and checks the genesis→tip `prev[cap]`
linkage against the *claimed* head (claimed hashes are never trusted), empty/foreign/reordered subchains
refuse, signatures are fail-CLOSED under `--trust` (unsigned/foreign-key/malformed/verify-false all refuse,
the signed message binds `scheme:ledgerId:eventHash` so a signature cannot be transplanted), and restore
runs every capsule through standalone verification before a content-addressed fork refusal, then
write-then-REPLAY reconciles the re-woven ledger against the anchor's count/heads/ledgerId/genesis — a
laundered fork cannot survive both gates. No fail-open found.

The one confirmed defect is fail-SAFE: the receiver's `capsule --verify` spuriously REFUSED any authentic
capsule whose subchain carries a `fencingToken` (i.e. any lease/mutation event — essentially all real
infrastructure history). The CLI decodes the capsule with `json.Unmarshal`, which makes every number a
float64, then called `VerifyCapsule` directly — but `state.ValidateEvent` asserts `fencingToken.(int)`,
which fails on float64. `ReplayFile` and `restore.loadCapsule` both normalize float64→int first; the
standalone verify path did not, so it depended on a normalization its own callers happened to do. The
conformance capsule cases missed it because they only carry `publish` events, which have no fencingToken.

Fix: `VerifyCapsule` now `normalize`s each event doc before `ValidateEvent`, exactly as `ReplayFile` does —
the standalone verifier must be self-sufficient (the D103 "receiver verifies with no ledger" promise), not
lean on its caller. A test round-trips a capsule carrying a fencingToken through JSON and verifies it, and
confirms a tampered head still refuses (the fix accepts the honest float64 shape without weakening
verification). Fails before the fix (`fencingToken must be a positive integer`). make check 402/402 green.

The second finding was fail-safe by design and left as a documented limitation: capsules verified under an
anchor that embeds a `--trust-from` policy (D135) refuse for any capability whose subchain does not carry
the one global boundary event. That refusal is CORRECT — a capsule lacking the boundary cannot locally
prove which of its events are post-boundary and thus must be signed, so accepting it would be fail-OPEN on
the signing obligation; a naive relaxation of the `Finish` truncation-guard would introduce exactly that
hole. The fix is honesty, not semantics: `VerifyCapsule` now wraps the generic "boundary absent" error to
name the real limitation (verify against a boundary-less anchor, or sign from genesis), and spec/capsule.md
documents it as a deliberate fail-closed limit.

## D188 — Forecast audit: the prediction path is clean; two preview-not-gate caveats documented

An adversarial audit of `forecast` (D40/D41/D45) — the path that predicts a sealed plan's effects WITHOUT
executing — found the four-valued discipline intact and no optimistic lie in the core logic. Traced clean:
`predict`/`compare` never collapse unknown into a confident match (missing→unknown, invalid/future
timestamp→unverifiable, stale→unknown, unparseable→unverifiable, kind/currency mismatch→unverifiable via the
verifier's own `scalars.Operators["equals"]`, not a private algebra); `Basis` is carried verbatim from the
candidate's provenance status, never upgraded; every plan action is enumerated with a closed effect set
(default→`unknown/unsupported-effect-model`) and every candidate attribute counted, so no effect is hidden;
the rollup is pure counts with no aggregate boolean to swallow a single unknown; the decision-heads CAS is
apples-to-apples (both the plan's pinned `reads.heads` and forecast's `heads` are `led.DecisionHeads`), and
`!fresh` flags EVERY action `stale-plan`. The candidate is pinned by hash (a different candidate refuses).

Two findings were by-design preview-vs-gate gaps, not logic errors — handled by documentation, not a rushed
code change:
- `freshPlan` is freshness against the DECLARED heads. With no `--ledger`/`--heads` the head set is empty and
  every cap defaults to `genesis`, so a greenfield plan correctly reads `freshPlan: true` — but a
  genesis-pinned plan whose real world has moved also reads `true`, because forecast cannot tell "no history"
  from "history not supplied" (it reads nothing from the world, D40). This is a declared-input semantics, and
  four conformance cases legitimately encode greenfield-is-fresh; "fixing" it would break them. Documented in
  spec/forecast.md: `freshPlan: true` means fresh against the declared world; supply `--ledger` to assess
  against real history.
- The exit code is always 0 for a well-formed prediction, even one full of `stale-plan`/drift/unknown — an
  agent gating `forecast && apply` on the exit code gets a false all-clear. By design (the enforcing gates —
  decision-heads CAS, staleness re-check, preflight — live in apply/converge, which refuse before mutating);
  the risk is fully honest in the JSON body. Documented: forecast is the preview, apply is the gate; read the
  rollup, do not gate on the exit channel. No code change; make check 402/402 green.

## D189 — Observe/probe audit: the negative-age fail-open, and a probe consent backstop

An adversarial audit of the observe/probe PIPELINE (the read path where reality becomes typed observations
feeding the deterministic verifier — the per-cloud driver reverse-mappings were D181, not re-audited here)
found the pipeline itself honest: observe records only paths the driver actually returned (empty result →
no event, no zero-value fabrication), passes the driver's `derivation` verbatim (never upgrades to
`measured`), is fail-closed on provider and ledger-append errors, and stamps the correct capability/env/prev;
probe keeps `probe.failed` entirely out of the observation stream (a crash refuses the run, a failure is a
separate event type, never a measured value), and the intrusive double-consent decision is fail-closed.
Two real findings, ranked:

**Finding 1 (fixed) — a future-dated observation read as FRESH (fail-open, false PASS).** The staleness gate
is written `evalClock - obsClock > TTL`, which only fires when the observation is OLDER than the eval clock.
When `observedAt` is AFTER the eval `--at`, the age is NEGATIVE, negative is never `> TTL`, so the reading
passes the freshness gate and is used as current reality — a hard constraint reads `satisfied`, a plan seals.
Reachable by time-travel evaluation: any `audit`/`plan` whose `--at` is earlier than a recorded observation
(the console `?at=` scrubber, historical evaluation). `forecast` already guards it (`age < 0 →
unverifiable`), but `audit.go` and the compiler's `classifyBound` had the same formula WITHOUT the guard —
an asymmetry across three consumers of one staleness rule. Fixed both: a negative age is `unverifiable` in
audit (blocks) and refuses at compile (cannot seal against a reading that did not exist at the evaluated
instant). Tests pin the false-PASS on both paths (audit returns `satisfied` before the fix; the compiler
seals).

**Finding 2 (fixed) — no framework backstop for intrusive-probe consent.** The double consent (operator flag
AND contract `allow_intrusive_probes`, per-cap, fail-closed) was computed correctly but only PASSED to the
driver; when the outcome came back the pipeline copied `m.Intrusive` verbatim with no check. A buggy or
hostile Prober that returned an intrusive measurement without consent would launder it into the observation
stream as measured evidence — the invariant "a typo must not authorize a restore test" rested entirely on
each driver self-policing. Added a defense-in-depth backstop: an intrusive measurement returned without
consent refuses the run. Test with a rogue prober (fails before the fix: the measurement is recorded).

**Finding 3 (flagged, not fixed) — `derivation` is cosmetic at the audit gate.** The audit verdict is
computed from `rec.Value` + operator; `rec.Derivation` is reported but never gates `satisfied`/`violated`,
so a `config-intent` observation (the driver read the DECLARED config, not measured reality) satisfies a
hard constraint identically to a `measured` proof. The pipeline tags derivation faithfully and never
upgrades — but the careful tag buys nothing at the gate. Whether weak-provenance evidence (config-intent)
should downgrade to `unknown`/`unverifiable` on a HARD constraint is a verifier-semantics decision that the
author-vs-witness doctrine (D177) suggests it should; it sits just past the pipeline boundary and touches
verify + conformance, so it is flagged for a considered change rather than patched here. make check 402/402.

## D190 — Audit honors verify.method: an observation's SOURCE must meet the required evidence bar

D189 Finding 3 (flagged) asked whether weak-provenance evidence should satisfy a HARD constraint. Grounding
the verify path answered it precisely: a constraint declares `verify.method ∈ {static | provider-api |
probe}` — the AUTHOR's required evidence bar. `verify.Verify` returns `unknown` for a non-static constraint
(not evaluable from the candidate alone, verify.go:173), so `audit` against observed reality is the ONLY
runtime discharger of that bar. But `audit` computed the verdict from the value + operator and IGNORED
`cn.VerifyMethod` entirely — so a hard `verify.method: probe` constraint (an OUTCOME: a restore test, a
reachability attempt) was satisfied identically by a `provider-api` config read as by a real probe. The
author's "prove this by a live probe" was HOLLOW at the gate — a false PASS: the config claims RPO=5m, no
restore was ever tested, hard constraint reads satisfied. `verify.method`'s only net effect was blocking
`plan`; at the runtime gate it was dead weight.

Consulted two independent reviewers (both agreed to enforce; one, reading the repo, corrected the axis): gate on
`source`, NOT `derivation`. A driver may label an IAM-policy-derived config read `"measured"`, so derivation
is driver self-report; `source` (set by observe→`provider-api` / probe→`probe`, never per-observation
driver-controlled) is machine-honest. The rule (monotone — stronger evidence satisfies a weaker
requirement): `method probe` ⇒ `source == probe`; `method provider-api` ⇒ `source ∈ {probe,
provider-api}`; `method static` ⇒ any (compile-time verify stays authoritative). An insufficient source is
`unknown` ("evidence weaker than required verify.method — probe first"), NOT `unverifiable` (which stays for
type/currency incomparability) — it is remediable by gathering the evidence, and blocks a hard constraint
either way. config-intent CAN still satisfy a hard constraint — iff the method is provider-api/static; the
author who wants measured-only writes `method: probe`. This is not new provenance policy (D5 keeps that with
policy); it honors a bar the contract already declared. Blast radius: ZERO flipped cases — the corpus has
exactly two non-static `verify:` declarations, both `probe`, both still correct. Audit is Go-only (the
reference impl has no audit), so no Python mirror. A test pins the false PASS (a probe-method constraint
reads `satisfied` on provider-api evidence before the fix) and a new conformance case
(probe-method-refuses-provider-api-evidence) contrasts the static-method observe-resolves flow.

**Deferred (follow-up): probe-evidence RETENTION.** The observation projection is single-slot per
(cap,path) and `obsNewer` (ledger.go:595) is newest-time-wins, so a later `observe` (provider-api)
overwrites an earlier `probe` record. With D190 a probe-method constraint then goes `unknown` until
re-probed — fail-safe (it blocks, never false-passes), but it loses hard-won probe evidence to a routine
observe. The naive fix (make `obsNewer` refuse to let a weaker source overwrite a stronger one) is WRONG: it
reintroduces a false PASS, because a stale probe value would then shadow a fresh observe that shows real
drift. The correct fix is per-SOURCE evidence retention (keep the latest observation per source, let audit
select the strongest fresh sufficient one) — a projection addition that must survive compaction (snapshot
serialization + fuzz, the D183 lesson), so it is its own slice, not crammed here. make check 403/403.

## D191 — Per-source observation retention: a probe measurement survives a later observe

D190 gated audit on evidence strength but noted a trap: the observation projection was single-slot per
(capability, path) and `obsNewer` is newest-time-wins, so a routine `observe` (source provider-api) erased
an earlier `probe` measurement of the same path. A probe-method constraint then went `unknown` until
re-probed — fail-safe, but it threw away hard-won (often intrusive, consented) evidence. The naive fix —
teach `obsNewer` to refuse a weaker source overwriting a stronger one — is WRONG: a stale probe value would
then shadow a fresh observe that shows real drift, reintroducing a false PASS. Evidence of different
strengths is not ordered by recency alone; both must be RETAINED and selected per constraint.

Fix: a new projection `ObservationsBySource` (capability → path → source → latest record) retains the newest
record PER SOURCE, so a probe and a provider-api reading of one path coexist. The single-slot `Observations`
stays newest-overall for the drift consumers (forecast, compiler) that do not method-gate — no behavior
change there. `audit` now selects, per constraint, the most-recent NON-FUTURE record whose source meets the
declared `verify.method` bar (`latestSufficient`), which subsumes the D189 future guard and the D190
sufficiency gate in one place: no sufficient source → `unknown` (probe first); a sufficient reading that is
only future-dated → `unverifiable`; otherwise the freshest sufficient record, then staleness + compare. So a
probe-method constraint reads `satisfied` off the retained probe even when a newer provider-api observe of
the same path (with a violating config value) exists.

Per the D183 lesson, the new projection is a first-class part of the fold: serialized in `Snapshot`,
restored in `SeedLedger`, number-normalized in `normalizeSnapshot`, and exercised by the snapshot-equivalence
fuzz (now emitting BOTH provider-api and probe readings of a path, so per-source retention crosses the
compaction boundary under `reflect.DeepEqual`). Audit is Go-only, so no Python mirror. Unit tests pin the
retention (a probe survives a newer violating observe → still satisfied) and the audit-unit seeds move to
the per-source projection. make check 403/403, all Go tests pass, differential clean.

## D192 — Brownfield onboarding: unadopt must not lie either (claim clearing + origin/pending gates)

An adversarial audit of discover/adopt/unadopt (D52) found the adopt CORE path solidly honest — it observes
the resource NOW and compares every declared non-assumed scalar against reality (`AdoptionMismatch` refuses
a non-observable, mismatched or incomparable value), guards double-adoption and competing reconcilers, and
is fail-closed on every ledger append; discover relays only what the provider enumerated (no fabrication).
The lies lived in the `unadopt` cluster, where the ledger could be made to assert a reality that is not
true. Four fixes:

- **F1 (top) — a stale `claimed` bit re-opens the D140 takeover hole on re-adopt.** The `claimed` projection
  (groundhold stamped authorship on the bound resource) was set on `ownership.claimed` and NEVER cleared.
  Sequence: adopt bucket-A → converge stamps `claimed[db]` → unadopt (releases the binding, `claimed[db]`
  stays true) → adopt bucket-B → the compiler reads `Adopted && !Claimed == true && !true == false`, emits
  NO claim action, and bucket-B is bound but never stamped. The converge reports a bare converged no-op while
  the new resource carries no ownership tag — the exact hole D140 closed, defeated via unadopt/re-adopt. Fix:
  the fold clears `claimed[c]` when a `binding.updated` releases the binding (empty resources) — the claim
  was on the resource just released.
- **F2 (top) — `unadopt` had no origin guard, so it orphaned CREATED resources.** It checked only that the
  capability was bound, not that it was `origin: adopted`. Apply-created bindings carry no origin, so
  `unadopt` would release a resource groundhold PROVISIONED — the ledger then asserts the capability unbound
  while the live, groundhold-owned resource still exists (a later discover sees a shadow). Fix: refuse unless
  `AdoptedCapabilities()[cap]` — a created resource is retired/deleted, never abandoned.
- **F4 — `unadopt` was missing from the N1 time-sensitive set.** It writes timestamped ledger events but was
  not gated, so a missing `--at` stamped release events at the epoch. Added to `timeSensitiveVerbs` (pinned
  by the membership test); it now refuses a missing `--at` like adopt.
- **F5 — `unadopt` skipped adopt's D29 in-flight guard.** It released a binding with an operation still
  pending, orphaning the receipt. Fix: mirror adopt's `PendingCount > 0` → reconcile-first refusal.

Tests pin each (fails before the fix): the fold clears the claim on release, unadopt refuses a created
binding, refuses with pending ops, and refuses a missing `--at`. make check 403/403.

Two findings were left as flags, not rushed:
- **F3 (medium, design) — an assumed-basis hard constraint passes adoption unconfirmed.** verify counts a
  hard constraint satisfied on an `assumed`/`inferred` value as non-blocking (Executable), and adopt's
  reality gate deliberately SKIPS assumed paths (they are the D59 probe's job to redeem). So a hard fact
  declared `assumed` adopts with status `adopted` though reality never confirmed it. This is the "provenance
  is reported, policy gates" doctrine (D5) again — the binding honestly carries the assumed basis — but the
  gate advertised as "adoption must not lie" has this blind spot. Whether adoption should require a probe for
  an assumed hard constraint is a verifier-semantics decision (sibling to D190); flagged for a considered
  change, not patched here.
- **F6 (low) — the discovery hash omits diagnostics.** `tree()` hashes resources but not the `Diagnostics`,
  so a partial sweep (some pages failed, `err == nil`) can hash-collide with a complete one, and an adoption
  citing `adoptedFromDiscoveryHash` cannot tell it derived from an incomplete enumeration. The diagnostics
  ARE reported (honesty intact), just not committed to the hash; folding them in flips a pinned hash for
  marginal value, so deferred.

## D193 — Converge porcelain: fail-closed the destructive-plan detection

An adversarial audit of `converge` (D51) — the one-verb full loop (verify → plan → forecast → apply) most
operators run — found the porcelain SOUND on both worst-class axes: no false-converged and no
unconsented-destroy path. Exit-code routing is fail-closed (`exitStatus` maps every child code, and its
default — including a signal-kill or unknown code — is `failed/4`, never `0`; it is never called on a
zero code); `verify` non-0/non-2 refuses; `apply`'s exit-2 codes are all pre-mutation so mapping them to
"refused" is honest while a mid-apply failure is `failed/4`. "Converged" is claimed only two ways, both
honest: `plan` returning `nothing-to-change`, or the POST-APPLY re-observe + re-plan returning
`nothing-to-change` (D136) — an inconclusive/unverified check downgrades the banner from CONVERGED to
APPLIED, so exit 0 means "apply succeeded", never a false "world matches". The data-loss consent gate keys
on a STRUCTURED signal (`Risk.DataLoss=="certain" || Risk.IdentityReplacement`), not a stdout scrape, and
is fail-closed: `--yes` does not cover destruction, and every non-interactive/`--json` path refuses
`consent-required`; the confirm prompt is exact-match and refuses on nil-input.

One latent fail-open was hardened: `describePlan` computed destructiveness from the plan JSON but
`_`-ignored the unmarshal error, so an unparseable plan body yielded empty Actions → `destructive=false`
→ the consent gate was SKIPPED. It is unreachable today (a `plan` that exits 0 always emits valid JSON),
but a consent gate must not silently depend on that contract holding forever — a `converge --yes` on an
unparseable plan would have applied it without `--allow-data-loss`. Fixed: an unmarshal error now returns
`destructive=true` (fail-closed), forcing explicit consent rather than skipping the gate on an empty parse.
A test pins it (an unparseable plan is destructive; a clean plan is not; a dataLoss/identity plan is).
Two by-design gaps were stated, not changed: downtime (as opposed to data loss) is surfaced but not
consent-gated, and per-change caveat strings are printed at the action line but not re-surfaced. make check
403/403.

## D194 — Presentation honesty: converge must not mask a VIOLATED world as REFUSED

An adversarial audit of the render layer (D89/D90) — the banner/glyph that tells a human what happened —
found the core `render.Pick` precedence sound (corruption > death > staleness > invalid > VIOLATED >
BLOCKED > REFUSED > green; green is doubly-gated on exit 0 AND an empty verdict rollup, so a populated
rollup renders VIOLATED/BLOCKED even on a stray exit 0). Glyphs/colours keep the four verdicts distinct
(unverifiable never collapses into unknown or satisfied), and the banner is a pure string function that
never pollutes the machine stdout. But three honesty gaps surfaced, all fixed:

- **F1 (live) — converge masked VIOLATED/BLOCKED as a blue REFUSED.** `converge`'s single exit point called
  `render.Pick("converge", exit, code, render.Rollup{})` with a HARDCODED empty rollup. So a converge whose
  initial verify is not-executable BECAUSE a hard constraint is violated (or unknown/unverifiable) fell
  through to the exit-2 arm and rendered `REFUSED not-executable` (blue, benign) — collapsing a proven-false
  world (VIOLATED, red) or a hard evidence-gap (BLOCKED, yellow) into a routine policy refusal, exactly the
  block-vs-refusal separation the doctrine forbids collapsing. Fix: converge parses the child verify's
  `verdicts` into the rollup (mirroring the standalone verb's `verdictRollup`) and threads it to the banner.
- **F2 (latent mirror) — the Go and Python green vocabularies diverged.** `render.py`'s `pick` returned
  `PROVEN` for every non-converge success; Go's `greenWord` maps apply→APPLIED, plan→SEALED, else→OK. Dead
  in Python's own CLI (it only greens verify→PROVEN, which agrees), but `render.pick` is a shared library
  contract and the two disagreed for any `(verb, 0)` — a console/differential caller rendering apply's
  executional success via the Python mirror would get the epistemic word PROVEN. Fixed: `render.py` gains a
  `_green_word` mirroring Go exactly.
- **F3 (latent fail-open) — `Pick` greened any unenumerated nonzero exit.** The final arm returned
  `greenWord` for any exit outside {1..5} once the rollup was empty — a signal or future code (6, 255) would
  render PROVEN/APPLIED. Not live (real exits normalize to 0..5), but the posture was inverted; both impls
  now fail-closed to a non-green `FAILED` when exit != 0.

Tests pin each (fails before the fix: converge renders REFUSED for a violated world; exit 6 renders
APPLIED). make check 403/403.

## D195 — Arm the assumed-basis gate: policy CAN gate satisfied-but-assumed on hard constraints

The verifier-semantics round asked the question D189/D192 kept flagging: when may WEAK PROVENANCE satisfy a
HARD constraint? Grounding answered it cleanly, and it is NOT a verifier bug. D5 is foundational and
deliberate: a value carries a provenance basis (declared|inferred|assumed|unknown), and the verifier
PROPAGATES that basis into verdicts but does NOT gate on it — DESIGN.md D5 verbatim: "Verdicts propagate the
basis they rest on, so POLICY CAN GATE on satisfied-but-on-an-assumed-value." So a hard constraint satisfied
by an `assumed` value verifies satisfied + Executable, basis reported. adopt's skip-assumed (D192) is the
same doctrine. This is the core adaptation to probabilistic authorship, and the verifier default MUST stay
permissive — changing it would break provenance-survives and legitimate declare-then-probe (D59) flows.

The defect was the HOLLOW KNOB: the policy gate D5 defers to is built end to end but nothing arms it. The
sealed-plan precondition registry `{report-executable, no-assumed-basis, within-autonomy}` includes
`no-assumed-basis`, the executor enforces it, the plan loader validates it, the spec documents it — but the
compiler only ever emitted `report-executable`. No contract field or flag caused the gate to fire, so "policy
can gate" was a promise with no mechanism (the same pattern D190 fixed for verify.method). Consulted two
independent reviewers; one, reading the repo, refined the design.

Fix (opt-in, D5 default preserved): a contract sets `autonomy.no_assumed_hard_basis: true`; the compiler then
emits a new `no-assumed-hard-basis` precondition into the sealed plan; the executor evaluates it against the
FRESH report, refusing if any HARD constraint's satisfied/violated verdict rests on an `assumed` basis.
Scope decisions (both reviewers, one repo-grounded):
- **Hard-only, not the all-severity `no-assumed-basis`.** A hard constraint is a deployment gate; a soft one
  is advisory. Blocking deploy because a SOFT constraint rested on a guess is too broad. A NEW precondition
  keeps the executor's scope explicit (the existing `no-assumed-basis` stays available as a stricter
  whole-plan mode). The evaluator loops `report.Verdicts` for `severity==hard && basis==assumed` — no new
  Summary field, so verify (Go AND Python) is untouched and no pinned report moves.
- **Assumed-only, not inferred.** `assumed` is a guess; `inferred` is derived from declared facts and stays
  reportable provenance. Named `no-assumed-hard-basis` (not "no-unproven") to state the assumed-only scope
  honestly.
- The gate's ONLY reachable bite is `satisfied-hard-on-assumed`: hard violated/unknown/unverifiable already
  block via `report-executable`. So this makes exactly the D5 sentence reachable, nothing more.
- Orthogonal to D190/D59: `verify.method: probe|provider-api` gates OBSERVED-evidence strength; this gates
  the CANDIDATE's declared-value confidence at compile time. A static hard constraint can still rest on an
  assumed declaration, so both matter.
- adopt is UNCHANGED: making it "confirm" assumed values would convert an assumption into an observation
  (breaking provenance-survives); the armed gate composes through the normal verify→apply path instead.
- A malformed (non-bool) `no_assumed_hard_basis` is a LOAD ERROR in both loaders — a disarmed gate the
  operator believes is armed is the fail-open the knob exists to prevent.

Python blast radius is a plan.py one-liner (the dual plan-loader registry) plus the contract bool check;
verify.py untouched. Tests pin the compiler emission, the executor refusal on satisfied-hard-assumed (and
apply of the same value when UNARMED — D5 default), and the malformed-knob load error (dual). make check
404/404, differential clean.

## D196. The vocabulary ships inside the binary (ready after download)

The binary knew only six capability-type NAMES intrinsically (a hardcoded map
for basic contract validation); the full attribute vocabulary — 34 documents,
every kind/enum/per-cloud mapping — lived in `spec/vocab/` and loaded ONLY via
`--vocab`. So a downloaded `groundhold`, with no repo checkout beside it, verified
every contract with an empty vocabulary: `pathInVocabulary` null everywhere, no
D23 kind/enum checks. The tool was not, in fact, ready to use after download —
the thing that makes verdicts sharp was an external file the user had to know to
fetch. A first user found this immediately.

Fix: `go:embed` the whole vocabulary into the binary and make it the DEFAULT.
`--vocab <dir>` now EXTENDS the built-in set (custom documents override per
capability) rather than being the only source; `--no-vocab` forces the empty
vocabulary for the D23 "no vocabulary" behavior. The embedded copy under
`go/internal/vocab/embedded/` mirrors the canonical `spec/vocab/`; an anti-drift
test (`internal/vocab`) fails `make check` byte-for-byte if they diverge, and
`make embed-vocab` re-syncs. go:embed cannot reach `../spec/vocab` (outside the
module), so the mirror is deliberate, not incidental.

Conformance is unaffected because it drives the vocabulary EXPLICITLY: the
harness (run.py, differential.py) sets `GROUNDHOLD_NO_EMBEDDED_VOCAB`, dropping the
embedded base so cases start from empty and a case that wants vocab passes
`--vocab` (isolated). This keeps both implementations measured against the exact
vocab-source semantics their cases assume — the built-in default is a
distribution concern, covered by Go unit tests, not a verifier semantic. The
Python reference is unchanged: it runs in-repo and takes `--vocab spec/vocab`,
never being "downloaded." Only the Go runtime, the thing users actually fetch,
carries its type system with it. The MCP server (`groundhold mcp`) likewise no
longer defaults `--vocab` to `spec/vocab`; it passes one only when supplied.

Checked that nothing else the binary needs is external: error-code remediation
is a compiled-in map (`internal/perr`, not `spec/errors.md`), schema validation
is Go code (no runtime `.schema.json` reads), and presentation lives in
`internal/render`. The vocabulary was the only runtime file dependency.

## D197. Onboarding DX: the binary teaches its own candidate schema and MCP wiring

D196 embedded the vocabulary so a downloaded binary knows its type system. But a
real first user (an agent authoring for a client) then burned ~8 iterations
reverse-engineering the CANDIDATE document shape — guessing `attrs` vs
`attributes`, list vs map, `contract` vs `contractHash` — and twice resorted to
grepping strings out of the binary. The vocabulary was ready; the schema was
still folklore. Two smaller discoverability gaps rode along: `apply`/`observe`/
`converge` usage listed only `fake|gcp` though `aws`/`k8s` are wired (so the
same user concluded AWS apply did not exist), and nothing told an agent how to
wire the MCP server into its own config.

Fixes, all discoverability, none touching the verifier:

- `groundhold example <contract|candidate>` prints a valid, annotated starter
  document. `groundhold example candidate <contract.yaml>` SCAFFOLDS a candidate
  from a contract: one entry per capability, keyed as the loader expects (the
  map that was reverse-engineered), each pre-filled with that capability type's
  vocabulary attribute paths, kinds, one-line docs and kind-valid sample values
  (enum members win over the kind default so the scaffold loads). The answer to
  "what shape is a candidate?" is now `groundhold example`, not string-grepping.

- Usage now names the providers each verb actually supports (`apply`:
  fake|gcp|aws|k8s; `observe`/`converge`: fake|gcp|aws) instead of a stale
  `fake|gcp` that hid working drivers.

- `groundhold mcp --print-config` emits the `.mcp.json` (absolute binary path) plus
  the `claude mcp add` one-liner and the GROUNDHOLD_MCP_ALLOW_APPLY note — the one
  wiring step a bare binary cannot perform on a foreign agent's config, made
  copy-paste. No server is started under the flag.

Go-only, like the rest of the runtime CLI surface (`mcp`, drivers): these are
distribution/authoring conveniences, not verifier semantics, so the conformance
suite and the Python reference are untouched. The measure of success is the next
first user reaching a verified candidate without reading the binary's bytes.

## D198. First contact teaches the discovery ladder; explain climbs it

D197 gave agents `example` so they stop reverse-engineering the candidate shape.
But a client agent still had to LEARN the moves out of band — it knew `explain`
worked on attribute paths, so it hunted enum values and attribute lists the long
way (scaffold a throwaway contract, or grep). The binary had the map (`parity`)
and the detail (`explain <path>`) but no rung between them and no first-contact
signpost pointing at either. An agent's very first `groundhold` call must teach it
HOW to discover what it can express, not just list verbs.

Three changes, all discoverability, verifier untouched:

- `groundhold` (no args) now carries a "Discovering what you can express" block: the
  ladder parity -> explain <type> -> explain <path> -> example candidate. The
  first call orients the agent toward self-service instead of guessing.
- `groundhold explain <capability.type>` lists that type's attributes (kind, inline
  enum, one-line doc) — the missing middle rung. An agent that learns a type
  from `parity` can now enumerate everything it may constrain, no contract
  needed.
- `groundhold explain <attribute-path>` prints allowed values (`enum: [...]`), which
  were previously invisible — the exact thing agents hunted for before authoring.
  The not-found message also points back at `parity`.

Go-only CLI surface, like `example`/`mcp`: an authoring/discovery convenience,
not a verifier semantic, so conformance and the Python reference are untouched.
The bet: the next first user never needs anything outside the binary — the tool
explains its own type system from the first keystroke.

## D199. compose + diff: environment DRY without inheritance in the language

A client building dev then staging/prod hit the multi-environment duplication
Terragrunt fights: most invariants are shared, a few differ (prod adds CMEK,
Multi-AZ, cross-region backup). They solved it well in shape — a base contract
(dev/common) plus a prod overlay, base as source of truth — but implemented it
as a hand-rolled `gen.py` that string-concatenates YAML text. That works once
and is fragile forever: a text merge cannot catch a duplicate id, a constraint
referencing a capability the base lacks, or a formatting drift, and every client
reinvents it. The pattern is right; the realization is bespoke glue.

groundhold already dissolves HALF the problem structurally — the contract holds the
invariants (what must be true), the candidate holds the per-environment HOW
(sizes, AZ count, tiers), so "same invariants, different sizing" is one contract
and N candidates, zero duplication. The open half is environment-DIFFERENTIATED
invariants, and the temptation is to answer it with contract inheritance /
includes / interpolation — exactly the expression language invariant #4 forbids,
because it is what keeps verification deterministic and contract identity a hash
of a flat, fully-legible document.

`groundhold compose <base> [overlay ...]` composes instead of inherits: a
deterministic STRUCTURAL merge (constraints and capabilities union by id, later
overlays win, meta shallow-overridden, id-keyed lists sorted so output is
byte-stable) producing ONE flat contract. The sealed result is an ordinary
contract — verifier, hashing, legibility untouched; the merge is an authoring
transform, and #4 holds because the output is just "more constraints", never a
template. Crucially it VALIDATES the result (contract.LoadContractDoc, extracted
from LoadContract for this) and refuses to emit an invalid contract — the
structural safety the string-concat generator cannot have.

`groundhold diff <a> <b>` reports the constraint/capability delta and whether a's
invariants are a subset of b's. That makes the promotion ladder a PROOF:
dev ⊆ staging ⊆ prod is a deterministic subset check, not a hand audit of an HCL
inheritance graph — a guarantee Terragrunt cannot give. A candidate that
satisfies prod's contract necessarily satisfies staging's when staging ⊆ prod.

Go-only authoring surface, like example/parity/mcp: the output flows through the
existing dual-implementation verify/hash pipeline, so composition itself is not a
verifier semantic and needs no Python port. (Considered and deferred: pinning the
merge rules with a dual conformance case. If a second author of merge semantics
ever appears, revisit — for now the Go unit tests in internal/compose hold it.)

## D200. Canon is total over native Go types — and why the corpus never caught it

The first user's `discover --provider aws` died on `cannot canonicalize value of
type []string`: an AWS driver returned a native Go `[]string` (certificate SANs,
security-group rules, Bedrock destinationRegions) and the Go canonicalizer's type
switch handled only `[]any`/`map[string]any` — the shapes YAML decoding yields —
plus the scalar kinds. The Python reference never had this bug: it treats every
`list` uniformly. So it was Go-only, in the DUAL verification core.

Why it survived to a user — the systemic blind spot, which matters more than the
bug: the conformance suite AND the differential harness feed inputs as YAML, and
YAML decoding in Go produces ONLY `[]any`/`map[string]any`/scalars. Native Go
types — typed slices, typed maps — arise EXCLUSIVELY from driver code unmarshaling
cloud responses into structs. No test ever pushed a driver's native-typed
observation through canon/hash. The source-of-truth corpus is structurally
incapable of exercising anything not expressible in YAML. That is a whole class:
"a component hands the core a Go type the core doesn't handle, uncaught because
every test input is YAML-shaped."

Fix — close the CLASS, not the instance. Canon gains a reflection fallback: any
Slice/Array normalizes to `[]any`, any string-keyed Map to `map[string]any`, and
concrete scalar kinds fold to the existing string/bool/int64/float64 paths, then
it recurses. The canonical form (and hash) of a native value is now byte-identical
to its generic twin and to the Python reference. Pure and deterministic (#6): a
shape conversion the YAML path already implied, no heuristics. A driver returning
`[]int` or `map[string]string` tomorrow just works.

Prevention — because we are our own first user and the surface is large:
1. Totality by construction (this change) beats enumerating types — the failure
   mode is gone, not patched.
2. `FuzzCanonTotalOverNativeTypes` builds values in native Go types across the
   driver-plausible domain and asserts Canon never errors, is deterministic, and
   native ≡ generic. 1.2M execs, zero failures. The blind spot now has a test
   tier that YAML cases cannot provide.
3. Deferred (noted, worth doing): a cross-driver SEAM test — every driver's
   observation set pushed through observe→canon→hash — so any future driver
   emitting an un-canonicalizable value fails in CI, not on a user's cloud. And a
   broader gated live-`discover` smoke against a real account with list-valued
   resources (certs with SANs), the exact shape that surfaced this.

The lesson generalizes past canon: wherever a Go-native value crosses into a core
that a YAML-fed corpus tests, add a native-typed test tier or make the core total.

## D201. Seam guardrail: driver observations must canonicalize (D200 #3 landed)

D200 closed the []string canonicalization CLASS by construction and fuzzed the
core, and named a deferred guardrail: prove every driver's observations survive
canon in CI, not on a user's cloud. This lands it. `canonicalizeObservations`
(internal/aws test helper, reusable per driver) canons every value a driver's
observe emits; `TestBedrock_ObservationsCanonicalize` drives it through the real
seam — observeBedrock returns inference.destinationRegions as a native []string,
the exact shape a YAML case cannot construct and the one that regressed. It also
guards the guard: the test fails if the driver stops emitting the []string, so it
can never pass vacuously. Extending the helper to every list-emitting driver's
observe test is the remaining mechanical follow-up; the pattern and the first,
load-bearing case are in.

## D202. Cost projection: an estimate at the end of the dry run, never a quote, never FX

A user asked for a contract's cost shown at the end of plan/dry-run, before
apply, per week/month/year, in a region-appropriate currency. Most of it already
existed: cost.monthly is a first-class money attribute and the compiler already
records each action's cost as risk.costDelta{amount, currency}. What was missing
was aggregation, periods, and presentation.

Design, constrained by the invariants:
- Reporting currency defaults to EUR, overridable with --currency <ISO> or
  GROUNDHOLD_CURRENCY (flag wins over env, the standard context pattern). This
  selects the HEADLINE currency; it is NOT an FX target. Costs declared in
  another currency are summed and shown on their own line, "NOT converted" —
  because coercing across currencies is exactly what invariant #2 forbids, and a
  live FX rate would break determinism (#6). A single-region deployment is
  single-currency in practice, so the headline is usually clean; mixed-currency
  contracts stay honest instead of silently wrong.
- Periods derive from the monthly base deterministically: yearly = monthly×12,
  weekly = yearly/52 (a month is not four weeks, so these are labelled
  projections, not separate billing).
- The estimate is DISPLAY, rendered to stderr at the end of plan (stdout stays
  the pure sealed plan) and surfaced by converge before apply. It is deliberately
  NOT a field of the plan document: HashPlan hashes the whole doc, so a reporting
  currency in the plan would make the same plan hash two ways. Verified: the plan
  hash is byte-identical under --currency EUR and --currency USD.
- Honesty, not a bill: the header states the weakest provenance among contributing
  costs (assumed beats declared for reporting, so a figure built on assumptions
  never reads as fact), and coverage — "M of N capabilities with a declared
  cost.monthly" — so a partial estimate cannot masquerade as complete.

Go-only presentation (internal/costproj, unit-tested; plan+converge render it):
it consumes the dual-pinned plan, adds no verifier semantic. FX-to-one-currency
via an explicit DECLARED rate table remains a possible future Dxx — deliberately
not live rates, never silent.

`groundhold cost <plan> <candidate> [--currency] [--json]` emits the SAME projection
machine-readably, so the console ingests the authoritative number verbatim rather
than recomputing it (grounding: a dashboard figure equals the CLI figure). The
human form is identical to the plan/converge estimate; --json is the console's
ingest shape (costproj.Report).

## D203. `groundhold suggest`: a deterministic, cited best-practice advisor

Agents kept hand-adding the same hardenings (private networking, TLS, CMEK,
backups, versioning, flow logs, key rotation, log-file integrity). `suggest`
systematizes that: for a contract it points out recommended-but-absent hardening
constraints and emits ready-to-paste snippets. Plan + rationale in
`docs/proposals/suggest-advisor.md` (ACCEPTED 2026-07-20).

Decisions:
- **Marker lives IN the vocab.** A `recommended:` block on an attribute
  (`{op, value, scope, rationale, ruleId, ruleVersion, controls[, when]}`), one
  glossary, no drift. It is INERT to the verifier — the vocab loader keeps it as
  an ordinary extra key and the verification core NEVER consults it (invariant
  #6). Only `suggest` reads it. Confirmed: verify/conformance unchanged.
- **Advisor is OUTSIDE the verification core.** `go/internal/suggest` is a pure,
  table-driven lookup — no network, no LLM, deterministic. The ruleset may be
  LLM-drafted from published frameworks, but it is human-reviewed and PINNED;
  runtime only reads it (same proposal/verification split as the rest of groundhold).
- **No new grammar (invariant #4).** Every suggestion is the existing constraint
  shape with an operator already in the closed set (equals/lte/in). Snippets are
  generated deterministically from `{subject, path, op, value}` and pinned by
  conformance + unit golden tests.
- **Advisory, never gates.** The exit code is independent of how many suggestions
  were found (0 whether 6 or 0) — pinned by a conformance case pair. Already-
  constrained (subject, path) pairs are skipped and COUNTED (`alreadyEnforced`),
  never silently dropped.
- **Cite control IDs only, never CIS/ISO prose.** `controls` is a structured
  `framework -> [ids]` map (rule/mapping split, prior-art lesson from Regula/
  Prowler/Trivy); rationale is our own, vendor-doc-grounded. NonCommercial-safe
  under the MPL runtime.
- **Scope keys off `meta.environment`** (all|prod|dev), composing with the D199
  overlays; the optional `when:` guard is one more `{path, op, value}` triple.
- **First slice: the full 16-row starter set** (§7 of the proposal) across
  database.relational, storage.object, cache.keyvalue, messaging.queue,
  network.private, cluster.kubernetes, key.encryption, audit.trail. ~Half the
  vocab intentionally carries NO recommendation (least-privilege identity, no
  universal ops default) — silence keeps output high-signal.

`groundhold suggest <contract> [<candidate>] [--json] [--as hard|soft]`: human form
prints grouped, cited, ready-to-paste snippets under constraints.<hard|soft>;
`--json` is the self-describing console ingest shape (specVersion + contract +
environment + suggestions[] with controls, mirroring `cost --json`). Plan and
converge print a one-line hint on stderr ("N hardening suggestion(s) — run
`groundhold suggest`"), same channel as the cost estimate — never on the hashed plan.

## D204 — Network availability.class (multi-AZ) across AWS/GCP/Azure
Surfaced by the first real-AWS run (a contract's internet-facing ALB refused
at preflight — AWS requires a load balancer to span >=2 availability zones,
and there was no way to express a multi-zone network in the contract). Added
`availability.class` (enum `zonal | regional`, the existing enum convention,
`equals` operator) to `capability.network.private`. A regional network is what
a zone-redundant workload — or an internet-facing load balancer — is placed on.

The cross-provider mapping is the point, and the analysis (before writing a
line) is why AWS is the exception, not the rule:
- **AWS**: subnets are AZ-bound (one subnet lives in exactly one zone), so a
  regional network means creating >=2 subnets across >=2 AZs. The VPC driver
  now resolves the private subnets from availability.class: zonal (or unset,
  back-compat) = one subnet, AWS-chosen AZ; regional = >=2 subnets, default
  a/b AZ letters + a derived second /24, overridable with
  implementation.subnet_cidrs / availability_zones. The imperative shell loops
  the create with the same partial-composite discipline (only the first subnet
  is a bare "failed"; a later one is unknown WITH the pid).
- **GCP**: a subnetwork is regional by construction — it spans every zone in
  the region. `regional` is satisfied natively with no extra resource; a
  `zonal`-only network is not honestly expressible, so the driver refuses it
  rather than fake it.
- **Azure**: a subnet is region-wide and availability-zone placement is a
  per-RESOURCE choice, not a subnet property. Same as GCP: `regional` native,
  `zonal` refused.

Conformance-first: three dual verifier cases (regional satisfied, zonal
violates, enum enforced) pin the vocab-driven semantic (D23, zero engine
changes); the driver behaviour is pinned by Go golden tests per provider.
Deliberately out of scope (a deeper follow-up): intra-plan wiring so a
freshly-created regional VPC's subnet ids feed a load balancer in the SAME
plan — that needs sealed-plan output references. Until then the path is
"create/adopt a regional network, then place workloads on it".

## D205. Honor a satisfiable attribute via a pre-created operand, not a refusal — TLS on AWS DB + Fargate
A driver must not refuse an attribute it CAN satisfy when the operator brings
the missing resource. Three AWS drivers refused a TLS attribute that GCP and
Azure honor natively, purely because honoring it needs a second resource the
one-binding rule forbids the driver from CREATING — but the operator can bring
a pre-created one, exactly as they already bring subnet groups, KMS keys,
security groups and execution roles (D26 operands). A proactive audit of every
"refuses for want of a separate binding" across all three clouds surfaced these
three (and confirmed the rest are honest refusals — provider-enforced defaults
you cannot turn off, or genuinely inexpressible topology):

- **Aurora** `encryption.inTransit=true`: add `implementation.clusterParameterGroupName`
  (a DB cluster parameter group with rds.force_ssl=1); referenced on
  CreateDBCluster (DBClusterParameterGroupName).
- **RDS** `encryption.inTransit=true`: add `implementation.db_parameter_group`
  (rds.force_ssl=1); referenced on CreateDBInstance (DBParameterGroupName).
- **ECS/Fargate** `tls.enforced=true`: add `implementation.targetGroupArn` +
  `implementation.containerPort` (a target group fronted by an HTTPS/TLS
  listener + ACM cert); the service registers behind it (loadBalancers) and the
  container gets a portMapping.

The honesty bar is the point: the create TRUSTS the operand, but observe MEASURES
the reality, so a wrong operand is caught as `violated`, never silently trusted.
Aurora/RDS observe read rds.force_ssl (DescribeDB[Cluster]Parameters); ECS observe
traces the target group to its load balancer's listener protocol
(DescribeTargetGroups -> DescribeListeners), reusing the ELBv2 client — an HTTPS/TLS
listener is tls.enforced, plaintext is not. An unreadable trace is a diagnostic,
never a fabricated false. GCP Cloud SQL (sslMode=ENCRYPTED_ONLY) and Azure
flexpostgres / Container Apps already honor these natively, so this closes the
cross-provider asymmetry rather than adding a new capability. Driver behaviour is
pinned by Go golden tests per provider (build honors the operand + observe measures
both directions); no vocab change (the attributes already exist), so no new
conformance case. Deliberately deferred: the in-place UPDATE path still refuses a
TLS flip on an existing DB (attaching/swapping a param group via ModifyDBCluster +
reboot) — create/replace is the path today.

The same honesty bar reversed an earlier observe-side punt (surfaced by the same
real-cloud run): Aurora/RDS observe used to emit a *diagnostic* for
`encryption.customerManagedKeys` because DescribeDB[Clusters|Instances] reports a
KmsKeyId without saying whether it is a customer CMK or the account-default aws/rds
key — treating the KMS DescribeKey as a binding boundary. But that boundary is the
same cross-service trace the ECS fix already crosses: DescribeKey returns
KeyManager (CUSTOMER vs AWS), so observe now MEASURES CMK (reusing the KMS client)
instead of punting. An unreadable KMS trace stays a diagnostic. The upshot for
brownfield adoption: a real Aurora/RDS with force_ssl + a customer key can now be
adopted and have BOTH `tls-*` and CMK confirmed by live observation — the adopt
Catch-22 (a hard constraint the driver could not observe) dissolves without any
constraint being softened to an assumption.

## D206. A safety PROVIDER fails closed — real-infra verbs refuse a defaulted fake (F4/F5)
The N1 sibling. The real-cloud run surfaced two fail-OPEN CLI edges where the
guarantee was silently weaker than it looked:

- **F4 — a provider verb defaulted to the FAKE driver.** `providerName` defaulted
  to `fake`, and several verbs' inline selection ended in `else { Fake }`, so a
  real `apply`/`adopt`/`observe` run with a forgotten (or typo'd) `--provider`
  would observe/adopt/apply nothing real while reporting success — exactly the
  fail-open hazard N1 forbids for clocks. Fix: a closed `providerVerbs` set (the
  verbs that touch real infra) refuses when the provider resolves to `fake` by
  DEFAULT, and an unknown provider name is an error rather than a silent fake
  fallthrough. `fake` stays fully supported as a DELIBERATE choice
  (`--provider fake` / `GROUNDHOLD_PROVIDER=fake`) — the conformance harness now
  declares it explicitly, the same deliberate choice a real operator must make.
  The guard sits beside the N1 `--at` guard and is pinned by a membership test
  (a verb dropped from the set is a fail-open regression).

- **F5 — adopt silently accepted and ignored `--observations`.** Adoption confirms
  every candidate-declared attribute against a LIVE observation only — an operator
  cannot attest their way into an adoption (D52, adoption must not lie). Accepting
  an attestation file it then ignored made that guarantee look softer than it is.
  Fix: `adopt` refuses `--observations` with a message stating the invariant,
  rather than silently dropping it.

Both are pure fail-closed refusals (no behaviour change for a correctly-invoked
command), the same shape as N1: a safety default must be named, never assumed.

## D207. Missing-operands preflight — every driver refusal in one pass (F7/F3)
apply drives the driver refuse-before-mutate hook (Validate) per capability and
fails fast on the FIRST refusal. On a real multi-capability contract that means N
round-trips: apply refuses on the first capability's first missing
implementation.* operand, you supply it, re-run, hit the next capability, and so
on — you never see the whole picture, and a contract with a dozen capabilities is
a dozen apply attempts.

`groundhold preflight <contract> <candidate> --provider <cloud>` runs the SAME
Validate hook for EVERY capability the candidate declares and collects all
refusals in one pass (apply.Preflight): the complete set of missing operands and
unsatisfiable attributes, each naming its capability + service + the driver's
exact message (the same messages D205 made name their operand), sorted for a
stable diffable report. Exit 2 when anything is unhonorable, 0 when the whole
contract is ready to plan/apply. It reuses Validate verbatim — no driver change,
no new declarative surface — so it can never disagree with what apply will
actually refuse. It is a provider verb (D206: refuses a defaulted fake) and
deterministic (Validate makes no network call, generation is 1 — a missing-operand
refusal is generation-independent). Deliberately NOT solved here: within a single
capability Validate still returns its first refusal, so a capability missing two
operands surfaces them across two preflights; collecting ALL operands per
capability would need each driver's builder to accumulate rather than fail fast (a
per-driver change, a later pass). The cross-capability collapse is the round-trip
that hurt.

## D208. Recursively self-documenting CLI — agents bootstrap from --help and drill
An agent's first contact is `groundhold --help`; from there it must be able to
reach every level of detail by following pointers the output itself gives — never
by guessing. Two rungs were missing:

- **No per-verb help.** `groundhold <verb> --help` did not exist; worse, on a
  provider verb it hit the F4 guard and printed "requires --provider" instead of
  help. Now `--help`/`-h` (and `groundhold help <verb>`) is intercepted before
  every guard and dispatch, and `verbHelp` extracts just that verb's block from
  the single usage source (so per-verb help can never drift from the overview).
  Each per-verb block is followed by a fixed drill-down tail naming the next rung:
  `explain <error-code>` (remediation), `explain <capability.type|attribute-path>`
  (the vocabulary), `parity` (the capability map), and the machine-contract rule
  (route on exit code + JSON "code", never banner text). A completeness test pins
  that EVERY guarded verb has a usage block, so a new verb without documentation
  fails CI rather than silently falling back to the whole usage.
- **The F4/N1 guards were half-documented.** N1's --at requirement was in the
  global notes; the F4 provider requirement (D206) was not. Both are now stated
  there, so an agent learns the fail-closed rules from --help instead of only by
  hitting them.

The ladder is now complete and self-referential: `--help` names `<verb> --help`,
which names `explain`, which explains codes and vocabulary — the whole surface is
learnable by drilling, with no external file and no guessing. `--help` exits 0 (an
explicit, successful request); a bare no-command invocation still exits 1.

## D209. Active bug detection at the wire — refuse-before-mutate on the serialized request
F10 (Aurora omitting MasterUsername → 400 mid-flight, after an ACM cert and ALB had
already landed) escaped every test because the httptest fakes return 200 for any
request body: the fake is a mirror of our assumptions, so it cannot catch a wrong
assumption. Consulted Codex (gpt-5.5) and Fable; both converged on the seam, Fable
pinned it exactly.

**The seam is the serialized provider request, not each driver's Build output.**
Every AWS request — whatever shape Build returned — funnels through `doSignedH`
(method + URL + headers + body) before signing. `enforceAWSWireContract(body)` runs
THERE, on mutating operations, before signing: a request that omits a field AWS
requires refuses at the last deterministic moment before partial state is possible.
This is not a test improvement, it is a runtime GUARANTEE (rhymes with D75
permission-preflight and D89 refusal-is-not-failure) — and because the check lives
in the real request path, every golden test that drives a create exercises it too,
with no per-fake wiring. Defense-in-depth BEHIND each driver's Validate: even a
driver that forgets a field cannot leak an incomplete mutating request.

**Two tiers, the correctness lesson (Fable): a generated table alone would NOT have
caught F10.** AWS Smithy marks MasterUsername "Required: No" — it is CONDITIONALLY
required (waived by a snapshot restore, a global-cluster secondary, or AWS-managed
password), and vendor models have no trait for conditionality. So the contract is
`required` (the FLOOR — unconditionally required, what a generated Smithy table
gives) plus `requiredUnless` (the OVERLAY — OR-groups and conditional rules, each
citing the evidence that proved it, e.g. F10's real 400). The overlay is not a
throwaway bootstrap for generation; it is the permanent tier the generated floor
cannot replace.

Scope now: AWS Query protocol (the RDS/Aurora/ELBv2/ACM family), the create ops in
play, hand-authored. Roadmap (both consults): a generator emitting the floor
(required/enum/pattern/range) from vendored Smithy/Discovery/OpenAPI, checked in and
CI-diffed (no network); the same decoder shape for GCP JSON / Azure REST; a small
STATEFUL fake for ordering/idempotency (the D37 scenario discipline pointed at the
provider boundary); and harvested request/response fixtures from real runs (every
real 400 becomes a pinned negative case) rather than a maintained credentialed VCR
suite. The gate stays deterministic, offline, stdlib-only — inside the verification-
core rules.

## D210. Driver-method completeness — every create service must be classifiable (F15)
F15: after a mid-flight apply bound an ACM certificate, the next plan had to
reconcile it, and `ClassifyChange` for the "acm" service was not wired — the default
"change-classification is not wired" is surfaced by the compiler as a HARD block
(classifyBound errors on any class outside mutable/immutable/caveated). One partial
apply then freezes every incremental apply. An audit found this is not one service
but a CLASS: 46 services can be Created, only 20 had ClassifyChange — 26 gaps, each a
latent F15. (Observe and Delete were already complete; Update has its own, narrower
need — only where ClassifyChange can return mutable/caveated.)

Two parts, mirroring D209's lesson (catch the class, not just the instance):

1. **ACM wired.** `classifyACMChange`: domain/validation/region are immutable (a
   change is a new certificate); `auto.renew` is `caveated` — ACM MANAGES renewal
   eligibility, so a freshly-issued certificate (not yet ELIGIBLE) converges to
   auto-renewing once validation completes; that transient difference is a managed
   no-op the Update path records, never a block and never a replacement of a healthy
   certificate. `updateACM` no-ops the managed path after an ownership re-check.

2. **The completeness gate.** `TestClassifyChangeCompleteness` source-parses the
   dispatch switches and asserts every Create service has ClassifyChange OR sits on
   an explicit allowlist (the 25 create-only services whose in-place update is
   deliberately unwired). It is the N1 / provider-verb membership pattern applied to
   driver-method wiring: a NEW create service without ClassifyChange fails CI; wiring
   an allowlisted one without removing it fails too. The allowlist is the visible
   burn-down of the latent-F15 debt, not a green light — reconciling a bound resource
   of an allowlisted service still errors, so each is a follow-up to wire per-path
   (immutable structural paths, caveated/unsupported platform paths) as ACM now is.

The gate is SYMMETRIC across clouds (the agnostic+symmetric discipline). Extending
it to GCP and Azure — parsing BOTH dispatch styles (AWS/Azure `switch { case }`,
GCP `if service == …` chains, Create and ClassifyChange in different GCP files) —
found the same latent-F15 reservoir everywhere: AWS 25, GCP 22, Azure 25 create
services without ClassifyChange (~72 total), each a frozen incremental apply
waiting for that service's first mid-flight partial. All three are now pinned with
per-cloud allowlists. The gate proved its worth immediately by catching gaps a hand
grep missed twice (GCP's Create is in driver.go with if-chains, so a switch-only or
wrong-file scan reported it clean when it was not). Burning down the allowlists
(wire each service per-path) is future work; the active detection — no NEW create
service ships without ClassifyChange on any cloud — is in place now.

## D211. Adoption confirms a version at the DECLARED granularity (F8)
F8: adopting a real Aurora whose observed engine.protocol is postgresql/16.13
against a candidate declaring postgresql/16 (major only) failed — adoption confirmed
every declared attribute with strict `equals`, and 16 != 16.13. An operator rarely
knows the minor version ahead of a discover, so a major-only declaration is normal.

The honest fix is NOT `compatible-with` (the existing >=minimum operator): the
protocol scalar does not track specified precision (16 and 16.0 both parse to minor
0), so compatible-with would confirm a MINOR-precise declaration (postgresql/16.5)
against a different minor reality (16.13) — recording a value untrue of reality,
which violates "adoption must not lie" (D52). Instead adoption confirms a protocol
attribute at the DECLARED granularity, read from the raw string: the engine name
must match, and every version component the DECLARATION specifies must equal the
observation's (which may be more precise). So postgresql/16 is confirmed by
postgresql/16.13 (the fact "PostgreSQL 16" is true of a 16.13 database), but
postgresql/16.5 is NOT confirmed by 16.13, and a declaration more precise than reality
is never confirmed. Every other scalar kind still confirms with strict `equals` (no
coercion, #2); no operator was added (#4); the change is local to adopt's confirmation
gate (a Go-only verb), pinned by protocolConfirms unit cases. Deliberately out of
scope: teaching the protocol scalar to track precision (16 vs 16.0) — a larger dual
scalar change; the raw-string granularity read is sufficient and honest here.

### D209 addendum — JSON-RPC arm + a clean proactive audit of the create-paths in play
The wire gate now covers a SECOND AWS protocol: JSON-RPC (X-Amz-Target header +
JSON body — ECS, DynamoDB, …), alongside the original Query protocol. The op is the
segment after the last "." in the target; fields are the top-level JSON keys; the
same two-tier contract (required floor + requiredUnless overlay) and the same
refuse-at-the-wire behaviour apply (contractMissing is shared). Seeded with the
obvious required fields for ECS (CreateService.serviceName, RegisterTaskDefinition.
family+containerDefinitions) and DynamoDB (CreateTable.TableName+KeySchema+
AttributeDefinitions, BillingMode|ProvisionedThroughput). REST (EKS, S3) stays a
future arm.

Ahead of a real apply of EKS / ElastiCache / S3 / DynamoDB / ECS, all five
create-paths were audited for the F10 class (a strictly-required field silently
omitted) — and found CLEAN: every AWS-required create field, accounting for
conditional waivers, is present, and the multi-resource creates front-load their
operands as preflight refusals in the Build* functions (roles, subnets, keys), which
is exactly what the Aurora bug lacked. One non-F10 operational note: ElastiCache
CreateReplicationGroup omits CacheSubnetGroupName unless implementation.
cache_subnet_group is supplied, which fails on the FIRST call (no partial state) if
the account has no default cache subnet group.

## D213. Projection attributes never gate a reconcile (F16)
A real mid-flight partial (an apply that created ACM + ALB + Aurora, then stopped)
exposed a systemic reconcile freeze: `classifyBound` requires an observation for
every candidate-declared attribute, but `cost.monthly` is a cost FORECAST and
`recovery.rto` a probe TARGET — neither is reconcilable resource state, and neither
is ever emitted as an observation. So the reconcile of an already-BOUND resource
refused "cost.monthly: no observation — re-observe first", and since every capability
carries a cost.monthly, ONE partial apply froze every subsequent apply. The drivers
already classify these as "projection — nothing to patch" when they reach
ClassifyChange, but classifyBound errored earlier, before the driver was asked.
Fix: classifyBound skips projection/probe attributes (isProjectionAttr:
cost.monthly, recovery.rto) — no observation is expected or required, exactly as it
already skips an unknown-status attribute. Deterministic, in the compiler core;
pinned by a Go test (the compiler is Go-only, D24). This unblocks retry-after-partial,
the incremental-apply path a mid-flight failure lands you on.

## D214. Bedrock create confirms from the ARN, not a bare id (F18)
A real full apply created ACM + ALB + Aurora, then the Bedrock step returned
`unknown — reconcile before retrying` and aborted — but the inference profile had
in fact been created and was ACTIVE. Root cause: AWS's CreateInferenceProfile
returns `inferenceProfileArn` (+ status), NOT a bare `inferenceProfileId`, and the
driver required the id — so a SUCCESSFUL create was reported `unknown`, which the
executor treats as a possible-partial and stops, leaving state to reconcile (into
the F16 path). Fix: derive the id from the ARN's last path segment when
`inferenceProfileId` is absent (bedrockIDFromArn); only a truly empty response
(neither id nor arn) stays `unknown`. Pinned by an ARN-only create case (the real
AWS shape). A false "unknown" is not harmless — it manufactures the partial-state
that every downstream reconcile bug then trips over.

## D215. A no-in-place-update service reconciles a drift by REPLACEMENT, not a freeze
D210 gave the completeness gate + wired the services that need non-immutable
classification (acm caveated, elasticache/others). But a real retry-after-partial
still risked freezing on the ~72 allowlisted services: `classifyBound` blocks on any
ClassifyChange class outside mutable/immutable/caveated, and the default returned
"unsupported" — so reconciling a bound resource of an unwired service (e.g. an
adopted vpc or route53 zone) stalled the whole apply "change-classification is not
wired". The fix: the default (all three clouds) now returns "immutable" — a service
with no explicit in-place update path honestly reconciles a drift by REPLACEMENT
(consent-gated when stateful, D48), never a silent freeze. It is the only
non-erroring class available to a no-Update service (mutable/caveated would then
error at Update), and it is honest: the driver genuinely cannot patch that resource
in place. Explicit per-service ClassifyChange stays the refinement where a path is
mutable in place (mutable/caveated + Update); the completeness gate keeps forcing a
conscious choice for every new create service. This unblocks retry-after-partial for
every allowlisted service at once — the reconcile path a mid-flight failure lands on.

## D216. Observe what reconcile needs — paginated force_ssl + ALB region (F17 real-cloud)
Two observe gaps froze a real retry-after-partial reconcile of already-bound
resources:
- **Aurora/RDS encryption.inTransit false-negatived.** The force_ssl observer
  (D205) read DescribeDB[Cluster]Parameters with a SINGLE call. A cluster parameter
  group has dozens of parameters and the API PAGINATES; rds.force_ssl can sit past
  the first page, so the scan missed it and reported inTransit=false — which drifted
  a bound cluster (whose param group really has rds.force_ssl=1) at reconcile, and
  the change-classifier refused "TLS needs a parameter group — not patchable in
  place". Fix: follow the Marker until the parameter is found or the list is
  exhausted (clusterForceSSL + dbForceSSL).
- **ALB location.region not observed.** The load balancer create requires
  location.region but the observe never emitted it, so a bound-ALB reconcile refused
  "location.region: no observation". The region is the balancer's own (its
  providerId); observe now emits it.

The pattern (the operator's meta-ask): a reconcile of a bound resource needs an
observation for EVERY candidate-declared attribute. Genuinely-unobservable
projections are skipped (D213); everything else the driver must actually OBSERVE —
completing an observer is the honest fix, never treating an unobserved real
attribute as satisfied.

## D217. The AWS driver reconciles pending receipts (F19)
F18's earlier false-"unknown" bedrock create left a PENDING receipt in the ledger.
Every subsequent apply/converge then refused "in-flight operations must be
reconciled first" (D29), and `resume` — the verb that concludes pending receipts —
returned "provider aws cannot reconcile receipts": the AWS driver never implemented
the OPTIONAL Reconciler capability (D57), so a lost/ambiguous mutation on AWS was a
PERMANENT stop (the GCP driver had it; AWS did not). Fix: implement Reconcile on the
AWS driver — read-only, dispatched on the receipt's target service, fail-closed to
unknown for an unwired service. The first service is bedrock: an application
inference profile carries groundhold ownership tags, so a paginated ListInference-
Profiles + tag match concludes the pending create — succeeded WITH the server-
assigned id (the tag is the deterministic handle D57 relies on), failed if a
complete readable list carries no owned profile, unknown if unreadable. Never
mutates. Other services fail-closed until wired (the same conscious-extension shape
as the ClassifyChange gate). This is the escape hatch a mid-flight partial needs:
without it, one ambiguous create freezes the whole apply forever.

## D218. Bedrock list uses the real typeEquals filter (F20)
The F19 reconcile listed application inference profiles with a `type=` query
parameter, but the AWS ListInferenceProfiles filter is `typeEquals` — an unknown
param, so the API defaulted to SYSTEM_DEFINED and returned no APPLICATION profiles.
So reconcileBedrock could not see the profile it had itself created, and `resume`
still could not conclude the pending create. Fix: use `typeEquals`. The fake now
mirrors AWS — it filters by typeEquals and defaults to SYSTEM_DEFINED when absent —
so the reconcile test genuinely exercises the correct parameter (it fails with the
old `type=`). Noted follow-up: discoverBedrock lists WITHOUT a type filter, so it
too sees only SYSTEM_DEFINED profiles on real AWS — discover/adopt of an application
profile misses it; a later slice lists both types.

## D219. AWS reconcile carries the operator region — the real F20 root cause

D218 (typeEquals) was necessary but not sufficient: on Acme's live retry the
binary still failed `resume` with an opaque "bedrock ListInferenceProfiles
unreadable". Root cause was one layer deeper and had nothing to do with the query
param — `reconcileBedrock` reads `d.Region`, but the CLI constructed the AWS driver
as `aws.NewDriver("")` in resume/converge/adopt/probe, DISCARDING the operator's
region. GCP and Azure pass `project` in the same positions (D28's read-set identity
for GCP); only AWS threw its scope away. A region-scoped list with an empty region
builds a malformed endpoint and fails as the opaque "unreadable" — three iterations
(F18 create-confirm, F19 reconciler, F20 typeEquals) each fixed a real symptom while
this asymmetry sat underneath, invisible because the bedrock test's fake OVERRIDES
`BedrockBaseURL`, so an empty region never reached URL construction in a test.

Fix: pass `region` (symmetric with GCP/Azure) in all four live verbs, and guard
`reconcileBedrock` to REFUSE honestly with a region-naming reason when the region is
absent — never a malformed request reported as "unreadable". A new test constructs a
region-less driver and asserts the honest refusal — the regression the URL-overriding
fake could not previously catch. The lesson: a symptom-at-a-time loop is the failure;
trace the whole path (CLI construction → driver → live call) before shipping.

## D220. Bedrock discover sweeps both profile types (closes D218's follow-up)

D218 noted it: discoverBedrock issued a bare ListInferenceProfiles, which on real
AWS defaults to SYSTEM_DEFINED — so it surfaced AWS built-ins for the residency audit
but SILENTLY MISSED every APPLICATION profile, the exact kind groundhold creates and a
brownfield adopt takes over. A discover that finds nothing to onboard is worse than
useless. Fix: sweep BOTH types explicitly via listInferenceProfiles (which carries
typeEquals + pagination), so system-defined profiles stay in the residency sweep and
application profiles are found for adoption. Pinned by a test that discovers an
APPLICATION profile against a fake mirroring the real SYSTEM_DEFINED default.

## D221. Reconcile is wired for every service, every cloud (F24)

F24 root cause was systematic, not per-service: `resume` concludes a pending create
receipt via driver.Reconcile, but reconcile was implemented per-service and covered
only bedrock (AWS) and cloudsql (GCP) — Azure had no Reconciler at all, so resume
REFUSED every Azure run. Any async create (EKS, Redis, ...) returns Status:"unknown"
without waiting to ready; an unwired reconcile then left the receipt in-flight forever
and converge stayed STALE (D29). Acme hit it on EKS.

Fix: wire reconcile for EVERY create-dispatch service across all three clouds (AWS
45/45, GCP 40/40, Azure 39/39). Three identity tiers, in preference order:
1. `receipt["targetProviderId"]` — apply now persists the id an unknown create computed
   (D57), so future receipts self-describe: split the pid, read live state by identity.
2. Deterministic-name recompute — most resources name themselves as a pure function of
   (environment, capability, generation[, account/project]); reconcile recomputes the
   name exactly as create derived it and reads live state. This is what concludes a
   receipt written BEFORE any id was persisted (the existing-receipt case).
3. List + ownership-tag scan (the bedrock pattern) for server-assigned ids that have a
   list wrapper. Server-assigned ids with NO list wrapper (aws vpc/kms/cloudfront/
   apigateway/route53health/vpngateway) rely on tier 1; absent a pid they return an
   honest unknown, never a guess.

Uniform four-valued verdict (`concludeByStatus` / the GCP `concludeGenericCreate` /
the Azure equivalent): succeeded ONLY on found+ready+ours; failed on a readable
absence (AWS/Azure authoritative describe-by-name) or a terminal-failed state or
foreign ownership; unknown on any unreadable read, still-provisioning, or not-ours.
GCP keeps cloudsql's create+absent→unknown (eventual-consistency honesty). Azure
`defender` is a subscription posture singleton with no per-op landing signal — it
concludes succeeded once the pricing plans are readable and defers tier correctness to
drift/audit (documented, the one weaker-than-tag signal). Reconcile is STRICTLY
READ-ONLY everywhere. ~150 new Go tests; make check 410/410.

## D222. AWS permission preflight — parity with GCP (D75)

Preflighter was GCP-only; AWS apply logged "provider aws cannot check permissions:
skipped" (Acme saw it). The permission TABLE already existed for AWS (PermissionsFor
"aws" case); the gap was only the live check. Added go/internal/aws/preflight.go via
iam:SimulatePrincipalPolicy — AWS's actual policy simulator (evaluates identity
policies + permission boundary, unlike GCP's testIamPermissions which has surface
gaps).

Honesty (D78 applied to AWS): explicitDeny is always authoritative (denied). An
implicitDeny is authoritative ONLY in the RESOURCE's ARN context —
CheckResourcePermissions rebuilds the ARN from the providerID (rds/aurora/dynamodb/
sqs/sns/kms; others fall back via ErrNoResourceSurface), so a missing grant there is a
real denial. Against "*" (account-level CheckPermissions, and every not-yet-created
resource) an implicitDeny is UNATTESTED — it may reflect a grant scoped to a specific
ARN, and groundhold must never refuse an authorized user. Assumed-role session ARNs
are normalized to the role ARN; non-simulatable principals (root/federated) and any
simulate error are inconclusive, never a denial. A pass is evidence, not proof.

## D223. Azure permission preflight — parity with GCP/AWS (D75)

Azure was the last cloud without a live preflight. Added go/internal/azure/preflight.go
via the ARM Microsoft.Authorization/permissions list (the caller's effective RBAC
actions at a scope), with RBAC-correct matching: an action is granted when some role
entry's actions glob-match it and that entry's notActions do not ('*' globs any run
incl '/', case-insensitive).

Same D78 honesty as AWS: at the SUBSCRIPTION scope an ungranted action is UNATTESTED
(a narrower-scope assignment may grant it; and the surface returns no deny-assignment
signal, so `denied` is always empty there). At the RESOURCE scope
(CheckResourcePermissions builds the resource id — flexpostgres/aks/rediscache/cosmos;
others fall back via ErrNoResourceSurface) the effective permissions include every
inherited assignment, so an ungranted action IS a real denial. Deny assignments and
ABAC conditions stay invisible — a pass is evidence, not proof. All three clouds now
implement Preflighter + ResourcePreflighter.

## D224. Outcome-probe parity: AWS RDS/Aurora + Azure flexpostgres (D59)

Prober was GCP-only (Cloud SQL). Added AWS (go/internal/aws/probe.go: rds + aurora) and
Azure (go/internal/azure/probe_azure.go: flexpostgres) probers, modeled on the GCP twin.
network.publicExposure by an ACTUAL TCP handshake (measured, never fabricated);
recovery.rto (INTRUSIVE, double-consented) by restoring the latest snapshot / a PITR
into a deterministically-named scratch resource, timing it to a USABLE state, then
deleting it. Ownership + sameAccount/subscription are gated BEFORE any billed create;
scratch cleanup is attempted on every path and a leak is surfaced loudly, never silent.

An adversarial audit (per cloud, read-only) gated the merge and caught two real Aurora
bugs the fakes masked: (1) deleteScratchAurora deleted the member then IMMEDIATELY the
cluster — AWS refuses a cluster delete while a member is still async-deleting, leaking a
billed cluster on EVERY successful run; fixed by waiting for the member to be gone and
retrying the cluster delete. (2) the RTO was timed to the cluster reaching "available",
which happens before the member is provisioned — understating the true time-to-usable
(optimism is fabrication); fixed by timing to the member instance "available", as RDS
does. The Aurora happy-path fake is now stateful (member lingers; cluster refuses until
the member clears), making it a genuine regression test. Azure was clean; added the
missing coverage (allowIntrusive=false → no scratch; terminal-failed and poll-timeout →
cleanup). All three clouds now implement Prober. make check 410/410.

## D225. Protocol reconcile: major-granularity satisfied-by-minor (F16-B)

A bound resource whose engine.protocol was declared at MAJOR granularity
(postgresql/16) but observed at major.minor (postgresql/16.11) drifted on every
plan — classifyBound compared observed-vs-desired with the `equals` operator, so
16.11 ≠ 16 emitted a perpetual no-op update (Acme's only remaining stack drift).

Fix (Acme's decision, over observer-emit-major): a precision-aware TYPED comparison
for the protocol kind in the reconcile change-detection — scalars.ProtocolSatisfiedBy.
A desired value that pins only the major accepts any observed minor of that major; a
desired value that pins a minor requires it to match; a different family or major is a
real change. The declaration's PRECISION survives the parse via the raw string (the
parser fills a missing minor with 0, so "16" and "16.0" would otherwise be
indistinguishable). The observer keeps the real minor — only the comparison semantics
change, so we never discard the observed 16.11 (the precision F28 fought for).

This is the precision-aware sibling of the existing `compatible-with` OPERATOR (which
is `>=`, for a minimum-version CONSTRAINT). It is a typed comparator over one kind, NOT
an expression language — invariant #4 (closed operator set) holds, the same class as
the currency-aware money comparison in invariant #2. classifyBound is Go-runtime, so
the conformance case carries impl: go (plan-protocol-major-satisfied-by-observed-minor:
declared /16 + observed /16.11 → engine.protocol stays out of the change-set while a
real drift still updates). Reusable for every versioned capability (redis/7, k8s 1.35).

## D226. Intra-plan output references — same-plan wiring without an expression language (F13)
A candidate operand could only be a literal the operator pre-created: subnet ids,
a KMS key, a roleArn, a subnet group (D26). So a resource created THIS plan could
not feed another action in the SAME plan — the workaround was "create/adopt the
network in a PRIOR run, then reference its literal ids" (D204 left this explicitly
out of scope: "that needs sealed-plan output references"). This is the biggest real
pilot pain. F13 adds those references without breaching invariant #4 (closed
operator set): a reference is a typed STRUCTURED node, never string interpolation.

Design consulted with two frontier models (convergent); the synthesis grounds every
piece in existing machinery rather than new mechanism.

**Reference shape.** An operand may be `{$ref: {capability: <capID>, output: <name>}}`
where `$ref` is the SOLE key of the operand node. No string carrier, no `${...}`, no
extra keys, no transforms/joins/selectors — that is the anti-interpolation wall, and
violating it is `reference-invalid`, not a parse of a mini-language. `capability` is a
capID in the SAME candidate (cross-candidate/cross-contract refs are refused; the
sanctioned cross-plan path stays observe-then-fold).

**Typed output contract.** Each driver declares `OutputsFor(capType) []OutputSpec`
(name + `scalars.Kind`), pure and table-driven, exactly parallel to `PermissionsFor`
(D75) and the observe enum tables. The output name must appear in the producer's
`OutputsFor`, and its Kind must equal the consuming operand slot's kind — no coercion
(invariant #2): a `list` output into a `string` slot is a refusal, never a `join(",")`.
Reusing `scalars.Kind` (String, List, ...) keeps this inside the existing type system;
no parallel output-type vocabulary.

**Compile: fold vs symbolic, one question — does THIS plan create the producer?**
- Producer already bound (existing resource): literal-FOLD. The compiler reads the
  latest observation from the D45 projection, gated by the vocab staleness TTL measured
  against the explicit `--at` (N1 — no epoch default can make stale look fresh). Fresh →
  the operand becomes a literal scalar with `basis: inferred`, and the observation event
  hash enters `Reads` so the D46 compile-time staleness gate re-fires at apply. Stale or
  absent → `observation-required` (run `observe`); NEVER a symbolic fallback, never the
  candidate's old literal.
- Producer is a same-plan create: emit a `SymbolicRef{ProducerAction, Capability,
  Output, Kind}` and add the `DependsOn` edge (ordering already existed; only value
  wiring was missing). `ProducerAction` is the action id `capID:gN`, not the bare
  capability — under D48 replace composition the new-generation create is the only
  unambiguous producer.

**Determinism.** Only the canonical `SymbolicRef` structure enters the plan hash (D34,
sorted keys); a resolved subnet id never touches it — restart-stable by construction,
pinned by a dual conformance case and swept by `make differential`. The consumer's
IdempotencyKey folds every producer's idemKey (sorted), so a producer replace bumps its
generation → its key changes → every consumer re-keys and cannot reuse a receipt minted
against a dead producer.

**Apply: refuse-before-mutate.** The producer runs first (DAG). When it returns, the
executor filters its raw result through `OutputsFor`, kind-checks each value, and writes
only declared, valid outputs into the `operation.receipt` event — a wrong-kinded or
missing declared output fails at receipt-WRITE time (producer concludes unknown, nothing
downstream starts). Before the consumer's write-ahead intent, the executor resolves each
ref from the producer receipt: missing receipt / producer not `succeeded` (unknown is
contagious) / output absent / kind mismatch → the consumer is `unknown`, no intent is
written, no driver call is made (`reference-unresolved`). `resume` (D57) re-resolves from
the persisted ledger; `converge` closes the loop — a receipt that lied diverges from the
subsequent observation and surfaces as non-convergence, not silent propagation.

**Refusal set** (each fails closed; no `--force`, matching the hard-constraint posture).
Compile (`reference-invalid`, prose carries which): unknown capability; unknown output;
kind mismatch; malformed `$ref` (not sole key / extra fields / interpolation pose);
dependency cycle; producer retired/deleted this same plan (`ref-producer-retiring` — a
value from a resource being destroyed is a lie); ambiguous producer generation. Stale
fold → `observation-required`. Apply (`reference-unresolved`, consumer→unknown, zero
mutation): producer receipt absent or not `succeeded`; declared output missing; provider
returned a value failing the pinned Kind (unverifiable — the provider spoke, wrong type).

**First slice (symmetric — AWS+GCP same PR):** `network.privateSubnetIds` (AWS, a
`list`) and `network.selfLink` (GCP, a `string`) → a managed database. One edge (create
network → create DB), the smallest DAG that proves fold, symbolic, receipt-outputs and
re-key end to end, and it makes the kind system load-bearing on day one (list AND string,
no-coercion enforced). eks.clusterName + workload-sa.roleArn → pod-identity is the natural
SECOND case (two refs; tests multi-ref key folding). Conformance-first (invariant #5):
a dual case pinning the sealed-plan hash with a `SymbolicRef`, a case per refusal, a
scenario case for a crash between producer receipt and consumer resolve, then the code.
## D227. Honest progress for the execution loop — liveness without a lie (progress track)
`apply` executed a sealed DAG of N actions, some long cloud LROs (Cloud SQL ~7m,
EKS ~30m), and said NOTHING during the wait: stderr silent for minutes. A human
operator could not tell a slow-but-fine create from a wedged one — no position, no
sense of remaining — and for an autonomous agent the run was a black box. Research
across IaC, CLI craft and agent tools converged on one finding: the #1 pain is
"is it hung or working?" (liveness + current state), NOT a percentage; and every
credible source rejects a fabricated %/ETA because it is non-deterministic AND masks
stalls. That rejection is exactly our thesis (never fabricate, four-valued honesty),
so progress here is designed to deliver only what is true. Consulted with two frontier
models (convergent); the synthesis grounds every piece in existing machinery.

**Governing idea.** Progress is a PROJECTION of the executor's action state machine,
not a second source of truth. The same machine that decides to write receipts emits
progress events. One source, two projections — durable receipts, ephemeral stream —
which cannot drift because neither derives from the other; both derive from the machine.

**Channel: hybrid, ledger untouched.** Progress is a versioned NDJSON stream
(`groundhold/progress/v1`) of per-action deltas keyed by ActionID, emitted in-process
to stderr; it is NOT in the sealed plan, NOT in the plan hash, NOT a receipt. Three
kills for "make it ledger events": (1) tick content depends on scheduler jitter and
provider latency — hash-chained events with run-varying payload would break D35
cross-language hashing and turn D38 differential into a coin flip; (2) a 30-min wait at
a 10s heartbeat is ~180 events/action — the ledger is a truth record with a ~10us/event
replay budget, not a metrics store; (3) receipts ALREADY bracket every action with
coordination-clock timestamps, so audit/export/capsules and the ETA history need nothing
more. Only liveness is missing, and liveness is definitionally ephemeral. Consumers:
human TTY folds the stream; an agent reads `--progress=ndjson` (banners ride as
`kind: banner` events so the channel stays pure); CI reads `--progress=plain`
(rate-limited ticks, no ANSI); the console derives done/active/pending from the receipts
it already projects (intent seen + not concluded = active) and may later tail the stream
read-only. Stdout is untouched in every mode — pinned by a case.

**Two event kinds, different honesty contracts.** A `transition` = the state machine
moved; it is the ONLY kind that advances k, changes state, or moves an indicator. A
`tick` = liveness heartbeat carrying elapsed and (if the provider literally supplied one)
a fresh percent; it can NEVER change state or k. Enforced by type and pinned by a case.

**Closed 10-state action enum** (the transition table is itself conformance data):
`pending | ready | running | provider-wait | stalled | blocked-consent | done | failed
| skipped | indeterminate`. `blocked-input` was dropped — a sealed plan takes no mid-flight
input by construction (else the seal is a lie); only consent friction (converge, two-step
MCP) is a legitimate human gate. `stalled` (evidence stale — poll budgets missed or polls
erroring; NOT terminal) and `indeterminate` (gave up without knowing → unverifiable, routes
to `resume`) were ADDED: "hung or working?" demands a visible stall state, and the
four-valued world demands a terminal that admits ignorance. Motion is a PURE FUNCTION of
state: only `running` and `provider-wait` animate, and `provider-wait` requires fresh
evidence or the machine transitions it to `stalled` (glyph freezes, reason names the
silence). Elapsed keeps incrementing in stillness — honest (time passes) and exactly how a
human distinguishes slow-but-fine (motion, elapsed within band) from wedged (stillness,
evidence age growing). k counts TERMINAL actions (done+failed+skipped+indeterminate) —
"k of N resolved" is the honest determinate signal; the terminal banner reports resolved
AND succeeded (different numbers).

**Three clocks, strictly partitioned (N1 survives untouched).** (1) evaluation clock
(`--at`, fail-closed): judges observation freshness in verdict logic; the progress
subsystem has no import path to it. (2) coordination clock (D56): stamps receipts and the
event `startedAt` — same source as the durable record, so progress adds no new time
authority. (3) monotonic runtime clock: produces `elapsedMs` durations only; a duration
cannot masquerade as a freshness claim (the human fold renders durations, never absolute
times). The partition is import-graph-enforced (vet, same discipline as the post-D62
`time.Now` bans): progress cannot read the evaluation clock, the verifier/ledger cannot
read the runtime clock.

**Provider percent is passthrough or absent.** GCP LROs (AIP-151) supply none, so Cloud
SQL renders no percent, ever; Azure sometimes supplies `percentComplete`, then we show it
attributed to the provider (`basis: declared`). We never compute a percent from
elapsed/typical — that is fabrication with extra steps.

**ETA band: basis-tagged, EWMA over own receipt history, often absent.** `{atLeast
(fastest success), typical (EWMA of successes), worst (p95), basis: inferred, samples}`
keyed by (capability type, operation, provider, region), success and failure populations
kept separate (failure durations predict nothing about success). No band when samples < 3,
or the history spans a provider/region change, or — the honest detail — elapsed has
EXCEEDED `worst`: the band is WITHDRAWN and replaced by prose ("beyond seen worst p95 9m2s,
still waiting"), because a band already beaten is a lie and being out-of-distribution is
itself information. No history → no number; never `{basis: unknown, typical: 123}`.

**Testing a non-deterministic stream deterministically** (the crux; invariant #5). Split
the surface: (1) golden layer — the D37 scenario engine scripts each action's provider
timeline as data (`polls: [running@+10s, silence@+120s]`) and binds the runtime clock to a
VIRTUAL clock, making every field (seq, elapsedMs, state, k) a pure function of the script;
the case asserts the byte-exact golden NDJSON sequence (stall transitions, tick cadence,
band presence/absence via seeded 0/2/12-receipt histories, percent passthrough). (2)
clock-free invariant layer — over a real-clock stream: every transition edge is in the
pinned table; k monotone, increments only on terminal transitions, ends at N; a tick never
changes state/k; every action reaches exactly one terminal; band absent with empty history;
percent absent unless scripted. (3) purity cases (load-bearing): stdout under
`--progress=ndjson` is byte-identical to `--progress=none`; and the LEDGER hash-matches
across progress modes for the same scenario — invariant #6 as an executable assertion, not
a comment. Rule: anything byte-pinned runs under the virtual clock; anything real-clock is
covered by clock-free invariants; nothing is exempt from both.

**First slice (T0):** the action state machine + closed enum + pinned transition table; the
event emitter with ndjson/plain/none sinks; run-manifest + terminal events; virtual-clock
scenario support; the conformance cases. **T1:** the TTY sticky region; ETA bands; stall
budget tuning; `--progress` flag surface. **Deferred:** console SSE tail, MCP progress
notifications, background+notify, Azure percent. All Go-runtime (`impl: go`). Deliberate
non-goal, forever: no global percent. `[k/N]` resolved, per-action state with reason,
honest elapsed, a basis-tagged band when history earned it — that is the whole vocabulary,
and it is enough.

### D227 addendum — the two honest gates surfaced by implementation
Building the epic surfaced two places where the honest substrate does not yet
exist, and the thesis (never fabricate) dictates the same answer in both: build
the machinery, emit nothing until the real source is there.

**ETA band — gated on a durable timing source.** The band math (`progress.Band`)
is complete and tested: an `inferred` band from measured success durations,
`nil` below three samples, withdrawn once elapsed beats `worst`. But the durable
source it needs does not exist. The deterministic ledger stamps receipts with
the LOGICAL coordination clock (= `--at`), which does not advance within a run —
so the intent/terminal receipt bracket is zero-width and carries no wall-time.
Recording measured wall-duration INTO a receipt would make the ledger
non-deterministic and break the conformance suite, which pins ledger hashes. An
honest band therefore needs a durable timing store OUTSIDE the hash-chained
ledger (a per-environment sidecar, a future Dxx). Until it exists the runtime
emits no band — fail-closed, not a gap. This is the invariant-#3 discipline
applied to time: no history, no number, never a guess dressed as fact.

**provider-wait / tick / stall — gated on driver LRO-polling.** The closed
enum, the transition table, the `Fold`, the sticky-region frame and the emitter
all support `provider-wait`, `tick` and `stalled` (unit-pinned). But today's
drivers return a SYNCHRONOUS terminal `CreateResult`, so the executor emits
`running -> {done|failed|indeterminate}` directly and no action enters
`provider-wait` in production. The "is it hung?" core — motion only while
evidence is fresh, demotion to `stalled` on poll-silence with the age named —
becomes live the moment a driver exposes incremental LRO polling (a future
optional interface the executor already has the shape for). Adoption is
per-driver and additive; nothing about the enum, the frame, or the stream
changes. What ships now is honest for a synchronous executor: position (k/N),
per-action state, measured elapsed, and the purity guarantee.

Net for the epic: the liveness core (stream, manifest, k/N, states, elapsed,
purity, plain/ndjson/tty renders) is LIVE and pinned; the two enhancements are
architecturally complete and gated on substrate that must arrive honestly, not
be faked. That boundary is the deliverable, stated plainly.
## D228. Human-readable plan preview — the review surface before apply (`show`)
`plan` compiled a verified candidate into a Sealed Plan and emitted it as JSON —
the machine IR. An operator who must CONSENT to an apply had only raw JSON to
review: what changes, at what risk, in what order, needing what consent. That is
the praised "plan mode" gap. `show <plan.json>` renders a SAVED plan to scannable
text. Design consulted with two frontier models (convergent).

**Placement: a `show` verb on the saved plan, not a `plan --human` flag, not
stderr.** Consent must bind to bytes: the flow is `plan --at ... > p.json;
show p.json; apply p.json`, and the render's header prints the plan hash, so the
reviewed artifact and the applied one are provably identical. `plan`'s stdout
stays pure IR forever (invariant: one stdout medium per verb; agents never face a
mode switch). The render is presentation only — never parsed for control flow;
the JSON remains the sole machine contract. And a verb whose stdout IS the render
is trivially golden-testable, where an stderr summary would be an unordered log
channel hostile to byte-exact pinning.

**Four-valued discipline, applied to risk.** The six-field Risk vector
(reversibility, dataLoss, downtime, securityExposure, cost, identityReplacement)
prints VERBATIM on every action. There is no composite "danger" score and no
severity adjective (high/medium/low) anywhere — a grep-negative conformance
assertion makes reintroducing one a failing case, not a review debate. R4,
`dataLoss certain` and `identity REPLACED` read for themselves.

**Destructive actions cannot be buried.** Any action that is a delete, a
replacement, or carries dataLoss certain / identityReplacement / R4 gets a
full-width `##` rail around its block (visual mass, not adjectives) AND is listed
again in a destructive-recap footer — it appears in two places, so a 40-action
plan cannot hide a delete. Absence is pinned too: a benign plan has no rail and no
recap (a conformance case asserts their absence).

**Honest cost, honest order.** Cost is summed PER CURRENCY (never coerced across
currencies — invariant #2) and labelled as the sum of DECLARED cost.monthly
deltas: because an unpriced action is indistinguishable from a declared 0 in the
IR, the label says exactly that rather than implying a complete total (no
fabricated PARTIAL/precision — the honest boundary of what the plan carries).
Actions render in DAG execution order (topological, lexicographic tiebreak), so a
permuted Actions[] array yields the same body — order is derived, not input order
(pinned by a permutation case; the plan hash correctly differs, as a permuted file
is a different artifact). The aggregate shows per-axis WORST values — a max per
axis is the vector's silhouette, honest, never a collapse.

**Adjacents, compact.** Witnessed (verified-not-authored, D177) as its own
section; Preconditions one per line; the RequiredPermissions union (exactly what
D75 preflights) in a footer; D226 References inline in the consuming action
(DependsOn itself is not printed — the ordering already encodes it). All in
`internal/planview` as a pure function of the plan bytes; three golden conformance
cases (four-op render, permutation-invariance, benign-absence) + the grep-negative.
The renderer needs no contract, so `show` takes only the plan — but "stateful" and
the specific consent name live in the contract, so the destructive call-out fires
from the plan's OWN signals (operation, Replaces, the risk vector), never inventing
a fact the plan does not carry.
## D229. Background runs + notify — stop babysitting, without a second truth
`apply`/`converge` ran only in the foreground: the operator was chained to the
terminal for the length of a cloud provision. The research #1 "stop babysitting"
mitigation is: run detached, get notified on the terminal verdict. Groundhold is
uniquely suited because the LEDGER is already a durable, resumable truth record —
detaching changes WHO watches, never the guarantees. Design consulted with two
frontier models (Fable's memo adopted; Codex returned empty).

**The one thing we refuse to build: a second status store.** Every answer derives
from ledger events plus an explicit clock. `runstatus.DeriveRunStatus(events,
handle, now)` is one pure function — the design's testable heart — with a closed
state set: `unknown` (no event carries the handle — there is deliberately no
`queued`, the ledger cannot prove a queue), `running` (started, no terminal, lease
TTL live), `stalled` (lease lapsed, nothing pending), `needs-reconcile` (lease
lapsed, a write-ahead receipt unsettled → `resume`), `done`, `failed`. The
four-valued discipline extends to run state: a lapsed writer is NEVER silently
`failed` and NEVER still `running` — the lease TTL is the honest death signal, not
a PID. Pinned by golden state tests × a table of `now` values, and CLI conformance
cases per state.

**status joins the N1 family; wait is its one exemption.** Judging lease-TTL
liveness against a defaulted clock is exactly the stale-freshness lie N1 forbids,
so `status` requires an explicit `--at`. `wait` is the sole verb whose meaning IS
the live clock — it samples now each poll and calls the same derivation, so the
honesty lives in one place. `wait` unblocks on `done`/`failed` AND on
`stalled`/`needs-reconcile`: continuing to wait on a dead writer is a lie. It
relays the run's exit code (D22 codes unchanged).

**detach-after-admission.** `apply --detach` computes the handle BEFORE the fork
(runID = sha256(planHash + "|" + at)[:12] — both inputs known at invocation, and
the handle cryptographically embeds the explicit `--at`, so a handle cannot exist
for a defaulted clock), re-execs itself minus `--detach` in a new session (setsid,
stderr→run log), then blocks up to 5s watching the ledger for the run's `*.started`
event — a fast refusal (preflight, staleness, lease contention) is surfaced to the
launcher, never swallowed into a log the operator has not been told to read. The
`Runner` is a seam: production re-execs; tests inject a synchronous in-process
runner, so admission/registry/handle are hermetic and the fork is one smoke, not a
subject. The registry (`.groundhold/runs/<handle>.json`) is a WRITE-ONCE POINTER
answering exactly one question the ledger cannot — which ledger file the handle
lives in; any ledger-derivable field is forbidden in it (a test enforces this), and
`pid` is listing garnish, never a liveness claim.

**Notify is a doorbell that cannot corrupt the run.** `--notify-url` /
`--notify-cmd` on `wait` (the guaranteed-terminal pattern — a corpse cannot notify
its own stall, so the documented way to be sure is a LIVE watcher: `wait <handle>
--notify-url ...`). It fires AFTER the terminal state is derived and the exit
computed; the `Notifier` holds an immutable payload and has NO ledger handle, so a
slow/broken hook can only log, never write truth. Delivery is best-effort-once (10s
timeout, no retries — a retry queue would be a second store); the payload
(`groundhold/notify/v1`) carries a `lastEventHash` so the ping is evidence
verifiable against `export`/a D103 capsule. Pinned by an httptest golden.

**Shipped:** `runstatus` (pure derivation), `status`/`wait` verbs, `notify`
(url/cmd), `apply --detach` AND `converge --detach`. Converge writes its own
lifecycle events — `converge.started`/`phase.entered`/`finished`/`failed`, a
domain-prefixed `convergeRunId` (embeds --at, cannot collide with an applyRunId),
lease-free and best-effort (a run marker never fails the run), carrying the
contract's caps (the ledger requires non-empty caps; status derives from the body's
convergeRunId, not the caps). `status`/`wait` then speak the converge tree (kind,
phase reached, state). New event types are registered additively in the state
allowlist. Remaining refinement: child applies correlated to their converge by a
`parentRunId` for a single unified tree view.

## D230. Actionable refusals — the exact next step, honestly (`next`)
A refusal carried a machine `code` + verbatim `reasons` + a STATIC remediation
(perr.Explain, "Run `observe --record`"). The static string cannot know THIS
run's contract path, ledger, --at, capability or the exact denied permissions —
but the refusal SITE does. Research: "errors explain what went wrong AND how to
fix it." D230 adds an advisory `next`: the exact command to run, edit to make, or
permission to grant that would unblock this invocation. Design consulted with two
frontier models (convergent).

**Shape.** `next` is a typed struct, an optional sibling of `code`/`reasons`,
discriminated by `kind`: `command` (a runnable groundhold invocation — `argv[]`
plus a `command` display string from one deterministic quoter, `runnable` true
iff no placeholders), `edit` (a contract/candidate change a human must make —
there is nothing to execute, which preserves gates like consent structurally),
`grant` (permissions to grant via the operator's own IAM tooling — never a
fabricated `gcloud`/`aws` command). Every next carries `retry`: the operator's own
invocation verbatim (argv[0] normalized to `groundhold`) — always known, always
correct as "what to run after the fix". It is emitted whenever derivable, NOT
gated behind `--explain` (an agent is a first-class consumer); the static
remediation remains the fallback and the `explain` verb stays static (it has no
invocation context).

**Advisory by construction.** Nothing in the runtime reads a `next`. The type
lives in `internal/perrnext` beside `perr`; engine packages (compiler, apply,
executor) never import it, so a `next` can never change control flow. The machine
`code` stays the contract.

**The honesty rule (omit over guess).** A `command` is emitted iff EVERY argument
the target verb requires is known verbatim — echoed from the operator's own inputs
(relative paths stay relative; `--at` is echoed ONLY when the operator supplied it,
never the epoch default) or from facts the refusal itself established. A
required-but-unknown argument means no command (the static remediation stands); an
optional-unknown flag is omitted, never placeholdered. Values are never
normalized, defaulted or reformatted — rewriting an input is a guess. Placeholders
(`<UPPER>`) are allowed only for arguments the runtime cannot know (operator
identity/choice) and force `runnable:false`. So `argv`, when present, is executable
as-is. This is invariant #1 made mechanical: the only path to a runnable command
is copying what is already true.

**Derivation, DRY.** One builder table keyed by `perr.Code`, colocated with
`perr.Explain` so the sets cannot drift. Invocation-level facts (paths, --at,
provider) are packaged once at the CLI boundary (`perrnext.Invocation`); site-level
facts (the offending capability, the denied permissions, the bad `$ref`) travel as
a typed `Detail`. `NextFor(inv, code, detail)` returns nil when no builder matches
or the builder declines. A completeness test asserts every code in `perr.Explain`
is either a builder or in the explicit `noNext` set — a new code cannot land
undecided. `noNext` names the situational/destructive cases deliberately left
generic (read-set-mismatch: pinned-doc paths unknown; lease-conflict: a break hint
could be destructive; ledger-corrupted: any command may deepen damage; ...).

**The set.** Two of five are runnable commands: `observation-required` ->
`groundhold observe --ledger <l> [--provider <p>] --at <T> --record`;
`reconcile-required` -> `groundhold resume <contract> --ledger <l> [--provider <p>]
--at <T>`. Three are non-commands, honestly: `consent-required` -> an `edit`
adding `autonomy.allow_replace_stateful: [<cap>]` with "do not apply
autonomously" (the consent gate survives); `provider-permission-denied` -> a
`grant` of the exact sorted denied permissions to the acting identity;
`reference-invalid` (D226) -> an `edit` pointing at the bad `$ref` in the
candidate. All three kinds ship: the two command kinds (observe/resume,
invocation-only) plus the edit (consent, reference) and grant
(permission-denied) kinds. The engine surfaces structured facts WITHOUT importing
perrnext: apply's Result carries json:-'d Denied/Capability fields, and the
compiler returns a typed *RefusalError{Capability, RefPointer, Note}; main
type-asserts these and assembles the Detail at the emitter. The consent edit's
unblock is proven by the existing paired replace cases — the same plan refuses
without autonomy.allow_replace_stateful and succeeds with it, which is exactly the
edit the `next` prescribes.

**Tested.** Builder goldens (fixed paths -> exact `Next`), negatives
(missing ledger/provider -> no command), the completeness + no-metacharacter
invariants; a conformance case pins the CLI integration structurally (tempdir
paths vary, so the case asserts kind/runnable/argv-contains, while the byte-exact
argv is pinned at the unit level). The strongest test is the future
refuse -> run `next` -> run `retry` -> code-cleared unblock scenario per runnable
code.

## D231. `runs` — the what-needs-my-attention list, derived from the ledger
D229 gave `status <handle>`/`wait <handle>` — one run at a time. An operator who
detached several runs (or came back after a while) had no way to ask "what do I
have, and what needs me?" `groundhold runs --ledger <l> --at <T>` lists EVERY run
with its derived state. Design consulted with a frontier model on the honesty
subtleties (the mechanism reuses D229).

**The ledger enumerates, not the registry.** The handle set comes from the ledger
events (every `applyRunId`/`convergeRunId` in any body) — the sole run truth
(D229), holding EVERY run, foreground and detached, where the write-once detach
registry holds only detached ones and a deleted registry file must not erase a run
from history. `runs` reuses `runstatus.DeriveRunStatus` per handle unchanged, so
the verdict still derives solely from events + the clock; enumeration only widens
the question set.

**N1, multiplied.** `runs` evaluates the identical lease-TTL liveness predicate as
`status`, N times — a defaulted clock is the stale-freshness lie N1 forbids, not
diluted but multiplied by N. And `runs` is definitionally the verb you invoke
after time has passed ("what happened while I was away"), where a stale clock is
most likely to flip `stalled` back to `running`. So `runs` joins the N1 family:
`--at` is mandatory.

**Ordering + honesty.** Most-recent-first by start clock (the first `*.started`);
ties break by chain index (first-seen in the total-order ledger), then handle — so
golden tests are byte-stable. A run whose `*.started` is not in view (a compacted
or copied tail) reads `unknown`, never `running`/`stalled` — guessing liveness
from a headless stream is the same fabrication N1 kills — and sorts last rather
than being dropped. The per-line note is the state's evidence stub (lease/pending/
phase), never invented.

**No health rollup.** Order stays chronological (re-sorting by severity would be a
covert ranking); attention states read at a glance via the state word, and a
trailing per-state count line ("1 failed, 1 stalled, 4 done") projects the closed
four-valued run-state set — a green/yellow/red aggregate would collapse it, exactly
the four-valued sin. Empty ledger is a true `0 runs` (exit 0), and the machine
output prints every run (no silent cap). Pinned by conformance cases (three runs, order +
per-state counts; and the registry-union below) and ListRuns unit tests.

**Registry union — the launched-but-not-admitted run.** The one condition the
ledger alone cannot surface is a run that was launched (a detach registry pointer
written) but never admitted (it wrote no events — e.g. it died before its first
`*.started`). `runs` reads the detach registry (`detach.ListRegistry`) and unions
any handle with NO ledger events as a `registry-only` run: `unknown`, tagged so,
sorting after every ledger run (it has no start clock). This is the single most
attention-worthy state — a process that may be a corpse — and omitting it is the
lie of silence. The pointer contributes ONLY to the question set: the verdict is
still `DeriveRunStatus([], handle, now) == unknown`, never read from the registry
(which stays non-authoritative, D229). A missing/unreadable registry is not an
error. Every run carries a `source` field (`ledger` | `registry-only`) so the
distinction is machine-visible; pinned by a conformance case and a unit test.

## D232. converge phase checklist — the roadmap, honestly (`converge`)
`converge` (verify -> plan -> [observe if stale] -> forecast -> confirm -> apply
-> observe -> [convergence-check]) printed append-only "-> phase" lines. Research
praised the "persistent plan/todo with checkmarks" pattern; converge has a KNOWN
loop shape, so it can show a live PHASE CHECKLIST. Design consulted with a
frontier model, which changed the initial instinct (reveal-as-entered) to
pre-list-the-full-roadmap — the more honest choice, argued below.

**Pre-list the full canonical loop.** The loop shape is deterministic and known to
the binary; hiding it is false modesty. And `pending` already claims exactly
`unknown` (the D227 semantics), never "will run" — so a pre-listed roadmap is
honest IF two specific lies are foreclosed: (1) an undifferentiated `pending` on a
conditional phase (implies it runs when reached), and (2) a `pending` row left
dangling after an early exit (implies it might still run once the loop is over).
The governing invariant (mirror of D227's): every pre-listed row reaches EXACTLY
ONE terminal state before the region freezes — no row is ever abandoned as
`pending`.

**Conditional phases carry their condition; they resolve, never dangle.** The
stale-refresh observe and the convergence-check pre-list with their condition in
dim text ("observe (refresh — if evidence stale)"). When the condition is
evaluated false, the row resolves to `skipped` with a mandatory why (D227's
skipWhy rule) — e.g. `observe (evidence fresh)` — never a bare pending, never
omitted (hiding a skip hides that staleness was checked and found fine).

**Early exit resolves the rest to skipped(loop ended), never blank or failed.**
When verify refuses, the unreached rows didn't succeed, didn't fail, and will not
run. Leaving them `pending` lies ("might still happen"); marking them `failed`
collapses the four-valued discipline. Each resolves to `skipped (loop ended:
<phase> refused)` — the D227 dep-failed shape (claim: unknown), reused. The
refusing phase itself carries the reason and the error code.

**Phase-state set = D227 minus lease-states, plus one new `refused`.** A phase is
a sub-process with an exit code (no lease, no LRO), so provider-wait/stalled/
blocked-consent don't apply. Closed set: `pending`(·/.) `active`(~) `done`(✓/OK)
`refused`(⊘/REF) `failed`(✗/X) `skipped`(»/SKIP), pinned in internal/render beside
the verdict glyphs. `refused` is genuinely new — D227 actions never refuse (refusal
precedes actions); phases do, and refusal-is-not-failure (D89) means it must NOT
wear `✗`. `done` means only "the sub-step ran and its exit code said proceed" — it
carries NO verdict.

**The trap: a fully-checked list reads as converged.** Eight green ✓ is a progress
bar's idea of success, and it is a lie here — a run can check every box and end
not-converged, or end refused with the refusal being the system working. Foreclosed
structurally: the checklist NEVER renders a loop verdict; the banner (finish) is
the SOLE carrier of converged/refused/failed, and the checklist freezes into
subordinate scrollback BEFORE the banner is emitted once, last (converge already
owns bannerState.done). A test pins that a verify refusal freezes as one `⊘ verify`
+ skipped rows + a refusal banner.

**Channel + two-observe.** stderr only; stdout stays machine; disabled in JSON
mode. On a TTY it is a sticky repainted region; off a TTY (plain/CI) it prints
append-only transition lines during the run and the full final roadmap once at
freeze (so the log carries the complete picture). observe appears twice, as two
rows named by ROLE (refresh / evidence) so a row never completes twice; the ledger
phase name stays "observe" for both (D229 stability). Pinned by checklist unit
goldens (pre-list, progression, conditional skip, early-exit resolution,
refused!=failed, no-verdict) and the render phase-glyph table test.

## D233. Machine-readable error registry — `explain --json`, so consumers can show the fix
A refusal carries a machine `code` (D64) and, at the site, an advisory `next`
(D230). But a downstream projection — the console — receives only the `code`
(e.g. a verify report's `code: not-executable`), not the remediation: it names
the problem without the fix. `explain <code>` prints the remediation as TEXT for
a human; there was no machine form for a consumer to project verbatim.

`explain --json` (no term) dumps the whole error registry — `{apiVersion:
"errors/v0", codes: [{code, summary, remediation}]}` — from the single source
(`perr.Explain`, via `perr.Registry()`, sorted, deterministic). `explain <code>
--json` emits one entry. The text form is unchanged (a human still gets the
`next:` line). A unit test pins that the registry is exactly `Explain` (a new
code appears automatically), so the machine glossary cannot drift from what
`explain` teaches.

This closes the console's grounding gap (item 35, one glossary, no drift): a
blocked/violated/refused figure carrying a `code` can now show HOW to fix it,
projected verbatim from proviso — the same discipline as the vocabulary glossary
(spec/vocab → /api/vocab). The invocation-specific `next` (exact command with the
operator's paths) stays a CLI-side affordance — a projection cannot know the
operator's invocation — so the console projects the STATIC per-code remediation,
which is exactly what `explain <code>` answers. That is the honest boundary, not
a compromise.

## D234. Response-fixture replay harness — catching API drift, honestly (API-drift #1)
Provider drivers parse cloud responses into semantic observations. Every driver
test hand-writes the fake response inline (httptest) — which matches the driver's
OWN assumption, so it CANNOT catch API drift: when the real provider response
shape changes (field renamed/retyped/omitted, enum member added), the driver
silently misreads it and the tests stay green. Motivating incident: a GCS Owner
identity was reported as lacking storage.buckets.get — a semantic misread of a
well-formed response. Design consulted with two frontier models (convergent).

**Capture produces evidence; replay enforces it.** Two acts, split by where creds
live. CAPTURE runs only where real creds exist (the canary, GCP first, AWS sandbox
later): it records the provider's verbatim response (via a RoundTripper on the
driver's own client, so the captured request is what the driver actually sends),
scrubs account-specifics, computes the shape signature, and opens a PR with the
diff — never pushes. REPLAY runs everywhere (`make check`, no creds, no network):
`internal/fixture` serves the recorded bytes from a fail-closed httptest handler
and runs the REAL driver parser against them through the existing `BaseURL` seam,
asserting the exact expected observations (the SEMANTIC, not just "did not crash").

**Two honesty rules make it real, not theatre.** (1) Provenance is a mandatory
enum, machine-checked: only `live` (carrying a canary `capturedBy` run id) is
drift EVIDENCE; a `handwritten-pending-canary` fixture may exercise the harness
and catch DRIVER drift against a doc-realistic shape, but the label — enforced by
`TestFixtureProvenance`, not convention — says it is not yet provider-verified. A
`live` claim without a capture source fails Load. (2) The shape signature — a
sorted field-path → JSON-kind skeleton, values erased, arrays folded to their
element-union, hashed — is committed and recomputed on Load (a committed hash
disagreeing with the raw bytes is a corrupt fixture, caught before the driver
runs). It turns a re-record from a silent rubber-stamp into a classified,
reviewable event: value churn (new etag/timestamp) leaves the hash unchanged; a
structural change moves it, and the canary PR renders the field-by-field diff.

**Two drift directions, both surfaced.** (1) Driver drifts: a parser change that
misreads the recorded real response fails replay offline, no creds. (2) Provider
drifts: the canary re-records, the shapeHash diff is reviewable, and CI replays
the NEW fixture against the current parser — the incident surfaces with the field
named, before production. Unknown enum members route to `unknown` (never a
fabricated success), pinned by a fixture whose Expected says so.

**First slice (honest, given no live creds in-session).** `internal/fixture`
(Fixture struct, Load with the corruption + provenance + mandatory-Expected
guards, ShapeOf, Serve fail-closed, AssertExpected) + one GCS buckets.get fixture
marked `handwritten-pending-canary` (body from GCP's published storage/v1 shape,
labeled as such) + a replay test driving the REAL observeGCS against it (asserts
the 6 observations incl. `network.publicExposure` — the incident's surface). It
catches driver drift TODAY; it is NOT yet provider-verified — the acceptance
criterion for that is the canary flipping the fixture to `provenance:live` on its
next run. Deferred (honest, flagged): the canary capture step + PR automation,
AWS sandbox capture, Azure (code-path only), XML shape signatures, fan-out to the
other ~120 services (mechanical once the pattern is pinned).

## D235. Fixture capture in the canary — flipping pending fixtures to live (API-drift #2)
D234 shipped the replay harness + a `handwritten-pending-canary` GCS fixture; the
acceptance criterion for provider-verified drift coverage is a LIVE capture. D235
builds the capture half and wires it into the canary — the ONLY place real creds
exist. Deliberately NOT run on a dev host: this session's host carries only client
PROD aws profiles and no sandbox — exactly the "stray creds"
hazard the capture-is-canary-only rule exists to foreclose. So capture ran nowhere
in this session; the canary flips the fixture on its next run.

**The recorder wraps the driver's own transport.** `fixture.NewRecorder(under)`
is an http.RoundTripper that records each exchange (request method/path/query +
verbatim response bytes) while delegating to the real transport and teeing the
body back — so the captured request is exactly what the driver sends, not a
hand-approximation. Inject it as the driver's `HTTP` client; the driver's real
observe/reconcile flows through it. `BuildFixture` assembles a `provenance: live`
fixture from the recorded exchange + the parser's observations (the expected
block, flagged for human review in the PR — review breaks the circularity), scrubs
account-specifics through an explicit redaction map (recorded in `scrubbed` for
audit), and computes the shape signature. Load's guards then apply: a live fixture
without `capturedBy` is refused.

**Canary-only, PR-only.** A `//go:build capture` entrypoint
(`internal/gcp/gcs_capture_test.go`) is excluded from the `make check` gate and
runs only under `-tags capture` in canary-gcp.yml, with the WIF token +
CANARY_FIXTURE_BUCKET. It overwrites the pending fixture with the live capture;
the canary uploads the changed fixture as an artifact for a REVIEW PR — never
pushes. A provider shape change then surfaces as the shapeHash diff in that PR,
and CI replays the new fixture against the current parser: the incident surfaces,
field-named, before production.

**Tested offline (no creds).** The recorder + BuildFixture are unit-tested against
an httptest upstream: the recorder captures the exact exchange, BuildFixture
scrubs + stamps live provenance + computes the shape, and the result Load-round-
trips cleanly. Deferred: AWS sandbox capture (needs the user's own sandbox creds,
absent here), Azure (code-path only), auto-opening the review PR from the canary.

## D236. API-version pin registry + drift detector (API-drift #3)
D234/D235 catch a shape change WITHIN a targeted API version; D236 catches the
version itself going stale. Every driver targets a specific provider API version,
embedded three ways: AWS a dated `Version` form param ("2016-11-15"), GCP a
version path segment ("compute/v1"), Azure an `api-version` query param
("2024-05-01"[-preview]). The drift risk is silent — the provider supersedes or
deprecates a version, the driver keeps the old one, we learn via a live incident.
#3 pins the version each driver targets and SURFACES a newer/deprecated one; it
never silently follows.

**The registry is true by construction, then fenced.** `internal/apiver` is one
enumerated Go table (77 pins: 9 AWS, 30 GCP, 38 Azure), seeded from a census of
the driver source. `consistency_test.go` (go/parser, so comments never count)
enforces both directions: registry ⊆ code — every pinned version is a literal the
driver actually embeds, so a pin cannot lie about a version we do not use — and
code ⊆ registry ∪ allowlist — every version-shaped literal in the driver source is
a registered pin, the anti-scatter tripwire that fails the build on a new
un-registered version. The one allowlisted dated literal is IAM's policy-LANGUAGE
version `2012-10-17` (not an API version, embedded in JSON policy docs); the three
inline IAM `2010-05-08` sites were folded into the existing `iamVersion` const so
the tripwire allowlist stays a single named exception.

**The drift detector is a pure comparator; AWS is structurally barred from green.**
`Compare(pin, *LiveVersions) → {pinned-current | newer-available | deprecated |
cannot-verify}` has no network and no write path back to the registry. GCP/Azure
carry preferred/deprecated flags (Discovery / ARM), so the full domain is
reachable; a preview/beta never supersedes a stable pin. AWS exposes no
authoritative current-version endpoint, so a matching SDK model is evidence, not
proof — the AWS domain is exactly {newer-available, cannot-verify}, PinnedCurrent
is unreachable for AWS by construction (a unit vector pins that an exact match
still yields cannot-verify). No live signal → cannot-verify, never a green guess
— the four-valued verifier's fail-closed spine.

**Surface, never follow.** `groundhold apiver` prints the offline catalog (live
state honestly cannot-verify without a snapshot); `groundhold apiver --live
<snapshot>` compares against a canary-fetched version list and exits 2 on
actionable drift (newer-available/deprecated) so CI can gate — cannot-verify never
fails. The detector reports; a human reads `source`, decides, bumps the pin, and
regenerates the golden fixtures (which fail until regenerated, proving the bump
reached the wire). Deferred (canary-only, no live creds on a dev host, exactly the
D235 discipline): the per-provider live fetchers — GCP Discovery (cleanest signal,
`preferred` flag), AWS SDK-model prober, Azure ARM providers — and the
transition-diffed PR that surfaces a verdict change without re-alert spam.

## D237. Structured provider errors — the wire never gets a verdict (API-drift #4)
Every driver classified provider HTTP errors ad-hoc, with a copy-pasted ladder
that already got 5xx and transport errors right (unknown, may-have-landed) but
lumped 429 (throttle), 503 (again-later) and 403 (permission) into a TERMINAL
`failed`. That is a never-fabricate violation: a rate-limit or a live 403 is a
statement about the CHANNEL, not the RESOURCE. The ruling principle: only the
provider saying "I understood you and the answer is no" — a clean 4xx refusal —
may produce a terminal `failed`; everything else the wire can say maps to
`unknown` with the providerId preserved, so a retry or reconcile can still land or
observe the resource.

**One shared classifier.** `internal/provider/errorclass.go` is a pure function
over `(httpStatus, normalized-code, transportErr)` returning a closed
`ErrorClass`: `Transient` (429/408 + the throttle/rate-limit code family — the
mutation did not land, safe to retry), `Ambiguous` (transport, 5xx, timeout/
internal codes — may have landed, reconcile), `Denied` (401/403 + the auth code
family), `Terminal` (any other 4xx). Transient/Ambiguous/Denied all map to
`unknown`; only Terminal fails. Per-cloud adapters extract the code (AWS nested
XML `<Code>`, GCP `error.status`/`errors[].reason`, Azure `error.code`) and hand
it to the shared status+code table — the throttle/auth/ambiguous vocabularies live
in one auditable place. The fail-closed default for any unrecognized non-2xx is
Ambiguous, never Terminal: an unknown new provider code is classified too
pessimistically (unknown), never too optimistically (a fabricated failed). A 3xx
is the one deterministic exception — a wrong-host redirect a retry cannot fix —
so it is Terminal.

**403 at mutation time is unknown, not failed, and not provider-permission-denied.**
IAM is eventually consistent, so a live 403 can be stale, and it can arrive after
a prior step of a compound mutation already landed — calling it `failed` would
fabricate "nothing landed" and orphan the resource (the D62 phantom class).
`provider-permission-denied` stays reserved for an AUTHORITATIVE preflight (D75); a
live 403 is not authoritative. The `Denied` class still earns its slot: the
receipt reason says "permission denied" so the operator checks IAM rather than
waits out a throttle. Codex and Fable converged on this independently.

**One new code, one new receipt distinction.** `provider-again-later` (perr +
spec/errors.md) is emitted only when the sole obstacle was a pure throttle
(`CreateResult.Retryable`, set by the classifier for `ClassTransient`): the
mutation provably did not execute, so the remediation is "wait and re-run the same
verb", not "reconcile". Every other unknown (5xx/transport/live-403) stays
`reconcile-required` — it may have landed. apply routes on `Retryable`; the
receipt stays pending either way (unknown never claims success).

**The harness locks it; the migration is incremental.** `certifynet` gains
`Fault429`/`Fault503`/`Fault403` on mutation roles, asserting `unknown` (never
failed/succeeded) with the providerId preserved — the Fault403 assertion pins the
403 decision so it cannot be "fixed" back to failed. The faults are gated per
driver by `Probe.AssertTransient`: a driver whose create/delete/claim ladders
route through `provider.MutationResult` sets it true and is locked; an un-migrated
driver leaves it false and is a tracked TODO, never a silent claim of coverage
(89 driver harnesses, 218 mutation sites — a genuine multi-PR migration). This PR
migrates 13 flagship drivers across all three clouds (AWS s3/rds; GCP gcs/cloudrun/
cloudfunctions/pubsub/pubsub-queue/vpc via the shared `mutationResult`
choke-point; Azure blob/flexpostgres/vnet/servicebusqueue/containerapps via the
`putAndPoll`/`deleteAndConfirm`/`terminalOr` choke-points) and upgrades those
shared helpers, which also improves create/delete honesty for the ~30 further
GCP/Azure drivers that call them even before their harness flag flips. Deferred
(harness-guarded, flip `AssertTransient` as migrated): the remaining inline
mutation ladders; Observe staying a hard Go error on a transient read (a read
fabricates nothing by failing loudly — a four-valued Observe is a separate D44
spec change); converge backoff-and-retry on `provider-again-later` (the code is
emitted; the loop routing is the next slice).

## D238. Effective org-policy PAP for GCS publicExposure (API-drift #5)
`observeGCS` reverse-maps `network.publicExposure`: PAP=="enforced" → private;
otherwise (inherited + UBLA on) an allUsers/allAuthenticatedUsers read binding →
public. But `buckets.get` returns the bucket's OWN PAP, not an org policy that
ENFORCES `constraints/storage.publicAccessPrevention` above it — so a bucket with
PAP="inherited" plus a stale allUsers binding read as public even when an org
constraint made it definitively private. A false positive (over-reporting exposure
on a privacy constraint — the safe direction, but imprecise; this was a documented
residual since D81). AWS and Azure were assumed effective-correct; a consult found
that only Azure fully is (`allowBlobPublicAccess` is the account-level enforcement
point). Both Codex and Fable independently confirmed the API and the honesty model.

**The fix — positive-evidence-only downgrade.** When PAP=="inherited" and the IAM
story would otherwise read public, `observeGCS` queries the effective org policy
(`internal/gcp/orgpolicy_net.go`: Org Policy **v2** `GET
.../v2/projects/{project}/policies/storage.publicAccessPrevention:getEffectivePolicy`,
the SHORT constraint name in the path — not the `constraints/` prefix, which is the
legacy v1 body convention) and parses `spec.rules[].enforce`. publicExposure is
downgraded to `false` (measured) ONLY on a literal `enforce:true`; `dryRunSpec` is
never read (a simulation is not enforcement). Every other outcome — `enforce:false`,
empty/absent spec, a 403 (`PERMISSION_DENIED`/`SERVICE_DISABLED`), a 404 (which
`getEffectivePolicy`, unlike `getPolicy`, never returns for a real constraint, so
it signals a malformed request), a 5xx, or unparseable JSON — keeps the
conservative `public=true` + a diagnostic. Never-fabricate: a false negative
(claiming private when public) is the catastrophic direction, so `false` has
exactly two producers (bucket PAP=enforced; org `enforce:true`) and every
ambiguity path is hard-wired to keep `true`.

**Lazy + a rescue branch.** The org read fires only after the bucket IAM story
comes back public (verdict-invariant otherwise — zero extra calls on the common
private bucket) OR as a rescue when the bucket IAM policy itself is unreadable (a
positively enforced org PAP is then still definitive private — an honesty gain
over emitting nothing). A downgrade also warns that the masked allUsers binding is
a latent hazard that would expose the bucket the day the org policy is lifted.

**Honest boundary.** GCP-only: AWS/Azure need no symmetry patch for this exact
drift (Azure reads the account-level gate directly; the AWS residual is the same
class in the same safe direction — tracked below). Offline-complete: the httptest
tests pin every branch (downgrade+mask-diag; not-enforced across enforce:false /
empty-spec / no-spec; unreadable across 403/404/500/503 + diag; lazy no-call on a
private bucket; the unreadable-IAM rescue). Live validation on a real GCP project is
canary-deferred (no live creds on a dev host; the strict parser degrades any live
wire deviation to the conservative row, so deferral costs precision, never safety).
Follow-ups, both flagged not silently skipped: (1) the AWS twin — `s3_net.go`'s
`GetBucketPolicyStatus.IsPublic` is documented over-broadly as "AWS's own EFFECTIVE
verdict"; it does not fold in account-level Block Public Access, so a public
bucket policy under `RestrictPublicBuckets=true` can still read `IsPublic=true`
(same residual, same safe direction). The comment is corrected now; the fix
(downgrade only on positive `GetPublicAccessBlock` evidence, identical honesty
table) is the twin PR. (2) per-project memoization of the effective policy across a
multi-bucket observe run — skipped to keep the driver stateless; each `observeGCS`
makes at most one org read, only for an IAM-public bucket.

## D239. Structured-errors sweep complete — all drivers on provider.MutationResult (D237 follow-up)
D237 shipped the shared classifier + harness faults gated per driver by
Probe.AssertTransient, migrating 13 flagship drivers and leaving the rest a
tracked, harness-guarded TODO (89 harnesses / ~218 mutation sites). D239 completes
that migration: every remaining driver's create/delete/claim/update mutation
ladder now routes its terminal branch through provider.MutationResult, so a
throttle (429), service-unavailable (503), server error (5xx), transport error, or
LIVE 403 returns unknown+pid instead of a terminal failed; only a clean 4xx refusal
fails. All 69 certifynet probes across aws/gcp/azure now carry AssertTransient, and
the Fault429/Fault503/Fault403 assertions pass for every one.

Executed as a three-agent workflow (one per cloud — disjoint Go packages, so
parallel in-place edits never raced), each converting its cloud's drivers and
iterating against `go test ./internal/<cloud>/... -run Honesty` until green, then
gofmt + vet. 123 MutationResult insertions across 55 driver files (24 AWS, 19 GCP,
12 Azure). The insertion is surgical — placed before each existing terminal failed
return, and MutationResult returns nil for a clean 4xx, so every deliberate
terminal refusal (tag/ownership mismatch, DependencyViolation, DistributionNotDisabled,
ResourceInUse, deletion-protection, a WORM-locked container, a non-empty bucket)
keeps its exact reason text unchanged. providerId is preserved at every knowable
site (deterministic-name creates, post-id config sub-steps, all delete/update);
"" only where the id is genuinely server-assigned and not yet known (VPC/Route53/
EFS/ACM/CloudFront/ApiGWv2/KMS pre-id create), which is the honest, harness-expected
value there. GCP's shared `mutationResult` and Azure's `putAndPoll`/
`deleteAndConfirm`/`terminalOr` choke-points (already converted in D237) covered
most create paths; the sweep's work was the inline delete ladders and per-driver
config sub-steps. make check 429/429 both implementations, differential 200/0.
Remaining D237 follow-ups unchanged: the AWS account-BPA effective-public twin,
converge backoff on provider-again-later, and a four-valued Observe (D44).

## D240. AWS effective Block Public Access for S3 publicExposure (D238 twin)
The GCS effective-org-policy fix (D238) flagged an AWS residual of the same class:
`observeS3` mapped `network.publicExposure` from `GetBucketPolicyStatus.IsPublic`,
which is a static verdict on the BUCKET POLICY document alone — it folds in Block
Public Access at NEITHER the bucket nor the account level (confirmed against the
S3 Control service model; the console shows this split as a "Public" policy badge
beside a "not public" access column). So a public bucket policy under an effective
`RestrictPublicBuckets=true` read `IsPublic=true` though it is effectively private
— the same over-reporting false positive GCS had (safe direction, imprecise). Both
Codex and Fable confirmed the semantics; Fable pinned the wire details.

**The fix — mirror D238.** `internal/aws/bpa_net.go`: when `IsPublic=true`,
`observeS3` resolves the EFFECTIVE `RestrictPublicBuckets` and downgrades
publicExposure to `false` (measured) ONLY on positive enforcement evidence.
Effective = bucket-level OR account-level (the most-restrictive combination AWS
applies): `bucketRPB` reads `GET /?publicAccessBlock` (s3:GetBucketPublicAccessBlock)
and short-circuits on true; else `accountRPB` reads
`GET /v20180820/configuration/publicAccessBlock` on `s3-control.{region}.amazonaws.com`
with an `x-amz-account-id` header (s3:GetAccountPublicAccessBlock). The one trap:
the endpoint prefix is `s3-control` but SigV4 signs it under service name **`s3`**
(the service model's signingName) — signing as `s3-control` yields a 403 that
masquerades as permission-denied. `RestrictPublicBuckets` (not `BlockPublicPolicy`,
which is prophylactic) is the flag that neutralizes an existing public policy.

**Honesty, identical to D238.** Downgrade only on a positively-read `true`; a 404
carrying `NoSuchPublicAccessBlockConfiguration` is a DEFINITIVE readable "not set"
(matched on the error code, never a bare 404 — a `NoSuchBucket`/wrong-account 404
stays unreadable); any needed read that is unreadable with no positive evidence
keeps the conservative `public=true` + a diagnostic (never a fabricated private —
the false negative is the catastrophic direction). Lazy: the two reads fire only
when the policy already reads public (zero BPA calls on a private bucket). The
account id comes from the acting identity (cached STS); a cross-account bucket
makes the account read unreadable → conservative + a diagnostic naming the cause.

**Offline-complete; live sandbox-deferred.** httptest fixtures pin every row:
bucket-restricted short-circuit (account endpoint asserted never hit), account-
restricted downgrade, both-not-set stays public (no unreadable diag), omitted
element = false, bucket-403 / account-500 unreadable stays conservative + diag,
and lazy no-call when the policy is private. Live validation on the AWS sandbox is
deferred (no creds on a dev host, D235 discipline); the strict code-matched parser
degrades any live deviation to the conservative row — deferral costs precision,
never safety. The first live-sandbox check is one raw account-PAB GET asserting a
200 (pins the `s3` signing name). Remaining D237/D238 follow-ups: converge backoff
on provider-again-later, four-valued Observe (D44).

## D241. converge backs off on provider-again-later; a throttle is a retryable receipt
D237 made apply emit `provider-again-later` for a throttled mutation (a Retryable
unknown — the mutation provably did not land) but the code was only half-actionable:
converge routed it like any failure, and the throttle still left a write-ahead
`unknown` receipt that KEEPS the capability pending, so any re-apply refused with
`reconcile-required`. D241 closes both halves.

**A throttle concludes the intent, it does not leave it pending.** A pure rate-limit
is authoritative "did not execute" (rejected at the door), unlike a 5xx/transport/
live-403 which may have landed. So apply, for `cr.Retryable`, writes the terminal
receipt with a new status **`retryable`** that CLEARS the pending set (like
succeeded/failed), and drops the `targetProviderId` (no resource exists). The status
is added to the ledger's `receiptStatuses` + its pending-clearing case, the Python
scenario engine's `RECEIPT_STATUSES` + clearing (kept in lockstep — D25), the state
schema enum, and spec/state-model.md. Conformance pins it: `apply-throttled-is-
retryable-not-reconcile` (retryableKeys → code provider-again-later, exit 4), the
sibling of `apply-unknown-outcome-is-not-failure` (which keeps pending). A Go apply
test proves the divergence directly: after a throttle the next apply is NOT blocked
by the pending gate (it reaches the stale-decision gate instead — because the
retryable receipt moved the head, which is *why* converge re-plans, next).

**converge backs off and re-plans.** The apply phase is now a bounded loop: on
`provider-again-later` it waits (injectable `Sleep`; bounded exponential, base 1s
capped 30s, `MaxApplyRetries` default 4), RE-PLANS (the retryable receipt moved the
capability's decision head, so the sealed plan is stale — a plain re-apply of the
old plan would fail stale-decision, confirmed by the apply test), and re-applies.
A persistent throttle surfaces `provider-again-later` after the bound rather than
looping forever; a re-plan that comes back `nothing-to-change` reports converged.
Two converge tests pin it: throttle-then-success converges (exactly one backoff,
one re-plan) and a persistent throttle is bounded (surfaces exit 4 after
MaxApplyRetries). Deferred: honoring the provider's `Retry-After` (apply does not
yet carry the hint — the backoff is blind exponential); the last D237/D238 follow-up
is a four-valued Observe (D44), left as its own spec change.

## D242. Four-valued Observe — a capability's read failure is isolated, never fatal (D44 follow-up)
The last D237/D238 follow-up. `observe.Run` aborted the ENTIRE run on the first
capability whose `Observe` returned a Go error — a transient primary read (a 429/
503/5xx or transport drop on `buckets.get`/`describeDB`/...) discarded the
already-gathered observations of every OTHER capability. That is the observe-side
twin of collapsing `unknown`: a read of capability X is evidence about X only, so
X's transient blip must not erase Y and Z. (A per-ATTRIBUTE unreadable sub-read was
already handled — a diagnostic + omission → verify unknown; only the whole-run abort
on a primary read was the gap.)

**Per-capability isolation (c-simple).** A capability whose primary read fails is
now recorded as `unreadable` (capability + free-text reason) with a diagnostic, and
the loop CONTINUES; it yields no observations, so verify resolves it to `unknown`
and the staleness gate refuses `observation-required` — the same fail-closed path a
never-observed attribute takes. The result gains `partial: true` + `unreadable[]`;
observe stays **exit 0** (a read verb that reported reality, including the part it
could not read). A distinct non-zero exit was rejected: it would push every caller
(converge, CI) to treat partial as failure and abort — recreating the abort bug one
layer up. Even all-capabilities-unreadable is exit-0-empty-partial; uniformity beats
a special case, and the downstream gate does not care whether the gap is 1/N or N/N.

**One sharp boundary: reads isolate, ledger writes abort.** A failed provider read
is missing evidence (a truth about the world); a failed ledger append is a broken
recording apparatus (a truth about the run) — the latter stays fatal. And a read
failure is never an `observation.recorded`: no `observation.failed` event, per D59
("probe.failed is never an observation") — failure lives in the result +
stderr, and absence + TTL is the mechanism verify already honors. No fabrication
surface is added because no new writing is.

**Deliberately NOT done.** The driver `Observe` signature is untouched — no
`ObserveResult`/class typing across ~90 drivers. `provider.Classify` (D237) exists
for MUTATIONS, where class drives machine behavior (Retryable/resume/receipts);
observe has no consumer that routes on transient-vs-structural, so threading it
through would be churn cosplaying as rigor. The escape hatch, if a consumer ever
appears (e.g. converge auto-retrying transient-only observe gaps): a typed
`provider.ObserveError` detected with `errors.As` at the run boundary — zero
signature churn, incremental adoption. observe is Go-only (D24), so this is a Go +
impl:go-conformance change; verify needed ZERO changes — the tell that this was a
plumbing bug, not a semantics gap. Cases: `observe-partial-continues-on-unreadable-
capability`, `observe-all-unreadable-is-empty-partial-not-error` (a `unreadable:<reason>`
sentinel providerID injects the read failure via the fake); no-fabrication-on-record
follows by construction (a failed cap yields zero docs, and recording is gated on
docs>0). spec/state-model.md carries the semantic + the TTL-masking caveat.

## D243. converge honors the provider's Retry-After on a throttle
D241 made converge back off and re-plan on `provider-again-later`, but the delay
was a blind bounded exponential — it ignored the provider's own `Retry-After`
hint. D243 threads that hint end to end so converge waits exactly as long as the
provider asked (capped), instead of guessing.

**The hint travels driver → CreateResult → apply result → converge.** `provider.
ParseRetryAfter` (pure, injected clock) parses a Retry-After value — delta-seconds
or an HTTP-date — into whole seconds (0 = no hint / past date). `CreateResult`
gains `RetryAfterSeconds`; `MutationResult` takes it as an OPTIONAL VARIADIC arg,
so the ~123 existing call sites compile unchanged and a driver opts a throttle
path in per site (one line: `provider.RetryAfterFrom(resp.Header, d.Now())`) — the
same incremental-adoption shape as the D239 sweep. The hint is carried only for a
pure throttle (ClassTransient); an ambiguous 5xx never carries it (that path
reconciles, it does not retry). apply propagates `cr.RetryAfterSeconds` into its
result JSON (`retryAfterSeconds`) when it emits `provider-again-later`.

**converge honors it, capped.** `backoffFor(attempt, retryAfterSeconds)` uses the
hint when present — clamped to `MaxBackoff` so a hostile or absurd value cannot
stall a converge unbounded — and falls back to the blind exponential when absent;
the say line and the `converge.apply.backoff` ledger event record which path ran
(`retryAfterHonored`). Fully proven end to end with the fake provider (a real
provider by the harness's lights): a `retryAfterSeconds:7` throttle sleeps exactly
7s then converges; a `99999` hint is capped to the 5s `MaxBackoff`. Tests:
ParseRetryAfter table (delta/HTTP-date/empty/past/negative), MutationResult carries
it only for a transient, apply propagates it, converge honors + caps it. Deferred
(incremental, honest): real-driver header capture — a driver passes the parsed hint
as its HTTP helper surfaces response headers; until then it degrades to the D241
exponential, never wrong. This closes the last D237/D241 throttle-handling
loose end.

## D244. Azure backup.vault — the domain's third cloud, full 3-cloud parity
`capability.backup.vault` shipped AWS + GCP in D127; Azure was the pending third
cloud (parity showed `azure: unbuilt`). D244 adds the Azure driver
(`Microsoft.DataProtection/backupVaults` — the parent of the DataProtection backup
policies the existing `backuppolicy` driver already speaks), completing the domain
to full 3-cloud parity per the agnostic-symmetric discipline. Azure is code+tests
only (no Azure creds on this host), flagged not-live, exactly like the other Azure
drivers.

**Azure is the MOST capable of the three — stated, not smoothed.** The honest
per-cloud story the vocab now records on 3 clouds:
- `retention.lockMode`: Azure honors BOTH `governance` and `compliance`
  (`immutabilitySettings.state` = Unlocked vs Locked) — where GCP REFUSES governance
  (its enforced retention is immutable by construction). The metamorphic test proves
  governance survives the write→read round trip (Unlocked → observed `governance`),
  the parity win no other cloud has.
- `encryption.customerManagedKeys`: a real vault-level capability on Azure
  (`encryptionSettings` + a system-assigned identity that reads the key, via
  `implementation.key_vault_key_uri`) — where GCP refuses it (Google-managed only).
- `retention.minimum` is OPTIONAL (soft-delete `retentionDurationInDays`), like AWS
  and unlike GCP which requires it. `storageSettings` (redundancy + datastore) is a
  required Azure operand, not a capability attribute — an honest default
  (LocallyRedundant/VaultStore), overridable via `implementation.storage_redundancy`.

**The stateful delete guard (D47) has teeth.** A compliance-`Locked` vault refuses
deletion outright (recovery points are data; the lock must elapse, never forced); a
still-populated vault's 4xx is surfaced as the honest stateful reason, not the raw
provider error. The full battery: builder goldens + six refusals, create/observe/
delete httptest shell, foreign-tag delete refused, the D47 locked-delete refusal,
the governance/compliance metamorphic round-trip, and the certifynet honesty probe
(D237 429/503/403 → unknown). Wired through every azure dispatch site (validate/
create/observe/delete + azureServices), reconcile (`reconcileStdARM`), discover,
claim (tag-bearing), parity (`spec/parity.yaml` regenerated — backup.vault now
`fulfilled` on all three), and PermissionsFor (D75). make check 432/432 both
implementations, differential 200/0.

## D245. Parity honesty: the three deliberate two-cloud refusals are structural gaps, not "unbuilt"
The parity matrix distinguishes a STRUCTURAL GAP (the cloud has no
capability-shaped service — a fact about the cloud, a closed decision) from
UNBUILT (groundhold has no driver yet — a fact about groundhold, a roadmap item).
Three cells were mislabeled: `apigateway.http/gcp`, `cdn.distribution/gcp` and
`certificate.tls/azure` are DELIBERATE two-cloud-honest refusals (D119/D118/D117 —
each vocab says the third cloud is "REFUSED by fail-closed dispatch, never faked"),
yet `structuralGaps` (internal/parity/gaps.go) only declared the two email cases,
so the derived matrix showed these three as `unbuilt`. That reads as "a driver is
pending" when the decision is closed — the exact class of lie the gap/unbuilt split
exists to prevent.

D245 declares the three as `not-capability-shaped` structural gaps with reasons
quoted from their vocabularies (GCP API Gateway is an api+apiConfig+gateway chain
requiring an opaque OpenAPI doc, not one managed-gateway resource; GCP Cloud CDN is
`enableCdn` on an L7 load-balancer backend, not a standalone distribution; Azure has
no management-plane managed-TLS-cert twin — Key Vault certs are data-plane, App
Service certs are plan-coupled). `spec/parity.yaml` is regenerated; the matrix now
tells the truth — the capability surface is complete but for these three closed
decisions, with NO phantom "unbuilt" roadmap items. TestParityMatrix proves each
new gap is real (no token fulfils it) and its class is in the closed set; make check
432/432, differential 200/0. No driver was built and no decision re-litigated — the
guardrail (do not build against a closed refusal; align the matrix to it) working as
intended.

## D246. Live-integration canary, AWS + Azure siblings (twin of D79)
D79 gave GCP a scheduled watchdog for provider-side drift that unit/golden/
httptest suites structurally cannot see (a moved verb, a new server-side default,
a narrowed permission surface). D246 extends it to the other two clouds — siblings,
not copies: each pins the drift its own provider actually exhibits, and each states
its honest boundary.

**AWS** (`scripts/canary-aws.sh`, `.github/workflows/canary-aws.yml`) is a full
twin: control probe, real S3+SQS converge loops (fast) / RDS with pinned class+
engine (daily), tag-gated self-cleaning sweep, and raw `aws`-CLI drift assertions.
The assertions encode two AWS-specific facts: (A) `simulate-principal-policy` must
still attest a permission we PROVABLY hold — with mandatory live-pairing, because
simulate alone is an approximation (it cannot see SCPs/resource policies), so a
bare deny is flake, not drift; guards the AWS Preflighter's "denied" mapping. (A2)
account Block Public Access must be either a well-formed four-boolean config or the
DISTINCT `NoSuchPublicAccessBlockConfiguration` error — never a silent
200-with-defaults; guards the D240 effective-public downgrade. Honest boundary: the
s3control SigV4 service-name fix (sign as "s3", not "s3-control") CANNOT be raw-
asserted — the `aws` CLI signs correctly and would mask our signer — so it can only
surface through the loop (exit 20); and AWS is barred from pinned-current API
versions, so there is deliberately no version canary.

**Azure** (`scripts/canary-azure.sh`, `.github/workflows/canary-azure.yml`) is
WATCH-ONLY, and says so: the executor's `apply` path is not yet wired for Azure
(it accepts fake|gcp|aws|k8s), so a converge loop would be a fabrication. Instead
it watches the one Azure drift that needs no execution and hurts most — API-VERSION
RETIREMENT: each pinned `*APIVersion` const (storage, servicebus/flexpostgres
`-preview`, dataprotection, defender) is GET-probed at the subscription scope and
goes red the day Azure stops serving it (bump the const, re-pin fixtures). Two
optional, fixture-gated assertions: compliance-lock still enforced (a PATCH
Locked→Unlocked must be rejected — a probe of enforcement, not a mutation) and
Defender `pricingTier` shape (guards the readable-only misread fix). Read-only
(Reader role), owns nothing. Honest boundary: the async `putAndPoll` poller cannot
be raw-asserted (`az` runs its own poller); the exit-20 class is reserved for the
converge loop to add when Azure `apply` is wired.

Both auth via OIDC only (AWS role assumption, Azure federated login — no long-lived
key/secret), guarded to the owner repo, inert until a maintainer provisions the
throwaway account + variables (checklists in docs/canary.md). All three canaries
share the exit taxonomy (0/10/20/30) and the A/B/C direction discipline (a
"stopped attesting / became unreadable" direction is red; a "started attesting"
direction is a promote-available notice, not red; a moved verb/route/shape is red).
No runtime code changed — canaries are pure operational scaffolding.
## D247. Executor wiring for Azure: apply + observe accept the third cloud
The Azure drivers implement the full provider.Provider interface (create/observe/
delete/reconcile/preflight/probe — the reconcile+preflight+probe parity work
proved it), and every provider verb wired Azure EXCEPT the two on the execution
path: `apply` and `observe`. Their inner provider switches enumerated
fake|gcp|aws|k8s and dropped azure to "unknown provider %q". So `converge
--provider azure` (plan → apply → observe) died at apply, and the D246 Azure
canary had to be watch-only. This was an unbuilt gap, not a closed decision —
nothing in DESIGN deferred it; the switch was simply never extended.

D247 wires both. `apply`'s azure branch mirrors gcp (D28): a create GENERATES the
providerId from the driver's subscription, so apply must pin it from the plan's
read-set — and Azure already carries the subscription in reads.provider.project
(the Project field is the "pinned identity", and every azure verb takes it via
--project), so the branch reads the same field gcp does, refusing when it is
absent. `observe`'s azure branch mirrors gcp/aws there: the subscription rides in
each providerId, so azure.NewDriver("") defers ownership to the providerId (the
driver's `sub != d.Subscription && d.Subscription != ""` guard is a no-op when the
driver subscription is empty). Two CLI pins (provider_guard_test.go's sibling
azure_apply_test.go): apply must REACH the azure branch (proven ARM-free by
compiling a plan with no pinned subscription so the branch refuses at its own D28
check — a message only that branch emits — before any network), and observe must
construct the driver rather than refuse. make check 432/432, differential 200/0.
No live Azure account exists here, so end-to-end apply is proven exactly as AWS's
is: wired + unit-pinned + green, with the provisioned Azure canary as the live
proof — which this unblocks (the canary's reserved exit-20 converge loop can now
be added).

## D248. EKS upgrade: the managed node group follows the cluster
D147 slice 3 wired the in-place control-plane upgrade (`cluster.version` mutable
via UpdateClusterVersion, polled to Successful). But a real Kubernetes upgrade is
not just the control plane — the managed node group must move to the same version
or it falls behind the API server. The node group is an OPERAND (implementation.
nodeGroup), not a governed attribute — its version is implicit (= the cluster's),
matching AWS's own model where a node group tracks its cluster. So the upgrade
completes as a DRIVER-SIDE consequence of the `cluster.version` update action, not
a second plan action or a new vocab attribute: once the control plane bump polls
to Successful, `updateEKS` rolls every node group via UpdateNodegroupVersion
(AWS's rolling replace respects PodDisruptionBudgets — it drains each node). This
was the chosen shape (author decision) over making node-group version a separately
declared attribute: it keeps the contract unchanged and the composite upgrades
atomically, and the "no side-effect binding" concern is moot because the node
group is part of the cluster composite the driver created.

Ordering is guaranteed by construction: the roll runs AFTER the control-plane
update completed, so a node group is never asked to outrun the API server (AWS
would reject it). Idempotent per node group: a group already at the target is
skipped (DescribeNodegroup version check), so a re-run after a partial roll
converges without a spurious replacement — and a re-apply after a clean upgrade
emits no `cluster.version` change at all, so the roll never fires. Four-valued
throughout: a failed/timed-out node-group roll after a successful control-plane
bump is `unknown` WITH the providerId (a half-upgraded cluster to reconcile),
never a bare success or failed. Three httptest cases pin it: the ordered roll +
idempotent skip, and the partial-failure `unknown`. make check green.

This is the deploy-driven answer to Acme's F-NEW (see the field report): the
driver was already REQUIRING an explicit cluster.version (never defaulting one) —
what was missing was the node group following the cluster on an upgrade, which is
what a "complex upgrade" test actually exercises. Note the SEPARATE, still-open
F16/F17 systemic finding (a non-observable declared attr on ANY bound resource can
freeze the whole replan): a full-contract upgrade may still hit it on unrelated
resources; that fix (per-capability isolation of the observation-required gate) is
its own change, not bundled here.

## D249. Per-capability isolation of the reconcile gate (Acme F16/F17/F15)
Reconciling a BOUND capability, `classifyBound` (compiler) gated on a fresh
observation for every declared attribute and, on any miss, returned a Go error
that ABORTED the whole `Compile`. So one un-reconcilable capability froze the
entire plan — Acme hit this repeatedly: a non-observable declared attribute on a
budget or an ACM cert (`cost.monthly`, `alert.threshold`, `auto.renew`) refused
`... : no observation` and blocked an unrelated EKS upgrade in the same contract.
The pre-existing `isProjectionAttr` was a two-item hardcoded patch for the same
class. D249 generalizes the fix and isolates per capability.

Two mechanisms, chosen by WHY reconcile could not complete:
- **Unverified** — a declared attribute the driver cannot observe. The signal is
  stateless and exact: observe records ALL observable attrs of a capability
  atomically, so if the capability HAS fresh observations but this attribute is
  absent, the attribute is structurally non-observable. It is taken at its
  DECLARED value (skipped from the change-set, like a projection) — the capability
  still reconciles its observable attrs and still emits its actions — and the
  attribute is recorded in `Unverified`. The run reports it inconclusive (D136),
  never a false "converged"; converge exits 0.
- **Blocked** — a capability that genuinely cannot be reconciled: an incomparable
  or unparseable observation, or an unwired change class (Acme F15's "acm
  change-classification not wired"). It is held back entirely (no action, never in
  `writes`), recorded in `Blocked`, and converge exits 2 — but the OTHER
  capabilities still plan and apply.

The re-observe recovery is preserved: a capability with NO observations at all
(never observed, as opposed to observed-but-this-attr-absent) is still an
ObservationRequired refusal, so converge's auto-observe and a human `observe` fix
it; stale and future-dated observations likewise stay refusals (re-observe is
their fix), never isolated. Only a GLOBAL fatal — an unset evaluation clock (N1)
— still aborts the whole compile, because it is a caller precondition affecting
every capability identically, not a per-capability condition.

Invariant 1 is untouched: it gates the VERIFIER's four-valued verdict on the
candidate's DECLARED values (`report.Executable`, checked before Compile runs),
not this D28 reconcile-freshness gate. An Unverified attribute is taken as
declared exactly as the verifier already accepted it; a Blocked capability is
never claimed converged. planview renders both sections; the plan JSON carries
`blocked`/`unverified` so any consumer sees them. Pinned by compiler unit tests
(the isolation, the missing-attr distinction) and the end-to-end
converge-inconclusive conformance case (now the Unverified path); make check
432/432, differential 200/0. This is the deploy-driven answer to Acme F16/F17
(non-observable no longer freezes) and F15 (an unwired classifier isolates,
does not freeze) — the observer-completeness fixes (reading force_ssl, ACM
RenewalEligibility) remain the separate, better fix where an attribute CAN be
made observable.

## D250. Budget reconcile heals a partial (missing alert notification), F25-b
A budget create writes TWO halves: the budget object, then its alert
notification (CreateNotificationWithSubscribers). If the notification half fails,
`createBudget` returns unknown-with-pid (a partial). But `reconcileBudget`
concluded the pending create on the BUDGET alone (`describeBudget` → succeeded),
binding a budget with NO alert — and once bound, a later converge saw the alert
threshold as merely un-observable (D249 Unverified) and never rebuilt it. The
alert was stranded forever.

D250: reconcile now checks BOTH halves. If the budget exists but the notification
is missing (readable and empty), the create is not complete, so reconcile
concludes FAILED rather than succeeded. reconcile cannot itself recreate the
notification — it lacks the candidate's declared threshold and SNS topic — so the
honest, unsticking move is to leave the create un-concluded-as-success: a re-apply
re-runs `createBudget`, whose DuplicateRecordException fall-through idempotently
(re)creates the notification and heals the budget. A notification we cannot READ
(e.g. a missing permission) is left to the budget-based verdict — the fix targets
the KNOWN-missing case, never a read error. Two pins: both-halves-present →
succeeded; budget-present-notification-empty → failed. make check 432/432,
differential 200/0. This closes the last real tail of Acme's F25: a budget whose
alert was lost to a mid-flight partial now self-heals on the next resume/apply
instead of binding half-made.

## D251. Lost-ledger advisory: an all-creates plan warns before it duplicates
The ledger holds the bindings; without it `converge` cannot see what already
exists and plans to CREATE every capability. Acme hit exactly this — a pilot
deploy's ledger was never persisted (it lived under /tmp and was lost), so a
converge planned to create all 26 capabilities against infrastructure that was
already standing. D251 makes the signature loud: when a plan is ENTIRELY creates
across three or more capabilities, converge advises that this is either a first
deployment or a lost/wrong ledger, and that applying against existing infra would
duplicate it — remedy: rebuild state with discover + adopt (docs/onboarding.md's
new "Recovering a lost or missing ledger"). It is an ADVISORY, not a refusal: a
genuine first deploy is all-creates and correct, so converge must not block it —
but it must never let the accident pass silently. Pinned by a planCreateSummary
unit test. This is the cheap detection layer; the durable fixes (a create that
adopts an existing owned resource instead of duplicating it; a bulk
adopt-from-discovery) are separate, larger changes.

## D252. Create-time adoption for bedrock: bind an existing owned profile
A create for a capability whose deterministic-named resource already exists in the
cloud is the lost-ledger signature (D251): the ledger was lost, so converge plans
to create what is already standing. Most AWS drivers already handle this — on the
API's own AlreadyExists signal they describe the resource, check ownership tags,
and bind it (succeeded + pid) rather than duplicate — via the shared
groundholdTagsMatch idiom (15 of 18 services). Bedrock was a gap: it DETECTED the
name conflict but returned unknown ("reconcile ownership") instead of completing
the bind inline. D252 finishes the pattern: on AlreadyExists, resolve the profile
by name among the APPLICATION inference profiles, and if one carries our ownership
tags, BIND it. Crucially it binds on OWNERSHIP (the deterministic name + our tags)
alone — never on candidate attribute values — so a lost-ledger recovery against a
reality that DIVERGED from the candidate (a different region tier, a toggled flag)
re-adopts what exists and lets the next reconcile carry the delta, instead of
refusing on the mismatch the way full `adopt` (adoption-must-not-lie) would. This
is the create half of self-healing recovery. Pinned by TestBedrock_CreateAdopts
Existing. The remaining server-assigned-id gaps (vpc, kms — a blind CreateVpc/
CreateKey mints a duplicate because there is no name to look up by) need a
pre-create tag-scan and careful integration with the ownership-bypass honesty
harness; they are a separate follow-up.

## D253. Create-time adoption for vpc + kms: the server-assigned-id gaps close
D252 gave bedrock create-adoption; 16 of 18 AWS services now bind an existing
owned resource on create instead of duplicating. The last two — vpc and kms —
could not use the others' reactive pattern (bind on the API's own AlreadyExists
signal): a VPC id and a KMS KeyId are SERVER-ASSIGNED with no idempotency token,
so a second create never collides — it silently mints a duplicate (a second VPC, a
second paid key). They need a PRE-create scan by ownership tags. D253 adds
findVpcByTags (DescribeVpcs, tag-filtered) and findKMSKeyByTags (paginated ListKeys
+ ListResourceTags), each VERIFYING the tags on what came back (never trusting the
server filter alone): exactly one owned resource -> BIND it (reality; drift is the
next reconcile's job); a foreign-tagged one never matches, so it is never adopted;
ambiguous (>1) refuses to guess; a readable-empty or unreadable scan falls through
to the normal create (best-effort — a real lost-ledger recovery has a readable
scan, and a genuine first deploy is never blocked). With this, converge against a
lost ledger self-re-adopts ALL 18 services (Acme's 1:N resources — addon sets,
per-model grants — are exactly why create-adoption is the only path: each create
action binds its own resource, where a manual `adopt` binds one providerId per
capability).

Honesty-harness integration was the crux. The ownership-bypass harness
(certifynet) poisons any read that precedes the first mutation with a foreign tag
and asserts NO mutation may follow — the correct law for a delete/observe
ownership gate, but the OPPOSITE of a create-adoption scan, whose correct response
to "not ours" is precisely to proceed and create. The reactive AlreadyExists path
(the other 16) is naturally exempt because its ownership read happens AFTER the
create attempt. So the pre-create scan is kept OUT of the harness's create probe:
the create-Op fixtures return an empty tag-filtered scan (no owner tag to poison ->
the fault is a no-op there -> the harness still certifies a genuine create), and
the adoption path itself is pinned by dedicated, harness-external tests
(TestFindVpcByTags_VerifiesOwnership / TestCreateAWSVPC_AdoptsExistingOwned and the
KMS twins): a foreign-tagged resource is provably never adopted, and an owned one
is bound with no mutation. make check 432/432, differential 200/0.

## D254. Azure create-path ownership pre-read: no PUT over a foreign resource
An ARM PUT is an unconditional UPSERT: a create writes with a PUT to a
deterministic resourceId, and if a resource already sits there, the PUT
OVERWRITES it — its tags, its properties, even a Flexible-Server administrator
password. Azure's delete and reconcile paths already gate on ownership tags, but
CREATE did not: a survey found ~30 of ~40 Azure services PUT unconditionally (via
the shared putAndPoll/putSetting or a direct doARM PUT) with no ownership check.
So a create — or a lost-ledger converge — could silently overwrite a same-named
FOREIGN resource. This is the create-side of "never touch a resource that is not
ours", the exact class the AWS ownership-bypass honesty harness protects against.

D254 adds a create-path ownership pre-read (internal/azure/ownership_preread.go).
It derives the ownership being ASSERTED from the body about to be PUT — a
tag-owned resource carries groundhold-capability/environment in `tags` — GETs the
live resource, and REFUSES (failed) when one already exists carrying different (or
absent) ownership tags. It proceeds when the body is not tag-owned (content-
addressed roles azrole/azcustomrole and tagless children carry no ownership claim
— they skip automatically), when the resource is absent (a genuine create) or
unreadable (fall back — an unreadable GET almost always means an unreadable PUT,
so the mutation fails on its own), and when the existing resource is OURS (an
idempotent re-PUT). It NEVER adopts or mutates — it only refuses. The guard is
promoted into the two shared PUT helpers (covering ~23 services at once) and added
to the six tag-owned direct-PUT creates (flexserver, managedidentity, azalert,
azdashboard, azscheduledquery, azwebtest). Pinned by TestRefuseForeignUpsert
(foreign/untagged-existing → refuse; ours/absent/tagless-body → proceed); make
check 432/432, differential 200/0.

Boundary, honestly: this is the SECURITY half — never overwrite a foreign
resource. The create-ADOPTION half (an existing OURS resource → bind without a
re-PUT, so a lost-ledger self-adopt does not reset our own config/password) is a
separate, later change; today an Azure re-PUT over our own resource still upserts.
And the tag-based check covers only tag-owned resources; name/marker-owned ones
(consumption budgets, diagnostic settings) keep their own ownership predicates in
delete/reconcile, not covered here.

## D255. Create-time adoption for GCP's three server-assigned monitoring resources
Most GCP creates already adopt on the deterministic-name 409 (Cloud SQL, GCS,
Cloud DNS: name collision -> check labels -> bind). Three Cloud Monitoring
resources cannot — a dashboard, an alert policy and an uptime check get a
SERVER-ASSIGNED id, so a blind POST on a lost ledger mints a DUPLICATE (nothing to
collide on). billingbudget already solved the identical shape with a pre-list by
its deterministic displayName; D255 applies the same guard to these three via a
shared paginated helper (findByDisplayName over the "dashboards"/"alertPolicies"/
"uptimeCheckConfigs" arrays). Each create now, before the POST, binds an existing
resource carrying our displayName; and on a lost-response POST it re-lists to
recover the server-assigned id rather than reporting a bare unknown. A
readable-empty or unreadable list falls through to the create (a genuine first
deploy is never blocked). Pinned by TestCreateDashboardAdoptsExisting; make check
432/432, differential 200/0. This closes the last GCP create-time-adoption gaps —
converge against a lost ledger now re-adopts GCP monitoring instead of duplicating
it, matching AWS (18/18) and the ~32 GCP services that already did.

## D256. Azure create adoption where a re-PUT would reset an unobservable secret
D254 stopped an Azure create from overwriting a FOREIGN resource. The other half —
an existing OURS resource — was left to re-PUT (an ARM upsert), which for most
resources is converge-correct: the declared body is the intent, and every property
is observable, so a lost-ledger self-adopt with a reality-exact candidate re-PUTs
the same values (a no-op) or applies genuine drift (an update). The exception is a
create body carrying an UNOBSERVABLE secret: a Flexible Server's
administratorLoginPassword cannot be read back to build a reality-exact candidate,
so a re-PUT would RESET it to the declared/placeholder value. D256 gives exactly
that create the adopt-half: refuseForeignOrAdopt binds an existing OURS server
(succeeded + pid) and SKIPS the PUT, leaving the password untouched; foreign still
refuses; absent still creates. createAKS already carried this shape (its own
ownership pre-read adopts an ours-healthy cluster); flexserver is the one remaining
secret-bearing create. The general adopt-half was deliberately NOT pushed into the
shared putAndPoll: for observable-only resources a re-PUT is converge-correct, and
forcing bind-on-ours there would (a) turn ~20 metamorphic round-trips into no-ops
in test and (b) suppress legitimate update-on-drift. Scope = where re-PUT is
actually harmful (an unobservable secret). Pinned by
TestCreateFlexServerAdoptsExistingSkipsPUT (adopt binds, zero mutation). make check
432/432, differential 200/0.

## D257. Intra-action progress: a long driver poll reports its phase, not silence
apply already emits per-ACTION progress (D227: pending -> running -> done), but a
single action whose driver polls for MINUTES (an EKS control-plane upgrade, a
node-group roll) showed "running" and then went silent — the executor cannot see
inside the driver call. D257 adds an OPTIONAL intra-action heartbeat: a new
provider.ProgressReporter interface (SetProgress(func(phase string))). The AWS
Driver implements it (a progressSink field + a progress() helper); its long poll
loops (waitEKSClusterActive, pollNodegroupActive, waitEKSUpdate,
waitEKSNodegroupUpdate, pollAnyNodegroupActive) call progress("control plane
upgrading ...") each iteration. apply, before each action, wires the sink to that
action's progress.Tick (ProviderPhase + ElapsedMS) and clears it after (a phase
never leaks onto the next action's id). Purely a projection — a driver that does
not implement the interface, or a nil sink, changes no mutation semantics (proven:
every existing test passes unchanged, the sink defaulting to nil). Pinned by
TestDriverProgressHook. FOLLOW-UP: converge runs apply as a subprocess and buffers
its stderr, so this heartbeat reaches a DIRECT `apply` (progress on) but not yet a
`converge`; streaming the child apply's progress into the converge display (without
double-printing the cost block it already re-prints) is the next slice.

## D258. EKS adopt: bind the cluster's REAL node group, never poll a phantom name
Adopting an existing cluster (createEKS found it ours) called ensureEKSNodeGroup,
which described/polled the node group by the DETERMINISTIC plan.NodeGroupName
(<cluster>-ng). For a cluster groundhold did not freshly create in this call, the
real node group need not carry that name — so DescribeNodegroup returned a
readable-false / not-found surface, pollNodegroupActive never saw ACTIVE, and the
adopt HUNG until the (long) poll timeout: exactly the multi-minute freeze Acme hit
mid-upgrade (goroutine dump: pollNodegroupActive <- ensureEKSNodeGroup <- createEKS),
with the cluster and its one ACTIVE node group untouched. D258: ensureEKSNodeGroup
now LISTS the cluster's real node groups (ListNodegroups) and, if any exist, binds
the composite as soon as ANY is ACTIVE (pollAnyNodegroupActive, polling the real
names) — the per-node-group version upgrade is the reconcile's job. Only a cluster
with ZERO node groups gets a fresh create (the genuine first-create path,
unchanged). Unreadable node groups conclude unknown-with-pid rather than spin
forever. Pinned by TestEKSAdoptExistingClusterBindsRealNodegroup (a differently-named
ACTIVE node group binds, no duplicate POST, no hang). make check 432/432,
differential 200/0.

## D259. EKS adopt binds on EXISTENCE, single pass — no poll loop can hang it
D258 fixed the phantom-name poll but kept a timeout LOOP (pollAnyNodegroupActive):
it re-described the real node groups until one reported ACTIVE. Acme hit the same
hang a SECOND time on the D258 binary — cluster ACTIVE, acme-ng ACTIVE, no
duplicate, yet it spun to the timeout (dump: pollAnyNodegroupActive <-
ensureEKSNodeGroup <- createEKS). The loop's silent "keep watching" branch is
reached whenever DescribeNodegroup never returns literal ACTIVE for a genuinely
running node group — a 404 on a just-listed name, an eventual-consistency window, a
permission that lists but does not describe. The exact API quirk was not
remotely diagnosable, so the fix is structural: for ADOPTION, EXISTENCE is the bind
criterion. bindExistingNodegroups does ONE describe pass — cluster ACTIVE + ours +
>=1 node group listed => the composite EXISTS => succeeded. The pass only DOWNGRADES:
a node group positively CREATE_FAILED/DEGRADED (none ACTIVE) is unknown-with-pid
(reconcile); an INCONCLUSIVE describe (404/unreadable/transient) never blocks or
loops — the node group's live health is an observe/verify concern, not a bind
concern, and a running adopted cluster must not be held hostage to a describe that
never says ACTIVE. The fresh-create path (zero node groups -> CreateNodegroup ->
pollNodegroupActive) still polls, correctly: there a poll IS waiting on provisioning.
Pinned by TestEKSAdoptNodegroupDescribeInconclusiveStillBinds (describe 404s forever,
still binds succeeded) and TestEKSAdoptNodegroupDegradedIsUnknown (honest downgrade);
PollTimeout=2s in tests means a reintroduced loop would flip succeeded->unknown and
fail the guard. make check 432/432, differential 200/0.

## D260. EKS adopt reads retry the transient class — one hiccup no longer DIES a converge
D259 made the node-group bind robust, and Acme's converge finally got past it — only
to DIE with "outcome unknown" AFTER binding the cluster, on an all-ACTIVE adopted
world (cluster 1.33 ACTIVE, one node group ACTIVE, app live). Root cause was not the
cluster: the whole EKS adopt path is a CHAIN of single-shot ownership reads
(DescribeCluster, ListNodegroups, DescribeAddon x4, DescribePodIdentity), and EACH one
turned a momentary transport/429/5xx into a fatal readable=false -> Status:"unknown"
with NO retry. One unknown action aborts the entire apply (exit 4, reconcile-required)
which converge renders as DIED. Adopting a healthy multi-resource cluster was only as
reliable as N consecutive flawless describes — and AWS throttles. This is the CLASS
behind the F13->D258->D259->this sequence: each binary fixed the symptom the previous
one exposed, but the read path itself was never resilient. D260 adds eksGet: a bounded
retry (4 attempts, PollInterval apart) on the TRANSIENT class only (transport error,
429, 5xx); a definitive status (2xx / 404 / 403 / other 4xx) returns at once — a 403 is
a real permission gap, not something to spin on, and 404 is a real absence. Routed
through the four single-shot adopt reads (cluster, node-group, addon, pod-identity list
+ describe). It never converts a genuine failure into a success — it rides out the
noise a live adopt is guaranteed to hit. The persistent-failure tail is made
ACTIONABLE: the pre-read unknown reasons now name the exact missing permission
(eks:DescribeCluster / eks:DescribeAddon / eks:ListPodIdentityAssociations) so a
CONSISTENT failure self-diagnoses as IAM rather than another blind binary round. Pinned
by TestEKSAddonAdoptRidesOutTransientRead (503 on the first 3 describes -> still
succeeded) and TestEKSAddonAdoptPersistentReadFailureIsActionable (never recovers ->
unknown naming eks:DescribeAddon). make check 432/432, differential 200/0.

## D261. EKS adopt-by-explicit-name: never duplicate a custom-named brownfield cluster
The whole F13->D258->D259->D260 EKS-adopt saga was a MISDIAGNOSIS on a stray. Root
cause: BuildEKS derives the cluster name DETERMINISTICALLY (eksCompositeName ->
eks-prod-<hash>). A real brownfield cluster with a CUSTOM name (eksctl/TF, e.g.
"acme") never matches that name, so createEKS described eks-prod-<hash>, found
nothing, and stood up a SECOND cluster. Its half-provisioned node group is what every
"poll hang" / "outcome unknown -> DIED" report was actually interacting with; the real
acme (1.33 ACTIVE) was never touched. "Self-adopt 18/18" only ever worked for
resources ALREADY carrying groundhold's deterministic name (recovery of a
groundhold-created cluster after a lost ledger). D261 lets a candidate target an
EXISTING custom-named cluster: BuildEKS reads implementation.clusterName (mirroring the
parent-clusterName operand eks_addon/eks_podidentity already use), sets plan.Name to it
and AdoptByName=true. In that mode the create-only operands (clusterRoleArn, subnetIds,
nodeRoleArn, nodeGroup) are OPTIONAL — a minimal adopt candidate is clusterName +
version — and createEKS, when the named cluster is NOT found, REFUSES rather than
creating (the anti-duplicate core: never stand up a cluster at an adoption name). A
named cluster that exists but is foreign (tags do not match) is refused with a pointer
to the sanctioned takeover flow: discover -> adopt (which claims it through adopt.Run's
gates: competing-reconciler, adoption-must-not-lie, then the compiler emits a claim,
EKS being claimable) -> converge. Foreign takeover deliberately stays in that gated
flow; createEKS never silently claims. This also retroactively vindicates D258/D259
(bind the cluster's REAL node groups) and D260 (retry transient reads): with the name
finally correct, those are exactly what make the node-group half of a real adopt work.
Pinned by TestEKSAdoptByNameBindsExistingOwned (owned custom name binds, zero
CreateCluster), TestEKSAdoptByNameAbsentRefusesNeverDuplicates (absent name -> refuse,
zero CreateCluster), TestEKSAdoptByNameForeignRefused, and
TestBuildEKSAdoptByNameMakesOperandsOptional. make check 432/432, differential 200/0.

## D262. capability.dns.record on all three clouds: a governed record inside a zone
capability.dns.zone was fulfilled on all three clouds but capability.dns.record (the
A/CNAME/TXT record SETS inside a zone) was unbuilt everywhere — the zone drivers
deliberately treat records as "data, out of band". D262 builds the record capability
as a first-class 3-cloud slice: AWS route53record (Route 53 ChangeResourceRecordSets),
GCP clouddnsrecord (Cloud DNS changes API), Azure dnsrecord (ARM record child under a
public dnsZone). The governed facts are the record's KIND (dns.type, a closed set) and
where it POINTS (dns.target); TTL/priority/id are noise. dns.proxied is a Cloudflare
EDGE concept (proxied vs direct-to-origin) with no equivalent on the three managed
clouds, so every driver REFUSES it at build and OMITS it at observe with a diagnostic
(an honest one-cloud-family gap, never a fabricated false). The zone and record name
are IDENTITY, supplied by the candidate implementation: block (impl.zone / zone_id +
record_name), not governed attributes — the vocab governs the record, the candidate
says WHICH record. OWNERSHIP is the crux: a record set carries no owner marker of its
own, so ownership derives from the PARENT ZONE — every create/delete first reads the
zone (tags on AWS/Azure, labels on GCP) and REFUSES a record in a zone that is not
ours (the zone is the ownership boundary). Within an owned zone the write is safe
(AWS/Azure upsert, GCP change-add), so a lost create is simply re-applied — idempotent,
never a duplicate. Provider ids: r53rec:zone:type:name, gdnsrec:project:zone:type:name,
adnsrec:sub:rg:zone:type:name. Pinned by three dual attribute-verify cases
(type/target satisfied, target-drift violated, proxied kind-mismatch load-error) and
three impl:go plan-permission cases (one per cloud). Parity matrix regenerated:
capability.dns.record now fulfilled on aws+gcp+azure. make check 438/438, differential
200/0.

## D263. dns.record in-place update: repoint without a resolution gap, 3 clouds
A DNS record's whole point is that its target changes — repointing a CNAME/A is the
canonical DNS operation. D262 shipped dns.record as create/replace (allowlisted, no
ClassifyChange), so a dns.target drift compiled to a REPLACEMENT: delete the record,
recreate it — a window where the name does not resolve. D263 wires in-place update
across all three clouds so a repoint is a single patch, no gap. dns.target -> MUTABLE
(AWS UPSERT ChangeResourceRecordSets; GCP an atomic managedZones.changes carrying
deletions:[current]+additions:[new] — Cloud DNS has no modify-rrset call, so the swap
must be one atomic change; Azure an idempotent record-child PUT). dns.type -> IMMUTABLE
(the kind is the record's identity — baked into the pid and, on Azure, the ARM child
path — so a type change is an honest replacement, consent-gated as before).
service.managed / dns.proxied / cost.monthly -> unsupported. Every update re-checks
parent-zone ownership before mutating and guards that the desired identity (zone/type/
name) equals the bound providerId — an update only ever repoints THE bound record,
never retargets a different one. Each cloud left its classifyChangeAllowlist entry
(now that it has a real ClassifyChange). Notably Azure already had Update
infrastructure (nine services wire it; the "no Azure update" header comment was stale),
so this was a clean wire-in, not a new subsystem. Pinned by per-cloud classify unit
tests + repoint round-trips (assert one patch, the immutable-type refusal, foreign-zone
refused) and three impl:go plan cases (aws/gcp/azure repoint -> one update action
carrying dns.target). make check 441/441, differential 200/0.

## D264. EKS long-running-operation timeout: a slow-but-healthy upgrade is not a failure
Pre-ship adversarial review of the greenfield-create + 1.33->1.34 upgrade lifecycle
(the exact flow a field user was about to run) found one real ship blocker: the driver
polls every EKS long-running operation against the generic PollTimeout (20 min), but a
real EKS control-plane MINOR-VERSION UPGRADE routinely takes 20-40 min. So waitEKSUpdate
would trip its deadline on a HEALTHY, still-progressing upgrade and return unknown ->
apply exit 4 -> converge DIED — a false failure on a slow-but-fine op (the same
"outcome unknown" surface, this time caused purely by too short a ceiling). D264 gives
EKS its own timeout: EKSLROTimeout (default 60 min), used by every EKS poll deadline
(waitEKSClusterActive, pollNodegroupActive, waitEKSUpdate, waitEKSNodegroupUpdate, the
node-group/cluster delete polls, pollEKSAddonActive) via d.eksLROTimeout(), which falls
back to PollTimeout when unset so tests keep their fast (2s) timeout paths. The rest of
the reviewed lifecycle was confirmed solid: cluster.version classifies as MUTABLE (an
in-place update, NEVER a replacement — a version bump can never delete the prod
cluster), the upgrade sequences control-plane-then-node-groups, rollEKSNodegroups polls
the REAL node-group names (the D258 phantom-name hang cannot recur on the upgrade path),
four-valued honesty holds throughout, and an in-place upgrade candidate does not need
the create operands. Pinned by TestEKSLROTimeoutExceedsPollTimeout (>=45m and > the
generic PollTimeout, plus the zero-value fallback). Guidance carried to the field: an
upgrade candidate should declare the unchanged governed attrs identical to the live
cluster (a present-but-mismatched unsupported attr would block the capability under
D249 isolation — safe, but it would silently skip the upgrade). make check 441/441,
differential 200/0.

## D265. Proactive class-gate for the LRO bug class + closing it on GKE/AKS
The Acme EKS saga was four bugs of two generalizable classes: a transient read with
no retry became a false unknown (D260), and a poll ceiling shorter than a real
control-plane upgrade (20-40 min) reported a HEALTHY slow upgrade as unknown (D264).
An honest audit found those two fixes were EKS-ONLY — GKE and AKS had the identical
classes OPEN (getGKE/getAKS did single-shot reads; both polled against the generic
20-min PollTimeout, and the AKS UPGRADE polled via the shared putAndPoll). So the same
production failure was waiting on two more drivers. D265 does two things:
(1) CLOSES the class on GKE and AKS: a bounded transient-read retry mirroring eksGet
(gcp gcpGetRetry over getGKE/addon/workload-identity reads; azure armGet over
getAKS/addon/FIC reads) and a generous LRO ceiling (GKELROTimeout / AKSLROTimeout,
default 60m, 0 falling back to PollTimeout for fast tests) on every cluster poll —
including the AKS upgrade, via a new putAndPollT(timeout) variant so the ~30 other ARM
callers keep the 20-min ceiling while the AKS control-plane upgrade gets 60m (else the
floor gate would be a false green: a declared budget the upgrade path did not use).
(2) MECHANIZES the D264 class as an automatic gate: provider.LROBudgeter
(LROTimeout() time.Duration) implemented by all three drivers, enforced by
TestInterfaceParity (a cluster driver that forgets it fails CI, like the Reconciler
precedent), and TestLROTimeoutFloor asserts every driver's ceiling >= 45m (above the
observed 40-min upper bound). A NEW cluster/LRO driver that ships a naive timeout now
fails in CI, not on a field user's production upgrade. Honest scope: the timeout class
is now mechanically gated cross-driver; the transient-read-retry class is closed on all
three cluster drivers but gated only by per-driver regression pins (no cross-driver
retry gate — a full lifecycle honesty harness that drives create->observe->update->
upgrade->delete against an adversarial fake, modeling custom names, read storms, and
slow multi-poll LROs, is the deeper follow-up that would also gate the D261 naming and
D258/D259 phantom-poll classes, still EKS point-fixes today). make check 441/441,
differential 200/0.

## D266. Lifecycle honesty harness: the Acme bug classes become cross-driver gates
D265 mechanized the timeout class (LROBudgeter + floor). D266 mechanizes the other two
generalizable classes as executable adversarial gates in certifynet, so a driver that
regresses them fails in CI, not on a field user's cluster. The base harness
(certifynet.go) injects ONE fault at ONE index and, by construction, never faults a
read transiently (a single-fault model cannot express "retry and still succeed") and
has no notion of a poll that never terminates — precisely the two axes the Acme saga
lived on. Two additive files, no change to the base:
- certifynet/readstorm.go `CertifyReadRetry`: a stormRT faults the FIRST 3 requests
  classified as reads with the transient class (503/429/conn-drop), then serves happy;
  the create MUST still succeed with the baseline pid. A driver whose reads retry
  (eksGet/gcpGetRetry/armGet, 4 attempts) rides it out; a one-shot-read driver reports
  a false unknown and fails — the D260 class, now gated cross-driver (the audit's named
  gap: retry was closed everywhere but ungated).
- certifynet/lifecycle.go `CertifyBoundedPoll`: drives a create against a StuckServer
  whose resource is created but never reaches ready; the result MUST be a prompt
  unknown-WITH-pid, and a goroutine guard fails the test cleanly if the create HANGS
  (rather than a whole-suite timeout) — the D258/D259 phantom-poll/infinite-hang class.
Both reuse the existing flat Probe plumbing (Classify + a create Op) and each driver's
own stateful fake, so enrollment is per-driver-cheap and needs no per-API knowledge in
the harness. Enrolled on all three cluster drivers: EKS, GKE, AKS (TestReadStorm* +
TestBoundedPoll*), each confirming — mechanically — that the D265 retry/timeout work
actually holds. Scorecard of the four Acme classes: D260 retry -> CertifyReadRetry
(gated x3); D258/D259 hang -> CertifyBoundedPoll (gated x3); D264 timeout ->
TestLROTimeoutFloor + LROBudgeter interface parity (gated x3, D265); D261 duplicate ->
still per-driver EKS regression tests (adopt-by-name is EKS-only, so it is not yet a
cross-driver class — it becomes a harness knob the day GKE/AKS gain adopt-by-name). The
gates run under `make check` (go test ./...). make check 441/441, differential 200/0.

## D267. Adopt-by-name on GKE + AKS, and the no-duplicate gate: 4/4 Acme classes gated
The last open Acme class was the root cause itself (D261): a deterministic name means
a custom-named brownfield cluster never matches, so a create stands up a DUPLICATE.
D261 fixed it on EKS only; GKE and AKS still duplicated. D267 closes it on both by
mirroring the EKS pattern exactly — an EKSPlan.AdoptByName-style flag on the GKE/AKS
plan, set when the candidate supplies implementation.clusterName; that name replaces
the deterministic one, the create-only operands become optional in adopt mode (a
minimal adopt candidate = clusterName + governed attrs), and createGKE/createAKS REFUSE
when the named cluster is absent rather than creating a duplicate. The AKS refuse is
placed BEFORE the PUT (an AKS PUT is create-OR-update — an upsert — so the anti-
duplicate check must precede it), and guarded with !found so the legitimate
ours-but-half-provisioned converge re-PUT still works. Then the class is MECHANIZED: a
new certifynet gate CertifyNoDuplicate drives a create whose candidate names an ABSENT
cluster and asserts BOTH the refusal AND — the real proof, via a mutation-counting
RoundTripper — that ZERO mutations were sent (no duplicate stood up). Enrolled on all
three cluster drivers (TestNoDuplicate{EKS,GKE,AKS}). With this the FULL Acme bug
class is gated cross-driver: D260 transient-read-retry -> CertifyReadRetry (x3);
D258/D259 phantom-poll hang -> CertifyBoundedPoll (x3); D264 slow-LRO timeout ->
TestLROTimeoutFloor + LROBudgeter parity (x3, D265); D261 custom-name duplicate ->
CertifyNoDuplicate (x3). 4/4 classes, three clouds, all running under make check —
a driver that regresses any of them fails in CI, not on a field user's cluster.
make check 441/441, differential 200/0.

## D268. HTTP/2 dead-idle-connection health-checks: the long-upgrade hang (F29)
Acme's live EKS upgrade run confirmed the whole D258-D267 chain works — AWS executes
1.33->1.34->1.35 as an in-place UPDATE, never a duplicate, and resume cleanly concludes
a pending receipt. But it surfaced a real P1 (F29): after a ~40-min control-plane
upgrade, groundhold HANGS at the end of the long apply, requiring SIGQUIT + resume. Root
cause is not the driver's poll logic (D264's LRO ceiling never gets to fire): during the
long upgrade the connection to the EKS API sits idle for stretches, an LB/NAT drops it
SILENTLY (no FIN/RST), and Go's HTTP/2 transport keeps REUSING the dead connection — a
poll read blocks and http.Client.Timeout does not reliably interrupt the wedged http2
transport, so the apply hangs indefinitely. The canonical fix is HTTP/2 health-check
pings, now available in the stdlib (Go 1.24+ http.HTTP2Config, so NO new dependency):
SendPingTimeout pings a connection idle for 15s and PingTimeout closes it if the ping is
unanswered within 15s, so a read on a dead connection fails FAST and the driver's bounded
retry (eksGet, D260) gets a fresh connection instead of hanging. Applied via a shared
newResilientHTTPClient (cloned DefaultTransport + IdleConnTimeout 90s + the HTTP2 config)
on ALL THREE cluster drivers (AWS/GCP/Azure) at once — a long GKE/AKS upgrade has the
identical latent hang, so the class is closed cross-driver in the same change (the D265
discipline). MECHANIZED by TestHTTPClientsHealthCheckIdleHTTP2 in parity: every
hyperscaler driver's HTTP client must run health-check pings, so a new driver shipping a
bare http.Client fails in CI, not on a field upgrade. Also folds in a small F19/F20/F24
recurrence Acme hit: NewDriver now falls back to AWS_REGION (the standard SDK variable
users actually set) before AWS_DEFAULT_REGION, so resume finds the region without an
explicit GROUNDHOLD_REGION. make check 441/441, differential 200/0.

## D269. The F29 fix that actually works: force HTTP/1.1 (D268's HTTP/2 pings did not)
Acme's live upgrade run PROVED D268 ineffective: the binary they tested (verified to
CONTAIN newResilientHTTPClient — the D268 fix was present, not absent as first suspected)
still hung 19+ min in the net/http HTTP/2 readLoop after a ~40-min upgrade, needing
SIGQUIT + resume. So the stdlib http.HTTP2Config health-check pings did NOT break the
wedged-HTTP/2-transport hang in the field, and neither did http.Client.Timeout (also
ignored by the wedged transport). D269 removes the whole failure class by forcing
HTTP/1.1 on all three cluster drivers (ForceAttemptHTTP2=false + a non-nil empty
TLSNextProto): every AWS/GCP/Azure control-plane API supports HTTP/1.1, and on HTTP/1.1
the per-request Timeout and ResponseHeaderTimeout are honored RELIABLY (the wedge is an
HTTP/2-only pathology) and a broken connection is discarded on error — so a poll on a
dead connection fails within ResponseHeaderTimeout and the driver's bounded retry gets a
fresh one. The lesson from D268 is baked into the gate: TestResilientClientBoundsStuckRead
now EMPIRICALLY verifies the construction bounds a read against a silent server (a config
pin that "looks right" is not enough — D268 passed its config pin and still hung).
TestHTTPClientsHealthCheckIdleHTTP2 asserts every driver disables HTTP/2 and sets
ResponseHeaderTimeout. make check 441/441, differential 200/0.

## D270. EKS post-update 409 is transient: retry the settling lock, do not DIE
The same live run surfaced a second blocker: for a few minutes AFTER a version-update
settles, EKS returns 409 "cluster is already undergoing an update" (eventual
consistency) — and applyEKSUpdate mapped that to failed, DYING the next converge
(Acme worked around it with a ~4-min cooldown). D270 recognizes this transient
post-update lock (eksUpdateInProgress matches the message) and RETRIES the update POST,
bounded by the LRO ceiling, instead of failing — so a back-to-back upgrade (1.34->1.35
->1.36) does not need a manual cooldown. A 409 that never clears concludes unknown
(reconcilable) at the deadline, never a false success or an infinite retry. Pinned by
TestApplyEKSUpdateRetriesTransient409 and TestApplyEKSUpdatePersistent409IsUnknown.

## D271. D269 shipped BROKEN: force-HTTP/1.1 must restrict ALPN, not just TLSNextProto
D269 forced HTTP/1.1 by setting ForceAttemptHTTP2=false + a non-nil empty TLSNextProto —
and shipped to Acme. It broke EVERY request: TLSNextProto disables the transport's h2
UPGRADE handling but does NOT change TLS ALPN, which still advertised "h2". An h2-capable
server (AWS EKS) negotiated HTTP/2, then the transport parsed the h2 SETTINGS frame as
HTTP/1.1 -> "malformed HTTP response". In the field this surfaced as a total EKS CREATE
regression: DescribeCluster reached AWS and returned ResourceNotFound (CloudTrail
confirmed), but the client could not PARSE the h2 response, so the pre-read was
readable=false ("unreadable"), never found=false ("not found"), so createEKS took the
unknown branch and DIED without ever calling CreateCluster. D271 fixes it by restricting
ALPN: clone the TLS config and set NextProtos=["http/1.1"] so the server negotiates
HTTP/1.1 (verified against the live AWS EKS + STS endpoints: HTTP 403/200 proto=HTTP/1.1,
and end-to-end via the shipped driver client). The lesson is pinned:
TestResilientClientForcesHTTP1OverALPN connects to a REAL httptest HTTP/2-capable TLS
server (EnableHTTP2 + StartTLS) and asserts the client connects AND speaks HTTP/1.1 — the
plain-HTTP tests (and D269's own "empirical" bounds test) could not catch an ALPN
mismatch. This is the second F29 miss (D268 pings ineffective, D269 ALPN broken); the
fix is now verified against the real cloud endpoint, not just a config pin or a plain
server. make check 441/441, differential 200/0.

## D272. Pre-ship gate: a live-AWS smoke, because hermetic CI shipped broken binaries
Two broken F29 binaries reached the field (D268 pings ineffective, D269 ALPN broke
EVERY request) and BOTH were green in make check. The reason is structural: ci.yml is
HERMETIC by design (no cloud, no network) and every driver test hits a plain-HTTP
httptest fake or pins a config field — so a client that fails against a real TLS/ALPN
cloud endpoint, or a SigV4 regression, is invisible to the gate. D272 adds the missing
integration layer WITHOUT breaking the hermetic guarantee: TestLiveAWSSmoke
(GROUNDHOLD_LIVE_AWS_SMOKE=1, skipped in make check) exercises the ACTUAL driver HTTP
client against the real AWS EKS endpoint — level 1 (always, no creds) asserts a
parseable HTTP/1.1 response (the exact D269 symptom was "malformed HTTP response"), and
level 2 (with creds) asserts a signed DescribeCluster on a nonexistent cluster is
readable=true/found=false (the create pre-read path D269 broke). scripts/preship.sh
chains make check + differential + the live smoke into the ONE gate that must pass before
a client binary ships. The delivery process is now: push a tag -> release.yml gates +
cross-builds + attests the artifact (already existed) -> run preship.sh on a box with AWS
egress -> copy the attested artifact (not a hand-build) to the client. Also fixed the
env-fragility D269 introduced: the *_EmptyRegion tests now clear AWS_REGION too (the new
first fallback), so an ambient AWS_REGION on a CI runner or dev box no longer fails
make check. The real-TLS unit gate (TestResilientClientForcesHTTP1OverALPN, D271) closes
the ALPN class inside hermetic CI; the live smoke closes the real-endpoint/signing class
outside it. make check 441/441, differential 200/0.

## D273. The REAL F29 root cause: the node-group upgrade poll used a nonexistent path
After D271 fixed the transport (HTTP/1.1), Acme's live upgrade STILL hung — and the
child-apply dump finally showed the true cause: goroutine in time.Sleep inside
waitEKSNodegroupUpdate, node group ACTIVE at the target version + its VersionUpdate
Successful on AWS, yet the poll spun forever. The bug: waitEKSNodegroupUpdate polled
"/clusters/<n>/node-groups/<ng>/updates/<id>" — a path that DOES NOT EXIST in the EKS API
(the real DescribeUpdate is "/clusters/<n>/updates/<id>?nodegroupName=<ng>"). Every GET
missed, the "Successful" branch was never reached, and the loop ran to the LRO timeout
even after AWS finished the roll. This was the F29 root cause ALL ALONG — every earlier
fix (D258/D259 bind, D260 retry, D264 timeout, D271 http1) treated a transport/timeout
symptom the wrong-path bug produced or was masked behind. The unit test did NOT catch it
because the hand-written fake MIRRORED the driver's wrong path (a fake that encodes the
same assumption as the driver is blind by construction — the deepest lesson of this
incident). D273 rewrites the poll to watch the NODE GROUP's own observable end state
(describeNodegroup: Status ACTIVE at the target Version) via a real, everywhere-used
endpoint through eksGet — correct AND robust, no fragile update-by-id path. Pinned by
TestWaitEKSNodegroupUpdatePollsObservableState (asserts the driver hits DescribeNodegroup
and NEVER an /updates/ path, and concludes done at the target version) and
TestWaitEKSNodegroupUpdateNeverReachesVersionIsUnknown (bounded unknown, never a hang);
the D248 upgrade test's fake was corrected to be stateful (node group -> target version
after the roll) rather than serving the nonexistent path. make check 441/441,
differential 200/0. (The general lesson — a fake that mirrors the driver cannot catch a
wrong API assumption — motivates a cross-cloud request-vs-real-API gate, next.)

## D274. Endpoint-reality: prove every driver path is a real cloud route, no creds
D273's lesson is that only an INDEPENDENT source of truth catches a wrong-path bug — a
hand fake that mirrors the driver is blind by construction, and the bounded-poll gate
(D266) only proves the STUCK case terminates, not that a HEALTHY poll on a wrong path
concludes. So the source of truth is the live cloud API itself. Key finding: the cloud
control-plane frontends return a DISTINGUISHABLE signal for an unmatched route vs a real
one — WITHOUT credentials. AWS API Gateway: a real EKS route needs auth ("Missing
Authentication Token") while a nonexistent one is "Unable to determine service/operation
name to be authorized"; GCP: a real container.googleapis.com route is 401 UNAUTHENTICATED
while an unmatched one is a 404 from the Google frontend. The gate (TestLiveAWSEndpoint-
Reality, TestLiveGCPEndpointReality) enumerates EVERY (method, path) the driver constructs,
hits the live API with bogus placeholders through the DRIVER's own HTTP client, and asserts
each is a recognized route — with a NEGATIVE control (the exact D273 path, and a plausible
GKE nested path) the gate MUST flag or it has no teeth. Because it drives the real client,
a transport/ALPN regression (D269) fails here too — one gate, two classes. It needs network
egress but NO creds, so it runs on any box and is wired into preship.sh (step 4). Honest
boundary: Azure has no creds-free twin (ARM validates the subscription before it routes the
provider path, short-circuiting to SubscriptionNotFound), and AKS carries no D273-class risk
anyway (it polls the resource's own provisioningState, never a constructed sub-resource
path — confirmed by a GKE/AKS audit), so that gap is accepted and documented. The mechanism
generalizes per service: list the paths a driver calls, assert each is real. Cross-cloud
audit verdict for the D273 class specifically: EKS was the only driver affected; GKE polls a
response-derived operation id on the canonical operations endpoint, AKS polls provisioning-
State — both already robust, no port of the D273 code fix required.

## D275. References resolve at apply: receipt outputs + deferred validate (D226 slice 2)
D226 shipped the COMPILE slice of F13 (the $ref grammar, OperandRef in the sealed plan,
the refusal set) — but nothing executed it: no driver declared OutputsFor except the fake,
CreateResult.Outputs had zero consumers, and apply passed the raw {$ref:...} map to the
driver, which refused it as a malformed operand. Acme's pure-groundhold full-deploy
request (2026-07-24) made this the #1 blocker: 16/26 capabilities wait on operands that
are outputs of the same plan. D275 wires the executor half exactly as D226 designed it.
(1) RECEIPT OUTPUTS: a succeeded create's raw result is filtered through the driver's
typed OutputsFor contract — only declared names, every declared name present, each value
kind-checked (string | list of non-empty strings, no coercion) — and lands as `outputs`
in the terminal receipt, so the ledger stays the durable record and the in-run map is
only its projection. A missing or wrong-kinded DECLARED output demotes the create to
`unknown` at receipt-write time (the driver broke its own contract; nothing downstream
starts; resume reconciles). (2) RESOLUTION: an action carrying references resolves each
from the producer's receipted outputs BEFORE its own write-ahead intent; any failure
refuses with reference-unresolved — no intent, no driver call, zero mutation, and the
producers (exactly its dependencies) are already durable. (3) DEFERRED VALIDATE: a
ref-consumer's driver Validate moves from the upfront pass to resolution time, still
pre-intent, and runs on the RESOLVED operands. The executor never passes a placeholder —
a made-up operand would make Validate's answer a lie; the honest cost is that a
ref-consumer's refusal surfaces mid-run (after durable producers), and that cost is
stated in spec/executor.md. (4) PREFLIGHT HONESTY: `groundhold preflight` substitutes a
typed stand-in for each well-formed $ref slot so the report judges the REMAINING
operands in one round-trip (F3/F14) and lists the wired slots as "slot <- cap.output"
in a new `references` field — a $ref naming an undeclared producer/output is left in
place so the driver's refusal names it. The stand-in never reaches apply. The
observe-then-fold branch (producer already bound) stays an explicit compile refusal —
next slice, D226's design (D45 projection + staleness TTL) unchanged. Pinned by five Go
cases (resolution value == receipted value; call order validate:producer -> create:
producer -> validate:consumer -> create:consumer; missing/wrong-kinded declared output
-> unknown, consumer never runs; deferred-validate refusal -> zero consumer receipts +
clean apply.failed; preflight references field) and the end-to-end conformance case
converge-resolves-intra-plan-reference-end-to-end (fake provider, $ref subnetIds,
CONVERGED then converged-no-op). make check 442/442. Real drivers declare their first
outputs in the next slice (AWS: vpc/kms/s3/sns for Acme's wiring table).

## D276. AWS declares its first typed outputs — the F13 wiring table goes live
With D275 the executor resolves references, but only the fake declared outputs. D276
gives the AWS driver its OutputsFor table — the first real cloud on the F13 path,
driven by Acme's wiring table (requests/2026-07-24): vpc {vpcId, privateSubnetIds,
publicSubnetIds}, kms {keyArn, keyId}, s3 {bucketName, bucketArn}, sns {topicArn},
acm {certificateArn}, eks {clusterName}, iam {roleArn, roleName}. The derivation is
CENTRAL and pid-based: Create becomes a thin wrapper (createService keeps the switch;
the completeness gate now scrapes it) that attaches outputs to any succeeded create of
a declaring service, derived from the PROVIDER ID — the same identity resume reconciles
by, present on every succeeded path including create-adoption (D253) and the idempotent
already-ours branches — never from a value the driver merely intended. So one attach
point covers every path, and a future create path cannot forget its outputs. The one
non-pid output set is vpc's subnets: one read of the standing network (DescribeSubnets +
DescribeRouteTables), classifying each subnet by its EFFECTIVE route table (0/0 -> igw =
public; NAT or no default route = private; association-less subnets fall back to the
main table), sorted for a deterministic receipt — the honest source for a created AND an
adopted VPC alike. kms's keyArn needs the account (cached representative read). An
underivable output demotes the create to unknown with the cause named, mirroring the
executor's receipt gate. Acme's table maps to: eks.subnetIds <- vpc.privateSubnetIds;
redis kms key + aurora kmsKeyArn <- kms.keyArn; cloudtrail.s3BucketName <- s3.bucketName;
budgets.notificationTopicArn <- sns.topicArn; alb certificateArn/vpcId <- acm/vpc;
eks-addons/pod-identity clusterName <- eks.clusterName; pod-identity roleArn <-
iam.roleArn. The EKS cluster/node ROLES need no new capability type: identity.
serviceaccount IS an IAM role and takes implementation.assume_role_policy (opaque trust),
so a cluster-role capability + $ref eks.clusterRoleArn <- role.roleArn closes that gap
with the existing vocabulary (worked example to Acme in the exchange note). Pinned by
TestDeriveOutputsFromPid (+ table<->derivation completeness), TestClassifyVpcSubnets
(route-table classification incl. main-table fallback), TestAttachOutputsUnderivable
DemotesToUnknown, and the end-to-end CLI check (plan emits the reference on the REAL
aws driver; preflight ready=true listing "s3BucketName <- media.bucketName"). GCP/Azure
tables are the next parity step, deliberately absent here rather than guessed.

## D277. The EKS role chain needs no new capability type — two operand slots close it
Acme's gap list (2026-07-24, item 2) asked for a new capability.identity.role to
create the EKS cluster/node service roles. The vocabulary already has the type:
capability.identity.serviceaccount IS an IAM role on AWS (D121 — a keyless assumable
machine identity) and takes an opaque trust policy via implementation.assume_role_policy,
so trust for eks.amazonaws.com / ec2.amazonaws.com is a candidate operand, not a vocab
change. What was actually missing were two small operand slots. (1) iamrole accepts an
EXPLICIT implementation.roleName (the D261 adopt-by-name twin): a service role that other
things reference by name must be nameable, and the existing ownership-tag gate on the
EntityAlreadyExists branch still refuses a foreign same-named role. (2) rolepolicy (the
authorization.grant driver) accepts the principal as an OPERAND, implementation.principal
— typically {$ref: role.roleName} — because grant.principal is an ATTRIBUTE and D226
references live in the implementation block only. The $ref buys the DAG edge that orders
AttachRolePolicy AFTER the role's create (previously nothing ordered a grant against its
principal — a mid-run NoSuchEntity waiting to happen). One-source-of-truth rule: if BOTH
the grant.principal attribute and the operand are given they must agree, else refuse —
the verified claim and the wired reality may never diverge. The worked example Acme
asked for (d254: "a contract shape, not another binary") now compiles on the real driver:
net(vpc) + cluster-role/node-role (identity.serviceaccount, explicit names, EKS/EC2
trust) + 4 grants (AmazonEKSClusterPolicy; WorkerNode/CNI/ECRReadOnly on the node role,
principal <- $ref roleName) + eks (clusterRoleArn/nodeRoleArn <- $ref roleArn, subnetIds
<- $ref net.privateSubnetIds) — 8 actions, references and edges exactly right; shipped to
the exchange channel. Known risks stated, not hidden: IAM propagation after CreateRole
may 400 an immediate CreateCluster (bounded-retry candidate if the field confirms), and
grants do not block eks (EKS surfaces a missing cluster policy as cluster health, not at
create — if live runs prove otherwise, ordering needs a mechanism, not a hope). Pinned by
TestBuildIAMRoleExplicitName and TestBuildRolePolicyPrincipalOperand.

## D278. Subnet groups are derived placement wiring, not a missing capability type
Acme's gap list asked for DB/cache "subnet group" capability types (Aurora's
subnetGroupName, ElastiCache's cache subnet group — old F26). A subnet group fails the
vocabulary test (capability semantics vs implementation noise): it carries no
independent meaning — it is pure placement wiring that exists only to serve its one
consumer — so it enters as an OPERAND, not a type. aurora and elasticache now accept
implementation.subnetIds (typically {$ref: vpc.privateSubnetIds}, closing the wiring
end-to-end from the VPC) as the alternative to a pre-created group name: the driver
derives a deterministic owned group (pv-<cap>-<env>-sng-<hash8>, generation-free so a
D48 replacement's successor reuses it) and stands it up BEFORE the cluster as part of
the composite create — the exact precedent of vpc owning its subnets/IGW/NAT (never the
F2 param-group case, which carries real semantics like force_ssl). One source of truth:
both operands set refuses; 1 subnet refuses on aurora (a DB subnet group spans AZs);
neither names BOTH options in the refusal. Already-exists resolves by CONTENT — the
group is reused only when its live subnet set EQUALS the requested one (the derived
name encodes cap+env; equal content is the same intent, and a lost create response
self-heals through this path), anything else is foreign-or-drifted and refuses; the
group is tagged at birth either way. Delete is honest, not best-effort — the honesty
harness caught exactly that: the first cut swallowed a 503 on the cleanup call and the
gate flagged an unresolved mutation concluding succeeded. Final shape: only the derived
deterministic name is ever deleted (an operator-provided group is never ours), gone/
not-found concludes, in-use is left standing by design (a successor generation places
into it), and an unresolved cleanup outcome concludes the retirement unknown. Pinned by
TestBuildAuroraSubnetIdsDerivesGroup, TestBuildElastiCacheSubnetIdsDerivesGroup,
TestEnsureCacheSubnetGroupContentCheck, and the untouched-green honesty harnesses.

## D279. Vocab-region-free capabilities take their region as an operand — the alb/addons/pod-identity catch-22
Acme's gap list item 3: alb, eks-addons and pod-identity refused with `location.region
"" is missing` on every preflight. Root cause is structural, not their candidate: the
vocabularies for capability.network.loadbalancer, capability.cluster.addon and
capability.identity.podidentity deliberately declare NO location.region (an addon or a
pod-identity association lives wherever its cluster lives; a load balancer wherever its
VPC does) — so a candidate CANNOT declare the attribute (verify refuses unknown vocab
attributes), while the AWS driver's Validate region gate and create dispatch demanded
attrs["location.region"]. A gate that cannot be satisfied by any legal candidate is a
bug, and the cloudwatch/cwlogfilter family already pins the right pattern: a
vocab-region-free capability's region is an IMPLEMENTATION OPERAND. The three services
join the Validate exemption list, and their create dispatch resolves the region via
regionOperand: implementation.region first — now REFERENCEABLE, because eks and vpc
gained a `region` output (derived from the pid like everything else in D276), so the
natural wiring is implementation.region: {$ref: {capability: eks, output: region}} for
addons/pod-identity and {$ref: <vpc-cap>, output: region} for the alb — never the
driver's ambient region (an operand is declared; ambient is not). Also in this slice,
the other two item-3 verdicts stay REFUSALS and gain nothing but teaching: s3
durability.class=single-zone now explains WHY (a general-purpose bucket is multi-AZ by
construction; One Zone classes are per-object lifecycle economics, not bucket
durability; Express One Zone is a different resource) and what to do (declare regional
or drop it); kinesis zonal and backupplan availability.class refusals were already
deliberate D208-style teachings — the fix belongs in the candidate generator that
scaffolds availability.class onto capabilities with no AZ concept of their own. Pinned
by TestRegionOperandResolution, TestVocabRegionFreeServicesAreExemptFromAttrsGate and
TestCreateRefusalNamesImplementationRegion.

## D280. Regional networks span the public side too — F1 closed (ALB in a fresh VPC)
F1 stood since Acme's first live deploy: vpc create stood ONE public subnet (the NAT
home), so an internet-facing ALB — which AWS requires to sit on >=2 public subnets in
>=2 AZs — could not be built into a freshly created regional network; the workaround was
pre-create+adopt. Worse, the audit exposed a silent sibling: only the FIRST private
subnet was associated with the NAT route table — a regional network's second private
subnet sat on the empty main table with no egress at all. D280 makes availability.class
=regional govern BOTH sides of a nat-road network: the public side gets one subnet per
private AZ (same AZs, CIDRs from implementation.public_subnet_cidrs or an odd-third-
octet chain derived from the public base — 10.0.1.0/24 -> 10.0.3.0/24, interleaving the
private 10.0.0.0/24 -> 10.0.2.0/24), the FIRST public subnet keeps the NAT (one NAT
stays the cost-conscious default; per-AZ NAT HA is a future knob, stated not assumed),
the public route table (0/0 -> IGW) associates EVERY public subnet and the private
route table (0/0 -> NAT) associates EVERY private subnet. The D276 outputs then carry
the full sets by construction (classifyVpcSubnets reads route tables), so the whole ALB
wiring is candidate-only: alb.subnets <- $ref publicSubnetIds, vpcId <- $ref vpcId,
region <- $ref region (D279), certificateArn <- $ref acm. Zonal/back-compat unchanged
(one private, one public). Pinned by TestCreateAWSVPCRegionalNatMultiAZ (subnet count/
AZ/CIDR sequence, NAT in the first public subnet, all four route-table associations)
and TestPublicSubnetCIDRs (chain, override, non-/24 refusal naming the operand).

## D281. Bounded retry for the IAM-propagation 400 on EKS creates
With D277 the cluster/node roles are same-plan creates, which exposes a DOCUMENTED AWS
consistency class: a freshly created IAM role can take seconds to become assumable, and
CreateCluster/CreateNodegroup answer 400 "Role ... could not be assumed" until it
propagates. That 400 was terminal — a correct plan would fail mid-run purely on timing
(flagged as field-risk (a) in the D277 exchange note; closed proactively because the
class is documented AWS behavior, not speculation — the D265 discipline). Both EKS
creates now retry EXACTLY that 400 (eksRoleNotYetVisible: the role-assumption wording,
deliberately narrow — every other 400 stays terminal) within a 90s window on the
driver's injectable clock; a role that never appears fails with AWS's own message,
never an endless loop, and nothing has mutated when it does. Field-risk (b) — grants
not ordering before create-eks — stays OPEN by design: EKS does not gate CreateCluster
on attached policies (a missing policy surfaces as cluster health), so no mechanism is
invented until a live run proves the need. Pinned by TestCreateEKSRetriesIAMPropagation
400 (two 400s then the landing create) and TestCreateEKSPersistentRole400FailsBounded
(stepping clock crosses the window; failed with the provider message; no cluster).

## D282. Tooling hardening for launch: race, blocking lint, portability, TLS floor
A pre-launch review found the CI/tooling was above-average (SLSA attestation, SBOM,
reproducible builds, a mutation gate) but had three gaps a public Go project should not
ship with: the race detector ran nowhere, lint was report-only, and CI was single-OS.
Closed here. (1) Race: `make race` + a dedicated CI job run `go test -race ./...` — the
runtime is concurrency-heavy (lease acquisition, ledger, scenario engine) and the
detector is clean, so a future data race fails CI, not a field user. (2) Lint BLOCKING:
the golangci-lint backlog (errcheck/gosec/staticcheck/unused/ineffassign/gosimple) was
triaged and cleared — dead code removed, ineffectual assignments fixed, three delete
funcs dropped a vestigial region arg (the pid carries the authoritative region), UI-writer
and best-effort-flag error returns made explicit. Every remaining exclusion is documented
in go/.golangci.yml as a deliberate decision (tests are not the security surface; the tool
by design reads user-named paths and runs its own binary; crypto/md5 is the S3 Content-MD5
header, not a security primitive), never a way to hide a defect. The action is pinned to
v1.64.8 so CI lints with the exact version validated locally. (3) Portability: a matrix job
builds+tests on macos-latest (arm64) — the platform the release cross-built but never
tested. (4) A `tidy` job fails on go.mod/go.sum drift (the yaml.v3 `// indirect` mislabel is
fixed). (5) A genuine security find surfaced in the sweep and was fixed, not excluded: the
driver HTTP clients (aws/azure/gcp) now pin `MinVersion: tls.VersionTLS12` — all three cloud
control planes require >=1.2. govulncheck is pinned (was `@latest`) and reports no vulns; the
G101/G115 findings were verified benign (a public API URL constant; JSON-safe-range-bounded
conversions), not real credentials or overflows. No semantic change: make check 441/441,
differential clean, race clean.
## D283. The fold branch of D226 — a reference to a BOUND producer becomes a sealed literal
D226 designed two resolution paths and D275 shipped one: same-plan references resolve
from receipts, references to an already-bound producer refused "not yet wired". That
refusal was the last structural gap in F13 — after ANY partial apply the producers are
bound, so the re-plan hit it and the operator was thrown back to hand-pasted literals
(the Acme exchange note carried this as the honest boundary). D283 wires the fold exactly
as D226 specified, with the outputs VALUE coming from the only honest source a bound
resource has: observation. (1) OBSERVE records outputs: OutputReader is the optional
read-side twin of OutputProducer (AWS: the same pid derivation the create attaches, so
observe records exactly what a receipt would carry; fake: pure function of the pid), and
observe emits each declared output as an "outputs.<name>" observation — kind-checked,
all-or-nothing per capability (a partial set could fold one operand and starve its
sibling mid-run), a failed read is a diagnostic and never a value (D242). The shared
kind-check moved to provider.OutputValueOfKind — executor, observe and compiler use ONE
definition of "list". (2) COMPILE folds: wireReferences' bound branch reads the D45
projection at "outputs.<name>" gated exactly like classifyBound — N1 unset-clock
refusal, TTL against the explicit --at, future-dated refused — and a fresh record
becomes an OperandFold {slot, capability, output, value, observedAt, ttlSeconds} on the
action: a LITERAL in the sealed decision, IN the plan hash (a new observation yields a
new plan; restart-stable because the same ledger folds the same value). Absent/stale →
observation-required (converge's auto-observe now records outputs, so the loop
self-heals); unbound-and-uncreated → reference-invalid naming all three remedies; a
producer this same plan DELETES → ref-producer-retiring (previously unenforced — a
value from a resource being destroyed is a lie in EITHER branch). (3) APPLY re-judges
every fold pre-lease against the replayed ledger at ITS OWN --at: record exists, value
unchanged (knowledge events are decision-head-neutral by D41, so the heads CAS cannot
catch a superseded fold — this gate is what does), within TTL — any miss is the
stale-plan class (exit 3, re-observe + re-seal). Fold-only consumers validate UP FRONT
on the folded literals; folds substitute before same-run references overlay. Pinned by
the compiler fold matrix (fresh/unbound/absent/stale/future/kind/retiring/N1), the
apply e2e trio (partial -> observe -> fold -> CONVERGED lands the receipted value;
decayed-at-apply refuses; superseded-at-apply refuses), three conformance cases
(fold shape in the plan incl. absent producer action; absent and stale -> observation-
required) and the four observe cases now pinning outputs.* documents. make check
445/445, differential 200/0.

## D284. Output parity: GCP and Azure declare their typed outputs — F13 wired on all three clouds
D276 gave AWS the first OutputsFor table; GCP and Azure stayed a stated gap. D284
closes it with the SAME architecture (a thin Create wrapper attaches pid-derived
outputs on every succeeded path; ReadOutputs re-reads them for observe/fold, D283) and
per-cloud HONEST tables — native names and shapes, never AWS-lookalikes. GCP: vpc
{network, networkSelfLink, region, subnetworks} (subnetworks from one getNetwork read —
the API's own self-links, truthful for created and adopted networks alike), gcs
{bucketName}, pubsub-topic {topicId, topicName}, serviceaccount {accountId, email,
member — the IAM-binding form consumers actually paste}, cloudkms {keyName — the full
resource path every CMEK slot takes}, gke {clusterName, location}, certmanager
{certificateName}. Azure: vnet {vnetId (ARM id), vnetName, resourceGroup}, blob
{storageAccount, containerName, blobEndpoint}, servicebustopic {namespace, topicId,
topicName — an sbq pid refuses the topic derivation}, managedidentity {identityId,
identityName, principalId, clientId — the two server-assigned GUIDs come from one
getUAMI read, the only honest source; a role assignment or federated credential needs
exactly them}, keyvaultkey {keyUri, vaultUri}, aks {aksId, clusterName, resourceGroup}.
Also fixed en route: classifyProviders in main NEVER constructed the azure driver, so
plan-time driver dispatch (outputKind, ClassifyChange) for azure capabilities silently
fell through to the D186 fake fallback — azure joins the map, which is what made the
azure $ref compile at all. Both completeness gates re-pointed at createService (the
Create wrappers are thin, like AWS in D276); the managedidentity metamorphic fake now
carries the GUIDs a real ARM GET always returns. Verified end to end through the CLI on
both clouds: gcp cloudsql network <- $ref net.networkSelfLink and azure flexpostgres
vnetId <- $ref net.vnetId both seal with the reference and the edge — the former being
literally D226's designed first slice. The honest boundary that remains: outputs exist
for the services above; a $ref to any other service still refuses unknown-output at
compile, and tables grow per real need, never speculatively (D10). Pinned by the
per-cloud derive/table-completeness/attach-demote tests, the vpc-subnetworks and
uami-GUID read tests. make check 445/445, differential 200/0, race clean.

## D285. Converge orphan guard: a killed converge must not leave apply mutating headless
The converge porcelain (D51) execs its own binary for each phase via SelfRunner. The
child `apply` inherited nothing: no process group, no parent-death signal. So a
terminated converge — a killed CronJob pod (SIGTERM then SIGKILL), a crash, an operator
Ctrl-C — could leave the `apply` child REPARENTED and still running: mutating cloud
resources headless while the operator believes the run was aborted, and still holding
the lease until its TTL. This is the last resilience gap of the Acme F29 family (the
converge-orphans-its-child note deferred through D267). Fix: SelfRunner now starts the
child with childProcAttr() — Setpgid (its own process group) plus, on Linux,
Pdeathsig=SIGKILL, which asks the KERNEL to kill the child the instant the converge
process dies for ANY reason, SIGKILL included. Pdeathsig alone closes both the graceful
(SIGTERM -> default parent death -> kernel kills child) and ungraceful (SIGKILL ->
kernel kills child) paths, so no signal-forwarding handler is needed — avoiding a
retry-loop-on-signal hazard and handler races. The hard kill is safe by construction:
apply is write-ahead + resumable (D42/D57), so an interrupted child is reconciled by
resume, never corrupt — which also declaws the documented Pdeathsig thread-exit caveat
(a rare premature kill), whose worst case here is a resumable interruption, not data
loss. Honest platform boundary: Pdeathsig is Linux-only (production); darwin (dev/CI)
gets Setpgid alone; non-unix is a no-op — stated, not silent, in the three build-tagged
procattr files. This is OS-process behavior, not contract semantics, so it is pinned by
Go tests not a conformance case (as the D56-D58 resilience work is): field/Setpgid
assertions, a group-leader functional test, and TestConvergeChildDiesWhenParentKilled —
a re-exec that kills a stand-in parent and proves the child dies (0.02s with the guard;
it would run to the 5s timeout without it). make check 445/445, golangci clean, race clean.
## D286. `outputs.*` is a WIRING namespace, not evidence — the fail-open D283 opened, closed
Projecting D275-D284 into the human surfaces started as presentation work and immediately
found a correctness bug I had introduced myself: D283 put typed outputs on the observation
stream as `outputs.<name>` records IN the same projection as semantic observations. Three
consumers ask "what do we know about this capability?" by counting that map, and all three
silently began counting wiring: (1) the compiler's reconcile — `len(obs) == 0` distinguishes
"never observed" (refuse observation-required) from "observed, but this attribute is not
emitted" (mark unverifiable, proceed). A capability with ONLY wiring records took the second
branch, so EVERY declared attribute was silently reclassified as non-observable and the plan
proceeded as if the capability had been checked. Reachable, not theoretical: a driver whose
semantic Observe yields nothing for a vanished resource (`not found — nothing to observe`)
while ReadOutputs still derives from the pid produces exactly that ledger. Proven with a
failing test before the fix (`err=nil`, `service.managed` silently unverifiable). (2)
`refresh`'s proof-decay test and (3) `posture`'s decayed-capability test share the same
`len(recs) == 0` shape — a wiring read made a never-semantically-observed capability look
proven. The fix is STRUCTURAL, not a rule to remember: `outputs.` becomes a RESERVED
namespace routed at replay into its own `Ledger.Outputs` projection (capability -> output
name), so wiring cannot be counted as semantic knowledge by construction — the compiler's
fold and apply's pre-lease re-check read `Outputs`, everything else reads `Observations` and
is correct without knowing why. The reservation is enforced (a vocabulary declaring an
`outputs.` attribute fails a gate, in an external test package because ledger transitively
imports vocab), the snapshot carries the new projection (fuzz-equivalence intact), and the
file-supplied `--observations` path splits identically — conformance caught that second
entry point, which is exactly the forgotten door that would have reopened the hole. THEN the
presentation work this slice set out to do: `show` renders a folded operand with its
provenance and shelf life (`folded subnetIds <- net output privateSubnetIds = [...]` /
`observed <T>, valid 15m`) rather than a bare literal indistinguishable from operator
typing — a reviewer cannot judge "is this still true?" without the source and the window;
and the console (same slice, per the one-glossary rule) splits `/api/evidence` into
`evidence` (semantic) and `wiring`, so `/api/summary` and `/api/debt` freshness stop being
inflatable by identity re-reads, with the wiring still SHOWN in its own block — hiding
information is the other failure. Pinned by: the two compiler regression tests, a
conformance case (bound capability known only by wiring -> observation-required), the vocab
reservation gate, planview fold-render + TTL-unit tests, and the console fold-split test.
make check 446/446, differential 200/0.

## D287. The maturity doc was wrong in both directions — corrected against evidence
`docs/MATURITY.md` is this project's flagship honesty artifact: every subsystem carries a
verdict AND a basis, because a maturity claim is a claim. It had gone stale in the one way
that matters most — it was WRONG, and wrong in both directions at once. It understated:
"AWS drivers — built | config-intent | **Never run against real AWS**", when an external
pilot had by then stood the substrate up on their own account (EKS + node group + addons +
pod-identity, sequential 1.33→1.36 upgrades driven end to end by `converge`, Aurora with
enforced TLS + CMK + managed password, ALB/ACM, Bedrock, ECR/S3/KMS/CloudTrail/CW-logs/SQS,
`discover` over 212 real resources, per-resource `adopt`, `resume` concluding a pending
receipt). It also overstated by omission: it claimed "no external users" while a real
operator had filed 36 findings, and it never said that the field caught bug classes every
hermetic gate passed. A document that exists to prevent unearned claims cannot itself carry
unearned claims — including flattering ones and self-deprecating ones. The pass moves what
the evidence moves and NOTHING else: executor → proven (measured on GCP + AWS); AWS drivers
→ partial with the exercised subset named and the ~34 golden-only services stated; GCP
drivers → partial for the same honest reason (only 3 of 41 services ever met a real API —
the old row implied the whole family); observe/discover/adopt → measured on two clouds;
console → measured basis now that `console-live/` holds real AWS output. Azure stays
`built` and is now named the weakest claim in the system. Three gaps were REPLACED with
sharper ones rather than deleted: one paused pilot is not a track record (the newest fixes
— D281, D283, D286 — are pinned by tests but never re-run in the field); the field found
what the gates did not (a poll on a nonexistent API path whose unit fake mirrored the same
wrong assumption, D273; a transport regression that broke every request while CI stayed
green, D269/D271); and several declared attributes cannot be read back, so a reconcile
reports them unverifiable rather than checked — honest about a gap is still a gap. The
"what ready would mean" bar moves accordingly: Azure reality, an external security review,
an operator running a workload SUSTAINED (a pilot that stood a substrate up and then paused
is not an operating record), and a probe that measures a real recovery. README's status
line carried the same false sentence and is corrected, plus a short "since the vertical
slice" section so the front page stops implying the system ends at D64.

## D288. Aurora derives its own TLS parameter group — reversing D278's aside, with the engine trap named
The pilot escalated R1 as the last blocker of a full pure-groundhold deploy: `encryption.inTransit=true`
refused unless the operator pre-created a cluster parameter group carrying the TLS parameter — the exact
"paste a resource you made by hand" the F13 work exists to abolish, and unavoidable for them because
TLS-to-the-database is a hard constraint they will not weaken. This REVERSES a line I wrote in D278
("wiring, not semantics — never the F2 param-group case, which carries real semantics like force_ssl").
That line was wrong, and the correction is the point: the SEMANTIC is `encryption.inTransit`, which lives
in the contract and is verified four-valued; the parameter group is the MECHANISM AWS requires to realize
it. A group the driver owns, containing exactly the one parameter derived from a declared attribute,
serving exactly one cluster, is not an independent binding — it is the D278 shape applied to a different
resource. What made F2's original refusal right was that the driver could not know WHICH parameters an
operator wanted and might shadow their group; both concerns are answered by the D278 pattern (deterministic
name, ownership tags, content-checked on already-exists, operator operand WINS and is attached verbatim
and never edited, cleaned up at retirement, in-use left standing). The part that needed real care is the
ENGINE TRAP: Aurora runs PostgreSQL and MySQL, and they enforce TLS through DIFFERENT parameters
(`rds.force_ssl` vs `require_secure_transport`, spelled 1 vs ON). A single hardcoded name would have
created, for MySQL, a group that enforces NOTHING while the contract claims TLS — a security-shaped lie —
and observe (which hardcoded the PostgreSQL parameter) would have reported inTransit=false forever on a
correctly-configured cluster, the F17 class that froze this pilot's plans once already. So: the parameter
is engine-derived on BOTH sides, enforcing values are accepted in every spelling, and an engine or version
this driver cannot map REFUSES with the operand escape named rather than guessing (a wrong parameter-group
family is rejected by AWS mid-create; a wrong parameter enforces nothing). The MySQL observe test caught a
real miss in this very implementation — the matcher edit had not applied and the read was still hardcoded —
which is exactly why it was written before the code was trusted. Pinned by per-engine derivation, family
derivation, operator-group-wins, refuse-to-guess, the net-path ordering (group created + parameter set
BEFORE the cluster attaches it), already-enforcing reuse, and the MySQL observe regression guard.

## D289. Preflight stand-ins must be format-plausible — a false "missing operand" is still a lie
The same escalation carried R2: `preflight` listed a slot as wired (`iamRoleArn <- workload-sa.roleArn`)
and in the same breath refused "requires implementation.iamRoleArn". Not a backup-driver bug — a bug in
D275's own preflight helper. It substitutes a stand-in for each $ref slot so the REST of a capability's
operands can be judged in one round trip (the F3/F14 purpose), but the stand-in was the generic string
`groundhold-preflight-ref`, and real drivers validate operand SHAPE (backup checks the `arn:aws:iam::`
prefix). So preflight answered "not ready" about a candidate that applies cleanly. The failure direction
was safe — it can only over-report work, never green-light a gap — but a surface whose entire job is to
tell an operator what is actually missing must not invent misses. D289 adds an optional `Sample` to
OutputSpec: a format-plausible example value the PRODUCER's driver declares beside the output's name and
kind, used only by preflight and never reaching a driver call (apply substitutes real receipted values or
folded literals). Table-driven like the rest of the output contract, and it doubles as documentation of
what an output looks like. Filled for all three clouds — the same false negative would otherwise hit GCP
and Azure — and a driver that declares no sample degrades to the old generic stand-in, still safe. Pinned
by a test with a shape-validating driver, and verified end to end through the CLI on the pilot's shape
(a backup plan whose IAM role arrives by reference now preflights ready).

## D290. The Azure live canary — prepared to the credential boundary, and stopped there honestly
D287 named Azure the weakest claim in the system: two clouds have closed the loop against real
APIs, Azure never has. This slice takes it as far as it can go without credentials, and is
explicit about where that is. Prepared: a canary contract + candidate (examples/canary-azure/)
on capability.network.private → the vnet driver, chosen because an Azure virtual network costs
NOTHING — so the run proves the whole spine (bearer auth, the ARM PUT, the async provisioning
poll, ownership tags, the observe reverse-map, the convergence check, retirement) without a
bill, and the README says plainly which surfaces it does NOT prove (AKS, Flexible PostgreSQL)
rather than letting a green canary imply more than it earned. Both documents verify PROVEN and
compile to a sealed plan locally, so nothing is left to discover at credential time. Two things
were found and fixed in the preparation: (1) the constraints were first written with
verify.method=provider-api, which BLOCKS the very first plan — no observation can exist before
the resource does. That is the system being right, not a contract worth shipping; a create-time
contract states what the candidate declares (static) and lets `observe` + the convergence check
supply the measured half afterwards. Worth writing down because it is the natural mistake a
first-time author makes with a four-valued verifier. (2) scripts/canary-azure.sh's header
claimed apply "is not yet wired for Azure" — false since D247, and surviving only because
nobody re-read it: the same doc-rot D287 went after, found one slice later in a file that
document did not cover. The header now states the REAL reason the scheduled canary stays
watch-only (it runs unattended with a reader identity; an unattended job that creates resources
is a standing bill and a standing blast radius), and points the mutation loop at the
operator-run canary. THE HONEST STOP: the run itself needs an interactive `az login` (the local
az CLI is additionally broken — a shebang pinned to a python that no longer exists), a
subscription id, and a pre-existing resource group, which groundhold deliberately does not own
(an RG is an account-shaped container, like the subscription — there is no such service in the
driver). Those are the operator's to supply; inventing them is not something a runtime that
refuses to fabricate observations should do with credentials either. Azure stays `built` in
MATURITY.md until the loop actually runs — preparation is not evidence.

## D291. The forecast phase could fail silently and still render green (adversarial audit of forecast)
The forecast subsystem was the last big unaudited surface on the go-live map. The predictor
itself came out clean: `predict` walks the CANDIDATE's declared paths and looks observations
up BY PATH (so D286's wiring namespace cannot leak in as phantom attributes), stale degrades
to `unknown` and future-dated to `unverifiable` (fail-closed both ways), a kind mismatch is
`unverifiable` rather than a false `differ` (invariant #2), and provenance rides through to
every prediction (invariant #3). One stale COMMENT was found — the `create`-on-bound branch
still claims the executor "would 409-continue and change NOTHING", which stopped being true
when create-time adoption and composite repair landed (D252/D258/D259: that path can create a
missing node group or member instance). It is unreachable through the compiler (a binding
moves the decision head, so such a plan is stale-plan first) and forecast gates nothing, so it
is recorded here rather than papered over. The REAL find is one layer up, in converge: of
every sub-verb it runs, the forecast was the ONLY one whose exit code was discarded
(`_, fout, _ :=`). And because the checklist completes the active row whenever the NEXT phase
is entered, a forecast that failed rendered exactly like one that succeeded — row done, no
rollup line, nothing said. That is green where reality was absent, and it sits on the CONSENT
path: this phase exists to show a human what will happen immediately before they confirm, so
its silent absence means someone consents believing they were shown a preview they never got.
The fix keeps the advisory boundary intact rather than over-correcting: a failed preview does
NOT block the loop (apply independently re-checks the read-set, the clock and the ledger — a
cosmetic preview failure must not stop a correct deploy), but it is now SAID on the human
channel with the child's own first line carried verbatim, and the row resolves to a new
`failed` state carrying a mandatory why (the render vocabulary already had the glyph; the
checklist gained `Fail`, distinct from `Skip` — a row that never ran — and from Freeze's
`refused` — a verb doing its job). Certainty is lost out loud instead of quietly. Pinned by
three cases: the failure is said with the child's reason, the loop still applies, and the
resolved row reads failed-with-why and is not resurrected into done by the next Enter.

## D292. The three two-cloud domains' gaps are DECLARED, not silently unbuilt
A pre-launch parity audit flagged three primary-cloud cells as UNBUILT-and-undeclared —
`search.index`/GCP, `streaming.pipe`/GCP, `container.job`/AWS — reading as "groundhold
isn't finished" when in fact each is a deliberate two-cloud domain whose third cloud has
no capability-shaped service. The vocabularies already documented this (D113/D114/D120:
"HONEST TWO-CLOUD domain... REFUSED by fail-closed dispatch, never a faked third mapping"),
but the parity gap registry did not carry the entries, so the matrix derived them as mere
unbuilt. D292 formalizes the vocab authors' judgment in structuralGaps: GCP has no managed
search-cluster twin (Vertex AI Search is ML/RAG), no clean managed streaming twin (Pub/Sub
Lite is deprecated, Managed Kafka is a cluster model), and AWS has no standalone managed-job
resource (Batch is a composite, ECS RunTask is ephemeral) — all `not-capability-shaped`.
The audit's separate suggestion to BUILD container.job/AWS was wrong: it did not read the
vocab, which had already judged AWS Batch/ECS not-capability-shaped; building a driver there
would be exactly the faked third mapping the honesty discipline forbids. No runtime change —
the dispatch already fail-closes (no token); TestParityMatrix proves each new gap is REAL
(no cloud token fulfils it) and its class is from the closed set. make check 446/446.

## D293. Complete D249: an observed-but-blind capability isolates, it does not freeze
D249 split "a bound capability's attribute has no observation" into (a) the capability
was never observed — re-observe recovers, so refuse ObservationRequired — and (b) the
capability was observed but this attribute is structurally non-observable — isolate it as
unverifiable and plan the rest (Acme F16/F17). But it told the two apart by len(obs)==0,
which CONFLATED "never observed" with "observed and yielded nothing observable": a bound
capability with a blind/empty observer had zero observations either way, so it took branch
(a) and froze the whole converge on the SECOND plan (after converge's one auto-observe),
even though re-observe could never help. The F16/F25 RESIDUAL. D286 sharpened the stakes:
with outputs.* moved out of Observations into their own wiring projection, a capability
that reads only outputs now ALSO has empty semantic Observations, widening the set that
hit the freeze. Fix: the ledger marks a capability `observed` on the observation.recorded
EVENT — recorded now even when it carried ZERO observations (observe records a readable-
but-empty capability instead of skipping it) — and the compiler tells (a) from (b) by that
signal (in.Observed) instead of len(obs)==0. A never-observed capability still refuses
ObservationRequired (the recovery is kept, narrowed to exactly the recoverable case); an
observed-but-blind one isolates as unverifiable and the compile proceeds. The signal is
DERIVED FROM THE EVENT, not from outputs/wiring, so it does not reintroduce the fail-open
D286 forbids (answering "has this been observed?" from wiring records). Pinned dual-half:
TestEmptyObservationMarksCapabilityObserved (ledger: empty event -> observed, zero
Observations), TestObserveRecordsAReadableButEmptyCapability (observe: a Fake "empty:"
blind resource is recorded observed-yet-empty), and two conformance cases —
plan-does-not-freeze-a-bound-but-blind-observer-capability (SEALED with db in unverified;
teeth-checked: reverting the one condition refreezes it) and its never-observed control
(still ObservationRequired). The Fake gained an "empty:" providerID marker (blind: no
Observe, no ReadOutputs) mirroring the "unreadable:" injection. make check 448/448,
differential 200/0, golangci + race clean.

## D294. Azure meets reality — and the first live run finds that observe never worked at all
The canary prepared in D290 ran against a real subscription. Result: the loop CLOSES on Azure —
create (a VNet in westeurope, correctly ownership-tagged, with its subnet), observe (measured
facts from live ARM), a second converge that refreshed stale knowledge, re-planned and reported
`converged — the world already matches the candidate` without touching anything, then retirement
through the contract leaving a tombstone, the resource gone, the resource group deleted. Cost:
zero, by construction (a VNet is free). That is the third cloud, and the strongest evidence in
the system after GCP: the whole thesis loop, end to end, against an API nobody had ever pointed
this driver at.

It also earned its keep immediately. The first converge APPLIED but the convergence check came
back inconclusive, and the ledger held NO observation at all: every Azure read returned
"unreadable". Root cause: `runObserve` builds the driver with NO subscription — deliberately,
and the code even says why ("subscription rides in each providerId; with an empty driver
subscription the ownership guard defers to the providerId", exactly what the GCP driver does) —
but `armURL` built every URL from `d.Subscription` and refused when it was empty. So the comment
described an intention the code never implemented, and **the entire 41-service Azure observe
family had never worked outside a test**. The hermetic gates could not see it because every
Azure test constructs the driver WITH a subscription (`NewDriver(testSub)`) — a construction
production never performs. That is the D273 lesson in a new costume: there, a fake mirrored the
driver's wrong assumption; here, a test harness mirrors a driver CONFIGURATION that no real
caller uses. A gate that only exercises the shape you already believe in cannot falsify it.
Fixed at the one choke point rather than 138 armURL call sites: `Observe` derives the
subscription from the providerId (every Azure id is `<kind>:<subscription>:<rg>:...`) and
dispatches through a per-call VALUE COPY of the driver — no shared mutation, no locks involved,
the driver's own pin still wins as a cross-check when set. Verified against the live resource:
the same observe that returned nothing now returns measured facts.

Two follow-ups recorded rather than half-fixed. (1) DIAGNOSABILITY: the read path collapses
three distinct failures (URL-build refusal, transport error, non-200) into the single word
"unreadable" and discards the HTTP status — the reason it took a hand-run `curl` (which
answered 200) to find the cause. It is a 43-observer change and deserves its own slice; it is
honesty about the SHAPE of a failure, not about a wrong answer. (2) The retirement path taught
the canary README a lesson worth keeping: a retired capability must be dropped from the
CANDIDATE entirely while the CONTRACT marks it retired, and constraints on it must go — three
successive refusals said so precisely, each one correct (D47), and each one is what an operator
will hit the first time they retire anything.

## D295. Reads that say WHY — retiring the bare word "unreadable" (Azure first)
D294's live run cost an hour of hand-issued `curl` to learn that a failing read was answering
HTTP 200: the driver collapsed four distinct failures — the scope guard refusing before any
request, a transport drop, a non-200 answer, an unparseable body — into the single word
"unreadable", discarding the status and the provider's own error code. The four-valued verdict
was never wrong (absence of evidence, never a fabricated value, D242); the DIAGNOSIS was
missing, and a system whose whole pitch is "never claim what you did not check" should also be
able to say what it failed to check and why. The fix is a shared reader (`armGetInto` /
`armGetURLInto`) returning `(found, error)` where a 404 stays an AUTHORITATIVE ABSENCE
(found=false, nil error) and every other outcome is an `armReadError` naming the operation, the
cause class, the HTTP status, the provider's code and a bounded message. Semantics are
deliberately UNCHANGED — this slice must not move a single verdict, and the conformance suite
agreeing throughout is the evidence. Two honesty details in the diagnostic itself: the provider's
message is trimmed to 200 chars and the raw body NEVER travels (an unbounded body in a log line
is how secrets leak), and a garbled 200 stays a refusal rather than a well-formed absence (D87).
Scope — and a CORRECTION to this entry's own first measurement (added the same night, before
anyone could act on it): I measured per FUNCTION ("does this function mention a status
anywhere?") and reported that only 12 of 57 sites lost it. That metric was too coarse. Measured
per BRANCH — the honest unit, since a function can name the status on one path and still say the
bare word on another — Azure has ~146 such expressions across 46 files. What this slice actually
converted is the subset where the status was lost on EVERY branch of the function (vnet, flexserver, log-analytics, managed identity,
federated credentials, backup policy, changefeed, consumption budget, plus four discover leaves
that collect diagnostics as strings, where `azReadWhy` renders the same information). The
initial estimate of "43 observers" was my own overcount, corrected by measuring before editing.
The same defect exists on the other two clouds — ~267 AWS expressions and ~233 GCP by the
per-branch measure — recorded as the next slices rather than implied to be done. The overclaim
is left visible above rather than quietly edited away: a maturity claim and a progress claim
fail the same way, and this document is where that has to be admitted first.

## D296. The same read defect on AWS — converted where a live operator will hit it
D295 fixed the diagnostic on Azure; the survey it ended with found the identical defect on the
other two clouds (68 AWS functions losing the status, 37 GCP). AWS cannot share Azure's single
reader: every service here carries its own transport helper (acmCall, rdsPost, eksDo, s3Do,
iamPost, …) and its own not-found predicate (an error CODE string, not a uniform 404), so this
slice ships the DIAGNOSTIC half only — `awsReadError` plus three constructors (transport /
http / body) — and each getter keeps its own call and its own absence test. Converted the paths
the live pilot actually runs: ACM, EKS (observe, the ownership pre-reads on create/update/
delete, the deletion poll) and IAM roles. Semantics are unchanged everywhere: an authoritative
ResourceNotFound / 404 stays found=false with a nil error, the conformance suite agrees
throughout, and the reason strings that used to read "pre-delete read unreadable — reconcile"
now carry the service's own answer. Scope stated rather than implied (and re-measured per BRANCH after D295's
correction — the per-function count flattered both slices): ~267 AWS expressions and ~233 GCP
ones still say the bare word. They are recorded, not done — converting
a cloud a paying operator is mid-deployment on is worth doing service by service with the suite
green after each, not in one sweep at speed. The mechanical risk is real and was demonstrated
in this very slice: a regex that rewrote `readable && found` also hit call sites of getters it
had NOT converted, and only the compiler caught it — which is the argument for converting in
small, verified batches rather than trusting a pattern.

## D297. The read-diagnostic debt becomes a ratchet — because it will outlive one night
D295/D296 converted the read paths that lost the failure cause on EVERY branch, plus the live
pilot's AWS services, and D295's own scope claim had to be corrected once when the per-function
measure turned out to flatter it. Measured per BRANCH — the honest unit, since a function can
name the status on one path and still answer with a bare word on another — what remains is
large: 267 AWS expressions, 139 Azure, 233 GCP. That is a service-by-service program, not an
overnight sweep, and this slice says so rather than grinding half-attentively through hundreds
of mechanical edits. The evidence for that caution is in this very series: twice, a regex that
rewrote a `readable` local also hit call sites of getters it had NOT converted, and only the
compiler caught it. A conversion that needs the compiler as its safety net is a conversion that
must go in small verified batches.
So the deliverable is the thing that makes the REST of the work safe and bounded: a ratchet.
`TestBareUnreadableDoesNotGrow` counts, per cloud, the expressions that say "unreadable" while
carrying neither a status nor a typed read error, and FAILS when the count goes up. It
deliberately does not fail on today's number — a gate demanding perfection immediately is a gate
someone disables, and a disabled gate protects nothing — but a new driver copying the old shape
now breaks CI, and lowering a baseline is a one-line edit that locks the progress in. Verified
to bite by injecting a bare "unreadable" and watching it fail with the offending line, then
reverting. Also converted in this slice: the Azure activity-log, Defender and probe getters
(three more services whose mutation-path reasons now carry the provider's own answer instead of
"pre-delete read unreadable"). The debt is not hidden, it is counted — which is the only honest
way to carry work this size.

## D298. capability.function.serverless — scale-to-zero is its own capability
A field request (Acme) exposed a conflation: `capability.workload.container`
(App Runner / Cloud Run / Container Apps / ECS) always has a floor of >= 1
running instance, so it cannot express request-driven, $0-idle compute. The
economics differ in kind, so the capability an org contracts differs in kind.
`capability.function.serverless` is the separate, stateless (D60) capability for
ephemeral functions, fulfilled on AWS by Lambda (container-image package type)
and on GCP by Cloud Functions gen2. Attributes are capability-semantic only:
location.region, network.publicExposure, tls.enforced, timeout.maximum (a REAL
per-cloud limit — Lambda 900s, gen2 3600s — refused, never clamped, when a
contract asks for more than a cloud can give), replicas.minimum (0 = pure
scale-to-zero, the defining value, honored on both; a warm floor > 0 is
minInstanceCount on GCP but refused on Lambda in v0, where it needs a published
version/alias), service.managed, cost.monthly. Left out as implementation noise:
the runtime/language family (it does NOT map cleanly — a Lambda container image
declares none, gen2 requires one), the handler, image/code location, env vars,
memory size, concurrency tuning, VPC connector.

Two mechanics worth recording. (1) The GCP driver needed a SECOND service token
on the Cloud Functions product: `cloudfunctions` was already pinned to
workload.container (D84), and the cross-cloud parity matrix is one-capability-
per-token, so `cloudfunctions-fn` (providerId prefix `cffn:`) carries the new
capability — the Pub/Sub precedent (`pubsub-topic` / `pubsub-queue`: one product,
two capability tokens). (2) The Lambda create LRO polls the OBSERVABLE state
(GetFunction Configuration.State: Pending -> Active/Failed), never an
operation-by-id path (D273), pinned by an anti-regression guard in the golden
test; the gen2 create polls the response-derived operation name on the canonical
operations endpoint (the GKE-style robust pattern). Public exposure is the
familiar two-gate discipline: on Lambda a Function URL (AuthType NONE) AND a
resource-based lambda:InvokeFunctionUrl grant to principal *; on gen2
ingressSettings ALLOW_ALL AND an allUsers invoker on the backing Run service — a
create that cannot complete both never reports succeeded.

## D299. AWS App Runner — a Cloud Run twin for workload.container, second AWS backend
Field request (Acme): capability.workload.container is portable — GCP=cloudrun,
Azure=containerapps — but AWS=ecs, the least cloud-run-like (ALB + service + cluster
scaling, no request-driven wakeup, no scale-to-zero economics), breaking the semantic
portability the vocabulary promises. D294 adds App Runner as a SECOND AWS backend for the
SAME capability, selected by the service token `apprunner` (dispatch by D76, exactly the
mechanism for two backends of one capability) — NOT a new capability (App Runner IS a
workload.container: container image -> managed HTTPS endpoint, request autoscaling). The
same contract now gives Cloud Run behavior on AWS. API: POST / on apprunner.<region>.
amazonaws.com, JSON-1.0, X-Amz-Target `AppRunner.<Op>`, SigV4 service `apprunner` — every
target verified real against the live endpoint (endpoint-reality, D274). LRO discipline
(D273): create and delete poll DescribeService and conclude on the OBSERVABLE Service.Status
(RUNNING/OPERATION_IN_PROGRESS/CREATE_FAILED/DELETED), never an operation-by-id path — pinned
by an anti-regression test that fails if ListOperations/DescribeOperation is ever hit, and
enrolled in the cross-driver CertifyBoundedPoll gate. replicas.minimum:0 is REFUSED (App
Runner MinSize>=1, no scale-to-zero) with a diagnostic pointing to capability.function.
serverless — never a silent 0->1 clamp; minimum>1 requires an implementation.autoScaling
ConfigurationArn operand (the one-binding rule, ECS-precedent). NOT live-run here (no AWS
sandbox creds in this job) — code+tests+endpoint-reality green, live validation is Acme's
on their account. make check 449/449, differential 0, race + golangci clean. Follow-up
(Acme's optional ask): capability.function.serverless (Lambda/cloudfunctions/functions) for
true $0-idle scale-to-zero — a separate domain, next slice.

## D300. registry.image declares repositoryUri — the container image closes by $ref, not a literal
Field finding (Acme, both compute slices D294-App-Runner-slice/D298-function.serverless): a
capability.registry.image (ECR/Artifact Registry/ACR) declared no typed create output, so a
workload.container / function.serverless candidate had to hand-paste the image URI as a literal
instead of `image: {$ref: {capability: <registry>, output: repositoryUri}}` — breaking the
pure-groundhold wiring (D226/D276) everywhere else the plan wires producers to consumers. D300
adds `repositoryUri` (string) to all three registries' OutputsFor, plus `repositoryArn` on ECR,
each DERIVED from the providerId alone (no new HTTP read, so the D296/D297 read-diagnostic ratchet
is untouched): AWS `<account>.dkr.ecr.<region>.amazonaws.com/<name>`, GCP `<location>-docker.pkg.
dev/<project>/<repo>`, Azure `<name>.azurecr.io` (lowercased — the ACR login server is always
lowercase, the truthful derivation for an adopted mixed-case registry). The consumer side needed
NO change: the $ref resolver is generic (wireReferences at compile, resolveActionRefs at apply set
the slot to the resolved string before the builder runs, which reads impl["image"].(string)); and
preflight substitutes each output's Sample (D289) as a format-plausible stand-in, so the samples
are real-shaped URIs. Pinned by golden output tests per cloud and three symmetric conformance cases
(gcp cloudrun<-artifactregistry, aws ecs<-ecr, azure containerapps<-acr) proving the image $ref
resolves at plan into create + dependsOn + a symbolic references entry. make check 451/451,
differential 200/0, race + golangci clean. Open debt (noted, not fixed): the compute backends
name the image operand inconsistently (App Runner `image`, Lambda `image_uri`; `access_role_arn`
vs `role_arn`) — a unification slice for after Acme's live validation.

## D301. Aurora Serverless v2 auto-pause — the MIN floor may be zero
Field finding (Acme cost analysis): Aurora Serverless v2 supports scale-to-zero
(MinCapacity=0, auto-pause after an idle window — AWS added it Nov 2024), which cuts
the serverless idle floor by ~43 EUR/mo, but the driver hard-refused serverlessMinACU=0
("must be > 0"). D301 relaxes ONLY the MIN operand to accept 0 (acuOperand gains an
allowZero flag; MAX still refuses 0). When min is 0 the builder also sets
ServerlessV2ScalingConfiguration.SecondsUntilAutoPause — the pause delay AWS requires —
from an optional implementation.serverlessSecondsUntilAutoPause operand (300..86400,
default 300 made explicit on the wire); that operand is REFUSED with min>0 (meaningless
there) rather than silently ignored, and out-of-range refuses. These are implementation
sizing operands, not capability attributes (no vocab change), so the change is pinned by
a Go builder test (min=0 -> MinCapacity=0 + default 300; custom in-range delay carried;
delay-without-min-0 / out-of-range / max=0 all refuse) not a conformance case. NOT
live-run here (no AWS creds) — flagged for Acme's live converge validation. make check
458/458, golangci + race clean.

## D302. ElastiCache Serverless — a second cache.keyvalue backend, the pay-per-use floor
Field cost pressure (Acme): the provisioned ElastiCache driver requires node-type
sizing and bills a fixed floor; ElastiCache Serverless is pay-per-use with no node
provisioning. D302 adds it as a SECOND AWS backend for capability.cache.keyvalue,
selected by a new service token `elasticache-serverless` — exactly the App Runner
pattern (D299): one capability, two AWS implementations, chosen by service token.
Parity is per-capability, and cache.keyvalue is already covered on all three clouds,
so a serverless backend is a cost-lever implementation choice, NOT a new domain and
NOT a parity gap: GCP Memorystore and Azure Cache for Redis have no serverless tier,
so there is no twin to build (stated here so the asymmetry is deliberate, not silent).
Query protocol (2015-02-02): CreateServerlessCache / DescribeServerlessCaches /
DeleteServerlessCache / ListTagsForResource. The LRO polls DescribeServerlessCaches
and concludes on the cache Status (AVAILABLE=done, CREATE-FAILED=failed-with-pid),
never an operation-by-id path (D273). Refuses provisioned-only operands (node type /
count / zonal placement) and memcached rather than silently clamping; encryption is
always-on. providerId deterministic + knowable pre-response (D29). Pinned by an
impl:go dispatch conformance case plus httptest golden tests (create+observe, reverse
delete, foreign-refused, bounded-poll enrollment). Five aoss-adjacent API-shape items
(MajorEngineVersion format, ARN element, fault strings, status spellings, KMS observe
field) flagged for Acme live validation — no AWS creds here. make check 460/460,
golangci + race + differential clean.

## D303. OpenSearch Serverless — a second search.index backend, and a composite
Alongside the provisioned OpenSearch domain, D303 adds OpenSearch Serverless as a
SECOND AWS backend for capability.search.index (service token `opensearch-serverless`,
the D299 pattern again). Same parity reasoning as D302: search.index is already placed
per-capability, GCP has no managed search at all (existing gap) and Azure Cognitive
Search has no serverless tier, so no twin — a deliberate, documented asymmetry. Unlike
a single-resource driver, an aoss collection is a COMPOSITE (like EKS/VPC): a collection
cannot reach ACTIVE without a matching encryption security policy, and needs a network
security policy for access. Create orchestrates ensure(encryption policy) ->
ensure(network policy) -> CreateCollection -> poll BatchGetCollection to ACTIVE; delete
is the exact reverse (DeleteCollection -> poll gone -> delete the two owned policies).
JSON-1.0 over service `aoss`, X-Amz-Target OpenSearchServerless.<Op>. The LRO concludes
on collectionDetails[].status (ACTIVE=done, CREATING=poll, FAILED=failed-with-pid),
never an operation-by-id path (D273; a test asserts BatchGetCollection is used and no
"Operation" action exists). Refuses provisioned sizing (instance/node/shard) and zonal;
encryption + TLS always-on; CMK via the encryption policy's KmsARN. The data-access
policy is deliberately NOT created — it governs data-plane index/search authz, a consumer
concern, and a collection reaches ACTIVE without it. Owned policies carry deterministic
name markers (<name>-enc / <name>-net); foreign collections refuse delete. Pinned by an
impl:go dispatch case + httptest goldens (policy-before-collection ordering, LRO
anti-regression, foreign-refused, bounded-poll). aoss JSON key casing and the
security-policy document shape (encryption object vs network array, stringified) flagged
for Acme live validation. make check 460/460, golangci + race + differential clean.
## D304. EventBridge Scheduler ClientToken — the F27 idempotency class, re-bitten
Field finding (Acme live converge): `CreateSchedule` returned HTTP 400 "ClientToken
cannot be empty." — the same class as F27 (Secrets Manager `CreateSecret` refusing a
missing `ClientRequestToken`). The Scheduler driver emitted no idempotency token, so
AWS rejected the create outright, and a retry after a lost response would double-create.
D304 emits `ebsClientToken(name)` — a deterministic UUID-format token derived from the
already-deterministic schedule name (which folds environment + capability + generation
via SHA-256), mirroring `asmRequestToken`. Deterministic means a retry reuses the same
token and AWS collapses the duplicate instead of creating twice. A full sweep of every
AWS create confirmed Scheduler was the ONLY required-but-missing case: Secrets Manager,
EFS, Route53 (zone + health check), CloudFront already carry their required token;
optional-token creates (ECS/EKS/EC2-VPC/Backup/ACM/GuardDuty/Bedrock) do not 400 on
omission and were left untouched to avoid golden churn. Cross-cloud: GCP uses an optional
`requestId` (omission never 400s — dedup on resource name), Azure `PUT` is idempotent by
path — the class does not apply off AWS. Pinned by `TestCreateEBSClientToken` (httptest
body capture + re-derivation for determinism). Three optional-token rows (ECS
`clientToken`, EKS `clientRequestToken`, Backup `CreatorRequestId`) flagged for Acme
live confirmation — I have no live 400 for them. make check + golangci + race + differential clean.

## D305. backup.vault declares its vault-name output — plan wires it by $ref (mirrors D300)
Field finding (Acme live converge): `CreateBackupPlan` returned HTTP 400 "A Backup vault
does not exist." The candidate passed `implementation.targetVaultName` as a bare literal,
but AWS Backup requires the vault to EXIST before the plan is created (class F13: a plan
references a resource the compiler neither creates nor can order against). D305 gives
`capability.backup.vault` a typed create output on all three clouds — AWS
`vaultName`/`vaultArn`, GCP `vaultName`/`backupVault` (full resource name), Azure
`vaultName`/`resourceGroup`/`vaultId` — each derived from the providerId ONLY (no read,
deterministic), exactly the D300 registry-image pattern. The `backup.plan` consumer now
wires its target vault via `{$ref:{capability,output}}`, which forces vault creation and a
`dependsOn` edge instead of a hand-pasted literal. Azure has a real backup.vault driver
so the twin was built, not gapped. No compiler change: `$ref` is validated symbolically
via `OutputsFor`/`outputKind` at compile and the resolved string is substituted before the
builder runs, so all three plan builders read a plain string. ARN/URI formats reuse each
driver's existing live-URL builders (AWS `bkvArn`, GCP resource name, Azure ARM id) — no
format uncertainty. Pinned by `conformance/cases/backup-vault-outputs.yaml` (three impl:go
plan cases: $ref wiring + create-vault-then-plan + `dependsOn` + `references` entry).
make check + golangci + race + differential clean.

## D306. The "unreadable" debt is paid — the ratchet becomes an invariant
D295/D296/D297 named the defect: a read that produced no document reported the bare
word "unreadable", discarding the HTTP status and the provider's own error code, so an
operator could not tell a throttle from a permission gap from a retired api-version
without re-issuing the call by hand. D297 measured it honestly (639 branches), fixed the
worst paths and installed a per-cloud RATCHET rather than claiming completion.

D306 closes it: the remaining ~336 bare branches were converted service by service, and
the baselines are now zero. The shape is uniform across the three clouds — a getter that
used to return a `readable bool` returns `error` instead; a 404 stays an authoritative
absence (`found=false`, nil error) and everything else becomes an `awsReadError` /
`armReadError` / `gcpReadError` naming operation, cause (scope|transport|http|body),
status and the provider's own code, bounded and newline-free so a diagnostic can never
become a channel for an unbounded body. The four shared reconcile cores stopped
flattening what they were handed: `concludeByStatus` (AWS and Azure),
`rc1ConcludeByStatus`, `rc7Scan` and the GCP probe adapters take the error itself.

Two semantic gains fell out of the mechanical work, not from chasing them:
  - Several GCP getters folded a 404 into "unreadable", so reconcile could never
    conclude "the create did not land" for a bucket, a service, a topic or a network.
    With absence separated from failure, those probes now answer `found=false`.
  - Sixteen diagnostics already HELD the error and threw it away (`if terr != nil` →
    a fixed sentence). Those cost nothing to fix and were the clearest evidence that
    the honest-verdict discipline had been kept while the diagnosis was dropped.

The gate now measures CODE, not commentary (a comment describing this history is
documentation, and counting it would either freeze the prose or force a meaningless
baseline), and a `budget: 0` makes it an invariant rather than a ratchet: a driver may
no longer say "unreadable" without naming the status or building a typed read error.
Verified by injecting one bare expression and watching the gate fail. Semantics are
unchanged throughout — absence of evidence still blocks (D242), no verdict moved.
Two Go tests that pinned the WORD ("unreadable") now pin the DIAGNOSIS instead; their
assertions (conservative public verdict kept, diagnostic emitted) are untouched.
make check + race clean; 463/463 conformance.

## D307. Unknown implementation operands refuse at compile — the silent-drop closes
Field finding (Acme, surfaced while wiring a Lambda into a VPC): `implementation:` is
free-form (D26) and had NO framework guard, so every driver SILENTLY DROPPED any `impl`
key it did not happen to read. A candidate declaring `implementation.vpcSubnetIds`
compiled clean, preflighted "ready", and applied to `succeeded` — producing a Lambda
attached to no VPC, with the operand silently gone. That is the cardinal-invariant
violation (never fabricate; refuse loudly). The asymmetry was the trap: candidate
ATTRIBUTES already had a fail-closed allowlist (a driver's `default:` arm refuses an
unmapped attribute), but `impl` OPERANDS did not. D307 gives operands the same
fail-closed treatment. A compile-time `refuseUnknownOperands` pass runs immediately after
`wireReferences` resolves `$ref` operands (so a malformed `$ref` still surfaces as
`reference-invalid`, not this code); any TOP-LEVEL `impl` key on a create/update action
that is neither in the driver's declared consumed set nor a resolved `$ref` slot refuses
with a new machine code `unknown-operand` (exit 2, errors.md, `explain`, and a `next`
edit pointing at the offending slot). Only top-level keys are checked, so a map/list
operand's arbitrary subkeys (e.g. `cloudsql.flags`, `aks-addon.addon_config`) stay free.
Refusing at compile means it fails before a plan is sealed — refuse before mutating.
The mechanism mirrors `OutputProducer.OutputsFor`: an optional `OperandConsumer`
interface with a per-driver, table-driven `ConsumedOperands(service)` (AWS 50 / GCP 42 /
Azure 41 services; the `Fake` double, which reads no operands, is exempt). The existing
conformance suite was the completeness proof: 16 cases initially false-refused — all
Azure permission cases passing a dead `subscription_id` in `impl` that NO Azure driver
reads (the subscription rides `reads.provider.project`, D28) — itself an instance of the
very silent-drop being closed. The dead operand was removed from those case INPUTS (no
assertion touched, invariant #5 intact) rather than whitelisted, because whitelisting it
would make the guard lie. Pinned by `conformance/cases/operand-guard.yaml` (unknown
operand refuses at compile with the `next` edit; recognized operands still plan). make
check 465/465 both impls, golangci + race + differential clean.

## D308. A Lambda reaches a private Aurora — VPC + env operands, and a DB endpoint output
Field finding (Acme live): the API Lambda must reach a PRIVATE Aurora Serverless v2 in
a VPC, but the Lambda driver read only `image_uri`/`role_arn` — no VPC attachment, no env
— and (pre-D307) silently dropped anything else. D308 builds the operands, on the D307
guard so they are recognized rather than refused:
  - **VpcConfig** — `implementation.subnets` + `security_groups` (the SAME operand names
    ECS already uses — cross-driver consistency, not new names) → `VpcConfig.{SubnetIds,
    SecurityGroupIds}` on CreateFunction; both-or-neither (a VpcConfig needs both).
    `subnets` is `$ref`-able to the existing `vpc.privateSubnetIds` list output.
  - **Environment** — `implementation.environment` (map) → `Environment.Variables`. A
    value may be a literal or a `$ref`, so `DATABASE_HOST` wires an Aurora endpoint
    instead of a hand-pasted literal. Secrets stay OFF-ledger: a plaintext-secret env
    value is out of scope (host/port by $ref, password by a runtime secret reference).
  - **Aurora connection output** — `aurora` now declares `writerEndpoint`/`readerEndpoint`
    /`port`, derived from ONE DescribeDBClusters read (network-reading, server-assigned,
    not in the pid — the elasticache-serverless/vpc pattern). Password is never an output.
Two core extensions fell out. First, `$ref` nested in a MAP operand's value: the compiler
`wireReferences` now walks one level into a map operand (deterministically) so an env var
can carry a producer $ref (dotted slot `environment.DATABASE_HOST`), and apply writes the
resolved value into a COPY of the map (the candidate is never mutated — differential stays
0). Second, Lambda gained its first UPDATE path: `UpdateFunctionConfiguration`
(Role/Timeout/VpcConfig/Environment) + `classifyLambdaChange` (timeout/publicExposure
mutable, region immutable), with `waitLambdaUpdated` polling `LastUpdateStatus` before the
next call — a 409 mid-patch is honestly unknown-with-pid, never a silent success. Pinned
by `conformance/cases/lambda-vpc-env.yaml` (list-$ref + map-value-$ref wiring with
dependsOn; a regression proving the operands don't trip D307). AWS only — GCP Cloud
Functions + Cloud SQL parity is the next step. make check 467/467 both impls, golangci +
race + differential clean.

## D309. A failed mutation's Reason is published evidence — it may not carry a body or a credential
Found while looking for the next debt of the D295–D306 family (the read side had just
been finished). The mutation side did the exact thing the read side forbids in writing:
`truncate(body)` / `truncateAz(body)` pasted up to 400 raw bytes of a provider response
into `CreateResult.Reason` — 241 sites across the three clouds.

A Reason is not a log line. `apply.go` copies it verbatim into `receipt["reason"]`, which
is appended as an `operation.receipt` LEDGER EVENT; `export` publishes it, and `capsule`
carries the event verbatim and SIGNS it, in an artifact explicitly designed to travel to a
third party. So a driver's Reason is, in effect, published.

The channel is not theoretical, and it is not just "a body is noisy": drivers must send
credentials — Aurora/RDS `MasterUserPassword`, Azure Flexible Server
`administratorLoginPassword` — and a provider that echoes the value it rejected puts that
credential into signed evidence. Proved first with a failing test per cloud (AWS and Azure
pin the live channel; GCP pins the WIRING and says so out loud, because no GCP driver
sends a credential today — Cloud Scheduler explicitly refuses a payload/auth header as a
secret under D53).

Two independent defences, because neither suffices alone:
  1. STRUCTURAL — `mutDetail` / `mutDetailAz` replace every paste: the provider's own
     error MESSAGE, bounded to 200 chars and newline-free, falling back to its error
     CODE. Nine per-service extractors that fell back to `string(body)` when they could
     not parse are bounded the same way. This is the read side's D296 rule, finally
     applied to the half that publishes.
  2. VALUE-BASED — the driver remembers the credential values the candidate's
     `implementation` block handed it and removes those exact strings from the Reason at
     the Create/Update boundary. Exact removal, not pattern-guessing: it never has to
     recognise a provider's message format and cannot miss a secret it was given. The
     redaction is VISIBLE (`[redacted-credential]`) so an operator can tell it from
     truncation, and the set is cleared per action so action N's credential can neither
     leak into nor redact action N+1. Key matching is deliberately narrow — `kms_key`,
     `key_vault_key` and friends name a key RESOURCE, and redacting those would blind the
     operator to which key was refused while protecting nothing.

What defence 2 does NOT cover, stated plainly: a secret the driver never saw (one the
provider minted itself and volunteered in an error). Defence 1 is what bounds that, and
nothing here can promise more.

Gate: `TestNoRawBodyInDriverDiagnostics` — no `string(body)` in a driver diagnostic, and
no body truncator may be reintroduced. It scans EVERY provider package, not just the
three big clouds: the receipt channel is the same one whatever wrote the resource, and
the k8s driver carried the identical paste (three sites + its own `truncate`) until the
widened gate found it. It has no budget; unlike the read-side ratchet it
went in with the debt already paid, so it is an invariant from birth. Verified by
injecting both shapes and watching it fail.

Completeness audit of the same channel, so the claim is bounded by what was checked and
not by what was fixed: `Reason` is the ONLY free-text field on a CreateResult —
`ProviderID`/`OperationID` are validated identifiers, and every declared output across the
three clouds is an identifier, endpoint, ARN, region or port (no credential-shaped name
exists, checked by name). Apply reconstructs a Reason in exactly one place (a declared
output that fails its kind) and that text echoes the Go TYPE, never the value. The other
provider packages carry their bearer token in a header from the environment, never from
the candidate, so the value-based scrub is wired where credentials can actually flow
(AWS/GCP/Azure Create+Update) rather than everywhere for symmetry.

The THREAT_MODEL row that claimed "the D53 boundary scan" covered
"ledger/observations/capsules" was an overclaim of the same family D287 corrected: D53's
control is an allowlist on the tf/pulumi STATE IMPORT path and never touched the receipt
channel. It is now three honest rows — hints (D53), receipts (D309), and observations
(structural: an observation is a typed vocabulary attribute and no vocabulary declares a
credential-valued one). make check + race clean; 467/467 conformance.

## D310. GCP parity: Cloud Functions VPC + env, Cloud SQL connection output
The GCP twin of D308 — a Cloud Function reaches a private Cloud SQL by $ref, not a
literal — on the D307 guard so the new operands are recognized, not refused.
  - **Cloud Functions gen2**: `implementation.vpc_connector` → `serviceConfig.vpcConnector`,
    `vpc_connector_egress_settings` → `vpcConnectorEgressSettings` (enum, refused without a
    connector), `environment` (map) → `serviceConfig.environmentVariables`. Registered in
    `ConsumedOperands["cloudfunctions-fn"]`.
  - **Connector wiring is a LITERAL, not a $ref** — a deliberate per-cloud difference.
    AWS Lambda $refs `vpc.privateSubnetIds` because it attaches directly to subnets; a GCP
    function attaches to a Serverless VPC Access CONNECTOR, a distinct resource groundhold
    has no capability for (the vocab calls connector wiring implementation noise). A
    regex-validated `projects/P/locations/L/connectors/NAME` is the honest mapping; it
    wires no dependency edge.
  - **Cloud SQL connection output**: `connectionName` (project:region:instance) is fully
    pid-derived — no read, always attestable; it is the canonical connection identifier the
    Cloud SQL Auth Proxy actually uses. `privateIpAddress` + `port` come from one
    instances.get (server-assigned). Per-cloud honest and deliberately UNLIKE aurora, which
    has no pid-derivable identifier and so demotes wholesale: cloudsql always publishes
    connectionName, adds the private endpoint only when a PRIVATE address exists, and a
    public-only instance publishes connectionName alone (never a fabricated endpoint). A
    consumer that $refs an absent private endpoint refuses at apply; a permission gap on the
    read is caught upstream by the D75 preflight (`cloudsql.instances.get` is in the create's
    required permissions), and a transient read failure self-heals on converge retry.
The D308 compiler map-value-`$ref` walk is provider-agnostic, so GCP `environment` gets
resolution for free — no compiler change. `cloudfunctions-fn` stays create-only (operand
drift → replacement, consistent — no disproportionate update path added). Azure Functions
has no driver (a pre-existing gap, tracked separately) — parity for function.serverless is
AWS+GCP. Pinned by `conformance/cases/cloudfunctions-vpc-env.yaml` (literal connector +
`environment.DATABASE_HOST` ← cloudsql.privateIpAddress map-value-$ref; a D307 regression).
make check 469/469 both impls, golangci + race + differential clean.

## D311. An attribute's evidence class belongs to the vocabulary, not to 190 hand-written cases
Found while looking for the next debt after D309. The vocabulary already said, in
PROSE nothing can read (`verification: static against a pricing catalog...`), that
`cost.monthly` is a forecast and `recovery.rto` a probe outcome — neither is resource
state. The engine then re-encoded that fact by hand **190 times**: a two-item switch in
the compiler (`isProjectionAttr`, which D249 itself called "a two-item hardcoded patch"
while generalizing only the machinery around it), ~124 no-op `case "cost.monthly":` arms
in driver BUILDERS, and ~65 more in `ClassifyChange`.

The no-op arms were not stylistic. A builder REFUSES any attribute it cannot map
("refusing rather than silently dropping it"), so without its arm a contract declaring
`cost.monthly` failed at Validate for that service. Adding one attribute of this class
meant editing ~50 Go files across four provider packages — the exact opposite of the
zero-engine-changes property a declarative vocabulary exists to give (D23/D55).

D311 makes it declarative. `evidence:` is a closed set on the attribute —
`resource` (default, omitted) | `projection` | `probe` — and:
  - the compiler DERIVES its projection skip from it (the hardcoded pair is gone);
  - `attributesRaw` filters such attributes out at the contract→driver BOUNDARY, so a
    builder never sees one and needs no arm. This was the architectural choice: the
    alternative (drivers consulting the vocabulary in their default arm) would have kept
    the pure builders honest but coupled them to the type system and still required ~50
    edits — the boundary filter costs one edit and zero future ones.

Behaviour is unchanged by construction: the derived set is exactly {cost.monthly,
recovery.rto}, the pair the switch hardcoded. An absent vocabulary yields the zero
Vocabulary, which classifies everything as resource state — the pre-D311 path — so a
caller without a type system loses nothing.

Proving it rather than asserting it, because "green after a 231-file refactor" can also
mean "nothing exercised it":
  - `TestProjectionSkipIsDrivenByTheVocabulary` runs the same input twice, once with the
    declared class and once with it stripped, and requires the second to REFUSE. The
    discriminating case is a capability with NO observations — there D249's
    observed-but-blind rescue does not apply, so only the projection skip prevents an
    ObservationRequired refusal. (Checked first: with observations present, D249 and the
    skip agree, so the obvious test would have passed either way and proved nothing.)
  - `TestARealDriverAcceptsACandidateDeclaringAProjection` drives a REAL driver through
    Preflight with `cost.monthly` declared. Remove the filter and it fails with the
    driver's own words: "attribute cost.monthly has no SNS mapping". That is the end-to-end
    pin for the 124 deleted arms — nothing else in the suite covered them.

Two gates, both verified by injecting the violation: `TestNoDriverHardcodesAnEvidenceClass`
(no `case` arm in any provider package may name such an attribute — producing one is fine
and expected, a probe EMITS recovery.rto and the compiler READS cost.monthly for the risk
projection) and `TestEveryDeclaredEvidenceClassIsInTheClosedSet` (a typo like
`projektion` would silently restore the default and make a reconcile block forever on an
observation that can never arrive). spec/vocab/AUTHORING.md §7 documents the class and the
checklist requires it. make check + race clean; 469/469 conformance.

## D312. Adversarial audit of restore: two real holes, one hardening, one stale claim
`restore` is the highest-stakes surface the adversarial series (D182–D195) never covered
as a subsystem — it is what you run when everything else is gone, and a fail-open there
produces a "recovered" history nobody checked. Findings, each proved with a failing test
before any fix:

**1 — an anchor with no ledgerId silently disabled three identity guards.** The
foreign-capsule check, the genesis-presence check and the restored-identity check were
each written `if anchor.LedgerId != "" { … }`, and `LoadAnchorFile` accepts any document
whose kind is LedgerAnchor. So an anchor with the id stripped turned all three off and
restore still reported `status: restored`, exit 0 — for a capsule set it had never proved
belongs to one history. A guard conditional on the very field it guards is not a guard.
`Anchor.RequireIdentity()` refuses it as operator input, the three conditionals became
unconditional, and the same shape in `VerifyCapsule`'s anchor branch is closed too.
Deliberately NOT enforced in `LoadAnchorFile`: two callers load an anchor opportunistically
(attest facts, trust arming) and must keep degrading quietly — the rule belongs where the
anchor is used AS PROOF. Honest scope: a foreign capsule was still caught in this scenario
by the anchor head pin, so what was lost is the identity PROOF, not (in that one path) the
outcome; the second test records that defence-in-depth rather than overclaiming.

**2 — the `--partial` failure code was author-controlled.** `capsule-trust-refused` vs
`capsule-tampered` was decided by substring-matching the verification error for "key",
"signed", "trust"… and several of those messages embed the CAPABILITY NAME. A capability
called `api-keys` therefore reported every structural corruption as a trust refusal. This
is the spoofable-substring class D62/D73 already ruled on ("substring matching over text
that embeds user-controlled ids is spoofable"), reappearing in a subsystem written after
that ruling. The class is carried by a typed `ledger.TrustError` now. Note: no test
covered `capsule-trust-refused` at all, so the typed error could have made that code
unreachable and every existing test would still have passed — pinned in BOTH directions.

**3 — determinism hardening, not a bug.** Two later checks (the full-mode manifest gate,
the restored-head check) walked raw maps and returned on the first offender, so the
reported capability could differ run to run. Both are sorted now — but the honest finding
is that they are SHADOWED by the sorted classify loop, which refuses first, so no
nondeterminism was reachable. The test pins the property where it is real (the classify
loop); it catches an unsorted loop across 40 runs and would be vacuous if pointed at the
shadowed checks.

**4 — a stale claim in the code.** `restore.go`'s header said "the documents layer is
still a later slice" long after slice 4 shipped it in `backup --documents` +
`VerifyDocuments`. Corrected to say what is actually true: restore rebuilds the decision
history and says nothing about the contract blobs those decisions referenced; a recovery
that needs them runs the document verify separately.

make check + race clean; 469/469 conformance.

## D313. Adversarial audit of backup: capsule DR and compaction are mutually exclusive, and nothing said so
Continuing D312 into the rest of the DR family. The first hypothesis was that `backup` of
a compacted ledger would report success and produce a set restore always refuses (the
anchor's `Events` is ABSOLUTE across snapshots, while capsules carry only the live tail).
Tested rather than assumed — and it was WRONG in the good direction: `EmitCapsule` already
refuses a capability whose chain begins in the archive, and `backup` propagates it. The
system was honest. What the probe found instead:

**1 — the limitation is total, and was undocumented.** A capsule is a chain from GENESIS,
so after `snapshot` every capability whose history predates it cannot be emitted — in
practice all of them. Capsule DR and compaction cannot both be used on one ledger. D143
(the DR entry), spec/capsule.md and MATURITY's "gaps we are NOT hiding" all omitted it. It
is now MATURITY gap 8.

**2 — the refusal advised a workaround that does not work.** The message said "emit the
capsule from the archive file (D137)". Following that advice literally: archive-emitted
capsules end at the PRE-snapshot head, the live anchor pins the post-snapshot one, and
restore refuses them as stale — correctly. Combining archive and live capsules for one
capability does not help either: the two event sets are disjoint, which merge adjudicates
as a fork. An error message that names a workaround is a promise; this one was empty. The
message now says what is actually true (preserve the archive files themselves), and a test
pins that the archive route does NOT satisfy the live anchor, so the advice cannot return.

**3 — a refused backup left a plausible artifact behind.** `backup` created the output
directory and wrote `anchor.json` (and any capsules emitted before the failing one) and
only THEN refused, leaving a directory an operator — or a cron job checking for a path —
cannot distinguish from a good backup, whose emptiness would be discovered during the
disaster. Restore already obeys the opposite discipline (it removes the ledger it wrote
when the replay refuses). `backup` now detects the compacted case UP FRONT, before creating
anything.

Also checked and found sound, recorded so the next audit does not re-tread: the Azure
`subMismatch` guard skips when either subscription is empty, but `armURL` then refuses the
read outright (fail-closed, not a cross-subscription read); `MergeAnchorPolicy` refuses a
disagreeing policy and a trust-less anchor cannot downgrade an armed one; `backup` already
sorts its document manifest. make check + race clean; 469/469 conformance.

## D314. AWS Lambda joins the resume reconciler — the in-flight create can be concluded
Field finding (Acme live, F-LC1): a converge/apply KILLED mid-create of a Lambda (ENI
provisioning in a VPC takes >2min; their foreground timeout fired) left an in-flight
operation in the ledger, and every later run went STALE ("in-flight operations must be
reconciled first", D29). `resume` then answered "aws reconcile for service lambda is not
wired yet — reconcile manually" — so the ledger was PERMANENTLY stuck, even though the
Lambda really was created and Active. D314 wires lambda into the AWS reconcile dispatch
(`reconcileLambda`, beside `reconcileECS`, which it mirrors — they even share `ECSName`).
Reconcile recomputes the DETERMINISTIC name (so it works for a write-ahead receipt that
predates any persisted id — no providerId ambiguity), reads `GetFunction` (observable
state, never an operation-by-id — D273) and concludes: Active+LastUpdateStatus∈{Successful,
""} → succeeded with the pid; Failed → failed with the reason named; Pending/InProgress →
poll to terminal within the bounded LRO window, deadline → unknown WITH pid (resume is
re-runnable); a readable 404 → failed ("the create did not land"), never a fabricated
success; foreign tags → unknown (refuse to attribute a function that isn't ours); a read
error → unknown WITH pid and the cause named (the typed `awsReadError`, D306). Reuses the
shared `concludeByStatus`; enrolled in the generic reconcile-invariant runner (succeeded
holds iff found∧ready∧ours) plus eight golden tests including an anti-regression that fails
if reconcile ever hits an operation-by-id path.

Honest boundary surfaced (out of scope here, flagged for a follow-up): the reconcile
framework concludes a create by writing `binding.updated` (providerId only) and does NOT
re-attach typed create OUTPUTS the way the apply path does. For lambda this is a no-op
(lambda declares no outputs). But for an output-DECLARING service (vpc/aurora/…), a create
concluded by `resume` rather than `apply` would not repopulate `ledger.Outputs`, so a
same-plan `$ref` consumer would lack the wiring record — a latent gap in the resume path
worth closing separately (it bites exactly the Lambda-$ref-Aurora shape when the Aurora
create is the one that gets killed). make check 469/469 both impls, golangci + race +
differential clean.

## D315. Adversarial audit of export: the handover surface was laxer than the fold
Third round of the DR-family audit (after D312 restore, D313 backup). `export` is the
handover surface — what a receiver, a SIEM or a downstream 4D view consumes — and it
verifies the chain and the signatures itself rather than replaying. That independence is
deliberate (it streams, replay folds), but it had drifted laxer than the thing it mirrors.

**1 — export accepted a ledger replay refuses, then silently shortened the stream.**
`ValidateEvent` requires `occurredAt` to be a quoted string but never PARSES it, despite
its own message promising RFC3339. `ReplayFile` does parse it and refuses the file. Export
neither replays nor parses — so it accepted such a file, and under `--from/--to` dropped
the unplaceable event with a bare `continue` whose comment called it "honestly outside any
bounded window". It is not honest: the consumer gets a short stream with nothing saying an
event was withheld, from a file the rest of the system considers corrupt. That is the
silent drop D53 forbids elsewhere, on the surface where it matters most. Fixed at both
ends — `ValidateEvent` now enforces what it promises (so the writer path is strict too),
and export refuses a bad `occurredAt` per line, with the window filter's former `continue`
turned into a loud refusal in case it ever becomes reachable again.

**2 — a blank line renumbered the entire export.** Two things keyed off the RAW LOOP
INDEX rather than the event count: the D134 identity pin (`if i == 0`, which a leading
blank line consumes, so `ExpectLedger` never ran — a deliberate cross-check skippable by
whitespace) and the exported `index` field itself (`base + i`), which is precisely what a
consumer correlates, dedupes and anchors on. One blank first line shifted every record's
index by one while the content stayed identical. Both now count EVENTS. Honest note on
severity: the identity half is hardening rather than a demonstrated hole, because
`verifySig` binds the ledger id into the signed message, so a consistent file is caught
there anyway; the renumbering half is a real output defect.

Also checked and found sound: the `--trust-from` boundary cannot be slid (the tolerated
unsigned era is bounded by hash linkage, not by position) and `Finish` refuses a file
missing the boundary; `SeedBoundaryHonored` is guarded at both call sites by the snapshot
receipt naming EXACTLY the armed boundary, and seeding makes verification stricter, not
weaker; export already buffers its whole output so a mid-stream refusal cannot leak
unverified lines into a pipeline. make check + race clean; 469/469 conformance.

## D316. Public serverless without anonymous exposure — CloudFront+OAC → IAM Function URL
Field finding (Acme): their org RCP blocks anonymous Function URL invoke (`Principal:*` →
403), so the only groundhold path to a public serverless frontend/api — a Function URL with
`AuthType=NONE` — was a dead end. D316 builds the AWS-correct alternative: CloudFront with an
Origin Access Control (OAC) that SigV4-signs the origin request to a Function URL with
`AuthType=AWS_IAM`. The invoke is signed, not anonymous, so the RCP never triggers, and the
viewer still gets public HTTPS at the edge. Three pieces wired by `$ref` (D226), one acyclic
edge:
  - **function.serverless** gains `implementation.url_auth: iam|none`. It is orthogonal to
    `network.publicExposure`: publicExposure decides WHETHER a Function URL exists, url_auth
    decides HOW it authenticates. `iam` → `AuthType=AWS_IAM` with NO anonymous `Principal:*`
    grant; `none` → the prior `AuthType=NONE` + public grant; `iam` refuses on a non-public
    function (fail closed — no URL to refine). observeLambda now maps publicExposure=true for
    ANY URL (the AuthType is implementation noise, invariant #4). Lambda gains its first
    outputs: `functionArn`/`functionName` (pid) and `functionUrl`/`functionUrlDomain` (one
    GetFunctionUrlConfig read; a private function's clean 404 OMITS them, never demotes).
  - **cdn.distribution** gains `origin_domain` ($ref-able — the compiler wires $ref from the
    `implementation:` block only, the D279 loadbalancer pattern), `origin_access: oac`, and
    `grant_invoke_lambda`. Create issues CreateOriginAccessControl (always/sigv4/lambda) then
    CreateDistribution with the OAC on the origin; reverse-delete tears the OAC down. Outputs
    `distributionArn` + `domainName` (the public URL).
  - **The invoke grant — Model 2 (chosen over Model 1 to keep the DAG acyclic).** The
    distribution grants ITSELF invoke on its origin lambda: after CreateDistribution returns,
    it issues `lambda:AddPermission` (principal `cloudfront.amazonaws.com`, action
    `lambda:InvokeFunctionUrl`, `FunctionUrlAuthType=AWS_IAM`, `SourceArn` = its OWN post-create
    ARN — least-privilege, one distribution, never a literal). DAG: `a-create-fn` (no deps) →
    `a-create-cdn` (dependsOn fn; references origin_domain→fn.functionUrlDomain,
    grant_invoke_lambda→fn.functionArn) — a single edge. Model 1 (a lambda operand $ref-ing the
    distribution ARN) was rejected: it makes lambda depend on cdn while cdn already depends on
    lambda → a cycle, breakable only by a second lambda action the one-per-capability model
    can't express. The cross-driver AddPermission is preflight-covered (cloudfront's create
    permissions declare `lambda:AddPermission`, so D75 refuses before mutating on a missing
    grant). Pinned by `conformance/cases/cdn-oac-lambda.yaml` (the full acyclic DAG + a D307
    regression that the new operands don't trip unknown-operand). Five aoss/cloudfront API
    shapes (OAC body + lambda origin type, AddPermission SourceArn condition, ARN format,
    OAC-on-custom-origin) flagged for Acme live validation. make check 471/471 both impls,
    golangci + race + differential clean.

## D317. create → observe was never gated, and a scrape cannot measure observability
Chasing MATURITY gap 4 ("several declared attributes cannot be read back"), the first job
was to turn "several" into a number. It ended somewhere more useful than a number.

**The measurement failed, and that is the finding.** Four successive static scrapes of the
drivers gave four different answers, each wrong for a different reason: keyed
`Observation{Path: …}` literals missed the positional `Observed{"path", …}` form; a
two-level call closure missed observers that build through pure reverse-map helpers; the
per-service dispatch parser mis-assigned case lists; and finally `sbObserve` — an observer
that does not match the `observeXxx` naming convention — was never collected at all, so its
two services silently inherited the next function's attribute set. A number produced that
way is not evidence, and this repo does not publish claims it cannot prove. The lesson is
the one the Certify family already encodes (CertifyDriver → CertifyDiscoverability →
CertifyParity): a property of the drivers is proven by ASKING THE DRIVERS, never by reading
their source. MATURITY gap 4 therefore stays qualitative until an
`ObservableAttributes()`-style declaration exists to prove against.

**What the probe did find, provably.** The completeness family had an asymmetry: since D210
every service that can be CREATED must have a `ClassifyChange` or sit on an explicit
burn-down allowlist — but nothing gated create → OBSERVE, the more fundamental half. Without
an observe, a bound capability can never be reconciled against reality: D249 marks every
declared attribute unverified and converge reports inconclusive forever. `TestObserveCompleteness`
now pins it on all three clouds, in both directions (a create with no observe; an observe
with no create — a stale or discover-only case), reusing the existing dispatch-parsing
helper rather than function names, so it is immune to the naming trap above.

Deliberately NO allowlist, unlike its ClassifyChange sibling: an unwired ClassifyChange is
an honest burn-down (the D215 default still replaces on drift), whereas a create with no
observe is a capability the runtime can build and then never check. If one is ever
genuinely unobservable, that belongs in the vocabulary as an evidence class (D311), not as
an exception in a test.

The property holds today on all three clouds (aws 50/50, azure 41/41, gcp likewise) — the
gate is a floor for what comes next, not a repair. Verified by injecting a create case with
no observe and watching it fail. make check clean; 471/471 conformance.

## D318. Lambda lifecycle closes — operand drift, recreate-on-absence, adopt intent (F-LC3)
Three gaps Acme hit live after D308/D314 stood up their Lambda-in-VPC. Each is a contained,
independently-tested slice; two general gaps are flagged, not unilaterally redesigned.

**Part 1 — operand drift triggers update-in-place.** D308 added `UpdateFunctionConfiguration`
but nothing CALLED it: `classifyBound` only compared typed vocab attributes; implementation
operands (`subnets`/`security_groups`/`environment`/`image_uri`) live in `Extras…implementation`
and were never diffed — so changing them on a bound Lambda was a silent no-op (the F16/F25
class). Fix, extending the existing engine not paralleling it: an opt-in `provider.OperandDrifter`
interface (mirrors the `ClassifyChange`/`Claimer` delegation), `observeLambda` reads back live
VpcConfig/Environment/image under reserved `implementation.*` paths canonicalized identically to
the declared side, and one delegated operand-drift loop in `classifyBound` (reusing
`ClassifyChange` + a shared `stalenessRefusal` helper) routes a real difference to update
(env/VpcConfig via UpdateFunctionConfiguration, image via a new UpdateFunctionCode) or replace.
F16/F25 was NOT re-litigated — only Lambda opts in.

**Part 2 — recreate after an out-of-band delete (general gap, Lambda slice).** No driver today
turns a vanished bound resource into a recreate — every one emits "not found — nothing to
observe" and the binding stays `succeeded` → no-op forever. Fix: `observeLambda` emits the
reserved `provider.ResourceAbsentPath` true on a READABLE GetFunction 404 (a real absence, nil
error) and false on a present function (a stale "gone" self-heals after recreate); the compiler
plans a `create` (same deterministic identity) for a bound capability carrying a fresh
`resource.absent=true`. A read ERROR (transport/5xx) stays an error → unknown → blocks — the
four-valued split (readable-404→recreate vs read-error→unknown) is the honesty guard against a
transient blip triggering a spurious recreate. The mechanism is general; only Lambda emits the
marker today — other drivers still no-op on out-of-band delete until they do (flagged).

**Part 3 — adopt records non-observable declared attributes as intent (owner-decided).** The
earlier rule refused any declared attribute the driver cannot observe ("adoption cannot confirm
it"). The owner reversed it: a NON-OBSERVABLE declared attribute is INTENT, not a lie. Adopt now
records it as an `observation.recorded` with the candidate's OWN provenance (source
`candidate-declared`, derivation = the candidate's basis, never `measured`), so invariant #3
survives; the audit evidence lattice ranks it 0 (satisfies a `static` constraint, rejected for
`provider-api`/`probe`), so intent NEVER passes for measurement. The honesty boundary is exactly
preserved and re-pinned: the discriminator is "did observe emit a value for this path?" — not
emitted → intent; emitted but MISMATCHED → still refuses ("reality says …"), because that is a
lie. `recovery.rpo` IS observable (rds/aurora emit it), so Acme's declared 60s vs real 5m stays
an observable mismatch and STILL refuses — it does not become intent.

Invariant #5 note (transparent): Part 3 directly contradicts the prior conformance case
`onboarding-adoption-must-not-lie` (which pinned "non-observable declared attr refuses"). Because
the owner reversed that exact semantics, the case was repurposed to
`onboarding-adoption-records-non-observable-as-intent` (exit 0, adopted). This is the one
existing expectation edited, driven by an owner decision, not to make failing code pass — and the
preserved boundary (observable mismatch refuses) is pinned by the Go test
`TestAdoptRefusesObservableMismatch` because the conformance Fake observes only `service.managed`
and cannot express an observable mismatch. make check 471/471 both impls, golangci + race +
differential clean.

## D319. Adversarial audit of the MCP boundary: a confirmation token pinned the plan, not the decision
The MCP server is where an untrusted (or prompt-injected) agent meets the runtime. It was
hardened once in D73 but never audited as a subsystem, which made it the highest-stakes
surface left after the DR family (D312/D313/D315).

**The finding.** `groundhold_apply` is a structural two-step: the first call returns
`confirmation_required` with the plan text and a short-lived, single-use token; the second
call spends the token to execute. The token pinned `hash(plan)` — and nothing else. But the
argv apply actually runs is `(plan, contract, candidate, ledger, vocab, provider, at)`, and
the confirmation payload displayed only the plan. So a token obtained for "apply plan P
against ledger A on gcp" could be spent on "apply plan P against ledger B on aws": the hash
matched, the token was valid, and bindings landed in a ledger nobody reviewed. Proved with a
test that watches the redirected argv actually execute.

The package is explicitly honest that the token does NOT authenticate a human (it is
delivered in-band to the same client, so an autonomous agent completes both steps alone).
This finding is narrower and survives that caveat: whatever the token DOES pin should cover
the decision it displays. A confirmation that shows one destination and licenses another is
not a weaker gate, it is a wrong one.

**The fix.** The token now binds `applyTarget` — a canonical fingerprint of contract,
candidate, ledger, vocab, provider and at — alongside the plan hash, and the
`confirmation_required` payload SHOWS that target so the displayed decision and the licensed
decision are the same object. A second call that changes any of it refuses with a distinct
reason rather than silently succeeding. `applyTarget` carries a note that any new apply
argument must be added there too, or the token stops covering the decision.

**Second, smaller finding.** Tokens were removed only on redemption, so a long-lived server
accumulated one per confirmation forever — an unbounded map fed by an untrusted client.
Issuing a confirmation now sweeps expired entries; pinned by a test.

Also checked and found sound: `rejectFlagLike` covers every path argument, and `provider`/`at`
cannot inject a flag because they are separate argv elements the child never re-parses;
`confineToWorkspace` refuses absolute paths and `..` escapes; the token is 16 bytes of
crypto/rand and FAILS CLOSED if the RNG errs, rather than issuing a guessable one. make check
clean; 471/471 conformance.

## D320. The output speaks — four UX gaps Acme hit running converge/apply live
Field feedback: long operations show silence, apply kills everything on one error, no-op says
nothing, and a killed run STALEs with no way out named. Four contained slices, no new banner
vocabulary (spec/presentation.md stays closed).

**A. apply isolates independent actions (was fail-fast).** The loop returned exit 4 on the first
non-success, so one failed action stripped every INDEPENDENT sibling — Acme had to gut their
contract to the core to make progress. apply now walks the whole DAG: each action's outcome is
recorded, an action whose `dependsOn` includes a non-succeeded action is SKIPPED (transitive — a
replacement's delete skips when its create failed), but independent branches still run. Write-ahead
discipline is untouched (every action that reaches its driver still writes pending→terminal
receipts; `unknown` keeps pending, `failed`/`retryable` clear it), and exactly one run-level
terminal marker is written after the DAG. Exit code = worst outcome
(unknown > failed > throttled > skipped > succeeded); a new omitempty `Outcomes` map carries the
per-action verdicts and `Reasons` list the non-successes in DAG order (first failure stays first,
preserving existing assertions).

**B. no-op says why.** A bound capability with no action now records a `NoOpCapability{reason}` and
renders one honest line — `bound, observed==declared` / `bound, no diff` / `bound, unwitnessed —
nothing to observe` — on the plan's stderr channel and converge's human surface, instead of a
silent "nothing happened". Go-only (the Python side is a plan loader), omitempty so a
work-carrying plan is unchanged.

**C. STALE points to resume.** The reconcile-required refusal already carried a resume `next`
(perrnext, with `--at`), but converge extracted only `reasons`. It now surfaces the child's
`next.command` + note, so a killed run prints the exact `groundhold resume … --at …` to run rather
than a dead end.

**D. LRO heartbeat goes live off a real source.** The D227 addendum shipped the provider-wait/tick
machinery but gated it on drivers exposing incremental polling; drivers now do (`d.progress`, D257).
Two honest gaps closed: the first driver heartbeat transitions an action `running → provider-wait`
(the gated state, unblocked exactly as the addendum prescribed) and ticks within it carrying the
provider phase + MEASURED elapsed; and the `ProviderPhase` — previously carried on the stream but
DROPPED by both renderers — now reaches the human (plain `phase=…`; a TTY row), only when non-empty
(so no render golden changed). Never fabricated: the phase/elapsed come from the driver's real poll.
Still gated, flagged honestly: stalled auto-demotion (needs a wall-clock watchdog), the ETA band
(needs a durable timing source, D227), and converge live-streaming (its SelfRunner buffers the apply
child's stderr, and interleaving with the D232 sticky checklist is a larger change — direct `apply`
streams the heartbeat live today). make check 471/471 both impls, golangci + race + differential
clean; no render golden changed.
## D321. Adversarial audit of the gentle crawl: gentleness was optional
`pace` calls itself "the anti-DoS policy in ONE place" — the promise groundhold makes to
someone else's cloud account. It had never been audited, and it is the one subsystem whose
failure lands on a third party rather than on us.

**The finding.** `waitToken` waits only when `b.tokens < 1 && s.pol.Rate > 0`. With `Rate`
left at zero the second clause is false, so no wait is ever taken: the bucket goes negative
and keeps going, and the scheduler issues calls as fast as the caller can loop. A negative
Rate does the same. One unset field turns the rate limiter off — silently, and in the
direction that hammers a customer.

Scope, honestly: the CLI never reaches it (both entry points start from `DefaultPolicy()`
and only override `Budget`, and only when positive), so this is a library fail-open, not a
live incident. It still matters, because it is the shape this repo refuses everywhere else
— a safety clock fails closed (N1), an unpredictable confirmation token is not issued
(D50). A safety component that does nothing when partially configured is worse than one
that is absent, because the caller believes it is protected.

**The fix.** `New` floors every non-positive field to its `DefaultPolicy` value. Gentleness
is not optional: a caller can ask for MORE (an explicit fast rate is respected, pinned by a
test) but never for none by omission. The substitution is not silent to the operator —
`Scheduler.Floored` names which fields were replaced, `Scheduler.Policy()` reports the
EFFECTIVE policy, and the crawl's honesty block now carries `rate`, `burst` and
`policyFloored` alongside `requestsMade`. An honesty block that says how hard we leaned on
the world must also say under which limits, or `requestsMade: 2000` is unreadable. Those
fields are excluded from the content hash by construction (`contentModel` already omits
crawl stats), so identity is unaffected.

Also checked and found sound: `AuthError` returns before touching the failure counter and
is never retried (401/403 is a pairing problem, not a throttle); the budget is checked
inside the attempt loop, before each call, so retries cannot exceed it; the breaker is
consulted at entry and trips on consecutive failures with the counter reset only on OK; an
explicit `Retry-After` wins over the computed backoff verbatim. make check + race clean;
471/471 conformance.

## D322. Adversarial audit of adopt: an assumption reality contradicts was skipped in silence
`adopt` is the only door for infrastructure groundhold did not create, and its own first
line is that it "must not lie": every declared attribute is checked against a live
observation before the binding is written.

**The finding.** A declaration with `status: assumed` is exempt from that gate — correctly.
An assumed value claims an assumption, not reality; provenance survives (D5) and policy can
gate satisfied-but-assumed on hard constraints separately (D195). What was wrong is the
SILENCE: adopt has already called Observe and is holding the contradicting value in its
hand when it hits the `continue`. The operator adopts believing
`network.publicExposure: false` while the live reading says `true`, at the one moment in
the system designed to confront a declaration with the world — and nothing is said, because
the result document had no channel for a fact that is neither a refusal nor a binding.

That is a lie of omission of exactly the kind the package's first line forbids. It is
narrow: the assumed exemption is right, the binding is right, and a later audit would
eventually surface it. But "eventually, somewhere else" is not the same as "at the moment
you took ownership".

**The fix.** `Result.Notes` carries facts the adoption OBSERVED but did not refuse on, and
a contradicted assumption is the first of them. The exemption is untouched — adoption still
succeeds, the value is still recorded with its own provenance — but the report now says
"assumed false, the live observation reads true; adopted anyway, and the assumption is
wrong". The CLI prints notes to stderr so the result document stays machine-clean. Pinned in
both directions: contradicted assumptions produce a note, agreeing ones stay quiet (an
exemption that starts shouting on every assumed value would be its own defect).

Also checked and found sound: the double-adoption projections refuse in BOTH directions
(capability already bound, providerId already owned by another capability); pending
in-flight operations refuse with reconcile-required before any binding; the competing-
reconciler gate fails CLOSED (an error proving nothing refuses too, so it cannot be bypassed
by making the check fail); a protocol attribute is confirmed at the DECLARED granularity, so
`postgresql/16` is confirmed by `16.13` but `postgresql/16.5` is not — declared precision is
what must be true. make check + race clean; 471/471 conformance.

## D323. The N1 gate checked that the clock was PRESENT, never that it PARSES
Found while auditing `posture` (the proactive classifier, never audited). The bug is not in
posture — it is in invariant 0 itself.

**The finding.** `timeSensitiveVerbs` refuses a missing `--at` with a message that promises
"(RFC3339 timestamp)" and explains that "a safety clock must not default to the epoch and
make stale observations look fresh". It only ever checked `atProvided`. `--at not-a-time`,
`--at 2026-07-25` (date-only) and `--at 1752600000` (unix seconds) all sailed through, and
every downstream site reads the clock with the error discarded:

    classifyPosture   atSec, _   := ledger.ParseTs(at)   -> 0
    runStatus / runs  nowClock, _ := ledger.ParseTs(at)  -> 0

At `atSec == 0` the decay test `observedAt + ttl <= atSec` is false for EVERY real
observation, so nothing is ever decayed and a capability whose proof expired years ago
reports `managed-ok`. `status`/`runs` judge lease-TTL liveness against the same zero, which
D229 called out by name as "exactly the stale-freshness lie N1 forbids". So the gate that
refuses an ABSENT clock waved through a BROKEN one, into the precise failure it exists to
prevent.

The class is the one D315 found in export (an unparseable time silently becoming zero),
except here it lands in a decision rather than a diagnostic, and it defeats a stated
invariant rather than shortening a stream.

**The fix.** The gate enforces what it always claimed: a time-sensitive verb refuses an
`--at` that does not parse as RFC3339, naming the value and why a non-parsing clock is
dangerous. Four malformed shapes are pinned, and a well-formed clock is pinned to still
pass — the gate must reject malformed input, not narrow what a legal timestamp is.
`classifyPosture` also refuses a bad clock directly: it is the function that decides
freshness, and a safety decision must not rest on a caller having validated its input.

Also checked in posture and found sound: `decayed` is tested BEFORE `satisfied`, so a
satisfied-but-stale capability is decayed and never green; the decay loop is total over the
bindings (a capability with no observations at all is decayed, not skipped); `unverifiable`
is honest unknown rather than green or red; shadow rows carry a remediation that refuses to
delete what groundhold does not manage (adopt-then-retire, so the delete flows through every
gate); the content hash covers the CLASSIFICATION only, so prose and `--at` cannot change
identity. make check + race clean; 471/471 conformance.

## D324. Prose has no gate, so it rots: the counts that shape how the project is understood
The last item on MATURITY's own "gaps we are NOT hiding" list that could be closed without
a live cloud was #6, "README roadmap is stale". Closing it turned up something better than
a refresh.

**The gap entry was itself stale.** It said the README "stops at ~D64/D75" with the breadth
drivers, the substrate and the adversarial series "not reflected there yet" — but someone
had since added both a frozen-by-intent preamble and a "Since the vertical slice" summary
carrying exactly those. A gap list that overstates its own gaps is the D287 failure in
miniature, pointed the other way, and it is worth saying out loud: the entry now describes
the real relationship (the README summarises, DESIGN.md is the record, the summary will
always trail).

**Two numbers had drifted, in the files that shape a reader's model of the system.**
CLAUDE.md — the first thing any contributor reads — claimed "153 conformance cases … six
vocabularies" against a real 471 and 52, understating the project threefold. The README
claimed "~128 service mappings across AWS (46), GCP (41), Azure (41)"; the drivers certify
133 mappings (50/42/41), and 46/41/41 were the distinct capability TYPES — a conflation this
repo cares about specifically (D76: one type, many services; rds and aurora both fulfil
`capability.database.relational`). Both corrected from the drivers' own certified
`ServiceCapabilities()` maps and a directory listing, never from prose or a source scrape
(D317).

**The fix that matters is the gate, not the edit.** `TestDocServiceCountsMatchTheDrivers`
and `TestClaudeMdVocabularyCountMatchesDisk` compare the documented counts against the
drivers and the vocabulary directory, so the next drift fails CI instead of quietly
misinforming a reader for months. Verified by editing a count and watching it fail. The gate
deliberately covers only the numbers a reader uses to judge the SIZE of the system — the
ones that actually drifted — rather than trying to police every figure in the docs, which
would be a gate nobody could keep green.

CLAUDE.md also now says where to read each number from, so the next person updates the tool
output rather than a sentence: `make check` for case counts, `ServiceCapabilities()` for the
per-cloud totals. make check clean; 471/471 conformance.

## D325. Invariant 1 was enforced only if the plan asked for it
Auditing the four-valued core after N1 (D323), on the theory that the project's other
foundational invariant might have the same shape of hole. It did, and worse.

**The finding.** Invariant 1 is the first rule in CLAUDE.md: "`unknown` or `unverifiable`
on a hard constraint blocks execution — no exceptions, no flags to bypass it." `apply`
re-verifies the candidate itself and holds the report — but it consulted
`report.Executable` ONLY inside its loop over the plan's `preconditions`, when it happened
to meet an entry of type `report-executable`. Delete that entry from the plan and the check
never runs.

That is not theoretical. The read-set carries the candidate's own hashes, so a plan
hand-authored for a candidate you supply matches by construction — no forgery needed,
writing the document IS the exploit. The test drives it end to end: a candidate whose hard
constraint verifies `unknown` (the value simply absent), a plan with `preconditions: []`,
and apply creates the resource and reports applied. Invariant 1 bypassed by omitting one
line.

`apply` defends against exactly this everywhere else, and says so: D47 — "autonomy is an
UNCONDITIONAL executor gate — a hand-authored plan must not bypass compiler policy"; D48
repeats it for replacement consent; D42's whole design is that the executor re-derives
rather than trusts. Invariant 1 was the one gate that still took its instructions from the
plan.

**The fix, two-layered.** The executable check now runs unconditionally, before the
precondition loop — apply holds the report, so it acts on it whether or not the plan asks.
And a plan that carries no `report-executable` precondition is refused outright: the
compiler makes it mandatory (D195), so a plan missing it was not sealed by this compiler and
its provenance is wrong. The first layer makes the invariant true; the second refuses the
shape that tried to dodge it.

Honest note on how it was found: the first version of the test mutated
`planDoc["preconditions"]` while apply reads `planDoc["plan"]["preconditions"]`, so it
"proved" the hole against a key nobody reads — the compiled plan's real precondition was
still there and doing its job. The finding only stands because the test was corrected to hit
the key apply actually consults, and then strengthened from "the check did not run" to "a
non-executable candidate was applied". A test that passes for the wrong reason proves
nothing; so does one that fails for the wrong reason. make check + race clean; 471/471
conformance.

## D326. Correcting D316's premise — OAC does not evade a principal-scoped RCP
D316 built CloudFront+OAC → a Lambda Function URL (AuthType AWS_IAM) and claimed "the
invoke is signed, not anonymous, so the RCP never triggers". Field validation (Acme, live
on their account, binary f12bd7a) proved that premise WRONG, and honesty (never a guess
dressed as fact) requires recording the correction rather than rewriting D316:

  | Request to the Function URL | AuthType | Principal | Result |
  |---|---|---|---|
  | Direct SigV4 | AWS_IAM | account principal | 200 (URL + IAM + app all work) |
  | Anonymous + Allow:* | NONE | anonymous | 403 |
  | Via CloudFront OAC | AWS_IAM | cloudfront.amazonaws.com | 403 |

The org's Resource Control Policy denies `lambda:InvokeFunctionUrl` to EVERY principal
outside the account — including the CloudFront SERVICE principal. So OAC's SigV4 signing,
which defeats an *anonymous-only* guardrail, does NOT evade a *principal-scoped* RCP: the
CloudFront principal is still "outside the account". D316's binding is nonetheless correct
to the byte (verified live: OAC SigningBehavior=always/SigningProtocol=sigv4/OriginType=
lambda, least-privilege grant scoped to the distribution's own SourceArn, Function URL
AuthType=AWS_IAM). What was wrong was only the CLAIM about the org boundary.

Scope discipline (the reason this is a docs-only correction, no code): whether the client's
org admits the CloudFront principal is the OPERATOR's environment decision — Groundhold
emits the correct wiring and stops at the account boundary; it does not administer a
client's AWS org or its RCP. The honest boundary is now stated where an operator meets the
feature (capability.cdn.distribution vocab header) and here. A product-level question —
whether Groundhold should offer an API Gateway → Lambda-proxy edge pattern for RCP-restricted
orgs — is deliberately deferred: API Gateway invokes as `apigateway.amazonaws.com` (also an
outside-account principal), so it may hit the same RCP; building it before the RCP's scope is
known would be building in the dark. No conformance/code change — D316's wiring stands;
only its premise is corrected.

## D327. The remaining invariants had no gate — two now do, and one was a latent panic
After N1 (D323) and invariant 1 (D325) both turned out to enforce something weaker than they
claimed, the obvious question was whether the other four non-negotiables were merely
UNGATED — true today, held by care, one refactor from being false. They were. Two are now
machine-checked; a third turned out to hide a crash.

**Invariant 6 (the verifier stays deterministic) — held, now gated.** It is the load-bearing
claim of the thesis: probabilistic proposal, DETERMINISTIC verification. Every other
invariant is about what a verdict MEANS; this one is about whether a verdict is reproducible
at all — and its failure is the hardest to notice, because nothing breaks, verdicts just
stop being reproducible. `TestVerificationCoreIsDeterministic` walks the import closure of
{verify, scalars, contract, canonical, vocab} inside the module and refuses `net*`,
`os/exec`, `math/rand`, `crypto/rand` and `time` — the wall clock included, because the
evaluation clock is an INPUT (N1), never something the core reads for itself. The Python
half is gated in the same test, since CLAUDE.md states the rule for `ref/groundholdlib/` by
name. Both halves verified by injecting an import and watching them fail.

**Invariant 4 (closed operator set) — a hand-written copy, and its drift mode is a panic.**
Go hand-listed `validOps` as a literal of ten operators while `scalars.Operators` implements
eight (the other two are presence forms handled separately). Nothing kept the two in step,
and the failure is not a wrong verdict but a CRASH: an operator accepted at load and absent
from the map makes `scalars.Operators[c.Op]` a nil function, which `verify.eval` calls
directly. A contract that passes validation would panic the verifier.

The Python reference already had this right — `VALID_OPS = set(OPERATORS) |
PRESENCE_OPERATORS`, derived, so it cannot drift. Go now derives it identically: the D311
lesson (the same knowledge written twice) applied to the operator set, with the reference
implementation as the design that was already correct. A second gate pins that the two
implementations' sets agree, because an operator legal in one and illegal in the other is
the D25 failure by definition.

Checked and found sound, so the next audit does not re-tread: invariant 2 (no coercion) is
honored at every one of the seven call sites of the operator map — verify, audit, forecast,
adopt, compiler and the GCP reconcile all turn a kind mismatch into `unverifiable`/unknown,
never a silent false; invariant 3's severity keying is fail-closed at load (`invalid
severity` refuses, and an absent budget severity defaults to hard). make check + race clean;
471/471 conformance.

## D328. A gate that finds nothing passes: hardening the gates against their own vacuity
Having spent D306–D327 adding gates, the honest next question was about the gates themselves:
what happens when one of them finds nothing to check? It passes. Green. And a green gate
reads as a guarantee, which makes a vacuous gate strictly worse than no gate at all — it
buys false confidence with the same CI time.

**The finding, in my own work first.** `TestObserveCompleteness` (D317) parses each driver's
dispatch switch and compares the create set against the observe set. Simulating a dispatch
whose shape changed — the `case` regex matching nothing — the parse yields two empty sets,
both loops run zero times, and the gate PASSES while checking nothing. Its older sibling
`TestClassifyChangeCompleteness` survived the same simulation only by accident: its stale-
allowlist check happens to fail when the create set is empty. Protection by luck is not
protection.

**The fix, at the shared helper.** `serviceCases` already refuses when the method is missing;
an empty PARSE is the same class of failure — the source shape changed (a switch rewritten as
if-chains, a renamed helper), not "this driver has no services". It now fatals, which covers
all six completeness gates in one place rather than asking each to remember.

**Two more of mine had the same shape.** `TestNoRawBodyInDriverDiagnostics` (D309) skipped an
unreadable provider package with a bare `continue`, so moving or renaming a package silently
removed it from coverage — the gate would keep passing while covering less. It now fails, and
asserts it scanned a non-zero number of files. `TestBareUnreadableDoesNotGrow` (the D297
ratchet) would have reported "down to 0" for a cloud whose files it could no longer see —
the debt looking paid because the measurement stopped. It now refuses to measure nothing.

The rule this leaves behind, and the reason it is worth a decision entry: a gate that
discovers its own subject must assert that it found one. Three of the gates written in this
series already did (`rawbody`, `doccounts`, the operator-set and determinism gates all fail
on an empty subject) — the discipline existed, it just was not applied consistently, which
is exactly how the debts in D306/D309/D311 started. Verified by simulating each failure mode
and watching the gate fail. make check + race clean; 471/471 conformance.

## D329. The OAC grant needs both invoke actions — and D326 was a misdiagnosis
Field correction (Acme, live-verified 200): the CloudFront-OAC → Lambda Function URL 403 was
NOT an org RCP. Two things follow.

First, the real bug: AWS changed behaviour ~October 2025 — a Function URL created AFTER that
date requires the caller's resource policy to allow BOTH `lambda:InvokeFunctionUrl` AND
`lambda:InvokeFunction` (older URLs work with just the former; refs aws-samples/
remote-swe-agents#361, hashicorp/terraform-provider-aws#39396). D316's OAC grant allowed only
`InvokeFunctionUrl`, so a post-Oct-2025 URL 403'd the CloudFront service principal. D329 grants
both: `grantCloudFrontInvoke` now issues TWO `lambda:AddPermission` calls (AddPermission takes a
single Action string, not a list), same principal `cloudfront.amazonaws.com` + `AWS:SourceArn`
= the distribution, distinct StatementIds (`groundhold-cf-<id>` keeps the InvokeFunctionUrl
statement idempotent for pre-fix distributions; `groundhold-cf-invoke-<id>` is new). The
InvokeFunctionUrl grant keeps its `FunctionUrlAuthType=AWS_IAM` condition; InvokeFunction is
SourceArn-scoped only. Granting both is backward-safe and unconditional (no date gate).
`PermissionsFor` already listed `lambda:AddPermission` (same API action) so no perm change. The
client verified 200 with both actions present.

Second, the honesty correction to D326: that entry recorded "OAC does not evade a
principal-scoped RCP" using Acme's 403 as the motivating case — but the org had ZERO custom
policies; there was never an RCP. The general statement in D326 remains true as a HYPOTHETICAL
(a principal-scoped RCP denying the CloudFront service principal would block, and that is the
operator's environment decision) — but it was NOT what bit Acme. The cdn.distribution vocab
caveat is corrected to lead with the real cause (the missing invoke action) and demote the RCP
note to a hypothetical. Consequence worth naming: a probe/audit remediation must never
confidently attribute a 403 to an org boundary (see the Layer-1 reachability probe, whose
401/403 verdict is `unknown` with a MULTI-cause remediation for exactly this reason). make check
471/471 both impls, golangci + race + differential clean.
## D330. Layer 1: the post-apply reachability probe — "APPLIED ≠ works"
Field pain (Acme): a converge stood up a public edge (CloudFront-OAC → Function URL) that
returned 403, but the run reported clean success — hours lost before anyone GET'd the URL. This
is the outcome half of the thesis loop (D59 probe): measure whether the thing you deployed
actually serves. After apply/converge for a capability with a PUBLIC edge (cdn.distribution with
a public/OAC origin → the distribution domainName; function.serverless → the Function URL), an
automatic reachability probe (default on; `--no-reachability` opts out LOUDLY) does one HTTPS GET,
its target derived purely from the applied resource's OUTPUTS (D316), and classifies four-valued —
never collapsing:
  - **2xx/3xx → reachable**: the only case that earns a green success claim; records
    `network.reachable=true` (measured).
  - **401/403 → unknown** (NOT a denial/violation): a 403 to an anonymous probe is genuinely
    ambiguous — a missing grant action (the D329 case), an auth-gated path (403 is correct there),
    or an org guardrail. Exit 2 / BLOCKED with a MULTI-CAUSE, non-accusatory remediation; it
    records NO observation (absence stays the honest blocking `unknown`). It NEVER reads as success
    and NEVER confidently blames the org boundary — the exact trap that cost the field team hours.
  - **transport failure (refused/DNS/TLS/timeout) or other 4xx/5xx → unknown**: unreachable-from-
    here (could be a firewalled CI runner or edge propagation), cause named (D306), never a denial.
  - no public output → nothing emitted (like probe.failed is never an observation — no fabrication).
The `Denied` verdict is deliberately ABSENT from Layer 1: proving a 403 is a *violation* requires a
DECLARED anonymous-reachability constraint, which is Layer 2. The network GET lives only in the
verb/porcelain (`internal/reach`), never in the deterministic executor or a hashed receipt
(injectable Getter; a fake for tests); differential never runs apply/converge, so no network
there. The reachability result is a measured observation (`--at` clocked) plus a surfaced
verdict on the correct channel, and it does NOT retroactively fail the apply (the receipts stand)
— it is a distinct "converged; reachability=<reachable|unknown>" outcome with its own exit signal
so an operator (and a script) can tell "up and serving" from "up but the edge won't answer".
Pinned by `conformance/cases/reachability.yaml` (impl:go) + `internal/reach` httptest goldens +
the converge fold test. Clean seam left for Layer 2 (a declared constraint that consumes this
observation). make check 480/480 both impls, golangci + race + differential clean.

## D329. The banner registry called itself closed while publishing ten of twelve words
Continuing the closed-set sweep that D327 started (invariant 4's operator set was a
hand-written copy). The presentation layer publishes a registry with the same kind of rules
as spec/errors.md — "exactly one banner word from this closed set", "additive-only; a
published word never changes meaning" — and had no gate.

**First, what was NOT wrong.** The implementation matches the union of the spec's two
tables: nothing in the code is unpublished, nothing published is unemitted. The banner
precedence is pinned by an existing test. So this is not a drift between code and docs.

**What was wrong is subtler and, for a published registry, worse.** The words live in TWO
tables: the D89 "Banner vocabulary" table, which is the one that declares closure, and the
D90 "Green words per verb" table. `SEALED` (plan) and `OK` (the procedural verbs) appear
only in the second. So the table that says "this closed set" published ten of the twelve
words, and a consumer implementing from it would meet two words it never learned. That
consumer is not hypothetical: the console is a SEPARATE REPOSITORY implementing against this
glossary, and CLAUDE.md's standing instruction is "one glossary, no drift".

A registry that is complete only if you also read a later section is not a registry. The D89
table now carries all twelve; which verb earns which green word still belongs to the D90
table, because that is a different question (assignment, not membership).

**The gate.** `TestBannerVocabularyMatchesTheSpec` asks the CODE for its vocabulary —
exercising `Pick` across the verb × exit × rollup matrix rather than scraping literals
(D317) — and compares it against the registry table alone, deliberately not the union: the
whole finding was that the union hid an incomplete registry. It fails in both directions (a
word emitted but unpublished; a word published but never emitted) and refuses to run on an
empty set (D328). Verified by renaming SEALED in the code and watching both directions fire
at once. make check + race clean; 480/480 conformance.

## D330. Five artefacts published the routing contract; no two agreed

`spec/errors.md` carries the strongest promise in the repo about a machine-readable field:
"the `code` field is the CONTRACT: scripts and agents route on it", additive-only, never
reused, one code per DISTINCT REMEDIATION. It is the registry whose rules D329's banner
vocabulary was written to mirror — and it had no gate either. Five artefacts published it:

- the constants the runtime emits — **33**
- `perr.Explain`, projected verbatim by `Registry()` for the console — **26**
- `spec/errors.md`, the published registry — **26**
- the closed `enum` in `spec/outputs.schema.json`, referenced by 8 verb output shapes — **21**
- `website/pages/errors.md`, which stated the count in prose — **"twenty-one codes"**

The seven the runtime emits and nothing published are the background-run family
(`run-unknown|running|stalled|needs-reconcile|done|failed`, `wait-timeout`, D229/D231). They
are `perr.Code` values on the same `code` field, and they travel FURTHER than the rest:
notification hooks receive them, so consumers outside the CLI route on them.

The consequences were not cosmetic, and one is reachable in two commands:

    groundhold wait <handle>       → code: run-stalled
    groundhold explain run-stalled → "not an error code"

The tool denied a code it had just emitted. The console, which projects `Registry()` under a
one-glossary rule, showed those states with no remediation. And the schema enum — closed,
and stale by twelve — makes a consumer validating groundhold's output against groundhold's
own published schema REJECT a valid refusal; five of those twelve (`provider-again-later`,
`mapping-schema-drift`, `reference-invalid`, `reference-unresolved`, `unknown-operand`) were
correctly in the registry all along and had simply never reached the schema.

Fixed: seven `Explain` entries, seven registry rows with honest exit codes (`run-done` exits
0 — the registry already publishes success codes: `nothing-to-change`), twelve enum members,
and the website's count removed rather than corrected, since a hand-synced number against an
additive-only registry is a guaranteed future lie (the page already points at the registry).

The gate compares all four machine artefacts, both directions each, with the D328 non-empty
guard. It honours the registry's own published rule for a superseded code: a row containing
"reserved" may be published without an implementation. Verified by injecting a phantom row
(fires), marking it reserved (passes), and mangling an enum member (both arms fire).

**One gate under-covered because another was incomplete.** `perrnext`'s `TestCompleteness`
iterates `perr.Explain` and demands every code have either a `next` builder or an explicit
`noNext` decision — so the seven unregistered codes had silently never faced it. Closing the
registry immediately made it fail. All seven are `noNext`, honestly: `resume` IS the
remediation for `run-stalled` and `run-needs-reconcile`, but it takes the contract and the
run verbs (`wait`, `runs`) never do, so the command is not derivable from the operator's own
inputs — omit over guess (D230).

Checked and found sound: `spec/errors.md` and `perr.Explain` agreed exactly on their 26, so
the drift was purely omission, never contradiction; no console file hard-codes a code (it
consumes the registry through the API, so it picks the seven up on its own); `runstatus`
keeps its context-specific prose ("the writer's lease lapsed") beside the new static
remediation — the same split as `next` vs `explain`, not a duplicate.

make check + race clean; 480/480 conformance.
## D331. CloudFront cache default is safe per origin type — dynamic origins are not cached
Field bug (Acme): `cdn.distribution` created every distribution with the managed
**CachingOptimized** policy. For a dynamic origin — a Lambda Function URL fronting an API/SSR app
(the D316 OAC pattern) — that caches dynamic responses keyed by URL, so the edge can serve one
request's cached body to a different user (stale or cross-user leak). A correctness/security-grade
default bug. D331 makes the default safe PER ORIGIN TYPE: the OAC path (`origin_access: oac`, whose
OAC OriginType is hardcoded `lambda`) is the dynamic signal → default managed **CachingDisabled**
(`4135ea2d-…`); a static origin (S3/website, from `origin.domain`) keeps CachingOptimized
(`658327ea-…`, correct there). An explicit `cache_policy: disabled|optimized` operand (registered
in ConsumedOperands so D307 accepts it; unrecognized value refuses loudly) overrides. Cache tuning
stays opaque impl (invariant #4) — no vocab attribute. Pinned by a Go builder test (default per
origin type + both overrides + bad-value refusal) and an httptest golden capturing the
CreateDistribution body (static→Optimized, OAC→Disabled). make check + golangci + race +
differential clean.

## D332. cdn.distribution custom domains — aliases + ACM viewer cert (us-east-1)
Field gap (Acme did it by CLI): a distribution could only serve as `*.cloudfront.net`. D332 adds
custom-domain operands: `aliases: [fqdn, ...]` → `Aliases` (each FQDN-validated), and `certificate`
→ `ViewerCertificate{ACMCertificateArn, SSLSupportMethod=sni-only, MinimumProtocolVersion=
TLSv1.2_2021}`, the ARN `$ref`-able to a `certificate.tls` output (D226 wiring + dependsOn). No
certificate operand → the pre-existing CloudFrontDefaultCertificate (untouched). Fail-closed
pairing: aliases-without-certificate refuses (CloudFront rejects aliases on the default cert) and
certificate-without-aliases refuses (ambiguous), mirroring the loadbalancer HTTPS↔cert stance.
The us-east-1 constraint (a CloudFront viewer cert MUST live in us-east-1) needed NO residency
relaxation: the ACM driver already treats `location.region` as pure create scope with no residency
refusal, so the operator authors the cert candidate in us-east-1 and the cdn `$ref`s it. A narrow
CloudFront-SIDE guard refuses a viewer cert whose region isn't us-east-1, with the message that a
CloudFront edge cert is a PUBLIC cert and us-east-1 is an AWS infrastructural requirement, not a
data-residency choice — no EU/single-residency invariant was touched. Route53 auto-alias is
deferred (flagged): the distribution already exports `domainName`, so A/AAAA ALIAS records
(AliasTarget → domainName, HostedZoneId=Z2FDTNDATAQYW2) are a clean follow-up. Pinned by
`conformance/cases/cdn-custom-domain.yaml` (cert $ref + aliases plan with dependsOn) + Go/httptest
goldens (aliases + ViewerCertificate on the wire; refusals). make check 483/483 both impls,
golangci + race + differential clean.
## D333. Advisory attributes never block a bound update (cost.monthly regression)
Field bug (Acme): a bound Lambda with `cost.monthly` (an advisory, forecast-only attribute —
`evidence: projection`, D311) plus a real change (`url_auth`) produced a SEALED plan with
`actions: []` — the update silently vanished. Root cause: `classifyBound`'s typed-attribute loop
already skipped projection attrs, but the D318 `OperandDrifter` branch passed the UNFILTERED
attribute map to `OperandTargets`, and AWS Lambda's `BuildLambda` `default:` arm refuses any
attribute it cannot map (cost.monthly included) — a per-capability D249 block that swallowed the
whole capability's legal update. D333 adds `nonProjectionAttrs` (keyed off the `evidence:
projection` vocab marker, not the name — mirrors the apply-side `attributesRaw` boundary) and feeds
that to `OperandTargets`, so advisory/projection attributes are stripped before any driver builder
sees them: they neither drift nor block. Shared fix at the generic OperandDrifter call — covers
every driver that does operand drift (only AWS Lambda implements it today; the apply boundary
already filtered projections). Pinned by an impl:go update case (bound lambda + cost.monthly +
a real change → the update action appears, not an empty plan; fails without the fix) + a Go test
driving the real driver through classifyBound. make check + golangci + race + differential clean.

## D334. AWS Lambda claim — adoption becomes ownership (brownfield takeover)
Field bug (Acme): an adopted brownfield Lambda could be neither updated (`url_auth`) nor have its
resource policy modified (the CDN/OAC `grant_invoke_lambda` → AddPermission), because claim was
unwired — converge aborted "aws cannot yet claim ownership of a lambda resource", forcing
delete+recreate (downtime). D334 wires claim for lambda: the ownership stamp rides the generic RGT
`claimByARN` path (the Lambda ARN is fully derivable from the providerId, like the ~24 other
ARN-derivable claimable services), plus a service-native GetFunction PRE-READ (the claimRDS/
claimSecretsManager shape). Ownership is taken by stamping the same `groundhold-capability`/
`groundhold-environment` tags the create builder uses, via the ADDITIVE RGT `TagResources`
(key-merge — the operator's own tags survive). Honesty guard: the pre-read verifies the function
exists (readable 404 → clean failed; unreadable → unknown WITH pid) AND that its live `FunctionArn`
equals the ARN built from the providerId — a name resolving to a DIFFERENT function is refused,
never tagged as ours; an already-owned function is an idempotent success with no re-write. This
also resolves a latent inconsistency (`awsClaimPerms["lambda"]` was already declared but the driver
refused). Full claim, consistent with every other claimable service — so brownfield OAC/CDN on an
existing function now works without delete+recreate. Pinned by a Go golden (claim stamps ownership
→ update + AddPermission both succeed on the claimed function; foreign-ARN refuses; vanished fails;
already-owned idempotent); the generic adopt→claim loop stays pinned through the Fake in
onboarding.yaml. make check 481/481 both impls, golangci + race + differential clean.

## D335. A requirement-invariant registry — remembering silent provider changes (API-drift, part 1)
D329's root cause was a SILENT server-side authorization change at a fixed API version (a
post-Oct-2025 Lambda Function URL requires both invoke actions) — a class that version-pinning
(apiver/D236) and shape-fixtures (D234) are structurally blind to, and that cost a field team
hours. D335 is the first of the API-drift work (a two-review scoping found Groundhold already has
a four-layer drift stack — per-cloud canaries, apiver, fixtures, endpoint-reality D274, the D330
probe — so the gap is narrow): a deterministic, creds-free **requirement-invariant registry**
(`go/internal/apireq`) that REMEMBERS known provider requirements and guards against regressing
them. It mirrors apiver's stance exactly (enumerated closed struct — invariant #4; records a CLAIM
+ source, not a currency proof). Each `Requirement` is `{Provider, Service, Operation, Requirement,
SinceDate, SourceURL[], GuardID}`. First entry (real, sourced): AWS Lambda Function URL invocation
via CloudFront OAC requires BOTH `lambda:InvokeFunctionUrl` AND `lambda:InvokeFunction` since
~2025-10. A regression guard (in package aws) binds that entry directly to `grantCloudFrontInvoke`:
dropping either action fails the build with a message CITING the registry (GuardID + SinceDate +
both SourceURLs), so a future edit can't silently regress a known provider requirement, and the
failure explains it's a documented AWS rule, not an arbitrary assertion. A `CanaryTargets()`
accessor exposes the entries as DATA for the functional edge-canary (part 2, D10 next slice — the
only layer that actually catches an unknown-unknown behaviour change, by converging the real edge
and reading the outcome). Cloud-agnostic by construction (the `Provider` field); no GCP/Azure
entries fabricated for parity — seeded only when a real, sourced requirement is known. Honesty
boundary: the registry is MEMORY + a regression GUARD, never foresight — it cannot predict a
requirement nobody has hit; currency is the canary's job (evidence, not proof — the D75 stance).
make check 480/480 both impls, golangci + race + differential clean.

## D336. AWS public-edge functional canary — catching the silent behaviour change (API-drift, part 2)
The requirement registry (D335) remembers; this DETECTS. A daily AWS canary (`MODE=edge` in the
existing canary-aws harness — same exit taxonomy 10/20/30, self-cleaning, OIDC, labelled issue)
converges a real CloudFront-OAC → Lambda Function URL edge on the throwaway account through the
real binary, then reads the outcome. Because a freshly-converged Function URL is always a
CURRENT-behaviour URL, an insufficient grant (the D329 class, or any FUTURE AWS authz/behaviour
change on this edge) surfaces as a live failure — the only layer that catches an unknown-unknown,
where version-pins and shape-fixtures are blind.
Sharp finding that shaped the design: the edge has TWO reach targets — the Lambda's own
`functionUrl` (AuthType=AWS_IAM → 403s an anonymous probe BY DESIGN) and the CloudFront
`domainName` (the real public path). So converge always exits 2 / `reachability: unknown` even when
healthy; the canary therefore reads converge `--json status=applied` as "did it build", waits for
the distribution `Status=Deployed` (~15-20 min), and anonymously GETs the CLOUDFRONT domain — never
gates on the Function-URL probe. Verdict via a tested Go core (`groundhold apireq classify` /
`internal/edgecanary`): applied + 2xx/3xx → green; 401/403/5xx on the known-good deployed edge →
provider-drift(10) CITING the apireq GuardID+source ("AWS may have changed the requirement again");
non-applied/other → groundhold-regression(20); not-deployed-in-budget/transport → infra-flake(30).
Targets come from `apireq.CanaryTargets()` (data, not hardcoded).
Honesty preserved: the verdict-UPGRADE (403-on-known-good → red) lives ONLY in the canary, which
owns its environment (no RCP, our own driver) — the customer-facing D330 probe is byte-untouched (a
403 stays `unknown` there). Green = this edge served anonymously today, not "no drift anywhere" —
evidence, not proof (D75). Self-cleaning extended to CloudFront/Lambda/OACs (higher leak cost). No
fake parity: GCP edge canary is a flagged follow-up; Azure stays out (apply not wired). The Go core
is unit-tested (target selection, the 11-case verdict table, citation); the converge/poll/GET/sweep
are canary-only (need live creds). OWNER actions flagged (docs/canary.md): apply the scoped IAM
role delta in the canary account, provision the two persistent fixtures, extend the budget alert,
enable the daily cron. make check 484/484 both impls, golangci + race + differential clean.
## D337. Azure CDN parity for cache + custom domains — honestly unlike CloudFront (D331/D332)
The AWS CloudFront fixes (D331 safe cache default, D332 custom domains) got their Azure CDN twin —
but Azure's model genuinely differs, so this is per-cloud-faithful, not a copy. Finding (D331): Azure
CDN (classic, Standard_Microsoft) has NO managed cache-policy id and its default HONORS the origin's
Cache-Control/Expires headers — a dynamic origin sending no-store/no-cache is not cached. So there is
NO dangerous default to fix (unlike CloudFront's CachingOptimized). Hence an operand-only change, no
default change: `cache_policy: disabled` attaches a global CacheExpiration delivery rule
(BypassCache) for a truly untrusted dynamic origin; unset/`honor` keeps the header-honoring default;
`optimized` is deliberately omitted (a forced TTL is opaque per-path tuning, invariant #4, and Azure
has no CachingOptimized-equivalent). D332: `aliases` → a `customDomains` SUB-resource (separate PUT,
not an inline CNAME), `certificate` → a separate `enableCustomHttps` POST — `"managed"` =
certificateSource Cdn (Azure-managed cert, no external resource; AWS has no twin) or a Key Vault
secret id = AzureKeyVault (BYO). The AWS `$ref: certificateArn` shape does NOT apply and is refused
honestly: `capability.certificate.tls` is AWS+GCP two-cloud with no Azure implementation (Key Vault
certs are data-plane), so there is nothing to reference — the Azure case uses `certificate: managed`.
Pairing mirrors AWS (aliases need a cert). Operands registered in ConsumedOperands (D307). Pinned by
`conformance/cases/cdn-custom-domain-azure.yaml` + httptest goldens (customDomains + enableCustomHttps
certificateSource + the cache-bypass delivery rule). ARM shapes (CustomDomainHttpsParameters,
CacheExpiration rule) + the header-honoring default flagged for live validation. make check 486/486
both impls, golangci + race + differential clean.

## D338. The reference implementation could not read a ledger the runtime writes

Continuing the registry sweep (D329 banners, D330 error codes) to the ORIGINAL registry —
`spec/errors.md` says its own rules mirror this one: the event type registry (D19, "closed
set, fail-closed"). It is the ledger's alphabet; capsule, export, restore, audit and replay
all route on it. Four artefacts published it:

- `go/internal/state/state.go` `EventTypes` — **21**
- `ref/groundholdlib/state.py` `EVENT_TYPES` — **16**
- `spec/state-model.md`, the published registry block — **16**
- `spec/state.schema.json`, the closed enum for `ledgerEvent.event.type` — **16**

Missing from all three: `ownership.claimed` (D140) and the four `converge.*` lifecycle
markers (D229).

This is not the documentation gap D329/D330 were. Both implementations are fail-closed on
this set BY DESIGN, so the divergence inverted the dual-implementation guarantee (D25) in the
substrate every piece of evidence lives in. Proven, not inferred:

    $ go run ./cmd/groundhold hash converge-event.yaml
    sha256:916463fe...
    $ python3 ref/groundhold.py hash converge-event.yaml
    document error: unknown event type: 'converge.started'
    INVALID

`converge.started` is written on every run of `converge` — the flagship porcelain verb (D51)
and the one the docs put in front of users. So the reference implementation could not read a
ledger produced by the ordinary path, and neither could anything validating against the
repo's own published state schema.

Per invariant 5 the fix started with a case: `converge-lifecycle-event-loads-in-both-
implementations` pins the event's HASH rather than merely its acceptance, so it proves both
sides load it AND canonicalize it identically. It failed against the reference for exactly
the right reason before the fix. The gate then compares all four artefacts against their
union, reporting per artefact what it does not know, with the D328 non-empty guard.

**Second finding, same subject: the classification was fail-open.** `MutationTypes[etype]` is
what makes an append require an active lease and a matching fencing token (D29), and it is a
hand-maintained map with a silent default — a mutating type omitted from it appends with no
lease and no token at all. Nothing forced a decision. This is the shape D330 found in
perrnext, except what was left undecided here is a concurrency control. Fixed the way that
package already solves it: an explicit `NonMutatingTypes` with a per-type reason, and a gate
requiring every event type to be in exactly one half. Checked: no current type is
misclassified, so this is hardening, not a bug fixed — verified by removing one type from the
set and watching the gate name it.

Checked and found sound: `DecisionTypes` is deliberately a free subset (a type that advances
no decision head is normal, and the default is inert), so it takes no completeness rule;
`MutationTypes` and `NonMutatingTypes` are disjoint and neither names a type outside the
registry.

make check 481/481 + reference 217/217 + race clean.
## D339. GCP parity for the reachability probe + edge canary (D330/D336 twins)
The AWS-only D330 (reachability probe) and D336 (edge canary) get their GCP twins, and the reach
machinery is made genuinely cloud-agnostic in the process. `reach.edgeOutput` became
`edgeOutputs(capType)` returning an ORDERED candidate-output-name list per capability type plus a
`gatePublic` flag — one vocab type fulfilled by different clouds whose output names differ, without
the probe knowing which cloud built it: cdn.distribution→[domainName], function.serverless→
[functionUrl, url], workload.container→[uri, fqdn]. AWS stays byte-intact (cdn/function.serverless
are presence-gated, gatePublic:false, exactly as before). `workload.container` is gatePublic:true
because a Cloud Run `uri` exists even for `ingress=internal`, so a per-capability public map (from
the candidate's declared `network.publicExposure`) gates it — an internal Cloud Run yields NO target
(mirrors AWS's no-public-output "nothing measured", never a false unknown). GCP outputs added:
`cloudrun → uri` (one services.get read — the honest source; the agent corrected the scoping
premise that it was create-captured), `cloudfunctionsfn → url` (functions.get, published only when
ingress ALLOW_ALL, mirroring AWS lambda functionUrl). The edge canary REUSED the shared core:
`internal/edgecanary` gained an `Edge` descriptor so the verdict truth table is cloud-agnostic
(AWSEdge/GCPEdge carry only wording + citation), `Classify == ClassifyFor(AWSEdge)` keeps AWS
untouched, `apireq classify --provider gcp` routes. GCP's canary converges a PUBLIC Cloud Run
(no CDN/OAC front — simpler than AWS, no dual-invoke guard) and its drift verdict is honestly
UNCITED (GCP has no apireq entry; none fabricated). Customer four-valued semantics unchanged; the
403→red verdict-upgrade stays canary-only. The reach core is left data-driven so Azure adds only its
`fqdn` output name + Container Apps derivation with no core change (the last parity slice). Pinned by
`conformance/cases/reachability.yaml` (public Cloud Run probed on its uri; internal → nothing) + Go
tests (cross-cloud recognition, public-gate suppression, uri/url derivation, GCP verdict table). make
check 486/486 both impls, golangci + race + differential clean.
## D340. The public export is publishable again — client scrub + export-standalone gate
A grounded export-readiness audit (the north star is going public via export-public.sh → a public
org) found the export FAILED its own gate on two independent counts, both introduced THIS session:
(1) the negative-space audit hit 90 occurrences of the token `acme` across 30 files — this
session's live field partner, named in DESIGN war-stories, test data, and comments — all COSMETIC
(proven: scrub acme→acme and Python 216/216 + Go 486/486 + unit tests still pass, so ZERO are
hash-load-bearing); (2) the standalone `make check` on the export failed independently on
`TestClaudeMdVocabularyCountMatchesDisk` (a D324 count gate) because it hard-reads CLAUDE.md, which
the export deliberately omits. Two small deterministic fixes, no fixture regeneration: an export-time
`acme→acme` sanitizer in export-public.sh (the SAME stance as the groundhold/a real GCP project
sanitizers already there — the honest field attribution stays in the PRIVATE repo, the client name
is genericized on export; `acme` was already on the denylist, only the sanitizer was missing), and a
`t.Skip` guard on the D324 test when CLAUDE.md is absent (the sibling README-based count check still
guards the number in-repo). Verified end-to-end: `export-public.sh` to a temp target now passes the
negative-space audit AND the standalone gate (486/486) — "export is publishable". The scary tokens
were already clean (the real account id and every other denylisted client token = 0 hits). Residual to launch is
the owner's non-code mechanics only: create the public org, `PUBLIC_ORG=<org> export-public.sh`, push
`../groundhold-public`, wire Pages. make check + golangci + race + differential clean.

## D341. Azure reachability parity — the third cloud on the probe (D330 completed)
The final parity slice: Azure Container Apps reachability, completing the D330 probe across all three
clouds (AWS D330, GCP D339, Azure here). Because the reach machinery was made data-driven in D339
(`edgeOutputs` returns candidate output names per capability type — `workload.container → [uri, fqdn]`
— with a public gate), the reach CORE needed NO change: Azure only supplies the output. Added `fqdn`
to `azureOutputs["containerapps"]`, derived from one containerApps.get of the server-assigned ingress
FQDN (a read failure demotes to unknown, mirroring GCP cloudrun uri; an ingress-disabled app returns
"" and omits the output — no demotion, since Container Apps ingress is optional). Public gating is the
shared cloud-agnostic projection (`network.publicExposure → ingress.external`), so an external app is
probed on its fqdn and an internal one has no target — never a false unknown. Also corrected three
stale `docs/canary.md` claims that the "Azure executor mutation path is not wired": it IS wired
(azure_provider.go Create dispatches createContainerApp/createAzureCDN/createFlexServer) — the Azure
EDGE canary is deferred on cost/fixture grounds, honestly stated, not an executor gap. Pinned by
`conformance/cases/reachability.yaml` (external Container App probed on fqdn; internal → nothing) + Go
tests (fqdn derivation public/internal/read-failure; reach recognizes the Azure fqdn). make check
490/490 both impls, golangci + race + differential clean.

## D342. Launch-prep hygiene — crawl hash determinism + certifynet transient sweep (18-driver flag)
Two pre-launch TODOs, plus a real correctness gap surfaced honestly rather than papered over.
(1) The discover Path-only sort feeding a hash was fixed for `discover` in D159, but the SAME latent
nondeterminism remained in the crawl `contentModel` (`crawl.go` sorted observations by `Path` alone,
feeding `ContextHash` via `canonical.Hash` — two observations sharing a path but differing in
value/derivation hash differently by enumeration order). Fixed with the same total-order tiebreak
`(path, value, derivation)`; pinned by a fails-without-fix order-independence test.
(2) certifynet's `AssertTransient` (the D237 transient-fault honesty sweep) was migrated to the 5
drivers that were already READY (aws/eks, aws/lambda, gcp/cloudfunctionsfn, gcp/cloudvpn, azure/aks —
they route 429/503/403 mutations to `unknown` via `provider.MutationResult`; they merely lacked the
flag). Turning the flag on for the rest exposed that **18 drivers genuinely FAIL the invariant**:
they map a transient 429/503/403 on create/delete to terminal `failed` AND drop the knowable
providerId — the D62 phantom/orphan class (a real apply hitting a throttle orphans a resource). This
was NOT forced green: the flag was reverted on the 18 with a tracked-TODO on each Probe naming the
cause (429/503/403 → failed, pid dropped, needs MutationResult), matching certifynet's "tracked TODO,
never a silent claim of coverage" convention. The 18 (aws: vpngateway, backupplan, redshiftserverless,
iamrole, backupvault, eventbridgescheduler; gcp: cloudbackupdr, cloudscheduler; azure: azurecdn, apim,
frontdoorwaf, containerappsjobs, cosmos, azfiles, azkafka, aisearch, eventhubs, azureopenai) are the
remaining D237 ladder — a per-driver correctness slice (route create/delete/claim through
MutationResult) worth prioritizing, as the orphan-on-transient impact is real. make check 491/491
both impls, golangci + race + differential clean.
## D343. The transient-fault orphan class closed on all 18 remaining drivers (D237 ladder complete)
D342 surfaced that 18 drivers mapped a transient fault (HTTP 429/503, live-403 throttle) on
create/delete to a terminal `failed` AND dropped the knowable providerId — the D62 phantom/orphan
class: a real apply hitting a throttle orphans a resource the executor can no longer reconcile by
name. D343 migrates all 18 to route transients through the shared `provider.MutationResult`
classifier → `unknown` WITH the deterministic providerId preserved (retryable; resume/reconcile
recovers by pid), while genuine terminals are untouched (a clean 4xx refusal stays `failed`, a
404-on-delete stays the authoritative absence, delete-conflict/retention holds still block). AWS (6:
vpngateway, backupplan, redshiftserverless, iamrole, backupvault, eventbridgescheduler — the
guard inserted before each `st>=400`/`st!=OK` terminal branch), GCP (2: cloudscheduler including its
compound pause step, cloudbackupdr — the retention-hold refusal still precedes it), Azure (10:
azurecdn, apim, frontdoorwaf, containerappsjobs, cosmos, azfiles, azkafka, aisearch, eventhubs,
azureopenai — creates were already honest via the shared putAndPoll/MutationResult helpers; the DELETE
path carried the bug). `AssertTransient: true` is now ON and green on every one of the 18 certifynet
Probes — the acceptance gate that proves each routes the injected transients to unknown-with-pid, so
the coverage is real, not a silent claim. Honest D29 nuance: the two AWS drivers with a
SERVER-ASSIGNED id (vpngateway, backupplan) emit unknown-WITHOUT-pid only on the id-yielding create
call itself (you cannot preserve an id you do not yet have) — every other mutation carries the pid.
The D237 ladder is now complete across the driver fleet. make check 491/491 both impls, golangci +
race + differential clean.

## D344. The CI pipeline, completed for launch — SAST, secret scanning, lint gates, dormant Pages
The pre-launch tree already carried the strong gates (D282): `make check` (vet + dual conformance +
differential), `race`, portability matrix, `tidy`, govulncheck, and golangci-lint with gosec +
staticcheck enabled. Four gaps remained between that and a launch-grade pipeline, closed here:
(1) **Deep SAST** — `codeql.yml` runs CodeQL over two languages, `go` (dataflow-aware queries that
gosec's pattern rules miss) and `actions` (the workflow files themselves, for script-injection and
token-scope flaws), on push/PR/weekly, uploading SARIF to the Security tab. gosec stays as the fast
blocking pre-filter; CodeQL is the deep pass. Code scanning is free on public repos but needs GitHub
Advanced Security on private ones, so the job is guarded on `repository.visibility == 'public'` — it
skips green on the private pre-launch repo and runs automatically once public (same platform-reality
handling as dormant Pages).
(2) **Secret scanning** — a `gitleaks` job in security.yml scans the whole tree against the upstream
ruleset. The three matches it found were all deliberate non-secrets (a test asserting a password is
NEVER echoed into a receipt; an importer state-fixture proving secrets are structurally excluded; an
example plan's idempotencyKey), allowlisted by path in `.gitleaks.toml` with each entry naming why —
the allowlist is tightened, never widened. The action is run from a pinned release binary rather than
the marketplace action, which requires a paid license for org repos.
(3) **Non-Go lint/syntax** — `lint.yml`: actionlint (workflow syntax + embedded-shell shellcheck),
shellcheck over every tracked `*.sh` (a clean no-op where a tree carries none — the public export omits
scripts/), and `python -m compileall` over the reference implementation and conformance runner.
shellcheck gates at warning+ (`SHELLCHECK_OPTS`); adopting it surfaced four real warnings across the
existing scripts and workflows — three unguarded `cd`s and an `rm -rf "$DST/bin"` that could expand to
`/bin` if the var were empty (now `${DST:?}`), plus a dead assignment — all fixed here.
(4) **Docs deploy** — `pages.yml` builds the mkdocs site with a pinned toolchain (website/
requirements.txt) and deploys to GitHub Pages, plus `site_url` in mkdocs.yml. It is DORMANT
(workflow_dispatch only) by design: Pages on a free org requires a public repo, and the launch repo is
still private — the workflow is staged so it deploys the moment the repo is made public and Pages is
enabled, with no red run in the meantime. Every added action is pinned to a full commit SHA per the
D282 supply-chain convention. Validated locally before commit: actionlint, gitleaks (0 leaks with the
config), python compileall, and mkdocs build --strict all clean. make check 491/491 both impls,
golangci + race + differential clean (no runtime code changed — CI, config, and docs only).

## D345. The publish path is a reviewed PR, not a push — export boundary fixes it exposed
D63 gave the export a whitelist and a negative-space audit, and both held. What it never fixed was
how the exported tree REACHES the public repo: the sync so far was a direct push to `main`, which
makes the public repo a mirror rather than a repository with a gate. The rule adopted here is the
same shape as the private repo's: changes are made and validated in the private tree, anonymized by
`scripts/export-public.sh`, then pushed to a BRANCH on the public repo and merged through a pull
request. `main` is protected and only a CODEOWNER merges it. The export is one-way as before; what
changes is that the last step is reviewable, so the anonymization has a place to be inspected before
it is public rather than after.
Three defects surfaced while wiring this, all in the boundary itself:
(1) **A crossing workflow left its config behind.** D344 added a gitleaks job that runs
`--config .gitleaks.toml`, and `.github` crosses wholesale, but `.gitleaks.toml` was not on the
whitelist. The public tree therefore carried a secret-scanning gate that dies on a missing file on
its first push. The standalone `make check` gate cannot catch this class — it runs the conformance
suite, not GitHub Actions. `.gitleaks.toml` is now whitelisted; the general lesson is that a
whitelist admitting a workflow must admit what the workflow reads.
(2) **CODEOWNERS named an organization.** The rule was a bare organization handle, which assigns
nobody: GitHub resolves code owners to users or `@org/team` only. It is now `* @jpazdyga`, a real
user, which is also what makes "only a CODEOWNER merges main" enforceable rather than decorative.
(3) **The denylist forbade the publisher's own handle.** The audit carries the maintainer's local
account name so that developer home-directory paths cannot cross. The public identity — commit
author, and now code owner — is that same name carrying a one-letter prefix, so a plain substring
match rejected it and the export refused to publish. The entry now requires the denied form NOT to
be preceded by that prefix letter: path forms stay denied, the GitHub handle is carved out. Verified
in both directions rather than assumed.
This entry is deliberately written without quoting the denied tokens themselves. DESIGN.md is an
exported file, so prose that names them is itself the leak the audit exists to stop — the same
self-leak already corrected once in the D340 entry. The audit caught this entry's first draft.
A fourth item, found the same way and decided by the owner: **the live cloud canaries no longer
cross.** `.github` is exported wholesale, so the canary workflows were reaching the public repo,
where they cannot possibly run — their runner scripts live in `scripts/`, which is denied because it
names internal hosts, and the cloud credentials and region variables exist only in the private repo.
They were already failing there on schedule (the first error is a missing region input, before the
missing script is even reached), which is the worst of both worlds: a red badge that proves nothing
and hides no secret. They are the only exported workflows that read secrets or vars, which is the
cheap check if this is ever revisited. The canary program stays real and stays private; what the
public tree keeps is the gates it can actually run.
Branch protection itself is NOT yet applied: the API returns 403 "Upgrade to GitHub Pro or make this
repository public" for both classic protection and rulesets, because the launch repo is private on a
free organization. This is the same platform-reality class as dormant Pages and the visibility-gated
CodeQL job (D344) — the configuration is decided and recorded here, and applies the moment the repo
becomes public. Until then the branch-and-PR discipline is convention, and it is stated as convention,
not claimed as enforcement.

## D346. Shipped examples are gated, not trusted — verify and plan are different questions
`examples/acme/aws.candidate.yaml` verified clean — 48 satisfied, 0 violated, PROVEN — and could not
be compiled. Two implementation operands named keys no driver reads: `inferenceProfile` where the
Bedrock driver requires `inferenceProfileName` plus `modelSource`, and camelCase
`deadLetterTargetArn`/`maxReceiveCount` where the SQS driver reads snake_case. `plan` refused with
`unknown-operand`, which is the operand contract working exactly as designed (D26: a key the driver
would ignore is refused, never silently dropped). The example had been exported to the public repo in
that state, and a second defect sat beside it: the GCP gitops candidate was missing the `gitops-root`
witness its AWS twin carries, so it verified `unknown` on two constraints and blocked.
The lesson is not "someone was careless". It is that **verify and plan ask different questions**, and
only verify had ever been run against the examples. Verify asks whether the declared attributes
satisfy the constraints; plan asks whether a driver can actually execute the declaration. An example
can pass the first and fail the second forever, silently, because nothing was checking. Prose and
examples rot the same way numbers do (D324) — for the same reason: no gate.
So `examples/check.sh` now runs both questions against every shipped pair, plus the README's converge
loop on the `fake` provider (first run converges, second run proves the no-op), and `make check`
depends on it. Two properties matter. First, **expectations are declared, not inferred**: a REFUSED
example is legitimate when the refusal IS the lesson — `orders-production` must keep refusing, because
an RTO claim is provable only by a restore test, and if it ever starts compiling the central guarantee
has broken. What is never legitimate is an outcome nobody wrote down. Second, the gate lives in
`examples/`, not `scripts/`, because `examples/` crosses the export boundary and `scripts/` does not
(D345) — so the identical gate runs inside the PUBLIC tree during the export's standalone `make check`.
An example that cannot work can no longer reach the public repo. The clock is pinned (`--at` fixed)
so a failure is reproducible on any day, and the runner reports every broken example rather than
exiting on the first. Proven to have teeth by breaking an operand on purpose and watching it name the
offending example and exit 1.
Left standing, deliberately: the operand naming convention is inconsistent between drivers (Bedrock
camelCase, SQS snake_case). That is a real wart, but renaming operands is a compatibility change to
the candidate surface, not a docs fix, and it belongs in its own entry rather than smuggled into one
about gating.

## D347. The README leads with using the system, not building it
The README opened with what the project believes, then how to compile it. Both are things a reader
wants EVENTUALLY; neither is what someone deciding whether to care wants FIRST. A contributor is
already engaged and will scroll — the person who has not decided yet will not. So the top of the file
is now, in order: get a binary, watch the loop close on a fake provider, create/change/delete real
capabilities, point it at a real cloud, drive it from an agent. The conceptual material and the build
instructions keep their content and move below, with the former Quickstart renamed to say plainly
that it is for working ON Groundhold rather than with it.
Three things this forced into existence rather than merely documented:
(1) **The lifecycle is now an example, not a claim.** `examples/lifecycle/` carries the three stages —
create two capabilities, tighten the contract to EU residency and watch a us-east-1 proposal get
refused, retire a capability and watch `--yes` REFUSE to cover destruction until `--allow-data-loss`
is added. All three run on `fake` and are asserted by `examples/check.sh` (D346), including that the
delete names its target from the recorded binding rather than guessing from the edited file. The
residency refusal is pinned as a REFUSAL: a constraint that quietly stopped biting would be the worst
regression this project could ship, and it now cannot happen silently.
(2) **Credentials are stated honestly, for all three clouds.** Only GCP had a documented auth story
(spec/providers/gcp.md); AWS and Azure had it in code comments. The README now says what each driver
actually reads — AWS: the three standard env vars ONLY, with `~/.aws/credentials` and `AWS_PROFILE`
deliberately NOT consulted; GCP: token → `service_account` key file → metadata server, explicitly not
ADC; Azure: an AAD bearer token in the environment. This is a NARROW adapter, and a cloud engineer
who assumes the SDK credential chain will be surprised, so the surprise belongs on the front page
rather than in a stack trace. The uneven maturity is stated in the same breath instead of implied.
(3) **A binary you can download beats a binary you must build.** The release workflow published
`groundhold_<version>_<os>_<arch>`, which cannot be linked as "the newest" — GitHub's
`/releases/latest/download/<asset>` resolves only a FIXED name. It now also publishes version-less
copies of the same bytes, so a one-line `curl` install exists that never goes stale. The versioned
names stay for pinned and archived downloads.
Open, and NOT papered over: the public repository has no releases yet, so the download link is dead
until a tag is pushed there. Writing a link that 404s would be exactly the kind of unchecked claim
D346 exists to prevent, so this is recorded as a launch step rather than presented as working today.

## D348. The distinguishing behaviour is shown, not asserted — and the screenshot is generated, never drawn
The README described what the system believes and demonstrated that it runs, but the things that make
it different — four-valued verdicts, provenance as a type, refusal-as-a-result, a deterministic core —
were inferable at best. Naming them in a feature list would have been the wrong fix: a list of claims
is exactly what a reader discounts. So the front page now shows ONE screen of real `verify` output and
reads it back: `c-rto` is `unknown` rather than `false`; the two dimmed rows are provenance rendered as
brightness and the summary counts them; the dim line teaches in passing; the run ends BLOCKED with no
flag that could have let it through; nothing in the loop involved a model. Six properties, one image,
no adjectives. A second section ("what you meet later") covers the ledger, signed events, capsules and
the anchor, permission preflight, adoption and parity — deliberately below the fold, because they are
what makes the front page hold up rather than what earns attention.
The screenshot is GENERATED (`scripts/ansi2svg.py`), never hand-drawn. The presentation layer (D89/D90)
carries meaning in colour and brightness — yellow is `unknown`, red is `violated`, a dimmed row is a
verdict resting on an inferred value — and a markdown code block silently discards all of it, which is
how a project ends up illustrating a feature it cannot show. So the real bytes are captured under a pty
and rendered to SVG by a tool that draws what the program printed and nothing else. A hand-made
terminal mock would be precisely the unchecked claim D346 exists to prevent.
Two findings from building it, both kept rather than hidden. The glyph vocabulary is only as good as the
reader's font: the first render showed tofu where every `✓` belonged, fixed by leading the font stack
with a family that actually carries U+2713 — worth knowing, since the same substitution can happen in a
user's terminal. And `converge` REDRAWS its phase checklist in place (cursor-up, erase-to-end), so its
output is an animation, not a document: a faithful still needs a real VT emulator, and a naive capture
stacks every frame. Rather than ship a screenshot that misrepresents what the terminal shows, converge
stays a text block and the animated display is recorded here as a known limit of static capture. Only
the honest image shipped.
