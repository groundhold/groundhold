# Groundhold (working name)

> AI should not write Terraform. It should emit verifiable contracts —
> and a deterministic runtime should validate, gate, execute and prove them.

[![CI](https://github.com/groundhold/groundhold/actions/workflows/ci.yml/badge.svg)](https://github.com/groundhold/groundhold/actions/workflows/ci.yml)
[![CodeQL](https://github.com/groundhold/groundhold/actions/workflows/codeql.yml/badge.svg)](https://github.com/groundhold/groundhold/actions/workflows/codeql.yml)
[![Security](https://github.com/groundhold/groundhold/actions/workflows/security.yml/badge.svg)](https://github.com/groundhold/groundhold/actions/workflows/security.yml)
[![Lint](https://github.com/groundhold/groundhold/actions/workflows/lint.yml/badge.svg)](https://github.com/groundhold/groundhold/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MPL--2.0-blue)](LICENSE)

**Status: private, pre-release (`v0.x`, experimental). Build quiet, launch loud.**
An honest self-assessment — what is proven vs merely built vs designed — lives in
[`docs/MATURITY.md`](docs/MATURITY.md): the verification core is proven and
adversarially hardened; execution has closed the loop against two real clouds
(GCP author-run, AWS at one external pilot that filed 36 findings) while Azure
is golden-tested only; there has been one pilot, no external security audit and
no production record.

## What this is

A specification and reference implementation for **Infrastructure Contracts**:
a typed, machine-first medium in which agents (and humans) declare *what must
be true* about infrastructure, instead of writing the implementation by hand.

Core ideas:

1. **Constraints, not resources, are the unit of meaning.** A contract says
   `dataResidency in EU`, `rpo <= 5m`, `publicExposure == false`. The
   implementation is an output, not the source of truth.
2. **Provenance is a type.** Every value knows whether it was `declared`,
   `inferred`, `assumed` or is `unknown` — because the author is a
   probabilistic model and the medium must say so.
3. **Four-valued verification.** Every constraint verdict is `satisfied`,
   `violated`, `unknown` or `unverifiable`. The system never pretends to have
   checked something it hasn't. `unknown` on a hard constraint blocks execution.
4. **Constraints declare how they are proven** (`static`, `provider-api`,
   `probe`). An RTO claim is not satisfied by configuration — only by a
   measured restore test.

## Repository layout

```
spec/           the normative artifacts: schemas, vocabularies, canonicalization,
                state model, sealed plan IR, examples
ref/            reference implementation (Python): loader, four-valued verifier,
                canonical hashing, concurrency scenario engine
go/             Go runtime — passes the identical conformance suite through
                its own binary
conformance/    language-independent test cases — the real definition of semantics
docs/           design decisions and rationale (D1–D203)
```

## Quickstart

Requirements: Go ≥ 1.25, Python ≥ 3.12 + PyYAML. Nothing else — the runtime
is stdlib + yaml only.

```
make check                              # every gate: vet + all suites, both implementations
cd go && go build -o ../bin/groundhold-go ./cmd/groundhold   # the CLI binary
make verify          # verify the example candidate against the example contract
make conformance-go  # just the Go runtime, through its own binary
```

A full walkthrough (your first contract, converge, brownfield adoption) lives
in [`website/pages/quickstart.md`](website/pages/quickstart.md); how to
contribute is in [`CONTRIBUTING.md`](CONTRIBUTING.md).

Document identity and the concurrency semantics are executable too:

```
ref/groundhold.py hash spec/examples/orders-production.contract.yaml
bin/groundhold-go  hash spec/examples/orders-production.contract.yaml   # same bytes
```

Example output — note the system refusing to execute because RTO is only
provable by a restore test:

```
  ✓ c-residency   satisfied
  ✓ c-private     satisfied
  ✓ c-encrypted   satisfied
  ✓ c-rpo         satisfied
  ? c-rto         unknown      requires probe verification
      recovery.rto — time to restore service after failure;
      a value here is a claim until a restore test measures it
  ✓ c-budget      satisfied    [inferred]

  5 satisfied, 0 violated, 1 unknown, 0 unverifiable
  BLOCKED: c-rto unknown — recovery.rto requires probe verification
```

## Roadmap (vertical slice, in order)

> This is the ORIGINAL vertical slice (through ~D64/D75), kept for the shape of
> the thesis. The system has since grown far past it: breadth drivers across
> three clouds (~128 service mappings), an EKS reference substrate, an
> adversarial-hardening series (D182–D195), intra-plan operand references so a
> contract wires itself instead of pasting ARNs (D226/D275–D286), and the field
> hardening a real AWS pilot forced (D248–D283). `docs/DESIGN.md` is the current
> record — every decision and why; `docs/MATURITY.md` says what is proven vs
> merely built, and names the gaps.

- [x] Contract spec v0.1 + four-valued verifier + conformance suite
- [x] Implementation Candidate spec + candidate emission skill for Claude Code
- [x] Go verifier, validated against the same conformance suite (D24 —
      everything below is born in Go)
- [x] Canonicalization + hashing spec with domain separation (D34,
      `spec/canonicalization.md`; reports carry contractHash/candidateHash)
- [x] State Model v0 as spec: ledger events, bindings, observations,
      operation receipts, heads/CAS, lease/fencing semantics (D27–D33, D35;
      `spec/state-model.md`)
- [x] Minimal Sealed Plan IR: read/write-sets, preconditions, toolchain
      versions, idempotency keys, multi-dimensional risk (D33, D36;
      `spec/sealed-plan.md`)
- [x] Concurrency conformance: deterministic scenario engine (D37) — CAS
      conflicts, stale plans, expired leases, resumed stale workers,
      receipt reconciliation
- [x] Compiler v0: verified candidate → Sealed Plan (D39 — standalone
      runtime, no Terraform on the execution path; `.tf.json` demoted to
      an optional future export)
- [x] Forecast v0: the preview stage — deterministic prediction with
      explicit epistemics (D40/D41; `spec/forecast.md`)
- [x] Executor v0: apply gated by the ledger — decision-heads CAS, leases
      with fencing, write-ahead receipts, per-action bindings (D42;
      `spec/executor.md`; deterministic fake provider)
- [x] Permission preflight (D75): the plan declares the provider permissions
      each action needs; apply checks the acting identity holds them (GCP
      `testIamPermissions`) before the lease — refuse before mutating. A
      preflight refusal is trustworthy; a pass is evidence, not proof.
- [x] GCP Cloud SQL driver (D43; `spec/providers/gcp.md`) — pure mapping
      core with golden tests, stdlib-only narrow auth, label-gated 409
      continuation, unknown-not-failure operation semantics
- [x] `observe` (D44): reverse mapping as a pure golden-tested function,
      derivation-tagged facts (config-intent vs measured), never
      fabricating measurements from intent
- [x] Forecast consumes observations (D45): four-valued attribute
      predictions (match/differ/unknown/unverifiable), freshness
      degradation, drift made loud — the ledger closes the loop
- [x] Update end to end (D46): compiler classifies bound capabilities
      against fresh observations, reviewed change-sets in plans,
      settingsVersion-pinned patches, will-update forecasts
- [x] Retirement and delete (D47): explicit `state: retired` (never
      absence), pinned delete targets, unconditional autonomy gate,
      structured tombstones, deletion protection default-on
- [x] Replace as create-before-destroy composition (D48): reviewed
      reasons, generation-discriminated names, scoped stateful consent
- [x] First real-cloud integration run (2026-07-11, GCP Cloud SQL,
      MySQL 8.0): full lifecycle — create, observe, convergence-refusal,
      retirement with a real tombstone. One bug found and pinned:
      retirement plans read provider identity from bindings
- [x] Authoring boundary made productive (D49): emit-candidate +
      draft-contract skills (the agent proposes, the human publishes),
      workdir convention, porcelain never-hide rules
- [x] MCP server (D50): the lifecycle as gated tools — stdlib JSON-RPC,
      draft-only inline YAML, two-step apply with single-use tokens,
      read-only by default
- [x] Converge porcelain (D51): one verb for the whole loop; a
      converged world is success; destruction takes explicit
      --allow-data-loss on top of contract consents
- [x] Brownfield onboarding (D52): discover → draft with
      observed-not-intent markers → adopt (must not lie) → converged
      no-op as proof of takeover; unadopt releases without deleting
- [x] Terraform/pulumi import (D53): `groundhold hints` — state parses
      into adoption hints, never a contract; live observations win
      every disagreement
- [x] Ledger exporters + audit (D54): `export` streams the ledger as
      ndjson/CloudEvents (hash as id); `audit` judges recorded reality
      against the contract and emits violation.detected — drift becomes
      an alert without knowing which alerting system exists
- [x] Identity vocab (D55): SSO + OAuth-client capability types — MFA,
      enforced federation, grant discipline, scope allowlists; the
      verifier needed zero changes
- [x] Executor resilience (D56-D58): coordination clock refuses
      backdated writes; `resume` concludes lost outcomes read-only and
      never guesses; `deposed` surfaces orphans of failed replacements
- [x] Corruption + tail hardening (D69-D72): `repair` diagnoses and
      quarantines a corrupt ledger under fingerprint consent; `anchor`
      closes the last-line boundary from outside the file;
      `plan --deposed` compiles pinned orphan deletes; update receipts
      carry a verifiable target shape so resume concludes them
- [x] Outcome probes (D59): `probe` — restore tests and connection
      attempts as measured observations; double-consent for intrusive;
      a claim becomes a measurement and the thesis loop closes
- [x] Breadth vocabularies (D60): object-storage, private-network,
      container-workload — including the first stateless capability
- [x] Voice track (D61): transcript-to-contract skill — the runtime
      never hears the meeting; a misheard word can only produce a
      wrong draft, never a wrong apply
- [x] Pre-launch review (D62): 9 bugs found and pinned before anyone
      else could find them
- [x] Hardening for launch (D64): machine error codes, --explain,
      output schemas, CI examples
- [x] Docs site (website/) and the voice worked example
      (examples/voice/: transcript → draft with supersession)
- [ ] Launch: public org, publish, Pages

## Since the vertical slice (the short version)

- **Breadth**: 133 service mappings across AWS (50), GCP (42) and Azure (41),
  fulfilling 46/41/41 distinct capability TYPES respectively — one type is often
  reached by several services (rds and aurora both fulfil
  `capability.database.relational`, D76). Counts are read from the drivers' own
  certified `ServiceCapabilities()` maps, not from prose. Reached through a
  parity program (D166–D172) that records per-cloud gaps honestly instead of
  faking symmetry.
- **Contracts that wire themselves** (D226, D275–D286): an operand may be a
  typed reference to another capability's output — resolved from the producer's
  receipt in the same plan, or folded at compile from a fresh observation when
  the producer already exists. No interpolation, no expression language: a
  reference is a structured node, kind-checked, and every failure refuses.
- **Field hardening** (D248–D283): a real AWS pilot drove sequential cluster
  upgrades through `converge` and found what hermetic tests could not — a poll
  against a nonexistent API path whose unit fake mirrored the same wrong
  assumption, and a transport regression that broke every request while CI
  stayed green. Both classes now have gates that touch a real endpoint
  (D272/D274).
- **Adversarial rounds** (D178–D195, D286, D312–D323): the recurring find is a
  *fail-open in the direction of "everything is fine"* — including ones this
  project introduced itself and then closed. The second sweep audited the
  disaster-recovery family, the MCP boundary, the gentle crawl, adoption and the
  proactive classifier; it found a guard keyed on the very field it guarded, a
  failure code an author could choose by naming a capability `api-keys`, a
  confirmation token that pinned the plan but not where it landed, a rate limiter
  one unset field turned off, and — sharpest — that invariant 0 checked the
  safety clock was PRESENT, never that it PARSED (D323). Most of what it probed
  held: the write-up records what was checked and found sound, not only what
  broke.
- **Debts paid, with the gate that keeps them paid** (D306–D311, D317): every
  read that produced nothing now names its cause instead of saying "unreadable"
  (639 → 0, gated); a failed mutation no longer pastes the provider's raw
  response — which is persisted in the ledger and signed into capsules — into
  the receipt; an attribute's evidence class moved out of ~190 hand-copied driver
  cases into the vocabulary that defines it.

## Non-goals for v0.x

Cross-capability references, an expression language, contract inheritance,
organizational policy layers, a full capability taxonomy. Vertical before
horizontal: one full loop (intent → contract → verify → compile → sealed
apply → outcome) on a narrow slice beats a wide spec that executes nothing.

## License

Dual-licensed by component: **Apache 2.0** for the spec, conformance
suite, and reference implementation (`LICENSE`); **MPL 2.0** for the Go
runtime (`LICENSE-runtime`). Contributions are inbound=outbound under the
per-directory license — see `CONTRIBUTING.md`; the never-relicense
commitment is in `GOVERNANCE.md`.
