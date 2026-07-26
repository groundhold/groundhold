# Extending groundhold (developer guide)

groundhold is meant to be extended along a few well-defined seams. Everything else
— the four-valued verifier, the ledger, the compiler, the sealed-plan executor —
is the fixed spine you extend *around*, not *inside*. This page is the on-ramp;
the deep guides are linked from each section.

## The one rule

**The conformance suite is the source of truth.** A change is not done until a
case in `conformance/cases/` pins it and BOTH implementations (the Go runtime
and the Python reference) pass. Case first, code second — never edit an existing
case's expectations to make code pass. Full contribution flow, setup, and the
"your first change" walkthrough live in
[`CONTRIBUTING.md`](https://github.com/groundhold/groundhold/blob/main/CONTRIBUTING.md).

## The two extension points

### 1. A capability type (vocabulary) — *what must be true*

A vocabulary file (`spec/vocab/capability.<domain>.<name>.yaml`) IS the type
system: it declares the attribute paths a capability has, their scalar kind, and
how each maps to real providers. Add one and the verifier, compiler, forecast
and audit pick up the new type with **zero engine changes** (D23) — the meaning
lives entirely in the declarative file, loaded identically by both impls.

The whole discipline is one judgment: **capability semantics vs implementation
noise** (residency/exposure/RPO-RTO/cost/protocol belong; instance tiers, disk
types, SKUs do not). Guide: [`spec/vocab/AUTHORING.md`](https://github.com/groundhold/groundhold/blob/main/spec/vocab/AUTHORING.md).

### 2. A provider driver — *how it is executed and observed*

A driver adapts the executor's provider interface to one cloud service
(`Name · Validate · Create · Observe · ClassifyChange · Update · Delete`, plus
optional `Discoverer`/`Reconciler`/`Prober`). It is a **pure mapping core +
a thin network shell**: the core is deterministic and golden-tested, the shell
is `httptest`-covered. Honesty is enforced, not hoped: absent fields emit
nothing, unknown enums skip with a diagnostic, measurements are never fabricated
from config intent. A driver is done when it passes `provider.CertifyDriver`.
Guide: [`spec/providers/AUTHORING.md`](https://github.com/groundhold/groundhold/blob/main/spec/providers/AUTHORING.md);
worked example: `go/internal/gcp/`.

## How you test (the same discipline everywhere)

| layer | what | command |
|---|---|---|
| **conformance** | the semantics — dual (Go + Python), the source of truth | `make check` |
| **differential** | seeded cross-implementation fuzzing after scalar/semantic changes | `make differential` |
| **golden** | a driver's pure builder — exact request bytes, no network | `go test ./internal/<driver>` |
| **httptest** | a driver's shell — happy path AND every error/loss branch | (same package) |
| **certification** | `provider.CertifyDriver` (static) + `certifynet.CertifyDriverNet` (adversarial honesty, D87) — every driver runs the SAME battery, so a check proven for one service can't be silently missing from another | (driver test) |

The invariants your change must never break (see the honesty rules): four-valued
verdicts (never collapse `unknown` into a boolean), no type coercion, provenance
survives, a closed operator set, a deterministic network-free verifier, and
fail-closed defaults. A change that weakens one of these is wrong even if the
suite is green — add the case that proves the invariant instead.

## Layer labels

Label your issue/PR by the seam it touches: `spec` · `schema` · `conformance` ·
`runtime` · `driver` · `mcp`.
