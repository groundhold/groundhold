# Schema-driven mapping documents (v0.1)

A **mapping document** promotes a vocabulary's `mappings:` table from prose to
data, so groundhold can read/write a resource type without hand-coding a Go driver
for it. This is the runtime half of "learn from the API contract": the machine
derives the mechanical facts, a human authors the meaning, and a hash pins them
together. It is Shape C from the design pass (two independent reviewers): a runtime-generic
engine driven by first-class, curated mapping documents — never a runtime that
interprets a live schema heuristically.

## Two authorship domains (the invariant that keeps it honest)

- **`resource:` — machine-authoritative.** A projection of the API contract:
  group / version / kind / plural / scope. Regenerated from the API's OpenAPI, it
  is a *refresh*, never a re-review. A human editing it is the bug.
- **`attributes:` — human-authoritative.** Which fields are the SEMANTICS an
  organization contracts, bound to vocabulary attributes. The generator emits
  nothing normative here — not even a ranked suggestion, because a pre-selected
  list gets rubber-stamped. The default is OUT (the vocab discipline: "when unsure,
  leave it out"); a field enters only when a human binds it.

A schema field becomes a contract attribute only via **two commits in two
domains**: (1) the attribute exists in the capability vocabulary (`spec/vocab/`,
dual-implementation, semantics review), and (2) a mapping references it. The engine
refuses any mapping attribute absent from the vocab, and the generator has no write
path into `spec/vocab/`. Auto-absorption of schema fields into the type system is
therefore structurally impossible.

## The closed operator set + named lenses (invariant #4 at the driver layer)

The engine applies a CLOSED operator set. v0.1: `copy` (raw field value), `const`
(a literal), `quantity-int` (a k8s quantity string → integer; non-integer → a
diagnostic, never a fabricated number). Growing the set is a spec change with a
conformance case and a DESIGN entry (invariant #5) — never an ad-hoc addition.

Anything conditional — NetworkPolicy's "default-deny only when policyTypes has
Ingress and the rule list is empty", RBAC's verb-class derivation — is a **named
lens**: an in-tree Go function referenced *by name* from the mapping, golden-tested
individually. Complexity is met with more named lenses, never a richer expression
language. `fieldpath/v1` is deliberately tiny: dot-separated identifiers and
bracket-quoted keys (`spec.hard["limits.cpu"]`) — no wildcards, indices or
predicates.

## Fieldpath grammar (`groundhold/fieldpath/v1`)

A path is a sequence of segments. A segment is either a bare identifier (between
dots) or a bracket-quoted key `["…"]` (for keys containing dots or slashes, like
`spec.hard["limits.cpu"]` or `metadata.labels["a/b"]`). Navigation is exact-match
map descent; a missing segment yields "absent" (the op emits no observation), never
an error or a guess.

## Schema fingerprint and drift (D132 applied to mappings)

A mapping declares its algebra (`mapping: v0.1`, `fieldpath: groundhold/fieldpath/v1`);
an engine that does not implement a declared op or algebra refuses **by name**,
never guesses. A mapping is authored against a specific schema, and the honest
tripwire against drift is a two-level fingerprint (wired in a follow-on slice):
`schema.fingerprint` over the whole resolved GVK schema, and `schema.mappedSurface`
over exactly the mapped field paths + identity facts. Drift OUTSIDE the mapped
surface is a diagnostic; drift INSIDE it (a mapped path vanished, changed type, or
lost an enum member) is a hard refusal (`mapping-schema-drift`) — the engine must
never reinterpret a diverged live schema, because best-effort is silent semantic
migration.

## Provenance and community drivers

The mapping's own content hash is pinned in conformance, and its `mappingHash`
travels into the observations/bindings/receipts produced through it (the D102/D103
evidence-that-travels pattern), so every fact is traceable to the exact mapping
that produced it. Because a mapping document cannot execute or exfiltrate, it is
also the community-driver format for the data tier: a contribution is a mapping doc
plus fixtures CAPTURED from a live API server (never authored by the mapping's own
author — a self-consistent lie is the failure mode) plus a passing run of the
driver conformance kit. New lenses remain code contributions under the existing
driver-authoring discipline.

## The differential pin (how a mapping earns trust)

A mapping is trusted the same way a hand-coded driver is: golden-tested. For a
resource that still has a hand-coded twin, the engine's output is asserted
BYTE-IDENTICAL to the hand-coded observe against the same recorded fixtures — the
hand-coded driver is the oracle. That pin is also the migration tool: once a mapped
service is byte-identical across the full fixture suite, the hand-coded twin is
deleted (the definition of done per service), so the two dialects never coexist
forever. ResourceQuota (`quota`) is the first fully migrated service: its
hand-coded observe/build/create/update/delete were deleted and the driver now
routes it through the engine.

## Where mappings live

The mapping documents are DRIVER artifacts in data form, so they ship embedded in
the binary (`go/internal/k8s/mappings/*.yaml`, `go:embed`) — a self-contained
runtime with no path dependency, which is exactly what lets a migrated service's
hand-coded twin be deleted safely (the generic path is always present). The
dispatch routes a service through the engine when its mapping is present and
`writeSafe` (no lens — a read-lens is not invertible, so a lensed mapping keeps its
hand-coded write until a write-lens lands).
