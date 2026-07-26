# Providers and drivers

A driver adapts the executor's provider interface to one cloud
service. The GCP Cloud SQL driver is the exemplar
(`go/internal/gcp/`, `spec/providers/gcp.md`).

## The core interface

`Name · Validate · Create · Observe · ClassifyChange · Update · Delete`

- **Validate** is refuse-before-mutate: a semantic attribute the
  driver cannot honor refuses in preflight, never by silent drop.
- **Create** derives a DETERMINISTIC name from
  (project, environment, capability, generation) — names are the
  idempotency mechanism and outlive request-dedup windows.
- **Observe** reverse-maps provider state into vocabulary attributes
  through a PURE function pinned by golden tests. Honesty rules:
  absent fields emit nothing; unknown enums skip with a diagnostic;
  measurements are never fabricated from config intent.
- **ClassifyChange** is pure provider knowledge: can this transition
  be honored in place? (`mutable | immutable | unsupported | caveated`)
- **Delete** re-checks ownership labels and never auto-disables
  deletion protection.

## Optional capabilities

| interface | verb | rule |
|---|---|---|
| `Discoverer` | `discover` | strictly read-only enumeration |
| `Reconciler` | `resume` | strictly read-only conclusion of lost outcomes; not-found ≠ failed for creates |
| `Prober` | `probe` | outcome measurements; intrusive ones run only under double consent |
| `Preflighter` | `apply` | read-only IAM permission check before mutating (D75); a refusal is trustworthy, a pass is evidence not proof |

## Writing one

Start from the GCP driver's shape: pure request builders + golden
tests (byte-exact bodies for fixed inputs), an httptest shell for the
network layer, ownership labels on everything you create, `unknown` as
a first-class outcome carrying the real operation id. Then run the
conformance suite — `impl: go` cases exercise driver-shaped behavior
through the fake provider, and your driver earns trust the same way
the runtime did.

## Writing a driver

One pattern, five disciplines, a security checklist, and a certification every
driver must pass — see `spec/providers/AUTHORING.md`. `provider.CertifyDriver`
is the gate; `go/internal/gcp/` is the worked example.
