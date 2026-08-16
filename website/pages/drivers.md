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
| `ResourcePreflighter` | `apply` | the same check at RESOURCE scope, where the provider can answer per-object |
| `CompetingManagers` | `adopt` | names another controller already managing the object. **A driver without it can certify, ship, and be adopted on top of someone else's resource** — found on a live cluster, where six of ten mapped services failed exactly this way (D1090) |
| `Claimer` | `adopt` | stamps authorship at takeover, so a binding says who owns the resource and since when |

**This table is the harm-shaped subset, not the whole set.** The provider package
defines SIXTEEN optional interfaces and every one of them is implemented by a shipped
cloud driver. The four above the line are the ones most drivers want; the three below
it are here because omitting them is not a missing feature but a hole — a driver that
skips them passes certification and then does something unsafe quietly. The remaining
nine are convenience, batching and progress reporting, and they are listed with what
each protects in [`spec/providers/AUTHORING.md`](https://github.com/groundhold/groundhold/blob/main/spec/providers/AUTHORING.md).

Saying the set is incomplete is the point: this page said "optional capabilities" over
four entries for months, and an author who read only this page had no way to learn the
other twelve existed.

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
