# Contributing to Groundhold

## The one rule that shapes everything

**The conformance suite is the source of truth.** A bug is not fixed —
a feature is not done — until it is pinned by a case in
`conformance/cases/` that both implementations pass.

## Development setup

Requirements: Go ≥ 1.25, Python ≥ 3.12 + PyYAML. No other dependencies —
the runtime is stdlib + yaml.

```sh
git clone git@github.com:groundhold/groundhold.git && cd groundhold
make check                                     # the gate: both implementations
cd go && go build -o ../bin/groundhold-go ./cmd/groundhold   # the CLI binary
```

Useful targets: `make check` (vet + validate + conformance, both
implementations — MUST pass), `make differential` (seeded cross-implementation
fuzzing, after semantic changes), `make conformance-go` / `make conformance`
(one implementation), `make verify` / `make plan` (run the example).

Layout: `spec/` (spec + vocabularies), `ref/` (Python reference),
`go/` (Go runtime), `conformance/cases/` (the source of truth),
`docs/DESIGN.md` (every decision, append-only).

## Reporting a bug

Use the issue template: expected behavior, actual behavior, and a
MINIMAL contract/candidate that reproduces it. You do not have to
write the conformance case yourself (maintainers label real-but-
unreduced reports `pending-conformance` and reduce them before
fixing) — but a report that arrives as a failing case gets fixed
fastest, because it arrives already true.

## Sending a change

1. Behavior changes MUST carry a conformance case. Case first,
   implementation second. Never edit an existing case's expectations
   to make code pass.
2. `make check` must pass — vet + go test + the full suite against
   BOTH implementations (Python reference and Go runtime). A change
   implemented in only one of them is not done.
3. After semantic changes run `make differential` (seeded
   cross-implementation fuzzing).
4. Design decisions are append-only: significant changes add an entry
   to `docs/DESIGN.md` explaining why — history is never rewritten.
5. Non-negotiable invariants: four-valued verdicts,
   no type coercion, provenance survives, closed operator set,
   deterministic verifier, fail-closed defaults.
6. No new dependencies (stdlib + yaml). Never generate raw Terraform/HCL
   as a deliverable — the compiler targets the Sealed Plan IR (D39).

## Your first change (the pattern)

1. Write a *failing* case in `conformance/cases/<area>.yaml` — copy the
   structure of an existing one (e.g. `update.yaml`).
2. `make check` → red. Good: the case now pins the intended behavior.
3. Implement it in the Python reference (`ref/groundholdlib/`) AND the Go
   runtime (`go/internal/`). A Go-only core (compiler, executor) marks its
   case `impl: go`.
4. `make check` → green, then `make differential`. Add a `docs/DESIGN.md`
   entry if the change is significant.
5. Open a PR labeled by the layer it touches.

## Writing a provider driver

Adapting groundhold to a new cloud service follows one pattern —
[`spec/providers/AUTHORING.md`](spec/providers/AUTHORING.md): a pure builder +
a thin network shell, five disciplines (build / test / validate / secure /
conform), and a security checklist drawn from real review findings. A driver is
done when it passes the certification (`provider.CertifyDriver`). Read
`go/internal/gcp/` as the worked example.

## Writing a vocabulary (a capability type)

Adding a new capability *type* — the attribute paths a contract can constrain —
follows [`spec/vocab/AUTHORING.md`](spec/vocab/AUTHORING.md): one judgment
(capability semantics vs implementation noise), the closed set of scalar kinds,
honest per-provider mappings, and a dual conformance case. The verifier,
compiler and audit pick up the new type with zero engine changes (D23) — the
meaning lives entirely in the declarative file.

A one-page map of both extension points (vocabulary + driver) and the whole
testing discipline is in the docs site: `website/pages/extending.md`.

## Layer labels

`spec` | `schema` | `conformance` | `runtime` | `driver` | `mcp` —
label your issue/PR by the layer it touches.

## Sign your work (DCO)

Contributions are accepted under the **Developer Certificate of Origin**
(<https://developercertificate.org>), not a CLA — no copyright assignment, in
keeping with the never-relicense promise (`GOVERNANCE.md`). Certify that you
wrote the change (or have the right to submit it under the applicable license)
by adding a `Signed-off-by` line to each commit:

```
git commit -s -m "your message"      # appends: Signed-off-by: Name <email>
```

The sign-off name and email must be real (no pseudonyms, no anonymous). A PR
whose commits are not signed off cannot be merged.

## Licensing

spec/, conformance/, ref/: Apache 2.0 (see LICENSE); go/ (runtime): MPL 2.0
(see LICENSE-runtime); third-party attributions in `NOTICE`. By contributing
you agree your contribution is licensed under the license of the directory it
lands in (inbound = outbound).

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
