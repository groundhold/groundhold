# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project is
**pre-release (`v0.x`, experimental)**, so there are no versioned releases yet.
See [`docs/MATURITY.md`](docs/MATURITY.md) for what is proven vs merely built.

The authoritative, rationale-carrying decision log is
[`docs/DESIGN.md`](docs/DESIGN.md) (append-only). This file is the human-facing
summary; DESIGN.md is the record.

## [Unreleased]

### Added
- **Post-apply reachability probe** on all three clouds (AWS CloudFront/Function
  URL, GCP Cloud Run, Azure Container Apps): after a public edge is provisioned,
  a real HTTPS GET measures whether it actually serves, four-valued — a 403 or an
  unreachable edge is never reported as clean success, and an unreachable-from-here
  is never mistaken for a denial. `converged` stops meaning "APPLIED but silently 403".
- **API-drift detection**: a deterministic requirement-invariant registry (the
  known "provider X requires Y since date Z" facts, each bound to a build-failing
  regression guard) plus daily AWS/GCP public-edge functional canaries that
  converge a real edge and read the outcome — catching a silent provider behaviour
  change before it reaches a user.
- **CDN custom domains** on AWS CloudFront and Azure CDN (aliases + viewer
  certificate), and a **safe per-origin cache default** (a dynamic origin is not
  cached — no stale/cross-user responses).
- **Serverless-to-database wiring**: Lambda VPC-attach + environment operands, an
  Aurora/Cloud SQL connection-endpoint output, and CloudFront+OAC → IAM Function
  URL so a public serverless front needs no anonymous exposure — all wired by
  `$ref`, not hand-pasted literals. Adopt→**claim** for Lambda (brownfield
  takeover without delete+recreate).

### Fixed
- An unknown `implementation:` operand is now **refused at compile** (`unknown-operand`)
  instead of silently dropped — a resource that quietly ignored a declared operand
  was the cardinal trust failure this closes.
- Advisory attributes (e.g. `cost.monthly`, forecast-only) no longer block an
  otherwise-legal in-place update.
- AWS Lambda joined the `resume` reconciler — a killed mid-create no longer leaves
  the ledger permanently stale.
- Serverless idempotency-token and provider-requirement gaps (scheduler
  `ClientToken`, backup-vault `$ref`, the Oct-2025 dual-action Function-URL grant).

## [v0.1.3] - 2026-07-19

### Added
- **Breadth drivers** across AWS, GCP and Azure (~130 service mappings) with a
  cross-cloud parity program: honest per-cloud gaps, pure mapping cores + golden
  and `httptest` tests, driver certification (`provider.CertifyDriver` and the
  adversarial `CertifyDriverNet` honesty harness).
- **Evidence that travels**: detached Ed25519 event/snapshot signatures and
  portable evidence **capsules** — a receiver verifies one capability's subchain
  with no ledger and no groundhold deployment; the tail **anchor** counters omission.
- **Presentation layer**: a closed banner vocabulary, shape-first glyphs,
  refusal-is-not-failure, the stderr/stdout channel rule; `explain` for any error
  code or vocabulary path.
- **Outcome probes**, **posture** classification, **refresh**, **crawl**,
  disaster-recovery **restore/merge** from capsules, and a **manifest anchor**
  that closes the per-capability-forest tamper gap.
- Authoring boundary: the `no-assumed-hard-basis` gate a contract can arm so a
  hard constraint may not seal on an assumed value (the verifier still only
  reports the basis — policy gates).
- Developer guides: authoring a driver (`spec/providers/AUTHORING.md`) and a
  vocabulary (`spec/vocab/AUTHORING.md`); a `NOTICE` and a structured
  `docs/THREAT_MODEL.md`.

### Changed
- Permission preflight (the plan declares per-action permissions; `apply` checks
  the acting identity before the lease).
- Repair/anchor/deposed/concluding-updates; two early adversarial review rounds
  hardened the executor and ledger (lease-clock, deposed safety, deletion-
  protection fail-closed, resume identity, providerId path validation).

### Security
- An adversarial-hardening series closed a recurring fail-open / fabrication /
  nondeterminism class, each pinned by a fails-without-fix case:
  ledger hash-chain + replay (forest-anchor, snapshot projections, diagnosis);
  compiler determinism; capsule/signature/restore forgery axis;
  observe/probe (future-dated fresh-read, evidence-bar enforcement, per-source
  retention); brownfield unadopt (authorship-claim clearing, origin/pending
  gates); converge destructive-plan fail-closed; presentation banner honesty.

<!-- On the first tagged release, move Unreleased items under a version
heading with the date, and start a fresh Unreleased section. -->
