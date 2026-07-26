# Maturity — groundhold judged by its own discipline

groundhold's thesis is that a system must never claim to have checked something it
hasn't. This document turns that discipline on groundhold itself. Every row carries
a **verdict** and a **basis**, exactly as a verdict does — because a maturity
claim is a claim, and the medium must say how it was earned.

- **verdict** — `proven` (exercised end to end and pinned) · `built`
  (implemented and pinned, but not against the real world) · `partial`
  (real on one surface, unproven on others) · `designed` (specified/coded,
  never run) · `planned` (not yet built).
- **basis** — `measured` (run against a real cloud) · `config-intent`
  (golden/recorded/fake provider, or conformance only) · `assumed`
  (reasoned, not executed).

The honest one-line summary: **the verification + state core is proven and
adversarially hardened; execution has now closed the loop against ALL THREE
clouds — GCP (author-run), AWS (one external pilot operator on their own
account, 36 findings) and Azure (author-run, 2026-07-24, which immediately
found that its whole observe family had never worked outside tests); there has been one external pilot, no external security audit, and no
production incident record. This is `v0.x`, experimental — an RFC you can run,
not a product with an SLA.**

## Core (the deterministic spine)

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Four-valued verifier, typed scalars, no-coercion | **proven** | measured | Dual impl (Go + Python) through one 510-case conformance suite; Strong-Kleene + injective canonicalization adversarially audited (D178–D179). The strongest claim in the system. |
| Canonicalization + hashing (cross-language identity) | **proven** | config-intent | Byte-identical hashes pinned across both impls + `make differential`; audited for round-trip injectivity (D179). "measured" would mean external cryptographic review — not done. |
| Ledger / state model (hash chain, replay, snapshot, anchor) | **proven** | config-intent | Adversarially audited D182–D185 (forest-anchor, snapshot projections, replay); snapshot-equivalence fuzz. It is a local deterministic engine — "real cloud" does not apply; "measured" would mean an external tamper-evidence review. |
| Capsules, ed25519 signatures, DR restore/merge | **proven** | config-intent | Recompute-from-bytes verify, fail-closed signatures, fork-refusal + write-then-replay restore; audited D187. No external crypto review. |
| Compiler → Sealed Plan IR (deterministic seal) | **proven** | config-intent | Conformance-pinned plans; per-capability dispatch + evidence gates audited (D186, D190, D195). |

## Execution (where reality enters)

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Executor / apply (leases, fencing, write-ahead receipts, resume, deposed) | **proven** | measured (GCP + AWS) | Full lifecycle on GCP (author-run, 2026-07: Cloud SQL, Cloud Run, VPC/subnet, canary create+retire) AND on AWS at an external pilot (2026-07: multi-action plans over a 26-capability contract, a ~40-min long-running cluster upgrade, `resume` concluding a pending receipt after a kill, throttle/409 retry paths, ~9 refusals that each landed BEFORE any mutation — `events: []`). The write-ahead/lease machinery is the part the field exercised hardest. Mutation logic audited D180. Azure execution is still fake-provider only. |
| GCP drivers (45 services) | **partial** | measured (a subset) / config-intent (the rest) | Real create/observe/converge/retire lifecycles for Cloud SQL, Cloud Run, VPC/subnet (author-run). The other ~39 services are golden/`httptest` only — the same honest split AWS now carries. |
| AWS drivers (53 services incl. the Acme reference EKS substrate) | **partial** | measured (a subset) / config-intent (the rest) | An external pilot operator stood the substrate up on their own account (2026-07): EKS cluster + managed node group + addons + pod-identity, sequential version upgrades 1.33→1.36 driven end to end by `converge`, Aurora Serverless v2 with enforced TLS + CMK + managed password, ALB/ACM, Bedrock EU inference profile, ECR/S3/KMS/CloudTrail/CloudWatch-logs/SQS/service-accounts, ElastiCache, budgets; plus `discover` over a real account (212 resources), per-resource `adopt`, and `resume`/reconcile. That run produced 36 findings, of which the create/upgrade/adopt/resume classes are fixed and pinned (D248–D283) — the engagement then PAUSED, so several classes are fixed-but-not-retested in the field (notably the D281 IAM-propagation retry and the D283 fold branch), and one risk stays deliberately unproven (grant ordering vs cluster create). The other ~38 services remain golden/`httptest` only. Observe-honesty audited D181. |
| Azure drivers (44 services) | **partial** | measured (vnet) / config-intent (the rest) | First real-Azure run 2026-07-24 (D294): a VNet through the FULL loop — create, observe, a converged no-op re-plan, retirement with a tombstone, teardown clean. That run also proved Azure `observe` had NEVER worked outside tests (the driver built its URLs from a pin `observe` deliberately does not set), so the 40 other services are golden-only AND were, until now, unobservable in production. Their read paths share the fixed choke point but none has been run for real. |
| Cross-cloud parity (AWS/GCP/Azure) | **built** | config-intent | Parity program complete (D166–D172); honest per-cloud gaps recorded. A machine-verifiable parity matrix is deferred. |
| Observe / probe (reality → typed observations) | **partial** | measured (GCP + AWS) / config-intent (probes) | Pipeline audited D189–D191 (future-dated fail-open, evidence-bar enforcement, per-source retention) and D286 (the wiring namespace — a fail-open the author introduced and closed). `observe` ran for real on GCP and AWS; the AWS pilot also proved the gap this pipeline still has: several declared attributes the drivers cannot read back (a reconcile then reports them unverifiable rather than checked). Probes (restore tests, reachability) remain golden/fake-exercised — no real recovery event has been measured. |
| Discover / adopt / onboarding | **partial** | measured (GCP + AWS) / config-intent (Azure) | Adoption-must-not-lie audited D192. Run for real on GCP and on AWS (`discover` over a live account, per-resource `adopt`, create-time adoption of server-assigned ids). The field also proved the model's edges: 1:N adoption (one capability, many resources) is unsupported, and a custom-named brownfield resource needed explicit naming to bind rather than duplicate (D261). Azure golden only. |

## Surfaces

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Converge porcelain, presentation/banners | **proven** | config-intent | Audited D193–D194 (destructive-plan fail-closed, VIOLATED-not-REFUSED). Human-facing, deterministic. |
| MCP server (gated tools, two-step apply) | **built** | config-intent | Protocol + gating pinned; hardened (token consume, symlink confinement, and D319: the confirmation token binds the whole decision — plan AND target — after an audit found it could be spent redirecting the same plan at another ledger/provider). Not exercised by a real external MCP client at scale. |
| Console / BFF (read-only projection) | **partial** | measured (real AWS exports) / config-intent | Read-model + honesty guards audited; `console-live/` now holds REAL output (a live AWS discover, verify reports, ledger exports) rather than simulated fixtures. The projection tracks the runtime through D286 (operand provenance, evidence-vs-wiring split). Not exercised by a real operator at scale. |
| Voice / authoring skills, docs site | **built** | assumed | Left of the execution boundary; a misheard word can only produce a wrong draft, never a wrong apply. Utility unproven with real authors. |

## The gaps we are NOT hiding

1. **Azure has met reality exactly once, on one free resource.** The loop
   closes (D294), but on a VNet — the expensive, stateful surfaces (AKS,
   Flexible PostgreSQL) have never run, and 40 of 41 services remain
   golden-only. One green canary is a floor, not a claim.
2. **One paused pilot is not a track record.** There has been exactly ONE
   external operator, on one account, for a few weeks, and the engagement is
   currently paused — so the most recent fixes (D281 IAM-propagation retry,
   D283 fold branch, D286 wiring split) are pinned by tests but have NOT been
   re-run in the field. No external security audit exists; no production
   incident record exists.
3. **The field found things the gates did not.** The pilot filed 36 findings,
   including bugs every hermetic suite passed — a poll against a path that
   does not exist in the cloud API (the unit fake mirrored the driver's wrong
   assumption, so it was blind by construction, D273), and a transport
   regression that broke every request while CI stayed green (D269/D271).
   Two mechanisms now exist because of that (a live smoke and an
   endpoint-reality gate, D272/D274), but the lesson stands: internal gates
   under-sample reality.
4. **Some declared attributes cannot be read back.** Several capability
   attributes the drivers can SET they cannot OBSERVE, so a reconcile of a
   bound resource reports them unverifiable rather than checked. The system is
   honest about it (D249/D136), but honest-about-a-gap is still a gap.
5. **One reference verifier, one runtime.** The *verifier* is dual (Go + Python)
   and that is what conformance pins. The *runtime* (executor, ledger, drivers)
   is Go-only by design (D24) — there is no second implementation to differ against
   below the verifier.
6. **The README summarises; DESIGN.md is the record.** The roadmap section is
   deliberately frozen at the ORIGINAL vertical slice (~D64/D75) for the shape of
   the thesis, with a "Since the vertical slice" summary carrying breadth, the
   self-wiring contracts, field hardening and both adversarial sweeps. That
   summary will always trail DESIGN.md, which is the only complete record. (This
   entry used to say the README "stops at ~D64/D75" with none of the later work
   reflected. That stopped being true, so the gap list was itself out of date —
   the D287 failure in miniature. Corrected in D324, together with a service
   count that had drifted: the drivers certify 133 service mappings, not the
   ~128 the README claimed, which had silently counted capability TYPES.)
7. **Probes have not measured a real failure.** The restore-test / reachability
   machinery is built and consent-gated, but "a claim becomes a measurement" has
   not yet happened against a real recovery event.
8. **Capsule DR and ledger compaction are mutually exclusive.** A capsule proves a
   chain from GENESIS, so once `snapshot` compacts a ledger (D137) `backup` refuses
   every capability whose history predates the snapshot — in practice all of them.
   Emitting from the archive does not substitute: those capsules end at the
   pre-snapshot head, which the live anchor no longer pins. So a long-lived
   deployment must choose between compaction and capsule-based backup, and the
   compacted era is preserved only by keeping the archive files themselves. Found
   by the D313 audit; the refusal is honest and up front, but the limitation was
   undocumented and the error message had been advising a workaround that does not
   work.

## What "ready" would mean (not yet true)

A GA claim would need: a real-cloud lifecycle on **Azure** (GCP and AWS are
done); an external security review of the ledger/signature/capsule layer; an
operator running a real workload through converge **sustained over time** —
the pilot stood a platform substrate up and ran an app on it, then paused,
which is a pilot, not an operating record; and a probe that measured a real
recovery. Until then the honest label is **experimental / RFC**, and every
verdict above that is not `proven`+`measured` is a promise the reader may hold
us to — exactly as a `basis: assumed` verdict is.
