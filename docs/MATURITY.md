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
account, 36 findings) and Azure (author-run across the driver set on our own
account; the first run, 2026-07-24, immediately found that its whole observe
family had never worked outside tests). Most of the 145 services have since been
field-tested on our own accounts (COVERAGE.md cites each), and a real Kubernetes
cluster exercised all ten mapped services — but there has been one EXTERNAL pilot
(AWS only), no external security audit, and ONE production incident (2026-07-26,
recorded below). This is `v0.x`, experimental — an RFC you can run, not a product
with an SLA.**

A per-service breakdown — every driver service labelled `measured` or `config-intent`,
machine-derived from the drivers and gated against overclaim — is in
[`docs/COVERAGE.md`](COVERAGE.md). Today: **144 of 145 services field-tested** — but
read that precisely. It means each was run against a real cloud, with the run cited;
mostly against **our own** accounts (dogfooding), **not** by an external operator. The
external track record is narrower and does not move with that number: one AWS pilot, no
external security audit, and no sustained customer production beyond it.

## Core (the deterministic spine)

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Four-valued verifier, typed scalars, no-coercion | **proven** | measured | Dual impl (Go + Python) through one 565-case conformance suite — 270 of the 565 run through both, the rest Go-only; Strong-Kleene + injective canonicalization adversarially audited (D178–D179). The strongest claim in the system. |
| Canonicalization + hashing (cross-language identity) | **proven** | config-intent | Byte-identical hashes pinned across both impls + `make differential`; audited for round-trip injectivity (D179). "measured" would mean external cryptographic review — not done. |
| Ledger / state model (hash chain, replay, snapshot, anchor) | **proven** | config-intent | Adversarially audited D182–D185 (forest-anchor, snapshot projections, replay); snapshot-equivalence fuzz. It is a local deterministic engine — "real cloud" does not apply; "measured" would mean an external tamper-evidence review. |
| Capsules, ed25519 signatures, DR restore/merge | **proven** | config-intent | Recompute-from-bytes verify, fail-closed signatures, fork-refusal + write-then-replay restore; audited D187. No external crypto review. |
| Compiler → Sealed Plan IR (deterministic seal) | **proven** | config-intent | Conformance-pinned plans; per-capability dispatch + evidence gates audited (D186, D190, D195). |

## Execution (where reality enters)

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Executor / apply (leases, fencing, write-ahead receipts, resume, deposed) | **proven** | measured (GCP + AWS) | Full lifecycle on GCP (author-run, 2026-07: Cloud SQL, Cloud Run, VPC/subnet, canary create+retire) AND on AWS at an external pilot (2026-07: multi-action plans over a 26-capability contract, a ~40-min long-running cluster upgrade, `resume` concluding a pending receipt after a kill, throttle/409 retry paths, ~9 refusals that each landed BEFORE any mutation — `events: []`). The write-ahead/lease machinery is the part the field exercised hardest. Mutation logic audited D180. Azure execution is measured too — the first three capabilities (VNet D294; managed-identity and custom-role 2026-08-06, author-run), and since then the full Azure driver set own-account (COVERAGE.md); external-operator coverage is still AWS-only. |
| GCP drivers (46 services) | **partial** | measured (own-account, 45/46) / exempt (scc) | Real create/observe/converge/retire lifecycles for Cloud SQL, Cloud Run, VPC/subnet (author-run, 2026-07) and a Pub/Sub topic (2026-08-06, own-account: create → converged re-plan → retire with the message-storage residency policy pinned to the requested region, verified live and gone after retire). The full GCP driver set has since been field-tested own-account (COVERAGE.md cites each), 45 of 46 — `scc` exempt (no org-level SCC enrollment). What GCP lacks, like Azure, is an external operator running it on their own estate. |
| AWS drivers (54 services incl. the Acme reference EKS substrate) | **partial** | measured (own-account, 54/54; one external pilot) | An external pilot operator stood the substrate up on their own account (2026-07): EKS cluster + managed node group + addons + pod-identity, sequential version upgrades 1.33→1.36 driven end to end by `converge`, Aurora Serverless v2 with enforced TLS + CMK + managed password, ALB/ACM, Bedrock EU inference profile, ECR/S3/KMS/CloudTrail/CloudWatch-logs/SQS/service-accounts, ElastiCache, budgets; plus `discover` over a real account (212 resources), per-resource `adopt`, and `resume`/reconcile. That run produced 36 findings, of which the create/upgrade/adopt/resume classes are fixed and pinned (D248–D283) — the engagement RESUMED on 2026-07-29 and is running daily against live production again — seven findings in two days on a shipped binary, including one against a fix made FOR them (D529: a summary that said "nothing was changed" about an action whose outcome was unknown, while the resource had been created). Several classes remain fixed-but-not-retested in the field (notably the D281 IAM-propagation retry and the D283 fold branch), and one risk stays deliberately unproven (grant ordering vs cluster create). The services the pilot did NOT touch have since been field-tested on our own AWS account (COVERAGE.md cites each run) — real cloud, but not an external operator's estate. Observe-honesty audited D181. |
| Azure drivers (45 services) | **partial** | measured (own-account, 45/45) | First real-Azure run 2026-07-24 (D294): a VNet through the FULL loop — create, observe, a converged no-op re-plan, retirement with a tombstone, teardown clean. That run also proved Azure `observe` had NEVER worked outside tests (the driver built its URLs from a pin `observe` deliberately does not set), so the other services were golden-only AND, until then, unobservable in production. 2026-08-06 (own-account run): `discover` over a real subscription (18 resources) — which found D872, a 1 MB read cap that made `roleDefinitions.list` (1.14 MB of built-in roles) unparseable, so custom roles were unreadable on EVERY real subscription — and a SECOND full execution lifecycle, a user-assigned managed identity through create → converged re-plan → retire, verified against ARM at each step (real clientId, ownership tags on create; a 404 after delete), including the identity-replacing consent friction refusing `--yes` alone. Also a custom role definition (Microsoft.Authorization/roleDefinitions) through the same full loop — the WRITE path complementing D872's read fix, verified live (a real CustomRole with the declared action, gone after retire). Those three were the first; since then the full Azure driver set has been field-tested on our own account (COVERAGE.md cites each create→converge→retire run, including AKS and Flexible PostgreSQL). What Azure still lacks is what only AWS has: an EXTERNAL operator running it on their own estate. |
| Corrupt-ledger recovery (`attest` / `repair` / quarantine) | **proven** | measured | Walked end to end against a tampered REAL ledger (D575): `attest` exits 5 naming the broken line, `repair` diagnoses `chain-broken` with the valid-prefix length and a fingerprint, quarantine REFUSES without that fingerprint and, given it, truncates to the valid prefix while preserving the WHOLE original file for forensics — then `attest` exits 0. It says what it cost: quarantined events may already have mutated the cloud, and plans sealed before the repair are void. Also walked on a COMPACTED ledger (D576): a tampered tail line that continues the snapshot heads is caught (exit 5), and the tail's LAST event is not — by construction, since nothing links to it — which an anchor taken beforehand does catch (`anchor --check`, exit 5 on the file `attest` calls clean). `attest` now states that limit in its own report. |
| k8s driver (10 mapped services) | **partial** | measured (10 of 10, at the extent each verb has) / config-intent (the rest) | Schema-driven: every service routes through ONE mapped write path (no hand-coded twins), so a single gate covers all ten — and D462 used it to find that `create` never pre-read ownership, applying our labels onto a foreign object without conflict and making every downstream check agree it was ours. The "10 of 10" was measured for `observe` and was NOT true of every verb: until D550 (2026-07-31) two observe-only services could not be observed at all — the read was gated on a WRITE-safety predicate, so `discover` enumerated one with measured values while `observe` refused it as unknown — and the competing-reconciler check that guards adoption failed for SIX of the ten, so those could not be adopted. Found on the live cluster, not by the gates; D557 now requires everything discovery enumerates to be observable. First real cluster 2026-07-30 (D509, k3s v1.35.5): a Namespace through the FULL loop — create, converged no-op re-plan, hand-injected drift on the enforced Pod Security Standard, repair, retirement with a tombstone. That run also proved the driver could not have created ANYTHING against a real API server: the schema walker could not resolve an annotated `$ref` (`allOf`-wrapped, which is how a real server spells any described property), so six of the seven wired services refused with `mapping-schema-drift` before touching the cluster. The single shared write path meant a single shared blindness — the argument for low risk was the mechanism of the failure. The fixtures could not have caught it: they were hand-simplified to the bare `$ref` the walker expected (D273's class), and are now verbatim recordings, four of five reproducing their committed pin exactly. D510 then ran the other five wired governance services through the same loop on that cluster (ResourceQuota, Role, RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy from one six-capability contract): five converged and stayed converged across further passes; the ClusterRole never converged and never would have, because a declared permission spelling the writer accepted was one the reader could not produce, so converge planned the identical update forever on an untouched cluster. **All ten are now `measured`, each to the extent its verbs go** (D549): seven governance services through the FULL write loop (create, converged re-plan, hand-injected drift, repair, retirement), cert-manager through create and converge, and the two GitOps mappings — ArgoCD and Flux — through observation of real objects, which is the whole of what a WITNESS does, since neither ever writes. Both normalise a live status the same way (`OutOfSync`/`Ready=False` to `drifted`), which is the cross-vendor claim the type makes. D511 installed the cert-manager/Argo/Flux CRDs on that cluster and closed the last of the schema debt: the two GitOps mappings that shipped with the drift guard OFF (`mappedSurface: ""`, pending a schema to vendor) are pinned from verbatim recordings, all ten mapped surfaces are verified against a live API server, and a new mapping can no longer arrive unpinned. That run also found that the cert-manager mapping had never built a valid object — it omitted cert-manager's required `spec.secretName`, so every Certificate it ever produced was rejected 422 by any real server. |
| Read-only drivers (cloudflare, hetzner, upstash) | **built** | config-intent | Discovery/pairing only; every write verb is a categorical refusal, driven by the D463 gate so the day one is wired it owes an ownership register. |
| Cross-cloud parity (AWS/GCP/Azure) | **built** | config-intent | Parity program complete (D166–D172); honest per-cloud gaps recorded. A machine-verifiable parity matrix is deferred. |
| Observe / probe (reality → typed observations) | **partial** | measured (GCP + AWS + Azure) / config-intent (probes) | Pipeline audited D189–D191 (future-dated fail-open, evidence-bar enforcement, per-source retention) and D286 (the wiring namespace — a fail-open the author introduced and closed). `observe` ran for real on GCP and AWS; the AWS pilot also proved the gap this pipeline still has: several declared attributes the drivers cannot read back (a reconcile then reports them unverifiable rather than checked). D762 replaced that "several" with a MEASUREMENT: 42 attribute paths across 26 services are accepted by a builder and emitted nowhere in their package. Most are honest REFUSALS (the branch exists to say no — `interconnect.private`, `immutable.tags`, Azure VNet flow logs), and a handful are set-but-unreadable (Azure Blob `versioning.enabled` is sent as `isVersioningEnabled` and never read back), which BLOCKS a hard constraint rather than satisfying one. No lie was found in the set; the count is here because "several" is not a number anyone can act on. Probes (restore tests, reachability) remain golden/fake-exercised — no real recovery event has been measured. |
| Discover / adopt / onboarding | **partial** | measured (GCP + AWS + Azure) | Adoption-must-not-lie audited D192. Run for real on GCP and on AWS (`discover` over a live account, per-resource `adopt`, create-time adoption of server-assigned ids). The field also proved the model's edges: 1:N adoption (one capability, many resources) is unsupported, and a custom-named brownfield resource needed explicit naming to bind rather than duplicate (D261). Azure `discover`/`adopt` is now measured own-account too (2026-08-06, a live subscription — D872 was found on it). Run for real on k8s too (D512): `discover` over a live cluster returned 166 resources across six capability types, with the model's narrowness stated in diagnostics on real data rather than smoothed over (a custom role's privilege left UNVERIFIABLE, a multi-subject RoleBinding left unobserved); a hand-made `kubectl` Role was adopted and the SECOND converge reported the world already matching — the takeover proof. |

## Surfaces

| Subsystem | verdict | basis | evidence / honest gap |
|---|---|---|---|
| Converge porcelain, presentation/banners | **proven** | config-intent | Audited D193–D194 (destructive-plan fail-closed, VIOLATED-not-REFUSED). Human-facing, deterministic. |
| MCP server (gated tools, two-step apply) | **built** | config-intent | Protocol + gating pinned; hardened (token consume, symlink confinement, and D319: the confirmation token binds the whole decision — plan AND target — after an audit found it could be spent redirecting the same plan at another ledger/provider). Not exercised by a real external MCP client at scale. |
| Console / BFF (read-only projection) | **partial** | measured (real AWS exports) / config-intent | Read-model + honesty guards audited; the projection was validated against REAL output (a live AWS discover, verify reports, ledger exports) rather than simulated fixtures — that live-output working set lives outside the public tree (it carries real-account data). The projection tracks the runtime through D286 (operand provenance, evidence-vs-wiring split). Not exercised by a real operator at scale. |
| Voice / authoring skills, docs site | **built** | assumed | Left of the execution boundary; a misheard word can only produce a wrong draft, never a wrong apply. Utility unproven with real authors. |

## The gaps we are NOT hiding

1. **Almost everything is field-tested on OUR OWN accounts, not a customer's.**
   The per-service loop now closes on real clouds across the driver set — Azure
   included (the loop first closed there at D294), AKS and Flexible PostgreSQL
   included, each run cited in COVERAGE.md and gated against an uncited claim
   (D876). That is real cloud, and it is NOT the same as an external operator
   running it in anger: only AWS has that (gap 2). Own-account dogfooding proves
   the driver builds and reconciles a real resource; it does not prove someone
   else's estate, sustained production, or a surface we do not happen to exercise.
2. **One pilot is not a track record.** There has been exactly ONE external
   operator, on one account. The engagement paused on 2026-07-24 and RESUMED on
   2026-07-29, running daily against live production; it has filed seven further
   findings, so the most recent fixes (D281 IAM-propagation retry,
   D283 fold branch, D286 wiring split) are pinned by tests but have NOT been
   re-run in the field. No external security audit exists.
3. **There has been one production incident, and groundhold contributed to it.**
   On 2026-07-26 the pilot lost roughly five minutes of production after
   deploying a bad image. groundhold did not cause the bad image. What it did
   was remove the signal that would have surfaced it: every `converge` run had
   been ending `DIED` on a permanently-refusing action, so the status looked
   IDENTICAL whether the deployment had worked or killed the API, and a sibling
   action had already applied. They found the outage by querying AWS by hand.
   Reported by the pilot; the causal chain and the fix are D378 (a refusal that
   was decidable from the candidate fired mid-DAG instead of at preflight). The
   deeper half — that a run's status collapses per-action outcomes into one bit —
   was the more important of the two, and is now fixed in two slices. D379 made
   the summary LEAD with what changed ("1 of 2 actions applied before the run
   stopped — the world HAS changed"), lifting a per-action `outcomes` map `apply`
   had been emitting all along and nothing had read. D387 fixed the rest: converge
   returned immediately on an apply failure, skipping the post-apply observe and
   the REACHABILITY PROBE — the mechanism built precisely to catch "it applied,
   but the edge does not answer". Evidence collection had been conditioned on the
   run SUCCEEDING; it is now conditioned on whether anything MUTATED, with
   `unknown` counting as mutated (D29: an action that may have landed is not
   "nothing happened"), and with `preserveVerdict` so gathering evidence cannot
   make a broken run look better.
   **This entry went on claiming the deeper half was unfixed for as long as it
   took to read the code instead of the document.** Corrected in D465 — one slice
   after an honesty pass (D464) that revised three other entries and did not catch
   it. The pessimistic direction is the easier one to leave lying around, because
   nobody challenges a document for being too hard on itself.
   The general lesson has a name in this document already: a gate that is
   always red stops being a gate. Here it stopped being one at the exact moment
   it was needed.
4. **The field found things the gates did not.** The pilot filed 36 findings,
   including bugs every hermetic suite passed — a poll against a path that
   does not exist in the cloud API (the unit fake mirrored the driver's wrong
   assumption, so it was blind by construction, D273), and a transport
   regression that broke every request while CI stayed green (D269/D271).
   Two mechanisms now exist because of that (a live smoke and an
   endpoint-reality gate, D272/D274), but the lesson stands: internal gates
   under-sample reality.
   A sweep of the record against those findings (D390) adds two things this
   doc should say plainly. First, the record accounts for **24** of the 36 by
   identifier; the rest cannot be traced from this repo, and the pilot paused
   on 2026-07-24, so the source is no longer available to reconcile them
   against. Whether they were closed silently, folded into others, or never
   addressed is not something we can claim either way. Second, most field
   classes ARE now gated cross-driver (D266/D267 lifecycle, D317 observe
   completeness, D221 reconcile coverage, D272/D274 wire reality), but the
   idempotency class was fixed twice and gated zero times — closed by D390.
   **This entry also owes the other direction, and did not say it.** The
   systematic internal sweep of the driver layer (D391-D472) found
   **25 live defects across four drivers** — a create that minted a second billed
   resource on a re-run, deletes that destroyed resources on nothing but a
   providerId, an update that replaced a stranger's whole budget, an SSA that
   stamped our labels onto a foreign object so every later check agreed it was
   ours. **No field run reported any of them**, and most could not have been
   reported: an operator does not notice a delete that would have hit someone
   else's resource until it does. So the relationship runs both ways — the field
   finds what hermetic fakes mirror wrongly, the gates find what nobody is
   positioned to observe — and neither substitutes for the other. The count is
   published once, in `internal/provider/sweepdefects_gate_test.go`, checked
   against the drivers' certified services and pinned against the figure quoted
   here so the two can only move together. It covers four classes: ownership on
   the mutating verbs, the estate boundary (project/subscription/account, which
   labels and tags cannot answer because they are identical across every estate we
   manage), a compliance hold surfaced as an unrelated error, and attributes
   realised but never read back.
   **A third kind of sweep, 2026-07-31 (D550-D584), found a class neither of the
   others is positioned to see.** Not a field report and not a driver-layer audit: a
   systematic walk of the OPERATOR'S OWN PATH against a live Kubernetes cluster —
   discover, posture, adopt, converge, retire, refresh, backup, restore, attest,
   repair, probe, forecast, export — doing what the documentation says and reading
   what came back. Thirty-five entries; four record a verified-clean result and the
   rest changed something that was wrong. The recurring shape is not a wrong
   computation but a **published claim nobody had executed**: remediation recipes
   that could not run as written, advice whose result was invisible so an operator
   would read it as having failed, a documented adopt-then-retire sequence that
   dead-ended because adoption binds without owning, and a reported pilot bug whose
   fix was unreachable for the exact state that motivated it. Two of the findings
   were in the publication path itself, which `make check` does not exercise.
   The lesson this doc should carry: hermetic suites test what the code does,
   cross-driver sweeps test what the drivers do, and **neither reads the sentences
   the system hands an operator**. Advice is a published claim like any other, and
   until this walk it was the only class of claim in the system nothing verified.
5. **A resource deleted out of band was invisible to every driver but one —
   CLOSED, and the closing is the more useful half of the story.** The provider
   contract reserves `resource.absent` for a bound resource the API authoritatively
   404s, and the compiler turns a fresh `true` into a re-create. Exactly ONE service
   ever emitted it (AWS Lambda). Everywhere else the read returned a diagnostic
   string and no observation, so the binding stayed a no-op forever and `converge`
   reported CONVERGED against a world that no longer contained the resource —
   measured on a real cluster after a FORCED fresh observation (D513), which is what
   makes it a finding rather than a stale-evidence artefact.

   It is now closed: **102 of 102 certification probes assert the property and the
   ratchet is at 0** (D523), driven red at zero to prove the gate still bites. The
   route there is worth keeping because most of it was not driver work. D517 made
   the readiness signal a CLOSURE rather than a boolean, so a probe could not claim
   coverage the harness never ran. D521–D523 then spent three entries teaching the
   test estate to speak each protocol, each service's own not-found code, each error
   body's shape and whether a read is a collection at all — because **the instrument
   was wrong more often than the drivers were**, and a correct driver failing looks
   exactly like a defect.

   What it did NOT prove: that every driver handles every absence correctly in
   production. It proves every service WITH A PROBE was asked, in an estate that
   speaks its dialect, and answered. Only the k8s answer was measured against a live
   cluster.

   **That is fewer services than the drivers serve, and the number belongs here**
   (D625). The ratchet behind this row counts PROBES — 102, all of them asserting the
   property — while D513 published the debt in SERVICES: "of roughly 145 certified
   services across AWS, GCP and Azure, one emits the marker". Walking each driver's
   own `ServiceCapabilities()` against the probe names: aws 17 of 54 unprobed, gcp 13
   of 46, azure 14 of 45 — **44 of 145**, of which 40 have no test naming the marker
   at all. (k8s is excluded: its ten mapped services prove the property through shared
   unit tests on one code path, which a probe-name scan would miscount as ten gaps.)
   The emission itself is broadly implemented — around 136 driver files reference the
   marker — so this is a PROOF gap, not a behaviour gap. It is now its own ratchet with
   the measured baseline, so it can only shrink. D514 also left the compiler saying `existence-not-witnessed` where a
   driver still cannot answer, which is now nobody — but the advisory stays, because
   a new driver can reintroduce the silence.

6. **Some declared attributes cannot be read back.** Several capability
   attributes the drivers can SET they cannot OBSERVE, so a reconcile of a
   bound resource reports them unverifiable rather than checked. The system is
   honest about it (D249/D136), but honest-about-a-gap is still a gap.
7. **One reference verifier, one runtime.** The *verifier* is dual (Go + Python)
   and that is what conformance pins. The *runtime* (executor, ledger, drivers)
   is Go-only by design (D24) — there is no second implementation to differ against
   below the verifier.
8. **The README summarises; DESIGN.md is the record.** The roadmap section is
   deliberately frozen at the ORIGINAL vertical slice (~D64/D75) for the shape of
   the thesis, with a "Since the vertical slice" summary carrying breadth, the
   self-wiring contracts, field hardening and both adversarial sweeps. That
   summary will always trail DESIGN.md, which is the only complete record. (This
   entry used to say the README "stops at ~D64/D75" with none of the later work
   reflected. That stopped being true, so the gap list was itself out of date —
   the D287 failure in miniature. Corrected in D324, together with a service
   count that had drifted: at D324 the drivers certified 133 service mappings
   (145 today), not the ~128 the README had claimed, which had silently counted
   capability TYPES.)
9. **Probes have measured reachability for real, but never a real RECOVERY.** The restore-test / reachability
   machinery is built (D59) and consent-gated, and its intrusive paths are now
   gated as a class — all four probers refuse a foreign estate before the spend
   (D461). D512 moved this HALFWAY: the k8s reachability probe ran against a real
   cluster with real network I/O and behaved on both branches — an open target
   records a measurement whose evidence claims only that a path EXISTS, a closed
   one records NO measurement and says filtered/dropped/down are indistinguishable,
   and the recorded observation carries `source: "probe"` so it cannot be mistaken
   for an API read. What did NOT happen: enforcement could not be proven from
   outside the cluster (the probe's design already refuses to conclude it, and the
   target is an operator declaration groundhold does not verify belongs to the
   policy), and no real recovery event has been measured. "A claim becomes a
   measurement" is now true of reachability and still false of restore.
10. **Capsule DR and ledger compaction are mutually exclusive.** A capsule proves a
   chain from GENESIS, so once `snapshot` compacts a ledger (D137) `backup` refuses
   every capability whose history predates the snapshot — in practice all of them.
   Emitting from the archive does not substitute: those capsules end at the
   pre-snapshot head, which the live anchor no longer pins. So a long-lived
   deployment must choose between compaction and capsule-based backup, and the
   compacted era is preserved only by keeping the archive files themselves. Found
   by the D313 audit; the refusal is honest and up front, but the limitation was
   undocumented and the error message had been advising a workaround that does not
   work.

11. **Two "settings-flip" capabilities can disable a flag they did not set.** For
   `gcp/scc` and `gcp/gke-addon`, "create" means turning a project- or
   cluster-level flag ON and retirement means turning it off. A create that meets
   an already-on flag adopts it silently — correct converge behaviour — and the
   API offers no ownership surface for a flag, so a later retirement cannot tell
   "we enabled this" from "it was already on when we arrived". A retirement can
   therefore disable an SCC module or a GKE addon that someone else enabled.
   Named and gated by D456 (the exemption re-derives the shape, so a change to it
   forces re-examination); the fix — recording found-vs-set at create time so
   retirement restores rather than disables — is a change to resource identity and
   is not yet built. **The second, sharper problem beside it is now CLOSED** (D481 →
   D698): turning threat detection off as a side effect of retirement collided with
   D47's rule that a protection is never auto-lifted, and it no longer happens.
   `capability.security.threatdetection` and `capability.security.waf` carry
   `protection: true`, and retiring one REFUSES unless the contract scopes
   `autonomy.allow_protection_lift` to it; dropping the capability from the contract
   instead leaves the control ON and `posture` reports it as unmanaged. That closes
   the "weakens a posture with no consent step" half for both clouds. **What remains
   open is the OWNERSHIP half**, which is what this gap is really about: a create
   still cannot tell "we enabled this" from "it was already on when we arrived", so a
   CONSENTED retirement can still disable a module someone else enabled. The addons
   (`gke-addon`, `aks-addon`) are deliberately unmarked — for those, retire-means-off
   is defensible — so the gap is theirs in full. **Azure has the same ownership gap in
   `defender` and `aks-addon`** (D458), with the same missing fix.

12. **`Claim` is the one write no register questions, and it is the one that hides
   its own mistakes.** Claim stamps groundhold's ownership marker on a resource we
   did NOT create (D52/D140/D145), so the foreign-refusal question every other verb
   answers — "is this ours?" — is answered *no* by construction, and a register
   built on it would refuse the verb's whole purpose. The question that DOES apply
   is `claimLambda`'s, whose comment states it exactly: *never tag a foreign
   function the acting account happens to hold under the same name*. Most other
   claim paths build the identity from the providerId and stamp without reading.
   Whether that is a gap or the intended reliance on adoption's own proof is a
   design question this document does not settle. What it does say plainly:
   **after a claim lands, every ownership check in the runtime says "ours"**, so a
   mistaken claim is invisible to all thirteen registers. It sits at 1 on the
   D461 verb-coverage ratchet, named rather than forgotten.

## What "ready" would mean (not yet true)

A GA claim would need: an **external operator** running a cloud other than AWS
on their own estate (all three clouds are done on our own accounts; only AWS has
had an outside operator); an external security review of the ledger/signature/capsule
layer; an operator running a real workload through converge **sustained over time** —
the pilot stood a platform substrate up and ran an app on it, then paused,
which is a pilot, not an operating record; and a probe that measured a real
recovery. Until then the honest label is **experimental / RFC**, and every
verdict above that is not `proven`+`measured` is a promise the reader may hold
us to — exactly as a `basis: assumed` verdict is.
