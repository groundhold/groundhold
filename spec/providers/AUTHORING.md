# Authoring a provider driver

A driver adapts groundhold's executor to one cloud service. This is the pattern
every driver follows — extracted from three built to it (Cloud SQL D43, Cloud
Run D76, GCS D77) and hardened by two adversarial security reviews. A driver is
DONE when it satisfies all five disciplines below and passes the driver
certification (`go/internal/provider/certify.go`).

The reference implementation to read alongside this is `go/internal/gcp/`.

## 1. The shape: pure core + network shell

Split every driver in two, as `go/internal/gcp/cloudsql.go` (pure) vs
`driver.go`/`update.go` (shell):

- **Pure core** — `BuildXCreateRequest(project, environment, capability,
  attrs, impl, generation) (Request, error)` and the reverse mapping. A pure
  function of its inputs: no I/O, no clock, no randomness. Pinned by GOLDEN
  tests (exact request bytes). This is the executable form of the vocabulary's
  mapping table.
- **Network shell** — auth, HTTP, operation polling, IAM. Thin, httptest-
  covered. Never puts semantics here.

Zero new dependencies (stdlib + yaml only). The service dispatches on the
SERVICE token (D76) — a closed switch that FAILS CLOSED on unknown, never a
default.

## 2. Build — the mapping refuses what it cannot honor

Iterate the candidate's attributes in sorted order; map each to the provider
API; **the `default` case REFUSES** ("attribute X has no mapping — refusing
rather than silently dropping it"). Silently dropping an attribute that
satisfied a constraint would fake compliance — the one unforgivable bug. An
attribute the driver cannot honor (a value the API cannot express) refuses in
`Validate`, in preflight, before any mutation (D43). Implementation detail
(image digests, tiers, flags) lives in the free-form `implementation:` block,
never the vocabulary.

## 3. Test — five layers, certification last

1. **Golden** tests on the pure builder — deterministic, no network.
2. **httptest** on the shell — happy path AND every error/loss branch.
3. **Conformance cases** via the deterministic fake — `impl: go` for
   Go-only behavior; the compiler/permission derivation is pinned here.
4. **Static certification** — `provider.CertifyDriver(t, d, ...)` runs the
   network-free battery every driver must pass (dispatch fails closed,
   providerId charset, refusal discipline, permission tables non-empty and
   quiet-reads-included).
5. **Adversarial honesty harness** (D87) — `certifynet.CertifyDriverNet(t,
   probe)` replays create/delete against the golden happy server injecting one
   fault per request (500, dropped-conn, garbled-200, empty-body, foreign-tag)
   and mechanically asserts the four-valued honesty laws: an ambiguous mutation
   outcome is `unknown` with the providerId preserved (where knowable), and a
   foreign-tag ownership read is refused. This is what catches the
   dropped-providerId / honesty-collapse class BY CONSTRUCTION, so it need not
   be re-found by review. A new driver wires one `certifynet.Probe` (a Role
   classifier, a happy-server factory per op, the ownership tag value); see
   `internal/aws/honesty_test.go`. A driver that does not pass 4 AND 5 is not
   done.

Case first: a behavior change lands as a case before the code (repo rule 5).

## 4. Validate — mutability and refusal

- `Validate` is the refuse-before-mutate hook (build the create request, return
  its error).
- `ClassifyChange` is pure provider knowledge: `mutable | immutable |
  unsupported | caveated`. Transition-dependent (removing public exposure needs
  a prepared network; adding it does not). Immutable drift is a replacement
  diagnosis, never a silent in-place edit.

## 5. Secure — the checklist a review WILL demand

Every item below is a real finding from the D76 review; get them right up front.

**Identity & dispatch**
- The service token is matched by exact string, NEVER interpolated into a URL.
- Dispatch fails closed on unknown/empty service — no default.
- The providerId is service-prefixed (`cloudrun:project:region:name`), NEVER
  the slash-form REST name (slashes are the char class D73 keeps out of stored
  identities). Its parser validates every component against the GCP charset
  BEFORE interpolation, and refuses a providerId whose service token or project
  disagrees with the dispatched service / the driver's pinned project
  (cross-service and cross-project confused-deputy).
- Every REST path component derived from candidate input (e.g. `location.region`)
  is charset-validated in the builder before it reaches a URL.

**Ownership**
- Set ownership labels on create; check them (identically sanitized on write and
  read) before 409-continuation, update, delete and any IAM mutation. A name
  collision is NEVER "ours" without matching labels.
- An unreadable resource is UNKNOWN, never a false "not ours" (three-valued).

**Mutation honesty (D29)**
- A lost response after a MUTATING call is `unknown`, never `failed` and never
  `succeeded` — the mutation may have landed.
- A 2xx that carries no operation name is a truncated body → `unknown`.
- Never report `succeeded` for a partial mutation. If exposure/config could not
  be fully applied, the result is `failed` (or `unknown` if the outcome is
  genuinely unknown) — a resource that exists but does not satisfy its contract
  is not convergence. The deterministic name + label-matched 409 make retries
  convergent.

**IAM (if the service has per-resource IAM)**
- Public exposure is TWO gates (reachability AND an IAM grant); observe derives
  it from BOTH, and an unreadable surface emits a diagnostic and NOTHING — never
  a default-safe value.
- setIamPolicy is a read-modify-write at policy **version 3** (to see and
  preserve conditional bindings), APPEND-ONLY, carrying the etag. Refuse a
  CAS-less write (no etag) — it would strip the whole policy. Add the grant
  ONLY to an UNCONDITIONAL binding (never merge into a conditional one — that
  creates a residual, condition-scoped grant). Re-read to CONFIRM it took and
  is unconditional.
- Org-policy blocks (e.g. Domain-Restricted-Sharing) are surfaced by name,
  distinct from a permission 403, so `converge` does not chase a grant org
  policy forbids.

**Secrets & scope**
- Receipts and exports NEVER carry raw provider responses (secrets).
- The auth scope must cover every service the driver calls (`cloud-platform`
  for a multi-service GCP driver + the D75 CRM preflight).

**Permissions (D75)**
- Add the driver's rows to `provider.PermissionsFor(name, service, op, attrs)`.
  Include the QUIET reads (the ownership GET, the operation poll) — an omitted
  permission produces a false PASS, the dangerous direction. Make the set
  attribute-aware where an option changes it (public exposure adds IAM perms).

## Layout of one service module

One file per service under the driver package: the pure builder + its reverse
mapping, its providerId parser, its ClassifyChange table, its permission rows.
Shared auth/config lives at the driver level. Add the service to the dispatch
switch and the `requireService` gate. Document the mapping and the security
boundary in `spec/providers/<cloud>.md`, add a `D` entry to `docs/DESIGN.md`,
and never generate raw Terraform (D39).

## The edge-case test battery (a driver is not done until it pins these)

Every item below was a REAL bug found in a shipped groundhold driver (the D81
hardening pass). The dominant failure was not novelty but INCONSISTENCY — a fix
proven for one service silently missing from another. Treat this as a checklist:
each line is a test your new driver must have, so the fourth driver never
relearns what the first three paid for. Group by the surface it guards.

**HTTP method / path — verify against reality, never assume**
- [ ] Every mutating and reading call's METHOD and PATH is confirmed against the
      live API (discovery doc or a real call), NOT guessed. GCP alone: Cloud Run
      getIamPolicy is GET but testIamPermissions is POST; GCS testIamPermissions
      is GET — the same provider is internally inconsistent.
- [ ] httptest servers ASSERT the method per route (a POST-vs-GET regression must
      fail the test, not only the live API).

**Mutation honesty (D29) — the executor trusts these verdicts**
> Layer 5 (`certifynet`, D87) now MECHANIZES most of this group: wire the driver's
> honesty probe and the harness injects these faults and asserts the verdicts for
> you. The list stays as the spec of WHAT it checks (and the few items — poll-loop
> transient, partial-config — the harness is blind to and you must still pin by hand).
- [ ] A transport error on a mutating call → `unknown` (never failed).
- [ ] A 5xx on a mutating call → `unknown` (a 502/504 can front a mutation that
      landed). Only a 4xx is a definitive `failed`.
- [ ] A 2xx with no/empty operation name → `unknown` (truncated body), never a
      synchronous "succeeded". Pin this for create AND update AND delete.
- [ ] A polled/reconciled operation that is DONE with ANY non-nil error object →
      `failed` — do not require a non-empty errors ARRAY (fail-open).
- [ ] A transient operation READ (429/403/5xx) during reconcile → `unknown`,
      never a verdict guessed from the resource name. Only a 404 (expired op)
      falls through to name-based reconciliation.
- [ ] A partial mutation (resource created but exposure/config not applied) →
      `failed`/`unknown`, never `succeeded`. A 200 mutation contradicted only by
      a failed CONFIRM read is `unknown` (three-valued confirm), not `failed`.

**Parsing — a garbled body must not become a confident answer**
- [ ] Every `json.Unmarshal` on a response whose fields gate a decision (labels,
      op name, IAM policy, testIamPermissions) checks the error. A pre-delete or
      observe read that won't parse → refuse/`unknown`, never proceed on
      half-populated fields.

**Ownership & identity**
- [ ] providerId is service-prefixed and its parser charset-validates EVERY
      component before interpolation; a cross-service or cross-project token is
      refused (confused deputy).
- [ ] The pinned project itself is charset-validated before interpolation.
- [ ] Ownership labels are sanitized IDENTICALLY on write and on every read
      (409-continue, update, delete, probe). A test with a `.`/uppercase value.
- [ ] `sameProject` refuses a cross-project providerId on every mutating path,
      and NO-OPS on the empty pin that read-only paths (observe/discover) run
      with — a guard that refuses observe is the recurring regression.
- [ ] For a GLOBAL namespace (e.g. GCS buckets), labels are not proof
      cross-project — verify a non-forgeable authority (projectNumber) on
      create-continue and delete; a foreign-project resource is refused.

**Concurrency (TOCTOU)**
- [ ] Every delete/update between a pre-read and the mutate carries a CAS
      precondition (settingsVersion / metageneration / etag). A concurrent
      change lands as a 409/412 conflict, never a blind mutate. Refuse rather
      than issue a precondition-less mutate when the token is absent.

**Refusal & fidelity (the builder)**
- [ ] The builder refuses what the API cannot honor, and refuses rather than
      SILENTLY DROPS a semantically meaningful key (the `edition` bug). A test
      that a read-but-unsent field either reaches the request or is refused.
- [ ] Fractional numbers where the API wants integers are refused, never
      truncated below a declared minimum (port, replicas); durations that are a
      MINIMUM round UP.
- [ ] Resource-name length/charset limits are enforced in the builder (verified
      against the API), not discovered as a 400 after apply starts.

**Observe honesty (converge depends on it)**
- [ ] Every attribute the builder can SET is observable, or converge can never
      converge a contract that requires it (the write-only attribute trap).
- [ ] A reachability/exposure attribute is derived from ALL its gates (e.g. Cloud
      Run: ingress AND (allUsers binding OR invokerIamDisabled)); an unreadable
      gate emits a diagnostic and NOTHING, never a default-safe value.
- [ ] Where the effective value depends on an invisible surface (org policy), the
      observation is a diagnostic or a clearly-tagged config-intent, never a
      measured guarantee.

**Certification** — `provider.CertifyDriver(t, d, services)` runs the
network-free invariants (fail-closed dispatch, non-empty/sorted/deduped
permission tables). It is necessary, not sufficient: the battery above is
per-service httptest/golden and is what actually makes a driver safe. A driver
that skips it is not done, however green its happy path.
