# The groundhold driver standard

A driver teaches groundhold to speak one provider's control plane. This document is
the **contract every driver — first-party or community — must satisfy**, and the
bar a new provider, platform, application or stack is held to before it ships.
It is not aspirational prose: most of it is already **enforced** by the
conformance suite (`make check`) and the per-driver certification gate. The parts
that are not yet enforced are named as such, with the roadmap to enforce them.

The governing principle is the same one that governs the runtime: **a driver may
refuse, may say `unknown`, may leave a fact out — but it must never lie.** Every
requirement below serves that.

## 1. The interface (required)

A driver is a `provider.Provider` (`go/internal/provider/provider.go`). It
implements, for each SERVICE token it handles (D76 — dispatch is on the service,
fail-closed, never a silent default):

- `Name() string` — the provider name (`aws`, `gcp`, `k8s`, `hetzner`, …).
- `Observe(service, capability, providerID)` — reverse-map live state to
  capability observations. READ-ONLY. Returns four-valued honesty: a
  transport/permission failure is `unknown` (an error), never a fabricated
  absence.
- `Validate` — refuse-before-mutate: an unmappable attribute or a false derived
  claim refuses here, before any write.
- `Create` / `Update` / `Delete` — the mutating half, each returning a
  `CreateResult` whose `Status` is `succeeded | failed | unknown` (D42/D57 — an
  ambiguous outcome is `unknown` WITH the providerId, never a silent success).
- `ClassifyChange(service, path, current, desired, impl)` — PURE provider
  knowledge (D46): is a change `mutable | immutable | caveated | unsupported`?
  Immutable ⇒ the compiler composes a replacement (D48).

A read-only driver (discovery only, no provisioning) may refuse-closed on the
mutating methods — but it must do so HONESTLY (`"not implemented"`), never a
silent no-op.

## 2. Optional capabilities — and when they become required

groundhold grows by these interfaces. Each is optional to the Go compiler, but the
standard makes some MANDATORY for a driver to be considered complete for its tier.

| Interface | What it grants | Required when |
|---|---|---|
| `Discoverer` (`List(scope)`) | read-only enumeration of existing resources — the input to `crawl` and `posture` | **Always, and now ENFORCED per service.** Every service a driver OBSERVES must also be listable: `provider.CertifyDiscoverability` (run in each driver's certify test) fails unless every certified service token is either a key in the driver's `serviceDiscoverers` registry or a declared non-listable exemption (see §4). A driver with a shadow-blind service — an Observe with no List sweep — does not pass `make check`. |
| `Enumerator` (`Enumerate()`) | lists a provider's crawlable SCOPES (projects/regions/namespaces) so a scopeless pairing fans out | **When the provider has more than one scope.** A single-scope provider (a token that IS the project, e.g. hetzner, upstash) correctly omits it. A multi-scope provider (aws regions, gcp projects, k8s namespaces) MUST implement it, or the crawl silently sees only the declared scope. |
| `Claimer` (`Claim`) | one-time ownership takeover of an adopted resource (D140) | When the provider supports brownfield adoption with a native ownership marker. |
| `CompetingManagers` | reports a foreign continuous reconciler (ArgoCD/Helm) owning a resource (D52) | When adoption could bind something another controller reverts. |
| `Prober` (D59) | measures an OUTCOME (reachability) vs config-intent | When a capability's truth needs a probe, not just config (e.g. network reachability). |

## 3. The event-driven posture (declared, and moving toward required)

Real-time posture (D144) turns the polling crawl's latency floor into seconds.
But **not every provider has an event source, and a driver must not fake one.**
So the standard requires every driver to DECLARE its posture, one of three:

- **`native-watch`** — the provider exposes a first-class change stream the
  operator need not provision (Kubernetes `watch`/informers are the exemplar, and
  BETTER than a cloud feed — it is a real stream, not a provisioned rule). A
  native-watch driver's job is to translate watch events into the `react` ingress'
  `(provider, scope)` coordinates. **WIRED for k8s:** `react.ParseEvent` maps a
  Kubernetes watch frame (`{"type":"ADDED|MODIFIED|DELETED","object":{…}}`) to
  `(k8s, namespace)` — a cluster-scoped object re-lists cluster-wide, a DELETE is
  honest (the freshened namespace listing no longer contains it), and BOOKMARK/ERROR
  frames are ignored loudly. The standing watch connection is operator glue feeding
  `groundhold react`, exactly as the cloud bus feeds an EventBridge event — but with no
  feed to provision.
- **`provisioned-feed`** — the provider has no standing stream, but groundhold can
  PROVISION one as a governed resource fulfilling `capability.observability.changefeed`
  (AWS EventBridge→SQS, GCP Cloud Asset feed→Pub/Sub, Azure Event Grid→queue).
  The feed is infrastructure in groundhold's mandate; the compute that drains it is
  operator glue (the honest infra/deployment boundary).
- **`polling-only`** — the provider offers no usable change signal. This is a
  legitimate, HONEST posture: the driver is crawled on the cron cadence and says
  so. A fabricated feed would be worse than none.

However posture is delivered, the honesty is invariant (D144): the event feed is
a LATENCY optimisation, never a source of truth — the periodic crawl remains the
completeness backstop, and an event carries only routing COORDINATES into a
read-only re-list, never a fact.

## 4. Certification (enforced by `make check`)

A driver is not done until it is certified:

- **`PermissionsFor` (D75)** — a COMPLETE permission table in
  `provider.PermissionsFor`, per service per operation (`create/adopt`, `update`,
  `delete`), including the quiet reads a mutation makes. `certify_test.go` in each
  driver package lists the services that MUST have a non-empty, complete table;
  the compiler fail-closes a plan for any service missing one.
- **Golden `httptest` tests** — every driver ships a fake endpoint (injectable
  `BaseURL`) asserting the SIGNED/authenticated requests it sends and the
  reverse-map it derives. No driver is merged on live-cloud testing alone (D99
  honesty stance): the golden test is the reproducible contract.
- **Conformance-case-first (N5)** — a semantic change starts with a case in
  `conformance/cases/`, then the implementation. Never edit a case to make code
  pass.
- **Discoverability (`CertifyDiscoverability`)** — every service the driver
  observes MUST be discoverable. The gate reads the driver's `DiscoverableServices()`
  (the `serviceDiscoverers` registry keys) and asserts every certified service is
  covered, OR carries a `NonListableServices()` exemption whose reason is from the
  CLOSED set `{provisioned-feed, sub-resource, test-fixture, project-metadata}`.
  Free-text reasons are rejected, so the exemption bucket cannot decay into a
  trust-me allowlist — a listable-but-unwritten sweep has nowhere to hide. This is
  what makes "new things are discoverable" mechanical: adding an Observe adds a
  certified service, which fails the gate until a discoverer (or a categorical
  exemption) exists.
- **Capability parity (`CertifyParity`)** — every certified service DECLARES the
  capability TYPE it fulfils via `ServiceCapabilities()`, so the cross-cloud parity
  matrix is PROVEN, not guessed. The gate asserts the map is a total, phantom-free
  projection of the certified set. This is what makes the parity matrix
  (`spec/parity.yaml`, §8) unable to drift or over-claim. See §8.

## 5. The vocabulary discipline

A driver reverse-maps to CAPABILITY vocabularies (`spec/vocab/`), never invents
its own semantics:

- **Semantics vs noise.** Map what an organization GOVERNS (residency, exposure,
  RPO/RTO, protocol, the security posture); drop instance tiers, internal IDs,
  ARNs, sizing. When unsure, LEAVE IT OUT and note it — an omitted fact is honest;
  a guessed one is a lie.
- **Every observation is `measured`** (read from live state), or carries its true
  derivation (`config-intent`, `platform-invariant`). Never `measured` for something
  inferred, and never `config-intent` for something the resource does not STORE —
  a guarantee the service makes for every instance is `platform-invariant` (D759).
- **Secrets are structurally excluded (D53).** A driver never reads a
  password/token/key into any observation, candidate or ledger event. Where a
  driver only NEEDS a reference (a pairing), it holds the reference, never the
  value.
- **The schema-driven path (learn-from-API-contract).** For providers with a
  machine contract (OpenAPI/CRD — Kubernetes today), the mapping is DATA (a
  mapping document + named lenses) with a drift fingerprint, not hand-code. New
  Kubernetes-shaped resources SHOULD be added as mappings, not twins.

## 6. Onboarding a new driver — the checklist

A first-party or community driver is ready when ALL hold:

1. Implements `provider.Provider` for its service(s), dispatch fail-closed (D76).
2. Implements `Discoverer` for EVERY service it observes (enforced by
   `CertifyDiscoverability`) — a service that genuinely cannot be listed standalone
   is declared in `NonListableServices()` with a closed-set reason, never left silent.
3. Implements `Enumerator` **iff** the provider has multiple scopes.
4. Declares its event-driven posture (native-watch / provisioned-feed /
   polling-only) — and implements the feed driver if provisioned-feed.
5. Has a complete `PermissionsFor` table and is in its package's certify list.
6. Ships golden `httptest` tests for create/observe/delete + the reverse-map.
7. Reverse-maps to a `spec/vocab/` capability, honoring semantics-vs-noise and
   secrets-excluded; adds the vocab if the capability is new (dual-registered in
   the Go and Python contract lists).
8. Four-valued throughout: `unknown` on ambiguity, refuse on a false claim, never
   a silent success or a fabricated absence.

## 7. The parity matrix (current state — the roadmap is the gaps)

| Provider | Discoverer (per-service, enforced) | Enumerator | Event posture | Provisioning |
|---|---|---|---|---|
| aws | yes — all observed services (gate) | yes (regions) | provisioned-feed (EventBridge) | yes |
| gcp | yes — all observed services (gate) | yes (projects) | provisioned-feed (Cloud Asset) | yes |
| azure | yes — all observed services (gate) | yes (subscriptions) | provisioned-feed (Event Grid) | yes |
| k8s | yes — all mapped kinds (gate) | yes (namespaces) | native-watch (wired into `react`) | yes (mappings) |
| hetzner | yes (networks) | n/a (token = project) | polling-only | read-only |
| upstash | yes (redis) | n/a (account-global) | polling-only | read-only |
| cloudflare | yes (DNS records) | n/a (token = account) | polling-only | read-only |
| fake | yes | yes | — | yes |

**Named parity gaps (the work to reach universality):**
- ~~**Enumerator on the real multi-scope drivers**~~ — CLOSED. aws (regions via
  `DescribeRegions`), gcp (projects via `cloudresourcemanager.projects.list`),
  azure (subscriptions via ARM), k8s (namespaces via `/api/v1/namespaces`) all
  enumerate their crawlable scopes, each honest on failure (an error or an
  explicit one-scope partial with a diagnostic, never a fabricated empty list).
  Pinned by `TestDriverParity` (`go/cmd/groundhold/parity_test.go`).
- ~~**Per-service discoverability**~~ — CLOSED for aws/gcp/azure. Every observed
  service now has a List sweep (43 backfilled: aws acm/apigateway/backupvault/
  cloudfront/cloudwatchdash/custompolicy/efs/eventbridgescheduler/kinesis/kms/msk/
  opensearch/redshiftserverless/route53/route53health/vpngateway/waf; gcp
  backupvault/bigquery/certmanager/cloudarmor/clouddns/cloudfunctions/cloudkms/
  cloudrunjobs/cloudscheduler/dashboard/filestore/logmetric/managedkafka/vpngateway;
  azure acr/aisearch/apim/azkafka/azurefiles/azurecdn/dnszone/eventhubs/frontdoorwaf/
  metricalert/portaldash/scheduledquery/webtest). Each reuses its service's Observe
  reverse-map (two-step List→observe, never a hollow all-unknown record) and is
  ENFORCED by `CertifyDiscoverability` — new services fail the gate until listable.
- ~~**k8s per-service discoverability gate**~~ — CLOSED. k8s is now under
  `CertifyDiscoverability`, keyed off the SCHEMA-MAPPING registry (its "services"
  are the mapped kinds, `Driver.MappedServiceTokens()`) rather than a `PermissionsFor`
  list. netpol + certmanager-cert were backfilled through a generic `sweepMapped`
  (collection LIST → the same `observeMapped` reverse-map), and `TestK8sDiscoverabilityComplete`
  fails if a new mapping ships without a discoverer — so a newly observed kind is
  discoverable immediately.
- ~~**k8s native-watch ingress**~~ — CLOSED. `react.ParseEvent` translates a
  Kubernetes watch frame into `(k8s, namespace)` coordinates, so a paired cluster's
  watch stream drives the same read-only re-list+splice+reclassify the cloud buses
  do — the app-layer real-time posture, where the stack actually lives, with no feed
  to provision.

The standard is now mechanically enforced across every driver
(`CertifyDriver`, `CertifyDiscoverability`, `TestDriverParity`) — cloud and k8s alike.

## 8. Cross-cloud capability parity (`spec/parity.yaml`)

§7 is parity of driver CAPABILITIES (does each driver discover/enumerate/watch/
provision). This section is a different axis: **which capability TYPE does each
cloud fulfil, and where a cloud genuinely CANNOT.** That distinction is the input
to the bake-off (D92) — an agent choosing a vendor must know when a cloud is a
structural dead end versus when groundhold merely lacks a driver.

**The artifact.** `spec/parity.yaml` is a GENERATED matrix: for every capability
TYPE (a row per `spec/vocab/capability.*.yaml`), each cloud cell is exactly one of:

- `fulfilled: [tokens]` — one or more SERVICE tokens fulfil it (D76: `rds` and
  `aurora` both fulfil `capability.database.relational`).
- `gap: {class, reason}` — the cloud STRUCTURALLY cannot fulfil it. A fact about
  the cloud. `class` is from the closed set `{no-native-service,
  not-capability-shaped, policy-refused}`; `reason` is the human explanation.
- `unbuilt: true` — DERIVED: no token and no declared gap. A fact about groundhold —
  a driver COULD be written; the cloud is not the blocker.

**Why it cannot lie.** The `fulfilled` cells are generated from the three drivers'
`ServiceCapabilities()` maps, each proven token-by-token against the driver's real
`ResourceType` emissions and gated by `CertifyParity` (total, phantom-free). The
`unbuilt` cells are derived — **nobody ever writes "unbuilt"**, which removes a
whole class of lie. Only the structural GAPS are authored (in
`go/internal/parity/gaps.go`), and `TestParityMatrix` proves every one is REAL: a
gap that some token actually fulfils fails the gate. The whole file is regenerated
and byte-compared, so a driver that adds/removes a service — or a gapped cell that
gains a driver — fails `make check` until `spec/parity.yaml` is regenerated
(`go test ./internal/parity -run TestParityMatrix -update`).

**The honesty bar for a gap.** A structural gap ("the cloud can't") is a stronger
claim than an honest "unbuilt", and a FALSE gap is a worse lie than an omission.
So the authored table holds only cases we are certain of — today: `email.sending`
(GCP has no first-party transactional email) and `email.inbound` (neither GCP nor
Azure has a managed inbound-mail-to-storage pipeline; SES receiving is unique).
Everything else absent is `unbuilt` — an honest roadmap entry, not a verdict on the
cloud.

This is the third certification battery, closing the symmetry with §4: which
services exist (`CertifyDriver`), which are discoverable (`CertifyDiscoverability`),
which capability each fulfils (`CertifyParity`).
