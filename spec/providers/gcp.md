# GCP Cloud SQL driver (D43)

The first real provider driver. Design split (D39, D42): the semantic
core — attribute mapping and request building — is a PURE function pinned
by golden tests; the network shell (auth, HTTP, 409 classification,
operation polling) is thin and httptest-covered. Zero new dependencies:
plain REST over `net/http`, RS256 JWT signing from the standard library.

## Auth: a deliberately narrow adapter — NOT ADC

Token sources, in order:
1. `GROUNDHOLD_GCP_ACCESS_TOKEN` — a ready token
2. `GROUNDHOLD_GCP_KEY_FILE` — a `service_account` key JSON ONLY (no
   federation configs, no user credentials; PKCS#8 RSA); self-signed
   RS256 JWT with 5-minute clock-skew backdating, exchanged at the key's
   token endpoint; cached until 60s before expiry
3. GCE metadata server

No `gcloud` shell-out (tool coupling), no claim of ADC compatibility —
workload identity federation is a future, explicit addition.

## Identity and idempotency

Cloud SQL `instances.insert` has no idempotency-key parameter: the
deterministic instance NAME is the mechanism. Name = sanitized slug of
`(capability, environment)` + 8-hex stable hash of
`(project, environment, capability)`, ≤98 chars, letter-first. Never
derived from candidateHash — a re-seal must not create a second
instance. Ownership labels (`groundhold-capability`,
`groundhold-environment`) are set at creation.

**409 = idempotent continuation ONLY when labels match.** On conflict
the driver reads the existing instance: matching labels → continue
(succeeded, adopt the providerId); anything else → failed. Binding
someone else's database is a decision (a future explicit `adopt`
action), not a conflict handler.

## Operations

`insert` returns an operation; the driver polls `operations.get`.
`DONE` is NOT success — the `error` field decides. Poll timeout or a
lost HTTP response after a mutating request → `unknown` (D29), carrying
the real operation name for reconciliation. Receipts pair by intent id;
the provider's operation name rides in the terminal receipt body as
`providerOperation`.

## Mapping table (refuse what cannot be honored)

| attribute | Cloud SQL |
|---|---|
| engine.protocol postgresql/N | `databaseVersion: POSTGRES_N` (mysql/N.M → `MYSQL_N_M`) |
| location.region | `region` (required; immutable) |
| availability.class zonal/regional | `settings.availabilityType`; **multi-regional → refuse** |
| network.publicExposure=false | `ipv4Enabled:false` + REQUIRES `implementation.network.privateNetwork` (prepared Private Services Access link) + empty authorizedNetworks; **no link → refuse** — a database driver must not create VPC peering as a side effect |
| recovery.rpo | PITR enabled; **> 7d → refuse** (transaction log retention bound) |
| recovery.rto, cost.monthly | probe-only / projection — nothing to configure |
| encryption.atRest=true | managed at-rest encryption (no-op); **=false → refuse**; never satisfies a future CMEK constraint |
| implementation.tier / disk_type / flags | `settings.tier` / `dataDiskType` / `databaseFlags[]` (bools → on/off, sorted) |
| anything else | **refuse** — silently dropping an attribute that satisfied a constraint would fake compliance |

## Observe (reverse mapping, D44)

`instances.get` → semantic attributes via the pure `MapInstance`,
golden-tested against a realistically NOISY response. Rules:
- absent fields emit nothing (raw-map lookups, no zero-value defaults);
  unknown enums skip the path with a diagnostic
- `engine.protocol` never invents a minor version (`POSTGRES_16` →
  `postgresql/16`); `databaseInstalledVersion` is runtime detail, ignored
- `network.publicExposure=false` needs config intent AND evidence: ipv4
  disabled + no authorized networks + no Data API exposure + no PRIMARY
  address in `ipAddresses[]`; either surface saying "exposed" → `true`
- `recovery.rpo`: daily backups without PITR → `24h` worst case
  (config-intent); PITR on → diagnostic, the value is a probe's job
- output-only noise (`etag`, `selfLink`, `settingsVersion`,
  `connectionName`, disk sizes) and implementation detail (tier, flags)
  are never emitted
- providerId is canonical `project:region:name`, everywhere

## Update (D46)

Mutability is transition-dependent (`ClassifyChange`): region and
engine/version are immutable (replacement diagnosis); availability class
and backup/PITR are patchable (caveat: patches can restart the
instance); removing public exposure requires a prepared private-network
link, adding it does not; platform properties are unsupported. The PATCH
is built pure (golden-tested): only changed semantic paths, nested
objects (`backupConfiguration`, `ipConfiguration`) merged from the
CURRENT instance so siblings survive, `settings.settingsVersion` pinned
— 409/412 means a concurrent settings change ("re-observe and
re-seal"), never a blind retry. Ownership labels are re-checked before
every patch.

## Delete (D47)

Create sets `deletionProtectionEnabled: true` by default — databases are
stateful; opting out is a reviewed, hash-pinned
`implementation.deletion_protection: false`. Delete GETs first
(ownership labels AND protection): protection on → refuse — lifting it
is an explicit prior step, NEVER auto-disabled. A 404 on the pre-delete
read is success (deleting is idempotent on absence). Successful deletes
tombstone the binding with the deletion operation id.

## Permission preflight (D75)

Before any mutation, the executor checks that the acting identity holds the
permissions the plan needs. Cloud SQL has NO per-resource IAM surface, so the
mechanism is `cloudresourcemanager.projects.testIamPermissions` against the
plan's pinned `reads.provider.project` — a SECOND API (Cloud Resource Manager)
that must be enabled; a project with Cloud SQL Admin on but CRM off fails the
CHECK (`preflight-inconclusive`), not the permissions.

Per-service, per-operation permission table
(`provider.PermissionsFor("gcp", service, op, attrs)`, D76), quiet reads
included because an omitted permission produces a false PASS:

Cloud SQL (`cloudsql`):

| operation | permissions |
|---|---|
| create | `cloudsql.instances.create`, `cloudsql.instances.get` (409 ownership classify + operation poll) |
| update | `cloudsql.instances.get` (ownership re-check), `cloudsql.instances.update` |
| delete | `cloudsql.instances.delete`, `cloudsql.instances.get` (deletion-protection pre-read) |

Cloud Run (`cloudrun`) — `run.operations.get` is a DISTINCT permission for the
v2 LRO poll; the IAM pair appears only when `network.publicExposure=true`
(attribute-aware, so a private service is not false-refused):

| operation | permissions |
|---|---|
| create | `run.services.create`, `run.services.get`, `run.operations.get` (+ `run.services.getIamPolicy`, `run.services.setIamPolicy` iff public) |
| update | *pending — Cloud Run in-place update is not wired; a stateless workload replaces (create-before-destroy), so the update row is intentionally absent until it lands* |
| delete | `run.services.delete`, `run.services.get`, `run.operations.get` |

`iam.serviceAccounts.actAs` (needed to deploy AS a runtime service account) is
deliberately NOT in the table: project-scoped `testIamPermissions` cannot
answer a per-service-account permission, so including it would false-refuse an
identity granted actAs on only the specific SA — the same honesty class as
Shared-VPC below. Providers ids: Cloud SQL keeps `project:region:name`; every
new service is prefix-qualified (`cloudrun:project:region:name`) with its own
charset-validated parser (never the slash-form REST name — that is the char
class D73 keeps out of stored identities).

**A preflight refusal is trustworthy; a preflight pass is evidence, not
proof.** testIamPermissions answers for the project, for the checked
permissions, over the same credentials, at that moment — it cannot see IAM
**deny policies**, **conditional role bindings** (conditions evaluate against
request context that differs at mutation time), policy **propagation lag**,
token **OAuth scope** limits, **org policy**, **VPC Service Controls**, or
**quota/billing**; and the private-network path can reference a **Shared-VPC
host project** whose `servicenetworking` permissions this project-scoped call
never sees. Mid-apply permission failure remains possible; write-ahead
receipts remain the recovery story. The feature never claims to eliminate
partial-mutation risk.

## Known limits (v0, deliberate)

Create + update + delete + observe + replace-as-composition (D48:
instance names gain -gN and a generation-salted hash from g2 up, so old
and new coexist; the slug truncates, never the suffix). Retention modes
(retain / final-backup-then-delete) are named and deferred. Lifting
deletion protection through Groundhold needs implementation-block diffing
(future). Label discovery of unbound/orphan instances is a future
explicit mode and never auto-binds. The intrusive restore-test probe (D65)
creates and deletes scratch instances — genuinely permission-hungry — but is
out of D75 preflight scope: the preflight covers a plan's actions, not probes.
