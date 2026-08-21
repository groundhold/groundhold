// Package provider defines the executor's provider interface (D42, D43)
// and ships a deterministic fake. Resource identities derive from
// deterministic names — names outlive request-dedup windows. Real
// drivers (internal/gcp) are adapters implementing the same interface.
package provider

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CreateResult statuses mirror receipt semantics (D29): `unknown` is a
// first-class outcome — a lost response after a mutating request is NOT
// a failure, and the real provider operation id (when known) rides along
// for reconciliation.
type CreateResult struct {
	ProviderID  string
	OperationID string // provider's real operation name, when known
	Status      string // succeeded | failed | unknown
	Reason      string
	// Retryable (D237) is set on an `unknown` outcome that was a pure throttle
	// (ClassTransient): the mutation provably did not land, so a plain retry is
	// safe and apply emits provider-again-later rather than reconcile-required.
	// Left false for ambiguous/denied unknowns, which need a reconcile first.
	Retryable bool
	// RetryAfterSeconds (D243) carries the provider's Retry-After hint on a
	// throttle, when the driver captured it — converge waits exactly this long
	// instead of a blind exponential backoff. 0 = no hint (fall back to backoff).
	RetryAfterSeconds int
	// Outputs (D226/F13) are the driver-declared typed values a create
	// yields — subnet ids, a network selfLink — that another same-plan
	// action references. The executor filters these through OutputsFor and
	// kind-checks them before writing the receipt; only declared, valid
	// outputs persist. nil when the service produces none.
	Outputs map[string]any
}

// OutputSpec (D226/F13) is one typed output a service's create yields. Kind is
// a scalars.Kind string ("string","list",...) — the reference wiring refuses a
// mismatch against the consuming operand slot rather than coercing (invariant #2).
type OutputSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Conditional (D774) marks an output that EXISTS ONLY IN SOME CONFIGURATIONS —
	// a Lambda's functionUrl is there when the function has a URL and absent when it
	// does not, which for a function declaring `network.publicExposure: false` is the
	// CORRECT state. The registry already described these as conditional in prose while
	// the observe loop treated every declared output as mandatory, so a deliberately
	// private function was reported as a driver that could not read its own outputs.
	Conditional bool `json:"conditional,omitempty"`
	// Sample (D289) is a FORMAT-PLAUSIBLE stand-in used ONLY by `preflight`
	// to judge the REST of a capability's operands while a referenced value
	// does not exist yet. Drivers validate operand SHAPE (an ARN prefix, an
	// id pattern), so a generic placeholder made preflight report "missing
	// operand" for a slot that was wired and would resolve fine at apply — a
	// false negative on the surface whose whole job is one-round-trip truth.
	// It never reaches a driver call: apply substitutes real receipted values
	// (D275) or compile-folded literals (D283).
	Sample any `json:"-"`
}

// OutputProducer is the OPTIONAL driver interface a service implements to
// declare its typed outputs (D226). Resolved by type-assertion like Claimer /
// Reconciler; a driver that does not implement it produces no outputs, so any
// $ref to it refuses at compile (unknown output). Pure and table-driven.
type OutputProducer interface {
	OutputsFor(service string) []OutputSpec
}

// EmittedCompanion is a resource a service's create causes the PROVIDER to
// auto-materialise as a side effect — groundhold never creates it, but it is a
// companion groundhold is accountable for surfacing (D1032). The dangerous case:
// AWS Lambda auto-creates /aws/lambda/<fn> (a CloudWatch Logs group) with NO
// retention on first invocation, and the function's logs land THERE — not in a
// separate managed group a monitoring.logs capability builds. An emission a
// capability GOVERNS (a bound monitoring.logs sets its retention) is closed; an
// ungoverned one is a completeness gap. This registry is NOT an authorization
// token to adopt the companion (that stays a plan-time sealed grant, D1032+): it
// only NAMES what is emitted and which capability CAN govern it.
type EmittedCompanion struct {
	// GovernedBy is the capability TYPE that can govern this companion, e.g.
	// "capability.monitoring.logs" for a log group. Certified against the driver's
	// own ServiceCapabilities() — never a token no service fulfils.
	GovernedBy string `json:"governedBy"`
	// NameOutput is the emitting service's OWN declared output that names the
	// companion (e.g. lambda's "logGroupName", D381). D329: the emission's name and
	// the producer's published output are the SAME derivation, so a witness reading
	// the companion and a bound consumer governing it can never disagree. Certified
	// against OutputsFor(service) — a NameOutput the producer does not publish is a
	// drift the gate refuses.
	NameOutput string `json:"nameOutput"`
}

// EmissionCertifier is the OPTIONAL driver interface declaring the companion
// resources each service's create auto-materialises (D1032). Resolved by
// type-assertion like OutputProducer; a driver that emits nothing need not
// implement it. Certified by CertifyEmissions: every NameOutput is a real declared
// output of the emitting service (D329, no writer/witness drift) and every
// GovernedBy is a capability the driver actually fulfils.
type EmissionCertifier interface {
	EmittedCompanions() map[string][]EmittedCompanion
}

// OperandConsumer is the OPTIONAL driver interface declaring, per service, the
// exact set of `implementation:` operand KEYS the driver legitimately reads.
// The candidate `implementation:` block is free-form (D26), but an operand no
// driver consumes must be REFUSED LOUDLY, never silently dropped — the same
// fail-closed rule the per-attribute allowlists already enforce (a driver's
// attribute switch ends in a `default:` that refuses an unmapped attribute
// rather than dropping it), applied to the operand half of the candidate. The
// COMPILER consults this to refuse an unknown operand before a plan is sealed
// (refuse before mutating). Resolved by type-assertion, parallel to
// OutputProducer.OutputsFor: pure, table-driven, keyed by the same SERVICE
// token the candidate declares. A driver that does NOT implement it declares no
// consumed set and is exempt from the guard (the deterministic Fake double,
// which reads no operands) — the guard binds the real cloud drivers.
type OperandConsumer interface {
	ConsumedOperands(service string) []string
}

// OperandPrefix reserves the observation-path namespace for IMPLEMENTATION
// operands (F-LC3): config a driver governs that is NOT a typed vocab attribute
// (a Lambda's VpcConfig, Environment, container image). A driver's observe
// records each operand's live state under OperandPrefix+<name> and the
// compiler's OperandDrifter step compares the DECLARED operand against it — so a
// change to a bound resource's operands is drift, not a silent no-op (the
// F16/F25 class: non-observable declared operands freeze replan).
const OperandPrefix = "implementation."

// ResourceAbsentPath (F-LC3) is the reserved observation path a driver emits
// when a BOUND resource is authoritatively GONE — a READABLE absence (a 404),
// never a read error. Value true means the resource no longer exists; the
// compiler turns a fresh true into a CREATE (re-create after an out-of-band
// delete). A driver that can read presence emits false when the resource is
// found, so the marker toggles both ways and a recreate self-heals. A read
// ERROR stays a returned error (unknown → blocks), never an absence.
const ResourceAbsentPath = "resource.absent"

// WithoutAbsence strips the absence marker from an observation set bound for a
// DISCOVERY record. Discovery enumerates what exists, so everything it returns is
// present by construction and the marker carries no information there — and a
// discovery record is a metadata-only vocabulary the drivers' own gates enforce.
// The observe path that reads ONE bound resource is where the marker means
// something; the reverse-mapping code is shared by both, so the filter belongs at
// the discovery boundary rather than inside every reader.
//
// Found by migrating the second driver (D518): D513 put the marker in the shared
// k8s mapped read, and k8s discovery reuses it, so the marker rode into discovery
// records. Azure's discovery gate refused the same thing on the next driver; k8s
// had no such gate, which is exactly why it did not.
// IsAbsent reports whether an observation set says the resource is GONE.
//
// Discovery enumerates what EXISTS, so a record must not be emitted for a
// resource whose read just said it does not. Some discoverers tested this
// indirectly — "no observations means not provisioned" — which was true only
// while an absent resource produced silence. The marker made silence impossible,
// so the indirect test stopped working and two posture discoverers started
// enumerating resources that were not there (D521). Ask directly.
func IsAbsent(obs []Observation) bool {
	for _, o := range obs {
		if o.Path == ResourceAbsentPath {
			gone, _ := o.Value.(bool)
			return gone
		}
	}
	return false
}

func WithoutAbsence(obs []Observation) []Observation {
	out := obs[:0:0]
	for _, o := range obs {
		if o.Path != ResourceAbsentPath {
			out = append(out, o)
		}
	}
	return out
}

// DeclaredIntentSource (F-LC3) marks an observation adopt recorded for a
// NON-OBSERVABLE declared attribute — intent taken on the candidate's own
// provenance, never measured reality. The audit evidence lattice ranks it 0
// (it satisfies a static constraint but is rejected for provider-api/probe
// methods), and the compiler treats it as unverified intent, never as drift or
// a staleness freeze.
const DeclaredIntentSource = "candidate-declared"

// OperandTarget (F-LC3) is one declared implementation operand's reconcile
// target: the reserved observation Path it is recorded under and the canonical
// Desired value the DECLARED implementation should hold there. The compiler
// compares Desired against the recorded observation and routes a difference
// through ClassifyChange (mutable → update, immutable → replace), exactly like a
// vocab attribute.
type OperandTarget struct {
	Path    string
	Desired any
}

// OperandDrifter (F-LC3) is an OPTIONAL driver capability: a driver whose
// IMPLEMENTATION operands can drift on a BOUND resource reports, for the
// DECLARED implementation, the operand targets to reconcile against. PURE — no
// network, no LLM (invariant #6). Returns targets sorted by Path (determinism);
// an error is a build/preflight refusal the compiler ISOLATES per capability.
type OperandDrifter interface {
	OperandTargets(service string, attributes, implementation map[string]any) ([]OperandTarget, error)
}

// Observation is a reverse-mapped semantic fact (D44). Derivation
// mirrors candidate provenance (D5): config-intent vs measured.
type Observation struct {
	Path       string
	Value      any
	Derivation string // config-intent | measured
}

// A multi-service driver (D76) dispatches on the SERVICE token
// (cloudsql | cloudrun | gcs …) — the API family that fulfils a capability,
// not the capability TYPE (a database.relational may be Cloud SQL today,
// AlloyDB tomorrow). The service is a schema'd candidate field, hash-pinned
// into the plan action's target and every binding, so it travels with the
// identity. Every method takes it explicitly; the driver dispatches with a
// closed switch that FAILS CLOSED on unknown/empty — never a default service.
type Provider interface {
	Name() string
	// Validate is the driver's refuse-before-mutate hook: a semantic
	// attribute the driver cannot honor refuses here, in preflight,
	// never by silently dropping it (D43).
	Validate(service, capability, environment string,
		attributes, implementation map[string]any, generation int) error
	// Create's generation feeds the deterministic name (D48): a
	// replacement (generation >= 2) coexists with its predecessor.
	Create(service, capability, environment string,
		attributes, implementation map[string]any,
		idempotencyKey string, generation int) CreateResult
	// Observe reads a bound resource and reverse-maps it to semantic
	// attributes; diagnostics name what was deliberately NOT observed
	// and why (D44).
	Observe(service, capability, providerID string) ([]Observation, []string, error)
	// ClassifyChange is PURE provider knowledge (D46): can this
	// transition be honored in place? Mutability is transition-dependent
	// (removing public exposure needs a prepared network; adding it does
	// not), so the classification sees current, desired and the
	// implementation block. Returns class and an optional caveat note.
	//   mutable | immutable | unsupported | caveated
	ClassifyChange(service, path string, current, desired any,
		implementation map[string]any) (string, string)
	// Update patches a bound resource with EXACTLY the changed paths,
	// values sourced from the hash-pinned candidate (D46).
	Update(service, capability, environment, providerID string,
		attributes, implementation map[string]any,
		changes []string, idempotencyKey string) CreateResult
	// Delete destroys the pinned identity (D47). Drivers re-check
	// ownership and deletion protection; protection is never
	// auto-disabled.
	Delete(service, capability, environment, providerID string,
		idempotencyKey string) CreateResult
}

// PermissionsFor is the PURE, deterministic permission table (D75, per-service
// D76): the full permission set an operation's driver call sequence needs —
// quiet reads included, because an OMITTED permission produces a false PASS
// (the dangerous direction). Keyed by (provider, SERVICE, operation) — the
// same service token the candidate declares, the target embeds and the
// binding stores, so dispatch, targets, permissions and providerIds share one
// vocabulary. attrs (from the hash-pinned candidate, nil legal) let a set be
// exposure-conditional: a Cloud Run service made public needs IAM permissions
// a private one does not — including them unconditionally false-refuses
// private deployers, omitting them false-PASSes public ones. Sorted, deduped,
// no network. This list enters the sealed plan; the LIVE check is Preflighter.
// claimPermissions declares the takeover-claim (D145) permission footprint per
// service, centralized because a claim is a small, uniform shape per cloud: a
// tag/label stamp. GCP/Azure claims are the resource read + write; AWS claims are
// a tag API (RGT `tag:TagResources` + the service's own tag action, or a native
// tag call). A service with no entry is not claimable (it honest-refuses at the
// driver), so it declares no claim permissions.
func claimPermissions(providerName, service string) []string {
	switch providerName {
	case "aws":
		return sortedDedup(awsClaimPerms[service])
	case "gcp":
		return sortedDedup(gcpClaimPerms[service])
	case "azure":
		return sortedDedup(azureClaimPerms[service])
	}
	return nil
}

// awsClaimPerms: RGT-by-ARN services need `tag:TagResources` PLUS the resource's
// own tag action (AWS enforces both); the region-only ARNs also read the account
// via STS. rds/secretsmanager use their native tag API.
var awsClaimPerms = map[string][]string{
	"rds":                    {"rds:AddTagsToResource", "rds:DescribeDBInstances"},
	"secretsmanager":         {"secretsmanager:TagResource", "secretsmanager:DescribeSecret"},
	"s3":                     {"tag:TagResources", "s3:PutBucketTagging"},
	"sqs":                    {"tag:TagResources", "sqs:TagQueue"},
	"sns":                    {"tag:TagResources", "sns:TagResource"},
	"dynamodb":               {"tag:TagResources", "dynamodb:TagResource"},
	"ecr":                    {"tag:TagResources", "ecr:TagResource"},
	"efs":                    {"tag:TagResources", "elasticfilesystem:TagResource"},
	"opensearch":             {"tag:TagResources", "es:AddTags"},
	"opensearch-serverless":  {"tag:TagResources", "aoss:TagResource", "aoss:BatchGetCollection"},
	"kinesis":                {"tag:TagResources", "kinesis:AddTagsToStream"},
	"elasticache":            {"tag:TagResources", "elasticache:AddTagsToResource"},
	"elasticache-serverless": {"tag:TagResources", "elasticache:AddTagsToResource"},
	"acm":                    {"tag:TagResources", "acm:AddTagsToCertificate"},
	"cloudwatch":             {"tag:TagResources", "cloudwatch:TagResource"},
	"backupvault":            {"tag:TagResources", "backup:TagResource"},
	// apigateway declares the RGT stamp ALONE, and the omission is deliberate (D846).
	// API Gateway does not authorize by operation name: its IAM actions are HTTP VERBS,
	// so there is no `apigateway:TagResource` to grant — the tag write is `PUT /tags/{arn}`
	// (v1) or `POST /v2/tags/{arn}` (v2). Which of the two RGT calls through for an HTTP
	// API's ARN is not derivable from anything readable here, and a claim targets an
	// EXISTING resource, so its preflight runs in the resource's context where an implicit
	// deny is authoritative: naming both verbs would REFUSE an operator who granted the
	// right one. Declaring less is the honest half — a missing entry degrades to a denial
	// at the call, which names the action AWS wanted, while a wrong one cannot be granted
	// at all.
	"apigateway": {"tag:TagResources"},
	"cloudfront": {"tag:TagResources", "cloudfront:TagResource"},
	"vpc":        {"tag:TagResources", "ec2:CreateTags", "sts:GetCallerIdentity"},
	"vpngateway": {"tag:TagResources", "ec2:CreateTags", "sts:GetCallerIdentity"},
	"kms":        {"tag:TagResources", "kms:TagResource", "sts:GetCallerIdentity"},
	// describe-to-resolve-ARN services: RGT stamp + the service tag action + the
	// read that resolves the ARN (the pid carries no taggable ARN).
	"ecs":                {"tag:TagResources", "ecs:TagResource", "ecs:DescribeServices"},
	"apprunner":          {"tag:TagResources", "apprunner:TagResource", "apprunner:ListServices"},
	"msk":                {"tag:TagResources", "kafka:TagResource", "kafka:ListClustersV2"},
	"waf":                {"tag:TagResources", "wafv2:TagResource", "wafv2:ListWebACLs"},
	"redshiftserverless": {"tag:TagResources", "redshift-serverless:TagResource", "redshift-serverless:GetWorkgroup"},
	"eks":                {"tag:TagResources", "eks:TagResource", "eks:DescribeCluster"},
	"ses-sending":        {"tag:TagResources", "ses:TagResource", "sts:GetCallerIdentity"},
	"aurora":             {"tag:TagResources", "rds:AddTagsToResource", "sts:GetCallerIdentity"},
	"guardduty":          {"tag:TagResources", "guardduty:TagResource", "sts:GetCallerIdentity"},
	"cwlogs":             {"tag:TagResources", "logs:TagResource", "sts:GetCallerIdentity"},
	"lambda":             {"tag:TagResources", "lambda:TagResource", "lambda:GetFunction"},
}

// gcpClaimPerms: a label read-modify-write is get+update on the resource; the LRO
// patches also poll operations.get.
var gcpClaimPerms = map[string][]string{
	"cloudsql":          {"cloudsql.instances.get", "cloudsql.instances.update"},
	"gcs":               {"storage.buckets.get", "storage.buckets.update"},
	"pubsub-topic":      {"pubsub.topics.get", "pubsub.topics.update"},
	"pubsub-queue":      {"pubsub.subscriptions.get", "pubsub.subscriptions.update"},
	"secretmanager":     {"secretmanager.secrets.get", "secretmanager.secrets.update"},
	"bigquery":          {"bigquery.datasets.get", "bigquery.datasets.update"},
	"clouddns":          {"dns.managedZones.get", "dns.managedZones.update"},
	"artifactregistry":  {"artifactregistry.repositories.get", "artifactregistry.repositories.update"},
	"cloudkms":          {"cloudkms.cryptoKeys.get", "cloudkms.cryptoKeys.update"},
	"monitoring":        {"monitoring.alertPolicies.get", "monitoring.alertPolicies.update"},
	"uptime":            {"monitoring.uptimeCheckConfigs.get", "monitoring.uptimeCheckConfigs.update"},
	"memorystore":       {"redis.instances.get", "redis.instances.update", "redis.operations.get"},
	"filestore":         {"file.instances.get", "file.instances.update", "file.operations.get"},
	"managedkafka":      {"managedkafka.clusters.get", "managedkafka.clusters.update", "managedkafka.operations.get"},
	"certmanager":       {"certificatemanager.certs.get", "certificatemanager.certs.update", "certificatemanager.operations.get"},
	"cloudfunctions":    {"cloudfunctions.functions.get", "cloudfunctions.functions.update", "cloudfunctions.operations.get"},
	"cloudfunctions-fn": {"cloudfunctions.functions.get", "cloudfunctions.functions.update", "cloudfunctions.operations.get"},
	"backupvault":       {"backupdr.backupVaults.get", "backupdr.backupVaults.update", "backupdr.operations.get"},
	"backupplan":        {"backupdr.backupPlans.get", "backupdr.backupPlans.update", "backupdr.operations.get"},
	"cloudrun":          {"run.services.get", "run.services.update", "run.operations.get"},
	"cloudrunjobs":      {"run.jobs.get", "run.jobs.update", "run.operations.get"},
}

// azureClaimPerms: the ARM tags PATCH is uniformly the resource-type read + write
// (a tags patch is a resource write, not a separate tags action).
var azureClaimPerms = map[string][]string{
	"flexpostgres":     {"Microsoft.DBforPostgreSQL/flexibleServers/read", "Microsoft.DBforPostgreSQL/flexibleServers/write"},
	"loganalytics":     {"Microsoft.OperationalInsights/workspaces/read", "Microsoft.OperationalInsights/workspaces/write"},
	"aks":              {"Microsoft.ContainerService/managedClusters/read", "Microsoft.ContainerService/managedClusters/write"},
	"acsemail":         {"Microsoft.Communication/emailServices/read", "Microsoft.Communication/emailServices/write"},
	"azureopenai":      {"Microsoft.CognitiveServices/accounts/read", "Microsoft.CognitiveServices/accounts/write"},
	"blob":             {"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
	"azurefiles":       {"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
	"vnet":             {"Microsoft.Network/virtualNetworks/read", "Microsoft.Network/virtualNetworks/write"},
	"dnszone":          {"Microsoft.Network/dnsZones/read", "Microsoft.Network/dnsZones/write", "Microsoft.Network/privateDnsZones/read", "Microsoft.Network/privateDnsZones/write"},
	"frontdoorwaf":     {"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read", "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/write"},
	"azurecdn":         {"Microsoft.Cdn/profiles/read", "Microsoft.Cdn/profiles/write"},
	"loadbalancer":     {"Microsoft.Network/applicationGateways/read", "Microsoft.Network/applicationGateways/write"},
	"containerapps":    {"Microsoft.App/containerApps/read", "Microsoft.App/containerApps/write"},
	"containerappsjob": {"Microsoft.App/jobs/read", "Microsoft.App/jobs/write"},
	"acr":              {"Microsoft.ContainerRegistry/registries/read", "Microsoft.ContainerRegistry/registries/write"},
	"servicebusqueue":  {"Microsoft.ServiceBus/namespaces/read", "Microsoft.ServiceBus/namespaces/write"},
	"servicebustopic":  {"Microsoft.ServiceBus/namespaces/read", "Microsoft.ServiceBus/namespaces/write"},
	"eventhubs":        {"Microsoft.EventHub/namespaces/read", "Microsoft.EventHub/namespaces/write"},
	"azkafka":          {"Microsoft.EventHub/namespaces/read", "Microsoft.EventHub/namespaces/write"},
	"keyvault":         {"Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/write"},
	"keyvaultkey":      {"Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/write"},
	"rediscache":       {"Microsoft.Cache/Redis/read", "Microsoft.Cache/Redis/write"},
	"cosmos":           {"Microsoft.DocumentDB/databaseAccounts/read", "Microsoft.DocumentDB/databaseAccounts/write"},
	"aisearch":         {"Microsoft.Search/searchServices/read", "Microsoft.Search/searchServices/write"},
	"apim":             {"Microsoft.ApiManagement/service/read", "Microsoft.ApiManagement/service/write"},
	"managedidentity":  {"Microsoft.ManagedIdentity/userAssignedIdentities/read", "Microsoft.ManagedIdentity/userAssignedIdentities/write"},
	"metricalert":      {"Microsoft.Insights/metricAlerts/read", "Microsoft.Insights/metricAlerts/write"},
	"portaldash":       {"Microsoft.Portal/dashboards/read", "Microsoft.Portal/dashboards/write"},
	"webtest":          {"Microsoft.Insights/webtests/read", "Microsoft.Insights/webtests/write"},
	"scheduledquery":   {"Microsoft.Insights/scheduledQueryRules/read", "Microsoft.Insights/scheduledQueryRules/write"},
}

func PermissionsFor(providerName, service, operation string, attrs map[string]any) []string {
	if operation == "claim" {
		return claimPermissions(providerName, service)
	}
	switch providerName {
	case "gcp":
		switch service {
		case "loadbalancer":
			// D26. Global external HTTP(S) LB composite: reserved IP + health check
			// + backend service + url map + target proxy + global forwarding rule,
			// polled via globalOperations.get. The proxy permission is conditional on
			// encryption.inTransit (HTTP vs HTTPS proxy; HTTPS also reads the cert).
			inTransit, _ := attrs["encryption.inTransit"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{
					"compute.backendServices.create", "compute.backendServices.get",
					"compute.globalAddresses.create", "compute.globalAddresses.get",
					"compute.globalForwardingRules.create", "compute.globalForwardingRules.get",
					"compute.globalOperations.get",
					"compute.healthChecks.create", "compute.healthChecks.get",
					"compute.urlMaps.create", "compute.urlMaps.get",
				}
				if inTransit {
					p = append(p, "compute.sslCertificates.get",
						"compute.targetHttpsProxies.create", "compute.targetHttpsProxies.get")
				} else {
					p = append(p, "compute.targetHttpProxies.create", "compute.targetHttpProxies.get")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"compute.globalOperations.get",
					"compute.healthChecks.get", "compute.healthChecks.update"})
			case "delete":
				return sortedDedup([]string{
					"compute.backendServices.delete", "compute.backendServices.get",
					"compute.globalAddresses.delete", "compute.globalAddresses.get",
					"compute.globalForwardingRules.delete", "compute.globalForwardingRules.get",
					"compute.globalOperations.get",
					"compute.healthChecks.delete", "compute.healthChecks.get",
					"compute.targetHttpProxies.delete", "compute.targetHttpProxies.get",
					"compute.targetHttpsProxies.delete", "compute.targetHttpsProxies.get",
					"compute.urlMaps.delete", "compute.urlMaps.get",
				})
			}
		case "assetfeed":
			// D142/D143. A Cloud Asset Inventory change feed -> Pub/Sub. feeds.get
			// is the quiet read (409 ownership classification on create, pre-read on
			// delete). The target topic's own IAM is a separate capability.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"cloudasset.feeds.create", "cloudasset.feeds.get"})
			case "update":
				return sortedDedup([]string{"cloudasset.feeds.get", "cloudasset.feeds.update"})
			case "delete":
				return sortedDedup([]string{"cloudasset.feeds.delete", "cloudasset.feeds.get"})
			}
		case "cloudsql":
			// D43. instances.get is the quiet read every mutation makes: 409
			// ownership classification + operation polling on create,
			// ownership re-check on update, protection pre-read on delete.
			switch operation {
			case "create", "adopt":
				return []string{"cloudsql.instances.create", "cloudsql.instances.get"}
			case "update":
				return []string{"cloudsql.instances.get", "cloudsql.instances.update"}
			case "delete":
				return []string{"cloudsql.instances.delete", "cloudsql.instances.get"}
			}
		case "cloudrun":
			// D76. run.operations.get is a DISTINCT permission for the v2 LRO
			// poll (unlike Cloud SQL where instances.get covered it). Public
			// exposure adds the IAM read-modify-write to grant allUsers invoker.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"run.operations.get", "run.services.create", "run.services.get"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"run.operations.get", "run.services.get", "run.services.update"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				return []string{"run.operations.get", "run.services.delete", "run.services.get"}
			}
		case "cloudfunctions":
			// D84. Gen2 function under the SAME capability.workload.container as
			// cloudrun. Public exposure grants the invoker role on the BACKING
			// Cloud Run service, so it adds the run.services IAM pair (not a
			// cloudfunctions-native one) — attribute-conditional like cloudrun.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"cloudfunctions.functions.create",
					"cloudfunctions.functions.get", "cloudfunctions.operations.get"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"cloudfunctions.functions.get",
					"cloudfunctions.functions.update", "cloudfunctions.operations.get"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				return []string{"cloudfunctions.functions.delete",
					"cloudfunctions.functions.get", "cloudfunctions.operations.get"}
			}
		case "cloudfunctions-fn":
			// capability.function.serverless on Cloud Functions gen2 — the SAME
			// functions.* + operations.get surface as the workload-container token,
			// with the public-exposure run.services IAM pair (the invoker is granted
			// on the BACKING Cloud Run service), attribute-conditional like cloudrun.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"cloudfunctions.functions.create",
					"cloudfunctions.functions.get", "cloudfunctions.operations.get"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"cloudfunctions.functions.get",
					"cloudfunctions.functions.update", "cloudfunctions.operations.get"}
				if public {
					p = append(p, "run.services.getIamPolicy", "run.services.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				return []string{"cloudfunctions.functions.delete",
					"cloudfunctions.functions.get", "cloudfunctions.operations.get"}
			}
		case "gcs":
			// D77. Bucket ops; public read adds the IAM pair (grant allUsers
			// objectViewer). storage.buckets.get is the ownership pre-read.
			// resourcemanager.projects.get resolves our project NUMBER for the
			// cross-project ownership check GCS's global namespace requires (D82).
			public, _ := attrs["network.publicExposure"].(bool)
			locked, _ := attrs["retention.locked"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"resourcemanager.projects.get",
					"storage.buckets.create", "storage.buckets.get"}
				if public {
					p = append(p, "storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy")
				}
				if locked {
					// buckets.lockRetentionPolicy is gated by storage.buckets.update
					p = append(p, "storage.buckets.update")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"resourcemanager.projects.get",
					"storage.buckets.get", "storage.buckets.update"}
				if public {
					p = append(p, "storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				return []string{"resourcemanager.projects.get",
					"storage.buckets.delete", "storage.buckets.get"}
			}
		case "pubsub-queue":
			// D94/D95. capability.messaging.queue is a CONSTITUTIVE COMPOSITE of a
			// subscription + a backing topic, so it adds the pubsub.subscriptions.*
			// actions on top of the topic ones. topics.get is the quiet read (409
			// ownership classification + the delete pre-read). Public exposure adds
			// the IAM read-modify-write (allUsers subscriber) — attribute-conditional,
			// like cloudrun/gcs. Dispatch is on the SERVICE token (D76), never a guess
			// from the attrs — the driver decides queue-vs-topic the same way.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"pubsub.subscriptions.create", "pubsub.subscriptions.get",
					"pubsub.topics.create", "pubsub.topics.get"}
				if public {
					p = append(p, "pubsub.subscriptions.getIamPolicy", "pubsub.subscriptions.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"pubsub.subscriptions.get", "pubsub.subscriptions.update"}
				if public {
					p = append(p, "pubsub.subscriptions.getIamPolicy", "pubsub.subscriptions.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				// reverse retirement: subscription then the backing topic.
				return sortedDedup([]string{"pubsub.subscriptions.delete",
					"pubsub.subscriptions.get", "pubsub.topics.delete", "pubsub.topics.get"})
			}
		case "pubsub-topic":
			// D94. capability.messaging.topic — a single topic. Public exposure adds
			// the IAM read-modify-write (allUsers publisher).
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"pubsub.topics.create", "pubsub.topics.get"}
				if public {
					p = append(p, "pubsub.topics.getIamPolicy", "pubsub.topics.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				p := []string{"pubsub.topics.get", "pubsub.topics.update"}
				if public {
					p = append(p, "pubsub.topics.getIamPolicy", "pubsub.topics.setIamPolicy")
				}
				return sortedDedup(p)
			case "delete":
				return []string{"pubsub.topics.delete", "pubsub.topics.get"}
			}
		case "vpc":
			// D83. Multi-resource: network + regional subnet + (if egress
			// restricted) a firewall; both operation-poll scopes are quiet reads.
			egress, _ := attrs["egress.restricted"].(bool)
			road, _ := attrs["egress.internet"].(string)
			switch operation {
			case "create", "adopt":
				p := []string{"compute.networks.create", "compute.networks.get",
					"compute.subnetworks.create", "compute.subnetworks.get",
					"compute.globalOperations.get", "compute.regionOperations.get"}
				if egress {
					p = append(p, "compute.firewalls.create", "compute.firewalls.get",
						"compute.networks.updatePolicy")
				}
				if road == "nat" {
					// fala 2: Cloud NAT rides a Cloud Router. Private Google Access
					// (serviceAccess.private) needs no extra perm — it is a subnet field
					// set at compute.subnetworks.create.
					p = append(p, "compute.routers.create", "compute.routers.get")
				}
				return sortedDedup(p)
			case "update":
				return []string{"compute.networks.get", "compute.subnetworks.update"}
			case "delete":
				return sortedDedup([]string{"compute.networks.delete",
					"compute.networks.get", "compute.subnetworks.delete",
					"compute.firewalls.delete", "compute.firewalls.list",
					"compute.routers.delete", "compute.routers.list", "compute.routers.get",
					"compute.globalOperations.get", "compute.regionOperations.get"})
			}
		case "secretmanager":
			// D97. A managed secret handle; public exposure adds the IAM RMW
			// (allUsers secretAccessor). secrets.get is the quiet read (409-continue
			// ownership + delete pre-read).
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"secretmanager.secrets.create", "secretmanager.secrets.get"}
				if public {
					p = append(p, "secretmanager.secrets.getIamPolicy", "secretmanager.secrets.setIamPolicy")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"secretmanager.secrets.get", "secretmanager.secrets.update"})
			case "delete":
				return sortedDedup([]string{"secretmanager.secrets.delete", "secretmanager.secrets.get"})
			}
		case "memorystore":
			// D100. Managed Redis (capability.cache.keyvalue). Async create/delete,
			// so redis.operations.get is the LRO poll permission; redis.instances.get
			// is the quiet read (409-continue ownership + delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"redis.instances.create",
					"redis.instances.get", "redis.operations.get"})
			case "update":
				return sortedDedup([]string{"redis.instances.get",
					"redis.instances.update", "redis.operations.get"})
			case "delete":
				return sortedDedup([]string{"redis.instances.delete",
					"redis.instances.get", "redis.operations.get"})
			}
		case "clouddns":
			// D101. A managed DNS zone (capability.dns.zone). Sync create/delete;
			// managedZones.get is the quiet read (409-continue ownership + delete
			// pre-read). Records are data, out of band — no rrsets.* permission.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"dns.managedZones.create", "dns.managedZones.get"})
			case "update":
				return sortedDedup([]string{"dns.managedZones.get", "dns.managedZones.update"})
			case "delete":
				return sortedDedup([]string{"dns.managedZones.delete", "dns.managedZones.get"})
			}
		case "clouddnsrecord":
			// D262. A single DNS record set (capability.dns.record) inside a managed
			// zone. The write is an atomic Change (additions/deletions of rrsets);
			// managedZones.get is the ownership read (the zone's labels), rrsets.list
			// the observe / pre-delete read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"dns.changes.create",
					"dns.resourceRecordSets.list", "dns.managedZones.get"})
			case "delete":
				return sortedDedup([]string{"dns.changes.create",
					"dns.resourceRecordSets.list", "dns.managedZones.get"})
			}
		case "iambinding":
			// D104. A named-role grant (capability.authorization.grant) = a binding in
			// the project IAM policy. Read-modify-write: getIamPolicy is the quiet read
			// (both create and delete read-then-write), setIamPolicy the mutation. No
			// role is authored — so no iam.roles.create.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"resourcemanager.projects.getIamPolicy",
					"resourcemanager.projects.setIamPolicy"})
			case "delete":
				return sortedDedup([]string{
					"resourcemanager.projects.getIamPolicy",
					"resourcemanager.projects.setIamPolicy"})
			}
		case "customrole":
			// D105. A custom role (capability.authorization.role). Sync create/delete;
			// roles.get is the quiet read (409-continue permission-set match + observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"iam.roles.create", "iam.roles.get"})
			case "update":
				return sortedDedup([]string{"iam.roles.get", "iam.roles.update"})
			case "delete":
				return sortedDedup([]string{"iam.roles.delete", "iam.roles.get"})
			}
		case "monitoring":
			// D106. A metric alert (capability.monitoring.alert). Sync create/delete;
			// alertPolicies.get is the quiet read (ownership pre-read on delete + observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"monitoring.alertPolicies.create", "monitoring.alertPolicies.get"})
			case "update":
				return sortedDedup([]string{"monitoring.alertPolicies.get", "monitoring.alertPolicies.update"})
			case "delete":
				return sortedDedup([]string{"monitoring.alertPolicies.delete", "monitoring.alertPolicies.get"})
			}
		case "dashboard":
			// D107. A metric dashboard (capability.monitoring.dashboard). Sync
			// create/delete; dashboards.get is the quiet read (ownership pre-read + observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"monitoring.dashboards.create", "monitoring.dashboards.get"})
			case "update":
				return sortedDedup([]string{"monitoring.dashboards.get", "monitoring.dashboards.update"})
			case "delete":
				return sortedDedup([]string{"monitoring.dashboards.delete", "monitoring.dashboards.get"})
			}
		case "uptime":
			// D108. A synthetic uptime check (capability.monitoring.uptime). Sync
			// create/delete; uptimeCheckConfigs.get is the quiet read (ownership + observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"monitoring.uptimeCheckConfigs.create", "monitoring.uptimeCheckConfigs.get"})
			case "update":
				return sortedDedup([]string{"monitoring.uptimeCheckConfigs.get", "monitoring.uptimeCheckConfigs.update"})
			case "delete":
				return sortedDedup([]string{"monitoring.uptimeCheckConfigs.delete", "monitoring.uptimeCheckConfigs.get"})
			}
		case "logmetric":
			// D109. A log-based metric (capability.monitoring.logmetric). Sync
			// create/delete; logMetrics.get is the quiet read (409-continue + observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"logging.logMetrics.create", "logging.logMetrics.get"})
			case "update":
				return sortedDedup([]string{"logging.logMetrics.get", "logging.logMetrics.update"})
			case "delete":
				return sortedDedup([]string{"logging.logMetrics.delete", "logging.logMetrics.get"})
			}
		case "mig":
			// D371. A fleet (capability.compute.autoscaling). insert takes no
			// idempotency key, so the deterministic NAME is the mechanism and
			// instanceGroupManagers.get is the quiet read (409 continuation + delete
			// pre-read). Ownership is the DESCRIPTION MARKER — a managed instance group
			// has no labels.
			//
			// instanceTemplates.get is the PREFLIGHT, not an extra: the group inherits
			// the template's addressing and cannot override it, so
			// `network.publicExposure` cannot be honored without reading a resource the
			// group does not own. Both operation scopes are listed because a regional
			// group is a different resource at a different scope.
			switch operation {
			case "create", "adopt":
				p := []string{"compute.instanceGroupManagers.create",
					"compute.instanceGroupManagers.get", "compute.instanceTemplates.get",
					"compute.zoneOperations.get", "compute.regionOperations.get"}
				if on, _ := attrs["autoscaling.enabled"].(bool); on {
					p = append(p, "compute.autoscalers.create", "compute.autoscalers.list")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"compute.instanceGroupManagers.get",
					"compute.instanceGroupManagers.update", "compute.autoscalers.list",
					"compute.autoscalers.update", "compute.instanceTemplates.get"})
			case "delete":
				return sortedDedup([]string{"compute.instanceGroupManagers.delete",
					"compute.instanceGroupManagers.get", "compute.zoneOperations.get",
					"compute.regionOperations.get"})
			}
		case "computeimage":
			// D370. A machine image (capability.compute.image), WITNESSED not authored
			// (D177) — so there is no create/delete permission set, only the reads.
			// getIamPolicy is a second permission for a second question: public sharing
			// is a POLICY on GCP, not a field on the resource, and an observe that
			// cannot make that call reports the fact unread rather than defaulting it.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"compute.images.get", "compute.images.list",
					"compute.images.getIamPolicy"})
			}
		case "pd":
			// D368. A block volume (capability.storage.block). disks.insert takes no
			// idempotency key, so the deterministic NAME is the mechanism and disks.get
			// is the quiet read (409 continuation + delete pre-read). Ownership is
			// labels — and on a STATEFUL capability that read is what stands between a
			// mis-pinned providerId and destroying data that is not ours, so it is
			// required on the delete path. A REGIONAL disk is a different resource at a
			// different scope, which is why regionOperations.get joins the zonal one.
			switch operation {
			case "create", "adopt":
				p := []string{"compute.disks.create", "compute.disks.get",
					"compute.zoneOperations.get", "compute.regionOperations.get"}
				if cmk, _ := attrs["encryption.customerManagedKeys"].(bool); cmk {
					p = append(p, "cloudkms.cryptoKeys.get",
						"cloudkms.cryptoKeyVersions.useToEncrypt")
				}
				return sortedDedup(p)
			case "update":
				// Every governed attribute is immutable on a volume (D368), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"compute.disks.get"})
			case "delete":
				return sortedDedup([]string{"compute.disks.delete", "compute.disks.get",
					"compute.zoneOperations.get", "compute.regionOperations.get"})
			}
		case "gce":
			// D359. A virtual machine (capability.compute.instance). instances.insert
			// takes no idempotency key, so the deterministic NAME is the mechanism and
			// instances.get is the quiet read (409 continuation + delete pre-read).
			// Ownership is labels. A customer-managed disk key adds the KMS encrypt/
			// decrypt pair, which the platform-managed default does not need.
			switch operation {
			case "create", "adopt":
				p := []string{"compute.instances.create", "compute.instances.get",
					"compute.disks.create", "compute.subnetworks.use", "compute.zoneOperations.get"}
				if cmk, _ := attrs["encryption.customerManagedKeys"].(bool); cmk {
					p = append(p, "cloudkms.cryptoKeys.get",
						"cloudkms.cryptoKeyVersions.useToEncrypt")
				}
				if public, _ := attrs["network.publicExposure"].(bool); public {
					p = append(p, "compute.subnetworks.useExternalIp")
				}
				return sortedDedup(p)
			case "update":
				// Every governed attribute is immutable on a machine (D357/D359), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"compute.instances.get"})
			case "delete":
				return sortedDedup([]string{"compute.instances.delete",
					"compute.instances.get", "compute.zoneOperations.get"})
			}
		case "artifactregistry":
			// D110. A container image registry (capability.registry.image). LRO create/
			// delete; repositories.get is the quiet read. Public exposure adds the IAM
			// pair to grant allUsers reader.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"artifactregistry.repositories.create", "artifactregistry.repositories.get"}
				if public {
					p = append(p, "artifactregistry.repositories.getIamPolicy", "artifactregistry.repositories.setIamPolicy")
				}
				if scan, _ := attrs["security.scanOnPush"].(bool); scan {
					// fala 2: GCP scanning is the project-level Container Scanning API,
					// enabled via Service Usage (not a per-repo field like ECR).
					p = append(p, "serviceusage.services.enable", "serviceusage.services.get")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"artifactregistry.repositories.get", "artifactregistry.repositories.update"})
			case "delete":
				return sortedDedup([]string{"artifactregistry.repositories.delete", "artifactregistry.repositories.get"})
			}
		case "filestore":
			// D111. A managed NFS file share (capability.storage.filesystem). Async
			// create/delete, so file.operations.get is the LRO poll permission;
			// file.instances.get is the quiet read (409-continue ownership + delete
			// pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"file.instances.create",
					"file.instances.get", "file.operations.get"})
			case "update":
				return sortedDedup([]string{"file.instances.get",
					"file.instances.update", "file.operations.get"})
			case "delete":
				return sortedDedup([]string{"file.instances.delete",
					"file.instances.get", "file.operations.get"})
			}
		case "firestore":
			// D112. A managed NoSQL database (capability.database.nosql) — a NAMED
			// Firestore database. Async create/delete, so datastore.operations.get is
			// the LRO poll permission; datastore.databases.get is the quiet read
			// (content-addressed ownership + delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"datastore.databases.create",
					"datastore.databases.get", "datastore.operations.get"})
			case "update":
				return sortedDedup([]string{"datastore.databases.get",
					"datastore.databases.update", "datastore.operations.get"})
			case "delete":
				return sortedDedup([]string{"datastore.databases.delete",
					"datastore.databases.get", "datastore.operations.get"})
			}
		case "managedkafka":
			// D115. A managed Kafka cluster (capability.messaging.kafka). Async
			// create/delete, so managedkafka.operations.get is the LRO poll
			// permission; managedkafka.clusters.get is the quiet read (409-continue
			// ownership + delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"managedkafka.clusters.create",
					"managedkafka.clusters.get", "managedkafka.operations.get"})
			case "update":
				return sortedDedup([]string{"managedkafka.clusters.get",
					"managedkafka.clusters.update", "managedkafka.operations.get"})
			case "delete":
				return sortedDedup([]string{"managedkafka.clusters.delete",
					"managedkafka.clusters.get", "managedkafka.operations.get"})
			}
		case "cloudarmor":
			// D116. A managed WAF policy (capability.security.waf) — a global Cloud
			// Armor securityPolicy. Insert/delete are compute global-operation LROs,
			// so compute.globalOperations.get is the poll permission;
			// securityPolicies.get is the quiet read (ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"compute.securityPolicies.create",
					"compute.securityPolicies.get", "compute.globalOperations.get"})
			case "update":
				return sortedDedup([]string{"compute.securityPolicies.get",
					"compute.securityPolicies.update", "compute.globalOperations.get"})
			case "delete":
				return sortedDedup([]string{"compute.securityPolicies.delete",
					"compute.securityPolicies.get", "compute.globalOperations.get"})
			}
		case "certmanager":
			// D117. A managed TLS certificate (capability.certificate.tls). Async
			// create/delete, so certificatemanager.operations.get is the LRO poll
			// permission; certificatemanager.certs.get is the quiet read (409-continue
			// ownership + delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"certificatemanager.certs.create",
					"certificatemanager.certs.get", "certificatemanager.operations.get"})
			case "update":
				return sortedDedup([]string{"certificatemanager.certs.get",
					"certificatemanager.certs.update", "certificatemanager.operations.get"})
			case "delete":
				return sortedDedup([]string{"certificatemanager.certs.delete",
					"certificatemanager.certs.get", "certificatemanager.operations.get"})
			}
		case "cloudrunjobs":
			// D120. A managed container job (capability.container.job) — a Cloud Run
			// Job. Async create/delete, so run.operations.get is the LRO poll
			// permission; run.jobs.get is the quiet read (409-continue ownership +
			// delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"run.jobs.create",
					"run.jobs.get", "run.operations.get"})
			case "update":
				return sortedDedup([]string{"run.jobs.get",
					"run.jobs.update", "run.operations.get"})
			case "delete":
				return sortedDedup([]string{"run.jobs.delete",
					"run.jobs.get", "run.operations.get"})
			}
		case "serviceaccount":
			// D121. A managed machine identity (capability.identity.serviceaccount) —
			// a service account. Synchronous create; serviceAccounts.get is the quiet
			// read (409-continue ownership + delete pre-read). Granted roles are a
			// separate authorization concern (no IAM policy permission here).
			switch operation {
			case "create":
				return sortedDedup([]string{"iam.serviceAccounts.create", "iam.serviceAccounts.get"})
			case "adopt":
				// D868: adopt OBSERVES before it binds (internal/adopt), and observe now
				// reads the account's OWN IAM policy for `trust.principals` — who may pick
				// this identity up. A read the code makes and the preflight does not name is
				// a permission the operator learns about from a 403.
				return sortedDedup([]string{"iam.serviceAccounts.create", "iam.serviceAccounts.get",
					"iam.serviceAccounts.getIamPolicy"})
			case "update":
				return sortedDedup([]string{"iam.serviceAccounts.get", "iam.serviceAccounts.update"})
			case "delete":
				return sortedDedup([]string{"iam.serviceAccounts.delete", "iam.serviceAccounts.get"})
			}
		case "bigquery":
			// D122. A managed data warehouse (capability.warehouse.analytics) — a
			// BigQuery dataset. Sync create/delete; datasets.get is the quiet read
			// (409-continue ownership + delete pre-read). Table schemas and query
			// config are data/opaque impl — no tables.* permission.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"bigquery.datasets.create", "bigquery.datasets.get"})
			case "update":
				return sortedDedup([]string{"bigquery.datasets.get", "bigquery.datasets.update"})
			case "delete":
				return sortedDedup([]string{"bigquery.datasets.delete", "bigquery.datasets.get"})
			}
		case "cloudscheduler":
			// D123. A managed cron trigger (capability.scheduler.cron). Sync create;
			// jobs.get is the quiet read (409-continue ownership + delete pre-read).
			// A paused job adds jobs.pause (schedule.enabled=false). The target and
			// cron are opaque impl — no target-service permission here.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"cloudscheduler.jobs.create", "cloudscheduler.jobs.get",
					"cloudscheduler.jobs.pause"})
			case "update":
				return sortedDedup([]string{"cloudscheduler.jobs.get", "cloudscheduler.jobs.update"})
			case "delete":
				return sortedDedup([]string{"cloudscheduler.jobs.delete", "cloudscheduler.jobs.get"})
			}
		case "cloudkms":
			// D102. A managed encryption key (capability.key.encryption) — the
			// constitutive composite keyRing + cryptoKey. Neither can be deleted, so
			// delete lists + destroys key VERSIONS (the material). cryptoKeys.get is
			// the quiet read (409-continue ownership + delete pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"cloudkms.keyRings.create", "cloudkms.keyRings.get",
					"cloudkms.cryptoKeys.create", "cloudkms.cryptoKeys.get"})
			case "update":
				return sortedDedup([]string{"cloudkms.cryptoKeys.get", "cloudkms.cryptoKeys.update"})
			case "delete":
				return sortedDedup([]string{"cloudkms.cryptoKeys.get",
					"cloudkms.cryptoKeyVersions.list", "cloudkms.cryptoKeyVersions.destroy"})
			}
		case "vpngateway":
			// D126. A managed HA VPN gateway (capability.vpn.gateway). Regional compute
			// LRO; vpnGateways.get is the quiet read (409-continue ownership + delete
			// pre-read) and compute.regionOperations.get polls the op. The tunnels,
			// Cloud Router and BGP are opaque impl — no vpnTunnels/routers permissions.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"compute.vpnGateways.create", "compute.vpnGateways.get",
					"compute.regionOperations.get"})
			case "update":
				return sortedDedup([]string{"compute.vpnGateways.get"})
			case "delete":
				return sortedDedup([]string{"compute.vpnGateways.delete", "compute.vpnGateways.get",
					"compute.regionOperations.get"})
			}
		case "backupvault":
			// D127. A managed backup vault (capability.backup.vault). LRO; backupVaults.get
			// is the quiet read (409-continue ownership + delete pre-read), and the LRO
			// poll needs backupdr.operations.get. Backup plans/selections are opaque impl.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"backupdr.backupVaults.create", "backupdr.backupVaults.get",
					"backupdr.operations.get"})
			case "update":
				return sortedDedup([]string{"backupdr.backupVaults.get"})
			case "delete":
				return sortedDedup([]string{"backupdr.backupVaults.delete", "backupdr.backupVaults.get",
					"backupdr.operations.get"})
			}
		case "billingbudget":
			// Cloud Billing Budget (capability.cost.budget). budgets.get is the quiet read
			// (idempotency by displayName + observe); the limit/period/threshold ride in one patch.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"billing.budgets.create", "billing.budgets.get", "billing.budgets.list"})
			case "update":
				return sortedDedup([]string{"billing.budgets.get", "billing.budgets.update"})
			case "delete":
				return sortedDedup([]string{"billing.budgets.delete", "billing.budgets.get"})
			}
		case "logbucket":
			// Cloud Logging bucket (capability.monitoring.logs). buckets.get is the quiet read;
			// retention.days + CMEK are buckets.update patches.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"logging.buckets.create", "logging.buckets.get"})
			case "update":
				return sortedDedup([]string{"logging.buckets.get", "logging.buckets.update"})
			case "delete":
				return sortedDedup([]string{"logging.buckets.delete", "logging.buckets.get"})
			}
		case "auditlogs":
			// Cloud Logging audit-log export sink (capability.audit.trail). Sync; sinks.get
			// is the quiet read (ownership + observe + pre-delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"logging.sinks.create", "logging.sinks.get"})
			case "update":
				return sortedDedup([]string{"logging.sinks.get", "logging.sinks.update"})
			case "delete":
				return sortedDedup([]string{"logging.sinks.delete", "logging.sinks.get"})
			}
		case "scc":
			// Security Command Center posture (capability.security.threatdetection) via
			// securityCenterServices modules. A per-module intendedEnablementState patch;
			// .get is the quiet pre-read. Singleton per parent, no ownership marker.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"securitycentermanagement.securityCenterServices.get",
					"securitycentermanagement.securityCenterServices.update"})
			}
		case "vertexai":
			// Vertex AI endpoint (capability.ai.inference). endpoints.get is the quiet read
			// + observe; the LRO poll needs operations.get; routing is immutable (no patch).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"aiplatform.endpoints.create", "aiplatform.endpoints.get",
					"aiplatform.operations.get"})
			case "update":
				return []string{"aiplatform.endpoints.get"}
			case "delete":
				return sortedDedup([]string{"aiplatform.endpoints.delete", "aiplatform.endpoints.get",
					"aiplatform.operations.get"})
			}
		case "gke":
			// GKE cluster (capability.cluster.kubernetes). LRO composite; clusters.get is
			// the quiet read (ownership + health/409); operations.get polls. Node pool rides
			// in the cluster body; VPC/subnet are operands.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"container.clusters.create", "container.clusters.get", "container.operations.get"})
			case "update":
				return sortedDedup([]string{"container.clusters.get", "container.clusters.update", "container.operations.get"})
			case "delete":
				return sortedDedup([]string{"container.clusters.delete", "container.clusters.get", "container.operations.get"})
			}
		case "gke-addon":
			// A GKE addon is a flag in the cluster's addonsConfig, toggled by SetAddonsConfig
			// (an UpdateCluster op). No per-addon version action — GKE addons aren't versioned.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"container.clusters.get", "container.clusters.update", "container.operations.get"})
			}
		case "gke-workloadidentity":
			// Workload Identity binding = a member on the GSA's own IAM policy. RMW:
			// getIamPolicy is the quiet read, setIamPolicy the mutation. No role is authored.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"iam.serviceAccounts.getIamPolicy", "iam.serviceAccounts.setIamPolicy"})
			}
		case "backupplan":
			// D76 fala 4. A managed backup PLAN (capability.backup.plan) — the DR-policy
			// layer over a vault. LRO create/patch/delete; backupPlans.get is the quiet read;
			// operations.get polls. No cross-region copy exists in backupdr (honest-refused).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"backupdr.backupPlans.create", "backupdr.backupPlans.get", "backupdr.operations.get"})
			case "update":
				return sortedDedup([]string{"backupdr.backupPlans.update", "backupdr.backupPlans.get", "backupdr.operations.get"})
			case "delete":
				return sortedDedup([]string{"backupdr.backupPlans.delete", "backupdr.backupPlans.get", "backupdr.operations.get"})
			}
		}
		return nil // unknown/empty service under gcp: the COMPILER refuses
	case "aws":
		switch service {
		case "loadbalancer":
			// D26. The ALB composite: target group + load balancer + listener.
			// DescribeLoadBalancers/DescribeTags/DescribeTargetGroups/DescribeListeners
			// are the ownership pre-read + the async wait + the teardown resolution.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"elasticloadbalancing:CreateTargetGroup",
					"elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateListener",
					"elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:AddTags",
					"elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTargetGroups",
					"elasticloadbalancing:DescribeListeners"})
			case "update":
				return sortedDedup([]string{"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:DescribeTags", "elasticloadbalancing:ModifyTargetGroup"})
			case "delete":
				return sortedDedup([]string{"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeListeners",
					"elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DeleteListener",
					"elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:DeleteTargetGroup"})
			}
		case "changefeed":
			// D142/D143. An EventBridge rule on CloudTrail change events -> SQS.
			// DescribeRule/ListTargetsByRule are the ownership pre-read. No sqs:* —
			// the target queue's own provisioning is a separate capability.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"events:PutRule", "events:PutTargets",
					"events:DescribeRule", "events:ListTargetsByRule"})
			case "update":
				return sortedDedup([]string{"events:PutRule", "events:DescribeRule"})
			case "delete":
				return sortedDedup([]string{"events:DeleteRule", "events:RemoveTargets",
					"events:DescribeRule", "events:ListTargetsByRule"})
			}
		case "s3":
			// D86. Bucket ops; public read adds PutBucketPolicy (the anonymous
			// s3:GetObject grant), versioning adds PutBucketVersioning.
			// GetBucketTagging is the ownership pre-read (409-continue + delete).
			public, _ := attrs["network.publicExposure"].(bool)
			versioning, _ := attrs["versioning.enabled"].(bool)
			_, retentionMax := attrs["retention.maximum"]
			cmek, _ := attrs["encryption.customerManagedKeys"].(bool)
			replication, _ := attrs["replication.enabled"].(bool)
			_, corsDeclared := attrs["cors.allowedOrigins"]
			_, retentionMin := attrs["retention.minimum"]
			retentionLocked, _ := attrs["retention.locked"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"s3:CreateBucket", "s3:GetBucketTagging",
					"s3:PutBucketTagging", "s3:PutBucketPublicAccessBlock"}
				if public {
					p = append(p, "s3:PutBucketPolicy")
				}
				if versioning {
					p = append(p, "s3:PutBucketVersioning")
				}
				if retentionMax {
					p = append(p, "s3:PutLifecycleConfiguration")
				}
				if cmek {
					p = append(p, "s3:PutEncryptionConfiguration")
				}
				if retentionMin || retentionLocked {
					// Object Lock (WORM) at bucket birth: the create header enables it and
					// the config PUT sets the default retention. One action covers both.
					p = append(p, "s3:PutBucketObjectLockConfiguration")
				}
				if replication {
					// CRR (D3). One action authorises both PutBucketReplication and
					// DeleteBucketReplication — there is no s3:DeleteReplicationConfiguration.
					p = append(p, "s3:PutReplicationConfiguration")
				}
				if corsDeclared {
					// one action authorises BOTH PutBucketCors and DeleteBucketCors, like
					// replication — asked for only when cors.allowedOrigins is declared.
					p = append(p, "s3:PutBucketCORS")
				}
				return sortedDedup(p)
			case "update":
				// DeleteBucketPolicy is the PRIVATE transition: updateS3 PUTs the public
				// policy when plan.Public and DELETEs it otherwise. Unlike replication —
				// where one action authorises both directions, as the comment above says —
				// S3 has a separate delete action, and only the put was declared, so the
				// going-private half of a hardening update was the undeclared one (D848).
				return sortedDedup([]string{"s3:GetBucketTagging",
					"s3:PutBucketVersioning", "s3:PutBucketPublicAccessBlock",
					"s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration",
					"s3:PutEncryptionConfiguration", "s3:PutReplicationConfiguration",
					"s3:PutBucketCORS"})
			case "delete":
				// GetBucketObjectLockConfiguration is the pre-delete guard
				// (refuseIfObjectLockCompliance): a bucket in COMPLIANCE mode must not be
				// walked into, and a read that gives no answer REFUSES the delete as
				// ambiguous — correctly. Undeclared, that refusal is what an operator
				// granted exactly this list got on EVERY bucket delete, with the reason
				// naming an ambiguous object-lock read rather than the missing grant.
				// AWS authorizes the GetObjectLockConfiguration operation with an action
				// spelled differently (D850).
				return sortedDedup([]string{"s3:DeleteBucket", "s3:GetBucketTagging",
					"s3:GetBucketObjectLockConfiguration"})
			}
		case "rds":
			// D86. DescribeDBInstances is the quiet read (409 ownership + the
			// async create/delete poll + the tag-based ownership check).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"rds:CreateDBInstance",
					"rds:DescribeDBInstances", "rds:AddTagsToResource"})
			case "update":
				return []string{"rds:DescribeDBInstances", "rds:ModifyDBInstance"}
			case "delete":
				return []string{"rds:DeleteDBInstance", "rds:DescribeDBInstances"}
			}
		case "aurora":
			// D152. Aurora PostgreSQL Serverless v2 composite: DB cluster + member
			// instance(s). Same RDS API family as the instance driver.
			switch operation {
			case "create", "adopt":
				// D853: createAurora also builds the two DERIVED groups the cluster
				// needs — a DB subnet group and a cluster parameter group — reading
				// each back before it writes. None of the four was declared, and they
				// run BEFORE the cluster exists, so the denial landed on a create that
				// had already made half its scaffolding.
				return sortedDedup([]string{"rds:CreateDBCluster", "rds:CreateDBInstance",
					"rds:DescribeDBClusters", "rds:DescribeDBInstances", "rds:AddTagsToResource",
					"rds:CreateDBSubnetGroup", "rds:DescribeDBSubnetGroups",
					"rds:CreateDBClusterParameterGroup", "rds:ModifyDBClusterParameterGroup"})
			case "update":
				return sortedDedup([]string{"rds:ModifyDBCluster", "rds:ModifyDBInstance",
					"rds:DescribeDBClusters"})
			case "delete":
				// D853: deleteAurora removes the derived groups it created with the
				// cluster. Undeclared, the cluster went and its scaffolding stayed.
				return sortedDedup([]string{"rds:DeleteDBCluster", "rds:DeleteDBInstance",
					"rds:DescribeDBClusters", "rds:DeleteDBSubnetGroup",
					"rds:DeleteDBClusterParameterGroup"})
			}
		case "cloudtrail":
			// Audit trail (capability.audit.trail). Create is a composite (CreateTrail +
			// StartLogging); TagsList at birth needs AddTags. GetTrail + ListTags are the
			// ownership pre-read every mutation makes. delivery.assured toggles logging.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"cloudtrail:CreateTrail", "cloudtrail:StartLogging",
					"cloudtrail:AddTags", "cloudtrail:GetTrail", "cloudtrail:ListTags"})
			case "update":
				return sortedDedup([]string{"cloudtrail:UpdateTrail", "cloudtrail:GetTrail",
					"cloudtrail:ListTags", "cloudtrail:StartLogging", "cloudtrail:StopLogging"})
			case "delete":
				return sortedDedup([]string{"cloudtrail:DeleteTrail", "cloudtrail:GetTrail",
					"cloudtrail:ListTags"})
			}
		case "backupplan":
			// D153. A managed backup plan (capability.backup.plan) — the DR-policy layer
			// over a vault. Composite create: CreateBackupPlan + CreateBackupSelection
			// (a plan with no selection backs up nothing). GetBackupPlan is the quiet read;
			// TagResource stamps ownership at birth. Target vault + role are operands.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"backup:CreateBackupPlan", "backup:CreateBackupSelection",
					"backup:GetBackupPlan", "backup:ListBackupSelections", "backup:TagResource"})
			case "update":
				return sortedDedup([]string{"backup:UpdateBackupPlan", "backup:GetBackupPlan", "backup:ListTags"})
			case "delete":
				return sortedDedup([]string{"backup:DeleteBackupSelection", "backup:DeleteBackupPlan",
					"backup:GetBackupPlan", "backup:ListBackupSelections", "backup:ListTags"})
			}
		case "guardduty":
			// GuardDuty detector (capability.security.threatdetection; singleton per
			// account+region). GetDetector is the ownership pre-read; ListDetectors is the
			// singleton probe; create converges an existing ours-detector via UpdateDetector.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"guardduty:CreateDetector", "guardduty:GetDetector",
					"guardduty:ListDetectors", "guardduty:UpdateDetector", "guardduty:TagResource"})
			case "update":
				return sortedDedup([]string{"guardduty:UpdateDetector", "guardduty:GetDetector"})
			case "delete":
				return sortedDedup([]string{"guardduty:DeleteDetector", "guardduty:GetDetector",
					"guardduty:ListDetectors"})
			}
		case "cwlogs":
			// capability.monitoring.logs: a managed log group + retention guarantee.
			// DescribeLogGroups is the read (observe + ownership pre-read); ListTagsForResource
			// is the quiet ownership tag read; tags at CreateLogGroup need logs:TagResource.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"logs:CreateLogGroup", "logs:PutRetentionPolicy",
					"logs:TagResource", "logs:DescribeLogGroups", "logs:ListTagsForResource",
					"logs:AssociateKmsKey"})
			case "update":
				return sortedDedup([]string{"logs:PutRetentionPolicy", "logs:DescribeLogGroups",
					"logs:ListTagsForResource", "logs:AssociateKmsKey", "logs:DisassociateKmsKey"})
			case "delete":
				return sortedDedup([]string{"logs:DeleteLogGroup", "logs:DescribeLogGroups",
					"logs:ListTagsForResource"})
			}
		case "ecs":
			// D86. Multi-resource: cluster + task def + service; iam:PassRole is
			// needed to pass the task execution role to Fargate.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"ecs:CreateCluster",
					"ecs:RegisterTaskDefinition", "ecs:CreateService",
					"ecs:DescribeServices", "ecs:TagResource", "iam:PassRole"})
			case "update":
				return []string{"ecs:DescribeServices", "ecs:UpdateService"}
			case "delete":
				// D853: the delete reads the CLUSTER's tags to prove ownership before
				// removing it — the pre-read that stands between a delete and someone
				// else's cluster, and nothing declared it.
				return sortedDedup([]string{"ecs:DeleteService",
					"ecs:DeleteCluster", "ecs:DescribeServices", "ecs:DescribeClusters"})
			}
		case "apprunner":
			// Second workload.container backend (App Runner, Cloud Run twin). The
			// two reads are the LRO poll (DescribeService) + the name->ARN resolve
			// (ListServices); ListTagsForResource gates ownership on update/delete;
			// a private ECR image needs iam:PassRole to hand App Runner the access role.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"apprunner:CreateService",
					"apprunner:DescribeService", "apprunner:ListServices",
					"apprunner:TagResource", "iam:PassRole"})
			case "update":
				return sortedDedup([]string{"apprunner:UpdateService",
					"apprunner:DescribeService", "apprunner:ListServices",
					"apprunner:ListTagsForResource"})
			case "delete":
				return sortedDedup([]string{"apprunner:DeleteService",
					"apprunner:DescribeService", "apprunner:ListServices",
					"apprunner:ListTagsForResource"})
			}
		case "lambda":
			// capability.function.serverless. Container-image function: CreateFunction +
			// the GetFunction ownership pre-read/LRO poll (State Active) + iam:PassRole for
			// the execution role. Public exposure adds the Function URL + resource-policy
			// grant (attribute-conditional, like cloudrun) — a private function needs none.
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				// GetFunctionUrlConfig is unconditional now: the create reads it to
				// derive the functionUrl/functionUrlDomain outputs (D226). A public
				// function also creates the URL; the anonymous self-grant
				// (lambda:AddPermission) is added only in the default url_auth=none
				// mode — url_auth=iam leaves the grant to the fronting CloudFront
				// distribution — but url_auth is an impl operand invisible here, so
				// AddPermission is declared for any public function (deterministic,
				// operand-blind; a superset the preflight tolerates).
				p := []string{"iam:PassRole", "lambda:CreateFunction",
					"lambda:GetFunction", "lambda:GetFunctionUrlConfig"}
				if public {
					p = append(p, "lambda:AddPermission", "lambda:CreateFunctionUrlConfig")
				}
				// D852: declared callers are resource-policy statements the create
				// writes and RECONCILES, so it reads the policy first. This is the
				// operand the table can finally see (permAttrs) — which is exactly what
				// keeps a private function WITHOUT invokers free of both, as its own
				// conformance case pins.
				if _, hasInvokers := attrs["impl:invokers"]; hasInvokers {
					p = append(p, "lambda:AddPermission", "lambda:GetPolicy")
				}
				// the reserved-concurrency ceiling is a SECONDARY PutFunctionConcurrency
				// call, made only when the operand is declared — so the permission is
				// asked for only then (the invokers rule: precise, operand-gated, not a
				// blanket superset that would burden every simple function).
				if _, hasConc := attrs["impl:reserved_concurrency"]; hasConc {
					p = append(p, "lambda:PutFunctionConcurrency")
				}
				return sortedDedup(p)
			case "update":
				// updateLambda patches the configuration, then the CODE, then moves the
				// exposure either way: ensureLambdaExposure creates the Function URL and
				// grants anonymous invoke, removeLambdaExposure deletes both. Only the
				// first two were declared (D848). Unlike D846's apigateway case — three
				// verbs of which at most ONE is ever needed, where naming all three would
				// refuse an operator who granted the right one — every action here is
				// required WHEN ITS BRANCH RUNS, and which branch runs depends on the
				// change-set this operand-blind table cannot see. A superset of
				// required-when-applicable actions refuses early; the alternative fails
				// after the lease.
				return sortedDedup([]string{"lambda:GetFunction",
					"lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode",
					"lambda:CreateFunctionUrlConfig", "lambda:AddPermission",
					"lambda:DeleteFunctionUrlConfig", "lambda:RemovePermission",
					"lambda:PutFunctionConcurrency"})
			case "delete":
				return sortedDedup([]string{"lambda:DeleteFunction", "lambda:GetFunction"})
			}
		case "eks":
			// D147. Cluster substrate composite: cluster + managed node group. The
			// two DescribeX are the LRO polls; iam:PassRole passes the control-plane
			// and node roles (operands from the impl block). In-place update
			// (version/endpoint) is slice 3 but its permissions are declared.
			switch operation {
			case "create", "adopt":
				// D1013: ensureEKSNodeGroup LISTS the cluster's real node groups (D258
				// self-adopt) before creating one — a cluster that already carries node
				// groups binds them instead. Declared on update (D848) but MISSING here,
				// so an operator with CreateNodegroup but not ListNodegroups passed the
				// preflight, the list 403'd, the scan fell open, and CreateNodegroup made
				// a DUPLICATE managed node group (doubled compute) — reported succeeded.
				// Declaring it makes the preflight refuse first (D75), like the update arm.
				return sortedDedup([]string{"eks:CreateCluster", "eks:DescribeCluster",
					"eks:CreateNodegroup", "eks:DescribeNodegroup", "eks:ListNodegroups",
					"eks:TagResource", "iam:PassRole"})
			case "update":
				// The node-group roll is part of an update, not a separate action
				// (D248): once the control plane is bumped, updateEKS lists the managed
				// node groups, reads each one's version and rolls the stale ones. Those
				// three were undeclared, so an operator granted the four below, passed
				// the preflight, and lost the grant AFTER the control-plane upgrade —
				// which cannot be undone — leaving the skew the driver's own comment
				// calls "a half-upgraded cluster" (D848).
				return sortedDedup([]string{"eks:UpdateClusterConfig",
					"eks:UpdateClusterVersion", "eks:DescribeCluster", "eks:DescribeUpdate",
					"eks:ListNodegroups", "eks:DescribeNodegroup", "eks:UpdateNodegroupVersion"})
			case "delete":
				return sortedDedup([]string{"eks:DeleteCluster", "eks:DeleteNodegroup",
					"eks:DescribeCluster", "eks:DescribeNodegroup"})
			}
		case "eks-addon":
			// D149. A managed EKS addon (vpc-cni/coredns/ebs-csi/pod-identity-agent).
			// iam:PassRole for addons that assume a role (e.g. ebs-csi); DescribeAddon
			// is the ownership pre-read + LRO poll.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"eks:CreateAddon", "eks:DescribeAddon",
					"eks:TagResource", "iam:PassRole"})
			case "update":
				return sortedDedup([]string{"eks:UpdateAddon", "eks:DescribeAddon"})
			case "delete":
				return sortedDedup([]string{"eks:DeleteAddon", "eks:DescribeAddon"})
			}
		case "eks-podidentity":
			// D149. A Pod Identity Association (serviceAccount -> IAM role). List
			// resolves the server-assigned associationId; iam:PassRole passes the role.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"eks:CreatePodIdentityAssociation",
					"eks:ListPodIdentityAssociations", "eks:TagResource", "iam:PassRole"})
			case "update":
				return sortedDedup([]string{"eks:UpdatePodIdentityAssociation",
					"eks:ListPodIdentityAssociations", "eks:DescribePodIdentityAssociation"})
			case "delete":
				return sortedDedup([]string{"eks:DeletePodIdentityAssociation",
					"eks:ListPodIdentityAssociations"})
			}
		case "ses-sending":
			// D148. Outbound-email composite: domain identity (Easy DKIM) +
			// configuration set + event destination (bounce/complaint -> SNS).
			// GetEmailIdentity is the ownership pre-read every mutation makes.
			switch operation {
			// PutEmailIdentityConfigurationSetAttributes makes the set the identity's
			// DEFAULT, which is what attachSESConfigSet does on BOTH paths (D746) — and
			// it was declared on neither, so the step that decides where bounces go was
			// the one nothing asked permission for (D848).
			case "create", "adopt":
				return sortedDedup([]string{"ses:CreateEmailIdentity", "ses:GetEmailIdentity",
					"ses:PutEmailIdentityDkimAttributes", "ses:CreateConfigurationSet",
					"ses:CreateConfigurationSetEventDestination",
					"ses:PutEmailIdentityConfigurationSetAttributes",
					"ses:GetConfigurationSetEventDestinations", "ses:TagResource"})
			case "update":
				return sortedDedup([]string{"ses:GetEmailIdentity",
					"ses:PutEmailIdentityDkimAttributes", "ses:GetConfigurationSetEventDestinations",
					"ses:PutEmailIdentityConfigurationSetAttributes",
					"ses:CreateConfigurationSetEventDestination", "ses:DeleteConfigurationSetEventDestination"})
			case "delete":
				return sortedDedup([]string{"ses:DeleteEmailIdentity",
					"ses:DeleteConfigurationSet", "ses:GetEmailIdentity"})
			}
		case "ses-inbound":
			// Inbound-email composite (deal mailbox): receipt rule set + receipt rule
			// (S3 delivery + spam/virus scan) + active rule set. Receipt rules carry no
			// tags — ownership is the deterministic name; DescribeReceiptRule is the pre-read.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"ses:CreateReceiptRuleSet", "ses:CreateReceiptRule",
					"ses:SetActiveReceiptRuleSet", "ses:DescribeReceiptRule", "ses:DescribeActiveReceiptRuleSet"})
			case "update":
				return sortedDedup([]string{"ses:DescribeReceiptRule", "ses:UpdateReceiptRule",
					"ses:SetActiveReceiptRuleSet", "ses:DescribeActiveReceiptRuleSet"})
			case "delete":
				return sortedDedup([]string{"ses:DescribeReceiptRule", "ses:DeleteReceiptRule",
					"ses:DescribeReceiptRuleSet", "ses:DescribeActiveReceiptRuleSet", "ses:DeleteReceiptRuleSet"})
			}
		case "budgets":
			// D151. AWS Budgets uses two coarse IAM actions (no per-call granularity):
			// ModifyBudget for create/update/delete, ViewBudget for reads.
			switch operation {
			case "create", "adopt", "update", "delete":
				return []string{"budgets:ModifyBudget", "budgets:ViewBudget"}
			}
		case "bedrock":
			// D150. Application inference profiles. A profile's routing is immutable,
			// so "update" is a re-read only (no UpdateInferenceProfile API exists) —
			// declared for the certify battery; the driver classifies changes unsupported.
			switch operation {
			case "create", "adopt":
				// ListInferenceProfiles is the create-ADOPTION branch (D252): when the
				// name already exists, createBedrock lists the profiles to find the one
				// carrying our name and tags and BINDS it. Undeclared, that list is
				// denied and the branch falls through to unknown — "not resolvably
				// ours" — which blames foreign ownership for a missing grant and sends
				// the operator looking for somebody else's resource (D849).
				return sortedDedup([]string{"bedrock:CreateInferenceProfile",
					"bedrock:GetInferenceProfile", "bedrock:ListInferenceProfiles",
					"bedrock:TagResource"})
			case "update":
				return []string{"bedrock:GetInferenceProfile"}
			case "delete":
				return sortedDedup([]string{"bedrock:DeleteInferenceProfile",
					"bedrock:GetInferenceProfile"})
			}
		case "sns":
			// D94. Topic ops (capability.messaging.topic). Ownership tags are set
			// at CreateTopic birth; ListTagsForResource is the ownership pre-read
			// (post-create re-check + delete). Encryption (a KMS key, incl. the
			// provider-default alias/aws/sns) or public exposure (a resource
			// policy) each add sns:SetTopicAttributes — attribute-conditional.
			public, _ := attrs["network.publicExposure"].(bool)
			atRest, _ := attrs["encryption.atRest"].(bool)
			cmek, _ := attrs["encryption.customerManagedKeys"].(bool)
			setAttrs := public || atRest || cmek
			switch operation {
			case "create", "adopt":
				p := []string{"sns:CreateTopic", "sns:ListTagsForResource", "sns:TagResource"}
				if setAttrs {
					p = append(p, "sns:SetTopicAttributes")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"sns:GetTopicAttributes", "sns:SetTopicAttributes"})
			case "delete":
				return []string{"sns:DeleteTopic", "sns:ListTagsForResource"}
			}
		case "sqs":
			// D95. Queue ops (capability.messaging.queue). Every attribute
			// (retention, encryption, dedup, the public policy) is set at
			// CreateQueue time, so create is unconditional: CreateQueue + the
			// ownership tag write + the ListQueueTags re-read. TagQueue rides with
			// the inline tags. Delete is the ownership pre-read + DeleteQueue.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"sqs:CreateQueue", "sqs:ListQueueTags", "sqs:TagQueue"})
			case "update":
				return sortedDedup([]string{"sqs:GetQueueAttributes", "sqs:SetQueueAttributes"})
			case "delete":
				return sortedDedup([]string{"sqs:DeleteQueue", "sqs:ListQueueTags"})
			}
		case "secretsmanager":
			// D97. A managed secret handle (capability.secret). DescribeSecret is
			// the quiet read (ownership re-check + delete pre-read). Public
			// exposure adds the resource-policy grant; CMEK is set inline on
			// CreateSecret (no extra permission).
			public, _ := attrs["network.publicExposure"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"secretsmanager:CreateSecret",
					"secretsmanager:DescribeSecret", "secretsmanager:TagResource"}
				if public {
					p = append(p, "secretsmanager:PutResourcePolicy")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"secretsmanager:DescribeSecret",
					"secretsmanager:UpdateSecret", "secretsmanager:PutResourcePolicy",
					"secretsmanager:DeleteResourcePolicy"})
			case "delete":
				return sortedDedup([]string{"secretsmanager:DeleteSecret",
					"secretsmanager:DescribeSecret"})
			}
		case "elasticache":
			// D100. Managed Redis (capability.cache.keyvalue) as a replication group.
			// DescribeReplicationGroups is the quiet read (poll + delete pre-read);
			// ListTagsForResource is the ownership read (tags live off the ARN).
			switch operation {
			case "create", "adopt":
				// D853: the cache subnet group is derived scaffolding the create builds
				// and reads back first, exactly as Aurora's is.
				return sortedDedup([]string{"elasticache:CreateReplicationGroup",
					"elasticache:DescribeReplicationGroups", "elasticache:AddTagsToResource",
					"elasticache:ListTagsForResource", "elasticache:CreateCacheSubnetGroup",
					"elasticache:DescribeCacheSubnetGroups"})
			case "update":
				return sortedDedup([]string{"elasticache:DescribeReplicationGroups",
					"elasticache:ModifyReplicationGroup"})
			case "delete":
				// D853: the delete removes the derived cache subnet group too.
				return sortedDedup([]string{"elasticache:DeleteReplicationGroup",
					"elasticache:DescribeReplicationGroups", "elasticache:ListTagsForResource",
					"elasticache:DeleteCacheSubnetGroup"})
			}
		case "elasticache-serverless":
			// Second cache.keyvalue backend (ElastiCache Serverless, pay-per-use).
			// DescribeServerlessCaches is the async poll + delete pre-read + the
			// ARN resolve for ownership; ListTagsForResource is the ownership read
			// (tags live off the ARN). No node/shard sizing — capacity auto-scales.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"elasticache:CreateServerlessCache",
					"elasticache:DescribeServerlessCaches", "elasticache:AddTagsToResource",
					"elasticache:ListTagsForResource"})
			case "update":
				// no in-place update is wired in this slice (ClassifyChange returns
				// immutable/unsupported, so this is never reached); the set is declared
				// so the D75 preflight has a non-empty union to check, matching provisioned.
				return sortedDedup([]string{"elasticache:DescribeServerlessCaches",
					"elasticache:ModifyServerlessCache"})
			case "delete":
				return sortedDedup([]string{"elasticache:DeleteServerlessCache",
					"elasticache:DescribeServerlessCaches", "elasticache:ListTagsForResource"})
			}
		case "vpc":
			// D86. Multi-resource: vpc + subnet + optional flow logs. B4 slice 1:
			// egress.internet=nat adds the NAT composite (IGW + EIP + NAT GW + route
			// tables); the teardown perms are always required (a no-op with no road).
			flow, _ := attrs["flowLogs.enabled"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{"ec2:CreateVpc", "ec2:CreateSubnet",
					"ec2:CreateTags", "ec2:DescribeVpcs"}
				if flow {
					// D727: the create READS the delivery role's trust policy before
					// handing it work, so it can refuse instead of building a flow log
					// that reports ACTIVE and delivers nothing.
					p = append(p, "ec2:CreateFlowLogs", "iam:PassRole", "iam:GetRole")
				}
				if road, _ := attrs["egress.internet"].(string); road == "nat" {
					p = append(p, "ec2:CreateInternetGateway", "ec2:AttachInternetGateway",
						"ec2:AllocateAddress", "ec2:CreateNatGateway", "ec2:DescribeNatGateways",
						"ec2:CreateRouteTable", "ec2:CreateRoute", "ec2:AssociateRouteTable")
				}
				if sap, _ := attrs["serviceAccess.private"].(bool); sap {
					// VPC slice 2: private AWS-service access via VPC endpoints.
					p = append(p, "ec2:CreateVpcEndpoint", "ec2:DescribeVpcEndpoints", "ec2:DescribeRouteTables")
				}
				if _, ok := attrs["ingress.public"]; ok {
					// VPC slice 3: author a baseline security group (ingress.public is the
					// contract-visible trigger). impl.baseline_sg-only override is a
					// documented skip-loudly preflight gap.
					p = append(p, "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress")
				}
				return sortedDedup(p)
			case "update":
				return []string{"ec2:DescribeVpcs", "ec2:ModifyVpcAttribute"}
			case "delete":
				return sortedDedup([]string{"ec2:DeleteVpc", "ec2:DeleteSubnet",
					"ec2:DescribeVpcs", "ec2:DescribeSubnets",
					"ec2:DescribeFlowLogs", "ec2:DeleteFlowLogs",
					// NAT teardown (no-op when there is no road):
					"ec2:DescribeRouteTables", "ec2:DisassociateRouteTable", "ec2:DeleteRouteTable",
					"ec2:DescribeNatGateways", "ec2:DeleteNatGateway",
					"ec2:DescribeAddresses", "ec2:ReleaseAddress",
					"ec2:DescribeInternetGateways", "ec2:DetachInternetGateway", "ec2:DeleteInternetGateway",
					// VPC endpoint teardown (no-op when none):
					"ec2:DescribeVpcEndpoints", "ec2:DeleteVpcEndpoints",
					// baseline SG teardown (no-op when we own none):
					"ec2:DescribeSecurityGroups", "ec2:DeleteSecurityGroup"})
			}
		case "route53":
			// D101. A managed DNS zone (capability.dns.zone). The hosted-zone id is
			// server-assigned; ListHostedZonesByName recovers it after a lost create
			// (deterministic CallerReference). Ownership is tags. Records are data.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"route53:CreateHostedZone",
					"route53:ChangeTagsForResource", "route53:ListTagsForResource",
					"route53:ListHostedZonesByName", "route53:GetHostedZone"})
			case "update":
				return sortedDedup([]string{"route53:GetHostedZone", "route53:ListTagsForResource"})
			case "delete":
				return sortedDedup([]string{"route53:DeleteHostedZone",
					"route53:GetHostedZone", "route53:ListTagsForResource"})
			}
		case "route53record":
			// D262. A single DNS record set (capability.dns.record) inside a hosted
			// zone. A record carries no tags, so ownership is the PARENT ZONE's tags
			// (ListTagsForResource + GetHostedZone gate every mutation); the write is
			// an UPSERT (create/replace), the read a ListResourceRecordSets.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"route53:ChangeResourceRecordSets",
					"route53:ListResourceRecordSets", "route53:GetHostedZone",
					"route53:ListTagsForResource"})
			case "delete":
				return sortedDedup([]string{"route53:ChangeResourceRecordSets",
					"route53:ListResourceRecordSets", "route53:GetHostedZone",
					"route53:ListTagsForResource"})
			}
		case "rolepolicy":
			// D104. A named-role grant (capability.authorization.grant) = a managed
			// policy attached to a role. Global; content-addressed by (role, policy).
			// ListAttachedRolePolicies is the quiet read (observe + attach idempotency).
			// No role/policy is authored — so no iam:CreatePolicy / iam:CreateRole.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"iam:AttachRolePolicy", "iam:ListAttachedRolePolicies"})
			case "delete":
				return sortedDedup([]string{"iam:DetachRolePolicy", "iam:ListAttachedRolePolicies"})
			}
		case "custompolicy":
			// D105. A custom role (capability.authorization.role) = a customer-managed
			// policy. Global; the account is resolved via STS for the Arn.
			// GetPolicy/GetPolicyVersion read the action set back on observe.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"sts:GetCallerIdentity",
					"iam:CreatePolicy", "iam:GetPolicy", "iam:GetPolicyVersion"})
			case "update":
				return sortedDedup([]string{"iam:GetPolicy", "iam:GetPolicyVersion",
					"iam:CreatePolicyVersion"})
			case "delete":
				return sortedDedup([]string{"iam:DeletePolicy"})
			}
		case "cloudwatch":
			// D106. A metric alert (capability.monitoring.alert) = a CloudWatch alarm.
			// PutMetricAlarm is an upsert; DescribeAlarms + ListTagsForResource are the
			// ownership pre-read (create-overwrite guard + delete). The account is
			// resolved via STS for the alarm ARN.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"sts:GetCallerIdentity",
					"cloudwatch:PutMetricAlarm", "cloudwatch:DescribeAlarms",
					"cloudwatch:ListTagsForResource", "cloudwatch:TagResource"})
			case "update":
				return sortedDedup([]string{"cloudwatch:PutMetricAlarm", "cloudwatch:DescribeAlarms"})
			case "delete":
				return sortedDedup([]string{"cloudwatch:DeleteAlarms",
					"cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource"})
			}
		case "cloudwatchdash":
			// D107. A metric dashboard (capability.monitoring.dashboard) = a global
			// CloudWatch dashboard. PutDashboard is an upsert; GetDashboard is the read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"cloudwatch:PutDashboard", "cloudwatch:GetDashboard"})
			case "delete":
				return sortedDedup([]string{"cloudwatch:DeleteDashboards", "cloudwatch:GetDashboard"})
			}
		case "route53health":
			// D108. A synthetic uptime check (capability.monitoring.uptime) = a Route 53
			// health check. Global; the Id is server-assigned. GetHealthCheck +
			// ListTagsForResource are the reads (observe + delete ownership).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"route53:CreateHealthCheck",
					"route53:ChangeTagsForResource", "route53:ListTagsForResource", "route53:GetHealthCheck"})
			case "update":
				return sortedDedup([]string{"route53:GetHealthCheck", "route53:ListTagsForResource"})
			case "delete":
				return sortedDedup([]string{"route53:DeleteHealthCheck",
					"route53:GetHealthCheck", "route53:ListTagsForResource"})
			}
		case "cwlogfilter":
			// D109. A log-based metric (capability.monitoring.logmetric) = a CloudWatch
			// Logs metric filter. PutMetricFilter is an upsert; DescribeMetricFilters is
			// the read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"logs:PutMetricFilter", "logs:DescribeMetricFilters"})
			case "delete":
				return sortedDedup([]string{"logs:DeleteMetricFilter", "logs:DescribeMetricFilters"})
			}
		case "ecr":
			// D110. A container image registry (capability.registry.image) = an ECR
			// repository. DescribeRepositories + ListTagsForResource are the reads
			// (observe + ownership pre-read on delete/conflict).
			switch operation {
			case "create", "adopt":
				perms := []string{"ecr:CreateRepository", "ecr:DescribeRepositories",
					"ecr:ListTagsForResource", "ecr:TagResource"}
				if _, ok := attrs["retention.maximum"]; ok {
					// D1029: applies the age-out lifecycle rule and reads it back on observe.
					perms = append(perms, "ecr:PutLifecyclePolicy", "ecr:GetLifecyclePolicy")
				}
				return sortedDedup(perms)
			case "update":
				// D4: scan-on-push (PutImageScanningConfiguration) + tag mutability, each
				// re-checking ownership tags via DescribeRepositories/ListTagsForResource.
				perms := []string{"ecr:DescribeRepositories", "ecr:ListTagsForResource",
					"ecr:PutImageTagMutability", "ecr:PutImageScanningConfiguration"}
				if _, ok := attrs["retention.maximum"]; ok {
					// D1029: re-assert or clear the age-out rule; converge observes it.
					perms = append(perms, "ecr:PutLifecyclePolicy",
						"ecr:DeleteLifecyclePolicy", "ecr:GetLifecyclePolicy")
				}
				return sortedDedup(perms)
			case "delete":
				return sortedDedup([]string{"ecr:DeleteRepository",
					"ecr:DescribeRepositories", "ecr:ListTagsForResource"})
			}
		case "ec2":
			// D358. A virtual machine (capability.compute.instance). The instance id is
			// server-assigned; DescribeInstances recovers it after a lost create (the
			// ClientToken is deterministic). Ownership is tags. DescribeVolumes is the
			// disk-encryption read — an observe that cannot make it reports the fact
			// as unread rather than defaulting it.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"ec2:RunInstances", "ec2:DescribeInstances",
					"ec2:DescribeVolumes", "ec2:CreateTags"})
			case "update":
				// Every governed attribute is immutable on a machine (D358), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"ec2:DescribeInstances", "ec2:DescribeVolumes"})
			case "delete":
				return sortedDedup([]string{"ec2:TerminateInstances", "ec2:DescribeInstances"})
			}
		case "ami":
			// D370. A machine image (capability.compute.image), WITNESSED not authored
			// (D177) — so there is no create/delete permission set, only the reads.
			// DescribeSnapshots is a second permission for a second resource: the
			// encryption pair lives on the backing snapshot, not on the image, and an
			// observe that cannot make that call reports the facts unread rather than
			// defaulting them.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"ec2:DescribeImages", "ec2:DescribeSnapshots"})
			}
		case "asg":
			// D371. A fleet (capability.compute.autoscaling). CreateAutoScalingGroup
			// takes no client token, so the deterministic NAME is the mechanism and
			// DescribeAutoScalingGroups is the quiet read (name-conflict continuation +
			// delete pre-read). Ownership is tags.
			//
			// The two EC2 reads are the PREFLIGHTS, not extras: the group's zone spread
			// follows its subnets and its addressing follows its launch template, so
			// neither `availability.class` nor `network.publicExposure` can be honored
			// without resolving a resource the group does not own. An identity that
			// cannot make those reads cannot create a group whose contract is true.
			switch operation {
			case "create", "adopt":
				p := []string{"autoscaling:CreateAutoScalingGroup",
					"autoscaling:DescribeAutoScalingGroups", "autoscaling:CreateOrUpdateTags",
					"ec2:DescribeSubnets", "ec2:DescribeLaunchTemplateVersions"}
				if on, _ := attrs["autoscaling.enabled"].(bool); on {
					p = append(p, "autoscaling:PutScalingPolicy")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"autoscaling:DescribeAutoScalingGroups",
					"autoscaling:DescribePolicies", "autoscaling:UpdateAutoScalingGroup",
					"autoscaling:PutScalingPolicy", "ec2:DescribeLaunchTemplateVersions"})
			case "delete":
				return sortedDedup([]string{"autoscaling:DeleteAutoScalingGroup",
					"autoscaling:DescribeAutoScalingGroups"})
			}
		case "ebs":
			// D367. A block volume (capability.storage.block). The volume id is
			// server-assigned; DescribeVolumes recovers it after a lost create (the
			// ClientToken is deterministic). Ownership is tags — and on a STATEFUL
			// capability that read is what stands between a mis-pinned providerId and
			// destroying someone else's data, so it is required on the delete path.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"ec2:CreateVolume", "ec2:DescribeVolumes",
					"ec2:CreateTags"})
			case "update":
				// Every governed attribute is immutable on a volume (D367), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"ec2:DescribeVolumes"})
			case "delete":
				return sortedDedup([]string{"ec2:DeleteVolume", "ec2:DescribeVolumes"})
			}
		case "efs":
			// D111. A managed NFS file share (capability.storage.filesystem). The
			// file-system id is server-assigned; DescribeFileSystems recovers it after
			// a lost create (deterministic CreationToken). Ownership is tags.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"elasticfilesystem:CreateFileSystem",
					"elasticfilesystem:DescribeFileSystems", "elasticfilesystem:TagResource",
					"elasticfilesystem:ListTagsForResource"})
			case "update":
				return sortedDedup([]string{"elasticfilesystem:DescribeFileSystems",
					"elasticfilesystem:ListTagsForResource", "elasticfilesystem:UpdateFileSystem"})
			case "delete":
				return sortedDedup([]string{"elasticfilesystem:DeleteFileSystem",
					"elasticfilesystem:DescribeFileSystems", "elasticfilesystem:ListTagsForResource"})
			}
		case "dynamodb":
			// D112. A managed NoSQL table (capability.database.nosql). PITR is a
			// separate UpdateContinuousBackups call; DescribeTable is the quiet read
			// (409-continue ownership + delete pre-read). Ownership is tags.
			_, pitr := attrs["backup.pointInTimeRecovery"]
			switch operation {
			case "create", "adopt":
				p := []string{"dynamodb:CreateTable", "dynamodb:DescribeTable",
					"dynamodb:ListTagsOfResource", "dynamodb:TagResource"}
				if pitr {
					p = append(p, "dynamodb:UpdateContinuousBackups", "dynamodb:DescribeContinuousBackups")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"dynamodb:DescribeTable", "dynamodb:UpdateTable",
					"dynamodb:UpdateContinuousBackups"})
			case "delete":
				return sortedDedup([]string{"dynamodb:DeleteTable", "dynamodb:DescribeTable",
					"dynamodb:ListTagsOfResource"})
			}
		case "opensearch":
			// D113. A managed search cluster (capability.search.index). DescribeDomain
			// is the quiet read (creation poll + ownership pre-read on delete);
			// ListTags is the ownership tag read. A private domain also needs the EC2
			// permissions to place ENIs in the VPC (attribute-conditional).
			private := false
			if p, ok := attrs["network.publicExposure"].(bool); ok && !p {
				private = true
			}
			switch operation {
			case "create", "adopt":
				perms := []string{"es:CreateDomain", "es:DescribeDomain", "es:ListTags", "es:AddTags"}
				if private {
					perms = append(perms, "ec2:CreateNetworkInterface", "ec2:DescribeVpcs", "ec2:DescribeSubnets")
				}
				return sortedDedup(perms)
			case "update":
				return sortedDedup([]string{"es:DescribeDomain", "es:UpdateDomainConfig", "es:ListTags"})
			case "delete":
				return sortedDedup([]string{"es:DeleteDomain", "es:DescribeDomain", "es:ListTags"})
			}
		case "opensearch-serverless":
			// Second search.index backend (OpenSearch Serverless, pay-per-use). A
			// COMPOSITE: a collection requires an encryption + a network security
			// policy (CreateSecurityPolicy), then CreateCollection; BatchGetCollection
			// is the async poll + the ARN/id resolve; ListTagsForResource + TagResource
			// are ownership; GetSecurityPolicy reads the network policy for exposure.
			// The delete tears the owned policies down in reverse (DeleteSecurityPolicy).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"aoss:CreateCollection", "aoss:BatchGetCollection",
					"aoss:CreateSecurityPolicy", "aoss:GetSecurityPolicy",
					"aoss:TagResource", "aoss:ListTagsForResource"})
			case "update":
				// no in-place update is wired in this slice (ClassifyChange returns
				// immutable/unsupported, so this is never reached); the set is declared
				// so the D75 preflight has a non-empty union to check.
				return sortedDedup([]string{"aoss:BatchGetCollection", "aoss:UpdateCollection"})
			case "delete":
				return sortedDedup([]string{"aoss:DeleteCollection", "aoss:BatchGetCollection",
					"aoss:ListTagsForResource", "aoss:DeleteSecurityPolicy"})
			}
		case "kinesis":
			// D114. A managed record stream (capability.streaming.pipe).
			// DescribeStreamSummary is the quiet read (creation poll + ownership
			// pre-read on delete); retention/CMK are separate post-create calls
			// (attribute-conditional). Ownership is tags.
			_, retention := attrs["retention.window"]
			cmek, _ := attrs["encryption.customerManagedKeys"].(bool)
			switch operation {
			case "create", "adopt":
				perms := []string{"kinesis:CreateStream", "kinesis:DescribeStreamSummary",
					"kinesis:AddTagsToStream", "kinesis:ListTagsForStream"}
				if retention {
					perms = append(perms, "kinesis:IncreaseStreamRetentionPeriod")
				}
				if cmek {
					perms = append(perms, "kinesis:StartStreamEncryption")
				}
				return sortedDedup(perms)
			case "update":
				return sortedDedup([]string{"kinesis:DescribeStreamSummary",
					"kinesis:IncreaseStreamRetentionPeriod", "kinesis:StartStreamEncryption"})
			case "delete":
				return sortedDedup([]string{"kinesis:DeleteStream",
					"kinesis:DescribeStreamSummary", "kinesis:ListTagsForStream"})
			}
		case "msk":
			// D115. A managed Kafka cluster (capability.messaging.kafka). ListClustersV2
			// resolves the server-assigned ARN by our deterministic name and is the
			// quiet read (creation poll + ownership pre-read on delete). The cluster
			// lives in a VPC, so create also needs the EC2 describe/ENI permissions.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"kafka:CreateClusterV2", "kafka:ListClustersV2",
					"kafka:DescribeClusterV2", "kafka:TagResource",
					"ec2:CreateNetworkInterface", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"})
			case "update":
				return sortedDedup([]string{"kafka:ListClustersV2", "kafka:DescribeClusterV2",
					"kafka:UpdateClusterConfiguration"})
			case "delete":
				return sortedDedup([]string{"kafka:DeleteCluster", "kafka:ListClustersV2",
					"kafka:DescribeClusterV2"})
			}
		case "waf":
			// D116. A managed WAF policy (capability.security.waf) — a CLOUDFRONT-scope
			// WebACL. ListWebACLs resolves the server-assigned Id/LockToken by our
			// deterministic name and is the quiet read (ownership pre-read on delete);
			// GetWebACL is the observe read; ListTagsForResource is the ownership read.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"wafv2:CreateWebACL", "wafv2:ListWebACLs",
					"wafv2:GetWebACL", "wafv2:ListTagsForResource", "wafv2:TagResource"})
			case "update":
				return sortedDedup([]string{"wafv2:ListWebACLs", "wafv2:GetWebACL",
					"wafv2:UpdateWebACL"})
			case "delete":
				return sortedDedup([]string{"wafv2:DeleteWebACL", "wafv2:ListWebACLs",
					"wafv2:ListTagsForResource"})
			}
		case "acm":
			// D117. A managed TLS certificate (capability.certificate.tls). The
			// CertificateArn is server-assigned; ListCertificates recovers it after a
			// lost create (deterministic IdempotencyToken). DescribeCertificate is the
			// quiet read (ownership pre-read on delete); ownership is tags.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"acm:RequestCertificate", "acm:DescribeCertificate",
					"acm:ListCertificates", "acm:ListTagsForCertificate", "acm:AddTagsToCertificate"})
			case "update":
				return sortedDedup([]string{"acm:DescribeCertificate", "acm:ListTagsForCertificate"})
			case "delete":
				return sortedDedup([]string{"acm:DeleteCertificate", "acm:DescribeCertificate",
					"acm:ListTagsForCertificate"})
			}
		case "cloudfront":
			// D118. A managed CDN distribution (capability.cdn.distribution). The
			// distribution Id is server-assigned; GetDistribution is the quiet read
			// (observe + delete pre-read + ETag), ListTagsForResource the ownership
			// read. Delete needs UpdateDistribution too (the disable-before-delete
			// step the driver surfaces rather than forcing).
			// CreateOriginAccessControl (the origin_access: oac operand) and
			// lambda:AddPermission (the grant_invoke_lambda operand — the
			// distribution grants itself invoke on its origin Function URL) are
			// declared unconditionally: both are impl operands invisible to this
			// operand-blind table, so the create declares the superset the preflight
			// tolerates. Delete removes the OAC we own, so it needs the OAC verbs too.
			switch operation {
			case "create", "adopt":
				// The call is CreateDistributionWithTags (POST /distribution?WithTags), but
				// AWS publishes no IAM action of that name — the authorization is
				// `cloudfront:CreateDistribution` plus `cloudfront:TagResource`, both below.
				// The neighbouring `CreateStreamingDistributionWithTags` IS an action, which
				// is why the wrong name read as right (D846).
				return sortedDedup([]string{"cloudfront:CreateDistribution",
					"cloudfront:GetDistribution", "cloudfront:ListTagsForResource", "cloudfront:TagResource",
					"cloudfront:CreateOriginAccessControl", "lambda:AddPermission"})
			case "update":
				return sortedDedup([]string{"cloudfront:GetDistribution", "cloudfront:UpdateDistribution"})
			case "delete":
				return sortedDedup([]string{"cloudfront:DeleteDistribution", "cloudfront:GetDistribution",
					"cloudfront:UpdateDistribution", "cloudfront:ListTagsForResource",
					"cloudfront:GetOriginAccessControl", "cloudfront:DeleteOriginAccessControl"})
			}
		case "apigateway":
			// D119. A managed HTTP API gateway (capability.apigateway.http). The ApiId
			// is server-assigned; GetApi is the quiet read (observe + ownership
			// pre-read on delete, tags returned inline). apigatewayv2 permissions are
			// coarse-grained (apigateway:* on the /apis path).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"apigateway:POST", "apigateway:GET"})
			case "update":
				return sortedDedup([]string{"apigateway:GET", "apigateway:PATCH"})
			case "delete":
				return sortedDedup([]string{"apigateway:DELETE", "apigateway:GET"})
			}
		case "iam":
			// D121. A managed machine identity (capability.identity.serviceaccount) —
			// an IAM role a workload assumes; keyless (no downloadable key, D53). IAM
			// is GLOBAL. Ownership is tags. The trust/permission policies are opaque
			// authorization config, out of this identity capability's scope.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"iam:CreateRole", "iam:GetRole", "iam:TagRole"})
			case "update":
				return sortedDedup([]string{"iam:GetRole"})
			case "delete":
				return sortedDedup([]string{"iam:DeleteRole", "iam:GetRole"})
			}
		case "redshiftserverless":
			// D122. A managed data warehouse (capability.warehouse.analytics) — a
			// Redshift Serverless namespace (data) + workgroup (compute) composite.
			// GetWorkgroup/GetNamespace/ListTagsForResource are the quiet reads
			// (async poll + ownership pre-read on delete). Node sizing and schemas
			// are opaque impl. No admin-credential permission (D53 — IAM auth only).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"redshift-serverless:CreateNamespace", "redshift-serverless:CreateWorkgroup",
					"redshift-serverless:GetNamespace", "redshift-serverless:GetWorkgroup",
					"redshift-serverless:TagResource", "redshift-serverless:ListTagsForResource"})
			case "update":
				return sortedDedup([]string{
					"redshift-serverless:GetWorkgroup", "redshift-serverless:ListTagsForResource"})
			case "delete":
				return sortedDedup([]string{
					"redshift-serverless:DeleteWorkgroup", "redshift-serverless:DeleteNamespace",
					"redshift-serverless:GetWorkgroup", "redshift-serverless:ListTagsForResource"})
			}
		case "eventbridgescheduler":
			// D123. A managed cron trigger (capability.scheduler.cron). Effectively
			// synchronous; GetSchedule is the quiet read (409-continue ownership +
			// delete pre-read). The target/cron are opaque impl; the invoker RoleArn
			// is passed through, so iam:PassRole on it is required to create.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"scheduler:CreateSchedule", "scheduler:GetSchedule", "iam:PassRole"})
			case "update":
				return sortedDedup([]string{"scheduler:GetSchedule", "scheduler:UpdateSchedule", "iam:PassRole"})
			case "delete":
				return sortedDedup([]string{"scheduler:DeleteSchedule", "scheduler:GetSchedule"})
			}
		case "kms":
			// D102. A managed encryption key (capability.key.encryption). CreateKey
			// carries tags inline; EnableKeyRotation is attribute-conditional.
			// A KMS key cannot be hard-deleted, so delete is ScheduleKeyDeletion.
			// ListResourceTags/DescribeKey are the quiet reads (ownership + observe).
			_, rotating := attrs["rotation.period"]
			switch operation {
			case "create", "adopt":
				// D853: the create looks for an EXISTING key carrying our tags before
				// making a second one (ListKeys). Undeclared, that search fails and the
				// create's own adoption path cannot run.
				// D1013: findKMSKeyByTags READS each listed key's tags (ListResourceTags)
				// to verify ownership — ListKeys alone only names them. Declared on delete
				// but MISSING here, so an operator with CreateKey but not ListResourceTags
				// passed the preflight, the tag read 403'd, the scan fell open (readable=
				// false), and CreateKey minted a DUPLICATE CMK on a lost-ledger redeploy —
				// reported succeeded. Declaring it makes the preflight refuse first (D75).
				p := []string{"kms:CreateKey", "kms:TagResource", "kms:ListKeys",
					"kms:ListResourceTags", "kms:DescribeKey", "kms:GetKeyRotationStatus"}
				if rotating {
					p = append(p, "kms:EnableKeyRotation")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"kms:DescribeKey", "kms:EnableKeyRotation",
					"kms:DisableKeyRotation"})
			case "delete":
				return sortedDedup([]string{"kms:ScheduleKeyDeletion",
					"kms:DescribeKey", "kms:ListResourceTags"})
			}
		case "vpngateway":
			// D126. A managed VPN gateway (capability.vpn.gateway) — a virtual private
			// gateway. Server-assigned id; DescribeVpnGateways is the quiet read
			// (ownership pre-read on delete). Tunnels/connections/BGP are opaque impl,
			// so no vpn-connection permissions here. CreateTags applies ownership tags.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"ec2:CreateVpnGateway", "ec2:DescribeVpnGateways", "ec2:CreateTags"})
			case "update":
				return sortedDedup([]string{"ec2:DescribeVpnGateways"})
			case "delete":
				return sortedDedup([]string{"ec2:DeleteVpnGateway", "ec2:DescribeVpnGateways"})
			}
		case "backupvault":
			// D127. A managed backup vault (capability.backup.vault). ListTags is the
			// quiet ownership read (Describe does not return tags). A retention lock
			// adds PutBackupVaultLockConfiguration. Backup plans/selections are opaque
			// impl — no backup-plan permissions here.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"backup:CreateBackupVault", "backup:DescribeBackupVault",
					"backup:ListTags", "backup:TagResource", "backup:PutBackupVaultLockConfiguration"})
			case "update":
				return sortedDedup([]string{"backup:DescribeBackupVault", "backup:ListTags"})
			case "delete":
				return sortedDedup([]string{"backup:DeleteBackupVault", "backup:DescribeBackupVault", "backup:ListTags"})
			}
		}
		return nil // unknown/empty service under aws: the COMPILER refuses
	case "azure":
		switch service {
		case "loadbalancer":
			// D26. App Gateway (the L7 composite). applicationGateways/read is the
			// quiet read (provisioning poll + ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.Network/applicationGateways/write",
					"Microsoft.Network/applicationGateways/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.Network/applicationGateways/read",
					"Microsoft.Network/applicationGateways/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Network/applicationGateways/delete",
					"Microsoft.Network/applicationGateways/read"})
			}
		case "changefeed":
			// D142/D143. An Event Grid subscription -> storage queue. read is the
			// quiet pre-read; the target queue's own lifecycle is separate.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.EventGrid/eventSubscriptions/write",
					"Microsoft.EventGrid/eventSubscriptions/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.EventGrid/eventSubscriptions/write",
					"Microsoft.EventGrid/eventSubscriptions/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.EventGrid/eventSubscriptions/delete",
					"Microsoft.EventGrid/eventSubscriptions/read"})
			}
		case "vnet":
			// D99. VNet + the constitutive NSG (created when egress is restricted).
			// virtualNetworks/read is the quiet read (provisioning poll + the
			// ownership pre-read on delete). ARM permissions are action strings.
			switch operation {
			case "create", "adopt":
				p := []string{
					"Microsoft.Network/virtualNetworks/write",
					"Microsoft.Network/virtualNetworks/read",
					"Microsoft.Network/networkSecurityGroups/write",
					"Microsoft.Network/networkSecurityGroups/read"}
				if road, _ := attrs["egress.internet"].(string); road == "nat" {
					// fala 2: NAT Gateway + its Standard public IP. Service endpoints
					// (serviceAccess.private) ride in virtualNetworks/write, no extra perm.
					p = append(p, "Microsoft.Network/natGateways/write", "Microsoft.Network/natGateways/read",
						"Microsoft.Network/publicIPAddresses/write", "Microsoft.Network/publicIPAddresses/read")
				}
				return sortedDedup(p)
			case "update":
				// the permission set a patch WOULD need (in-place update is not
				// wired for azure v0 — Update() refuses honestly; the table is
				// still complete so D75 preflight never false-passes a future one).
				return sortedDedup([]string{
					"Microsoft.Network/virtualNetworks/read",
					"Microsoft.Network/virtualNetworks/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Network/virtualNetworks/delete",
					"Microsoft.Network/virtualNetworks/read",
					"Microsoft.Network/networkSecurityGroups/delete",
					// NAT teardown (no-op when there is no road):
					"Microsoft.Network/natGateways/delete",
					"Microsoft.Network/publicIPAddresses/delete"})
			}
		case "blob":
			// D99. Constitutive composite: storage account + blobServices +
			// container. Attribute-conditional: an immutability policy (retention)
			// adds the immutabilityPolicies action, a WORM lock adds the /lock
			// action, a lifecycle rule adds managementPolicies.
			_, retMin := attrs["retention.minimum"]
			locked, _ := attrs["retention.locked"].(bool)
			_, retMax := attrs["retention.maximum"]
			repl, _ := attrs["replication.enabled"].(bool)
			switch operation {
			case "create", "adopt":
				p := []string{
					"Microsoft.Storage/storageAccounts/write",
					"Microsoft.Storage/storageAccounts/read",
					"Microsoft.Storage/storageAccounts/blobServices/write",
					"Microsoft.Storage/storageAccounts/blobServices/containers/write",
					"Microsoft.Storage/storageAccounts/blobServices/containers/read"}
				if retMin {
					p = append(p, "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write")
				}
				if locked {
					p = append(p, "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/lock/action")
				}
				if retMax {
					p = append(p, "Microsoft.Storage/storageAccounts/managementPolicies/write")
				}
				if repl {
					// fala 2: object replication writes the policy on BOTH source and
					// destination account and reads the destination to measure its region.
					p = append(p, "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write",
						"Microsoft.Storage/storageAccounts/objectReplicationPolicies/read")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{
					"Microsoft.Storage/storageAccounts/read",
					"Microsoft.Storage/storageAccounts/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Storage/storageAccounts/delete",
					"Microsoft.Storage/storageAccounts/read"})
			}
		case "containerapps":
			// D99. Constitutive composite: managed environment + container app.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.App/managedEnvironments/write",
					"Microsoft.App/managedEnvironments/read",
					"Microsoft.App/containerApps/write",
					"Microsoft.App/containerApps/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.App/containerApps/read",
					"Microsoft.App/containerApps/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.App/containerApps/delete",
					"Microsoft.App/containerApps/read",
					"Microsoft.App/managedEnvironments/delete"})
			}
		case "flexpostgres":
			// D99. PostgreSQL Flexible Server — a single ARM resource.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.DBforPostgreSQL/flexibleServers/write",
					"Microsoft.DBforPostgreSQL/flexibleServers/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.DBforPostgreSQL/flexibleServers/read",
					"Microsoft.DBforPostgreSQL/flexibleServers/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.DBforPostgreSQL/flexibleServers/delete",
					"Microsoft.DBforPostgreSQL/flexibleServers/read"})
			}
		case "servicebusqueue":
			// D99. Service Bus namespace + queue (constitutive composite).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/write",
					"Microsoft.ServiceBus/namespaces/read", "Microsoft.ServiceBus/namespaces/queues/write"})
			case "update":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/read",
					"Microsoft.ServiceBus/namespaces/queues/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/delete",
					"Microsoft.ServiceBus/namespaces/read"})
			}
		case "servicebustopic":
			// D99. Service Bus namespace + topic (constitutive composite).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/write",
					"Microsoft.ServiceBus/namespaces/read", "Microsoft.ServiceBus/namespaces/topics/write"})
			case "update":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/read",
					"Microsoft.ServiceBus/namespaces/topics/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.ServiceBus/namespaces/delete",
					"Microsoft.ServiceBus/namespaces/read"})
			}
		case "keyvault":
			// D97. A Key Vault as the secret's home (capability.secret). vaults/read
			// is the quiet read (provisioning poll + ownership pre-read on delete).
			// The secret VALUE is data-plane, out of band — never written, so no
			// secrets/* permission appears here.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/write",
					"Microsoft.KeyVault/vaults/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/read",
					"Microsoft.KeyVault/vaults/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/delete",
					"Microsoft.KeyVault/vaults/read"})
			}
		case "rediscache":
			// D100. Managed Redis (capability.cache.keyvalue). redis/read is the
			// quiet read (provisioning poll + ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.Cache/redis/write",
					"Microsoft.Cache/redis/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.Cache/redis/read",
					"Microsoft.Cache/redis/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Cache/redis/delete",
					"Microsoft.Cache/redis/read"})
			}
		case "dnszone":
			// D101. A managed DNS zone (capability.dns.zone). The RESOURCE TYPE forks
			// on exposure — dnsZones (public) vs privateDnsZones (private) — so the
			// permission strings do too. .../read is the quiet read (provisioning
			// poll + ownership pre-read on delete). Records are data, out of band.
			public, _ := attrs["network.publicExposure"].(bool)
			base := "Microsoft.Network/privateDnsZones/"
			if public {
				base = "Microsoft.Network/dnsZones/"
			}
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{base + "write", base + "read"})
			case "update":
				return sortedDedup([]string{base + "read", base + "write"})
			case "delete":
				return sortedDedup([]string{base + "delete", base + "read"})
			}
		case "dnsrecord":
			// D262. A single DNS record set (capability.dns.record) — an ARM child
			// resource under a PUBLIC dnsZone, one per record type. The type is
			// resolved at runtime, so the static declaration is the per-type wildcard;
			// dnsZones/read is the ownership pre-read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"Microsoft.Network/dnsZones/read",
					"Microsoft.Network/dnsZones/*/read", "Microsoft.Network/dnsZones/*/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Network/dnsZones/read",
					"Microsoft.Network/dnsZones/*/read", "Microsoft.Network/dnsZones/*/delete"})
			}
		case "roleassignment":
			// D104. A named-role grant (capability.authorization.grant) = an RBAC role
			// assignment. Content-addressed by a deterministic GUID. roleAssignments/read
			// is the quiet read (observe). No role is authored, so no roleDefinitions/write.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Authorization/roleAssignments/write",
					"Microsoft.Authorization/roleAssignments/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Authorization/roleAssignments/delete",
					"Microsoft.Authorization/roleAssignments/read"})
			}
		case "customroledef":
			// D105. A custom role (capability.authorization.role) = a custom
			// roleDefinition. Content-addressed by a deterministic GUID.
			// roleDefinitions/read is the quiet read (observe).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Authorization/roleDefinitions/write",
					"Microsoft.Authorization/roleDefinitions/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Authorization/roleDefinitions/delete",
					"Microsoft.Authorization/roleDefinitions/read"})
			}
		case "metricalert":
			// D106. A metric alert (capability.monitoring.alert) = a metricAlert.
			// metricAlerts/read is the quiet read (ownership pre-read on delete + observe).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Insights/metricAlerts/write",
					"Microsoft.Insights/metricAlerts/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Insights/metricAlerts/delete",
					"Microsoft.Insights/metricAlerts/read"})
			}
		case "portaldash":
			// D107. A metric dashboard (capability.monitoring.dashboard) = a Portal
			// dashboard. dashboards/read is the quiet read (ownership pre-read + observe).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Portal/dashboards/write",
					"Microsoft.Portal/dashboards/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Portal/dashboards/delete",
					"Microsoft.Portal/dashboards/read"})
			}
		case "webtest":
			// D108. A synthetic uptime check (capability.monitoring.uptime) = an
			// Application Insights availability test. webtests/read is the quiet read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Insights/webtests/write",
					"Microsoft.Insights/webtests/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Insights/webtests/delete",
					"Microsoft.Insights/webtests/read"})
			}
		case "scheduledquery":
			// D109. A log-based metric (capability.monitoring.logmetric) = a scheduled
			// query rule. scheduledQueryRules/read is the quiet read.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.Insights/scheduledQueryRules/write",
					"Microsoft.Insights/scheduledQueryRules/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Insights/scheduledQueryRules/delete",
					"Microsoft.Insights/scheduledQueryRules/read"})
			}
		case "acr":
			// D110. A container image registry (capability.registry.image) = an ACR
			// registry. registries/read is the quiet read (provisioning poll + ownership).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.ContainerRegistry/registries/write",
					"Microsoft.ContainerRegistry/registries/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.ContainerRegistry/registries/delete",
					"Microsoft.ContainerRegistry/registries/read"})
			}
		case "azurefiles":
			// D111. Constitutive composite: storage account + fileServices + share
			// (capability.storage.filesystem). storageAccounts/read is the quiet read
			// (provisioning poll + ownership pre-read on delete). Delete removes the
			// account (which removes the share).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.Storage/storageAccounts/write",
					"Microsoft.Storage/storageAccounts/read",
					"Microsoft.Storage/storageAccounts/fileServices/write",
					"Microsoft.Storage/storageAccounts/fileServices/shares/write",
					"Microsoft.Storage/storageAccounts/fileServices/shares/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.Storage/storageAccounts/read",
					"Microsoft.Storage/storageAccounts/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Storage/storageAccounts/delete",
					"Microsoft.Storage/storageAccounts/read"})
			}
		case "cosmos":
			// D112. A managed NoSQL database (capability.database.nosql) — a Cosmos DB
			// account. databaseAccounts/read is the quiet read (provisioning poll +
			// ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.DocumentDB/databaseAccounts/write",
					"Microsoft.DocumentDB/databaseAccounts/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.DocumentDB/databaseAccounts/read",
					"Microsoft.DocumentDB/databaseAccounts/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.DocumentDB/databaseAccounts/delete",
					"Microsoft.DocumentDB/databaseAccounts/read"})
			}
		case "azvmss":
			// D372. A fleet (capability.compute.autoscaling). ARM PUT is an UPSERT and
			// idempotent by name, so virtualMachineScaleSets/read is the quiet read.
			// Ownership is tags.
			//
			// Unlike its two twins there is NO template permission: a scale set holds
			// its VM profile inline, so `network.publicExposure` is authored here
			// rather than verified against a resource the fleet only references. The
			// autoscale permissions are attribute-conditional AND appear on delete
			// unconditionally — a setting left behind keeps evaluating against a
			// target that no longer exists.
			switch operation {
			case "create", "adopt":
				p := []string{"Microsoft.Compute/virtualMachineScaleSets/write",
					"Microsoft.Compute/virtualMachineScaleSets/read"}
				if on, _ := attrs["autoscaling.enabled"].(bool); on {
					p = append(p, "Microsoft.Insights/autoscalesettings/write",
						"Microsoft.Insights/autoscalesettings/read")
				}
				return sortedDedup(p)
			case "update":
				return sortedDedup([]string{"Microsoft.Compute/virtualMachineScaleSets/read",
					"Microsoft.Compute/virtualMachineScaleSets/write",
					"Microsoft.Insights/autoscalesettings/read",
					"Microsoft.Insights/autoscalesettings/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Compute/virtualMachineScaleSets/delete",
					"Microsoft.Compute/virtualMachineScaleSets/read",
					"Microsoft.Insights/autoscalesettings/delete"})
			}
		case "azimage":
			// D370. A machine image (capability.compute.image), WITNESSED not authored
			// (D177) — so there is no create/delete permission set, only the read. A
			// managed image cannot be shared outside its subscription, so unlike the
			// GCP twin there is no policy permission to ask for.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"Microsoft.Compute/images/read"})
			}
		case "azdisk":
			// D369. A block volume (capability.storage.block). ARM PUT is an UPSERT and
			// idempotent by name, so disks/read is the quiet read (foreign-upsert
			// refusal + delete pre-read) — and on a STATEFUL capability that read is
			// what stands between a name collision and overwriting somebody else's
			// data. A disk-encryption set adds a read of its own, because it cannot be
			// used without being readable.
			//
			// A COPY source also needs Microsoft.Compute/snapshots/read, and it is
			// deliberately absent: this table sees `attrs`, not the operand block, so
			// the copy source is invisible here. Claiming it unconditionally would
			// refuse identities that only ever create empty disks — and the honest
			// failure mode of omitting it is a permission error from the API on the
			// one create that needed it, which is what a preflight is allowed to
			// miss (D75: a pass is evidence, not proof).
			switch operation {
			case "create", "adopt":
				p := []string{"Microsoft.Compute/disks/write", "Microsoft.Compute/disks/read"}
				if cmk, _ := attrs["encryption.customerManagedKeys"].(bool); cmk {
					p = append(p, "Microsoft.Compute/diskEncryptionSets/read")
				}
				return sortedDedup(p)
			case "update":
				// Every governed attribute is immutable on a volume (D369), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"Microsoft.Compute/disks/read"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Compute/disks/delete",
					"Microsoft.Compute/disks/read"})
			}
		case "azvm":
			// D360. A virtual machine (capability.compute.instance). ARM PUT is an
			// UPSERT and idempotent by name, so virtualMachines/read is the quiet read
			// (foreign-upsert refusal + delete pre-read). networkInterfaces/read is the
			// public-exposure read: on Azure the address belongs to the interface, not
			// the machine, so observing exposure needs a second permission.
			switch operation {
			case "create", "adopt":
				p := []string{"Microsoft.Compute/virtualMachines/write",
					"Microsoft.Compute/virtualMachines/read",
					"Microsoft.Network/networkInterfaces/read",
					"Microsoft.Network/networkInterfaces/join/action"}
				if cmk, _ := attrs["encryption.customerManagedKeys"].(bool); cmk {
					p = append(p, "Microsoft.Compute/diskEncryptionSets/read")
				}
				return sortedDedup(p)
			case "update":
				// Every governed attribute is immutable on a machine (D357), so an
				// update is a read plus the replacement the compiler plans.
				return sortedDedup([]string{"Microsoft.Compute/virtualMachines/read",
					"Microsoft.Network/networkInterfaces/read"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Compute/virtualMachines/delete",
					"Microsoft.Compute/virtualMachines/read"})
			}
		case "aisearch":
			// D113. A managed search service (capability.search.index). searchServices/
			// read is the quiet read (provisioning poll + ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.Search/searchServices/write",
					"Microsoft.Search/searchServices/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.Search/searchServices/read",
					"Microsoft.Search/searchServices/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Search/searchServices/delete",
					"Microsoft.Search/searchServices/read"})
			}
		case "eventhubs":
			// D114. A managed record stream (capability.streaming.pipe) — a namespace
			// + event hub composite. namespaces/read is the quiet read (provisioning
			// poll + ownership pre-read on delete). Delete removes the namespace.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/write",
					"Microsoft.EventHub/namespaces/read",
					"Microsoft.EventHub/namespaces/eventhubs/write",
					"Microsoft.EventHub/namespaces/eventhubs/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/read",
					"Microsoft.EventHub/namespaces/eventhubs/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/delete",
					"Microsoft.EventHub/namespaces/read"})
			}
		case "azkafka":
			// D115. A managed Kafka cluster (capability.messaging.kafka) — an Event
			// Hubs namespace with the Kafka endpoint. namespaces/read is the quiet
			// read (provisioning poll + ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/write",
					"Microsoft.EventHub/namespaces/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/read",
					"Microsoft.EventHub/namespaces/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.EventHub/namespaces/delete",
					"Microsoft.EventHub/namespaces/read"})
			}
		case "frontdoorwaf":
			// D116. A managed WAF policy (capability.security.waf) — a Front Door WAF
			// policy. .../read is the quiet read (provisioning poll + ownership
			// pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/write",
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read",
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/delete",
					"Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read"})
			}
		case "azurecdn":
			// D118. A managed CDN distribution (capability.cdn.distribution) — a CDN
			// profile + endpoint composite. profiles/read is the quiet read
			// (provisioning poll + ownership pre-read on delete). Delete removes the
			// profile (and its endpoints).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.Cdn/profiles/write",
					"Microsoft.Cdn/profiles/read",
					"Microsoft.Cdn/profiles/endpoints/write",
					"Microsoft.Cdn/profiles/endpoints/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.Cdn/profiles/read",
					"Microsoft.Cdn/profiles/endpoints/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.Cdn/profiles/delete",
					"Microsoft.Cdn/profiles/read"})
			}
		case "apim":
			// D119. A managed HTTP API gateway (capability.apigateway.http) — an API
			// Management service. service/read is the quiet read (provisioning poll +
			// ownership pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.ApiManagement/service/write",
					"Microsoft.ApiManagement/service/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.ApiManagement/service/read",
					"Microsoft.ApiManagement/service/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.ApiManagement/service/delete",
					"Microsoft.ApiManagement/service/read"})
			}
		case "containerappsjob":
			// D120. A managed container job (capability.container.job) — a Container
			// Apps Job. jobs/read is the quiet read (provisioning poll + ownership
			// pre-read on delete).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.App/jobs/write",
					"Microsoft.App/jobs/read"})
			case "update":
				return sortedDedup([]string{
					"Microsoft.App/jobs/read",
					"Microsoft.App/jobs/write"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.App/jobs/delete",
					"Microsoft.App/jobs/read"})
			}
		case "managedidentity":
			// D121. A managed machine identity (capability.identity.serviceaccount) —
			// a user-assigned managed identity; keyless (Azure holds the credential,
			// D53). .../read is the quiet read (ownership pre-read on delete). Role
			// assignments (what it may do) are opaque authorization config, out of scope.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{
					"Microsoft.ManagedIdentity/userAssignedIdentities/write",
					"Microsoft.ManagedIdentity/userAssignedIdentities/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.ManagedIdentity/userAssignedIdentities/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.ManagedIdentity/userAssignedIdentities/delete",
					"Microsoft.ManagedIdentity/userAssignedIdentities/read"})
			}
		case "keyvaultkey":
			// D102. A managed encryption key (capability.key.encryption) — the
			// constitutive composite vault + key. vaults/read is the ownership
			// pre-read; delete removes the vault (and its key with it).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/write",
					"Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/keys/write"})
			case "update":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/read",
					"Microsoft.KeyVault/vaults/keys/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.KeyVault/vaults/delete",
					"Microsoft.KeyVault/vaults/read"})
			}
		case "consumptionbudget":
			// D76 parity. Microsoft.Consumption/budgets — a synchronous PUT; read is the
			// quiet pre-read (ownership on delete/update, observe).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.Consumption/budgets/write", "Microsoft.Consumption/budgets/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.Consumption/budgets/read", "Microsoft.Consumption/budgets/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Consumption/budgets/delete", "Microsoft.Consumption/budgets/read"})
			}
		case "loganalytics":
			// D76 parity. Log Analytics workspace (capability.monitoring.logs). workspaces/read
			// is the quiet read (provisioning poll + ownership pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.OperationalInsights/workspaces/write", "Microsoft.OperationalInsights/workspaces/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.OperationalInsights/workspaces/read", "Microsoft.OperationalInsights/workspaces/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.OperationalInsights/workspaces/delete", "Microsoft.OperationalInsights/workspaces/read"})
			}
		case "activitylog":
			// D76 parity. A subscription Activity Log export = a diagnostic setting.
			// diagnosticSettings/read is the quiet read (observe + pre-update).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"Microsoft.Insights/diagnosticSettings/read", "Microsoft.Insights/diagnosticSettings/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Insights/diagnosticSettings/delete", "Microsoft.Insights/diagnosticSettings/read"})
			}
		case "defender":
			// D76 parity. Microsoft.Security/pricings plan singletons — a PUT of
			// pricingTier/subPlan/extensions; /read is the quiet pre-read. No ownership marker.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"Microsoft.Security/pricings/read", "Microsoft.Security/pricings/write"})
			}
		case "azureopenai":
			// D76 parity. An Azure OpenAI account + model deployments. accounts/read is the
			// quiet read (provisioning poll + ownership pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.CognitiveServices/accounts/write",
					"Microsoft.CognitiveServices/accounts/read",
					"Microsoft.CognitiveServices/accounts/deployments/write",
					"Microsoft.CognitiveServices/accounts/deployments/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.CognitiveServices/accounts/read", "Microsoft.CognitiveServices/accounts/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.CognitiveServices/accounts/delete", "Microsoft.CognitiveServices/accounts/read"})
			}
		case "aks":
			// AKS managed cluster (capability.cluster.kubernetes). managedClusters/read is
			// the quiet read (provisioning poll + ownership pre-read).
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.ContainerService/managedClusters/write", "Microsoft.ContainerService/managedClusters/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.ContainerService/managedClusters/read", "Microsoft.ContainerService/managedClusters/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.ContainerService/managedClusters/delete", "Microsoft.ContainerService/managedClusters/read"})
			}
		case "aks-addon":
			// An AKS addon is an entry in the cluster's addonProfiles, toggled by a
			// managedCluster PUT (read-modify-write). Delete disables the profile (a write,
			// never a cluster delete). No per-addon version action — AKS addons aren't versioned.
			switch operation {
			case "create", "adopt", "update", "delete":
				return sortedDedup([]string{"Microsoft.ContainerService/managedClusters/read", "Microsoft.ContainerService/managedClusters/write"})
			}
		case "aks-workloadidentity":
			// A federated identity credential (KSA subject -> UAMI), a sub-resource of the
			// UAMI. read is the ownership pre-read (content match, no tag marker) + discover.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{
					"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
					"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read"})
			case "delete":
				return sortedDedup([]string{
					"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete",
					"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read"})
			}
		case "backuppolicy":
			// D76 fala 4. A DataProtection backup policy under an existing vault.
			// backupVaults/read is the substrate verify (location check); the policy
			// PUT/GET/DELETE are backupPolicies/{write,read,delete}. Sync PUT; ownership is
			// the deterministic name (no tag/claim action). No cross-region copy in a policy.
			switch operation {
			case "create", "adopt":
				return sortedDedup([]string{"Microsoft.DataProtection/backupVaults/read",
					"Microsoft.DataProtection/backupVaults/backupPolicies/write",
					"Microsoft.DataProtection/backupVaults/backupPolicies/read"})
			case "update":
				return sortedDedup([]string{"Microsoft.DataProtection/backupVaults/backupPolicies/read",
					"Microsoft.DataProtection/backupVaults/backupPolicies/write"})
			case "delete":
				return sortedDedup([]string{"Microsoft.DataProtection/backupVaults/backupPolicies/delete",
					"Microsoft.DataProtection/backupVaults/backupPolicies/read"})
			}
		case "backupvault":
			// D244. The backup VAULT itself (the DataProtection top-level resource,
			// parent of the policies above).
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"Microsoft.DataProtection/backupVaults/write",
					"Microsoft.DataProtection/backupVaults/read"})
			case "delete":
				return sortedDedup([]string{"Microsoft.DataProtection/backupVaults/delete",
					"Microsoft.DataProtection/backupVaults/read"})
			}
		case "acsemail":
			// D76 fala 4. capability.email.sending = emailService + DKIM domain sub-resource.
			// emailServices/read is the quiet read (provisioning poll + ownership pre-read +
			// discover); domains write/delete provision/tear down the DKIM domain.
			switch operation {
			case "create", "adopt", "update":
				return sortedDedup([]string{"Microsoft.Communication/emailServices/write",
					"Microsoft.Communication/emailServices/read",
					"Microsoft.Communication/emailServices/domains/write",
					"Microsoft.Communication/emailServices/domains/read"})
			case "delete":
				return sortedDedup([]string{"Microsoft.Communication/emailServices/delete",
					"Microsoft.Communication/emailServices/read",
					"Microsoft.Communication/emailServices/domains/delete",
					"Microsoft.Communication/emailServices/domains/read"})
			}
		}
		return nil // unknown/empty service under azure: the COMPILER refuses
	case "fake":
		switch operation {
		case "create", "adopt":
			return []string{"fake.resources.create", "fake.resources.get"}
		case "update":
			return []string{"fake.resources.get", "fake.resources.update"}
		case "delete":
			return []string{"fake.resources.delete", "fake.resources.get"}
		}
	}
	return nil
}

func sortedDedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Preflighter is an OPTIONAL driver capability (D75, revised D78): given the
// pinned project and a permission set, the provider partitions them into two
// non-authoritative-safe classes for the acting identity:
//
//   - denied:     the check AUTHORITATIVELY attests the permission is absent
//     (the check surface evaluates that permission at that scope
//     and reports it not held) — a trustworthy negative.
//   - unattested: the check could not attest the permission (the surface has
//     an allowlist and silently omits it) — NOT evidence of
//     absence. An omission is not a denial.
//
// The split exists because a provider's negative signal is often not
// authoritative (project-level testIamPermissions is "not for authorization
// checking" and omits resource-scoped permissions — proven live D78), and
// collapsing an omission into a denial makes groundhold tell an authorized user
// they lack access. The executor hard-refuses only on `denied`; `unattested`
// (and a run error) is inconclusive. A pass is still evidence, never proof
// (deny policies, IAM conditions, propagation, org policy, VPC-SC, OAuth
// scope can diverge). A returned error means the check could not run at all.
type Preflighter interface {
	CheckPermissions(project string, permissions []string) (denied, unattested []string, err error)
}

// ErrNoResourceSurface is returned by CheckResourcePermissions for a service
// with no per-resource IAM surface (Cloud SQL): the executor falls back to the
// project-level check, where that service's permissions are CRM-attested and a
// negative is authoritative anyway.
var ErrNoResourceSurface = errors.New("no resource-level permission surface")

// ResourcePreflighter (D80) is the AUTHORITATIVE half of the preflight, for the
// case D78 could only degrade to inconclusive: an action on an EXISTING resource
// (update/delete/adopt/deposed — a pinned providerId) can be checked against the
// resource's OWN testIamPermissions surface, whose negative IS trustworthy
// (proven live: it grants storage.buckets.get the project surface omits). A
// returned `denied` on a 200 is authoritative; ErrNoResourceSurface means fall
// back to the project check; any other error means the surface could not be
// read (missing resource, network) and the permissions are inconclusive, NEVER
// denied.
// D720: `unattested` is the resource-level twin of the account-level channel. A
// simulator can answer a question we asked incompletely — AWS reports the condition
// keys its policies needed and we did not supply — and such a verdict must not block
// an apply. Without this channel the only honest options were to drop the action
// (silently "granted", so --require-preflight reports certainty it does not have) or
// to fail the whole group. Providers with no such notion return nil.
type ResourcePreflighter interface {
	CheckResourcePermissions(service, providerID string, permissions []string) (denied, unattested []string, err error)
}

// Fake is fully deterministic: same keys, same ids, same outcomes.
// FailKeys / UnknownKeys inject terminal failure or an unknown outcome
// per idempotency key for conformance cases.
type Fake struct {
	FailKeys    map[string]bool
	UnknownKeys map[string]bool
	// D237 injection: RetryableKeys return an `unknown` CreateResult flagged
	// Retryable (a pure throttle) so apply maps them to provider-again-later
	// rather than reconcile-required.
	RetryableKeys map[string]bool
	// D243 injection: the Retry-After hint carried on a RetryableKeys throttle.
	RetryAfterSeconds int
	// D75/D78 injection: MissingPermissions are reported as authoritatively
	// DENIED; UnattestedPermissions as non-authoritative omissions (the check
	// could not attest them); PreflightErr makes the check itself fail
	// (fail-closed path). All keyed for conformance staging.
	MissingPermissions    map[string]bool
	UnattestedPermissions map[string]bool
	PreflightErr          bool
	// D76 injection: a real driver refuses a service it does not support;
	// RefuseServices pins that fail-closed path for conformance.
	RefuseServices map[string]bool
	// D80 injection: the resource-level (authoritative) preflight.
	// ResourceDenied are reported as authoritatively denied; NoResourceSurface
	// services return ErrNoResourceSurface (executor falls back to project);
	// ResourcePreflightErr makes the resource check itself fail (inconclusive).
	AdoptAsProviderID    map[string]string // D723: create adopts this id instead of creating
	ResourceDenied       map[string]bool
	ResourceUnattested   map[string]bool // D720: resource-level inconclusive
	NoResourceSurface    map[string]bool
	ResourcePreflightErr bool
}

func (f *Fake) Name() string { return "fake" }

// CheckPermissions: deterministic live-check stand-in. PreflightErr →
// fail-closed error; otherwise partition into injected denied/unattested sets.
func (f *Fake) CheckPermissions(project string, permissions []string) (denied, unattested []string, err error) {
	if f.PreflightErr {
		return nil, nil, fmt.Errorf("injected preflight failure")
	}
	for _, p := range permissions {
		switch {
		case f.MissingPermissions[p]:
			denied = append(denied, p)
		case f.UnattestedPermissions[p]:
			unattested = append(unattested, p)
		}
	}
	return denied, unattested, nil
}

// CheckResourcePermissions: deterministic resource-level stand-in (D80).
func (f *Fake) CheckResourcePermissions(service, providerID string, permissions []string) ([]string, []string, error) {
	if f.NoResourceSurface[service] {
		return nil, nil, ErrNoResourceSurface
	}
	if f.ResourcePreflightErr {
		return nil, nil, fmt.Errorf("injected resource preflight failure")
	}
	var denied, unattested []string
	for _, p := range permissions {
		switch {
		case f.ResourceDenied[p]:
			denied = append(denied, p)
		case f.ResourceUnattested[p]:
			// D720: a resource-level verdict the provider could not stand behind.
			unattested = append(unattested, p)
		}
	}
	return denied, unattested, nil
}

func (f *Fake) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	if f.RefuseServices[service] {
		return fmt.Errorf("driver does not support service %q", service)
	}
	return nil
}

func (f *Fake) Observe(service, capability,
	providerID string) ([]Observation, []string, error) {
	// D242 injection: a providerID of "unreadable:<reason>" makes the primary read
	// fail (a transient/structural read error), so tests and conformance can
	// exercise per-capability isolation without a real provider.
	if r, ok := strings.CutPrefix(providerID, "unreadable:"); ok {
		return nil, nil, fmt.Errorf("injected read failure: %s", r)
	}
	// A providerID prefixed "empty:" reads CLEANLY but yields zero observable
	// attributes (a structurally blind observer), so tests and conformance can
	// exercise the compiler's observed-but-blind isolation without a real provider.
	if strings.HasPrefix(providerID, "empty:") {
		return nil, nil, nil
	}
	return []Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (f *Fake) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	return "mutable", ""
}

func (f *Fake) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) CreateResult {
	switch {
	case f.RetryableKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key, ProviderID: "fake:" + key,
			Status: "unknown", Reason: "injected throttle", Retryable: true,
			RetryAfterSeconds: f.RetryAfterSeconds}
	case f.UnknownKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "unknown", Reason: "injected unknown outcome"}
	case f.FailKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "failed", Reason: "injected failure"}
	}
	if pid := f.AdoptAsProviderID[key]; pid != "" {
		// D723: model a driver whose create-adoption scan bound an EXISTING resource
		// instead of creating one — the shape that let a replacement return the
		// identity it was about to delete.
		return CreateResult{ProviderID: pid, OperationID: "fake-op-" + key, Status: "succeeded"}
	}
	outs := map[string]any{
		"id":               "fake:" + key,
		"selfLink":         "fake://net/" + key,
		"endpoint":         key + ".fake.internal",
		"privateSubnetIds": []any{"subnet-" + key + "-a", "subnet-" + key + "-b"},
	}
	for k, v := range fakeEdgeValues(service, key) {
		outs[k] = v
	}
	return CreateResult{
		ProviderID:  "fake:" + key,
		OperationID: "fake-op-" + key,
		Status:      "succeeded",
		// D226/F13: deterministic typed outputs so intra-plan references
		// resolve in tests. Names/kinds match Fake.OutputsFor.
		Outputs: outs,
	}
}

// OutputsFor (D226/F13): the fake declares a fixed typed output set for every
// service, enough to exercise the reference wiring — a list output
// (privateSubnetIds) and string outputs (id/selfLink/endpoint). A $ref naming
// anything else refuses at compile (unknown output). PUBLIC-EDGE services
// (cloudfront/cdn, lambda/function) additionally declare the D316 edge outputs
// (domainName / functionUrl) so the post-apply reachability probe (Layer 1) has
// a target to derive from — mirroring the real aws driver's output set.
func (f *Fake) OutputsFor(service string) []OutputSpec {
	return append(fakeOutputs(), fakeEdgeOutputs(service)...)
}

func fakeOutputs() []OutputSpec {
	return []OutputSpec{
		{Name: "id", Kind: "string", Sample: "fake:preflight"},
		{Name: "selfLink", Kind: "string", Sample: "fake://net/preflight"},
		{Name: "endpoint", Kind: "string", Sample: "preflight.fake.internal"},
		{Name: "privateSubnetIds", Kind: "list",
			Sample: []any{"subnet-preflight-a", "subnet-preflight-b"}},
	}
}

// fakeEdgeKind classifies a service as a public edge for the reachability probe:
// a CDN distribution (domainName), a serverless function URL (functionUrl), or a
// container workload URL (uri, the Cloud Run shape). CROSS-CLOUD: the fake mirrors
// each real driver's edge output set so the D330 probe has a target to derive
// from in conformance.
func fakeEdgeKind(service string) string {
	switch service {
	case "cloudfront", "cdn":
		return "cdn"
	case "lambda", "function", "cloudfunctions":
		return "function"
	case "cloudrun", "container":
		return "container"
	case "containerapps":
		// Azure Container Apps: the SAME workload.container edge, but its output is
		// a bare ingress `fqdn` (a DIFFERENT name+shape than Cloud Run's `uri`), so
		// it is a distinct kind — proving the D330 probe recognizes the Azure edge
		// output name cross-cloud without a Cloud-Run assumption.
		return "container-azure"
	}
	return ""
}

func fakeEdgeOutputs(service string) []OutputSpec {
	switch fakeEdgeKind(service) {
	case "cdn":
		return []OutputSpec{{Name: "domainName", Kind: "string",
			Sample: "d111.fake-edge.example"}}
	case "function":
		return []OutputSpec{
			{Name: "functionUrl", Kind: "string", Sample: "https://fn.fake-edge.example/"},
			{Name: "functionUrlDomain", Kind: "string", Sample: "fn.fake-edge.example"},
		}
	case "container":
		// uri is a FULL URL, always published (the container's URL exists even
		// when private); the reachability probe gates PUBLIC-only from the
		// candidate's network.publicExposure, exactly as the real Cloud Run driver.
		return []OutputSpec{{Name: "uri", Kind: "string",
			Sample: "https://cr.fake-edge.example"}}
	case "container-azure":
		// fqdn is a BARE HOST (the probe wraps it into https://<host>/), always
		// published like Cloud Run's uri; the probe gates PUBLIC-only from the
		// candidate's network.publicExposure, exactly as the real Container Apps
		// driver.
		return []OutputSpec{{Name: "fqdn", Kind: "string",
			Sample: "aca.fake-edge.example"}}
	}
	return nil
}

// fakeEdgeValues returns the concrete edge output VALUES for a bound fake
// resource — a per-key host so distinct edges get distinct URLs. Kept in step
// with fakeEdgeOutputs so OutputsFor, Create and ReadOutputs never drift.
func fakeEdgeValues(service, key string) map[string]any {
	switch fakeEdgeKind(service) {
	case "cdn":
		return map[string]any{"domainName": "d-" + key + ".fake-edge.example"}
	case "function":
		host := "fn-" + key + ".fake-edge.example"
		return map[string]any{
			"functionUrl":       "https://" + host + "/",
			"functionUrlDomain": host,
		}
	case "container":
		return map[string]any{"uri": "https://cr-" + key + ".fake-edge.example"}
	case "container-azure":
		return map[string]any{"fqdn": "aca-" + key + ".fake-edge.example"}
	}
	return nil
}

func (f *Fake) Delete(service, capability, environment, providerID string,
	key string) CreateResult {
	switch {
	case f.UnknownKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "unknown", Reason: "injected unknown outcome"}
	case f.FailKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "failed", Reason: "injected failure"}
	}
	return CreateResult{ProviderID: providerID,
		OperationID: "fake-op-" + key, Status: "succeeded"}
}

// Discovered is one pre-existing resource surfaced by discovery (D52):
// identity, the vocabulary type the driver maps it to, and the same
// reverse-mapped observations Observe would emit.
type Discovered struct {
	ProviderID   string
	ResourceType string // vocabulary capability type
	Observations []Observation
}

// Discoverer is an OPTIONAL driver capability: enumerate resources the
// runtime did not create. Strictly read-only — discovery never touches
// the ledger or the cloud state.
type Discoverer interface {
	List(region string) ([]Discovered, []string, error)
}

// SweepAll runs one discovery sweep per service token, in the order given, and
// applies the rule every Discoverer owes its caller: a service that fails becomes a
// DIAGNOSTIC so one unreadable kind cannot hide the rest — but if EVERY sweep
// failed, nothing was read, and zero resources must not be handed back as an empty
// estate (D621, D642).
//
// The rule lived in four hand-written loops, each guarded by a different
// precondition: AWS checked for a region, Azure for a subscription GUID, GCP for a
// credential, and k8s for nothing at all. None of those is reachability. A dead
// network, an expired credential or a wrong API-server address left every sweep
// failing and every driver returning `nil` error — `discover` exited 0 with
// `"resources": []`, which is the input `adopt` and `posture` are told to take.
//
// The preconditions stay where they are: they name the missing thing precisely,
// which a count of failures cannot. This is the floor underneath them.
//
// D873: a PARTIAL failure is the dangerous one. When SOME sweeps fail and others
// succeed, the resources found are real but the estate is only partly read — and until
// now that returned err=nil with the failures buried in diagnostics, so the scope was
// recorded COMPLETE. posture then reported `shadowLowerBound=false` on a capability whose
// sweep wholly failed: an affirmative claim of exactness (D650/D803) about resources it
// never saw. The `rec` recorder is the fix: a failed sweep notes incompleteness through
// the SAME channel a truncated page does (ListingCompleteness), because the consequence
// is identical — the count is a lower bound. rec may be nil (Note is nil-safe); the
// cloud drivers pass their own recorder, and k8s gained one for exactly this.
func SweepAll(tokens []string, sweep func(token string) ([]Discovered, []string, error), rec *ListingRecord) ([]Discovered, []string, error) {
	var out []Discovered
	var diags []string
	failed := 0
	for _, tok := range tokens {
		found, ds, err := sweep(tok)
		if err != nil {
			failed++
			diags = append(diags, err.Error())
			// The token, not the error text: the note feeds an informational reason and
			// must stay deterministic (the error detail is already in diags).
			rec.Note("discovery sweep '"+tok+"' did not complete", nil)
			continue
		}
		out = append(out, found...)
		diags = append(diags, ds...)
	}
	if len(tokens) > 0 && failed == len(tokens) {
		return nil, diags, fmt.Errorf(
			"discovery could not reach the provider: all %d service sweeps failed, "+
				"so nothing was read — this is not an empty estate. First failure: %s",
			failed, firstDiag(diags))
	}
	return out, diags, nil
}

func firstDiag(diags []string) string {
	if len(diags) == 0 {
		return "(no diagnostic recorded)"
	}
	return diags[0]
}

// Enumerator is an OPTIONAL driver capability: list the CRAWLABLE SCOPES of a
// provider — projects/regions for clouds, namespaces for a cluster — so the gentle
// crawl (D141) can fan out when a pairing declares no explicit scope. Strictly
// read-only. Diagnostics carry what could not be listed (a partial enumeration is
// a fact, never a silently short list).
type Enumerator interface {
	Enumerate() (scopes []string, diags []string, err error)
}

// CompetingManagers is an OPTIONAL driver capability: report live evidence
// that ANOTHER continuous reconciler (ArgoCD, Helm, ...) owns the object at
// providerID. Adoption is fail-closed on it — a non-empty result (or an error,
// which cannot prove absence) REFUSES, because binding to something a foreign
// controller will keep reverting poisons ownership exactly as binding to
// something that does not satisfy the contract does (D52's rejected
// --tolerate-drift). The remedy is to release the object from that controller
// first, then adopt; there is deliberately no override. Returns the competing
// manager identities (verbatim) so the refusal can name them.
type CompetingManagers interface {
	CompetingManagers(service, providerID string) ([]string, error)
}

// Claimer is an OPTIONAL driver capability: take exclusive AUTHORSHIP of a
// resource groundhold adopted but did not create (D52 takeover). Adoption binds
// the ledger and proves reality matches the contract, but a converged no-op is
// a READ-ONLY proof — it does not stamp groundhold's ownership on the object, so
// the FIRST later drift would hit the driver's "not ours" guard with no writer
// left to repair it (the reviewers' Q5 hole). Claim closes it: it stamps the
// driver-native ownership marker (labels/tags, or a k8s SSA field-manager
// takeover) so subsequent updates recognise the object as ours. It is
// idempotent and loses no data. A driver that does not implement it simply does
// not gain the explicit-claim step (its adopted resources keep the old
// behaviour); a driver that does makes takeover honest end to end.
type Claimer interface {
	Claim(service, capability, environment, providerID string) CreateResult
}

// ProgressReporter (D257) is an OPTIONAL driver capability: a driver whose long
// operations poll for minutes (a cluster version upgrade, a node-group roll)
// accepts an intra-action heartbeat sink so it reports the phase it is waiting on
// instead of going silent. The executor sets the sink before an action and clears
// it after; the sink routes each phase into the progress stream (a Tick). Purely a
// projection — a driver that does not implement it, or a nil sink, changes no
// mutation semantics.
type ProgressReporter interface {
	SetProgress(report func(phase string))
}

// FieldReclaimer (D699) is an OPTIONAL driver capability, for a provider whose write
// can be REFUSED because another manager owns a field we declare — Kubernetes
// server-side apply, which 409s rather than stomping a live controller.
//
// Failing closed there is right by default. But `kubectl label` is the most common way
// a real cluster drifts, and after one, converge could never correct that field again:
// the repair was permanently blocked and the operator was told to "release it first"
// with no supported way to do so. The executor sets this per action, from consent the
// COMPILER sealed into the plan — so granting it after sealing yields a different plan
// hash rather than quietly changing what an existing plan does.
//
// What it permits is narrow by construction: an apply patch carries exactly the fields
// the mapping declares, so forcing it takes those and nothing else. It is never a
// blanket force.
type FieldReclaimer interface {
	SetFieldReclaim(allowed bool)
}

// EmissionAdopter (D1036) is an OPTIONAL driver capability: a create may need to
// govern a companion resource the PROVIDER auto-materialised — the /aws/lambda/<fn>
// log group a compute emits (D1032), which a bound monitoring.logs sets retention on.
// That group carries no groundhold ownership tags (the provider made it), so a create
// refuses it by default (D439–D472). The executor sets this per action from the
// SEALED emission-adopt grant (D1034), which the compiler minted only for a $ref to a
// certified emission with scoped consent — so when set, the driver takes over exactly
// the group its own Target names, and never decides adoption from the group string
// (the fold-at-plan leak the reviews flagged). Cleared after the call so it never
// leaks onto the next action.
type EmissionAdopter interface {
	SetEmissionAdopt(allowed bool)
}

// LROBudgeter reports a driver's ceiling for a long-running operation — the deadline
// a provisioning/upgrade poll may run before it concludes `unknown` (D264/D265). It
// exists to MECHANIZE a class of bug the Acme EKS saga exposed: a real control-plane
// minor-version upgrade routinely takes 20-40 min, so a driver polling against a naive
// ~20-min timeout reports a HEALTHY, still-progressing upgrade as `unknown` (a false
// failure). TestInterfaceParity forces every hyperscaler driver to implement this, and
// a floor test asserts the budget is generous enough — so a NEW cluster/LRO driver that
// ships a too-short ceiling fails CI instead of a field user's production upgrade.
type LROBudgeter interface {
	LROTimeout() time.Duration
}

// Fake claim: the deterministic ownership stamp the conformance loop needs to
// prove takeover completes only after authorship is acquired.
func (f *Fake) Claim(service, capability, environment, providerID string) CreateResult {
	return CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// Fake enumeration: two deterministic scopes, so the gentle crawl's scope fan-out
// (D141) is testable without a cloud.
func (f *Fake) Enumerate() ([]string, []string, error) {
	return []string{"fake-project-a", "fake-project-b"}, nil, nil
}

// Fake discovery: one deterministic pre-existing resource, so the
// onboarding path (discover -> draft -> adopt -> converge) is
// conformance-testable without a cloud.
func (f *Fake) List(region string) ([]Discovered, []string, error) {
	return []Discovered{{
		ProviderID:   "fake:existing-db",
		ResourceType: "capability.database.relational",
		Observations: []Observation{
			{Path: "service.managed", Value: true, Derivation: "measured"},
		},
	}}, nil, nil
}

func (f *Fake) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string,
	key string) CreateResult {
	switch {
	case f.UnknownKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "unknown", Reason: "injected unknown outcome"}
	case f.FailKeys[key]:
		return CreateResult{OperationID: "fake-op-" + key,
			Status: "failed", Reason: "injected failure"}
	}
	return CreateResult{
		ProviderID:  providerID, // identity survives an update
		OperationID: "fake-op-" + key,
		Status:      "succeeded",
	}
}

// ReconcileResult concludes a pending receipt (D57). Status unknown
// keeps it pending — reconciliation never guesses.
type ReconcileResult struct {
	Status     string // succeeded | failed | unknown
	ProviderID string // for concluded creates: the live identity
	Reason     string
}

// Reconciler is an OPTIONAL driver capability (D57): given a pending
// receipt's intent (operation, idempotencyKey, target,
// providerOperation?, targetProviderId?), determine what actually
// happened. STRICTLY READ-ONLY — a reconciler that mutates is a bug,
// not a feature. Deterministic names are the contract here: a driver
// whose Create derives identity from the idempotency key can answer
// existence questions long after the original response was lost.
type Reconciler interface {
	Reconcile(capability, environment string,
		receipt map[string]any) ReconcileResult
}

// Fake reconciliation mirrors Fake outcomes: the injection maps answer
// for the provider, so conformance cases stage every path — a key
// still in UnknownKeys stays unknown; FailKeys concludes failed;
// otherwise the deterministic name answers.
func (f *Fake) Reconcile(capability, environment string,
	receipt map[string]any) ReconcileResult {
	key, _ := receipt["idempotencyKey"].(string)
	switch {
	case f.UnknownKeys[key]:
		return ReconcileResult{Status: "unknown",
			Reason: "provider still cannot answer for " + key}
	case f.FailKeys[key]:
		return ReconcileResult{Status: "failed",
			Reason: "operation " + key + " concluded: never happened"}
	}
	switch op, _ := receipt["operation"].(string); op {
	case "delete", "update":
		// identity survives an update; a delete concludes on its pin
		pid, _ := receipt["targetProviderId"].(string)
		return ReconcileResult{Status: "succeeded", ProviderID: pid}
	}
	return ReconcileResult{Status: "succeeded", ProviderID: "fake:" + key}
}

// ProbeMeasurement is measured reality from an outcome probe (D59):
// the same observation stream as Observe, but proving OUTCOMES
// (connection attempts, restore tests) rather than reading config.
type ProbeMeasurement struct {
	Path      string
	Value     any
	Method    string // e.g. tcp-connect, restore-test
	Evidence  string // one line a human can audit
	Intrusive bool   // ran only because intrusion was doubly consented
}

// ProbeFailure: the probe itself crashed/timed out — no reality was
// measured, so this is NEVER an observation (review verdict, D59).
type ProbeFailure struct {
	Path      string
	Method    string
	Reason    string
	Retryable bool
}

type ProbeOutcome struct {
	Measurements []ProbeMeasurement
	Failures     []ProbeFailure
}

// Prober is an OPTIONAL driver capability (D59). Probes are expensive
// and sometimes intrusive: they NEVER run implicitly (no probe from
// converge/observe), and intrusive ones run only when allowIntrusive —
// which the runtime grants only under BOTH the operator flag and the
// contract's autonomy consent.
type Prober interface {
	Probe(service, capability, providerID string,
		allowIntrusive bool) (ProbeOutcome, error)
}

// Fake probes: a non-intrusive exposure check always; an intrusive
// restore-test measuring recovery.rto only under consent. FailKeys
// ("probe:"+capability) injects a probe crash for conformance.
func (f *Fake) Probe(service, capability, providerID string,
	allowIntrusive bool) (ProbeOutcome, error) {
	if f.FailKeys["probe:"+capability] {
		return ProbeOutcome{Failures: []ProbeFailure{{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason: "injected probe crash", Retryable: true}}}, nil
	}
	out := ProbeOutcome{Measurements: []ProbeMeasurement{{
		Path: "network.publicExposure", Value: false,
		Method:   "tcp-connect",
		Evidence: "0 open paths from 3 external vantage points"}}}
	if allowIntrusive {
		out.Measurements = append(out.Measurements, ProbeMeasurement{
			Path: "recovery.rto", Value: "35m", Method: "restore-test",
			Evidence:  "scratch restore completed in 35m",
			Intrusive: true})
	}
	return out, nil
}
