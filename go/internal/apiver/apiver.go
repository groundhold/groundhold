// Package apiver is the API-version pin registry + drift detector (D236,
// API-drift #3). Every driver targets a SPECIFIC provider API version, embedded
// three different ways depending on the cloud:
//
//   - AWS:   a dated Version form parameter    ("2016-11-15")
//   - GCP:   a version segment in the URL path ("compute/v1")
//   - Azure: an api-version query parameter     ("2024-05-01" / "...-preview")
//
// The drift risk is silent: the provider deprecates or supersedes a version, the
// driver keeps targeting the old one, and we learn via a live incident. The
// response-fixture harness (D234/D235) catches a shape change WITHIN a version;
// this package catches the version itself going stale.
//
// Two honesty rules make the pin real, not documentation:
//
//   - The registry is the single ENUMERATED catalog of what we target, and a
//     consistency test (consistency_test.go) binds every entry to a literal
//     actually present in the driver source — registry ⊆ code — so a pin cannot
//     lie about a version we do not use. The reverse direction (code ⊆ registry
//     ∪ allowlist) is the anti-scatter tripwire: a new un-registered version
//     literal fails the build.
//   - The drift detector is a PURE comparator over a live version list
//     (canary-fetched). It SURFACES a newer or deprecated version; it never
//     silently follows one. An unknown live state is cannot-verify, never green
//     — the same fail-closed spine as the four-valued verifier.
//
// The live half (per-provider version fetchers) is canary-only, exactly like
// fixture capture: no live provider call ever runs on a dev host. This slice
// ships the registry, the consistency fences, and the offline comparator; the
// GCP Discovery / AWS SDK-model / Azure ARM fetchers wire into the canary next.
package apiver

import "sort"

// Embed is how a provider's API version is spliced into a request. Closed set.
type Embed string

const (
	// EmbedFormParam: AWS dated Version form value (e.g. Version=2016-11-15).
	EmbedFormParam Embed = "aws-form-version"
	// EmbedPathSegment: GCP version segment in the request URL path (compute/v1).
	EmbedPathSegment Embed = "gcp-path-segment"
	// EmbedQueryParam: Azure api-version query parameter (?api-version=2024-05-01).
	EmbedQueryParam Embed = "azure-api-version"
)

// Pin is one provider+service -> targeted-API-version record.
type Pin struct {
	Provider string `json:"provider"` // aws | gcp | azure
	Service  string `json:"service"`  // stable kebab id, e.g. "ec2", "compute", "container-service"
	Version  string `json:"version"`  // the EXACT literal embedded: "2016-11-15" | "compute/v1" | "2024-05-01"
	Embed    Embed  `json:"embed"`
	Source   string `json:"source"` // the provider host/discovery id a human checks to verify currency
	// CataloguedAt is the date this pin was recorded FROM THE DRIVER SOURCE. It
	// is deliberately not "verified against the provider": these are seeded from
	// code, and the drift detector is what establishes currency (canary). Do not
	// read it as a provider-verification stamp.
	CataloguedAt string `json:"cataloguedAt"`
}

// cataloguedAt is the D236 seeding date (source census, not provider-verified).
const cataloguedAt = "2026-07-23"

func aws(svc, ver, src string) Pin {
	return Pin{"aws", svc, ver, EmbedFormParam, src, cataloguedAt}
}
func gcp(svc, ver, src string) Pin {
	return Pin{"gcp", svc, ver, EmbedPathSegment, src, cataloguedAt}
}
func az(svc, ver, src string) Pin {
	return Pin{"azure", svc, ver, EmbedQueryParam, src, cataloguedAt}
}

// registry is the enumerated catalog. Seeded by a census of the driver source
// (D236). Every Version here is asserted present in the corresponding driver by
// consistency_test.go — keep it that way: a bump changes both, in one diff.
var registry = []Pin{
	// --- AWS: dated Version form parameters ------------------------------------
	// (the IAM policy-LANGUAGE version "2012-10-17" is NOT an API version and is
	// deliberately absent — see awsPolicyLangAllow in consistency_test.go.)
	aws("ec2", "2016-11-15", "ec2.amazonaws.com (Query API)"),
	aws("rds", "2014-10-31", "rds.amazonaws.com (Query API)"),
	aws("elasticache", "2015-02-02", "elasticache.amazonaws.com (Query API)"),
	aws("elbv2", "2015-12-01", "elasticloadbalancing.amazonaws.com (Query API)"),
	aws("iam", "2010-05-08", "iam.amazonaws.com (Query API)"),
	aws("sns", "2010-03-31", "sns.amazonaws.com (Query API)"),
	aws("sqs", "2012-11-05", "sqs.amazonaws.com (Query API)"),
	aws("ses", "2010-12-01", "email.amazonaws.com (Query API)"),
	aws("cloudwatch", "2010-08-01", "monitoring.amazonaws.com (Query API)"),

	// --- GCP: version path segments --------------------------------------------
	gcp("compute", "compute/v1", "compute.googleapis.com"),
	gcp("cloud-storage", "storage/v1", "storage.googleapis.com"),
	gcp("cloud-dns", "dns/v1", "dns.googleapis.com"),
	gcp("bigquery", "bigquery/v2", "bigquery.googleapis.com"),
	gcp("cloud-sql", "v1", "sqladmin.googleapis.com"),
	gcp("gke", "v1", "container.googleapis.com"),
	gcp("iam", "v1", "iam.googleapis.com"),
	gcp("secret-manager", "v1", "secretmanager.googleapis.com"),
	gcp("cloud-kms", "v1", "cloudkms.googleapis.com"),
	gcp("pubsub", "v1", "pubsub.googleapis.com"),
	gcp("cloud-run", "v2", "run.googleapis.com"),
	gcp("cloud-functions", "v2", "cloudfunctions.googleapis.com"),
	gcp("cloud-logging", "v2", "logging.googleapis.com"),
	gcp("monitoring", "v3", "monitoring.googleapis.com"),
	gcp("monitoring-dashboard", "v1", "monitoring.googleapis.com"),
	gcp("resource-manager", "v1", "cloudresourcemanager.googleapis.com"),
	gcp("service-usage", "v1", "serviceusage.googleapis.com"),
	gcp("artifact-registry", "v1", "artifactregistry.googleapis.com"),
	gcp("cloud-asset", "v1", "cloudasset.googleapis.com"),
	gcp("cloud-billing", "v1", "cloudbilling.googleapis.com"),
	gcp("billing-budgets", "v1", "billingbudgets.googleapis.com"),
	gcp("certificate-manager", "v1", "certificatemanager.googleapis.com"),
	gcp("cloud-scheduler", "v1", "cloudscheduler.googleapis.com"),
	gcp("backup-dr", "v1", "backupdr.googleapis.com"),
	gcp("filestore", "v1", "file.googleapis.com"),
	gcp("firestore", "v1", "firestore.googleapis.com"),
	gcp("memorystore-redis", "v1", "redis.googleapis.com"),
	gcp("managed-kafka", "v1", "managedkafka.googleapis.com"),
	gcp("scc", "v1", "securitycentermanagement.googleapis.com"),
	gcp("vertex-ai", "v1", "aiplatform.googleapis.com"),

	// --- Azure: api-version query parameters -----------------------------------
	az("container-service", "2024-05-01", "Microsoft.ContainerService"),
	az("container-service-addon", "2024-05-01", "Microsoft.ContainerService"),
	az("container-registry", "2023-07-01", "Microsoft.ContainerRegistry"),
	az("container-apps", "2024-03-01", "Microsoft.App"),
	az("container-apps-jobs", "2023-05-01", "Microsoft.App"),
	az("communication-email", "2023-04-01", "Microsoft.Communication"),
	az("insights-diagnostic-settings", "2021-05-01-preview", "Microsoft.Insights"),
	az("monitor-metric-alert", "2018-03-01", "Microsoft.Insights"),
	az("scheduled-query", "2023-03-15-preview", "Microsoft.Insights"),
	az("log-analytics", "2022-10-01", "Microsoft.OperationalInsights"),
	az("app-insights-webtest", "2022-06-15", "Microsoft.Insights"),
	az("portal-dashboard", "2020-09-01-preview", "Microsoft.Portal"),
	az("api-management", "2023-05-01-preview", "Microsoft.ApiManagement"),
	az("cdn", "2023-05-01", "Microsoft.Cdn"),
	az("frontdoor-waf", "2022-05-01", "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"),
	az("cognitive-services", "2023-05-01", "Microsoft.CognitiveServices"),
	az("consumption-budget", "2023-05-01", "Microsoft.Consumption"),
	az("data-protection", "2023-05-01", "Microsoft.DataProtection"),
	az("cosmos-db", "2024-05-15", "Microsoft.DocumentDB"),
	az("cosmos-change-feed", "2025-02-15", "Microsoft.DocumentDB"),
	az("defender", "2024-01-01", "Microsoft.Security"),
	az("event-hubs", "2024-01-01", "Microsoft.EventHub"),
	az("event-hubs-kafka", "2024-01-01", "Microsoft.EventHub"),
	az("key-vault", "2023-07-01", "Microsoft.KeyVault"),
	az("authorization", "2022-04-01", "Microsoft.Authorization"),
	az("authorization-custom-role", "2022-04-01", "Microsoft.Authorization/roleDefinitions"),
	az("authorization-role-assignment", "2022-04-01", "Microsoft.Authorization/roleAssignments"),
	az("managed-identity", "2023-01-31", "Microsoft.ManagedIdentity"),
	az("managed-identity-federated-credential", "2023-01-31", "Microsoft.ManagedIdentity/federatedIdentityCredentials"),
	az("network", "2023-11-01", "Microsoft.Network"),
	az("private-dns", "2020-06-01", "Microsoft.Network/privateDnsZones"),
	az("public-dns", "2018-05-01", "Microsoft.Network/dnsZones"),
	az("search", "2023-11-01", "Microsoft.Search"),
	az("service-bus", "2022-10-01-preview", "Microsoft.ServiceBus"),
	az("storage", "2023-05-01", "Microsoft.Storage"),
	az("postgresql-flexible", "2023-06-01-preview", "Microsoft.DBforPostgreSQL/flexibleServers"),
	az("redis", "2023-08-01", "Microsoft.Cache"),
	az("subscriptions", "2020-01-01", "Microsoft.Resources/subscriptions"),
}

// All returns a copy of the registry, sorted by provider then service.
func All() []Pin {
	out := make([]Pin, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Service < out[j].Service
	})
	return out
}

// ByProvider returns the pins for one provider (aws|gcp|azure), sorted by service.
func ByProvider(provider string) []Pin {
	var out []Pin
	for _, p := range registry {
		if p.Provider == provider {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// Get returns the pin for a provider+service.
func Get(provider, service string) (Pin, bool) {
	for _, p := range registry {
		if p.Provider == provider && p.Service == service {
			return p, true
		}
	}
	return Pin{}, false
}

// versionSet returns the distinct set of Version strings registered for a
// provider (used by the consistency fence).
func versionSet(provider string) map[string]bool {
	m := map[string]bool{}
	for _, p := range registry {
		if p.Provider == provider {
			m[p.Version] = true
		}
	}
	return m
}
