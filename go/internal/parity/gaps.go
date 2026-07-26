// Package parity builds and PROVES the cross-cloud capability parity matrix.
//
// The matrix answers, for every capability TYPE, whether each cloud (aws/gcp/
// azure) fulfils it — and critically distinguishes a STRUCTURAL GAP (the cloud
// has no service that can fulfil the capability — a fact about the cloud) from
// UNBUILT (groundhold simply has no driver yet — a fact about groundhold). That
// distinction is the point: the bake-off (D92) must know when a cloud CANNOT
// satisfy a contract versus when a driver is merely missing.
//
// The fulfilled cells are GENERATED from the three drivers' ServiceCapabilities()
// maps (proven per-driver by provider.CertifyParity), so they can never drift or
// over-claim. The unbuilt cells are DERIVED (no token, no declared gap) — nobody
// ever writes "unbuilt", which eliminates a whole class of lie. Only structural
// gaps are authored, here, and each is proven REAL by TestParityMatrix: a gap that
// some token actually fulfils fails the gate.
package parity

// Gap is an authored, machine-enforced claim that a cloud structurally cannot
// fulfil a capability. Class is drawn from the closed set below; Reason is the
// human explanation surfaced to the bake-off.
type Gap struct {
	Class  string
	Reason string
}

// gapClasses is the CLOSED set of legitimate structural-gap reasons (mirroring
// provider.nonListableReasons). A free-text class is rejected so the gap bucket
// cannot become a trust-me allowlist — the thing the matrix exists to prevent.
var gapClasses = map[string]bool{
	"no-native-service":     true, // the cloud has no product for this capability at all
	"not-capability-shaped": true, // a product exists but cannot honor the capability contract
	"policy-refused":        true, // a deliberate refusal (e.g. a residency/sovereignty policy)
}

// structuralGaps declares the (capability TYPE, cloud) pairs where the cloud
// GENUINELY lacks the service — not merely where groundhold has not written a driver.
// The bar is high on purpose: a false structural gap ("the cloud can't", when it
// can) is a lie worse than an honest "unbuilt". So this table holds only the cases
// we are certain of; everything else absent is derived as unbuilt.
//
// TestParityMatrix proves every entry here is REAL (no token in that cloud fulfils
// the TYPE) and that the class is from the closed set — so if a driver is ever
// written for a gapped cell, the gate fails and the entry must be removed by hand.
var structuralGaps = map[string]map[string]Gap{
	"capability.email.sending": {
		"gcp": {
			Class:  "no-native-service",
			Reason: "GCP has no first-party transactional email service — sending relies on a third-party relay (SendGrid/Mailgun), which is outside groundhold's provider boundary.",
		},
	},
	"capability.email.inbound": {
		"gcp": {
			Class:  "no-native-service",
			Reason: "GCP has no managed inbound-mail-to-storage pipeline (the SES-receiving analog does not exist).",
		},
		"azure": {
			Class:  "no-native-service",
			Reason: "Azure has no managed inbound-mail-to-storage pipeline (ACS Email is send-only; there is no SES-receiving analog).",
		},
	},
	// D119 — GCP API Gateway exists, but a serving gateway is not one resource: it
	// is an api + apiConfig + gateway chain whose apiConfig REQUIRES an OpenAPI/
	// Swagger document (opaque routing config, invariant #4), so it cannot honor
	// the single managed-gateway capability the way apigatewayv2 / APIM do. The GCP
	// dispatch fail-closes on it rather than faking a third mapping.
	"capability.apigateway.http": {
		"gcp": {
			Class:  "not-capability-shaped",
			Reason: "GCP API Gateway is not a single managed-gateway resource — a serving gateway is an api+apiConfig+gateway chain whose apiConfig requires an OpenAPI document (opaque config), so it cannot honor this capability the way AWS API Gateway v2 and Azure API Management do (D119).",
		},
	},
	// D118 — GCP Cloud CDN is not a standalone resource: it is a toggle on a
	// load-balancer backend service (an irreducible L7 LB composite), not a
	// capability-shaped distribution the way CloudFront and Azure CDN are.
	"capability.cdn.distribution": {
		"gcp": {
			Class:  "not-capability-shaped",
			Reason: "GCP Cloud CDN is not a standalone resource — it is enableCdn on a load-balancer backend service, part of an irreducible L7 load-balancer composite, so it cannot honor this single-distribution capability the way AWS CloudFront and Azure CDN do (D118).",
		},
	},
	// D117 — Azure has no management-plane managed-TLS-certificate twin: Key Vault
	// certificates are data-plane (the vault.azure.net endpoint), and App Service
	// managed certificates are coupled to an App Service Plan; neither is a
	// standalone managed cert the way ACM and Certificate Manager are.
	"capability.certificate.tls": {
		"azure": {
			Class:  "not-capability-shaped",
			Reason: "Azure has no management-plane managed-TLS-certificate service: Key Vault certificates are data-plane and App Service managed certificates are coupled to an App Service Plan, so neither honors this standalone managed-certificate capability the way AWS ACM and GCP Certificate Manager do (D117).",
		},
	},
	// D113 — the search.index vocab is an honest two-cloud domain (AWS OpenSearch,
	// Azure AI Search): GCP's Vertex AI Search is an ML/RAG product, not an
	// operable full-text search cluster, so the GCP driver fail-closes rather than
	// fake a third mapping. Formalized here so the matrix reads "declared", not
	// "unbuilt".
	"capability.search.index": {
		"gcp": {
			Class:  "not-capability-shaped",
			Reason: "GCP has no managed search-cluster twin: Vertex AI Search is an ML/RAG product, not an operable full-text search cluster the way AWS OpenSearch Service and Azure AI Search are (D113).",
		},
	},
	// D114 — the streaming.pipe vocab is an honest two-cloud domain (AWS Kinesis,
	// Azure Event Hubs): GCP's closest, Pub/Sub Lite, is deprecated, and Managed
	// Service for Apache Kafka is a Kafka-cluster model, not a single stream
	// resource; the GCP driver fail-closes rather than fake a third mapping.
	"capability.streaming.pipe": {
		"gcp": {
			Class:  "not-capability-shaped",
			Reason: "GCP has no clean managed streaming twin: Pub/Sub Lite (the closest) is deprecated and Managed Service for Apache Kafka is a Kafka-cluster model, not a single stream resource the way AWS Kinesis Data Streams and Azure Event Hubs are (D114).",
		},
	},
	// D120 — the container.job vocab is an honest two-cloud domain (GCP Cloud Run
	// Jobs, Azure Container Apps Jobs): AWS Batch is a job-definition + queue +
	// compute-environment composite and an ECS RunTask is an ephemeral action,
	// neither a single durable job resource; the AWS driver fail-closes rather than
	// fake a third mapping. The audit's "build it" was wrong — the vocab author
	// already judged AWS not-capability-shaped here.
	"capability.container.job": {
		"aws": {
			Class:  "not-capability-shaped",
			Reason: "AWS has no standalone managed-job resource: AWS Batch is a job-definition + queue + compute-environment composite and an ECS RunTask is an ephemeral action, not a single durable job resource the way GCP Cloud Run Jobs and Azure Container Apps Jobs are (D120).",
		},
	},
}
