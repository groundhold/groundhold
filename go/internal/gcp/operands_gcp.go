// The GCP half of the SILENT-IGNORE GUARD: per service, the exact set of
// candidate `implementation:` operand KEYS this driver reads. The block is
// free-form (D26), but an operand no driver consumes is refused at compile
// rather than silently dropped — the same fail-closed rule the per-attribute
// allowlists already enforce. Only TOP-LEVEL keys are declared: a map/array-
// valued operand (cloudsql.flags, cloudsql.network, cloudfunctions.source,
// gke.nodePool, loadbalancer.backendService, clouddns.networks,
// billingbudget.monitoringNotificationChannels) is one key whose arbitrary
// subkeys/elements are free. Keyed by the SERVICE token the candidate declares,
// parallel to OutputsFor/PermissionsFor: pure and table-driven.
package gcp

import "groundhold/internal/provider"

// gcpConsumedOperands: enumerated by reading every impl[...] read on the create,
// update and ClassifyChange paths of each service (including the operand helpers
// pubsubIntOperand/lbPortOperand/applyBackendServiceOperand/implIntG). A service
// that reads no operand declares the empty set — any operand on it then refuses.
// Naming trap preserved verbatim: artifactregistry reads "kms_key" (not the
// "kms_key_name" every other CMEK service reads).
var gcpConsumedOperands = map[string][]string{
	"cloudsql":             {"deletion_protection", "disk_type", "edition", "flags", "kms_key_name", "network", "tier"},
	"cloudrun":             {"image", "port"},
	"cloudfunctions":       {"entry_point", "event_trigger", "runtime", "source"},
	"cloudfunctions-fn":    {"entry_point", "environment", "event_trigger", "runtime", "source", "vpc_connector", "vpc_connector_egress_settings"},
	"gcs":                  {"kms_key_name"},
	"pubsub-topic":         {"kms_key_name"},
	"pubsub-queue":         {"dead_letter_topic", "kms_key_name", "max_delivery_attempts"},
	"vpc":                  {"cidr"},
	"secretmanager":        {"kms_key_name"},
	"memorystore":          {"kms_key_name", "memory_size_gb"},
	"clouddns":             {"networks"},
	"clouddnsrecord":       {"record_name", "zone"},
	"iambinding":           {},
	"customrole":           {},
	"monitoring":           {"notification_channel"},
	"dashboard":            {},
	"uptime":               {"port"},
	"logmetric":            {"value_field"},
	"artifactregistry":     {"kms_key"},
	"filestore":            {"capacity_gb", "kms_key_name", "network"},
	"firestore":            {"kms_key_name"},
	"managedkafka":         {"kms_key_name", "subnet"},
	"cloudarmor":           {},
	"certmanager":          {"dns_authorization"},
	"cloudrunjobs":         {},
	"serviceaccount":       {},
	"bigquery":             {"kms_key_name"},
	"cloudscheduler":       {"http_uri", "pubsub_topic", "schedule", "timezone"},
	"cloudkms":             {},
	"vpngateway":           {"network"},
	"backupvault":          {},
	"backupplan":           {"backupVault", "backupWindowEndHour", "backupWindowStartHour", "resourceType", "timeZone"},
	"assetfeed":            {},
	"loadbalancer":         {"backendService", "healthCheckPath", "port", "sslCertificate"},
	"billingbudget":        {"billingAccountId", "monitoringNotificationChannels", "pubsubTopic"},
	"logbucket":            {"kms_key_name", "log_bucket_id"},
	"auditlogs":            {"destination", "kms_key_name", "sinkName"},
	"scc":                  {"organizationId", "projectId", "tier"},
	"vertexai":             {"displayName", "publisherModel"},
	"gke":                  {"nodePool"},
	"gke-addon":            {"clusterName", "location"},
	"gke-workloadidentity": {"clusterProject", "gsaEmail"},
}

// ConsumedOperands implements provider.OperandConsumer (the operand twin of
// OutputsFor): the compiler refuses any implementation operand not in this set.
func (d *Driver) ConsumedOperands(service string) []string {
	return gcpConsumedOperands[service]
}

var _ provider.OperandConsumer = (*Driver)(nil)
