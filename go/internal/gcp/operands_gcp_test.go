package gcp

import (
	"sort"
	"testing"

	"groundhold/internal/provider"
)

// D307: the SILENT-IGNORE GUARD — ConsumedOperands is the operand twin of
// OutputsFor/ServiceCapabilities. Its key set must equal the certified service
// set exactly (parity_gcp_test.go pins that discipline for ServiceCapabilities;
// this file pins it for ConsumedOperands), and the driver must implement
// provider.OperandConsumer. Individual service entries are spot-checked against
// the actual impl[...] reads in the corresponding *.go files (verified by
// inspection while writing this test — cloudsql, cloudfunctions-fn,
// artifactregistry's "kms_key" vs "kms_key_name" naming trap, and
// loadbalancer/billingbudget were all cross-checked against their operand reads).

func TestConsumedOperandsKeySetMatchesCertifiedServices(t *testing.T) {
	d := NewDriver("proj")
	want := make(map[string]bool, len(gcpCertifyServices))
	for _, tok := range gcpCertifyServices {
		want[tok] = true
		if _, ok := gcpConsumedOperands[tok]; !ok {
			t.Errorf("gcpConsumedOperands missing certified token %q", tok)
		}
	}
	for tok := range gcpConsumedOperands {
		if !want[tok] {
			t.Errorf("gcpConsumedOperands has surplus token %q not in gcpCertifyServices", tok)
		}
	}
	if len(gcpConsumedOperands) != len(gcpCertifyServices) {
		gotKeys := make([]string, 0, len(gcpConsumedOperands))
		for k := range gcpConsumedOperands {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)
		t.Errorf("key count mismatch: got %d, want %d (%v)",
			len(gcpConsumedOperands), len(gcpCertifyServices), gotKeys)
	}
	// ConsumedOperands is a thin passthrough — assert it actually reads the
	// package map, not a stale copy.
	for _, tok := range gcpCertifyServices {
		got := d.ConsumedOperands(tok)
		want := gcpConsumedOperands[tok]
		if len(got) != len(want) {
			t.Errorf("%s: ConsumedOperands returned %v, map has %v", tok, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: ConsumedOperands[%d] = %q, want %q", tok, i, got[i], want[i])
			}
		}
	}
}

func TestConsumedOperandsImplementsInterface(t *testing.T) {
	var _ provider.OperandConsumer = (*Driver)(nil)
	d := NewDriver("proj")
	var oc provider.OperandConsumer = d
	if got := oc.ConsumedOperands("cloudsql"); len(got) == 0 {
		t.Fatalf("cloudsql must declare a non-empty operand set via the interface, got %v", got)
	}
}

func TestConsumedOperandsUnknownServiceReturnsNil(t *testing.T) {
	d := NewDriver("proj")
	if got := d.ConsumedOperands("__not_a_service__"); got != nil {
		t.Fatalf("an unrecognized service must declare no operands, got %v", got)
	}
}

// TestConsumedOperandsExactSets pins the exact declared operand keys for every
// service — a spot-check catches both an under-declaration (silently refusing
// an operand the driver actually reads) and an over-declaration (accepting an
// operand nothing consumes, defeating the silent-ignore guard). Naming traps
// verified against the reader code: artifactregistry reads "kms_key" (NOT
// "kms_key_name" like every other CMEK service); cloudsql's edition/disk_type/
// flags are read in cloudsql.go; cloudfunctions-fn's vpc_connector* pair and
// environment map are read in cloudfunctionsfn.go.
func TestConsumedOperandsExactSets(t *testing.T) {
	d := NewDriver("proj")
	cases := map[string][]string{
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
		"artifactregistry":     {"kms_key"}, // naming trap: NOT kms_key_name
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
		// naming trap: the GCE key operand is kms_key_name, unlike artifactregistry's kms_key
		"gce": {"disk_size_gb", "kms_key_name", "machine_type", "source_image", "subnetwork", "zone"},
		// naming trap: a standalone disk sizes with size_gb, while the same disk as
		// a GCE boot operand is disk_size_gb — one concept, two spellings, and a
		// silently ignored operand is exactly what this registry exists to prevent
		"pd": {"disk_type", "kms_key_name", "replica_zones", "size_gb", "source_snapshot", "zone"},
		// a witness (D370) has no operands: nothing is built, so nothing is configured
		"computeimage": {},
	}
	// this test's case map must itself cover every certified service — guards
	// against a service being silently added to the map above without a
	// spot-check here.
	if len(cases) != len(gcpCertifyServices) {
		t.Fatalf("test case map has %d services, gcpCertifyServices has %d — update this test",
			len(cases), len(gcpCertifyServices))
	}
	for svc, want := range cases {
		got := d.ConsumedOperands(svc)
		gotSorted := append([]string(nil), got...)
		wantSorted := append([]string(nil), want...)
		sort.Strings(gotSorted)
		sort.Strings(wantSorted)
		if len(gotSorted) != len(wantSorted) {
			t.Errorf("%s: ConsumedOperands = %v, want %v", svc, gotSorted, wantSorted)
			continue
		}
		for i := range wantSorted {
			if gotSorted[i] != wantSorted[i] {
				t.Errorf("%s: ConsumedOperands = %v, want %v", svc, gotSorted, wantSorted)
				break
			}
		}
	}
}
