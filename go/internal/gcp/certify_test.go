package gcp

import (
	"testing"

	"groundhold/internal/provider"
)

// gcpCertifyServices is the authoritative set of SERVICE tokens the GCP driver
// observes/provisions — both certification gates run over the same set.
var gcpCertifyServices = []string{"loadbalancer", "assetfeed", "cloudsql", "cloudrun", "gcs", "vpc", "cloudfunctions", "cloudfunctions-fn", "pubsub-topic", "pubsub-queue", "secretmanager", "memorystore", "clouddns", "clouddnsrecord", "iambinding", "customrole", "monitoring", "dashboard", "uptime", "logmetric", "artifactregistry", "filestore", "firestore", "managedkafka", "cloudarmor", "certmanager", "cloudrunjobs", "serviceaccount", "bigquery", "cloudscheduler", "cloudkms", "vpngateway", "backupvault", "billingbudget", "logbucket", "auditlogs", "scc", "vertexai", "gke", "gke-addon", "gke-workloadidentity", "backupplan", "gce", "pd", "computeimage", "mig"}

// The GCP driver must pass the driver-agnostic certification (fail-closed
// dispatch + well-formed permission tables for every service it declares).
func TestGCPDriverCertification(t *testing.T) {
	provider.CertifyDriver(t, NewDriver("proj"), gcpCertifyServices)
}

// TestGCPDiscoverabilityComplete enforces spec/drivers.md §2: every observable
// GCP service is either covered by a List sweep or a declared non-listable feed.
func TestGCPDiscoverabilityComplete(t *testing.T) {
	provider.CertifyDiscoverability(t, NewDriver("proj"), gcpCertifyServices)
}

// TestGCPParityComplete enforces spec/drivers.md §8: every certified GCP service
// declares the capability TYPE it fulfils, so the parity matrix is proven.
func TestGCPParityComplete(t *testing.T) {
	provider.CertifyParity(t, NewDriver("proj"), gcpCertifyServices)
}
