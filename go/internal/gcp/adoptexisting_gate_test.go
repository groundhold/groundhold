package gcp

import (
	"os"
	"sort"
	"testing"
)

// D413: the create-time-adoption sweep (D391-D412) was ONE CLOUD. It decided all 54 AWS
// creates and found two live defects doing it — vpngateway and apigateway, each able to
// mint a second billed resource on a re-run. GCP has 44 creates and none of them was
// ever asserted as a class.
//
// The damage model here is not the same, and saying so precisely matters. GCP resources
// are name-addressed almost everywhere, so a second create meets ALREADY_EXISTS rather
// than silently duplicating: the usual failure is a converge that HARD-FAILS against an
// estate that is already correct, not a duplicate. That is milder in money and identical
// in effect — a lost-ledger converge cannot proceed — and it is exactly what create-time
// adoption (D252/D253) exists to prevent.
//
// A static scan says roughly forty of these files handle a conflict. It also said
// thirteen did not, and it was WRONG about several of them, because it matched one
// spelling of the status check and GCS uses another (D317, again, on my own measurement).
// So membership here is not derived from a scrape: a service is gated when a test DRIVES
// its create against an estate where the resource already stands.

// adoptGatedGCP: enrolled in CertifyCreateAdoptsExisting through the public Create
// dispatch, against a fake where the resource already exists and carries our labels.
var adoptGatedGCP = map[string]string{
	"artifactregistry":     "TestAdoptsExistingARRepo",
	"bigquery":             "TestAdoptsExistingBigQuery",
	"secretmanager":        "TestAdoptsExistingSecret",
	"memorystore":          "TestAdoptsExistingMemorystore",
	"filestore":            "TestAdoptsExistingFilestore",
	"clouddns":             "TestAdoptsExistingCloudDNS",
	"cloudkms":             "TestAdoptsExistingCloudKMS",
	"cloudscheduler":       "TestAdoptsExistingCloudScheduler",
	"certmanager":          "TestAdoptsExistingCertManager",
	"firestore":            "TestAdoptsExistingFirestore",
	"customrole":           "TestAdoptsExistingCustomRole",
	"logmetric":            "TestAdoptsExistingLogMetric",
	"serviceaccount":       "TestAdoptsExistingServiceAccount",
	"cloudarmor":           "TestAdoptsExistingCloudArmor",
	"managedkafka":         "TestAdoptsExistingManagedKafka",
	"cloudrunjobs":         "TestAdoptsExistingCloudRunJob",
	"assetfeed":            "TestAdoptsExistingAssetFeed",
	"pubsub-topic":         "TestAdoptsExistingPubSubTopic",
	"gcs":                  "TestAdoptsExistingGCS",
	"billingbudget":        "TestAdoptsExistingBillingBudget",
	"backupplan":           "TestAdoptsExistingBackupPlanGCP",
	"clouddnsrecord":       "TestAdoptsExistingDNSRecord",
	"iambinding":           "TestAdoptsExistingIAMBinding",
	"gke-workloadidentity": "TestAdoptsExistingWorkloadIdentity",
	"cloudrun":             "TestAdoptsExistingCloudRun",
	"auditlogs":            "TestAdoptsExistingAuditLogs",
	"scc":                  "TestAdoptsExistingSCC",
	"vertexai":             "TestAdoptsExistingVertexAI", // D424: the enrolment that found a real bug
	"gke-addon":            "TestAdoptsExistingGKEAddon",
	"pd":                   "TestAdoptsExistingPersistentDisk",
	"mig":                  "TestAdoptsExistingMIG",
	"gce":                  "TestAdoptsExistingGCEInstance",
	"monitoring":           "TestAdoptsExistingAlertPolicy",
	"vpngateway":           "TestAdoptsExistingCloudVPN",
	"pubsub-queue":         "TestAdoptsExistingPubSubQueue",
	"cloudfunctions":       "TestAdoptsExistingCloudFunction",
	"cloudfunctions-fn":    "TestAdoptsExistingCloudFunctionFn",
	"loadbalancer":         "TestAdoptsExistingLoadBalancer",
	"backupvault":          "TestAdoptsExistingBackupVaultGCP",
	"gke":                  "TestAdoptsExistingGKE",
	"dashboard":            "TestAdoptsExistingDashboard",
	"logbucket":            "TestAdoptsExistingLogBucket",
	"uptime":               "TestAdoptsExistingUptimeCheck",
	"vpc":                  "TestAdoptsExistingVPC",
}

// adoptNotApplicableGCP: reviewed, and a re-run provably cannot duplicate OR fail. Every
// entry must name evidence a test re-derives — the rule D404 established and D412 leaned
// on. Empty until something earns it.
var adoptNotApplicableGCP = map[string]string{}

// adoptUnenrolledGCP is the DEBT. Baseline may only go DOWN, and a new create service is
// in none of the three sets, which fails the gate.
var adoptUnenrolledGCP = map[string]bool{}

const adoptUnenrolledBaselineGCP = 0

func TestEveryGCPCreateHasAnAdoptionDecision(t *testing.T) {
	raw, err := os.ReadFile("driver.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")

	var undecided, multiple []string
	for svc := range create {
		n := 0
		if _, ok := adoptGatedGCP[svc]; ok {
			n++
		}
		if _, ok := adoptNotApplicableGCP[svc]; ok {
			n++
		}
		if adoptUnenrolledGCP[svc] {
			n++
		}
		switch {
		case n == 0:
			undecided = append(undecided, svc)
		case n > 1:
			multiple = append(multiple, svc)
		}
	}
	sort.Strings(undecided)
	sort.Strings(multiple)

	if len(undecided) > 0 {
		t.Errorf("GCP create services with NO create-time-adoption decision: %v\n"+
			"A create that cannot bind an existing owned resource cannot converge against "+
			"a standing estate (D252/D253). Enroll it, or record why it cannot fail — with "+
			"evidence a test re-derives.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("GCP create services in more than one adoption set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"adoptGatedGCP":         keysOfStrGCP(adoptGatedGCP),
		"adoptNotApplicableGCP": keysOfStrGCP(adoptNotApplicableGCP),
		"adoptUnenrolledGCP":    keysOfBoolGCP(adoptUnenrolledGCP),
	} {
		var stale []string
		for _, svc := range keys {
			if !create[svc] {
				stale = append(stale, svc)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s names services the create dispatch does not have: %v", name, stale)
		}
	}
}

func TestGCPAdoptionEnrolmentRatchet(t *testing.T) {
	if n := len(adoptUnenrolledGCP); n > adoptUnenrolledBaselineGCP {
		t.Errorf("unenrolled GCP creates rose to %d (baseline %d) — the adoption gap may "+
			"only be paid down, never grown", n, adoptUnenrolledBaselineGCP)
	} else if n < adoptUnenrolledBaselineGCP {
		t.Errorf("unenrolled is down to %d — lower adoptUnenrolledBaselineGCP to %d "+
			"(this failure is the good kind)", n, n)
	}
	// The vacuity guard must watch the DISPATCH, not the unenrolled set: keyed on the
	// debt it would fire exactly when the debt reached zero, turning success into a
	// failure. Wrote it that way first — the D328 lesson catches its own author.
	raw, err := os.ReadFile("driver.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceCases(t, string(raw), "createService")) == 0 {
		t.Fatal("no create services found — the gate would be vacuous (D328)")
	}
	if len(adoptGatedGCP)+len(adoptNotApplicableGCP)+len(adoptUnenrolledGCP) == 0 {
		t.Fatal("every decision set is empty — the gate would be vacuous (D328)")
	}
}

func keysOfStrGCP(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBoolGCP(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
