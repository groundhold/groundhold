package gcp

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D460: the update register on GCP. See D459 for the argument; the shape here differs in
// one honest way. GCP's update dispatch is an if-chain, and nine of its twenty-two
// services land in a single categorical refusal — "in-place update is not wired yet" —
// with a tenth (loadbalancer) refusing in the same spirit for its own reasons. Those are
// not gaps in ownership: there is no update to take anything over WITH.

var updateForeignGatedGCP = map[string]string{
	"gcs":            "TestRefusesForeignUpdateGCS",
	"pubsub-topic":   "TestRefusesForeignUpdatePubSubTopic",
	"pubsub-queue":   "TestRefusesForeignUpdatePubSubQueue",
	"secretmanager":  "TestRefusesForeignUpdateSecret",
	"logbucket":      "TestRefusesForeignUpdateLogBucketGCP",
	"clouddnsrecord": "TestRefusesForeignUpdateDNSRecordGCP", // parent zone is the boundary
	"gke":            "TestRefusesForeignUpdateGKE",
	"backupplan":     "TestRefusesForeignUpdateBackupPlanGCP",
	"billingbudget":  "TestRefusesForeignUpdateBillingBudget",
	"auditlogs":      "TestRefusesForeignUpdateAuditSink",
}

// updateForeignNotApplicableGCP: reviewed, with evidence a test re-derives (D404).
var updateForeignNotApplicableGCP = map[string]string{
	"cloudrun":          "no-in-place-update",
	"vpc":               "no-in-place-update",
	"cloudfunctions":    "no-in-place-update",
	"cloudfunctions-fn": "no-in-place-update",
	"bigquery":          "no-in-place-update",
	"cloudscheduler":    "no-in-place-update",
	"vpngateway":        "no-in-place-update",
	"backupvault":       "no-in-place-update",
	"assetfeed":         "no-in-place-update",
	"loadbalancer":      "no-in-place-update",
	"gke-addon":         "settings-flip",
	"scc":               "settings-flip",
}

var updateForeignUnreviewedGCP = map[string]bool{}

const updateForeignBaselineGCP = 0

// gcpUpdateServices reads the if-chain dispatch rather than a case switch, because that
// is what the GCP driver has. Asserting on the real shape beats reshaping the driver to
// suit the gate.
func gcpUpdateServices(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "func (d *Driver) update(")
	if i < 0 {
		t.Fatal("update dispatch not found — the gate would be vacuous (D328)")
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j > 0 {
		body = body[:j]
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`service == "([a-z0-9-]+)"`).FindAllStringSubmatch(body, -1) {
		out[m[1]] = true
	}
	return out
}

func TestEveryGCPUpdateHasAForeignRefusalDecision(t *testing.T) {
	upds := gcpUpdateServices(t)

	var undecided, multiple []string
	for svc := range upds {
		n := 0
		if _, ok := updateForeignGatedGCP[svc]; ok {
			n++
		}
		if _, ok := updateForeignNotApplicableGCP[svc]; ok {
			n++
		}
		if updateForeignUnreviewedGCP[svc] {
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
		t.Errorf("GCP update services with NO foreign-refusal decision: %v\n"+
			"A PATCH that trusts its providerId leaves a stranger's resource running "+
			"with our configuration in it. Enroll it, or record why it cannot.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("GCP update services in more than one set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"updateForeignGatedGCP":         keysOfStrGCP(updateForeignGatedGCP),
		"updateForeignNotApplicableGCP": keysOfStrGCP(updateForeignNotApplicableGCP),
		"updateForeignUnreviewedGCP":    keysOfBoolGCP(updateForeignUnreviewedGCP),
	} {
		var stale []string
		for _, svc := range keys {
			if !upds[svc] {
				stale = append(stale, svc)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s names services the update dispatch does not have: %v", name, stale)
		}
	}
}

// TestGCPUpdateExemptionsAreBacked: the D404 rule, driven.
func TestGCPUpdateExemptionsAreBacked(t *testing.T) {
	// A gate that iterates an empty map passes without checking anything — the
	// vacuity shape this repository names in D328, which I wrote into my own gate
	// while auditing everyone else for it (D488). These registers are expected to
	// hold entries; an empty one is a register that stopped being maintained.
	if len(updateForeignNotApplicableGCP) == 0 {
		t.Fatal("no GCP update exemptions declared — the gate would be vacuous (D328)")
	}
	for svc, reason := range updateForeignNotApplicableGCP {
		switch reason {
		case "no-in-place-update":
			// There is no update to take anything over WITH. The refusal must be
			// categorical — reached before any providerId or estate is consulted.
			t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
			d := NewDriver("acme-prod")
			res := d.Update(svc, "c", "prod", svc+":acme-prod:x",
				map[string]any{"location.region": "europe-west1"}, nil,
				[]string{"location.region"}, "k")
			if res.Status != "failed" ||
				!strings.Contains(res.Reason, "in-place update is not wired") {
				t.Errorf("%s claims no-in-place-update, but its update did not refuse as "+
					"one: %+v", svc, res)
			}
		case "settings-flip":
			// The class D456 named: "create" turns a flag on, so there is no resource to
			// own and no marker to read. Re-derived on the create side by the delete
			// register's own exemption gate — named here so the two registers cannot
			// drift into disagreeing about what these services are.
			if _, ok := deleteForeignNotApplicableGCP[svc]; !ok {
				t.Errorf("%s claims settings-flip on update but not on delete — the two "+
					"registers disagree about what this service is", svc)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

func TestGCPUpdateForeignRatchet(t *testing.T) {
	if n := len(updateForeignUnreviewedGCP); n > updateForeignBaselineGCP {
		t.Errorf("unreviewed GCP updates rose to %d (baseline %d)", n, updateForeignBaselineGCP)
	} else if n < updateForeignBaselineGCP {
		t.Errorf("unreviewed is down to %d — lower updateForeignBaselineGCP to %d", n, n)
	}
	if len(gcpUpdateServices(t)) == 0 {
		t.Fatal("no update services found — the gate would be vacuous (D328)")
	}
}
