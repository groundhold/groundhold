package gcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
)

// D451: the delete-ownership register on GCP. The AWS half (D439-D450) decided all 54
// deletes and found FIVE live defects, every one on a service where the provider offers
// no tags: the deterministic NAME was already ownership evidence for the create path and
// forgotten by the delete path. GCP has 44 deletes and the same shape exists here.
//
// The question is the mirror of the adoption sweep's: when the resource at this
// providerId is NOT ours, does the driver refuse to delete it? Neither property implies
// the other, and this is the half where being wrong cannot be undone.

var deleteForeignGatedGCP = map[string]string{
	"customrole":       "TestRefusesForeignDeleteCustomRoleGCP", // D451: found a real bug
	"assetfeed":        "TestRefusesForeignDeleteAssetFeed",     // D451: found a real bug
	"artifactregistry": "TestRefusesForeignDeleteARRepo",
	"certmanager":      "TestRefusesForeignDeleteCertManager",
	"cloudarmor":       "TestRefusesForeignDeleteCloudArmor",
	"clouddns":         "TestRefusesForeignDeleteCloudDNS",
	"cloudkms":         "TestRefusesForeignDeleteCloudKMS",
	"managedkafka":     "TestRefusesForeignDeleteManagedKafka",
	"memorystore":      "TestRefusesForeignDeleteMemorystore",
	"secretmanager":    "TestRefusesForeignDeleteSecretGCP",
	"backupplan":       "TestRefusesForeignDeleteBackupPlanGCP",
	"backupvault":      "TestRefusesForeignDeleteBackupVaultGCP",
	"bigquery":         "TestRefusesForeignDeleteBigQuery",
	"cloudrunjobs":     "TestRefusesForeignDeleteCloudRunJob",
	"cloudscheduler":   "TestRefusesForeignDeleteCloudScheduler",
	"logmetric":        "TestRefusesForeignDeleteLogMetric",
	"serviceaccount":   "TestRefusesForeignDeleteServiceAccount",
	"vpngateway":       "TestRefusesForeignDeleteCloudVPN",
	// D454: the batch that finished the label-carrying majority.
	"cloudrun":          "TestRefusesForeignDeleteCloudRunGCP",
	"filestore":         "TestRefusesForeignDeleteFilestore",
	"clouddnsrecord":    "TestRefusesForeignDeleteDNSRecordGCP",
	"monitoring":        "TestRefusesForeignDeleteAlertPolicy",
	"dashboard":         "TestRefusesForeignDeleteDashboard", // no labels: displayName is all of it
	"uptime":            "TestRefusesForeignDeleteUptimeCheck",
	"pubsub-topic":      "TestRefusesForeignDeletePubSubTopic",
	"pubsub-queue":      "TestRefusesForeignDeletePubSubQueue",
	"cloudfunctions":    "TestRefusesForeignDeleteCloudFunction",
	"cloudfunctions-fn": "TestRefusesForeignDeleteCloudFunctionFn",
	"vpc":               "TestRefusesForeignDeleteVPC", // no labels: description marker
	"billingbudget":     "TestRefusesForeignDeleteBillingBudget",
	// D455: the remainder that had a check to prove.
	"gce":          "TestRefusesForeignDeleteGCE",
	"pd":           "TestRefusesForeignDeletePD",
	"mig":          "TestRefusesForeignDeleteMIG",
	"logbucket":    "TestRefusesForeignDeleteLogBucket",
	"gcs":          "TestRefusesForeignDeleteGCSBucket", // live projectNumber, not a label (D82)
	"vertexai":     "TestRefusesForeignDeleteVertexAI",
	"gke":          "TestRefusesForeignDeleteGKECluster",
	"auditlogs":    "TestRefusesForeignDeleteAuditSink",
	"firestore":    "TestRefusesForeignDeleteFirestore", // content-addressed id, no read possible
	"loadbalancer": "TestRefusesForeignDeleteLoadBalancer",
}

// deleteForeignNotApplicableGCP: reviewed, with evidence a test re-derives (D404).
// These are the shapes the foreign-delete probe cannot fit, and the two classes are not
// equally comfortable — see D456.
var deleteForeignNotApplicableGCP = map[string]string{
	"iambinding":           "member-scoped",
	"gke-workloadidentity": "member-scoped",
	"scc":                  "settings-flip",
	"gke-addon":            "settings-flip",
}

var deleteForeignUnreviewedGCP = map[string]bool{}

const deleteForeignBaselineGCP = 0

func TestEveryGCPDeleteHasAForeignRefusalDecision(t *testing.T) {
	raw, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatal(err)
	}
	del := serviceCases(t, string(raw), "Delete")
	// D488: an empty dispatch decides nothing and this test reported success. The
	// sibling registers were protected only ACCIDENTALLY, by a stale-check that
	// fires when the registry names services the dispatch lacks — these two had no
	// such check and passed vacuously. Assert the subject explicitly rather than
	// relying on another assertion's side effect.
	if len(del) == 0 {
		t.Fatal("no GCP delete services parsed — the gate would be vacuous (D328)")
	}

	var undecided, multiple []string
	for svc := range del {
		n := 0
		if _, ok := deleteForeignGatedGCP[svc]; ok {
			n++
		}
		if _, ok := deleteForeignNotApplicableGCP[svc]; ok {
			n++
		}
		if deleteForeignUnreviewedGCP[svc] {
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
		t.Errorf("GCP delete services with NO foreign-refusal decision: %v\n"+
			"A delete that trusts its providerId can destroy a resource that was never "+
			"ours, and nothing later undoes that.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("GCP delete services in more than one set: %v", multiple)
	}
}

func TestGCPDeleteForeignRatchet(t *testing.T) {
	if n := len(deleteForeignUnreviewedGCP); n > deleteForeignBaselineGCP {
		t.Errorf("unreviewed GCP deletes rose to %d (baseline %d)", n, deleteForeignBaselineGCP)
	} else if n < deleteForeignBaselineGCP {
		t.Errorf("unreviewed is down to %d — lower deleteForeignBaselineGCP to %d "+
			"(this failure is the good kind)", n, n)
	}
	raw, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceCases(t, string(raw), "Delete")) == 0 {
		t.Fatal("no delete services found — the gate would be vacuous (D328)")
	}
}

// TestGCPDeleteForeignExemptionsAreBacked is the D404 rule on the delete side: an
// exemption must name evidence this gate RE-DERIVES, and free text is refused outright.
func TestGCPDeleteForeignExemptionsAreBacked(t *testing.T) {
	if len(deleteForeignNotApplicableGCP) == 0 {
		t.Skip("nothing claimed not-applicable")
	}
	for svc, reason := range deleteForeignNotApplicableGCP {
		switch reason {
		case "member-scoped":
			// The delete removes exactly ONE member from a shared policy, identified by
			// the providerId. There is no resource to own, and a foreign member in the
			// same role must survive. Driven, not asserted.
			assertForeignMemberSurvives(t, svc)
		case "settings-flip":
			// The delete returns a project- or cluster-level FLAG to its default. There
			// is no per-resource ownership surface in the API, so the probe's question
			// ("is this resource ours?") has no answer to read. What the gate can and
			// does re-derive is the shape that makes the exemption necessary: the CREATE
			// treats an already-on flag as an idempotent success without mutating, which
			// is exactly why a later delete cannot tell "we turned it on" from "it was
			// already on". D456 names that gap rather than papering over it.
			assertAdoptsAnAlreadyOnFlag(t, svc)
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

// assertForeignMemberSurvives drives the member-scoped delete against a policy that also
// holds a STRANGER's member in the same role, and requires that member to survive. This
// is the authorization analogue of a foreign-delete refusal: there is no resource to
// refuse, so the property is that the blast radius is exactly one member wide.
func assertForeignMemberSurvives(t *testing.T, svc string) {
	t.Helper()
	switch svc {
	case "iambinding":
		seed := `{"bindings":[{"role":"roles/storage.objectViewer","members":[` +
			`"serviceAccount:runner@acme-prod.iam.gserviceaccount.com",` +
			`"serviceAccount:someone-else@acme-prod.iam.gserviceaccount.com"]}],"etag":"BwXseed"}`
		srv := crmPolicyServer(t, seed)
		defer srv.Close()
		d := authzDriver(t, srv)
		pid := "gauth:acme-prod:roles/storage.objectViewer:" +
			"serviceAccount:runner@acme-prod.iam.gserviceaccount.com"
		if del := d.deleteIAMBinding("reader", "prod", pid); del.Status != "succeeded" {
			t.Fatalf("iambinding delete: %+v", del)
		}
		other := "gauth:acme-prod:roles/storage.objectViewer:" +
			"serviceAccount:someone-else@acme-prod.iam.gserviceaccount.com"
		if _, diags, _ := d.observeIAMBinding("reader", other); len(diags) != 0 {
			t.Errorf("iambinding claims member-scoped, but deleting our grant disturbed "+
				"another principal's grant in the same role: %v", diags)
		}
	case "gke-workloadidentity":
		foreign := "serviceAccount:other-proj.svc.id.goog[team/other-sa]"
		ours := wiMember("acme-prod", "default", "app-sa")
		seed := &iamPolicy{Etag: "BwXseed", Bindings: []iamPolicyBinding{
			{Role: wiRole, Members: []string{ours, foreign}},
		}}
		srv := saPolicyServer(t, seed, false)
		defer srv.Close()
		d := wiDriver(t, srv)
		if del := d.deleteGKEWorkloadIdentity("runner", "prod", wiPID()); del.Status != "succeeded" {
			t.Fatalf("gke-workloadidentity delete: %+v", del)
		}
		pol, perr := d.saGetIamPolicy(wiGSA)
		if perr != nil {
			t.Fatalf("policy read gave no answer: %v", perr)
		}
		if !memberInRole(pol, wiRole, foreign) {
			t.Error("gke-workloadidentity claims member-scoped, but the delete clobbered " +
				"a foreign member of the same role")
		}
		if memberInRole(pol, wiRole, ours) {
			t.Error("our own member was not removed — the delete did nothing")
		}
	default:
		t.Errorf("%s claims member-scoped but this gate has no way to drive it", svc)
	}
}

// assertAdoptsAnAlreadyOnFlag re-derives the shape that MAKES the settings-flip exemption
// necessary, which is not the same as proving the delete is safe — and D456 says so. A
// create that meets an already-on flag reports success without mutating, so the flag it
// "owns" may be one a stranger turned on, and the retirement that turns it off cannot
// tell the difference. The gate pins the shape so the day someone changes it, this
// exemption is re-examined rather than inherited.
func assertAdoptsAnAlreadyOnFlag(t *testing.T, svc string) {
	t.Helper()
	switch svc {
	case "scc":
		f := newFakeSCC("ENABLED", "ENABLED", "ENABLED")
		srv := f.handler(t)
		defer srv.Close()
		d := sccDriver(t, srv)
		res := d.createSCC(sccCap, "prod", sccAttrs(true, true, true), sccImpl(), 1)
		if res.Status != "succeeded" {
			t.Fatalf("scc create over an already-enabled posture: %+v", res)
		}
		if len(f.order) != 0 {
			t.Errorf("scc create mutated %v over an already-enabled posture — the "+
				"settings-flip exemption assumes it adopts silently", f.order)
		}
	case "gke-addon":
		// A cluster whose addon is already ON. Any mutation is a gate failure: the
		// exemption rests on the create adopting the flag silently.
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("gke-addon create %s %s over an already-enabled addon — the "+
						"settings-flip exemption assumes it adopts silently",
						r.Method, r.URL.Path)
					w.WriteHeader(400)
					return
				}
				_, _ = w.Write([]byte(`{"name":"acme-eks","status":"RUNNING",` +
					`"addonsConfig":{"gcePersistentDiskCsiDriverConfig":{"enabled":true}}}`))
			}))
		defer srv.Close()
		d := gkeAddonDriver(t, srv)
		res := d.createGKEAddon("csi", "prod", gkeAddonAttrs(), gkeAddonImpl(), 1)
		if res.Status != "succeeded" {
			t.Fatalf("gke-addon create over an already-enabled addon: %+v", res)
		}
	default:
		t.Errorf("%s claims settings-flip but this gate has no way to drive it", svc)
	}
}
