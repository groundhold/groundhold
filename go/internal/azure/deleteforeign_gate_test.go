package azure

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
)

// D457: the third and last delete register. AWS closed at 54 decided (D439-D450), GCP at
// 44 (D451-D456), and between them the sweep found six live defects — every one of them a
// service whose provider offers NO tags, where the deterministic name was ownership
// evidence for create and forgotten by delete.
//
// Azure is the cloud where getting this wrong is least recoverable. An ARM DELETE takes a
// resourceId and nothing else: there is no if-match-on-tags, no conditional delete, no
// server-side notion of who owns what. Whatever refuses must refuse HERE, in the driver,
// before the request. The create side already learned this the hard way (D254: a PUT to
// an occupied path is an unconditional upsert, so a create could take over a stranger's
// resource); the delete side has the same API shape and worse consequences.

// deleteForeignGatedAz: driven through the public Delete dispatch against a fake where
// the resource EXISTS carrying a stranger's ownership markers.
var deleteForeignGatedAz = map[string]string{
	"azkafka":           "TestRefusesForeignDeleteAzAzkafka",
	"rediscache":        "TestRefusesForeignDeleteAzRediscache",
	"azurecdn":          "TestRefusesForeignDeleteAzAzurecdn",
	"containerappsjob":  "TestRefusesForeignDeleteAzContainerappsjob",
	"keyvault":          "TestRefusesForeignDeleteAzKeyvault",
	"azurefiles":        "TestRefusesForeignDeleteAzAzurefiles",
	"eventhubs":         "TestRefusesForeignDeleteAzEventhubs",
	"cosmos":            "TestRefusesForeignDeleteAzCosmos",
	"apim":              "TestRefusesForeignDeleteAzApim",
	"keyvaultkey":       "TestRefusesForeignDeleteAzKeyvaultkey",
	"containerapps":     "TestRefusesForeignDeleteAzContainerapps",
	"consumptionbudget": "TestRefusesForeignDeleteAzConsumptionbudget", // name-derived
	"aisearch":          "TestRefusesForeignDeleteAzAisearch",
	"loganalytics":      "TestRefusesForeignDeleteAzLoganalytics",
	"managedidentity":   "TestRefusesForeignDeleteAzManagedidentity",
	"servicebusqueue":   "TestRefusesForeignDeleteAzServicebusqueue",
	"flexpostgres":      "TestRefusesForeignDeleteAzFlexpostgres",
	"blob":              "TestRefusesForeignDeleteAzBlob",
	"frontdoorwaf":      "TestRefusesForeignDeleteAzFrontdoorwaf",
	"backuppolicy":      "TestRefusesForeignDeleteAzBackuppolicy", // name-derived
	// D458: the second batch — monitoring, DNS, the registry, the network edge, AKS.
	"metricalert":     "TestRefusesForeignDeleteAzMetricalert",
	"scheduledquery":  "TestRefusesForeignDeleteAzScheduledquery",
	"webtest":         "TestRefusesForeignDeleteAzWebtest",
	"portaldash":      "TestRefusesForeignDeleteAzPortaldash",
	"dnszone":         "TestRefusesForeignDeleteAzDnszone",
	"dnsrecord":       "TestRefusesForeignDeleteAzDnsrecord",
	"acr":             "TestRefusesForeignDeleteAzAcr",
	"vnet":            "TestRefusesForeignDeleteAzVnet",
	"servicebustopic": "TestRefusesForeignDeleteAzServicebustopic",
	"backupvault":     "TestRefusesForeignDeleteAzBackupvault",
	"azureopenai":     "TestRefusesForeignDeleteAzAzureopenai",
	"loadbalancer":    "TestRefusesForeignDeleteAzLoadbalancer",
	"aks":             "TestRefusesForeignDeleteAzAks",
	// D458: compute, the two name-only objects, and the authorization pair.
	"azdisk":               "TestRefusesForeignDeleteAzDisk",
	"azvmss":               "TestRefusesForeignDeleteAzVmss",
	"azvm":                 "TestRefusesForeignDeleteAzVm",
	"acsemail":             "TestRefusesForeignDeleteAzAcsemail",
	"activitylog":          "TestRefusesForeignDeleteAzActivitylog",    // D458: found a real bug
	"changefeed":           "TestRefusesForeignDeleteAzChangefeed",     // D458: found a real bug
	"customroledef":        "TestRefusesForeignDeleteAzCustomroledef",  // D458: found a real bug
	"roleassignment":       "TestRefusesForeignDeleteAzRoleassignment", // D458: found a real bug
	"aks-workloadidentity": "TestRefusesForeignDeleteAzAksWorkloadidentity",
}

// deleteForeignNotApplicableAz: reviewed, with evidence a test re-derives (D404).
var deleteForeignNotApplicableAz = map[string]string{
	"azimage":   "witness-only", // no create, so no delete to own anything with
	"defender":  "settings-flip",
	"aks-addon": "settings-flip",
}

// deleteForeignUnreviewedAz is the DEBT. Baseline may only go DOWN.
var deleteForeignUnreviewedAz = map[string]bool{}

const deleteForeignBaselineAz = 0

func TestEveryAzureDeleteHasAForeignRefusalDecision(t *testing.T) {
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	del := serviceCases(t, string(raw), "Delete")

	var undecided, multiple []string
	for svc := range del {
		n := 0
		if _, ok := deleteForeignGatedAz[svc]; ok {
			n++
		}
		if _, ok := deleteForeignNotApplicableAz[svc]; ok {
			n++
		}
		if deleteForeignUnreviewedAz[svc] {
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
		t.Errorf("Azure delete services with NO foreign-refusal decision: %v\n"+
			"An ARM DELETE carries no ownership precondition — whatever refuses must "+
			"refuse in the driver, before the request.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("Azure delete services in more than one set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"deleteForeignGatedAz":         keysOfStrAz(deleteForeignGatedAz),
		"deleteForeignNotApplicableAz": keysOfStrAz(deleteForeignNotApplicableAz),
		"deleteForeignUnreviewedAz":    keysOfBoolAz(deleteForeignUnreviewedAz),
	} {
		var stale []string
		for _, svc := range keys {
			if !del[svc] {
				stale = append(stale, svc)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s names services the Delete dispatch does not have: %v", name, stale)
		}
	}
}

func TestAzureDeleteForeignRatchet(t *testing.T) {
	if n := len(deleteForeignUnreviewedAz); n > deleteForeignBaselineAz {
		t.Errorf("unreviewed Azure deletes rose to %d (baseline %d)", n, deleteForeignBaselineAz)
	} else if n < deleteForeignBaselineAz {
		t.Errorf("unreviewed is down to %d — lower deleteForeignBaselineAz to %d "+
			"(this failure is the good kind)", n, n)
	}
	// The vacuity guard watches the DISPATCH, never the debt (D413).
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceCases(t, string(raw), "Delete")) == 0 {
		t.Fatal("no delete services found — the gate would be vacuous (D328)")
	}
}

// TestAzureDeleteForeignExemptionsAreBacked is the D404 rule: an exemption must name
// evidence this gate RE-DERIVES, and free text is refused outright.
func TestAzureDeleteForeignExemptionsAreBacked(t *testing.T) {
	if len(deleteForeignNotApplicableAz) == 0 {
		t.Skip("nothing claimed not-applicable")
	}
	for svc, reason := range deleteForeignNotApplicableAz {
		switch reason {
		case "witness-only":
			d := NewDriver(testSub)
			d.token = "test-token"
			res := d.Delete(svc, "c", "prod", svc+":"+testSub+":rg1:x", "k")
			if res.Status != "failed" ||
				!strings.Contains(strings.ToLower(res.Reason), "witness") {
				t.Errorf("%s claims witness-only, but its delete did not refuse as one: %+v",
					svc, res)
			}
		case "settings-flip":
			// The same class GCP's scc/gke-addon fall into (D456): "create" turns a
			// subscription- or cluster-level FLAG on and retirement turns it off, so
			// there is no resource to own and no marker to read. The gap is real and
			// named in MATURITY; what the gate re-derives is the shape that makes the
			// exemption necessary — the create adopts an already-on flag silently, which
			// is exactly why the delete cannot tell "we set this" from "it was set".
			assertAzAdoptsAnAlreadyOnFlag(t, svc)
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

// assertAzAdoptsAnAlreadyOnFlag mirrors the GCP helper (D456): it re-derives the SHAPE
// that makes the settings-flip exemption necessary rather than claiming the delete is
// safe. A create meeting an already-on flag reports success without mutating, so the
// flag it "owns" may be one a stranger set, and the retirement cannot tell.
func assertAzAdoptsAnAlreadyOnFlag(t *testing.T, svc string) {
	t.Helper()
	switch svc {
	case "defender":
		// Reach the desired posture with a real create, then run the SAME create again:
		// a stricter re-derivation than seeding a guess, because it proves the second
		// pass is a no-op against the estate the first pass produced.
		f := newFakeDefender("Free", "Free", "Free")
		srv := f.handler(t)
		defer srv.Close()
		d := defenderDriver(t, srv)
		attrs := defenderAttrs(true, true, false)
		if first := d.Create(svc, defenderCap, "prod", attrs, nil, "k", 1); first.Status != "succeeded" {
			t.Fatalf("defender create: %+v", first)
		}
		f.order = nil
		res := d.Create(svc, defenderCap, "prod", attrs, nil, "k", 1)
		if res.Status != "succeeded" {
			t.Fatalf("defender create over an already-Standard posture: %+v", res)
		}
		if len(f.order) != 0 {
			t.Errorf("defender create mutated plans %v over an already-Standard posture "+
				"— the settings-flip exemption assumes it adopts silently", f.order)
		}
	case "aks-addon":
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("aks-addon create %s %s over an already-enabled addon — the "+
						"settings-flip exemption assumes it adopts silently",
						r.Method, r.URL.Path)
					w.WriteHeader(400)
					return
				}
				_, _ = w.Write([]byte(`{"name":"acme-aks","location":"westeurope",` +
					`"properties":{"provisioningState":"Succeeded","addonProfiles":{` +
					`"azureKeyvaultSecretsProvider":{"enabled":true}}}}`))
			}))
		defer srv.Close()
		d := aksAddonDriver(t, srv)
		res := d.Create(svc, "csi", "prod", aksAddonAttrs(), aksAddonImpl(), "k", 1)
		if res.Status != "succeeded" {
			t.Fatalf("aks-addon create over an already-enabled addon: %+v", res)
		}
	default:
		t.Errorf("%s claims settings-flip but this gate has no way to drive it", svc)
	}
}
