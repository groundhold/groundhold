package azure

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// D431: the third and last cloud. AWS finished at 54 creates decided (D411), GCP at 44
// (D430), and three live defects were found doing it — vpngateway, apigateway, vertexai,
// each able to mint a second billed resource on a re-run. Azure has 45 creates and none
// of them has ever been asserted as a class.
//
// **The damage model is different again, and Azure's is the subtlest of the three.** An
// ARM create is a PUT to a resource PATH, which is idempotent by construction: a re-run
// cannot duplicate, because the path IS the identity. So the question this sweep has been
// asking on the other two clouds — can a re-run mint a second resource — has a structural
// answer here, and D253 said so ("Azure PUT is idempotent by path — the class does not
// apply off AWS").
//
// What that structure buys in safety it spends elsewhere. A PUT to an occupied path does
// not fail; it OVERWRITES. So Azure's risk is not a duplicate but a takeover: a converge
// that finds someone else's resource at our deterministic path and rewrites it into ours.
// D254 built the defence — an ownership pre-read before the PUT — and this ratchet is
// where it stops being per-driver care and becomes a class.
//
// So on Azure the gate asserts a slightly different property with the same instrument: a
// create meeting an OURS resource must bind it, and the driver-level foreign-resource
// tests must exist to say what happens when it is not ours. Both halves matter more here
// than anywhere, because the API will happily do the wrong thing on request.

// adoptGatedAz: enrolled in CertifyCreateAdoptsExisting through the public Create
// dispatch, against a fake where the resource already exists carrying our tags.
var adoptGatedAz = map[string]string{
	"vnet":                 "TestAdoptsExistingVNet",
	"cosmos":               "TestAdoptsExistingCosmos",
	"blob":                 "TestAdoptsExistingBlob",
	"acr":                  "TestAdoptsExistingACR",
	"azkafka":              "TestAdoptsExistingAzKafka",
	"azurefiles":           "TestAdoptsExistingAzFiles",
	"eventhubs":            "TestAdoptsExistingEventHubs",
	"flexpostgres":         "TestAdoptsExistingFlexPostgres",
	"loganalytics":         "TestAdoptsExistingLogAnalytics",
	"rediscache":           "TestAdoptsExistingRedisAzure",
	"servicebusqueue":      "TestAdoptsExistingServiceBusQueue",
	"aisearch":             "TestAdoptsExistingAISearch",
	"apim":                 "TestAdoptsExistingAPIM",
	"azurecdn":             "TestAdoptsExistingAzureCDN",
	"containerapps":        "TestAdoptsExistingContainerApp",
	"containerappsjob":     "TestAdoptsExistingContainerAppsJob",
	"customroledef":        "TestAdoptsExistingCustomRoleDef",
	"frontdoorwaf":         "TestAdoptsExistingFrontDoorWAF",
	"keyvault":             "TestAdoptsExistingKeyVault",
	"keyvaultkey":          "TestAdoptsExistingKeyVaultKey",
	"metricalert":          "TestAdoptsExistingMetricAlert",
	"portaldash":           "TestAdoptsExistingPortalDash",
	"scheduledquery":       "TestAdoptsExistingScheduledQuery",
	"webtest":              "TestAdoptsExistingWebtest",
	"acsemail":             "TestAdoptsExistingACSEmail",
	"activitylog":          "TestAdoptsExistingActivityLog",
	"aks-addon":            "TestAdoptsExistingAKSAddon",
	"backuppolicy":         "TestAdoptsExistingBackupPolicy",
	"backupvault":          "TestAdoptsExistingAzBackupVault",
	"consumptionbudget":    "TestAdoptsExistingConsumptionBudget",
	"dnsrecord":            "TestAdoptsExistingAzureDNSRecord",
	"dnszone":              "TestAdoptsExistingAzureDNSZone",
	"managedidentity":      "TestAdoptsExistingManagedIdentity",
	"roleassignment":       "TestAdoptsExistingRoleAssignment",
	"servicebustopic":      "TestAdoptsExistingServiceBusTopic",
	"aks":                  "TestAdoptsExistingAKS",
	"aks-workloadidentity": "TestAdoptsExistingAKSWorkloadIdentity",
	"changefeed":           "TestAdoptsExistingChangeFeedAz",
	"azdisk":               "TestAdoptsExistingAzureDisk",
	"azvmss":               "TestAdoptsExistingAzureVMSS",
	"azureopenai":          "TestAdoptsExistingAzureOpenAI",
	"defender":             "TestAdoptsExistingDefender",
	"loadbalancer":         "TestAdoptsExistingAppGateway",
	"azvm":                 "TestAdoptsExistingAzureVM",
}

// adoptNotApplicableAz: reviewed, with evidence a test re-derives (the D404 rule). Empty
// until something earns it.
var adoptNotApplicableAz = map[string]string{
	"azimage": "witness-only",
}

// adoptUnenrolledAz is the DEBT. Baseline may only go DOWN; a new create service lands in
// none of the three sets and fails the gate.
var adoptUnenrolledAz = map[string]bool{}

const adoptUnenrolledBaselineAz = 0

func TestEveryAzureCreateHasAnAdoptionDecision(t *testing.T) {
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")

	var undecided, multiple []string
	for svc := range create {
		n := 0
		if _, ok := adoptGatedAz[svc]; ok {
			n++
		}
		if _, ok := adoptNotApplicableAz[svc]; ok {
			n++
		}
		if adoptUnenrolledAz[svc] {
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
		t.Errorf("Azure create services with NO create-time-adoption decision: %v\n"+
			"An ARM PUT to an occupied path OVERWRITES rather than failing, so a create "+
			"that does not check ownership first can rewrite a stranger's resource into "+
			"ours (D254). Enroll it, or record why it cannot — with evidence.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("Azure create services in more than one adoption set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"adoptGatedAz":         keysOfStrAz(adoptGatedAz),
		"adoptNotApplicableAz": keysOfStrAz(adoptNotApplicableAz),
		"adoptUnenrolledAz":    keysOfBoolAz(adoptUnenrolledAz),
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

// TestAzureNotApplicableClaimsAreBacked mirrors the AWS rule (D404/D411): an exemption
// must name evidence this gate re-derives, and free text is refused outright.
func TestAzureNotApplicableClaimsAreBacked(t *testing.T) {
	if len(adoptNotApplicableAz) == 0 {
		t.Skip("nothing claimed not-applicable")
	}
	for svc, reason := range adoptNotApplicableAz {
		switch reason {
		case "witness-only":
			// There is no create to adopt into. Driven, not asserted.
			d := NewDriver(testSub)
			d.token = "test-token"
			res := d.Create(svc, "c", "prod",
				map[string]any{"location.region": "eastus"}, nil, "k", 1)
			if res.Status != "failed" || !strings.Contains(strings.ToLower(res.Reason), "witness") {
				t.Errorf("%s claims it is witness-only, but its create did not refuse as "+
					"one: %+v", svc, res)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

func TestAzureAdoptionEnrolmentRatchet(t *testing.T) {
	if n := len(adoptUnenrolledAz); n > adoptUnenrolledBaselineAz {
		t.Errorf("unenrolled Azure creates rose to %d (baseline %d) — the adoption gap may "+
			"only be paid down, never grown", n, adoptUnenrolledBaselineAz)
	} else if n < adoptUnenrolledBaselineAz {
		t.Errorf("unenrolled is down to %d — lower adoptUnenrolledBaselineAz to %d "+
			"(this failure is the good kind)", n, n)
	}
	// The vacuity guard watches the DISPATCH, never the debt (D413: keyed on the debt it
	// would fire exactly when the debt reached zero).
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceCases(t, string(raw), "createService")) == 0 {
		t.Fatal("no create services found — the gate would be vacuous (D328)")
	}
}

func keysOfStrAz(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBoolAz(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
