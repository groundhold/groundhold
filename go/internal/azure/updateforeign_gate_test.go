package azure

import (
	"os"
	"sort"
	"testing"
)

// D460: the update register on Azure. Ten services, and the cloud where the verb bites
// hardest — an ARM update is frequently a PUT, and a PUT to an occupied path is an
// unconditional upsert (D254). Without an ownership check the update does not fail
// against a stranger's resource; it overwrites it, quietly, in place.

var updateForeignGatedAz = map[string]string{
	"loganalytics":      "TestRefusesForeignUpdateAzLogAnalytics",
	"backuppolicy":      "TestRefusesForeignUpdateAzBackupPolicy", // name-derived
	"consumptionbudget": "TestRefusesForeignUpdateAzConsumptionBudget",
	"servicebusqueue":   "TestRefusesForeignUpdateAzServiceBus", // D460: found a real bug
	"aks":               "TestRefusesForeignUpdateAzAKS",
	"dnsrecord":         "TestRefusesForeignUpdateAzDNSRecord", // parent zone is the boundary
	"acsemail":          "TestRefusesForeignUpdateAzACSEmail",
	"activitylog":       "TestRefusesForeignUpdateAzActivityLog",
}

// updateForeignNotApplicableAz: reviewed, with evidence a test re-derives (D404).
var updateForeignNotApplicableAz = map[string]string{
	"defender":  "settings-flip",
	"aks-addon": "settings-flip",
}

var updateForeignUnreviewedAz = map[string]bool{}

const updateForeignBaselineAz = 0

func azUpdateServices(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	return serviceCases(t, string(raw), "update")
}

func TestEveryAzureUpdateHasAForeignRefusalDecision(t *testing.T) {
	upds := azUpdateServices(t)

	var undecided, multiple []string
	for svc := range upds {
		n := 0
		if _, ok := updateForeignGatedAz[svc]; ok {
			n++
		}
		if _, ok := updateForeignNotApplicableAz[svc]; ok {
			n++
		}
		if updateForeignUnreviewedAz[svc] {
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
		t.Errorf("Azure update services with NO foreign-refusal decision: %v\n"+
			"An ARM PUT to an occupied path OVERWRITES rather than failing (D254), so an "+
			"update that does not check ownership first rewrites a stranger's resource "+
			"into ours and leaves it running.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("Azure update services in more than one set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"updateForeignGatedAz":         keysOfStrAz(updateForeignGatedAz),
		"updateForeignNotApplicableAz": keysOfStrAz(updateForeignNotApplicableAz),
		"updateForeignUnreviewedAz":    keysOfBoolAz(updateForeignUnreviewedAz),
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

// TestAzureUpdateExemptionsAreBacked: the D404 rule, and it also pins the two registers
// to each other — a service cannot be settings-flip on one verb and something else on
// the other without this failing.
func TestAzureUpdateExemptionsAreBacked(t *testing.T) {
	// A gate that iterates an empty map passes without checking anything — the
	// vacuity shape this repository names in D328, which I wrote into my own gate
	// while auditing everyone else for it (D488). These registers are expected to
	// hold entries; an empty one is a register that stopped being maintained.
	if len(updateForeignNotApplicableAz) == 0 {
		t.Fatal("no Azure update exemptions declared — the gate would be vacuous (D328)")
	}
	for svc, reason := range updateForeignNotApplicableAz {
		switch reason {
		case "settings-flip":
			if deleteForeignNotApplicableAz[svc] != "settings-flip" {
				t.Errorf("%s claims settings-flip on update but not on delete — the two "+
					"registers disagree about what this service is", svc)
			}
			assertAzAdoptsAnAlreadyOnFlag(t, svc)
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

func TestAzureUpdateForeignRatchet(t *testing.T) {
	if n := len(updateForeignUnreviewedAz); n > updateForeignBaselineAz {
		t.Errorf("unreviewed Azure updates rose to %d (baseline %d)", n, updateForeignBaselineAz)
	} else if n < updateForeignBaselineAz {
		t.Errorf("unreviewed is down to %d — lower updateForeignBaselineAz to %d", n, n)
	}
	if len(azUpdateServices(t)) == 0 {
		t.Fatal("no update services found — the gate would be vacuous (D328)")
	}
}
