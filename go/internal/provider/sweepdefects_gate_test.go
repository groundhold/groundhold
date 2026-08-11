package provider_test

import (
	"fmt"
	"sort"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
)

// D464: the sweep's own count, published once. Extended by D472 to cover the whole
// sweep rather than only its ownership half — the register drifted from the work ONE
// SLICE after it was built to stop exactly that, which is the most direct evidence
// available that a published count needs a gate rather than good intentions.
//
// The registers marked their defects in comments, in three different phrasings, and one
// was not marked at all. So the number of defects the sweep found depended on which file
// you counted, which is the shape this repo has hit three times already (D329/D330/D338:
// a closed set published in several places, no two agreeing). A count that appears in
// MATURITY.md has to come from somewhere checkable.
//
// This is that somewhere. Each entry names the driver, the service, the verb whose
// register found it, and the decision that fixed it — and the gate below refuses any
// entry naming a service the driver does not certify.

type sweepDefect struct {
	driver, service, verb, decision, what string
}

var sweepDefects = []sweepDefect{
	// Create-time adoption (D391-D438): a re-run could mint a second billed resource.
	{"aws", "vpngateway", "create", "D409", "no pre-scan: a re-run minted a second gateway"},
	{"aws", "apigateway", "create", "D410", "no pre-scan: a re-run minted a second API"},
	{"gcp", "vertexai", "create", "D424", "no pre-scan by displayName"},

	// Delete ownership (D439-D458): the deterministic name was evidence for the verbs
	// that write and forgotten by the verb that destroys.
	{"aws", "budgets", "delete", "D444", "no ownership check (no tags on a budget)"},
	{"aws", "custompolicy", "delete", "D444", "no ownership check on the policy name"},
	{"aws", "cwlogfilter", "delete", "D446", "no ownership check on the filter name"},
	{"aws", "ses-inbound", "delete", "D446", "no ownership check on the rule name"},
	{"aws", "cloudwatchdash", "delete", "D449", "no ownership check on the dashboard name"},
	{"aws", "rolepolicy", "delete", "D445", "detached a policy from a role it never read"},
	{"azure", "activitylog", "delete", "D458", "deleted a diagnostic setting by name, unchecked"},
	{"azure", "changefeed", "delete", "D458", "deleted an event subscription by name, unchecked"},
	{"azure", "customroledef", "delete", "D458", "deleted a roleDefinition by GUID, unchecked"},
	{"azure", "roleassignment", "delete", "D458", "revoked a grant by GUID, unchecked"},

	// Update ownership (D459-D460): both were a check that LOOKS like the one needed.
	{"aws", "budgets", "update", "D459", "comment claimed a name check; code checked existence"},
	{"azure", "servicebusqueue", "update", "D460", "identity check standing in for ownership"},

	// The fourth driver (D462).
	{"k8s", "*", "create", "D462", "SSA applied our labels onto a foreign object, unread"},

	// Scope boundaries (D466-D468). Not ownership — ESTATE. The labels and tags that
	// answer "is this the right capability?" are identical in every project,
	// subscription and account we manage, so they cannot answer "is this the right
	// estate?". Each of these was outside a convention its neighbours already had.
	{"gcp", "pd", "delete", "D466", "no project check; labels are project-agnostic"},
	{"gcp", "mig", "delete", "D466", "no project check; labels are project-agnostic"},
	{"gcp", "gce", "delete", "D466", "no project check; labels are project-agnostic"},
	{"azure", "metricalert", "delete", "D467", "parsed the subscription, discarded it"},
	{"azure", "containerapps", "delete", "D467", "parsed the subscription, discarded it"},
	{"azure", "vnet", "delete", "D467", "discarded sub: retargeted the delete at ours"},

	// Safety and visibility (D469-D471).
	{"aws", "s3", "delete", "D469", "never read Object Lock; a hold surfaced as 'not empty'"},
	{"aws", "vpc", "observe", "D470", "availability.class realised, neither read nor explained"},
	{"azure", "blob", "observe", "D471", "retention.maximum written, never read back"},
}

func TestSweepDefectsNameRealServices(t *testing.T) {
	certified := map[string]map[string]string{
		"aws":   aws.NewDriver("eu-central-1").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("acme-prod").ServiceCapabilities(),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001").ServiceCapabilities(),
	}
	k8sMappings := k8s.NewDriver("http://unused", "tok").Mappings
	if len(certified["aws"]) == 0 || len(k8sMappings) == 0 {
		t.Fatal("no certified services — the gate would be vacuous (D328)")
	}
	if len(sweepDefects) == 0 {
		t.Fatal("no defects recorded — the gate would be vacuous (D328)")
	}

	seen := map[string]bool{}
	for _, d := range sweepDefects {
		key := d.driver + "/" + d.service + "/" + d.verb
		if seen[key] {
			t.Errorf("%s recorded twice — a double-counted defect inflates the number "+
				"this repo publishes about itself", key)
		}
		seen[key] = true

		switch d.driver {
		case "k8s":
			// The k8s defect is in the ONE shared write path, so it is not per-service.
			if d.service != "*" {
				t.Errorf("k8s defect names service %q, but its write path is shared — "+
					"claiming one service understates it", d.service)
			}
		default:
			svcs, ok := certified[d.driver]
			if !ok {
				t.Errorf("%s names driver %q, which this gate does not know", key, d.driver)
				continue
			}
			if _, ok := svcs[d.service]; !ok {
				t.Errorf("%s names a service the %s driver does not certify — a defect "+
					"record that outlives its service reads as coverage it does not have",
					key, d.driver)
			}
		}
		switch d.verb {
		case "create", "update", "delete", "observe":
		default:
			t.Errorf("%s names verb %q — the registers cover create/update/delete/observe", key, d.verb)
		}
	}
}

// TestSweepDefectCount is the number MATURITY.md is allowed to quote. It exists so the
// figure has one source, and so raising it is a deliberate edit rather than a recount.
func TestSweepDefectCount(t *testing.T) {
	const published = 25
	if len(sweepDefects) != published {
		t.Errorf("the sweep recorded %d defects, MATURITY.md quotes %d — update both, in "+
			"the same commit", len(sweepDefects), published)
	}
	byDriver := map[string]int{}
	for _, d := range sweepDefects {
		byDriver[d.driver]++
	}
	keys := make([]string, 0, len(byDriver))
	for k := range byDriver {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, byDriver[k]))
	}
	t.Logf("ownership sweep defects: %d total (%v)", len(sweepDefects), parts)
}
