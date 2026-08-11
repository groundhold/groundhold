package aws

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// D459: the update register. The create sweep (D391-D438) asked whether a create binds
// what is already ours; the delete sweep (D439-D458) asked whether a delete refuses what
// is not. Between them sits the verb nobody asked about as a class, and the delete sweep
// is precisely the reason to ask: nine of its defects were a check that the create and
// update paths carried and the delete did not. The same argument runs the other way.
//
// An update on a foreign resource is a TAKEOVER rather than a destruction: the resource
// keeps running under someone else's name with our configuration written into it. That
// is quieter than a delete, not milder — nobody goes looking for a retention policy that
// silently became someone else's.

// updateForeignGated: driven through the public Update dispatch against a fake where the
// resource EXISTS carrying a stranger's ownership markers.
var updateForeignGated = map[string]string{
	"s3":                   "TestRefusesForeignUpdateS3",
	"sns":                  "TestRefusesForeignUpdateSNS",
	"sqs":                  "TestRefusesForeignUpdateSQS",
	"cwlogs":               "TestRefusesForeignUpdateCWLogs",
	"ecr":                  "TestRefusesForeignUpdateECR",
	"route53record":        "TestRefusesForeignUpdateRoute53Record", // parent zone is the boundary
	"secretsmanager":       "TestRefusesForeignUpdateASM",
	"rds":                  "TestRefusesForeignUpdateRDS",
	"aurora":               "TestRefusesForeignUpdateAurora",
	"eks":                  "TestRefusesForeignUpdateEKS",
	"apprunner":            "TestRefusesForeignUpdateAppRunner",
	"ses-sending":          "TestRefusesForeignUpdateSESSending",
	"acm":                  "TestRefusesForeignUpdateACM",
	"backupplan":           "TestRefusesForeignUpdateBackupPlan",
	"cloudtrail":           "TestRefusesForeignUpdateCloudTrail",
	"eks-addon":            "TestRefusesForeignUpdateEKSAddon",
	"guardduty":            "TestRefusesForeignUpdateGuardDuty",
	"lambda":               "TestRefusesForeignUpdateLambda",
	"budgets":              "TestRefusesForeignUpdateBudgets", // D459: found a real bug
	"ses-inbound":          "TestRefusesForeignUpdateSESInbound",
	"dynamodb":             "TestRefusesForeignUpdateDynamoDB", // D1004
	"eventbridgescheduler": "TestRefusesForeignUpdateEBS",      // D1004
}

// updateForeignNotApplicable: reviewed, with evidence a test re-derives (D404).
var updateForeignNotApplicable = map[string]string{
	"loadbalancer": "no-in-place-update",
}

var updateForeignUnreviewed = map[string]bool{}

const updateForeignBaseline = 0

func updateServices(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	return serviceCases(t, string(raw), "update")
}

func TestEveryAWSUpdateHasAForeignRefusalDecision(t *testing.T) {
	upds := updateServices(t)

	var undecided, multiple []string
	for svc := range upds {
		n := 0
		if _, ok := updateForeignGated[svc]; ok {
			n++
		}
		if _, ok := updateForeignNotApplicable[svc]; ok {
			n++
		}
		if updateForeignUnreviewed[svc] {
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
		t.Errorf("AWS update services with NO foreign-refusal decision: %v\n"+
			"An update that trusts its providerId writes our configuration into a "+
			"resource that was never ours, and it keeps running under someone else's "+
			"name. Enroll it, or record why it cannot — with evidence.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("AWS update services in more than one set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"updateForeignGated":         keysOfStr(updateForeignGated),
		"updateForeignNotApplicable": keysOfStr(updateForeignNotApplicable),
		"updateForeignUnreviewed":    keysOfBool(updateForeignUnreviewed),
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

// TestAWSUpdateExemptionsAreBacked: the D404 rule. An exemption names evidence this gate
// re-derives, and free text is refused outright.
func TestAWSUpdateExemptionsAreBacked(t *testing.T) {
	if len(updateForeignNotApplicable) == 0 {
		t.Skip("nothing claimed not-applicable")
	}
	for svc, reason := range updateForeignNotApplicable {
		switch reason {
		case "no-in-place-update":
			// There is no update to take anything over WITH: every governed attribute is
			// fixed at creation and a change routes to a replacement (D46/D48). Driven,
			// not asserted — and the refusal must be categorical, reached before any
			// providerId or estate is consulted.
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.Account = "000000000000"
			res := d.Update(svc, "edge", "prod", "elb:eu-central-1:000000000000:pv-x",
				map[string]any{"location.region": "eu-central-1"}, nil,
				[]string{"network.publicExposure"}, "k")
			if res.Status != "failed" ||
				!strings.Contains(res.Reason, "update is not supported") {
				t.Errorf("%s claims no-in-place-update, but its update did not refuse as "+
					"one: %+v", svc, res)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check — an unverifiable "+
				"exemption is how a debt register starts lying.", svc, reason)
		}
	}
}

func TestAWSUpdateForeignRatchet(t *testing.T) {
	if n := len(updateForeignUnreviewed); n > updateForeignBaseline {
		t.Errorf("unreviewed AWS updates rose to %d (baseline %d)", n, updateForeignBaseline)
	} else if n < updateForeignBaseline {
		t.Errorf("unreviewed is down to %d — lower updateForeignBaseline to %d "+
			"(this failure is the good kind)", n, n)
	}
	// The vacuity guard watches the DISPATCH, never the debt (D413).
	if len(updateServices(t)) == 0 {
		t.Fatal("no update services found — the gate would be vacuous (D328)")
	}
}
