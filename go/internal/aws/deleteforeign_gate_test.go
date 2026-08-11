package aws

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// D439: the adoption sweep asked, for every create on three clouds, "when the resource is
// already there and it is OURS, does the driver bind it?". This register asks the mirror
// question of the mirror verb: **when the resource is there and it is NOT ours, does the
// driver refuse to delete it?**
//
// Neither property implies the other, and the delete side is the one where being wrong
// cannot be undone. A create that adopts correctly can still have a delete that trusts the
// providerId it was handed — and that id comes from the ledger, which a mistaken adoption,
// a hand-authored plan or a stale binding can populate with a stranger's resource.
//
// Every driver here already carries an ownership check on delete; roughly forty AWS tests
// assert one. What has never existed is the STATEMENT that all of them do. A name-matching
// scan put the gap at ten services and I do not believe it — that instrument has been wrong
// three times in this series (D317, D403, D413). So membership is driven, not scraped.

var deleteForeignGated = map[string]string{
	"kms":                    "TestRefusesForeignDeleteKMS",
	"vpc":                    "TestRefusesForeignDeleteVPC",
	"s3":                     "TestRefusesForeignDeleteS3",
	"dynamodb":               "TestRefusesForeignDeleteDynamoDB",
	"cwlogs":                 "TestRefusesForeignDeleteCWLogs",
	"ecr":                    "TestRefusesForeignDeleteECR",
	"efs":                    "TestRefusesForeignDeleteEFS",
	"elasticache":            "TestRefusesForeignDeleteElastiCache",
	"kinesis":                "TestRefusesForeignDeleteKinesis",
	"opensearch":             "TestRefusesForeignDeleteOpenSearch",
	"acm":                    "TestRefusesForeignDeleteACM",
	"backupplan":             "TestRefusesForeignDeleteBackupPlan",
	"cloudfront":             "TestRefusesForeignDeleteCloudFront",
	"msk":                    "TestRefusesForeignDeleteMSK",
	"secretsmanager":         "TestRefusesForeignDeleteSecretsManager",
	"waf":                    "TestRefusesForeignDeleteWAF",
	"ecs":                    "TestRefusesForeignDeleteECS",
	"rds":                    "TestRefusesForeignDeleteRDS",
	"sns":                    "TestRefusesForeignDeleteSNS",
	"sqs":                    "TestRefusesForeignDeleteSQS",
	"apprunner":              "TestRefusesForeignDeleteAppRunner",
	"aurora":                 "TestRefusesForeignDeleteAurora",
	"cloudtrail":             "TestRefusesForeignDeleteCloudTrail",
	"budgets":                "TestRefusesForeignDeleteBudgets",      // D443: found a real bug
	"custompolicy":           "TestRefusesForeignDeleteCustomPolicy", // D444: found a real bug
	"cwlogfilter":            "TestRefusesForeignDeleteCWLogFilter",  // D444: found a real bug
	"rolepolicy":             "TestRefusesForeignDeleteRolePolicy",   // D445: found a real bug
	"ses-inbound":            "TestRefusesForeignDeleteSESInbound",   // D446: found a real bug
	"elasticache-serverless": "TestRefusesForeignDeleteElastiCacheServerless",
	"guardduty":              "TestRefusesForeignDeleteGuardDuty",
	"lambda":                 "TestRefusesForeignDeleteLambda",
	"opensearch-serverless":  "TestRefusesForeignDeleteOpenSearchServerless",
	"route53":                "TestRefusesForeignDeleteRoute53",
	"bedrock":                "TestRefusesForeignDeleteBedrock",
	"ebs":                    "TestRefusesForeignDeleteEBSVolume",
	"ec2":                    "TestRefusesForeignDeleteEC2Instance",
	"eventbridgescheduler":   "TestRefusesForeignDeleteEventBridgeScheduler",
	"backupvault":            "TestRefusesForeignDeleteBackupVault",
	"iam":                    "TestRefusesForeignDeleteIAMRole",
	"redshiftserverless":     "TestRefusesForeignDeleteRedshiftServerless",
	"vpngateway":             "TestRefusesForeignDeleteVpnGateway",
	"apigateway":             "TestRefusesForeignDeleteApiGWv2",
	"cloudwatchdash":         "TestRefusesForeignDeleteCWDashboard",
	"route53health":          "TestRefusesForeignDeleteRoute53HealthCheck",
	"route53record":          "TestRefusesForeignDeleteRoute53Record",
	"asg":                    "TestRefusesForeignDeleteASG",
	"changefeed":             "TestRefusesForeignDeleteChangeFeed",
	"cloudwatch":             "TestRefusesForeignDeleteCloudWatchAlarm",
	"eks":                    "TestRefusesForeignDeleteEKS",
	"eks-addon":              "TestRefusesForeignDeleteEKSAddon",
	"eks-podidentity":        "TestRefusesForeignDeleteEKSPodIdentity",
	"loadbalancer":           "TestRefusesForeignDeleteLoadBalancer",
	"ses-sending":            "TestRefusesForeignDeleteSESSending",
}

// deleteForeignNotApplicable: reviewed, with evidence a test re-derives (the D404 rule).
var deleteForeignNotApplicable = map[string]string{
	"ami": "witness-only",
}

var deleteForeignUnreviewed = map[string]bool{}

const deleteForeignBaseline = 0

func TestEveryDeleteHasAForeignRefusalDecision(t *testing.T) {
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	del := serviceCases(t, string(raw), "Delete")

	var undecided, multiple []string
	for svc := range del {
		n := 0
		if _, ok := deleteForeignGated[svc]; ok {
			n++
		}
		if _, ok := deleteForeignNotApplicable[svc]; ok {
			n++
		}
		if deleteForeignUnreviewed[svc] {
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
		t.Errorf("delete services with NO foreign-refusal decision: %v\n"+
			"A delete that trusts its providerId can destroy a resource that was never "+
			"ours, and nothing later undoes that. Enroll it in CertifyDeleteRefusesForeign, "+
			"or record why it cannot delete a stranger's resource — with evidence.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("delete services in more than one foreign-refusal set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"deleteForeignGated":         keysOfStr(deleteForeignGated),
		"deleteForeignNotApplicable": keysOfStr(deleteForeignNotApplicable),
		"deleteForeignUnreviewed":    keysOfBool(deleteForeignUnreviewed),
	} {
		var stale []string
		for _, svc := range keys {
			if !del[svc] {
				stale = append(stale, svc)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s names services the delete dispatch does not have: %v", name, stale)
		}
	}
}

// TestDeleteForeignExemptionsAreBacked: the D404 rule on the delete side — an exemption
// must name evidence this gate re-derives, and free text is refused.
func TestDeleteForeignExemptionsAreBacked(t *testing.T) {
	if len(deleteForeignNotApplicable) == 0 {
		t.Skip("nothing exempt")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	for svc, reason := range deleteForeignNotApplicable {
		switch reason {
		case "witness-only":
			// The driver refuses to delete what it never authored. Its own comment says
			// why: "Deleting an image groundhold never created would destroy something a
			// pipeline owns, on the strength of a record we only ever read."
			d := NewDriver("eu-central-1")
			d.Account = "000000000000"
			res := d.Delete(svc, "c", "prod", "ami:eu-central-1:000000000000:ami-0123", "k")
			if res.Status != "failed" || !strings.Contains(strings.ToLower(res.Reason), "witness") {
				t.Errorf("%s claims witness-only, but its delete did not refuse as one: %+v",
					svc, res)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check.", svc, reason)
		}
	}
}

func TestDeleteForeignRatchet(t *testing.T) {
	if n := len(deleteForeignUnreviewed); n > deleteForeignBaseline {
		t.Errorf("unreviewed deletes rose to %d (baseline %d) — the gap may only be paid "+
			"down, never grown", n, deleteForeignBaseline)
	} else if n < deleteForeignBaseline {
		t.Errorf("unreviewed is down to %d — lower deleteForeignBaseline to %d "+
			"(this failure is the good kind)", n, n)
	}
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceCases(t, string(raw), "Delete")) == 0 {
		t.Fatal("no delete services found — the gate would be vacuous (D328)")
	}
}
