package aws

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// D391: D252/D253 built create-time adoption — a create that finds an OWNED resource
// already standing binds it instead of minting a second one — and proved it for a
// roster of 18 AWS services. The roster is now 54 creates. Nothing asserted the
// property as a class, and nothing noticed the roster tripling underneath the claim.
//
// This is the D338 shape (a property proven once against a roster that then grew)
// applied to behaviour rather than to a registry, and the damage is the field's most
// expensive: D253's own words, "a second VPC, a second paid key", neither in the ledger.
//
// So enrolment in CertifyCreateAdoptsExisting becomes a decision every create service
// must have, with the unenrolled remainder a ratchet that may only go down.

// adoptGated: enrolled in the cross-driver gate, which drives the PUBLIC Create dispatch
// against a fake where the owned resource already exists and counts the wire.
var adoptGated = map[string]string{
	"kms":                    "TestAdoptsExistingKMS", // D253's example: a second paid key
	"vpc":                    "TestAdoptsExistingVPC", // D253's example: a second VPC
	"bedrock":                "TestAdoptsExistingBedrock",
	"s3":                     "TestAdoptsExistingS3",  // the ours-tagged path was "covered live" only
	"sns":                    "TestAdoptsExistingSNS", // untagged/foreign had tests; OURS did not
	"sqs":                    "TestAdoptsExistingSQS", // same
	"cwlogs":                 "TestAdoptsExistingCWLogs",
	"custompolicy":           "TestAdoptsExistingCustomPolicy",
	"guardduty":              "TestAdoptsExistingGuardDuty",
	"eks-podidentity":        "TestAdoptsExistingEKSPodIdentity",
	"eks-addon":              "TestAdoptsExistingEKSAddon",
	"loadbalancer":           "TestAdoptsExistingLoadBalancer",
	"ses-inbound":            "TestAdoptsExistingSESInbound",
	"eks":                    "TestAdoptsExistingEKS",
	"aurora":                 "TestAdoptsExistingAurora",
	"ecs":                    "TestAdoptsExistingECS",
	"ses-sending":            "TestAdoptsExistingSESSending",
	"ecr":                    "TestAdoptsExistingECR",
	"budgets":                "TestAdoptsExistingBudget",
	"efs":                    "TestAdoptsExistingEFS",
	"cloudtrail":             "TestAdoptsExistingCloudTrail",
	"route53":                "TestAdoptsExistingRoute53",
	"backupvault":            "TestAdoptsExistingBackupVault",
	"iam":                    "TestAdoptsExistingIAMRole",
	"rds":                    "TestAdoptsExistingRDS",
	"elasticache":            "TestAdoptsExistingElastiCache",
	"opensearch":             "TestAdoptsExistingOpenSearch",
	"asg":                    "TestAdoptsExistingASG",
	"kinesis":                "TestAdoptsExistingKinesis",
	"dynamodb":               "TestAdoptsExistingDynamoDB",
	"lambda":                 "TestAdoptsExistingLambda",
	"apprunner":              "TestAdoptsExistingAppRunner",
	"rolepolicy":             "TestAdoptsExistingRolePolicy",
	"elasticache-serverless": "TestAdoptsExistingElastiCacheServerless",
	"cloudwatch":             "TestAdoptsExistingCloudWatchAlarm",
	"cloudwatchdash":         "TestAdoptsExistingCWDashboard",
	"route53record":          "TestAdoptsExistingRoute53Record",
	"msk":                    "TestAdoptsExistingMSK",
	"redshiftserverless":     "TestAdoptsExistingRedshiftServerless",
	"vpngateway":             "TestAdoptsExistingVpnGateway", // D409: the enrolment that found a real bug
	"apigateway":             "TestAdoptsExistingApiGWv2",    // D410: the second real bug
	"waf":                    "TestAdoptsExistingWAF",
	"cwlogfilter":            "TestAdoptsExistingCWLogFilter",
	"changefeed":             "TestAdoptsExistingChangeFeed",
	"opensearch-serverless":  "TestAdoptsExistingOpenSearchServerless",
}

// adoptNotApplicable: reviewed, and the create cannot duplicate. An entry here is a
// claim that a retry is safe — exactly the claim F27 and D304 punished when it was
// assumed rather than established — so every entry must name its EVIDENCE, and the
// gate below checks the evidence rather than trusting the sentence.
//
// The only evidence admitted so far is the one D403 made checkable: a deterministic
// idempotency token, derived from environment|capability|generation, which makes AWS
// collapse the retry onto the ORIGINAL resource. That is adoption achieved by the API
// instead of by the driver — same property, different mechanism — and membership in
// idempotencyCarried is itself gated against the drivers' own derivations, so this is
// not a sentence about AWS but a fact about the code.
var adoptNotApplicable = map[string]string{
	"acm":                  "idempotency-token",
	"backupplan":           "idempotency-token",
	"cloudfront":           "idempotency-token",
	"ebs":                  "idempotency-token",
	"ec2":                  "idempotency-token",
	"eventbridgescheduler": "idempotency-token",
	"route53health":        "idempotency-token",
	"secretsmanager":       "idempotency-token",
	"ami":                  "witness-only",
}

// adoptUnenrolled is the DEBT: create services whose create-time-adoption behaviour no
// cross-driver gate asserts. Baseline may only go DOWN. A new create service is in
// none of the three sets and fails the gate.
var adoptUnenrolled = map[string]bool{}

const adoptUnenrolledBaseline = 0

func TestEveryCreateHasAnAdoptionDecision(t *testing.T) {
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")
	// D488: an empty dispatch decides nothing and this test reported success. The
	// sibling registers were protected only ACCIDENTALLY, by a stale-check that
	// fires when the registry names services the dispatch lacks — these two had no
	// such check and passed vacuously. Assert the subject explicitly rather than
	// relying on another assertion's side effect.
	if len(create) == 0 {
		t.Fatal("no AWS create services parsed — the gate would be vacuous (D328)")
	}

	var undecided, multiple []string
	for svc := range create {
		n := 0
		if _, ok := adoptGated[svc]; ok {
			n++
		}
		if _, ok := adoptNotApplicable[svc]; ok {
			n++
		}
		if adoptUnenrolled[svc] {
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
		t.Errorf("create services with NO create-time-adoption decision: %v\n"+
			"A create that cannot adopt an existing owned resource duplicates it on a "+
			"lost-ledger converge (D252/D253). Enroll it in CertifyCreateAdoptsExisting, "+
			"or record why it cannot duplicate — with the evidence.", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("create services in more than one adoption set: %v", multiple)
	}

	for name, keys := range map[string][]string{
		"adoptGated":         keysOfStr(adoptGated),
		"adoptNotApplicable": keysOfStr(adoptNotApplicable),
		"adoptUnenrolled":    keysOfBool(adoptUnenrolled),
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

func TestAdoptionEnrolmentRatchet(t *testing.T) {
	if n := len(adoptUnenrolled); n > adoptUnenrolledBaseline {
		t.Errorf("unenrolled create services rose to %d (baseline %d) — the adoption gap "+
			"may only be paid down, never grown", n, adoptUnenrolledBaseline)
	} else if n < adoptUnenrolledBaseline {
		t.Errorf("unenrolled is down to %d — lower adoptUnenrolledBaseline to %d "+
			"(this failure is the good kind)", n, n)
	}
	if len(adoptGated) == 0 {
		t.Fatal("nothing enrolled — the gate would be vacuous (D328)")
	}
}

// TestNotApplicableClaimsAreBacked: every adoptNotApplicable entry must name evidence
// this gate can check, and the evidence must hold. Today the only admitted reason is a
// deterministic idempotency token, and the check is membership in idempotencyCarried —
// which D403's derivation cross-check keeps honest against the drivers themselves.
//
// The point is that "reviewed, it is fine" must never be sayable without something a
// test can re-derive. D304 closed F27 with a manual sweep and a sentence; this is what
// that sentence should have been.
func TestNotApplicableClaimsAreBacked(t *testing.T) {
	if len(adoptNotApplicable) == 0 {
		t.Skip("nothing claimed not-applicable yet")
	}
	// credentials, so a witness-only create reaches the witness gate rather than
	// stopping at the earlier no-credentials refusal (which would pass for the wrong
	// reason — the gate must see the property it claims to check).
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	for svc, reason := range adoptNotApplicable {
		switch reason {
		case "idempotency-token":
			if _, ok := idempotencyCarried[svc]; !ok {
				t.Errorf("%s claims adoption is not applicable because it carries a "+
					"deterministic idempotency token, but idempotencyCarried does not list "+
					"it — the claim has no backing.", svc)
			}
		case "witness-only":
			// The capability cannot be created at all — it is observed, never authored
			// (errWitnessOnly). Checked by DRIVING the create and requiring the refusal,
			// so the exemption cannot outlive the property.
			d := NewDriver("eu-central-1")
			d.Account = "000000000000"
			res := d.Create(svc, "c", "prod", map[string]any{"location.region": "eu-central-1"}, nil, "k", 1)
			if res.Status != "failed" || !strings.Contains(strings.ToLower(res.Reason), "witness") {
				t.Errorf("%s claims it is witness-only, but its create did not refuse as one: %+v",
					svc, res)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check. Either add a check for "+
				"that evidence or enroll the driver — an unverifiable exemption is how a "+
				"debt register starts lying.", svc, reason)
		}
	}
}
