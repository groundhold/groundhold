package aws

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D390: the idempotency-token class is the one field finding that bit TWICE.
//
//	F27  — Secrets Manager CreateSecret refused a missing ClientRequestToken.
//	D304 — EventBridge Scheduler CreateSchedule returned 400 "ClientToken cannot be
//	       empty" on a live converge, after other resources were already standing.
//
// Both times the damage is the same: a create refused mid-run, and — worse — a retry
// after a lost response double-creates, because without a deterministic token AWS
// cannot collapse the duplicate. Both times the fix was one driver. Neither time did
// a gate land, so the path that let it recur is still open: a new AWS driver can be
// authored today with no idempotency decision made about it at all.
//
// D304 closed its case with "a full sweep of every AWS create confirmed Scheduler was
// the ONLY required-but-missing case". That sweep was a manual read of the drivers —
// the instrument D317 showed gives wrong answers (four different ones) — and three of
// its rows were explicitly "flagged for Acme live confirmation", from a pilot that
// paused on 2026-07-24. That confirmation is not coming.
//
// So this gate does NOT claim to know what each AWS API requires; inventing 54 such
// claims would be the same mistake in a new costume. It forces the DECISION to exist
// and be attributable, and it makes the unreviewed remainder a ratchet — visible, and
// payable only downwards.
//
// The token's parameter name differs per API (ClientToken, ClientRequestToken,
// CallerReference, CreatorRequestId, CreationToken), which is exactly why membership
// is declared here rather than derived from a name match.

// idempotencyCarried: the driver emits a deterministic idempotency token on create.
// Every entry is verifiable in this package's source — the value is derived from the
// resource's own deterministic name/environment/capability/generation, never random,
// so a retry reuses it and AWS collapses the duplicate.
var idempotencyCarried = map[string]string{
	"backupplan":           "CreatorRequestId",
	"cloudfront":           "CallerReference",
	"ebs":                  "ClientToken",
	"ec2":                  "ClientToken",
	"efs":                  "CreationToken",
	"eventbridgescheduler": "ClientToken", // D304
	"route53":              "CallerReference",
	"route53health":        "CallerReference",
	"secretsmanager":       "ClientRequestToken", // F27
	"acm":                  "IdempotencyToken",   // D403: a fifth spelling, missed by D390
}

// idempotencyNotApplicable: a retry provably cannot duplicate, so whether this API
// happens to REQUIRE a token is no longer a safety question for it.
//
// D412: this register was asking "does this AWS API require an idempotency token" — a
// claim about AWS that nothing here can re-derive, which is exactly why it sat
// unreviewed. The question it EXISTS for is "can a re-run mint a second resource", and
// D391-D411 answered that mechanically for all 54 creates by driving each one against an
// estate where the resource already stands. That is STRONGER evidence than a token: a
// token makes AWS collapse the retry, adoption makes the DRIVER bind it, and the second
// is checked here rather than assumed of the provider.
//
// Every entry names evidence the gate re-derives. Nothing is filled from memory.
var idempotencyNotApplicable = map[string]string{
	"ami":                    "witness-only",
	"apigateway":             "adoption-gated",
	"apprunner":              "adoption-gated",
	"asg":                    "adoption-gated",
	"aurora":                 "adoption-gated",
	"backupvault":            "adoption-gated",
	"bedrock":                "adoption-gated",
	"budgets":                "adoption-gated",
	"changefeed":             "adoption-gated",
	"cloudtrail":             "adoption-gated",
	"cloudwatch":             "adoption-gated",
	"cloudwatchdash":         "adoption-gated",
	"custompolicy":           "adoption-gated",
	"cwlogfilter":            "adoption-gated",
	"cwlogs":                 "adoption-gated",
	"dynamodb":               "adoption-gated",
	"ecr":                    "adoption-gated",
	"ecs":                    "adoption-gated",
	"eks":                    "adoption-gated",
	"eks-addon":              "adoption-gated",
	"eks-podidentity":        "adoption-gated",
	"elasticache":            "adoption-gated",
	"elasticache-serverless": "adoption-gated",
	"guardduty":              "adoption-gated",
	"iam":                    "adoption-gated",
	"kinesis":                "adoption-gated",
	"kms":                    "adoption-gated",
	"lambda":                 "adoption-gated",
	"loadbalancer":           "adoption-gated",
	"msk":                    "adoption-gated",
	"opensearch":             "adoption-gated",
	"opensearch-serverless":  "adoption-gated",
	"rds":                    "adoption-gated",
	"redshiftserverless":     "adoption-gated",
	"rolepolicy":             "adoption-gated",
	"route53record":          "adoption-gated",
	"s3":                     "adoption-gated",
	"ses-inbound":            "adoption-gated",
	"ses-sending":            "adoption-gated",
	"sns":                    "adoption-gated",
	"sqs":                    "adoption-gated",
	"vpc":                    "adoption-gated",
	"vpngateway":             "adoption-gated",
	"waf":                    "adoption-gated",
}

// idempotencyUnreviewed is the DEBT: create services nobody has made an idempotency
// decision about. The baseline may only go down. A new create service is in none of
// the three sets, which fails the gate — the recurrence path D304 left open.
var idempotencyUnreviewed = map[string]bool{}

// unreviewedBaseline may only go DOWN (the D297 ratchet discipline).
const unreviewedBaseline = 0

func TestEveryCreateHasAnIdempotencyDecision(t *testing.T) {
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")

	var undecided, multiple []string
	for svc := range create {
		n := 0
		if _, ok := idempotencyCarried[svc]; ok {
			n++
		}
		if _, ok := idempotencyNotApplicable[svc]; ok {
			n++
		}
		if idempotencyUnreviewed[svc] {
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
		t.Errorf("create services with NO idempotency decision: %v\n"+
			"This is how F27 recurred as D304. Decide: does this API require a token "+
			"(then carry a deterministic one and list it in idempotencyCarried), does it "+
			"take none (idempotencyNotApplicable, with the source for that claim), or is "+
			"it genuinely unreviewed (idempotencyUnreviewed — and then raise the baseline "+
			"NEVER; review it instead).", undecided)
	}
	if len(multiple) > 0 {
		t.Errorf("create services in more than one idempotency set: %v", multiple)
	}

	// Reverse direction: a decision about a service that no longer creates anything
	// reads like coverage while covering nothing.
	for _, set := range []struct {
		name string
		keys []string
	}{
		{"idempotencyCarried", keysOfStr(idempotencyCarried)},
		{"idempotencyNotApplicable", keysOfStr(idempotencyNotApplicable)},
		{"idempotencyUnreviewed", keysOfBool(idempotencyUnreviewed)},
	} {
		var stale []string
		for _, svc := range set.keys {
			if !create[svc] {
				stale = append(stale, svc)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s names services the create dispatch does not have: %v",
				set.name, stale)
		}
	}
}

// TestIdempotencyReviewRatchet: the unreviewed set may only shrink.
func TestIdempotencyReviewRatchet(t *testing.T) {
	if n := len(idempotencyUnreviewed); n > unreviewedBaseline {
		t.Errorf("unreviewed create services rose to %d (baseline %d) — the idempotency "+
			"debt may only be paid down, never grown", n, unreviewedBaseline)
	} else if n < unreviewedBaseline {
		t.Errorf("unreviewed is down to %d — lower unreviewedBaseline to %d to keep the "+
			"ratchet tight (this failure is the good kind)", n, n)
	}
	if len(idempotencyCarried) == 0 {
		t.Fatal("no carried tokens — the gate would be vacuous (D328)")
	}
}

func keysOfStr(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCarriedTokensMatchTheDrivers is the correction D390 needed and did not have.
//
// D390 built idempotencyCarried by grepping for token FIELD NAMES — the same instrument
// it had just finished calling unreliable — and missed `acm`, whose token is spelled
// IdempotencyToken, a fifth spelling. The service sat in the unreviewed debt while
// carrying a perfectly good deterministic token, so the registry understated the
// defence AND overstated the debt.
//
// The durable fix is to key on the DERIVATION rather than the name: every deterministic
// token in this package is a hash of environment|capability|generation, which is what
// makes a retry reuse it. Any field assigned from letterHash and named like a token
// must appear in idempotencyCarried.
//
// What this cannot do is find a service that NEEDS a token and has none — that is a
// claim about an AWS API, and it stays where D390 put it: in the unreviewed ratchet,
// payable only by review.
func TestCarriedTokensMatchTheDrivers(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	tokenAssign := regexp.MustCompile(
		`(?i)(\w*(?:token|reference|requestid))\s*[:=]\s*"[^"]*"\s*\+\s*letterHash`)

	found := map[string]bool{}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if tokenAssign.Match(raw) {
			found[strings.TrimSuffix(strings.TrimSuffix(name, ".go"), "_net")] = true
		}
	}
	if scanned == 0 {
		t.Fatal("scanned zero driver files — the gate would be vacuous (D328)")
	}
	if len(found) == 0 {
		t.Fatal("found no deterministic token derivations at all — the pattern changed " +
			"and this gate stopped measuring what it guards")
	}

	// file name -> create-dispatch service key, where they differ
	fileToService := map[string]string{
		"ebsvolume": "ebs", "ec2instance": "ec2", "awshealthcheck": "route53health",
		"eventbridgescheduler": "eventbridgescheduler",
	}
	var unlisted []string
	for file := range found {
		svc := file
		if m, ok := fileToService[file]; ok {
			svc = m
		}
		if _, listed := idempotencyCarried[svc]; !listed {
			unlisted = append(unlisted, svc+" ("+file+".go)")
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		t.Errorf("drivers deriving a deterministic idempotency token that "+
			"idempotencyCarried does not list: %v\nThe registry understates the defence "+
			"and overstates the debt — this is exactly how acm was mis-filed (D403).",
			unlisted)
	}
}

// TestIdempotencyExemptionsAreBacked: every idempotencyNotApplicable entry must name
// evidence this gate can re-derive, and the evidence must hold. The mirror of
// TestNotApplicableClaimsAreBacked on the adoption side, and the reason the D412 paydown
// is a retirement rather than a rename: the claims are checked, not asserted.
//
// A reason the gate cannot check is refused outright. D304 closed F27 with "a full sweep
// of every AWS create confirmed" — a sentence nothing could re-derive, from a sweep whose
// three open rows were flagged for a pilot that then paused. That is the shape this
// refuses to admit.
func TestIdempotencyExemptionsAreBacked(t *testing.T) {
	if len(idempotencyNotApplicable) == 0 {
		t.Fatal("nothing exempt — the gate would be vacuous (D328)")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")

	for svc, reason := range idempotencyNotApplicable {
		switch reason {
		case "adoption-gated":
			// The create was DRIVEN against an estate where the resource already stands
			// and bound it (D391). A retry therefore cannot mint a second resource,
			// whatever the API's token policy is — which is a stronger guarantee than
			// the token question this register was originally asking.
			if _, ok := adoptGated[svc]; !ok {
				t.Errorf("%s claims a retry cannot duplicate because its create-time "+
					"adoption is gated, but adoptGated does not list it — the claim has "+
					"no backing.", svc)
			}
		case "witness-only":
			// There is no create to be idempotent about. Driven, not asserted.
			d := NewDriver("eu-central-1")
			d.Account = "000000000000"
			res := d.Create(svc, "c", "prod", map[string]any{"location.region": "eu-central-1"}, nil, "k", 1)
			if res.Status != "failed" || !strings.Contains(strings.ToLower(res.Reason), "witness") {
				t.Errorf("%s claims it is witness-only, but its create did not refuse as "+
					"one: %+v", svc, res)
			}
		default:
			t.Errorf("%s claims %q, which this gate cannot check. Either add a check for "+
				"that evidence or leave the service in the unreviewed ratchet — an "+
				"unverifiable exemption is how a debt register starts lying.", svc, reason)
		}
	}
}
