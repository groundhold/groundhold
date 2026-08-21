package aws

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestLiveAWSSmoke is the pre-ship INTEGRATION gate against REAL AWS that the hermetic
// make-check CI cannot run (D272). It exercises the ACTUAL driver HTTP client end to end
// — the layer whose absence let TWO broken F29 binaries ship (D268 ping ineffective;
// D269 ALPN broke EVERY request), both green in make check. Gated by
// GROUNDHOLD_LIVE_AWS_SMOKE=1; run on a box with AWS reachability before shipping a
// binary to a client.
func TestLiveAWSSmoke(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_AWS_SMOKE") != "1" {
		t.Skip("live AWS smoke disabled (set GROUNDHOLD_LIVE_AWS_SMOKE=1 on a box with AWS egress)")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)

	// (1) Protocol/transport — catches the D269 ALPN break WITHOUT creds: a real request
	// to the EKS endpoint must return a PARSEABLE response over HTTP/1.1, never the
	// "malformed HTTP response" (an h2 frame parsed as http1) that broke every request.
	resp, err := d.HTTP.Get("https://eks." + region + ".amazonaws.com/clusters/groundhold-smoke-none")
	if err != nil {
		t.Fatalf("driver client cannot reach EKS over TLS: %v — this is the shape of the D269 ALPN "+
			"break ('malformed HTTP response')", err)
	}
	proto := resp.Proto
	code := resp.StatusCode
	resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("driver client must speak HTTP/1.1 to AWS, got %s (an h2 negotiation is the D269 bug)", proto)
	}
	t.Logf("protocol check: EKS reachable, HTTP %d proto=%s (no malformed response)", code, proto)

	// (2) Full SIGNED pre-read — catches SigV4 regressions AND the NotFound->found=false
	// branch that D269 turned into "unreadable" (the exact path a create relies on). Needs
	// creds; skipped (with the protocol check still asserted) when absent.
	// D604: the signed half is its OWN test now. It used to be the tail of this one,
	// behind a `t.Log` + `return` when credentials were absent — which reports PASS,
	// with the one check `scripts/preship.sh` exists for never executed. Split, the
	// protocol half still passes on a credential-free box and the signed half reports
	// SKIP, which is what it is. Both are what a reader downstream needs to see.
}

// signedSmokeSkipReason answers ONE question — can this driver make a signed request
// right now — and returns "" when it can (D1155).
//
// It exists as a function rather than an `if` inside the test so it can be measured.
// The guard it replaces asked whether AWS_ACCESS_KEY_ID *or* AWS_PROFILE was set, and
// a profile is the one arrangement where the answer is provably NO: NewDriver reads
// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN and never ~/.aws, so
// profiles, MFA and Identity Center are invisible to it. With a profile set the test
// went ahead and made the request anyway, spent forty-five seconds on the driver's
// retries, and failed accusing D269 of a signing regression that had not happened.
//
// A guard over a capability must ask what the CODE answers, not what the operator
// meant. And when the answer is no, it names the bridge — the operator holding a
// profile has the credentials; what they lack is the three variables.
func signedSmokeSkipReason(key, profile string) string {
	if key != "" {
		return ""
	}
	if profile != "" {
		return fmt.Sprintf("AWS_PROFILE=%s is set, but this driver reads credentials "+
			"ONLY from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN — "+
			"never ~/.aws. The SIGNED DescribeCluster check cannot run. Bridge the "+
			"profile you already have: eval \"$(aws configure export-credentials "+
			"--profile %s --format env)\"", profile, profile)
	}
	return "no AWS credentials in the environment — the SIGNED DescribeCluster check " +
		"cannot run, and no other gate sees a SigV4 regression"
}

// The four combinations, because the bug lived in the one nobody had written down:
// every case that existed set both variables together or neither.
func TestTheSignedSmokeGuardAsksWhatTheDriverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, key, profile string
		wantRun            bool
		why                string
	}{
		{"exported keys", "AKIAEXAMPLE", "", true,
			"the guard skipped with the exact credentials the driver reads — the " +
				"signed check would never run anywhere"},
		{"keys bridged from a profile", "AKIAEXAMPLE", "some-profile", true,
			"the guard skipped when a profile HAD been bridged, which is what its " +
				"own remediation tells the operator to do"},
		{"a profile and nothing else", "", "some-profile", false,
			"the guard let the signed check proceed on a profile alone. NewDriver " +
				"cannot read one, so the request provably cannot be signed; running " +
				"it costs 45s of retries and reports the failure as a SIGNING " +
				"regression that did not happen"},
		{"nothing at all", "", "", false,
			"the guard let the signed check proceed with no credentials at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			why := signedSmokeSkipReason(tc.key, tc.profile)
			if got := why == ""; got != tc.wantRun {
				t.Fatalf("%s (reason=%q)", tc.why, why)
			}
			if tc.wantRun {
				return
			}
			// A refusal that does not say how to proceed sends an operator who is
			// HOLDING the credentials looking for a credential problem.
			if tc.profile != "" && !strings.Contains(why, "export-credentials") {
				t.Errorf("the skip does not name the bridge from the profile the "+
					"operator already has (D730 makes the driver name it): %q", why)
			}
		})
	}
}

// TestLiveAWSSignedSmoke is the SigV4 half (D604): a signed pre-read against real AWS.
// It catches a signing regression and the NotFound->found=false branch D269 turned into
// "unreadable" — the exact path a create relies on. Nothing else in the project covers
// signing against a real endpoint, so when this SKIPs, that class is unmeasured and
// `scripts/preship.sh` refuses to call the run clean.
func TestLiveAWSSignedSmoke(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_AWS_SMOKE") == "" {
		t.Skip("set GROUNDHOLD_LIVE_AWS_SMOKE=1 to run the live AWS smoke")
	}
	if why := signedSmokeSkipReason(os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_PROFILE")); why != "" {
		t.Skip(why)
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)

	_, found, rerr := d.describeEKSCluster(region, "groundhold-smoke-none")
	if rerr != nil {
		// D1155: the error used to be DISCARDED and replaced with the sentence below
		// alone, so every cause — expired keys, a denied policy, no network, a
		// throttle — was reported as a signing regression. Naming a cause you did
		// not measure is the failure this project spends most of its refusals
		// avoiding, and a gate is not exempt from its own rule.
		t.Fatalf("signed DescribeCluster on a nonexistent cluster must be READABLE (a "+
			"clean 404) — D269 broke exactly this (create DIED because the 404 response "+
			"was unparseable -> 'unreadable').\nregion=%s\nwhat actually came back: %v",
			region, rerr)
	}
	if found {
		t.Fatal("a nonexistent cluster must be found=false")
	}
	t.Log("signed DescribeCluster check: nonexistent cluster -> readable=true, found=false (create pre-read OK)")
}

// awsServiceHost maps a SigV4 service name to the host the drivers address in
// production — taken from the drivers' own defaults, not from AWS documentation, so
// the live gate asks about the endpoint the binary would really call. An unmapped
// service returns "", which TestEveryRecordedServiceHasAHost turns into a make-check
// failure rather than a route nobody asked about.
func awsServiceHost(service, region string) string {
	switch service {
	// Global endpoints (no region in the host).
	case "iam", "budgets", "cloudfront", "route53":
		return service + ".amazonaws.com"
	// The endpoint prefix differs from the signing name.
	case "ses":
		return "email." + region + ".amazonaws.com"
	case "ecr":
		return "api.ecr." + region + ".amazonaws.com"
	case "acm", "aoss", "apigateway", "apprunner", "autoscaling", "backup", "bedrock",
		"cloudtrail", "dynamodb", "ec2", "ecs", "eks", "elasticache", "elasticfilesystem",
		"elasticloadbalancing", "es", "events", "guardduty", "kafka", "kinesis", "kms",
		"lambda", "logs", "monitoring", "rds", "redshift-serverless", "s3", "s3-control",
		"scheduler", "secretsmanager", "sns", "sqs", "sts", "tagging", "wafv2":
		return service + "." + region + ".amazonaws.com"
	}
	return ""
}

// TestLiveAWSEndpointReality (D274) asks real AWS whether every route the drivers
// construct is a route AWS actually has. AWS returns a DISTINGUISHABLE signal for an
// unmatched route ("Unable to determine service/operation name") versus a real one
// ("Missing Authentication Token"), so this needs network egress but NO credentials.
// It drives the DRIVER's own HTTP client, so a transport regression (the D269 ALPN
// break) fails here too. Gated by GROUNDHOLD_LIVE_AWS_SMOKE=1.
//
// D717: the subject is DERIVED, not typed. This gate used to carry two hand-written
// route lists — EKS from D273 and Lambda from D694 — so it covered two services out
// of forty, and the driver that shipped a nonexistent MSK delete route was never
// asked about. It now reads testdata/aws-routes.txt, which TestMain records from what
// the drivers actually build, so a new driver is covered without anyone remembering.
//
// The three known-wrong routes stay written down as NEGATIVE CONTROLS: the drivers do
// not construct them any more, so the capture cannot produce them, and without them a
// green run would not prove the classifier still works.
func TestLiveAWSEndpointReality(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_AWS_SMOKE") != "1" {
		t.Skip("live AWS endpoint-reality disabled (set GROUNDHOLD_LIVE_AWS_SMOKE=1 with network egress)")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	// D820: AWS gives MORE THAN ONE answer for a route it does not have, and this gate
	// knew one of them. The Query/JSON frontend says "Unable to determine service/
	// operation name"; the REST services answer `<UnknownOperationException/>` with a
	// 404. Reading only the first meant every fabricated REST path passed as real — and
	// two did, for OpenSearch, until an offline check of the provider's models found
	// them. A classifier that recognises one of two failure signals is not a classifier
	// for the half it cannot see.
	unmatchedSignals := []string{
		"Unable to determine service/operation name",
		"UnknownOperationException",
	}
	d := NewDriver(region)

	ask := func(host, method, target string) (recognized bool, detail string) {
		req, err := http.NewRequest(method, "https://"+host+target, nil)
		if err != nil {
			return false, "unbuildable request: " + err.Error()
		}
		resp, err := d.HTTP.Do(req) // the DRIVER's client — a transport/ALPN break fails here
		if err != nil {
			return false, "transport error: " + err.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		resp.Body.Close()
		for _, u := range unmatchedSignals {
			if strings.Contains(string(b), u) {
				return false, strings.TrimSpace(string(b))
			}
		}
		return true, strings.TrimSpace(string(b))
	}

	raw, err := os.ReadFile(routesFile)
	if err != nil {
		t.Fatalf("read %s: %v", routesFile, err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// D328: assert the subject before reporting on it. A truncated file would make this
	// gate print a clean run over nothing.
	if len(lines) < 100 {
		t.Fatalf("%s holds %d routes — too few to be the real set; the gate would report "+
			"clean without asking about most of what the drivers call", routesFile, len(lines))
	}
	services := map[string]bool{}
	var unasked []string
	asked := 0
	for _, l := range lines {
		parts := strings.SplitN(l, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("malformed line in %s: %q", routesFile, l)
		}
		service, method, target := parts[0], parts[1], parts[2]
		host := awsServiceHost(service, region)
		if host == "" {
			t.Errorf("no endpoint host for service %q — its routes went unasked", service)
			continue
		}
		// D820: a bare "/" carries no operation. The Query and JSON services choose it
		// with an Action form field or an X-Amz-Target header, neither of which this
		// unauthenticated probe sends — so AWS answers UnknownOperationException for a
		// route that is perfectly real. Counted and named, never silently passed: a gate
		// that quietly stops applying to part of its subject is how one becomes
		// decorative. The offline check (TestEveryRouteTheDriverBuildsIsARouteAWSHas)
		// holds the same ceiling over the same routes.
		if strings.Trim(strings.SplitN(target, "?", 2)[0], "/") == "" {
			unasked = append(unasked, service+" "+method+" "+target)
			continue
		}
		services[service] = true
		asked++
		if ok, detail := ask(host, method, target); !ok {
			t.Errorf("%s %s %s is NOT a real AWS route (%q) — the driver calls a path AWS "+
				"does not have (the D273/D694/D717 class)", service, method, target, detail)
		}
	}
	t.Logf("asked AWS about %d routes across %d services", asked, len(services))
	if len(unasked) > 0 {
		t.Logf("%d routes carry no path to ask about (the protocol roots): %s",
			len(unasked), strings.Join(unasked, ", "))
	}
	// D328 in its sharpest form: if almost everything were unaskable, the run above would
	// be clean and would mean nothing.
	if asked < 100 {
		t.Fatalf("only %d routes carried a path to ask about — this gate stopped applying "+
			"to its subject", asked)
	}

	// NEGATIVE CONTROLS: three routes this project shipped, each read as an answer
	// about the world when it was an answer about our URL. If any reads as real, the
	// classifier has stopped working and every result above is meaningless.
	for _, c := range []struct{ why, service, method, target string }{
		{"D273", "eks", "GET", "/clusters/x/node-groups/y/updates/z"},
		{"D694", "lambda", "GET", "/2021-10-31/functions/x/policy"},
		{"D717", "kafka", "DELETE", "/api/v2/clusters/x"},
		// D820: this one answers with the OTHER signal, so the half of the classifier
		// added for it is proven rather than asserted. The first three all produce
		// "Unable to determine service/operation name"; every one of them would still
		// pass with the REST half deleted.
		{"D820", "es", "GET", "/2021-01-01/opensearch/domain"},
	} {
		if ok, _ := ask(awsServiceHost(c.service, region), c.method, c.target); ok {
			t.Errorf("negative control FAILED (%s): the known-nonexistent route %s %s %s "+
				"was not flagged — the gate has no teeth", c.why, c.service, c.method, c.target)
		}
	}
}
