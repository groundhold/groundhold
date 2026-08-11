package reach

import "testing"

// D537, from the field. `edgeOutputs` claimed the Lambda Function URL is a
// "PUBLIC-only output (present only for a public function), so output-presence is
// the gate". That is not true of AWS: a Function URL exists with
// `AuthType: AWS_IAM`, which is the CORRECT shape behind CloudFront/OAC — present,
// and deliberately not public.
//
// The consequence was the one they reported: the probe measured the ORIGIN, got a
// 403 to its anonymous GET (which is the origin working as designed), and the run
// came back BLOCKED. They disabled the probe with a flag and wrote why, quoting our
// own argument back at us: a signal that is always red stops being a signal.
//
// D534 made `network.publicExposure` measure AuthType, so the gate now has a true
// input. This makes the gate apply — which is exactly the fix they ranked first,
// obtained the way they predicted, as a consequence of fixing the observation.
func TestPrivateFunctionURLIsNotProbed(t *testing.T) {
	capTypes := map[string]string{"web": "capability.function.serverless"}
	outputs := map[string]map[string]any{
		"web": {"functionUrl": "https://x.lambda-url.eu-central-1.on.aws/"},
	}
	// AuthType AWS_IAM: the URL exists, anonymous callers are refused by design.
	private := map[string]bool{"web": false}

	if got := Targets(capTypes, outputs, private); len(got) != 0 {
		t.Fatalf("a deliberately private Function URL was probed: %+v\n"+
			"Its 403 to an anonymous GET is the origin WORKING; reporting it as a "+
			"failed reachability check makes the probe always-red for a correct setup.", got)
	}
}

// The genuinely public function must still be probed, or the fix removes the
// measurement instead of correcting it — the dangerous direction.
func TestPublicFunctionURLIsStillProbed(t *testing.T) {
	capTypes := map[string]string{"api": "capability.function.serverless"}
	outputs := map[string]map[string]any{
		"api": {"functionUrl": "https://y.lambda-url.eu-central-1.on.aws/"},
	}
	public := map[string]bool{"api": true}

	got := Targets(capTypes, outputs, public)
	if len(got) != 1 || got[0].Capability != "api" {
		t.Fatalf("a public Function URL stopped being probed: %+v", got)
	}
}

// The CDN distribution is the PUBLIC path and is never gated on a capability's
// own exposure flag — it is public by construction, and it is the target that
// measures what a user actually sees.
func TestCDNDistributionStillProbed(t *testing.T) {
	capTypes := map[string]string{"web-cdn": "capability.cdn.distribution"}
	outputs := map[string]map[string]any{"web-cdn": {"domainName": "d123.cloudfront.net"}}

	got := Targets(capTypes, outputs, map[string]bool{})
	if len(got) != 1 {
		t.Fatalf("the CDN edge stopped being probed: %+v", got)
	}
}
