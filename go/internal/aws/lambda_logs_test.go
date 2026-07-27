package aws

import "testing"

// D381. The conformance case pins the compile-time WIRING (the declared output
// exists, the reference type-checks). It cannot pin the VALUE — gutting the
// resolver leaves it green, which I confirmed by doing exactly that. So the value
// is pinned here, where it can be.
//
// The stakes are the reason: this string is what a retention guarantee lands on.
// A wrong one silently sets 365-day retention on a group nobody writes to, while
// the group that holds the logs keeps them forever — which is what a field
// partner shipped, believing the contract.
func TestLambdaLogGroupNameIsTheGroupAWSCreates(t *testing.T) {
	// AWS fixes this shape; it is not a groundhold naming choice.
	if got := lambdaLogGroupName("pv-api-prod-1a2b3c4d"); got != "/aws/lambda/pv-api-prod-1a2b3c4d" {
		t.Errorf("lambdaLogGroupName = %q, want the /aws/lambda/<fn> group AWS creates", got)
	}
}
