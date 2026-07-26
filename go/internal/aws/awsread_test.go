package aws

import (
	"fmt"
	"strings"
	"testing"
)

// D296: an AWS read that produced nothing must SAY why — the status and the
// service's own error code — instead of the bare word "unreadable". The
// four-valued meaning is unchanged: an authoritative absence is still
// found=false with NO error; only the diagnosis is new.
func TestAWSReadErrorsNameTheCause(t *testing.T) {
	if got := readTransport("DescribeCluster", fmt.Errorf("dial tcp: i/o timeout")).Error(); !strings.Contains(got, "no answer") ||
		!strings.Contains(got, "DescribeCluster") || !strings.Contains(got, "timeout") {
		t.Fatalf("transport failure = %q", got)
	}
	got := readHTTP("GetRole", 403, "AccessDenied: not authorized to perform iam:GetRole").Error()
	for _, w := range []string{"GetRole", "HTTP 403", "AccessDenied"} {
		if !strings.Contains(got, w) {
			t.Fatalf("%q must contain %q", got, w)
		}
	}
	if got := readBody("DescribeCertificate", 200).Error(); !strings.Contains(got, "HTTP 200") ||
		!strings.Contains(got, "did not parse") {
		t.Fatalf("garbled body = %q", got)
	}
	// bounded and single-line: a diagnostic must not become a body channel
	long := readHTTP("X", 500, strings.Repeat("y", 900)+"\nsecret").Error()
	if len(long) > 220 || strings.Contains(long, "\n") {
		t.Fatalf("diagnostic must stay bounded and single-line, got %d chars", len(long))
	}
}
