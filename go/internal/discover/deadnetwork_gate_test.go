package discover_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/discover"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
	"groundhold/internal/provider"
)

// dead is a transport that reaches nothing — the honest shape of an unplugged
// cable, a wrong API-server address, a VPN that is down, an expired credential
// that never gets as far as a response.
type dead struct{}

func (dead) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connect: connection refused")
}

func deadClient() *http.Client { return &http.Client{Transport: dead{}} }

// D642. D621 established the rule — "a sweep that could not happen is not an empty
// estate" — and enforced it with ONE precondition inside ONE driver. Each of the
// other three checked something different and weaker: AWS that a region was given,
// Azure that a subscription looked like a GUID, k8s nothing at all. A dead network
// passes all three, so every service sweep failed, every failure became a
// diagnostic, and `discover` exited 0 with `"resources": []` — the document `adopt`
// and `posture` are then told to take.
//
// This gate is behavioural and covers every discoverer at once: point the real
// driver at a transport that cannot connect and require the sweep to FAIL. It runs
// against the four drivers rather than against a rule written down somewhere,
// because "the rule exists" is what was true while three drivers did not follow it.
func TestNoDriverReportsAnEmptyEstateOverADeadNetwork(t *testing.T) {
	// Credentials that are syntactically fine: the point is that the network is
	// dead, not that the driver is unconfigured. A driver that refuses for a
	// MISSING credential would prove nothing about the case that got through.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "ya29.fake-token-for-a-dead-network")
	t.Setenv("GROUNDHOLD_AZURE_ACCESS_TOKEN", "fake-token-for-a-dead-network")

	awsD := aws.NewDriver("eu-central-1")
	awsD.HTTP = deadClient()
	// Several AWS sweeps retry a read with a PollInterval sleep between attempts.
	// The retry policy is not what this gate is about, and at the 5s default it
	// costs 45 seconds of `make check` to measure something else.
	awsD.PollInterval = time.Millisecond
	gcpD := gcp.NewDriver("proj")
	gcpD.HTTP = deadClient()
	gcpD.PollInterval = time.Millisecond
	azD := azure.NewDriver("00000000-0000-0000-0000-000000000000")
	azD.HTTP = deadClient()
	azD.PollInterval = time.Millisecond

	cases := []struct {
		name   string
		drv    provider.Provider
		region string
	}{
		{"aws", awsD, "eu-central-1"},
		{"gcp", gcpD, "europe-west1"},
		{"azure", azD, "westeurope"},
		{"k8s", &k8s.Driver{Server: "https://127.0.0.1:1", HTTP: deadClient()}, "default"},
		// namespaced k8s: the cluster-scoped kinds are skipped, so the all-failed
		// floor must count only the sweeps this scope actually ran.
		{"k8s-cluster-wide", &k8s.Driver{Server: "https://127.0.0.1:1", HTTP: deadClient()}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := discover.Run(tc.drv, "proj", tc.region, "2026-02-01T00:00:00Z")
			if err == nil {
				t.Fatalf("%s swept a network that answers nothing and produced a "+
					"document with %d resources at no error. A caller branching on "+
					"the exit status reads \"the estate is empty\"; the truth is "+
					"\"the provider was never reached\".",
					tc.name, len(res.Discovery.Resources))
			}
			if !strings.Contains(err.Error(), "reach") {
				t.Errorf("%s failed for some other reason — the message must say the "+
					"provider was unreachable, or an operator debugs the wrong thing: %v",
					tc.name, err)
			}
		})
	}
}

// The control, without which the case above is satisfied by refusing everything:
// a provider that ANSWERS and has nothing in it is an empty estate, and must
// succeed. Half the sweeps failing is also a success — that is the resilience
// D621 deliberately kept, so one unreadable kind cannot hide the others.
func TestSweepAllStillToleratesPartialFailure(t *testing.T) {
	var rec provider.ListingRecord
	out, diags, err := provider.SweepAll([]string{"a", "b", "c"},
		func(tok string) ([]provider.Discovered, []string, error) {
			if tok == "b" {
				return nil, nil, errors.New("b: the identity may not list this kind")
			}
			return []provider.Discovered{{ProviderID: tok}}, nil, nil
		}, &rec)
	if err != nil {
		t.Fatalf("one unreadable kind must not fail the sweep: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("the readable kinds were dropped: %+v", out)
	}
	if len(diags) != 1 {
		t.Errorf("the unreadable kind must still be reported: %v", diags)
	}
	// D873: tolerating the partial failure is right, but it is ALSO incomplete — the scope
	// must be marked a lower bound, or posture claims exactness (shadowLowerBound=false) on
	// a capability whose sweep wholly failed. The resilience and the honesty are separate,
	// and before D873 only the first was here.
	if notes := rec.Take(); len(notes) == 0 {
		t.Fatal("a failed sweep left the scope recorded COMPLETE — posture would report " +
			"the missing capability's shadow count as exact (D873)")
	}

	// And an estate that is genuinely empty stays a success AND complete (nothing failed).
	var rec2 provider.ListingRecord
	if _, _, err := provider.SweepAll([]string{"a"},
		func(string) ([]provider.Discovered, []string, error) { return nil, nil, nil }, &rec2); err != nil {
		t.Errorf("a reachable provider with nothing in it must succeed: %v", err)
	}
	if notes := rec2.Take(); len(notes) != 0 {
		t.Errorf("an all-succeeded sweep must NOT mark the scope incomplete: %v", notes)
	}
}
