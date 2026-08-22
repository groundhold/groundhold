package gcp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// cidrIsWholeInternet / gkeAuthorizesWholeInternet: only a /0 mask authorizes every
// address. A real authorized-network CIDR is a genuine restriction; an unparseable
// entry is not guessed public.
func TestCidrIsWholeInternet(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"1.2.3.4/0", true}, // any /0 covers everything
		{" 0.0.0.0/0 ", true},
		{"10.0.0.0/8", false},
		{"203.0.113.5/32", false},
		{"0.0.0.0/1", false}, // half the internet, not all — a genuine (if broad) restriction
		{"garbage", false},
		{"", false},
	}
	for _, c := range cases {
		if got := cidrIsWholeInternet(c.cidr); got != c.want {
			t.Errorf("cidrIsWholeInternet(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
	if !gkeAuthorizesWholeInternet([]gkeCidrBlock{{CidrBlock: "10.0.0.0/8"}, {CidrBlock: "0.0.0.0/0"}}) {
		t.Error("a list containing 0.0.0.0/0 authorizes the whole internet")
	}
	if gkeAuthorizesWholeInternet([]gkeCidrBlock{{CidrBlock: "10.0.0.0/8"}}) {
		t.Error("a list of real CIDRs does not authorize the whole internet")
	}
}

// THE MUTANT-DEFECT TEST: an authorized-networks list that contains 0.0.0.0/0 leaves
// the API server reachable by anyone. The old observe read only the Enabled flag and
// emitted apiExposure="mixed" (a restricted control) — a false-green over an
// internet-open control plane. It must read "public".
func TestObserveGKE_WholeInternetAuthorizedNetworkIsPublic(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.manEnabled = true
	f.manCidrs = []string{"0.0.0.0/0"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	m := gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1", name))
	if m["network.apiExposure"] != "public" {
		t.Fatalf("apiExposure = %v, want public (0.0.0.0/0 in the authorized-network set is no restriction)",
			m["network.apiExposure"])
	}
}

// A real authorized-network CIDR still reads "mixed" — the fix must not over-flag a
// genuinely restricted endpoint.
func TestObserveGKE_RealAuthorizedNetworkStaysMixed(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.manEnabled = true
	f.manCidrs = []string{"203.0.113.0/24"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	m := gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1", name))
	if m["network.apiExposure"] != "mixed" {
		t.Fatalf("apiExposure = %v, want mixed (a real authorized-network restriction)", m["network.apiExposure"])
	}
}

// The build side must refuse minting the same false-green: apiExposure=mixed with a
// 0.0.0.0/0 authorized CIDR is public, not mixed.
func TestBuildGKE_RejectsWholeInternetAuthorizedCidr(t *testing.T) {
	attrs, impl := gkeCandidate()
	attrs["network.apiExposure"] = "mixed"
	impl["masterAuthorizedCidrs"] = []any{"0.0.0.0/0"}
	_, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err == nil || !strings.Contains(err.Error(), "WHOLE internet") {
		t.Fatalf("a /0 authorized CIDR under mixed must be refused as public, got err=%v", err)
	}
}
