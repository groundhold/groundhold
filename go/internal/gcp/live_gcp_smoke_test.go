package gcp

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestLiveGCPEndpointReality (D274) is the GKE twin of the AWS endpoint-reality gate:
// it validates that EVERY GKE endpoint the driver constructs ACTUALLY EXISTS on real
// GCP. The container.googleapis.com frontend returns a DISTINGUISHABLE signal — a real
// route needs auth (401 UNAUTHENTICATED) while an unmatched route is a 404 from the
// Google frontend — so this needs network egress but NO credentials. It drives the
// DRIVER's own HTTP client, so a transport regression fails here too. The pattern is
// identical across clouds; only the unmatched-route signal differs (AWS: an API-Gateway
// message; GCP: a 404). Gated by GROUNDHOLD_LIVE_GCP_SMOKE=1.
//
// Azure has no creds-free twin: ARM validates the subscription before it routes the
// provider path (a well-formed but nonexistent subscription short-circuits to
// SubscriptionNotFound), so an ARM endpoint-reality check needs a real subscription.
// AKS also carries no D273-class risk — it polls the resource's own provisioningState,
// never a constructed sub-resource path — so that gap is an accepted, documented boundary.
func TestLiveGCPEndpointReality(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_GCP_SMOKE") != "1" {
		t.Skip("live GCP endpoint-reality disabled (set GROUNDHOLD_LIVE_GCP_SMOKE=1 with network egress)")
	}
	const base = "https://container.googleapis.com/v1"
	d := NewDriver("x")

	route := func(method, path string) (recognized bool, detail string) {
		req, _ := http.NewRequest(method, base+path, nil)
		resp, err := d.HTTP.Do(req) // the DRIVER's client — a transport regression fails here
		if err != nil {
			return false, "transport error: " + err.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		resp.Body.Close()
		// A real route is auth-gated (401) for an unauthenticated call; an unmatched route
		// is a 404 from the Google frontend. 404 == the route does not exist.
		return resp.StatusCode != http.StatusNotFound, strings.TrimSpace(string(b[:min(len(b), 120)]))
	}

	// EVERY (method, path) the GKE driver constructs, with bogus placeholders.
	for _, e := range []struct{ method, path string }{
		{"GET", "/projects/x/locations/y/clusters"}, {"POST", "/projects/x/locations/y/clusters"},
		{"GET", "/projects/x/locations/y/clusters/z"}, {"PUT", "/projects/x/locations/y/clusters/z"},
		{"DELETE", "/projects/x/locations/y/clusters/z"},
		{"GET", "/projects/x/locations/y/operations/op"},
		{"GET", "/projects/x/locations/-/clusters"},
		{"POST", "/projects/x/locations/y/clusters/z:setAddons"},
	} {
		if ok, detail := route(e.method, e.path); !ok {
			t.Errorf("GKE endpoint %s %s is NOT a real GCP route (%q) — the driver calls a nonexistent "+
				"path (the D273 class), or the client cannot connect (a transport regression)", e.method, e.path, detail)
		}
	}
	// NEGATIVE CONTROL: a plausible-but-nonexistent nested sub-resource MUST be flagged.
	if ok, _ := route("GET", "/projects/x/locations/y/clusters/z/nodePools/np/updates/id"); ok {
		t.Error("negative control FAILED: a known-nonexistent nested path was not flagged — the gate has no teeth")
	}
}
