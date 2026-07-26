package aws

import (
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
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Log("no AWS creds in env — signed DescribeCluster check skipped (protocol check passed)")
		return
	}
	_, found, rerr := d.describeEKSCluster(region, "groundhold-smoke-none")
	if rerr != nil {
		t.Fatal("signed DescribeCluster on a nonexistent cluster must be READABLE (a clean 404) — " +
			"D269 broke exactly this (create DIED because the 404 response was unparseable -> 'unreadable')")
	}
	if found {
		t.Fatal("a nonexistent cluster must be found=false")
	}
	t.Log("signed DescribeCluster check: nonexistent cluster -> readable=true, found=false (create pre-read OK)")
}

// TestLiveAWSEndpointReality (D274) is the generalizable gate for the D273 wrong-path
// class: it validates that EVERY EKS endpoint the driver constructs ACTUALLY EXISTS on
// real AWS. AWS API Gateway returns a DISTINGUISHABLE signal for an unmatched route
// ("Unable to determine service/operation name") vs a real one ("Missing Authentication
// Token"), so this needs network egress but NO credentials. It drives the DRIVER's own
// HTTP client, so a transport regression (the D269 ALPN break -> a connection error)
// fails here too. The nonexistent path that caused F29 (D273) is a NEGATIVE control the
// gate MUST flag. Gated by GROUNDHOLD_LIVE_AWS_SMOKE=1. The pattern extends to every
// service/cloud: list the (method,path) a driver calls, assert each is a real route.
func TestLiveAWSEndpointReality(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_AWS_SMOKE") != "1" {
		t.Skip("live AWS endpoint-reality disabled (set GROUNDHOLD_LIVE_AWS_SMOKE=1 with network egress)")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	base := "https://eks." + region + ".amazonaws.com"
	const unmatched = "Unable to determine service/operation name"
	d := NewDriver(region)

	route := func(method, path string) (recognized bool, detail string) {
		req, _ := http.NewRequest(method, base+path, nil)
		resp, err := d.HTTP.Do(req) // the DRIVER's client — a transport/ALPN break fails here
		if err != nil {
			return false, "transport error: " + err.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		resp.Body.Close()
		return !strings.Contains(string(b), unmatched), strings.TrimSpace(string(b))
	}

	// EVERY (method, path) the EKS driver constructs, with bogus placeholders.
	for _, e := range []struct{ method, path string }{
		{"GET", "/clusters"}, {"POST", "/clusters"},
		{"GET", "/clusters/x"}, {"DELETE", "/clusters/x"},
		{"GET", "/clusters/x/node-groups"}, {"POST", "/clusters/x/node-groups"},
		{"GET", "/clusters/x/node-groups/y"}, {"DELETE", "/clusters/x/node-groups/y"},
		{"POST", "/clusters/x/node-groups/y/update-version"},
		{"GET", "/clusters/x/updates/z"},
		{"GET", "/clusters/x/addons"}, {"POST", "/clusters/x/addons"},
		{"GET", "/clusters/x/addons/a"}, {"DELETE", "/clusters/x/addons/a"},
		{"POST", "/clusters/x/addons/a/update"},
		{"GET", "/clusters/x/pod-identity-associations"}, {"POST", "/clusters/x/pod-identity-associations"},
		{"GET", "/clusters/x/pod-identity-associations/id"}, {"DELETE", "/clusters/x/pod-identity-associations/id"},
	} {
		if ok, detail := route(e.method, e.path); !ok {
			t.Errorf("EKS endpoint %s %s is NOT a real AWS route (%q) — the driver calls a nonexistent "+
				"path (the D273 class), or the client cannot connect (a transport regression)", e.method, e.path, detail)
		}
	}
	// NEGATIVE CONTROL: the exact D273 wrong path MUST be flagged, or the gate is toothless.
	if ok, _ := route("GET", "/clusters/x/node-groups/y/updates/z"); ok {
		t.Error("negative control FAILED: the known-nonexistent D273 path was not flagged — the gate has no teeth")
	}
}
