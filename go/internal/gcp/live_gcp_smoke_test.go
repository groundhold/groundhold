package gcp

import (
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
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
//
// D718: the subject is DERIVED, not typed. This gate carried eight GKE paths by hand,
// so it covered one service; the measurement that found the Secret Manager and
// Artifact Registry `:getIamPolicy` defect had to be run outside it. It reads
// testdata/gcp-routes.txt now, recorded from what the drivers build.
//
// The predicate is deliberately WEAKER than the AWS one, and the reason is worth
// stating rather than hiding: GCP tests point several base-URL overrides at one
// fixture server, so a recorded URL's origin often cannot say which service it
// belonged to. Such a line carries its candidate set, and the gate accuses only when a
// route exists under NONE of them. That still catches "the driver builds a path this
// cloud does not have anywhere" — the D717/D718 class — and never accuses a driver
// because the test harness was ambiguous.
func TestLiveGCPEndpointReality(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_GCP_SMOKE") != "1" {
		t.Skip("live GCP endpoint-reality disabled (set GROUNDHOLD_LIVE_GCP_SMOKE=1 with network egress)")
	}
	d := NewDriver("x")

	// A real route is auth-gated (401/403) for an unauthenticated call. A 404 is
	// ambiguous and the distinction matters: the Google FRONTEND answers an unmatched
	// route with an HTML page, while an API answers a missing RESOURCE under a real
	// route with its JSON error envelope. Reading every 404 as "no such route" accused
	// every Cloud Storage and IAM path in the set, because those APIs answer an
	// anonymous caller about a resource rather than demanding credentials first.
	exists := func(method, url string) (bool, string) {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return false, "unbuildable request: " + err.Error()
		}
		resp, err := d.HTTP.Do(req) // the DRIVER's client — a transport regression fails here
		if err != nil {
			return false, "transport error: " + err.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		resp.Body.Close()
		body := strings.TrimSpace(string(b))
		absent := resp.StatusCode == http.StatusNotFound && strings.HasPrefix(body, "<")
		return !absent, body[:min(len(body), 140)]
	}

	raw, err := os.ReadFile(routesFile)
	if err != nil {
		t.Fatalf("read %s: %v", routesFile, err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// D328: assert the subject before reporting on it.
	if len(lines) < 400 {
		t.Fatalf("%s holds %d routes — too few to be the real set; the gate would report "+
			"clean without asking about most of what the drivers call", routesFile, len(lines))
	}
	// 694 routes with candidate sets is thousands of requests, and the same URL recurs
	// across lines. Ask each DISTINCT (method, url) once, concurrently, then read the
	// verdicts out of that table. Asked naively this outran the test timeout, and when
	// it did finish it accused two dozen healthy routes — the extra load produced
	// transport errors that the classifier could not tell from "route absent". A gate
	// that manufactures its own evidence is worse than no gate.
	type req struct{ method, url string }
	type ans struct {
		exists bool
		detail string
	}
	want := map[req]bool{}
	type job struct {
		method, shown string
		urls          []string
	}
	var jobs []job
	ambiguous := 0
	for _, l := range lines {
		p := strings.SplitN(l, "\t", 3)
		if len(p) != 3 {
			t.Fatalf("malformed line in %s: %q", routesFile, l)
		}
		urls := candidateURLs(p[0], p[2])
		if len(urls) == 0 {
			t.Errorf("route %q resolves to no URL — it went unasked", l)
			continue
		}
		if len(urls) > 1 {
			ambiguous++
		}
		for _, u := range urls {
			want[req{p[1], u}] = true
		}
		jobs = append(jobs, job{method: p[1], shown: p[2], urls: urls})
	}

	var mu sync.Mutex
	answers := map[req]ans{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for r := range want {
		wg.Add(1)
		go func(r req) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok, detail := exists(r.method, r.url)
			mu.Lock()
			answers[r] = ans{ok, detail}
			mu.Unlock()
		}(r)
	}
	wg.Wait()

	// A transport failure is NOT an absent route. Counting it as one is how this gate
	// accused healthy drivers; it is reported as unmeasured instead, loudly.
	unmeasured := 0
	for r, a := range answers {
		if !a.exists && strings.HasPrefix(a.detail, "transport error") {
			unmeasured++
			answers[r] = ans{true, a.detail} // do not accuse on evidence we do not have
		}
	}
	for _, j := range jobs {
		var details []string
		found := false
		for _, u := range j.urls {
			a := answers[req{j.method, u}]
			if a.exists {
				found = true
				break
			}
			details = append(details, u+" -> "+strings.ReplaceAll(a.detail, "\n", " "))
		}
		if !found {
			t.Errorf("%s %s exists under none of its candidate services — the driver builds "+
				"a path GCP does not have (the D717/D718 class):\n    %s",
				j.method, j.shown, strings.Join(details, "\n    "))
		}
	}
	t.Logf("asked Google about %d distinct requests for %d routes (%d against a candidate "+
		"set, because the test harness shares one fixture across several bases); %d could "+
		"not be measured and were not counted against any driver",
		len(want), len(jobs), ambiguous, unmeasured)

	// NEGATIVE CONTROLS: routes this project either never had or shipped wrongly. If any
	// reads as real, the classifier has stopped working and every result above is noise.
	for _, c := range []struct{ why, method, url string }{
		{"D273-shaped nested sub-resource", "GET",
			"https://container.googleapis.com/v1/projects/x/locations/y/clusters/z/nodePools/np/updates/id"},
		{"D718 secretmanager getIamPolicy under POST", "POST",
			"https://secretmanager.googleapis.com/v1/projects/p/secrets/x:getIamPolicy"},
		{"D718 artifactregistry getIamPolicy under POST", "POST",
			"https://artifactregistry.googleapis.com/v1/projects/p/locations/l/repositories/r:getIamPolicy"},
	} {
		if ok, _ := exists(c.method, c.url); ok {
			t.Errorf("negative control FAILED (%s): a known-nonexistent route was not "+
				"flagged — the gate has no teeth", c.why)
		}
	}
}
