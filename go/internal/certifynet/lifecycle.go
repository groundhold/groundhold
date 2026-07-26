// Lifecycle certification (D266) — the cross-driver gate for the bounded-poll /
// never-hang class the Acme saga exposed (D258/D259). A driver that polls a resource
// to a terminal state must BOUND that poll: if the resource never reaches ready (a
// phantom name it will never see ACTIVE, a genuinely stuck LRO), the driver must
// conclude `unknown` WITH the pid within its poll budget — never spin forever (the
// multi-minute hang Acme hit twice) and never fabricate success. This gate drives a
// create against a fake whose resource is created but never becomes ready, and asserts
// the result is a prompt unknown-with-pid. The hang itself is caught cleanly by a
// goroutine guard rather than a whole-suite test timeout.
package certifynet

import (
	"net/http"
	"net/http/httptest"
	"time"

	"groundhold/internal/provider"
)

// LifecycleProbe wires a driver's stuck-resource scenario into the bounded-poll gate.
// StuckServer returns a fake where the primary resource is CREATED but its status
// poll never reports ready. New builds the driver pointed at it with a SHORT LRO
// budget (so a bounded driver concludes quickly). PID is the deterministic providerId
// the create must preserve for reconcile.
type LifecycleProbe struct {
	Name        string
	StuckServer func() *httptest.Server
	New         func(happyURL string, rt http.RoundTripper) provider.Provider
	Create      func(p provider.Provider) provider.CreateResult
	PID         string
}

// CertifyBoundedPoll asserts a create whose resource never reaches ready concludes a
// prompt unknown-with-pid — never hangs, never falsely succeeds (D258/D259/D266).
func CertifyBoundedPoll(t TestingT, p *LifecycleProbe) {
	t.Helper()
	srv := p.StuckServer()
	defer srv.Close()
	prov := p.New(srv.URL, http.DefaultTransport)

	done := make(chan provider.CreateResult, 1)
	go func() { done <- p.Create(prov) }()
	select {
	case res := <-done:
		if res.Status != "unknown" {
			t.Errorf("%s: a create whose resource never reaches ready must be unknown — a bounded poll "+
				"with the handle preserved, never a false success. Got status=%q reason=%q.",
				p.Name, res.Status, res.Reason)
		}
		if p.PID != "" && res.Status == "unknown" && res.ProviderID != p.PID {
			t.Errorf("%s: a stuck-poll create must preserve the pid for reconcile, got %q want %q",
				p.Name, res.ProviderID, p.PID)
		}
	case <-time.After(30 * time.Second):
		t.Errorf("%s: create HUNG — the poll is not bounded by the LRO budget (the D258/D259 phantom-poll "+
			"hang class). A stuck resource must conclude unknown, never spin forever.", p.Name)
	}
}

// countRT counts the mutations a driver sends, faulting nothing — the wire evidence
// for the no-duplicate invariant.
type countRT struct {
	inner     http.RoundTripper
	classify  Classifier
	mutations int
}

func (c *countRT) RoundTrip(req *http.Request) (*http.Response, error) {
	body := peekBody(req)
	if c.classify(req, body).isMutation() {
		c.mutations++
	}
	return c.inner.RoundTrip(req)
}

// DuplicateProbe wires a driver's adopt-by-name path into the no-duplicate gate.
// AbsentServer returns a fake in which the cluster the candidate names (its
// implementation.clusterName) does NOT exist; Create runs a create whose candidate
// carries that adopt name; Classify counts mutations structurally.
type DuplicateProbe struct {
	Name         string
	AbsentServer func() *httptest.Server
	New          func(happyURL string, rt http.RoundTripper) provider.Provider
	Classify     Classifier
	Create       func(p provider.Provider) provider.CreateResult
}

// CertifyNoDuplicate is the D267 gate for the custom-name duplicate class (D261): a
// create whose candidate targets an existing cluster BY NAME (adopt-by-name), but
// whose named cluster does not exist, must REFUSE — never stand up a duplicate at an
// adoption name. That was the root of the whole Acme saga: a custom-named brownfield
// cluster never matched a deterministic name, so a SECOND cluster was created and every
// later "hang"/"unknown" was interaction with that stray. The gate asserts BOTH the
// refusal AND — the real proof — that ZERO mutations were sent.
func CertifyNoDuplicate(t TestingT, p *DuplicateProbe) {
	t.Helper()
	srv := p.AbsentServer()
	defer srv.Close()
	rt := &countRT{inner: http.DefaultTransport, classify: p.Classify}
	res := p.Create(p.New(srv.URL, rt))
	if res.Status != "failed" {
		t.Errorf("%s: adopt-by-name for a cluster that does NOT exist must REFUSE (never create at an adoption "+
			"name — the Acme D261 class). Got status=%q reason=%q.", p.Name, res.Status, res.Reason)
	}
	if rt.mutations > 0 {
		t.Errorf("%s: adopt-by-name for an ABSENT named cluster sent %d mutation(s) — it created a DUPLICATE "+
			"instead of refusing (the exact Acme failure).", p.Name, rt.mutations)
	}
}
