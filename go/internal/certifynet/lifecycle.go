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
	requests  int
	// readFound records whether any READ actually found something (a 2xx). A
	// foreign-refusal probe whose estate answers 404 to every read proves nothing
	// about the ownership check: the driver refuses because the resource is not
	// there, which is a different code path and a different guarantee (D524).
	readFound bool
}

func (c *countRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.requests++
	body := peekBody(req)
	role := c.classify(req, body)
	restoreBody(req, body) // a classifier that read the request must not cost the driver its body
	if role.isMutation() {
		c.mutations++
	}
	resp, err := c.inner.RoundTrip(req)
	if err == nil && resp != nil && !role.isMutation() &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.readFound = true
	}
	return resp, err
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
	// D527: the refusal must come from LOOKING. A driver that refuses at validation
	// — a malformed operand, a missing field — satisfies both assertions above
	// without ever asking whether the named cluster is there, and the property this
	// gate exists for goes unexercised. Same hole D455 closed in the foreign-refusal
	// harness, in a harness D455 did not touch.
	if rt.requests == 0 {
		t.Errorf("%s: [reason=%q] the refusal came WITHOUT reading the estate — the driver "+
			"never asked whether the named cluster exists, so this proves nothing about "+
			"adopt-by-name. Either the fixture's operands are malformed (the driver refused "+
			"at validation) or the check is missing.", p.Name, res.Reason)
	}
}
