package certifynet

import (
	"net/http"
	"net/http/httptest"

	"groundhold/internal/provider"
)

// D461 — the fourth register: the intrusive probe.
//
// A probe normally reads. Under `allowIntrusive` (D59's double consent) it does not: it
// CREATES a scratch resource — a restored database, on the caller's bill — measures the
// recovery, and destroys it. That is a write, on a resource, with money attached, and
// until now no register asked whether it was the right resource.
//
// The three cloud probers each gate by hand and each says why, in a comment written by
// whoever added it. That is exactly the state the delete paths were in before D439:
// individually careful, collectively unasserted, and silent about the next one. The
// damage model is its own: a foreign intrusive probe does not destroy the resource it
// targets, it SPENDS against an account that never agreed to the spend, and on AWS the
// scratch restore is created from a stranger's snapshot.
type IntrusiveProbeProbe struct {
	Name string
	// ForeignServer is a fake where the resource at our providerId EXISTS but carries
	// ownership markers that are NOT ours.
	ForeignServer func() *httptest.Server
	New           func(happyURL string, rt http.RoundTripper) provider.Prober
	Classify      Classifier
	// Probe runs the driver's probe with allowIntrusive TRUE against that resource.
	Probe func(p provider.Prober) (provider.ProbeOutcome, error)
}

// CertifyIntrusiveProbeRefusesForeign requires the refusal to happen BEFORE the spend:
// an error, no intrusive outcome, and zero mutations on the wire. The mutation count is
// the load-bearing assertion — a prober can report an error after having already asked
// for a restore, and the error would read exactly the same.
func CertifyIntrusiveProbeRefusesForeign(t TestingT, p *IntrusiveProbeProbe) {
	t.Helper()
	srv := p.ForeignServer()
	defer srv.Close()
	rt := &countRT{inner: http.DefaultTransport, classify: p.Classify}

	out, err := p.Probe(p.New(srv.URL, rt))

	if err == nil {
		t.Errorf("%s: an INTRUSIVE probe against a resource whose ownership markers are "+
			"NOT ours returned no error — the driver was willing to bill a restore "+
			"against an estate that never agreed to it.", p.Name)
	}
	if rt.mutations > 0 {
		t.Errorf("%s: refusing an intrusive probe on a FOREIGN resource still sent %d "+
			"mutation(s). The refusal came after the spend, which makes it a report "+
			"rather than a guard.", p.Name, rt.mutations)
	}
	// D527: the refusal must come from LOOKING, and there must have been something
	// to look at. A driver that refuses at providerId parsing returns an error and
	// zero mutations without ever asking whose resource it is; an estate that 404s
	// every read makes it refuse an ABSENT resource, not a foreign one. Both satisfy
	// every assertion above. This harness was written in the same session that
	// closed the identical hole in the delete/update family (D455) and did not
	// carry the lesson across — which is the argument for asking a property of a
	// CLASS rather than of one verb at a time.
	if rt.requests == 0 {
		t.Errorf("%s: the intrusive probe refused WITHOUT reading the estate — it never "+
			"asked whose resource this is, so the ownership check is unproven.", p.Name)
	} else if !rt.readFound {
		t.Errorf("%s: no read of the foreign estate returned a resource — every read 404'd, "+
			"so the probe refused an ABSENT resource rather than a foreign one.", p.Name)
	}
	for _, m := range out.Measurements {
		if m.Intrusive {
			t.Errorf("%s: refused, yet reported an INTRUSIVE measurement (%q) — an "+
				"outcome that was never measured is worse than no outcome.", p.Name, m.Path)
		}
	}
}
