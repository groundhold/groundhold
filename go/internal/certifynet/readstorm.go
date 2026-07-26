// Read-storm certification (D266) — the cross-driver gate for the transient-read
// retry class the Acme saga exposed (D260). The base harness (certifynet.go) injects
// ONE fault at ONE index and, by construction, never faults a read with a transient
// error: a single-fault model cannot express "the driver should RETRY and still
// succeed". This file adds that missing axis. A stormRT faults the FIRST K requests
// classified as a READ with the transient class (503/429/connection-drop), then serves
// happy. A driver whose single-shot reads retry the transient class (EKS eksGet, GCP
// gcpGetRetry, Azure armGet) rides out the storm and still concludes the create
// SUCCEEDED with its pid; a driver that does one-shot-then-give-up reports a false
// `unknown` and fails HERE, in CI — not on a field user's production run (which is
// exactly how D260 escaped: a momentary throttle on an ownership read DIED a healthy
// converge). No per-API knowledge is needed: the gate reuses the driver's existing
// happy fake and Classify, so any retry-claiming driver enrolls with its create op.
package certifynet

import (
	"fmt"
	"net/http"
)

// stormRT faults the first faultReads READ requests with a rotating transient fault,
// then delegates to inner. Mutations are never faulted here (that is the base
// harness's job) — this axis is exclusively about read resilience.
type stormRT struct {
	inner      http.RoundTripper
	classify   Classifier
	faultReads int
	faults     []Fault

	seen int // READ requests faulted so far
}

func (s *stormRT) RoundTrip(req *http.Request) (*http.Response, error) {
	body := peekBody(req)
	if s.classify(req, body) == RoleRead && s.seen < s.faultReads {
		f := s.faults[s.seen%len(s.faults)]
		s.seen++
		switch f {
		case FaultConnDrop:
			return nil, fmt.Errorf("injected transient read drop")
		case Fault429:
			return mkResp(req, 429, `{"error":{"message":"rate limited"}}`), nil
		default: // Fault503
			return mkResp(req, 503, `{"error":{"message":"service unavailable"}}`), nil
		}
	}
	return s.inner.RoundTrip(req)
}

// ReadStormFaults is the transient class faulted on leading reads. Below any real
// driver's retry budget (EKS/GCP/Azure use 4 attempts), so a correct driver rides it
// out and a non-retrying one is caught.
const ReadStormFaults = 3

// CertifyReadRetry runs the read-storm gate on a probe's create op: the first
// ReadStormFaults READ requests fault transiently, and the create MUST still succeed
// with the baseline providerId. Enroll every driver whose read layer claims to retry
// the transient class; a regression that drops the retry fails here.
func CertifyReadRetry(t TestingT, p *Probe) {
	t.Helper()
	ran := false
	for _, op := range p.Ops {
		if op.Name != "create" {
			continue
		}
		ran = true
		// baseline: no faults -> establish the pid the storm run must preserve.
		baseSrv := op.Happy()
		basePID := op.Run(p.New(baseSrv.URL, http.DefaultTransport)).ProviderID
		baseSrv.Close()

		srv := op.Happy()
		rt := &stormRT{
			inner:      http.DefaultTransport,
			classify:   p.Classify,
			faultReads: ReadStormFaults,
			faults:     []Fault{Fault503, Fault429, FaultConnDrop},
		}
		res := op.Run(p.New(srv.URL, rt))
		srv.Close()

		if res.Status != "succeeded" {
			t.Errorf("%s: a create that hit %d leading transient READ faults must still succeed — the "+
				"read layer must retry the transient class (D260/D266). Got status=%q reason=%q. A "+
				"single-shot read with no retry turns a healthy op into a false unknown (the Acme D260 class).",
				p.Name, ReadStormFaults, res.Status, res.Reason)
		}
		if res.Status == "succeeded" && basePID != "" && res.ProviderID != basePID {
			t.Errorf("%s: read-storm create bound a different pid (%q) than the baseline (%q) — the handle "+
				"must survive a retried read", p.Name, res.ProviderID, basePID)
		}
	}
	if !ran {
		t.Errorf("%s: CertifyReadRetry needs a create op", p.Name)
	}
}
