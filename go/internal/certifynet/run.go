package certifynet

import (
	"net/http"

	"groundhold/internal/provider"
)

type runResult struct {
	res      provider.CreateResult
	trace    []record
	mutAfter int
	poisoned bool
}

// runOnce builds the provider against the happy server with a scripted transport
// and runs one op, optionally injecting a fault at request index faultAt.
func runOnce(p *Probe, op Op, faultAt int, fault Fault) runResult {
	srv := op.Happy()
	defer srv.Close()
	rt := &scriptRT{
		inner:    http.DefaultTransport,
		classify: p.Classify,
		faultAt:  faultAt,
		fault:    fault,
		ownerTag: p.OwnerTagValue,
	}
	prov := p.New(srv.URL, rt)
	res := op.Run(prov)
	return runResult{res: res, trace: rt.trace, mutAfter: rt.mutAfter, poisoned: rt.poisoned}
}

// CertifyDriverNet runs the adversarial honesty harness for one driver probe.
// It records each op's baseline trace, then perturbs every request with every
// applicable fault and asserts the law-derived honesty invariants.
func CertifyDriverNet(t TestingT, p *Probe) {
	t.Helper()
	if p.ObserveAbsent != nil {
		certifyAbsence(t, p)
	}
	for _, op := range p.Ops {
		base := runOnce(p, op, -1, FaultNone)
		if base.res.Status != "succeeded" {
			t.Fatalf("%s/%s: baseline (no fault) must succeed, got %+v", p.Name, op.Name, base.res)
			continue
		}
		basePID := base.res.ProviderID
		if len(base.trace) == 0 {
			t.Errorf("%s/%s: baseline made no HTTP requests — probe misconfigured", p.Name, op.Name)
			continue
		}
		firstParsed := firstParsedIndex(base.trace)
		// delete/update receive the providerId as INPUT, so it is always knowable;
		// only create may discover a server-assigned id.
		pidAlwaysKnown := op.Name != "create"
		for i := 0; i < len(base.trace); i++ {
			// the pid is knowable at a fault at index i if it is an input, or
			// deterministic, or the id-yielding parsed mutation already succeeded.
			pidKnown := pidAlwaysKnown || p.DeterministicID || (firstParsed >= 0 && i > firstParsed)
			for _, f := range faultsAt(base.trace, i, p.AssertTransient) {
				r := runOnce(p, op, i, f)
				assertHonest(t, p.Name, op.Name, i, f, r, basePID, pidKnown)
			}
		}
	}
}

// firstParsedIndex returns the first RoleMutateParsed trace index (the call that
// yields a server-assigned id), or -1.
func firstParsedIndex(trace []record) int {
	for _, r := range trace {
		if r.role == RoleMutateParsed {
			return r.idx
		}
	}
	return -1
}

// assertHonest applies the derived oracle: the verdict SHAPE is a function of
// (fault class, request role), never of driver identity. pidKnown says whether the
// providerId is knowable at this fault position (always for deterministic names;
// only after the id-yielding call for server-assigned ids).
func assertHonest(t TestingT, driver, op string, i int, f Fault, r runResult, basePID string, pidKnown bool) {
	t.Helper()
	res := r.res
	where := driverWhere(driver, op, i, f)

	switch f {
	case Fault500, FaultConnDrop, FaultGarbled200, FaultEmptyBody, Fault429, Fault503, Fault403:
		// An unresolved mutation outcome must be unknown. NEVER succeeded (didn't
		// confirm), NEVER failed. D237: a throttle (429), a service-unavailable
		// (503) and — crucially — a LIVE permission denial (403) are all
		// statements about the WIRE, not proof the resource does not exist; a 403
		// can be a stale IAM read or arrive after a compound mutation partly
		// landed, so terminal `failed` would orphan a resource (the D62 phantom
		// class). All map to unknown with the providerId preserved.
		if res.Status != "unknown" {
			t.Errorf("%s: an unresolved mutation outcome must be unknown, got %q: %+v", where, res.Status, res)
		}
		// the handle must be preserved wherever it is knowable; a non-empty pid
		// must always be the right one.
		if pidKnown && basePID != "" && res.ProviderID != basePID {
			t.Errorf("%s: the unknown dropped the knowable providerId (want %q) — handle lost: %+v",
				where, basePID, res)
		} else if res.ProviderID != "" && basePID != "" && res.ProviderID != basePID {
			t.Errorf("%s: the unknown carried a WRONG providerId (want %q): %+v", where, basePID, res)
		}
	case FaultForeignTag:
		if !r.poisoned {
			return // the surgery did not hit an ownership tag on this request — n/a
		}
		if res.Status != "failed" {
			t.Errorf("%s: a foreign-owned resource must be REFUSED (failed), got %q: %+v", where, res.Status, res)
		}
		if r.mutAfter > 0 {
			t.Errorf("%s: driver MUTATED a resource whose ownership tag was FOREIGN — ownership bypass: %+v", where, res)
		}
	}
}

func driverWhere(driver, op string, i int, f Fault) string {
	return driver + "/" + op + " fault=" + f.String() + " at req#" + itoa(i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
