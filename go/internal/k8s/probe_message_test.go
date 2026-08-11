package k8s

import (
	"strings"
	"testing"
)

// D574, the call site D550 missed. Running the reachability probe against the live
// cluster on a cert-manager contract:
//
//	web: probe error: k8s driver: unknown service "certmanager-cert"
//	     (wired: rbac-role, rbac-grant, rbac-clusterrole, ...)
//
// The driver serves that service — it observes, creates, adopts and retires it, all
// proven on the same cluster the same afternoon. What it does not have is a PROBE for
// it, and `Probe` says exactly that two lines below:
//
//	k8s driver: probes for service %q are not wired
//
// The truthful refusal is unreachable, because `requireService` runs first and
// answers a different question. An operator reads "unknown service" as "this driver
// cannot see my resource at all" and goes looking for a driver bug that is not there.
//
// D550 fixed this class at three call sites. It missed this one because I found them
// by tracing ONE failing command, so the fix covered exactly the trace. Enumerating
// the call sites afterwards is what turned up the fourth — three of the four now ask
// the mapping registry before the hand-coded list, and this was the one that did not.
func TestProbeSaysNoProbeNotUnknownService(t *testing.T) {
	d := NewDriver("https://example.invalid", "t")
	// Both halves of the registry, because they fall through differently once the
	// dispatch gate stopped saying "unknown service" for everything mapped (D584):
	// a WRITE-SAFE service now reaches a truthful fallback by accident, while a
	// read-only one lands on "observed but not written" — accurate about writing and
	// silent about the probe the operator actually asked for.
	for _, svc := range []string{"certmanager-cert", "flux-kustomization"} {
		m := d.mappingFor(svc)
		if m == nil {
			t.Fatalf("%s is not mapped — the fixture is wrong", svc)
		}
		_, err := d.Probe(svc, m.Capability, m.buildProviderID("default", "web"), false)
		if err == nil {
			t.Fatalf("%s: a service with no probe must refuse", svc)
		}
		if strings.Contains(err.Error(), "unknown service") {
			t.Errorf("%s: the refusal says the driver does not know a service it "+
				"observes and adopts: %v", svc, err)
		}
		if !strings.Contains(err.Error(), "probe") {
			t.Errorf("%s: the refusal never mentions probes, so it answers a question "+
				"the operator did not ask: %v", svc, err)
		}
	}
}

// A service the driver genuinely does not serve must still fail closed, and must not
// borrow the friendlier probe wording.
func TestProbeStillRefusesAnUnservedService(t *testing.T) {
	d := NewDriver("https://example.invalid", "t")
	_, err := d.Probe("__not_a_service__", "capability.network.private", "x/y/Z/n/m", false)
	if err == nil {
		t.Fatal("an unserved service was accepted by the probe gate")
	}
	if !strings.Contains(err.Error(), "unknown service") {
		t.Errorf("a service the driver does not serve should say so, not blame a "+
			"missing probe: %v", err)
	}
}
