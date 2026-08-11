package k8s

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D550, measured on a live cluster: adopting a Flux Kustomization refused with
//
//	cannot confirm no competing reconciler owns .../Kustomization/default/platform:
//	k8s driver: unknown service "flux-kustomization"
//
// The driver serves ten mapped services and `requireService` hard-codes seven. Every
// other verb checks the mapping REGISTRY first and returns before reaching that
// list — `Observe`, `Validate`, `Create` all do — which is why observation and
// creation work for the other three and only ADOPTION fails. One call site was
// missing the pattern every sibling has.
//
// The consequence is brownfield takeover: a cert-manager Certificate, an ArgoCD
// Application or a Flux Kustomization that already exists cannot be adopted at all,
// and the error blames a competing-reconciler check that never ran.
func TestCompetingManagersKnowsTheMappedServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"name":"platform","namespace":"default","managedFields":[]}}`))
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")

	tokens := d.MappedServiceTokens()
	if len(tokens) < 10 {
		t.Fatalf("only %d mapped services — the fixture stopped covering the driver", len(tokens))
	}
	for _, svc := range tokens {
		m := d.mappingFor(svc)
		_, err := d.CompetingManagers(svc, m.buildProviderID("default", "platform"))
		if err != nil {
			t.Errorf("%s: CompetingManagers fails for a service the driver SERVES: %v\n"+
				"adopt cannot take over an existing one, and the error blames a check "+
				"that never ran", svc, err)
		}
	}
}

// The dispatch gate must still fail closed on a service the driver does not serve —
// the whole point of it (D76). Widening it must not turn it into a pass-through.
func TestCompetingManagersStillRefusesAnUnknownService(t *testing.T) {
	d := NewDriver("https://x", "t")
	if _, err := d.CompetingManagers("__not_a_service__", "x/y/Z/n"); err == nil {
		t.Error("an unknown service was accepted — the dispatch gate stopped failing closed")
	}
}

// D550, second half, measured on the same live cluster: `discover` enumerated
//
//	providerId: argoproj.io/v1alpha1/Application/default/root-app
//	observations: health.status=degraded (measured), service.managed=true (measured)
//
// while `observe` on that exact service refused with `unknown service
// "argocd-application"`. Discovery asks the mapping REGISTRY (mappingFor); every
// verb asked genericMapping, which is mappingFor AND writeSafe. So a mapping with
// no write lens — flux-kustomization, argocd-application — is enumerated as real,
// with measured values, and then disowned when anything asks about it by name.
//
// Reading is not writing. A read has no business consulting a write-safety
// predicate, and gating it on one makes the driver contradict itself about the
// same object within one run.
func TestReadingDoesNotRequireAWriteLens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"apiVersion":"argoproj.io/v1alpha1","kind":"Application",` +
			`"metadata":{"name":"root-app","namespace":"default"},"spec":{},"status":{}}`))
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")

	for _, svc := range d.MappedServiceTokens() {
		m := d.mappingFor(svc)
		if m.writeSafe() {
			continue // covered by every other test; the gap is the read-only ones
		}
		_, _, err := d.Observe(svc, "capability.gitops.application", m.buildProviderID("default", "root-app"))
		if err != nil {
			t.Errorf("%s: Observe refuses a service DISCOVERY enumerates with measured "+
				"values: %v\nthe driver contradicts itself about the same object", svc, err)
		}
	}
}

// The converse must hold: a mapping with no write lens must still not be WRITTEN
// through. Widening reads must not widen mutation — and the refusal must say why,
// because "unknown service" for a service the driver demonstrably serves sends the
// reader looking for the wrong bug (it cost an hour on a live cluster).
func TestWritingStillRequiresAWriteLens(t *testing.T) {
	d := NewDriver("https://x", "t")
	for _, svc := range d.MappedServiceTokens() {
		m := d.mappingFor(svc)
		if m.writeSafe() {
			continue
		}
		res := d.Create(svc, "capability.gitops.application", "prod", nil, nil, "k", 1)
		if res.Status != "failed" {
			t.Errorf("%s: Create accepted a mapping with no write lens (status %q)", svc, res.Status)
			continue
		}
		if strings.Contains(res.Reason, "unknown service") {
			t.Errorf("%s: refusal blames an unknown service for one the driver serves "+
				"read-only: %v", svc, res.Reason)
		}
	}
}
