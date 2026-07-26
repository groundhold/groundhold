package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSweepMappedNetpolDiscovers proves the generic mapped-kind discoverer: it
// LISTs the collection, then reverse-maps each object through the SAME observeMapped
// the hand-addressed Observe uses (two-step), producing a Discovered with the
// mapping's providerId + capability. This is what makes netpol/certmanager-cert
// discoverable without a bespoke sweep.
func TestSweepMappedNetpolDiscovers(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"name": "np", "namespace": "payments"},
		"spec": map[string]any{
			"podSelector": map[string]any{},
			"policyTypes": []any{"Ingress"},
			"ingress":     []any{},
		},
	}
	var listHit, objHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauth", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/apis/networking.k8s.io/v1/networkpolicies":
			listHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{obj}})
		case strings.HasSuffix(r.URL.Path, "/namespaces/payments/networkpolicies/np"):
			objHit = true
			_ = json.NewEncoder(w).Encode(obj)
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	d := NewDriver(srv.URL, "tok")
	m := d.mappingFor("netpol")
	if m == nil {
		t.Fatal("netpol mapping missing")
	}
	found, diags, err := d.sweepMapped(m, "") // cluster-wide list
	if err != nil {
		t.Fatalf("sweepMapped: %v (%v)", err, diags)
	}
	if !listHit || !objHit {
		t.Fatalf("expected both the collection LIST and the per-object observe GET, list=%v obj=%v", listHit, objHit)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered netpol, got %d", len(found))
	}
	if found[0].ProviderID != "networking.k8s.io/v1/NetworkPolicy/payments/np" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.network.private" {
		t.Fatalf("capability = %q", found[0].ResourceType)
	}
	if len(found[0].Observations) == 0 {
		t.Fatal("a discovered netpol must carry the reverse-mapped observations, got none")
	}
}

// TestSweepMappedListForbiddenIsError: a non-200 on the collection LIST is an error
// (crawl-incomplete), never a fabricated empty discovery.
func TestSweepMappedListForbiddenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := d.mappingFor("netpol")
	found, _, err := d.sweepMapped(m, "")
	if err == nil {
		t.Fatalf("a 403 list must be an error, got %v", found)
	}
	if found != nil {
		t.Fatalf("failure must not fabricate discoveries, got %v", found)
	}
}
