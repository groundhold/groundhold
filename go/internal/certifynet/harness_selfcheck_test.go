package certifynet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// recorder captures what a harness reports, so a harness can be tested the way it
// tests drivers. Without this, "the gate would catch X" is an assertion nobody
// checked — which is the D524 defect one level up.
type recorder struct{ msgs []string }

func (r *recorder) Errorf(f string, a ...any) { r.msgs = append(r.msgs, fmt.Sprintf(f, a...)) }
func (r *recorder) Fatalf(f string, a ...any) { r.msgs = append(r.msgs, fmt.Sprintf(f, a...)) }
func (r *recorder) Helper()                   {}
func (r *recorder) saidAbout(sub string) bool {
	for _, m := range r.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

type fakeAdoptProv struct{ url string }

func (p *fakeAdoptProv) Name() string { return "fake" }
func (p *fakeAdoptProv) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	// A create that reads (and finds nothing, because the estate is empty), then
	// writes — exactly what a driver does when the resource is not there.
	resp, err := http.Get(p.url + "/thing")
	if err == nil {
		_ = resp.Body.Close()
	}
	return provider.CreateResult{ProviderID: "fake:thing", Status: "succeeded"}
}

func (p *fakeAdoptProv) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	return nil
}
func (p *fakeAdoptProv) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return nil, nil, nil
}
func (p *fakeAdoptProv) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	return "mutable", ""
}
func (p *fakeAdoptProv) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{}
}
func (p *fakeAdoptProv) Delete(service, capability, environment, providerID string,
	idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{}
}

// TestAdoptGateRequiresAnAdoption: with an estate in which the resource does NOT
// exist, `CertifyCreateAdoptsExisting` must REPORT — the create made one rather
// than adopting one, and every other assertion (succeeded, a providerId, no excess
// mutations) is satisfied by that (D524).
func TestAdoptGateRequiresAnAdoption(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"NotFound"}`, http.StatusNotFound)
	}))
	defer empty.Close()

	rec := &recorder{}
	CertifyCreateAdoptsExisting(rec, &ExistingProbe{
		Name:           "fake/nothing-here",
		Classify:       func(*http.Request, []byte) Role { return RoleRead },
		ExistingServer: func() *httptest.Server { return empty },
		New: func(url string, rt http.RoundTripper) provider.Provider {
			return &fakeAdoptProv{url: url}
		},
		Create: func(p provider.Provider) provider.CreateResult {
			return p.Create("thing", "cap", "prod", nil, nil, "k", 1)
		},
	})
	if !rec.saidAbout("no read of the estate returned the resource") {
		t.Fatalf("the adopt gate accepted a create that adopted NOTHING — the estate was "+
			"empty, so the driver made the resource and the gate called it adoption.\n"+
			"  reported: %v", rec.msgs)
	}
}
