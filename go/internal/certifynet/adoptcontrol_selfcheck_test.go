package certifynet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// recordT captures gate failures so a self-check can assert the gate FIRES (D1062).
// A gate that cannot fail is not a gate — the control-completeness check exists to
// catch a driver that reports succeeded over a resource missing a declared control,
// so we prove it actually does.
type recordT struct{ errs []string }

func (r *recordT) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *recordT) Fatalf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *recordT) Helper()                   {}

// adoptLiar reads the estate (so the no-duplicate half sees a read) and then
// reports succeeded no matter what — the exact defect the control-completeness
// check must catch.
type adoptLiar struct {
	*provider.Fake
	url string
	rt  http.RoundTripper
}

func (l *adoptLiar) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	req, _ := http.NewRequest("GET", l.url+"/exists", nil)
	if resp, err := (&http.Client{Transport: l.rt}).Do(req); err == nil {
		_ = resp.Body.Close()
	}
	return provider.CreateResult{Status: "succeeded", ProviderID: "fake:the-resource"}
}

func TestAdoptControlGateCatchesALiar(t *testing.T) {
	srv := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
	}
	rec := &recordT{}
	p := &ExistingProbe{
		Name:           "fake/liar",
		ExistingServer: srv,
		New: func(u string, rt http.RoundTripper) provider.Provider {
			return &adoptLiar{Fake: &provider.Fake{}, url: u, rt: rt}
		},
		Classify: func(*http.Request, []byte) Role { return RoleRead }, // every call is a read
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("svc", "cap", "prod", nil, nil, "cap", 1)
		},
		// the estate serves a resource missing a declared control; the liar succeeds
		// anyway — the gate MUST report it.
		MissingControl: []ControlCase{
			{Path: "encryption.customerManagedKeys", Server: srv, WantStatus: "failed"},
		},
	}
	CertifyCreateAdoptsExisting(rec, p)

	var caught bool
	for _, e := range rec.errs {
		if strings.Contains(e, "missing declared control") && strings.Contains(e, "customerManagedKeys") {
			caught = true
		}
	}
	if !caught {
		t.Fatalf("the control-completeness gate did NOT catch a driver that reports succeeded "+
			"over a missing control — a gate that cannot fail is not a gate. Errors: %v", rec.errs)
	}
}
