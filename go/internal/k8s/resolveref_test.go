package k8s

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D551. `capability.gitops.application` exists to be CONTROLLER-NEUTRAL: ArgoCD and
// Flux are equal citizens, and `source.repoURL` says WHICH repo governs the cluster
// (that is the attribute's stated purpose in the vocabulary). ArgoCD emits a URL.
// Flux emitted `spec.sourceRef.name` — the NAME of a GitRepository object — marked
// `derivation: measured` under a path that promises a URL.
//
// The divergence was documented (the mapping comment and the vocabulary both say
// "URL resolution is a future lens"), which makes it honest prose and a broken
// contract at the same time: the same neutral path carries two incomparable kinds of
// value, so a portable contract cannot pin the repo on both controllers. Worse, the
// name is not provenance — two clusters can each hold a GitRepository/platform
// aimed at different repositories, and groundhold would call them equal.
//
// Measured on a live k3d cluster: adopt refused with
//
//	platform.source.repoURL: declared https://github.com/acme/platform.git
//	but reality says platform
func TestFluxResolvesTheSourceURLNotItsName(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch {
		case strings.Contains(r.URL.Path, "gitrepositories"):
			_, _ = w.Write([]byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository",` +
				`"metadata":{"name":"platform","namespace":"default"},` +
				`"spec":{"url":"https://github.com/acme/platform.git"}}`))
		default:
			_, _ = w.Write([]byte(`{"apiVersion":"kustomize.toolkit.fluxcd.io/v1","kind":"Kustomization",` +
				`"metadata":{"name":"platform","namespace":"default"},` +
				`"spec":{"sourceRef":{"kind":"GitRepository","name":"platform"}},"status":{}}`))
		}
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")

	m := d.mappingFor("flux-kustomization")
	obs, _, err := d.Observe("flux-kustomization", "capability.gitops.application",
		m.buildProviderID("default", "platform"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got, ok := findObs(obs, "source.repoURL")
	if !ok {
		t.Fatal("source.repoURL not observed at all")
	}
	if got != "https://github.com/acme/platform.git" {
		t.Errorf("source.repoURL = %q, want the referent's URL\n"+
			"a GitRepository NAME under a path that promises a URL is not portable "+
			"with the ArgoCD twin, and is not provenance", got)
	}
	if len(asked) < 2 {
		t.Errorf("only %d read(s) — the referent was never fetched, so any right "+
			"answer here came from somewhere it could not have come from", len(asked))
	}
}

// TestFluxSourceURLCredentialIsStripped pins D991: a GitRepository whose spec.url carries
// an inline git token must NOT be observed verbatim — observations are persisted to the
// ledger and republished by export, so the credential would leak. The URL userinfo is
// stripped at the emit; the host/path (the capability-semantic part) survives.
func TestFluxSourceURLCredentialIsStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "gitrepositories"):
			_, _ = w.Write([]byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository",` +
				`"metadata":{"name":"platform","namespace":"default"},` +
				`"spec":{"url":"https://svc:ghp_SECRETtoken@github.com/acme/platform.git"}}`))
		default:
			_, _ = w.Write([]byte(`{"apiVersion":"kustomize.toolkit.fluxcd.io/v1","kind":"Kustomization",` +
				`"metadata":{"name":"platform","namespace":"default"},` +
				`"spec":{"sourceRef":{"kind":"GitRepository","name":"platform"}},"status":{}}`))
		}
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")
	m := d.mappingFor("flux-kustomization")
	obs, _, err := d.Observe("flux-kustomization", "capability.gitops.application",
		m.buildProviderID("default", "platform"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got, ok := findObs(obs, "source.repoURL")
	if !ok {
		t.Fatal("source.repoURL not observed")
	}
	gs, _ := got.(string)
	if strings.Contains(gs, "ghp_SECRETtoken") || strings.Contains(gs, "svc:") || strings.Contains(gs, "@") {
		t.Fatalf("source.repoURL leaked the inline credential: %q — a git token is now in the ledger/export", gs)
	}
	if gs != "https://github.com/acme/platform.git" {
		t.Fatalf("source.repoURL = %q, want the userinfo-stripped URL", gs)
	}
}

// The referent can be missing (Flux tolerates a dangling sourceRef; the Kustomization
// simply never becomes Ready). That must produce a DIAGNOSTIC and no value — never a
// fabricated URL, and never silence, which is how a failed read gets mistaken for a
// measured world (D522).
func TestFluxDanglingSourceRefSaysSoAndEmitsNoURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "gitrepositories") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","code":404}`))
			return
		}
		_, _ = w.Write([]byte(`{"apiVersion":"kustomize.toolkit.fluxcd.io/v1","kind":"Kustomization",` +
			`"metadata":{"name":"platform","namespace":"default"},` +
			`"spec":{"sourceRef":{"kind":"GitRepository","name":"ghost"}},"status":{}}`))
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "t")
	m := d.mappingFor("flux-kustomization")
	obs, diags, err := d.Observe("flux-kustomization", "capability.gitops.application",
		m.buildProviderID("default", "platform"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if v, ok := findObs(obs, "source.repoURL"); ok {
		t.Errorf("source.repoURL = %v for a dangling ref — a value was invented", v)
	}
	if !strings.Contains(strings.Join(diags, "|"), "ghost") {
		t.Errorf("no diagnostic naming the missing referent; diags = %v\n"+
			"an unresolvable read that says nothing is indistinguishable from a "+
			"resolved empty world", diags)
	}
}

func findObs(obs []provider.Observation, path string) (any, bool) {
	for _, o := range obs {
		if o.Path == path {
			return o.Value, true
		}
	}
	return nil, false
}
