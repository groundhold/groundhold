package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// coreServer serves one core-group object (ResourceQuota or Namespace) at its
// exact path, handling GET / merge-PATCH (claim) / apply-PATCH.
func coreServer(t *testing.T, path string, body map[string]any, labels *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, path) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			meta, _ := body["metadata"].(map[string]any)
			meta["labels"] = *labels
			_ = json.NewEncoder(w).Encode(body)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			var doc map[string]any
			_ = json.Unmarshal(b, &doc)
			if m, ok := doc["metadata"].(map[string]any); ok {
				if l, ok := m["labels"].(map[string]any); ok {
					if *labels == nil {
						*labels = map[string]string{}
					}
					for k, v := range l {
						(*labels)[k] = v.(string)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}})
		default:
			http.Error(w, "m", http.StatusMethodNotAllowed)
		}
	}))
}

// quota observe/build now go through the generic engine (see generic_test.go);
// the hand-coded twin is deleted. Claim stays path-based (shared across kinds).
func TestClaimQuotaStampsOwnership(t *testing.T) {
	body := map[string]any{"metadata": map[string]any{"name": "budget", "namespace": "team"}, "spec": map[string]any{"hard": map[string]any{}}}
	lbls := map[string]string{"app.kubernetes.io/managed-by": "terraform"}
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	if cl := d.Claim("quota", "budget", "prod", quotaProviderID("team", "budget")); cl.Status != "succeeded" {
		t.Fatalf("claim quota: %+v", cl)
	}
	if lbls[capLabel] != "budget" {
		t.Fatalf("claim must stamp ownership on the ResourceQuota, got %v", lbls)
	}
}

// TestEnumerateNamespaces pins the gentle-crawl scope fan-out (D141): the k8s
// driver enumerates the cluster's namespaces by name off GET /api/v1/namespaces,
// carrying the bearer token, so a scopeless pairing crawls each namespace.
func TestEnumerateNamespaces(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"metadata": map[string]any{"name": "default"}},
			{"metadata": map[string]any{"name": "kube-system"}},
			{"metadata": map[string]any{"name": "payments"}},
		}})
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if gotMethod != "GET" || gotPath != "/api/v1/namespaces" {
		t.Fatalf("hit %s %s, want GET /api/v1/namespaces", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q, want %q", gotAuth, "Bearer tok")
	}
	want := []string{"default", "kube-system", "payments"}
	if len(scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", scopes, want)
	}
	for i := range want {
		if scopes[i] != want[i] {
			t.Fatalf("scopes = %v, want %v", scopes, want)
		}
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %v, want none", diags)
	}
}

// TestEnumerateNamespacesTransportFailIsError: a non-200 (permission/transport)
// failure is an error, never a fabricated empty scope list.
func TestEnumerateNamespacesForbiddenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	scopes, _, err := d.Enumerate()
	if err == nil {
		t.Fatalf("a 403 must be an error, got scopes=%v nil err", scopes)
	}
	if scopes != nil {
		t.Fatalf("failure must not fabricate scopes, got %v", scopes)
	}
}

func TestNamespacePodSecurityWriteLens(t *testing.T) {
	m := loadRealMapping(t, "k8s.namespace.yaml")
	obj, err := m.buildMappedObject("", "payments", "tenant", "prod",
		map[string]any{"security.podSecurity": "restricted", "service.managed": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := obj["metadata"].(map[string]any)["labels"].(map[string]any)
	if labels[podSecurityEnforceLabel] != "restricted" {
		t.Fatalf("labels = %v", labels)
	}
	if _, err := m.buildMappedObject("", "payments", "tenant", "prod",
		map[string]any{"security.podSecurity": "wideopen"}, nil); err == nil {
		t.Fatal("an invalid pod-security level must refuse")
	}
}

func TestObserveNamespacePosture(t *testing.T) {
	body := map[string]any{"metadata": map[string]any{"name": "payments"}}
	lbls := map[string]string{podSecurityEnforceLabel: "restricted"}
	srv := coreServer(t, corePathCluster("namespaces", "payments"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m, _ := d.serviceMapping("namespace", forWrite)
	if m == nil {
		t.Fatal("namespace must route through the schema-driven engine")
	}
	obs, diags, err := d.observeMapped(m, nsProviderID("payments"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	deriv := map[string]string{}
	for _, o := range obs {
		got[o.Path] = o.Value
		deriv[o.Path] = o.Derivation
	}
	if got["security.podSecurity"] != "restricted" {
		t.Fatalf("observe namespace = %v", got)
	}
	// D1060: enforcement of the pod-security standard depends on the PodSecurity
	// admission plugin, which a static label read cannot witness — the value is
	// CONFIG-INTENT, not measured (the netpol enforcement-vs-declaration split), and a
	// caveat names the dependency. A `measured restricted` would read satisfied on a
	// cluster with PSA admission off, admitting privileged pods — the dangerous direction.
	if deriv["security.podSecurity"] != "config-intent" {
		t.Fatalf("security.podSecurity derivation = %q, want config-intent", deriv["security.podSecurity"])
	}
	var sawCaveat bool
	for _, dg := range diags {
		if strings.Contains(dg, "PodSecurity admission plugin") {
			sawCaveat = true
		}
	}
	if !sawCaveat {
		t.Fatalf("want a PodSecurity-admission caveat diagnostic, got %v", diags)
	}
	if got["service.managed"] != true {
		t.Fatalf("service.managed const missing: %v", got)
	}
}

// TestClassifyLensPaths pins the classify table: a lens-emitted path must report a
// concrete change class, never "unsupported" (which the compiler treats as a hard
// error). Guards both the namespace and the backfilled netpol mappings.
func TestClassifyLensPaths(t *testing.T) {
	d := NewDriver("", "")
	for _, c := range []struct{ svc, path string }{
		{"namespace", "security.podSecurity"},
		{"netpol", "ingress.public"},
		{"netpol", "egress.restricted"},
	} {
		if class, _ := d.ClassifyChange(c.svc, c.path, nil, nil, nil); class != "mutable" {
			t.Fatalf("%s.%s classify = %q, want mutable", c.svc, c.path, class)
		}
	}
}

// TestNamespaceMappingPinMatchesVendoredSchema authors + guards the mapped-surface
// fingerprint from the vendored Namespace schema.
func TestNamespaceMappingPinMatchesVendoredSchema(t *testing.T) {
	m := loadRealMapping(t, "k8s.namespace.yaml")
	schemas := loadFixtureSchemas(t, "namespace-openapi.json")
	got, err := m.MappedSurfaceHash(schemas)
	if err != nil {
		t.Fatal(err)
	}
	if got != m.Schema.MappedSurface {
		t.Fatalf("mapped-surface fingerprint drift:\n pin  %s\n live %s", m.Schema.MappedSurface, got)
	}
}

func TestNamespaceProviderIDIsClusterScoped(t *testing.T) {
	pid := nsProviderID("payments")
	if pid != "core/v1/Namespace/payments" {
		t.Fatalf("namespace providerId must be 4-field cluster-scoped, got %q", pid)
	}
	_, _, ns, name, err := splitRBACProviderID(pid, "Namespace")
	if err != nil || ns != "" || name != "payments" {
		t.Fatalf("split namespace pid: ns=%q name=%q err=%v", ns, name, err)
	}
}

func TestClaimNamespaceStampsOwnership(t *testing.T) {
	body := map[string]any{"metadata": map[string]any{"name": "payments"}}
	lbls := map[string]string{}
	srv := coreServer(t, corePathCluster("namespaces", "payments"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	if cl := d.Claim("namespace", "tenant", "prod", nsProviderID("payments")); cl.Status != "succeeded" {
		t.Fatalf("claim namespace: %+v", cl)
	}
	if lbls[capLabel] != "tenant" {
		t.Fatalf("claim must stamp ownership on the Namespace, got %v", lbls)
	}
}
