package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// certServer serves one cert-manager Certificate CRD object.
func certServer(t *testing.T, ns, name string, dnsNames []any) *httptest.Server {
	t.Helper()
	want := "/apis/cert-manager.io/v1/namespaces/" + ns + "/certificates/" + name
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec":     map[string]any{"dnsNames": dnsNames, "secretName": name + "-tls", "issuerRef": map[string]any{"name": "letsencrypt"}},
		})
	}))
}

// THE PAYOFF (slice 5): the generic engine observes a CRD it was NEVER hand-coded
// for — cert-manager Certificate — purely from the mapping document + one lens.
// New resource coverage is a YAML file, not a Go driver.
func TestGenericObservesCRDWithNoHandCodedTwin(t *testing.T) {
	// there is no hand-coded certmanager Certificate driver: the closed service
	// dispatch does not know it.
	d0 := &Driver{}
	if err := d0.requireService("certmanager-cert"); err == nil {
		t.Fatal("precondition: certmanager-cert must NOT be a hand-coded service (this is the point)")
	}

	srv := certServer(t, "prod", "app-tls", []any{"app.example.com", "www.example.com"})
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := loadRealMapping(t, "k8s.certmanager-certificate.yaml")
	pid := m.providerID("prod", "app-tls")

	obs, diags, err := d.observeMapped(m, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	deriv := map[string]string{}
	for _, o := range obs {
		got[o.Path] = o.Value
		deriv[o.Path] = o.Derivation
	}
	want := map[string]any{"domain": "app.example.com", "auto.renew": true, "service.managed": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CRD observations = %#v, want %#v", got, want)
	}
	if deriv["domain"] != "measured" || deriv["auto.renew"] != "config-intent" {
		t.Fatalf("derivations wrong: %v", deriv)
	}
	// the second SAN is implementation detail — surfaced as a diagnostic, not over-claimed
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "SANs") {
		t.Fatalf("multiple SANs must be diagnosed, got %v", diags)
	}
}

func TestGenericCRDDriftRefuses(t *testing.T) {
	m := loadRealMapping(t, "k8s.certmanager-certificate.yaml")
	fd, _ := os.ReadFile("testdata/certmanager-certificate-openapi.json")
	var doc map[string]any
	_ = json.Unmarshal(fd, &doc)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	if _, err := m.checkDrift(schemas); err != nil {
		t.Fatalf("matching CRD schema must not drift: %v", err)
	}
	// dnsNames changes from array to a single string across a CRD version
	spec := schemas["com.github.cert-manager.pkg.apis.certmanager.v1.CertificateSpec"].(map[string]any)
	spec["properties"].(map[string]any)["dnsNames"].(map[string]any)["type"] = "string"
	if _, err := m.checkDrift(schemas); err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("a CRD schema change on a lens field must refuse, got %v", err)
	}
}
