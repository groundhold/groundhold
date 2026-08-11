package k8s

import (
	"groundhold/internal/provider"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// npServer serves one NetworkPolicy with the given spec.
func npServer(t *testing.T, ns, name string, spec map[string]any) *httptest.Server {
	t.Helper()
	want := netpolPath(ns, name)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec":     spec,
		})
	}))
}

// The netpol read-lens, now the sole path (its hand-coded twin is deleted).
// Asserts the conditional config-intent semantics across the interesting shapes.
func TestNetpolLensObservations(t *testing.T) {
	cases := []struct {
		name  string
		spec  map[string]any
		want  map[string]any
		diags []string // substrings that must appear
	}{
		{"default-deny-both",
			map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress", "Egress"}, "ingress": []any{}, "egress": []any{}},
			map[string]any{"ingress.public": false, "egress.restricted": true, "service.managed": true},
			[]string{"CONFIG-INTENT"}},
		{"partial-selector",
			map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}}, "policyTypes": []any{"Ingress"}, "ingress": []any{}},
			map[string]any{"ingress.public": false, "service.managed": true},
			[]string{"only some pods", "CONFIG-INTENT"}},
		{"allow-rules",
			map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}, "ingress": []any{map[string]any{"from": []any{}}}},
			map[string]any{"service.managed": true},
			[]string{"allows specific ingress", "CONFIG-INTENT"}},
		{"egress-only",
			map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Egress"}, "egress": []any{}},
			map[string]any{"egress.restricted": true, "service.managed": true},
			[]string{"CONFIG-INTENT"}},
		// D987: an egress rule list with a wide-open rule ({}) ALLOWS all outbound —
		// egress.restricted must NOT be emitted (there is no prober to correct it).
		{"egress-allow-all-rule",
			map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Egress"}, "egress": []any{map[string]any{}}},
			map[string]any{"service.managed": true},
			[]string{"allows specific egress", "CONFIG-INTENT"}},
	}
	m := loadRealMapping(t, "k8s.networkpolicy.yaml")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := npServer(t, "payments", "np", c.spec)
			defer srv.Close()
			d := NewDriver(srv.URL, "tok")
			obs, diags, err := d.observeMapped(m, netpolProviderID("payments", "np"))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// Every present resource now carries the absence marker set to false
			// (F-LC3, D513) — asserted once here rather than repeated in each
			// case's want, which is about the LENS's semantics.
			if got[provider.ResourceAbsentPath] != false {
				t.Fatalf("%s: a present object must clear %s, got %v",
					c.name, provider.ResourceAbsentPath, got[provider.ResourceAbsentPath])
			}
			delete(got, provider.ResourceAbsentPath)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("%s observations = %#v, want %#v", c.name, got, c.want)
			}
			joined := strings.Join(diags, " | ")
			for _, sub := range c.diags {
				if !strings.Contains(joined, sub) {
					t.Fatalf("%s diagnostics %q missing %q", c.name, joined, sub)
				}
			}
		})
	}
}

// The netpol WRITE lens authors the default-deny spec; a fully-permissive request
// is the absence of a policy and must refuse.
func TestNetpolWriteLensRefusesPermissive(t *testing.T) {
	m := loadRealMapping(t, "k8s.networkpolicy.yaml")
	if err := m.validateMapped(map[string]any{"ingress.public": true, "service.managed": true}, nil); err == nil {
		t.Fatal("a permissive request must refuse (nothing to author)")
	}
	if err := m.validateMapped(map[string]any{"ingress.public": false, "service.managed": true}, nil); err != nil {
		t.Fatalf("a default-deny request must validate, got %v", err)
	}
}

func TestUnregisteredLensRefusesAtLoad(t *testing.T) {
	y := "mapping: v0.1\nfieldpath: groundhold/fieldpath/v1\nresource: {group: g, version: v1, kind: X, plural: xs, scope: Cluster}\nlenses: [k8s.not.real]\n"
	if _, err := loadMapping([]byte(y)); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("an unregistered lens must refuse by name, got %v", err)
	}
}

func TestNetpolLensDriftOnLensField(t *testing.T) {
	m := loadRealMapping(t, "k8s.networkpolicy.yaml")
	fd, _ := os.ReadFile("testdata/networkpolicy-openapi.json")
	var doc map[string]any
	_ = json.Unmarshal(fd, &doc)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	// matching schema: no drift
	if _, err := m.checkDrift(schemas); err != nil {
		t.Fatalf("matching schema must not drift: %v", err)
	}
	// mutate a LENS input field's type: policyTypes array -> string
	spec := schemas["io.k8s.api.networking.v1.NetworkPolicySpec"].(map[string]any)
	spec["properties"].(map[string]any)["policyTypes"].(map[string]any)["type"] = "string"
	if _, err := m.checkDrift(schemas); err == nil || !strings.Contains(err.Error(), "mapping-schema-drift") {
		t.Fatalf("drift on a lens input must refuse, got %v", err)
	}
}

// cert-manager REQUIRES spec.secretName — a Certificate without it is rejected by
// the API server with a 422, always. This function's own comment says the issuer
// and the target secret are both operands, and it refused for the issuer while
// silently omitting the secret, so every Certificate it built was invalid. Found
// the first time the mapping met a real cluster (D511): the object never reached
// etcd, on any cluster, ever.
func TestCertificateRefusesWithoutItsTargetSecret(t *testing.T) {
	attrs := map[string]any{"domain": "app.example.com"}
	issuer := map[string]any{"name": "selfsigned", "kind": "ClusterIssuer", "group": "cert-manager.io"}

	obj := map[string]any{}
	err := writeLensCertmanagerPrimaryDomain(obj, attrs, map[string]any{"issuerRef": issuer})
	if err == nil {
		t.Fatalf("a Certificate was built with no secretName; the API server rejects it "+
			"with `spec.secretName: Required value`, so this object could never be created.\n  spec: %v",
			obj["spec"])
	}
	if !strings.Contains(err.Error(), "secretName") {
		t.Errorf("the refusal does not name the missing operand: %v", err)
	}

	// with it, the spec carries it through unchanged
	obj = map[string]any{}
	if err := writeLensCertmanagerPrimaryDomain(obj, attrs,
		map[string]any{"issuerRef": issuer, "secretName": "app-tls"}); err != nil {
		t.Fatalf("a complete Certificate was refused: %v", err)
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec["secretName"] != "app-tls" {
		t.Errorf("secretName = %v, want app-tls", spec["secretName"])
	}
}
