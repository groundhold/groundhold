package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// captureServer records the last PATCH (apply) body sent to it.
func captureServer(t *testing.T, path string, last *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, path) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		if r.Method == "PATCH" {
			b, _ := io.ReadAll(r.Body)
			*last = b
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"metadata":{}}`))
	}))
}

// quota's create body, now the sole (generic) path — pinned against the exact
// expected apply object (was a differential vs the deleted hand-coded twin).
func TestGenericCreateQuotaBody(t *testing.T) {
	attrs := map[string]any{"cpu.limit": "10", "memory.limit": "20Gi", "pods.max": 50, "service.managed": true}
	impl := map[string]any{"namespace": "team"}
	path := corePathNS("resourcequotas", "team", "budget-prod")

	var body []byte
	gs := captureServer(t, path, &body)
	defer gs.Close()
	gd := NewDriver(gs.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	if res := gd.createMapped(m, "budget", "prod", attrs, impl); res.Status != "succeeded" {
		t.Fatalf("generic create: %+v", res)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("apply body not JSON: %v (%s)", err, body)
	}
	want := map[string]any{
		"apiVersion": "v1", "kind": "ResourceQuota",
		"metadata": map[string]any{"name": "budget-prod", "namespace": "team",
			"labels": map[string]any{capLabel: "budget", envLabel: "prod"}},
		"spec": map[string]any{"hard": map[string]any{"limits.cpu": "10", "limits.memory": "20Gi", "pods": "50"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apply body =\n %#v\n want\n %#v", got, want)
	}
}

func TestBuildMappedObjectConstContradictionRefuses(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	// service.managed is a const=true; declaring false must refuse
	if err := m.validateMapped(map[string]any{"cpu.limit": "10", "service.managed": false}, nil); err == nil {
		t.Fatal("a const contradiction must refuse")
	}
	if err := m.validateMapped(map[string]any{"cpu.limit": "10", "service.managed": true}, nil); err != nil {
		t.Fatalf("a consistent candidate must validate, got %v", err)
	}
}

func TestGenericUpdateGuardsOwnership(t *testing.T) {
	body := map[string]any{"metadata": map[string]any{"name": "budget", "namespace": "team"}, "spec": map[string]any{"hard": map[string]any{}}}
	lbls := map[string]string{"app.kubernetes.io/managed-by": "terraform"} // not ours
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	pid := m.providerID("team", "budget")
	res := d.updateMapped(m, "budget", "prod", pid, map[string]any{"cpu.limit": "20", "service.managed": true}, nil)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("update of an unclaimed object must refuse, got %+v", res)
	}
}

func TestGenericCreateRefusesOnDrift(t *testing.T) {
	path := corePathNS("resourcequotas", "team", "budget-prod")
	var body []byte
	srv := captureServer(t, path, &body)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	bad := loadQuotaSchemas(t)
	bad["io.k8s.apimachinery.pkg.api.resource.Quantity"].(map[string]any)["type"] = "integer"
	d.SchemaFetch = func(g, v string) (map[string]any, error) { return bad, nil }
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	res := d.createMapped(m, "budget", "prod", map[string]any{"cpu.limit": "10", "service.managed": true}, map[string]any{"namespace": "team"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "mapping-schema-drift") {
		t.Fatalf("create under drift must refuse, got %+v", res)
	}
	if len(body) != 0 {
		t.Fatal("create under drift must NOT have sent an apply body")
	}
}
