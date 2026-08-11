package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClusterKindScopeAndPaths(t *testing.T) {
	cr, _ := kindInfo("rbac-clusterrole")
	if cr.Namespaced || cr.Plural != "clusterroles" {
		t.Fatalf("clusterrole kind = %+v", cr)
	}
	if got := cr.objPath("ignored", "cluster-admin"); got != "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin" {
		t.Fatalf("cluster objPath must omit namespace, got %q", got)
	}
	crb, _ := kindInfo("rbac-clustergrant")
	if grantScope(crb) != "account" {
		t.Fatalf("ClusterRoleBinding must confer account scope, got %q", grantScope(crb))
	}
	rb, _ := kindInfo("rbac-grant")
	if grantScope(rb) != "resource" {
		t.Fatalf("RoleBinding must confer resource scope, got %q", grantScope(rb))
	}
}

func TestClusterProviderIDRoundTrip(t *testing.T) {
	pid := rbacProviderID(rbacGroup, rbacVersion, "ClusterRole", "", "cluster-admin")
	if pid != "rbac.authorization.k8s.io/v1/ClusterRole/cluster-admin" {
		t.Fatalf("cluster providerId must be 4-field, got %q", pid)
	}
	_, _, ns, name, err := splitRBACProviderID(pid, "ClusterRole")
	if err != nil || ns != "" || name != "cluster-admin" {
		t.Fatalf("split cluster pid: ns=%q name=%q err=%v", ns, name, err)
	}
	// a namespaced-shaped id must be rejected for a cluster kind
	if _, _, _, _, err := splitRBACProviderID("rbac.authorization.k8s.io/v1/ClusterRole/ns/x", "ClusterRole"); err == nil {
		t.Fatal("a 5-field id must be rejected for a cluster-scoped kind")
	}
}

func TestObserveClusterRole(t *testing.T) {
	want := "/apis/rbac.authorization.k8s.io/v1/clusterroles/platform-admin"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": "platform-admin"},
			"rules":    []map[string]any{{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}}},
		})
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID(rbacGroup, rbacVersion, "ClusterRole", "", "platform-admin")
	mp, _ := d.serviceMapping("rbac-clusterrole", forWrite)
	if mp == nil {
		t.Fatal("rbac-clusterrole must route through the schema-driven engine")
	}
	obs, _, err := d.observeMapped(mp, pid)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["access.privileged"] != true || m["access.mutating"] != true {
		t.Fatalf("wildcard ClusterRole must be privileged+mutating, got %v", m)
	}
}

func TestRoleMappingPinsMatchVendoredSchema(t *testing.T) {
	schemas := loadFixtureSchemas(t, "rbacrole-openapi.json")
	for _, name := range []string{"k8s.role.yaml", "k8s.clusterrole.yaml"} {
		m := loadRealMapping(t, name)
		got, err := m.MappedSurfaceHash(schemas)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != m.Schema.MappedSurface {
			t.Fatalf("%s mapped-surface drift:\n pin  %s\n live %s", name, m.Schema.MappedSurface, got)
		}
	}
}

func TestBuildGrantAccountScopeForClusterBinding(t *testing.T) {
	// a ClusterRoleBinding must accept account scope and refuse resource
	_, _, err := buildGrant(map[string]any{
		"grant.role": "ClusterRole/cluster-admin", "grant.principal": "Group:ops",
		"access.scope": "resource"}, "account")
	if err == nil || !strings.Contains(err.Error(), "account") {
		t.Fatalf("a ClusterRoleBinding must refuse resource scope, got %v", err)
	}
	rr, subs, err := buildGrant(map[string]any{
		"grant.role": "ClusterRole/view", "grant.principal": "Group:auditors",
		"access.scope": "account", "service.managed": true}, "account")
	if err != nil {
		t.Fatal(err)
	}
	if rr.Name != "view" || len(subs) != 1 || subs[0].Kind != "Group" {
		t.Fatalf("build cluster grant: rr=%+v subs=%+v", rr, subs)
	}
}
