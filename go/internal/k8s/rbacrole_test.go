package k8s

import (
	"groundhold/internal/provider"

	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// roleServer is the golden API-server fake: it serves one Role at the RBAC path
// and 404s everything else, asserting the driver builds the exact REST path.
func roleServer(t *testing.T, ns, name string, rules []map[string]any) *httptest.Server {
	t.Helper()
	want := fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/roles/%s", ns, name)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"rules":    rules,
		})
	}))
}

func observeMap(t *testing.T, d *Driver, pid string) (map[string]any, []string) {
	t.Helper()
	mp, _ := d.serviceMapping("rbac-role", forWrite)
	if mp == nil {
		t.Fatal("rbac-role must route through the schema-driven engine")
	}
	obs, diags, err := d.observeMapped(mp, pid)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m, diags
}

func TestObserveRoleReverseMapAndDerivations(t *testing.T) {
	rules := []map[string]any{
		{"apiGroups": []any{"apps"}, "resources": []any{"deployments"}, "verbs": []any{"get", "list", "create"}},
		{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}},
	}
	srv := roleServer(t, "payments", "deploy-role", rules)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "payments", "deploy-role")

	m, diags := observeMap(t, d, pid)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	wantPerms := []any{"apps/deployments:create", "apps/deployments:get", "apps/deployments:list", "core/pods:get"}
	if !reflect.DeepEqual(m["role.permissions"], wantPerms) {
		t.Fatalf("role.permissions = %v, want %v", m["role.permissions"], wantPerms)
	}
	// includes a create verb -> mutating; no wildcard/rbac-write/bind -> not privileged
	if m["access.mutating"] != true {
		t.Fatalf("access.mutating = %v, want true", m["access.mutating"])
	}
	if m["access.privileged"] != false {
		t.Fatalf("access.privileged = %v, want false", m["access.privileged"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed = %v, want true", m["service.managed"])
	}
}

func TestObserveRoleReadOnlyIsNotMutating(t *testing.T) {
	rules := []map[string]any{
		{"apiGroups": []any{""}, "resources": []any{"configmaps", "secrets"}, "verbs": []any{"get", "list", "watch"}},
	}
	srv := roleServer(t, "team", "viewer", rules)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "team", "viewer")

	m, _ := observeMap(t, d, pid)
	if m["access.mutating"] != false {
		t.Fatalf("read-only role: access.mutating = %v, want false", m["access.mutating"])
	}
	if m["access.privileged"] != false {
		t.Fatalf("read-only role: access.privileged = %v, want false", m["access.privileged"])
	}
}

func TestObserveRolePrivilegedSignals(t *testing.T) {
	cases := []struct {
		name  string
		rules []map[string]any
	}{
		{"wildcard", []map[string]any{{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}}}},
		// D988: full control of all resources of a NAMED group (apps/*:*) is admin-shaped
		// over that group — schedule an arbitrary privileged pod — and must read privileged.
		{"apps-wildcard", []map[string]any{{"apiGroups": []any{"apps"}, "resources": []any{"*"}, "verbs": []any{"*"}}}},
		{"rbac-write", []map[string]any{{"apiGroups": []any{"rbac.authorization.k8s.io"}, "resources": []any{"rolebindings"}, "verbs": []any{"create"}}}},
		{"escalate", []map[string]any{{"apiGroups": []any{"rbac.authorization.k8s.io"}, "resources": []any{"roles"}, "verbs": []any{"escalate"}}}},
		// D1051: enumerated write verbs over */* — the "spell out the verbs to avoid *"
		// shape — is cluster-admin-equivalent (can create a ClusterRoleBinding) and must
		// read privileged even though no permission is the literal */*:*.
		{"enumerated-wildcard-write", []map[string]any{{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"get", "list", "watch", "create", "update", "patch", "delete"}}}},
		// D1051: rbac-object write under a WILDCARD apiGroup — the API server resolves "*"
		// to include the rbac group, so this re-grants exactly as the named group does.
		{"wildcard-group-rbac-write", []map[string]any{{"apiGroups": []any{"*"}, "resources": []any{"clusterrolebindings"}, "verbs": []any{"create"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := roleServer(t, "ns", "r", c.rules)
			defer srv.Close()
			d := NewDriver(srv.URL, "tok")
			pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "ns", "r")
			m, _ := observeMap(t, d, pid)
			if m["access.privileged"] != true {
				t.Fatalf("%s: access.privileged = %v, want true", c.name, m["access.privileged"])
			}
		})
	}
}

func TestObserveRoleResourceNamesDiagnostic(t *testing.T) {
	rules := []map[string]any{
		{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}, "resourceNames": []any{"db-password"}},
	}
	srv := roleServer(t, "ns", "scoped", rules)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "ns", "scoped")
	_, diags := observeMap(t, d, pid)
	if len(diags) == 0 {
		t.Fatal("a rule with resourceNames must surface a diagnostic (scoping is not part of the flat set)")
	}
}

func TestObserveRoleNotFound(t *testing.T) {
	srv := roleServer(t, "ns", "present", []map[string]any{{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}}})
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "ns", "absent")
	obs, diags := observeMap(t, d, pid)
	// This test used to demand the OPPOSITE — "want no observations + a
	// diagnostic" — and that expectation was the defect, written down and
	// guarded. A bound resource the server 404s is authoritatively gone, and
	// silence about it is what let converge report a world it had just been told
	// was empty (D513). The absence marker is the contract's one way to say it.
	if len(diags) == 0 {
		t.Errorf("not-found: the diagnostic is gone too")
	}
	if got, ok := obs[provider.ResourceAbsentPath]; !ok || got != true {
		t.Fatalf("not-found: want %s=true, got obs=%v", provider.ResourceAbsentPath, obs)
	}
}

func TestSplitRBACProviderIDRejectsMalformed(t *testing.T) {
	bad := []string{
		"rbac.authorization.k8s.io/v1/Role/ns", // too few
		"rbac.authorization.k8s.io/v1/ClusterRole/ns/name",
		"rbac.authorization.k8s.io/v1/Role//name",       // empty ns
		"rbac.authorization.k8s.io/v1/Role/ns/Bad_Name", // invalid name charset
	}
	for _, pid := range bad {
		if _, _, _, _, err := splitRBACProviderID(pid, "Role"); err == nil {
			t.Fatalf("providerId %q must be rejected", pid)
		}
	}
}
