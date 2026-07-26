package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReverseGrantPrivilegeAndPrincipal(t *testing.T) {
	// well-known privileged ClusterRole, single ServiceAccount subject
	obs, diags := reverseGrant(
		roleRef{Kind: "ClusterRole", Name: "edit"},
		[]subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "payments"}}, "resource")
	if obs["grant.role"] != "ClusterRole/edit" {
		t.Fatalf("grant.role=%v", obs["grant.role"])
	}
	if obs["grant.principal"] != "ServiceAccount:payments/deployer" {
		t.Fatalf("grant.principal=%v", obs["grant.principal"])
	}
	if obs["access.scope"] != "resource" {
		t.Fatalf("access.scope=%v", obs["access.scope"])
	}
	if obs["access.privileged"] != true {
		t.Fatalf("edit must classify privileged, got %v", obs["access.privileged"])
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
}

func TestReverseGrantCustomRoleIsUnverifiable(t *testing.T) {
	obs, diags := reverseGrant(roleRef{Kind: "Role", Name: "team-custom"},
		[]subject{{Kind: "User", Name: "alice"}}, "resource")
	if _, ok := obs["access.privileged"]; ok {
		t.Fatal("a custom role's privilege must NOT be guessed — access.privileged must be absent")
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "UNVERIFIABLE") {
		t.Fatalf("must diagnose the unverifiable privilege, got %v", diags)
	}
}

func TestReverseGrantMultipleSubjectsDiagnosed(t *testing.T) {
	obs, diags := reverseGrant(roleRef{Kind: "ClusterRole", Name: "view"},
		[]subject{{Kind: "User", Name: "a"}, {Kind: "User", Name: "b"}}, "resource")
	if _, ok := obs["grant.principal"]; ok {
		t.Fatal("multiple subjects do not fit one principal — grant.principal must be absent")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d, "2 subjects") {
			found = true
		}
	}
	if !found {
		t.Fatalf("must diagnose multiple subjects, got %v", diags)
	}
}

func TestBuildGrantRefusals(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"false-privilege", map[string]any{"grant.role": "ClusterRole/edit", "grant.principal": "User:alice", "access.privileged": false}, "false claim"},
		{"account-scope", map[string]any{"grant.role": "ClusterRole/view", "grant.principal": "User:a", "access.scope": "account"}, "resource-scoped"},
		{"sa-without-ns", map[string]any{"grant.role": "ClusterRole/view", "grant.principal": "ServiceAccount:deployer"}, "needs a namespace"},
		{"unmapped", map[string]any{"grant.role": "ClusterRole/view", "grant.principal": "User:a", "bogus": 1}, "no k8s RBAC RoleBinding mapping"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := buildGrant(c.attrs, "resource")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestBuildGrantHappyPath(t *testing.T) {
	rr, subs, err := buildGrant(map[string]any{
		"grant.role": "Role/deploy", "grant.principal": "ServiceAccount:payments/ci",
		"access.scope": "resource", "service.managed": true}, "resource")
	if err != nil {
		t.Fatal(err)
	}
	if rr.Kind != "Role" || rr.Name != "deploy" {
		t.Fatalf("roleRef=%+v", rr)
	}
	if len(subs) != 1 || subs[0].Kind != "ServiceAccount" || subs[0].Namespace != "payments" || subs[0].Name != "ci" {
		t.Fatalf("subjects=%+v", subs)
	}
}

func TestGrantMappingPinsMatchVendoredSchema(t *testing.T) {
	schemas := loadFixtureSchemas(t, "rbacgrant-openapi.json")
	for _, name := range []string{"k8s.rolebinding.yaml", "k8s.clusterrolebinding.yaml"} {
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

// TestGrantRoleIsImmutable pins the replacement-driving classification: a change to
// grant.role (the roleRef) or access.scope must be immutable, so the compiler
// composes create-before-destroy instead of an impossible in-place patch.
func TestGrantRoleIsImmutable(t *testing.T) {
	d := NewDriver("", "")
	for _, svc := range []string{"rbac-grant", "rbac-clustergrant"} {
		for _, p := range []string{"grant.role", "access.scope"} {
			if c, _ := d.ClassifyChange(svc, p, nil, nil, nil); c != "immutable" {
				t.Fatalf("%s.%s classify = %q, want immutable", svc, p, c)
			}
		}
		if c, _ := d.ClassifyChange(svc, "grant.principal", nil, nil, nil); c != "mutable" {
			t.Fatalf("%s.grant.principal classify = %q, want mutable", svc, c)
		}
	}
}

// rbServer serves one RoleBinding for observe + accepts a merge PATCH (claim).
func rbServer(t *testing.T, ns, name string, rr map[string]any, subs []any, labels map[string]string) (*httptest.Server, *map[string]string) {
	t.Helper()
	base := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns + "/rolebindings/" + name
	lbls := labels
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, base) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind":     "RoleBinding",
				"metadata": map[string]any{"name": name, "namespace": ns, "labels": lbls},
				"roleRef":  rr, "subjects": subs})
		case "PATCH":
			var doc map[string]any
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &doc)
			if m, ok := doc["metadata"].(map[string]any); ok {
				if l, ok := m["labels"].(map[string]any); ok {
					if lbls == nil {
						lbls = map[string]string{}
					}
					for k, v := range l {
						lbls[k] = v.(string)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}})
		default:
			http.Error(w, "m", http.StatusMethodNotAllowed)
		}
	}))
	return srv, &lbls
}

func TestObserveRoleBindingAndClaim(t *testing.T) {
	rr := map[string]any{"kind": "ClusterRole", "name": "admin"}
	subs := []any{map[string]any{"kind": "ServiceAccount", "name": "ops", "namespace": "team"}}
	srv, lbls := rbServer(t, "team", "ops-admin", rr, subs, map[string]string{"app.kubernetes.io/managed-by": "terraform"})
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID(rbacGroup, rbacVersion, "RoleBinding", "team", "ops-admin")

	mp := d.genericMapping("rbac-grant")
	if mp == nil {
		t.Fatal("rbac-grant must route through the schema-driven engine")
	}
	obs, _, err := d.observeMapped(mp, pid)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["grant.role"] != "ClusterRole/admin" || m["grant.principal"] != "ServiceAccount:team/ops" || m["access.privileged"] != true {
		t.Fatalf("observe: %v", m)
	}
	if m["access.scope"] != "resource" || m["service.managed"] != true {
		t.Fatalf("observe scope/managed: %v", m)
	}

	// claim stamps ownership via the shared kind-aware path
	cl := d.Claim("rbac-grant", "ops-admin", "prod", pid)
	if cl.Status != "succeeded" {
		t.Fatalf("claim: %+v", cl)
	}
	if (*lbls)[capLabel] != "ops-admin" {
		t.Fatalf("claim must stamp ownership label on the RoleBinding, got %v", *lbls)
	}
}
