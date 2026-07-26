package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func roleAttrs() map[string]any {
	return map[string]any{
		"role.permissions":  []any{"storage.objects.get", "storage.objects.list"},
		"access.mutating":   false,
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildCustomRoleHonorsAndClassifies(t *testing.T) {
	p, err := BuildCustomRole("acme-prod", "prod", "viewer", roleAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !gcRoleIDOK.MatchString(p.RoleID) || len(p.Permissions) != 2 {
		t.Fatalf("plan = %+v", p)
	}
	// a mutating role declared mutating, privileged declared privileged, builds
	a := map[string]any{
		"role.permissions":  []any{"storage.objects.delete", "storage.buckets.setIamPolicy"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	if _, err := BuildCustomRole("acme-prod", "prod", "admin", a, nil, 1); err != nil {
		t.Errorf("a mutating/privileged role declared as such should build: %v", err)
	}
}

func TestBuildCustomRoleRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"mutating-lie":   {"role.permissions": []any{"storage.objects.delete"}, "access.mutating": false},
		"privileged-lie": {"role.permissions": []any{"resourcemanager.projects.setIamPolicy"}, "access.privileged": false},
		"empty-perms":    {"role.permissions": []any{}},
		"bad-perm":       {"role.permissions": []any{"not a permission"}},
		"unmanaged":      {"service.managed": false},
		"policy-attr":    {"role.condition": "resource.type == x"}, // no conditions/effects
	}
	for name, extra := range cases {
		a := roleAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCustomRole("acme-prod", "prod", "viewer", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing permissions entirely
	a := roleAttrs()
	delete(a, "role.permissions")
	if _, err := BuildCustomRole("acme-prod", "prod", "viewer", a, nil, 1); err == nil {
		t.Error("missing role.permissions must refuse")
	}
}

// customRoleServer is a STATEFUL fake: create records includedPermissions, get
// reflects them.
func customRoleServer(t *testing.T) *httptest.Server {
	t.Helper()
	perms := []string(nil)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/roles"):
				body, _ := io.ReadAll(r.Body)
				var req struct {
					Role struct {
						IncludedPermissions []string `json:"includedPermissions"`
					} `json:"role"`
				}
				_ = json.Unmarshal(body, &req)
				perms = req.Role.IncludedPermissions
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/roles/x"}`))
			case r.Method == "GET":
				b, _ := json.Marshal(map[string]any{"name": "projects/acme-prod/roles/x", "includedPermissions": perms})
				_, _ = w.Write(b)
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func customRoleDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.IAMBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteCustomRole(t *testing.T) {
	srv := customRoleServer(t)
	defer srv.Close()
	d := customRoleDriver(t, srv)
	res := d.createCustomRole("viewer", "prod", roleAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gcrole:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCustomRole("viewer", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["access.mutating"] != false || got["access.privileged"] != false {
		t.Fatalf("observe classification: %+v", got)
	}
	perms, _ := got["role.permissions"].([]string)
	if len(perms) != 2 {
		t.Fatalf("role.permissions not reflected: %+v", got["role.permissions"])
	}
	if del := d.deleteCustomRole("viewer", "prod", res.ProviderID); del.Status != "succeeded" ||
		!strings.Contains(del.Reason, "undelete") {
		t.Fatalf("delete must succeed + note undelete window: %+v", del)
	}
}

// The derived classification is MEASURED from live permissions: a mutating/
// privileged permission set observes access.mutating/access.privileged = true.
func TestObserveCustomRoleMeasuresPrivilege(t *testing.T) {
	srv := customRoleServer(t)
	defer srv.Close()
	d := customRoleDriver(t, srv)
	a := map[string]any{
		"role.permissions":  []any{"storage.objects.get", "iam.serviceAccounts.setIamPolicy"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	res := d.createCustomRole("admin", "prod", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, _ := d.observeCustomRole("admin", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["access.mutating"] != true || got["access.privileged"] != true {
		t.Fatalf("a setIamPolicy permission must observe mutating+privileged: %+v", got)
	}
}
