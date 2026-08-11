package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func azRoleDefAttrs() map[string]any {
	return map[string]any{
		"role.permissions":  []any{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/blobServices/containers/read"},
		"access.mutating":   false,
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildAzureCustomRoleHonorsAndClassifies(t *testing.T) {
	p, err := BuildAzureCustomRole("prod", "viewer", azRoleDefAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Permissions) != 2 || !strings.Contains(p.RoleName, "viewer") {
		t.Fatalf("plan = %+v", p)
	}
	a := map[string]any{
		"role.permissions":  []any{"Microsoft.Storage/storageAccounts/write", "Microsoft.Authorization/roleAssignments/write"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	if _, err := BuildAzureCustomRole("prod", "admin", a, nil, 1); err != nil {
		t.Errorf("mutating/privileged role declared as such should build: %v", err)
	}
}

func TestBuildAzureCustomRoleRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"mutating-lie":   {"role.permissions": []any{"Microsoft.Storage/storageAccounts/write"}, "access.mutating": false},
		"privileged-lie": {"role.permissions": []any{"Microsoft.Authorization/roleDefinitions/write"}, "access.privileged": false},
		"empty-perms":    {"role.permissions": []any{}},
		"bad-action":     {"role.permissions": []any{"not an action"}},
		"unmanaged":      {"service.managed": false},
		"policy-attr":    {"role.notActions": "x"},
	}
	for name, extra := range cases {
		a := azRoleDefAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzureCustomRole("prod", "viewer", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := azRoleDefAttrs()
	delete(a, "role.permissions")
	if _, err := BuildAzureCustomRole("prod", "viewer", a, nil, 1); err == nil {
		t.Error("missing role.permissions must refuse")
	}
}

func azCustomRoleServer(t *testing.T) *httptest.Server {
	t.Helper()
	actions := []string(nil)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Properties struct {
						Permissions []struct {
							Actions []string `json:"actions"`
						} `json:"permissions"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &doc)
				if len(doc.Properties.Permissions) > 0 {
					actions = doc.Properties.Permissions[0].Actions
				}
				w.WriteHeader(201)
				b, _ := json.Marshal(map[string]any{"properties": map[string]any{
					"permissions": []any{map[string]any{"actions": actions}}}})
				_, _ = w.Write(b)
			case "GET":
				b, _ := json.Marshal(map[string]any{"properties": map[string]any{
					"permissions": []any{map[string]any{"actions": actions}}}})
				_, _ = w.Write(b)
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azCustomRoleDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureCustomRole(t *testing.T) {
	srv := azCustomRoleServer(t)
	defer srv.Close()
	d := azCustomRoleDriver(t, srv)
	res := d.createAzureCustomRole("prod", "viewer", azRoleDefAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azcrole:"+testSub+":") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureCustomRole("viewer", res.ProviderID)
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
	if del := d.deleteAzureCustomRole("viewer", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveAzureCustomRoleMeasuresPrivilege(t *testing.T) {
	srv := azCustomRoleServer(t)
	defer srv.Close()
	d := azCustomRoleDriver(t, srv)
	a := map[string]any{
		"role.permissions":  []any{"Microsoft.Storage/storageAccounts/read", "Microsoft.Authorization/roleAssignments/write"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	res := d.createAzureCustomRole("prod", "admin", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, _ := d.observeAzureCustomRole("admin", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["access.mutating"] != true || got["access.privileged"] != true {
		t.Fatalf("an Authorization/write action must observe mutating+privileged: %+v", got)
	}
}

// D797, one cloud over: the same first-element read, the same under-report.
func TestRoleActionsUnionEveryPermissionBlock(t *testing.T) {
	var doc azureCustomRoleDoc
	if err := json.Unmarshal([]byte(`{"properties":{"permissions":[
	  {"actions":["Microsoft.Storage/storageAccounts/read"]},
	  {"actions":["Microsoft.Authorization/roleAssignments/write"],"notActions":["x/delete"]}]}}`),
		&doc); err != nil {
		t.Fatal(err)
	}
	actions, narrowed := azRoleActions(doc)
	if len(actions) != 2 {
		t.Fatalf("permission blocks past the first were not read: %v", actions)
	}
	if !azRolePrivileged(actions) {
		t.Fatal("an Authorization/write grant in the SECOND block reported as unprivileged")
	}
	if !narrowed {
		t.Fatal("notActions present but the reported set was not flagged as a ceiling")
	}
}
