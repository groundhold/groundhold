package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testPrincipal = "11111111-1111-1111-1111-111111111111"
const readerGUID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

func azRoleAttrs() map[string]any {
	return map[string]any{
		"grant.role":        "Reader",
		"grant.principal":   testPrincipal,
		"access.scope":      "account",
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildAzureRoleHonors(t *testing.T) {
	p, err := BuildAzureRole("prod", "reader", azRoleAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleGuid != readerGUID || p.PrincipalID != testPrincipal {
		t.Fatalf("plan = %+v", p)
	}
	// a raw role-definition GUID is accepted (privilege unclassifiable)
	a := azRoleAttrs()
	a["grant.role"] = "00000000-0000-0000-0000-0000000000ab"
	delete(a, "access.privileged")
	if _, err := BuildAzureRole("prod", "custom", a, nil, 1); err != nil {
		t.Errorf("a raw role GUID should build: %v", err)
	}
	// a privileged built-in declared privileged builds
	a2 := azRoleAttrs()
	a2["grant.role"] = "Owner"
	a2["access.privileged"] = true
	if _, err := BuildAzureRole("prod", "admin", a2, nil, 1); err != nil {
		t.Errorf("Owner declared privileged should build: %v", err)
	}
}

func TestBuildAzureRoleRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"resource-scope-deferred": {"access.scope": "resource"},
		"unknown-role":            {"grant.role": "Sorcerer"}, // not a built-in name or GUID
		"bad-principal":           {"grant.principal": "not-a-guid"},
		"privilege-lie":           {"grant.role": "Owner", "access.privileged": false},
		"unmanaged":               {"service.managed": false},
		"policy-attr":             {"grant.actions": "*"},
	}
	for name, extra := range cases {
		a := azRoleAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzureRole("prod", "reader", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"grant.role", "grant.principal"} {
		a := azRoleAttrs()
		delete(a, drop)
		if _, err := BuildAzureRole("prod", "reader", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func azRoleServer(t *testing.T, roleGUID string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"properties":{` +
					`"roleDefinitionId":"/subscriptions/` + testSub + `/providers/Microsoft.Authorization/roleDefinitions/` + roleGUID + `",` +
					`"principalId":"` + testPrincipal + `"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azRoleDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureRole(t *testing.T) {
	srv := azRoleServer(t, readerGUID)
	defer srv.Close()
	d := azRoleDriver(t, srv)
	res := d.createAzureRole("prod", "reader", azRoleAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azauth:"+testSub+":") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureRole("reader", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["grant.role"] != "Reader" || got["grant.principal"] != testPrincipal ||
		got["access.scope"] != "account" || got["access.privileged"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureRole("reader", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// A custom (unclassifiable) role leaves access.privileged unverifiable, never
// guessed — the four-valued honesty the domain exists to show.
func TestObserveAzureRoleUnknownPrivilegeIsUnverifiable(t *testing.T) {
	customGUID := "00000000-0000-0000-0000-0000000000ab"
	srv := azRoleServer(t, customGUID)
	defer srv.Close()
	d := azRoleDriver(t, srv)
	pid := azureRoleProviderID(testSub, azAssignmentGUID("/subscriptions/"+testSub, testPrincipal, customGUID))
	obs, diags, _ := d.observeAzureRole("custom", pid)
	for _, o := range obs {
		if o.Path == "access.privileged" {
			t.Fatalf("a custom role's privilege must NOT be guessed, got %v", o.Value)
		}
	}
	if len(diags) == 0 {
		t.Fatalf("expected a diagnostic that access.privileged is unverifiable")
	}
}
