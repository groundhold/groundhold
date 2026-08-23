package azure

import (
	"io"
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

// TestBuildAzureRolePrincipalType (D896): the principal type is an operand, not a hardcoded
// "ServicePrincipal". It defaults to ServicePrincipal (the workload-grant common case), honors
// an explicit User/Group, and refuses an unknown value rather than sending it to a 400.
func TestBuildAzureRolePrincipalType(t *testing.T) {
	// default
	p, err := BuildAzureRole("prod", "reader", azRoleAttrs(), nil, 1)
	if err != nil || p.PrincipalType != "ServicePrincipal" {
		t.Fatalf("default principalType = %q err=%v", p.PrincipalType, err)
	}
	// explicit User / Group honored
	for _, pt := range []string{"User", "Group", "ServicePrincipal"} {
		p, err := BuildAzureRole("prod", "reader", azRoleAttrs(), map[string]any{"principal_type": pt}, 1)
		if err != nil || p.PrincipalType != pt {
			t.Errorf("principal_type %q = %q err=%v", pt, p.PrincipalType, err)
		}
	}
	// an unknown type refuses
	if _, err := BuildAzureRole("prod", "reader", azRoleAttrs(), map[string]any{"principal_type": "Robot"}, 1); err == nil {
		t.Fatal("an unknown principal_type was accepted")
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

// A role outside the curated set leaves access.privileged unverifiable, never
// guessed — the four-valued honesty the domain exists to show. It is NOT necessarily
// a custom role, and D1225 stopped the diagnostic from saying so; see
// azrole_named_gate_test.go for the gates on which cause gets named.
// TestCreateAzureRoleBodyCarriesPrincipalType (D896): the PUT body's principalType must be
// the operand's value, not a hardcoded "ServicePrincipal" — else a User/Group grant is sent
// as a ServicePrincipal and Azure 400s it.
func TestCreateAzureRoleBodyCarriesPrincipalType(t *testing.T) {
	var putBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			b, _ := io.ReadAll(r.Body)
			putBody = string(b)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	d := azRoleDriver(t, srv)
	res := d.createAzureRole("prod", "reader", azRoleAttrs(), map[string]any{"principal_type": "User"}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(putBody, `"principalType":"User"`) {
		t.Fatalf("PUT body must carry the operand principalType User, got %s", putBody)
	}
}

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
