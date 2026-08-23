package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authzAttrs() map[string]any {
	return map[string]any{
		"grant.role":        "roles/storage.objectViewer",
		"grant.principal":   "serviceAccount:runner@acme-prod.iam.gserviceaccount.com",
		"access.scope":      "account",
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildIAMBindingHonors(t *testing.T) {
	p, err := BuildIAMBinding("acme-prod", "prod", "reader", authzAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != "roles/storage.objectViewer" ||
		p.Member != "serviceAccount:runner@acme-prod.iam.gserviceaccount.com" {
		t.Fatalf("plan = %+v", p)
	}
	// a privileged role declared privileged builds fine
	a := authzAttrs()
	a["grant.role"] = "roles/owner"
	a["access.privileged"] = true
	if _, err := BuildIAMBinding("acme-prod", "prod", "admin", a, nil, 1); err != nil {
		t.Errorf("privileged role declared privileged should build: %v", err)
	}
}

func TestBuildIAMBindingRefusals(t *testing.T) {
	base := authzAttrs
	cases := map[string]map[string]any{
		"resource-scope-deferred": {"access.scope": "resource"},
		"bad-role":                {"grant.role": "not-a-role"},
		"bad-member":              {"grant.principal": "allUsers"}, // not a typed member
		"untyped-member":          {"grant.principal": "runner@acme-prod.iam.gserviceaccount.com"},
		"privilege-lie":           {"grant.role": "roles/owner", "access.privileged": false}, // owner is privileged
		"unmanaged":               {"service.managed": false},
		"policy-attr":             {"grant.condition": "resource.name == 'x'"}, // no inline policy/conditions
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildIAMBinding("acme-prod", "prod", "reader", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing role / principal
	for _, drop := range []string{"grant.role", "grant.principal"} {
		a := base()
		delete(a, drop)
		if _, err := BuildIAMBinding("acme-prod", "prod", "reader", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

// crmPolicyServer is a STATEFUL fake project IAM policy: setIamPolicy records the
// written policy, getIamPolicy reflects it. seed pre-populates the policy.
// gcpRoleFixturePerms lets a test choose the includedPermissions roles.get serves;
// empty = a narrow read-only set (no escalation match). gcpRoleFixtureHits counts
// fetches so the per-sweep cache is asserted by observation.
var gcpRoleFixturePerms string
var gcpRoleFixtureHits int

func crmPolicyServer(t *testing.T, seed string) *httptest.Server {
	t.Helper()
	pol := seed
	if pol == "" {
		pol = `{"bindings":[],"etag":"BwXseed"}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/roles/"):
				// D1231: observe reads the role DEFINITION when the id does not settle
				// privilege. Without this the driver reached the REAL iam.googleapis.com
				// from a unit test — a hermeticity break the 401 in the diagnostic made
				// visible. authzDriver now pins IAMBaseURL here too.
				gcpRoleFixtureHits++
				perms := gcpRoleFixturePerms
				if perms == "" {
					perms = `"storage.objects.get","storage.objects.list"`
				}
				_, _ = w.Write([]byte(`{"includedPermissions":[` + perms + `]}`))
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_, _ = w.Write([]byte(pol))
			case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				body, _ := io.ReadAll(r.Body)
				var req struct {
					Policy json.RawMessage `json:"policy"`
				}
				_ = json.Unmarshal(body, &req)
				pol = string(req.Policy)
				_, _ = w.Write(req.Policy)
			default:
				w.WriteHeader(404)
			}
		}))
}

func authzDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.CRMBaseURL = srv.URL
	d.IAMBaseURL = srv.URL // hermetic: roles.get must not reach the real IAM API
	return d
}

func TestCreateObserveDeleteIAMBinding(t *testing.T) {
	srv := crmPolicyServer(t, "")
	defer srv.Close()
	d := authzDriver(t, srv)
	res := d.createIAMBinding("reader", "prod", authzAttrs(), nil, 1)
	if res.Status != "succeeded" ||
		res.ProviderID != "gauth:acme-prod:roles/storage.objectViewer:serviceAccount:runner@acme-prod.iam.gserviceaccount.com" {
		t.Fatalf("create: %+v", res)
	}
	// idempotent re-create
	if r2 := d.createIAMBinding("reader", "prod", authzAttrs(), nil, 1); r2.Status != "succeeded" {
		t.Fatalf("idempotent create: %+v", r2)
	}
	obs, _, err := d.observeIAMBinding("reader", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["grant.role"] != "roles/storage.objectViewer" ||
		got["access.scope"] != "account" || got["access.privileged"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteIAMBinding("reader", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// after delete the grant is gone
	_, diags, _ := d.observeIAMBinding("reader", res.ProviderID)
	if len(diags) == 0 {
		t.Fatalf("grant should be absent after delete")
	}
}

// The content-addressed safety property (the authorization analogue of a
// foreign-delete refusal): removing our grant must leave ANOTHER principal's grant
// in the SAME role untouched.
func TestDeleteIAMBindingRemovesOnlyOurMember(t *testing.T) {
	seed := `{"bindings":[{"role":"roles/storage.objectViewer","members":[` +
		`"serviceAccount:runner@acme-prod.iam.gserviceaccount.com",` +
		`"serviceAccount:someone-else@acme-prod.iam.gserviceaccount.com"]}],"etag":"BwXseed"}`
	srv := crmPolicyServer(t, seed)
	defer srv.Close()
	d := authzDriver(t, srv)
	pid := "gauth:acme-prod:roles/storage.objectViewer:serviceAccount:runner@acme-prod.iam.gserviceaccount.com"
	if del := d.deleteIAMBinding("reader", "prod", pid); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// the OTHER member must survive
	other := "gauth:acme-prod:roles/storage.objectViewer:serviceAccount:someone-else@acme-prod.iam.gserviceaccount.com"
	obs, diags, _ := d.observeIAMBinding("reader", other)
	if len(diags) != 0 || len(obs) == 0 {
		t.Fatalf("another principal's grant must survive our delete: diags=%v", diags)
	}
}
