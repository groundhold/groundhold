package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func iamRoleAttrs() map[string]any {
	// IAM is global: no location.region (regionFreeAWS exempts it).
	return map[string]any{
		"display.name":    "batch runner",
		"key.exportable":  false,
		"service.managed": true,
	}
}

func TestBuildIAMRoleHonors(t *testing.T) {
	p, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !iamRoleNameOK.MatchString(p.RoleName) || !strings.HasPrefix(p.RoleName, "pv-runner-prod-") {
		t.Fatalf("role name = %q", p.RoleName)
	}
	if !strings.Contains(p.TrustPolicy, "000000000000:root") {
		t.Fatalf("default trust policy missing self-account: %q", p.TrustPolicy)
	}
	params := p.createParams("runner", "prod")
	if params["Action"] != "CreateRole" || params["Tags.member.1.Value"] != "runner" {
		t.Fatalf("createParams = %+v", params)
	}
}

func TestBuildIAMRoleRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"exportable-key-refused": {"key.exportable": true}, // D53 — keyless identity
		"unmanaged":              {"service.managed": false},
		"unknown-attr":           {"identity.tier": "x"},
	}
	for name, extra := range cases {
		a := iamRoleAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildIAMRole("000000000000", "prod", "runner", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestBuildIAMRoleCustomTrustPolicy(t *testing.T) {
	impl := map[string]any{"assume_role_policy": `{"Version":"2012-10-17","Statement":[]}`}
	p, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.TrustPolicy, "root") {
		t.Fatalf("custom trust policy should be verbatim, got %q", p.TrustPolicy)
	}
}

// iamRoleXML reflects the owner tags a GetRole/CreateRole response carries.
func iamRoleXML(result, capLabel, env string) string {
	return `<` + result + `Response><` + result + `Result><Role>` +
		`<RoleName>pv-runner-prod-x</RoleName>` +
		`<Arn>arn:aws:iam::000000000000:role/pv-runner-prod-x</Arn>` +
		`<Description>batch runner</Description>` +
		`<Tags><member><Key>groundhold-capability</Key><Value>` + capLabel + `</Value></member>` +
		`<member><Key>groundhold-environment</Key><Value>` + env + `</Value></member></Tags>` +
		`</Role></` + result + `Result></` + result + `Response>`
}

func iamServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			switch queryAction(b) {
			case "CreateRole":
				_, _ = w.Write([]byte(iamRoleXML("CreateRole", capLabel, "prod")))
			case "GetRole":
				_, _ = w.Write([]byte(iamRoleXML("GetRole", capLabel, "prod")))
			case "DeleteRole":
				_, _ = w.Write([]byte(`<DeleteRoleResponse></DeleteRoleResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func iamRoleDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.IAMBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteIAMRole(t *testing.T) {
	srv := iamServer(t, "runner")
	defer srv.Close()
	d := iamRoleDriver(t, srv)
	res := d.Create("iam", "runner", "prod", iamRoleAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "iamrole:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeIAMRole("runner", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["display.name"] != "batch runner" || got["key.exportable"] != false || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("iam", "runner", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteIAMRoleForeignRefused(t *testing.T) {
	srv := iamServer(t, "someone-else")
	defer srv.Close()
	d := iamRoleDriver(t, srv)
	pid := iamRoleProviderID("000000000000", IAMRoleName("prod", "runner", 1))
	res := d.Delete("iam", "runner", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign role must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessIAM(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := iamRoleProviderID("000000000000", IAMRoleName("prod", "runner", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "aws/iam",
		AssertTransient: true,         // D237: create/delete route through provider.MutationResult
		Classify:        queryXMLRole, // CreateRole/DeleteRole opaque; GetRole is a read
		OwnerTagValue:   "runner",
		DeterministicID: true, // the role name is a deterministic chosen name
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return iamServer(t, "runner") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("iam", "runner", "prod", iamRoleAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return iamServer(t, "runner") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("iam", "runner", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// D277: an explicit implementation.roleName overrides the deterministic name —
// a service role other capabilities reference by name (EKS cluster role, a
// grant's principal) must be nameable; a bad name refuses.
func TestBuildIAMRoleExplicitName(t *testing.T) {
	p, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		map[string]any{"roleName": "acme-eks-cluster-role"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleName != "acme-eks-cluster-role" {
		t.Fatalf("explicit roleName not honored: %q", p.RoleName)
	}
	if _, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		map[string]any{"roleName": "bad name with spaces"}, 1); err == nil {
		t.Fatal("an invalid explicit role name must refuse")
	}
	if _, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		map[string]any{"roleName": 7}, 1); err == nil {
		t.Fatal("a non-string explicit role name must refuse")
	}
}
