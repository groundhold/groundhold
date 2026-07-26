package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func awsRoleAttrs() map[string]any {
	return map[string]any{
		"role.permissions":  []any{"s3:GetObject", "s3:ListBucket"},
		"access.mutating":   false,
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildCustomPolicyHonorsAndAssembles(t *testing.T) {
	p, err := BuildCustomPolicy("prod", "viewer", awsRoleAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !awsPolicyNameOK.MatchString(p.PolicyName) || len(p.Permissions) != 2 {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.Contains(p.Document, `"Effect":"Allow"`) || !strings.Contains(p.Document, `"Resource":"*"`) ||
		!strings.Contains(p.Document, "s3:GetObject") {
		t.Fatalf("assembled document = %s", p.Document)
	}
	// a mutating/privileged set declared as such builds
	a := map[string]any{
		"role.permissions":  []any{"s3:PutObject", "iam:PassRole"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	if _, err := BuildCustomPolicy("prod", "admin", a, nil, 1); err != nil {
		t.Errorf("mutating/privileged role declared as such should build: %v", err)
	}
}

func TestBuildCustomPolicyRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"mutating-lie":   {"role.permissions": []any{"s3:PutObject"}, "access.mutating": false},
		"privileged-lie": {"role.permissions": []any{"iam:CreateUser"}, "access.privileged": false},
		"empty-perms":    {"role.permissions": []any{}},
		"bad-action":     {"role.permissions": []any{"not an action"}},
		"unmanaged":      {"service.managed": false},
		"policy-attr":    {"role.condition": "aws:SourceIp"},
	}
	for name, extra := range cases {
		a := awsRoleAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCustomPolicy("prod", "viewer", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := awsRoleAttrs()
	delete(a, "role.permissions")
	if _, err := BuildCustomPolicy("prod", "viewer", a, nil, 1); err == nil {
		t.Error("missing role.permissions must refuse")
	}
}

func customPolicyServer(t *testing.T) *httptest.Server {
	t.Helper()
	doc := ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			switch r.PostForm.Get("Action") {
			case "CreatePolicy":
				doc = r.PostForm.Get("PolicyDocument")
				_, _ = w.Write([]byte(`<CreatePolicyResponse><CreatePolicyResult><Policy>` +
					`<Arn>arn:aws:iam::000000000000:policy/x</Arn><DefaultVersionId>v1</DefaultVersionId>` +
					`</Policy></CreatePolicyResult></CreatePolicyResponse>`))
			case "GetPolicy":
				_, _ = w.Write([]byte(`<GetPolicyResponse><GetPolicyResult><Policy>` +
					`<DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`))
			case "GetPolicyVersion":
				_, _ = w.Write([]byte(`<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion>` +
					`<Document>` + url.QueryEscape(doc) + `</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`))
			case "DeletePolicy":
				_, _ = w.Write([]byte(`<DeletePolicyResponse></DeletePolicyResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func customPolicyDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.IAMBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestCreateObserveDeleteCustomPolicy(t *testing.T) {
	srv := customPolicyServer(t)
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.createCustomPolicy("prod", "viewer", awsRoleAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "acrole:arn:aws:iam::000000000000:policy/") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCustomPolicy("viewer", res.ProviderID)
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
	if del := d.deleteCustomPolicy("viewer", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// The derived classification is measured from the live document: a privileged/
// mutating action set observes access.mutating/access.privileged = true.
func TestObserveCustomPolicyMeasuresPrivilege(t *testing.T) {
	srv := customPolicyServer(t)
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	a := map[string]any{
		"role.permissions":  []any{"s3:GetObject", "iam:PassRole"},
		"access.mutating":   true,
		"access.privileged": true,
		"service.managed":   true,
	}
	res := d.createCustomPolicy("prod", "admin", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, _ := d.observeCustomPolicy("admin", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["access.mutating"] != true || got["access.privileged"] != true {
		t.Fatalf("an iam: action must observe mutating+privileged: %+v", got)
	}
}
