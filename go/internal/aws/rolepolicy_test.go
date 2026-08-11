package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func awsAuthzAttrs() map[string]any {
	return map[string]any{
		"grant.role":        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
		"grant.principal":   "app-runner",
		"access.scope":      "account",
		"access.privileged": false,
		"service.managed":   true,
	}
}

func TestBuildRolePolicyAttachmentHonors(t *testing.T) {
	p, err := BuildRolePolicyAttachment("prod", "reader", awsAuthzAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleName != "app-runner" || p.PolicyArn != "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" {
		t.Fatalf("plan = %+v", p)
	}
	// a privileged policy declared privileged builds fine
	a := awsAuthzAttrs()
	a["grant.role"] = "arn:aws:iam::aws:policy/AdministratorAccess"
	a["access.privileged"] = true
	if _, err := BuildRolePolicyAttachment("prod", "admin", a, nil, 1); err != nil {
		t.Errorf("privileged policy declared privileged should build: %v", err)
	}
}

func TestBuildRolePolicyAttachmentRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"resource-scope-gap": {"access.scope": "resource"}, // AWS is principal-attached
		"bad-arn":            {"grant.role": "not-an-arn"},
		"bad-role":           {"grant.principal": "bad role name!"},
		"privilege-lie":      {"grant.role": "arn:aws:iam::aws:policy/AdministratorAccess", "access.privileged": false},
		"unmanaged":          {"service.managed": false},
		"policy-attr":        {"grant.actions": "s3:*"}, // no inline policy
	}
	for name, extra := range cases {
		a := awsAuthzAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildRolePolicyAttachment("prod", "reader", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"grant.role", "grant.principal"} {
		a := awsAuthzAttrs()
		delete(a, drop)
		if _, err := BuildRolePolicyAttachment("prod", "reader", a, nil, 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

// rolePolicyServer is a STATEFUL fake: AttachRolePolicy records the arn,
// ListAttachedRolePolicies reflects it, DetachRolePolicy clears it.
func rolePolicyServer(t *testing.T) *httptest.Server {
	t.Helper()
	attached := ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			switch r.PostForm.Get("Action") {
			case "GetRole":
				// D445: the detach now reads the ROLE's tags first — an attachment has no
				// ownership surface of its own, but the role it modifies does. The fixture
				// has to describe the role for the same reason every other ownership
				// fixture describes its resource.
				_, _ = w.Write([]byte(iamRoleXML("GetRole", "reader", "prod")))
			case "AttachRolePolicy":
				attached = r.PostForm.Get("PolicyArn")
				_, _ = w.Write([]byte(`<AttachRolePolicyResponse></AttachRolePolicyResponse>`))
			case "ListAttachedRolePolicies":
				m := ""
				if attached != "" {
					m = `<member><PolicyName>p</PolicyName><PolicyArn>` + attached + `</PolicyArn></member>`
				}
				_, _ = w.Write([]byte(`<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult>` +
					`<AttachedPolicies>` + m + `</AttachedPolicies></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`))
			case "DetachRolePolicy":
				attached = ""
				_, _ = w.Write([]byte(`<DetachRolePolicyResponse></DetachRolePolicyResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func rolePolicyDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.IAMBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteRolePolicy(t *testing.T) {
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	res := d.createRolePolicyAttachment("prod", "reader", awsAuthzAttrs(), nil, 1)
	if res.Status != "succeeded" ||
		res.ProviderID != "aauth:app-runner:arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeRolePolicyAttachment("reader", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["grant.principal"] != "app-runner" || got["access.scope"] != "account" ||
		got["access.privileged"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteRolePolicyAttachment("reader", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// after detach the grant is gone
	_, diags, _ := d.observeRolePolicyAttachment("reader", res.ProviderID)
	if len(diags) == 0 {
		t.Fatalf("grant should be absent after detach")
	}
}

// A custom (unclassifiable) policy leaves access.privileged unverifiable, never
// guessed — the four-valued honesty the domain exists to show.
func TestObserveRolePolicyUnknownPrivilegeIsUnverifiable(t *testing.T) {
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	a := awsAuthzAttrs()
	a["grant.role"] = "arn:aws:iam::000000000000:policy/team-custom-thing"
	delete(a, "access.privileged") // don't declare it
	res := d.createRolePolicyAttachment("prod", "reader", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, diags, _ := d.observeRolePolicyAttachment("reader", res.ProviderID)
	for _, o := range obs {
		if o.Path == "access.privileged" {
			t.Fatalf("a custom policy's privilege must NOT be guessed, got %v", o.Value)
		}
	}
	if len(diags) == 0 {
		t.Fatalf("expected a diagnostic that access.privileged is unverifiable")
	}
}

// D277: the grant's principal may arrive as an OPERAND (implementation.principal,
// typically a $ref to a same-plan role's roleName output) — one source of truth
// with the grant.principal attribute, never two.
func TestBuildRolePolicyPrincipalOperand(t *testing.T) {
	attrs := awsAuthzAttrs()
	delete(attrs, "grant.principal")
	p, err := BuildRolePolicyAttachment("prod", "g", attrs,
		map[string]any{"principal": "acme-eks-cluster-role"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleName != "acme-eks-cluster-role" {
		t.Fatalf("operand principal not honored: %q", p.RoleName)
	}

	// attribute AND operand agreeing is fine
	attrs = awsAuthzAttrs()
	attrs["grant.principal"] = "acme-eks-cluster-role"
	if _, err := BuildRolePolicyAttachment("prod", "g", attrs,
		map[string]any{"principal": "acme-eks-cluster-role"}, 1); err != nil {
		t.Fatalf("agreeing attribute+operand must pass: %v", err)
	}

	// disagreeing sources refuse — no silent winner
	if _, err := BuildRolePolicyAttachment("prod", "g", attrs,
		map[string]any{"principal": "other-role"}, 1); err == nil {
		t.Fatal("disagreeing grant.principal and implementation.principal must refuse")
	}

	// an unresolved $ref map reaching the builder refuses by name
	attrs = awsAuthzAttrs()
	delete(attrs, "grant.principal")
	if _, err := BuildRolePolicyAttachment("prod", "g", attrs,
		map[string]any{"principal": map[string]any{"$ref": map[string]any{}}}, 1); err == nil {
		t.Fatal("a non-string principal operand must refuse")
	}
}

// TestAdoptsExistingRolePolicy enrols rolepolicy in the D391 gate. This one is safe by
// the API's own semantics: AttachRolePolicy on an ALREADY-attached policy is a no-op
// success, so there is nothing to duplicate and no pre-read is needed — the driver says
// so in its own comment. The gate turns that comment into an assertion: the create runs
// against a role that already carries the policy, and must still bind the same pid.
func TestAdoptsExistingRolePolicy(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		// D525: AttachRolePolicy is idempotent on (role, policy) — the write can
		// only ever land on exactly that attachment, so no pre-read is needed.
		IdentityFromContent: true,
		Name:                "aws/rolepolicy",
		Classify:            iamQueryRole,
		ExistingServer: func() *httptest.Server {
			const arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body := make([]byte, r.ContentLength)
					_, _ = r.Body.Read(body)
					v, _ := url.ParseQuery(string(body))
					switch v.Get("Action") {
					case "AttachRolePolicy":
						// already attached — AWS answers success, no second attachment
						_, _ = w.Write([]byte(`<AttachRolePolicyResponse></AttachRolePolicyResponse>`))
					case "ListAttachedRolePolicies":
						_, _ = w.Write([]byte(`<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult>` +
							`<AttachedPolicies><member><PolicyName>p</PolicyName><PolicyArn>` + arn +
							`</PolicyArn></member></AttachedPolicies>` +
							`</ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.IAMBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("rolepolicy", "reader", "prod", awsAuthzAttrs(), nil, "reader", 1)
		},
		PID:              "aauth:app-runner:arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
		AllowedMutations: 1, // the idempotent AttachRolePolicy
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
