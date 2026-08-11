package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// This file rounds out awspolicy_net.go coverage: sameActionSet (0%) and the
// EntityAlreadyExists re-check branch in createCustomPolicy (a name conflict
// that must be idempotent when the action set matches, and a refusal when it
// does not — "adopt explicitly", never a silent overwrite).

// ---- sameActionSet: PURE, order/duplicate independent ---------------------

func TestSameActionSet(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"identical", []string{"s3:GetObject", "s3:PutObject"}, []string{"s3:GetObject", "s3:PutObject"}, true},
		{"reordered", []string{"s3:GetObject", "s3:PutObject"}, []string{"s3:PutObject", "s3:GetObject"}, true},
		{"different length", []string{"s3:GetObject"}, []string{"s3:GetObject", "s3:PutObject"}, false},
		{"different action", []string{"s3:GetObject"}, []string{"s3:PutObject"}, false},
		{"both empty", nil, nil, true},
		{"duplicate in one, not the other", []string{"s3:GetObject", "s3:GetObject"}, []string{"s3:GetObject", "s3:PutObject"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameActionSet(c.a, c.b); got != c.want {
				t.Errorf("sameActionSet(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

// customPolicyConflictServer answers CreatePolicy with EntityAlreadyExists and
// GetPolicy/GetPolicyVersion with a fixed document carrying `existingActions` —
// simulating a policy that already landed at our deterministic name.
func customPolicyConflictServer(t *testing.T, existingActions string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			switch r.PostForm.Get("Action") {
			case "CreatePolicy":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>EntityAlreadyExists</Code></Error></ErrorResponse>`))
			case "GetPolicy":
				_, _ = w.Write([]byte(`<GetPolicyResponse><GetPolicyResult><Policy>` +
					`<DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`))
			case "GetPolicyVersion":
				doc := `{"Statement":[{"Effect":"Allow","Action":` + existingActions + `,"Resource":"*"}]}`
				_, _ = w.Write([]byte(`<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion>` +
					`<Document>` + url.QueryEscape(doc) + `</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

// TestCreateCustomPolicy_NameConflictSameActionsIsIdempotent: a policy already
// exists at our deterministic name with the SAME action set — idempotent
// success (never a re-write; a policy is content-addressed by its Arn, and one
// version already carries the right content).
func TestCreateCustomPolicy_NameConflictSameActionsIsIdempotent(t *testing.T) {
	srv := customPolicyConflictServer(t, `["s3:GetObject","s3:ListBucket"]`)
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.createCustomPolicy("prod", "viewer", awsRoleAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("a name conflict with a matching action set must be idempotent success, got %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "acrole:arn:aws:iam::000000000000:policy/") {
		t.Fatalf("providerId = %q", res.ProviderID)
	}
}

// TestCreateCustomPolicy_NameConflictDifferentActionsRefuses: a policy at our
// name with a DIFFERENT action set must refuse — never silently overwritten.
func TestCreateCustomPolicy_NameConflictDifferentActionsRefuses(t *testing.T) {
	srv := customPolicyConflictServer(t, `["iam:CreateUser"]`)
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.createCustomPolicy("prod", "viewer", awsRoleAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "DIFFERENT action set") {
		t.Fatalf("a mismatched name conflict must refuse naming the mismatch, got %+v", res)
	}
}

// TestCreateCustomPolicy_NameConflictUnreadableIsUnknown: the conflict re-check
// itself is unreadable — ambiguous, unknown WITH the pid (reconcile), never a
// guessed success or failure.
func TestCreateCustomPolicy_NameConflictUnreadableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if r.PostForm.Get("Action") == "CreatePolicy" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>EntityAlreadyExists</Code></Error></ErrorResponse>`))
				return
			}
			w.WriteHeader(500) // GetPolicy unreadable
		}))
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.createCustomPolicy("prod", "viewer", awsRoleAttrs(), nil, 1)
	if res.Status != "unknown" {
		t.Fatalf("an unreadable conflict re-check must be unknown, got %+v", res)
	}
	if res.ProviderID == "" {
		t.Fatalf("the unknown result must still carry the pid, got %+v", res)
	}
}

// iamQueryRole reads the PEEKED body the harness hands it. It must never call
// req.ParseForm: that drains the request the driver is still about to send.
func iamQueryRole(_ *http.Request, body []byte) certifynet.Role {
	v, _ := url.ParseQuery(string(body))
	switch v.Get("Action") {
	case "GetPolicy", "GetPolicyVersion", "GetRole", "ListPolicies", "ListRoleTags",
		"ListAttachedRolePolicies", "GetRolePolicy":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingCustomPolicy enrols custompolicy in the D391 gate. An IAM policy is
// name-addressed and CONTENT-addressed by its Arn: a policy already standing at our
// deterministic name with the same action set is bound as-is and never re-written, so
// the proof here is that the create binds it and adds no policy version.
func TestAdoptsExistingCustomPolicy(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/custompolicy",
		Classify: iamQueryRole,
		ExistingServer: func() *httptest.Server {
			return customPolicyConflictServer(t, `["s3:GetObject","s3:ListBucket"]`)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.IAMBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("custompolicy", "viewer", "prod", awsRoleAttrs(), nil, "viewer", 1)
		},
		AllowedMutations: 1, // the refused CreatePolicy — the detection itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D528: the mutation meter caught this test family having no teeth for the D522
// fix. `observeCustomPolicy` used to turn EVERY error — a 500, a timeout, an
// expired credential — into "nothing to observe", so a failure to READ was
// reported as an empty world and converge agreed with it. The absence branch was
// covered; the FAILURE branch was not, and re-injecting the bug broke nothing.
//
// A read that fails is not a fact about the resource. It must return an error,
// which blocks, and never an observation set that a reconcile can act on.
func TestCustomPolicyReadFailureIsNotAnEmptyWorld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Not a 404: the estate could not answer at all.
		http.Error(w, `<ErrorResponse><Error><Code>ServiceFailure</Code></Error></ErrorResponse>`,
			http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := newForeignDriver(nil)
	d.IAMBaseURL = srv.URL
	obs, diags, err := d.observeCustomPolicy("perms",
		customPolicyProviderID("arn:aws:iam::000000000000:policy/pv-perms-prod-1a2b3c4d"))
	if err == nil {
		t.Fatalf("a 500 from the policy read was reported as a readable world "+
			"(obs=%v diags=%v) — a failure to read must BLOCK, not converge", obs, diags)
	}
	if len(obs) != 0 {
		t.Errorf("a failed read still produced observations: %v", obs)
	}
}
