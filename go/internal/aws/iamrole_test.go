package aws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// D751: this passed `nil` operands and asserted the account-root default. A role
	// with no declared trust is now refused, so the test states the trust it means.
	p, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		map[string]any{"trust_service": "lambda.amazonaws.com"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !iamRoleNameOK.MatchString(p.RoleName) || !strings.HasPrefix(p.RoleName, "pv-runner-prod-") {
		t.Fatalf("role name = %q", p.RoleName)
	}
	if !strings.Contains(p.TrustPolicy, "lambda.amazonaws.com") {
		t.Fatalf("trust policy does not name the declared service: %q", p.TrustPolicy)
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
		// D751: with a trust operand supplied, each case still refuses for the reason
		// it names. Passing nil here would have refused for the MISSING TRUST instead,
		// and every case would pass while testing nothing it claims to.
		if _, err := BuildIAMRole("000000000000", "prod", "runner", a, iamRoleImpl(nil), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// iamRoleImpl is the smallest operand block that BUILDS: a role must say who may
// assume it (D751). Tests whose subject is something else use this.
func iamRoleImpl(extra map[string]any) map[string]any {
	m := map[string]any{"trust_service": "lambda.amazonaws.com"}
	for k, v := range extra {
		m[k] = v
	}
	return m
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
// iamTrustDoc is the trust policy the fake serves. It served NONE until D751, so the
// driver's read of it could not be exercised end to end — the D520 class, a fixture
// mirroring the driver's blind spot. Default: a real service role.
var iamTrustDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

func iamRoleXML(result, capLabel, env string) string {
	return `<` + result + `Response><` + result + `Result><Role>` +
		`<RoleName>pv-runner-prod-x</RoleName>` +
		`<AssumeRolePolicyDocument>` + url.QueryEscape(iamTrustDoc) +
		`</AssumeRolePolicyDocument>` +
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
	res := d.Create("iam", "runner", "prod", iamRoleAttrs(), iamRoleImpl(nil), "k", 1)
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
		Name:            "aws/iam",
		AssertTransient: true,         // D237: create/delete route through provider.MutationResult
		Classify:        queryXMLRole, // CreateRole/DeleteRole opaque; GetRole is a read
		OwnerTagValue:   "runner",
		DeterministicID: true, // the role name is a deterministic chosen name
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("iam", "runner", pid)
		},
		GoneCode: "NoSuchEntity", // this service's own not-found code (D522)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return iamServer(t, "runner") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("iam", "runner", "prod", iamRoleAttrs(), iamRoleImpl(nil), "k", 1)
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
		iamRoleImpl(map[string]any{"roleName": "acme-eks-cluster-role"}), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleName != "acme-eks-cluster-role" {
		t.Fatalf("explicit roleName not honored: %q", p.RoleName)
	}
	if _, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		iamRoleImpl(map[string]any{"roleName": "bad name with spaces"}), 1); err == nil {
		t.Fatal("an invalid explicit role name must refuse")
	}
	if _, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		iamRoleImpl(map[string]any{"roleName": 7}), 1); err == nil {
		t.Fatal("a non-string explicit role name must refuse")
	}
}

// TestAdoptsExistingIAMRole enrols iam in the D391 gate. A role is name-addressed, so a
// second create cannot duplicate — it is answered EntityAlreadyExists — and the tags on
// the standing role are what license binding it. An unowned role at our name is refused,
// which is the case that already had a test.
func TestAdoptsExistingIAMRole(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/iam",
		Classify: iamQueryRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					b := make([]byte, r.ContentLength)
					_, _ = r.Body.Read(b)
					switch queryAction(b) {
					case "CreateRole":
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`<ErrorResponse><Error>` +
							`<Code>EntityAlreadyExists</Code></Error></ErrorResponse>`))
					case "GetRole":
						_, _ = w.Write([]byte(iamRoleXML("GetRole", "runner", "prod")))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.IAMBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("iam", "runner", "prod", iamRoleAttrs(), iamRoleImpl(nil), "runner", 1)
		},
		AllowedMutations: 1, // the refused CreateRole
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D740. Two halves of the same hole, both reachable from the same operand.
//
// A field report created a flow-log delivery role trusted only by the account root, so
// the flow log AWS accepted delivered nothing (D727). The create refuses such a role
// now — which closed the road without opening another one, because the only way to
// build a correct trust policy was to hand-write the JSON document, and getting that
// wrong is how the estate got there.
func TestIAMRoleTrustOperands(t *testing.T) {
	base := func(impl map[string]any) (IAMRolePlan, error) {
		return BuildIAMRole("000000000000", "prod", "flowlog",
			map[string]any{"service.managed": true}, impl, 1)
	}

	t.Run("a trust policy the builder cannot read must refuse", func(t *testing.T) {
		// The natural YAML shape: a mapping. This used to vanish into a type assertion
		// and leave the account-root default, so the author saw a role they believed
		// was scoped to a service and the service could not assume it.
		_, err := base(map[string]any{"assume_role_policy": map[string]any{
			"Version": "2012-10-17", "Statement": []any{}}})
		if err == nil {
			t.Fatal("a non-string trust policy was accepted — it silently becomes the " +
				"same-account default, which trusts nothing the author scoped it for")
		}
		if !strings.Contains(err.Error(), "must not fall back") {
			t.Fatalf("the refusal must say what the silent fallback costs, got %v", err)
		}
	})

	t.Run("trust_service builds a policy the service can assume", func(t *testing.T) {
		p, err := base(map[string]any{"trust_service": "vpc-flow-logs.amazonaws.com"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(p.TrustPolicy, `"Service":"vpc-flow-logs.amazonaws.com"`) {
			t.Fatalf("trust policy = %s", p.TrustPolicy)
		}
		// And the check D727 added must accept it — the two must agree, or the driver
		// still refuses a role it built itself.
		r := iamRole{AssumeRolePolicyDocument: url.QueryEscape(p.TrustPolicy)}
		trusts, ok := r.trustsService("vpc-flow-logs.amazonaws.com")
		if !ok || !trusts {
			t.Fatalf("the role this builder produces must satisfy the check that refuses "+
				"one it cannot: trusts=%v readable=%v", trusts, ok)
		}
	})

	t.Run("both spellings at once refuse", func(t *testing.T) {
		if _, err := base(map[string]any{
			"trust_service":      "vpc-flow-logs.amazonaws.com",
			"assume_role_policy": `{"Statement":[]}`,
		}); err == nil {
			t.Fatal("one trust policy or the other, never both")
		}
	})

	t.Run("a bogus service principal refuses", func(t *testing.T) {
		if _, err := base(map[string]any{"trust_service": "not a principal"}); err == nil {
			t.Fatal("an unbounded string is interpolated into a policy document")
		}
	})

	// D751 SUPERSEDES the subtest `no operand still gets the minimal default`, whose
	// name asserted the defect: it called account-root trust MINIMAL. It is not — a
	// role trusting `<acct>:root` can be assumed by every principal in the account
	// whose identity policy allows it, and by no service at all. The field built five
	// such roles, could not attach one to a Lambda, and fixed them by hand.
	t.Run("no operand at all is a refusal, not a default", func(t *testing.T) {
		_, err := base(nil)
		if err == nil {
			t.Fatal("a candidate that declares no trust policy must be refused: the " +
				"account-root fallback is WIDER than any service role, not narrower")
		}
		for _, want := range []string{"trust_service", "assume_role_policy"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal must name %s — a refusal that does not say how to "+
					"proceed routes the reader at nothing", want)
			}
		}
	})
}

// D751, the observe half. The vocabulary for capability.identity.serviceaccount has four
// attributes and NONE of them says who may assume the role, so a contract cannot ask and
// no verdict can carry the answer. The field put it exactly right: "polityka zaufania jest
// pierwszą własnością roli — i jedyną, której kontrakt nie widzi". Until there is an
// attribute, the driver can still say what it READ, and a role trusting only the account
// root is a fact with a consequence at both ends.
func TestObserveReportsARoleNoServiceCanAssume(t *testing.T) {
	cases := []struct {
		name     string
		trust    string
		wantDiag bool
	}{
		{"only the account root", `{"Statement":[{"Effect":"Allow","Principal":` +
			`{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`, true},
		{"a service principal", `{"Statement":[{"Effect":"Allow","Principal":` +
			`{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, false},
		{"root AND a service — the service can assume it", `{"Statement":[{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:aws:iam::000000000000:root","Service":"lambda.amazonaws.com"},` +
			`"Action":"sts:AssumeRole"}]}`, false},
		{"undecodable — we could not tell, so we say nothing", `not json at all`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := iamRole{AssumeRolePolicyDocument: url.QueryEscape(c.trust)}
			onlyRoot, ok := r.trustsOnlyAccountRoot()
			got := ok && onlyRoot
			if got != c.wantDiag {
				t.Fatalf("trustsOnlyAccountRoot = (%v, %v), want a diagnostic: %v — a role "+
					"the intended service cannot assume, and every principal in the account "+
					"can, must not read as an ordinary role (D751)", onlyRoot, ok, c.wantDiag)
			}
		})
	}
}

// The emission, not the helper: a diagnostic that never reaches observe's return value
// tells nobody anything (D726).
func TestObserveEmitsTheRootTrustDiagnostic(t *testing.T) {
	old := iamTrustDoc
	iamTrustDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
	defer func() { iamTrustDoc = old }()

	srv := iamServer(t, "runner")
	defer srv.Close()
	d := iamRoleDriver(t, srv)

	_, diags, err := d.observeIAMRole("runner", "iamrole:000000000000:pv-runner-prod-x")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "only the account root") {
			found = true
		}
	}
	if !found {
		t.Fatalf("observe said nothing about a role no service can assume: %v — the five "+
			"roles in the field stood for days and the tool never mentioned them (D751)", diags)
	}
}

// D776, from the field. `trust_service` writes a BARE service principal and nothing else.
// It read as one of two equivalent spellings, and the reporter measured their own six
// roles: EVERY one carried a condition (aws:SourceAccount, one with ArnLike on the VPC).
// Declaring them with trust_service would have recorded trust WEAKER than the trust that
// stands — and with no `trust.principals` attribute to compare against, the divergence
// would surface only at the next re-create, as a silent weakening.
//
// They found it by checking reality instead of trusting our advice. The advice is the
// defect: a refusal that routes at the operand which would quietly downgrade you.
func TestTheTrustOperandsAreNotTwoSpellingsOfTheSameThing(t *testing.T) {
	_, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(), nil, 1)
	if err == nil {
		t.Fatal("a candidate with no trust operand must refuse (D751)")
	}
	msg := err.Error()
	for _, want := range []string{"NO condition", "assume_role_policy", "WEAKER"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must say %q — it routes the reader at the operand to use, "+
				"and for a conditioned role trust_service is the WRONG one: %s", want, msg)
		}
	}

	// The control: the shortcut still works for what it is for.
	if _, err := BuildIAMRole("000000000000", "prod", "runner", iamRoleAttrs(),
		map[string]any{"trust_service": "lambda.amazonaws.com"}, 1); err != nil {
		t.Fatalf("an unconditioned service role is exactly what trust_service is for: %v", err)
	}
}
