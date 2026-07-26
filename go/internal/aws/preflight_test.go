package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// preflightFake serves STS GetCallerIdentity and IAM SimulatePrincipalPolicy from one
// endpoint (both drivers point their *BaseURL at it). decisions maps an action name to
// the EvalDecision the simulator should return; callerArn is what GetCallerIdentity
// echoes. It records the last ResourceArns.member.1 so a test can assert the resource
// context was passed.
type preflightFake struct {
	callerArn    string
	decisions    map[string]string
	lastResource string
	simHTTP      int // non-200 to force an inconclusive simulate
}

func (f *preflightFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		switch form.Get("Action") {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
				`<Account>000000000000</Account><Arn>` + f.callerArn + `</Arn>` +
				`</GetCallerIdentityResult></GetCallerIdentityResponse>`))
		case "SimulatePrincipalPolicy":
			if f.simHTTP != 0 {
				http.Error(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`, f.simHTTP)
				return
			}
			f.lastResource = form.Get("ResourceArns.member.1")
			var members string
			for i := 1; ; i++ {
				a := form.Get("ActionNames.member." + strconv.Itoa(i))
				if a == "" {
					break
				}
				dec := f.decisions[a]
				if dec == "" {
					dec = "implicitDeny"
				}
				members += `<member><EvalActionName>` + a + `</EvalActionName>` +
					`<EvalDecision>` + dec + `</EvalDecision></member>`
			}
			_, _ = w.Write([]byte(`<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>` +
				`<EvaluationResults>` + members + `</EvaluationResults>` +
				`</SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`))
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
}

func preflightDriver(t *testing.T, f *preflightFake) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := f.server(t)
	t.Cleanup(srv.Close)
	d := NewDriver("eu-central-1")
	d.STSBaseURL = srv.URL
	d.IAMBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

// TestCheckPermissions_AccountLevel: against "*", explicitDeny is authoritative
// (denied), implicitDeny is unattested (a grant could be ARN-scoped), allowed passes.
func TestCheckPermissions_AccountLevel(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{
			"rds:CreateDBInstance": "allowed",
			"rds:DeleteDBInstance": "explicitDeny",
			"rds:ModifyDBInstance": "implicitDeny",
		},
	}
	d := preflightDriver(t, f)
	denied, unatt, err := d.CheckPermissions("000000000000",
		[]string{"rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:ModifyDBInstance"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Join(denied, ",") != "rds:DeleteDBInstance" {
		t.Fatalf("denied = %v, want only the explicitDeny", denied)
	}
	if strings.Join(unatt, ",") != "rds:ModifyDBInstance" {
		t.Fatalf("unattested = %v, want the implicitDeny (not a denial against *)", unatt)
	}
	if f.lastResource != "*" {
		t.Fatalf("account-level check must simulate against '*', got %q", f.lastResource)
	}
}

// TestCheckResourcePermissions_Authoritative: in the resource's ARN context, an
// implicit deny IS a real denial. And the ARN reconstructed from the pid is passed.
func TestCheckResourcePermissions_Authoritative(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{"rds:ModifyDBInstance": "implicitDeny"},
	}
	d := preflightDriver(t, f)
	pid := "rds:eu-central-1:orders-db"
	denied, err := d.CheckResourcePermissions("rds", pid, []string{"rds:ModifyDBInstance"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Join(denied, ",") != "rds:ModifyDBInstance" {
		t.Fatalf("in resource context an implicit deny is authoritative; denied = %v", denied)
	}
	if f.lastResource != "arn:aws:rds:eu-central-1:000000000000:db:orders-db" {
		t.Fatalf("resource ARN not passed to the simulator, got %q", f.lastResource)
	}
}

// TestCheckResourcePermissions_NoSurface: a service without an exact ARN mapping
// falls back (ErrNoResourceSurface) so the caller uses the account "*" check.
func TestCheckResourcePermissions_NoSurface(t *testing.T) {
	f := &preflightFake{callerArn: "arn:aws:iam::000000000000:role/deployer"}
	d := preflightDriver(t, f)
	_, err := d.CheckResourcePermissions("secretsmanager", "asm:eu-central-1:pw", []string{"secretsmanager:GetSecretValue"})
	if err != provider.ErrNoResourceSurface {
		t.Fatalf("unmapped service must return ErrNoResourceSurface, got %v", err)
	}
}

// TestSimulate_InconclusiveNotDenied: a failed simulation is an error (inconclusive),
// never a fabricated denial.
func TestSimulate_InconclusiveNotDenied(t *testing.T) {
	f := &preflightFake{callerArn: "arn:aws:iam::000000000000:role/deployer", simHTTP: http.StatusForbidden}
	d := preflightDriver(t, f)
	if _, _, err := d.CheckPermissions("000000000000", []string{"rds:CreateDBInstance"}); err == nil {
		t.Fatal("a simulate the caller cannot run must be an error (inconclusive), not a silent pass/denial")
	}
}

// TestSimulatablePrincipal normalizes an assumed-role session ARN to its role ARN and
// rejects non-simulatable principals (root/federated) as not-ok (inconclusive).
func TestSimulatablePrincipal(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"arn:aws:iam::000000000000:role/deployer", "arn:aws:iam::000000000000:role/deployer", true},
		{"arn:aws:iam::000000000000:user/ci", "arn:aws:iam::000000000000:user/ci", true},
		{"arn:aws:sts::000000000000:assumed-role/deployer/session-123", "arn:aws:iam::000000000000:role/deployer", true},
		{"arn:aws:iam::000000000000:root", "", false},
		{"arn:aws:sts::000000000000:federated-user/bob", "", false},
	}
	for _, c := range cases {
		got, ok := simulatablePrincipal(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("simulatablePrincipal(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
