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
	simHTTP      int    // non-200 to force an inconclusive simulate
	simErrCode   string // the <Error><Code> the non-200 carries (default AccessDenied)

	// D720: the request CONTEXT half. lastContext records the condition keys the
	// driver sent; regionGuard makes the fake behave like an account whose SCP is
	// written in aws:RequestedRegion — it denies, and reports the key it needed,
	// exactly as AWS does when the simulation omits one.
	lastContext map[string]string
	regionGuard bool

	// D750: the guardrail as the field actually writes it — `Deny` with
	// `StringNotEquals: {aws:RequestedRegion: <allowed>}`. It needs no key to decide:
	// an ABSENT aws:RequestedRegion does not equal the allowed region, so the condition
	// is satisfied and the deny fires with MissingContextValues EMPTY. The friendly
	// guardrail above (deny AND name the key) was the only shape modelled, so the
	// safety net built on MissingContextValues looked sound against a fixture that
	// always fed it.
	negatedRegionGuard bool

	// D750: a guardrail keyed on something we cannot enumerate at all (org id, a tag,
	// a source ip). It denies AND names the key, whatever region the request carries —
	// which is the ONLY way left to exercise D720's MissingContextValues half now that
	// a knowingly contextless simulation is untrustworthy by itself.
	orgGuard bool

	// contextByAction records, per action, the context that action was simulated
	// with — the batches are separate calls, so one lastContext cannot show it.
	contextByAction map[string]map[string]string
	pageSize        int // >0 to paginate the evaluation results
	pages           int
	omit            map[string]bool // actions the simulator answers nothing about
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
				code := f.simErrCode
				if code == "" {
					code = "AccessDenied"
				}
				http.Error(w, `<ErrorResponse><Error><Code>`+code+`</Code><Message>x</Message></Error></ErrorResponse>`, f.simHTTP)
				return
			}
			f.lastResource = form.Get("ResourceArns.member.1")
			f.lastContext = map[string]string{}
			for i := 1; ; i++ {
				k := form.Get("ContextEntries.member." + strconv.Itoa(i) + ".ContextKeyName")
				if k == "" {
					break
				}
				f.lastContext[k] = form.Get("ContextEntries.member." + strconv.Itoa(i) +
					".ContextKeyValues.member.1")
			}
			f.pages++
			var acts []string
			for i := 1; ; i++ {
				a := form.Get("ActionNames.member." + strconv.Itoa(i))
				if a == "" {
					break
				}
				if f.contextByAction != nil {
					cp := map[string]string{}
					for k, v := range f.lastContext {
						cp[k] = v
					}
					f.contextByAction[a] = cp
				}
				acts = append(acts, a)
			}
			// Pagination: hand back one page and a marker naming the offset.
			truncated, marker := false, ""
			if f.pageSize > 0 {
				off := 0
				if m := form.Get("Marker"); m != "" {
					off, _ = strconv.Atoi(m)
				}
				end := off + f.pageSize
				if end < len(acts) {
					truncated, marker = true, strconv.Itoa(end)
				} else {
					end = len(acts)
				}
				if off > len(acts) {
					off = len(acts)
				}
				acts = acts[off:end]
			}
			var members string
			for _, a := range acts {
				if f.omit[a] {
					continue // AWS returned no EvaluationResult for this action
				}
				dec := f.decisions[a]
				if dec == "" {
					dec = "implicitDeny"
				}
				missing := ""
				// An account with a region-conditioned guardrail: with no region in
				// the request the policy cannot be evaluated, so AWS denies AND names
				// the key it wanted. With the region supplied, the same action is
				// allowed — which is what the field measured.
				if f.orgGuard {
					dec = "explicitDeny"
					missing = `<MissingContextValues><member>aws:PrincipalOrgID` +
						`</member></MissingContextValues>`
				}
				if f.negatedRegionGuard {
					if f.lastContext["aws:RequestedRegion"] == "" {
						dec = "explicitDeny" // and nothing is reported as missing
					} else {
						dec = "allowed"
					}
				}
				if f.regionGuard {
					if f.lastContext["aws:RequestedRegion"] == "" {
						dec = "explicitDeny"
						missing = `<MissingContextValues><member>aws:RequestedRegion` +
							`</member></MissingContextValues>`
					} else {
						dec = "allowed"
					}
				}
				members += `<member><EvalActionName>` + a + `</EvalActionName>` +
					`<EvalDecision>` + dec + `</EvalDecision>` + missing + `</member>`
			}
			trunc := ""
			if truncated {
				trunc = `<IsTruncated>true</IsTruncated><Marker>` + marker + `</Marker>`
			}
			_, _ = w.Write([]byte(`<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>` +
				`<EvaluationResults>` + members + `</EvaluationResults>` + trunc +
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
	denied, _, err := d.CheckResourcePermissions("rds", pid, []string{"rds:ModifyDBInstance"})
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

// TestCheckResourcePermissions_CrossServiceNotDenied (D885): a cross-service action in
// the permission set — sts:GetCallerIdentity against an rds cluster ARN — has no grant
// scoped to THAT resource, so the simulator returns implicitDeny for a permission the
// caller in fact holds. The resource-ARN rule would read that as a real denial and refuse
// a legitimate apply (the Aurora retire this fixed). The resource's OWN service stays
// authoritative; the cross-service action falls to the account "*" check, where an
// implicitDeny is unattested, never a denial.
func TestCheckResourcePermissions_CrossServiceNotDenied(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{
			"rds:DeleteDBCluster":   "implicitDeny", // same service, in ARN context: authoritative
			"sts:GetCallerIdentity": "implicitDeny", // cross service: must NOT be authoritative here
			"tag:TagResources":      "implicitDeny", // cross service
		},
	}
	d := preflightDriver(t, f)
	pid := "aurora:eu-central-1:orders-cluster"
	denied, unattested, err := d.CheckResourcePermissions("aurora", pid,
		[]string{"rds:DeleteDBCluster", "sts:GetCallerIdentity", "tag:TagResources"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Join(denied, ",") != "rds:DeleteDBCluster" {
		t.Fatalf("only the resource's own service is authoritative in ARN context; denied = %v", denied)
	}
	got := strings.Join(unattested, ",")
	if got != "sts:GetCallerIdentity,tag:TagResources" {
		t.Fatalf("cross-service implicit denies must be unattested, not denied; unattested = %v", unattested)
	}
}

// TestCheckResourcePermissions_CrossResourceTypeNotDenied (D886): a same-SERVICE action
// that targets a DIFFERENT resource type than the ARN — rds:DeleteDBInstance (type db)
// against an aurora CLUSTER arn — has no grant that could match this ARN, so its
// implicitDeny is about the wrong resource, not the caller. It must route to the account
// check (unattested), while the action that DOES target the cluster (rds:DeleteDBCluster,
// type cluster) stays authoritative. This is the Aurora-retire block, one type deeper than
// the cross-service D885 case.
func TestCheckResourcePermissions_CrossResourceTypeNotDenied(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{
			"rds:DeleteDBCluster":  "implicitDeny", // type cluster == arn type: authoritative
			"rds:DeleteDBInstance": "implicitDeny", // type db != cluster: must NOT be authoritative
		},
	}
	d := preflightDriver(t, f)
	pid := "aurora:eu-central-1:orders-cluster"
	denied, unattested, err := d.CheckResourcePermissions("aurora", pid,
		[]string{"rds:DeleteDBCluster", "rds:DeleteDBInstance"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Join(denied, ",") != "rds:DeleteDBCluster" {
		t.Fatalf("only the ARN's own resource type is authoritative; denied = %v", denied)
	}
	if strings.Join(unattested, ",") != "rds:DeleteDBInstance" {
		t.Fatalf("a cross-resource-type implicit deny must be unattested, not denied; unattested = %v", unattested)
	}
}

// TestCheckResourcePermissions_NoSurface: a service without an exact ARN mapping
// falls back (ErrNoResourceSurface) so the caller uses the account "*" check.
func TestCheckResourcePermissions_NoSurface(t *testing.T) {
	f := &preflightFake{callerArn: "arn:aws:iam::000000000000:role/deployer"}
	d := preflightDriver(t, f)
	_, _, err := d.CheckResourcePermissions("secretsmanager", "asm:eu-central-1:pw", []string{"secretsmanager:GetSecretValue"})
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

// TestSimulate_ThrottleIsNotMissingPermission (D1002): the IAM query API answers a
// SimulatePrincipalPolicy rate limit with HTTP 400 <Code>Throttling</Code> "Rate exceeded".
// The message must ask for a RETRY, not say "the acting identity needs
// iam:SimulatePrincipalPolicy" — the identity HAS it, and that wording sends the operator
// to grant a permission they hold (ACME-036). A real denial still asks for the grant.
func TestSimulate_ThrottleIsNotMissingPermission(t *testing.T) {
	f := &preflightFake{callerArn: "arn:aws:iam::000000000000:role/deployer",
		simHTTP: http.StatusBadRequest, simErrCode: "Throttling"}
	d := preflightDriver(t, f)
	_, _, err := d.CheckPermissions("000000000000", []string{"rds:CreateDBInstance"})
	if err == nil {
		t.Fatal("a throttled simulate must be inconclusive (error), not a pass")
	}
	if strings.Contains(err.Error(), "needs iam:SimulatePrincipalPolicy") {
		t.Fatalf("a throttle must NOT read as a missing permission: %v", err)
	}
	if !strings.Contains(err.Error(), "rate-limiting") && !strings.Contains(err.Error(), "retry") {
		t.Fatalf("a throttle should ask for a retry: %v", err)
	}
	// contrast: a real 403 AccessDenied still names the missing permission.
	f2 := &preflightFake{callerArn: "arn:aws:iam::000000000000:role/deployer",
		simHTTP: http.StatusForbidden, simErrCode: "AccessDenied"}
	_, _, err2 := preflightDriver(t, f2).CheckPermissions("000000000000", []string{"rds:CreateDBInstance"})
	if err2 == nil || !strings.Contains(err2.Error(), "needs iam:SimulatePrincipalPolicy") {
		t.Fatalf("a real denial must still name the missing permission: %v", err2)
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

// D720. The field report that produced this test (a second pilot, on a live account):
// `apply` refused with provider-permission-denied over ~65 actions the caller could
// perform. The account's SCP allows only EU regions — a hard residency requirement —
// and the simulation carried no `aws:RequestedRegion`, so every region-conditioned
// statement denied. Their workaround was to DETACH the regional guardrail for the
// duration of each apply: our false statement made them turn a security control off.
func TestPreflightCarriesTheRegionARealCallWouldCarry(t *testing.T) {
	f := &preflightFake{
		callerArn:   "arn:aws:iam::000000000000:role/deployer",
		regionGuard: true,
	}
	d := preflightDriver(t, f)

	denied, unattested, err := d.CheckPermissions("000000000000",
		[]string{"ec2:CreateVpc", "ec2:CreateSubnet"})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if got := f.lastContext["aws:RequestedRegion"]; got != d.Region {
		t.Fatalf("the simulation asked about no region (context %v) — an account whose "+
			"guardrail is written in aws:RequestedRegion then denies everything, and "+
			"the tool reports permissions the caller has as missing", f.lastContext)
	}
	if len(denied) > 0 {
		t.Fatalf("actions the caller can perform reported as denied: %v", denied)
	}
	if len(unattested) > 0 {
		t.Fatalf("with the region supplied these are plainly allowed, not unattested: %v", unattested)
	}
}

// D720, the general half: AWS reports which condition keys its evaluation needed and
// the request did not carry. A verdict resting on a key we did not send is an answer
// about our question, not about the caller — so it can never block an apply. This is
// what covers the guardrails we cannot enumerate (org id, tags, source ip).
func TestADenialThatNeededContextWeDidNotSendIsNotADenial(t *testing.T) {
	// D750 STRENGTHENS this test. It used to set `d.Region = ""`, so the simulation
	// carried no context and D750's own clause (a deny from a context we CHOSE not to
	// send is untrustworthy) answered it — leaving the MissingContextValues mechanism
	// this test exists for completely uncovered. The meter said so plainly: the D720
	// mutant survived. It now uses a guardrail keyed on something no driver can
	// enumerate, WITH the region supplied, which is the case only this half can catch.
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		orgGuard:  true,
	}
	d := preflightDriver(t, f) // a real region: the simulation is fully in context

	denied, unattested, err := d.CheckPermissions("000000000000", []string{"ec2:CreateVpc"})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if len(denied) > 0 {
		t.Fatalf("an explicitDeny carrying MissingContextValues was treated as "+
			"authoritative (%v) — this is the refusal that made a pilot detach their "+
			"own regional guardrail on every deploy", denied)
	}
	if len(unattested) != 1 || unattested[0] != "ec2:CreateVpc" {
		t.Fatalf("a context-incomplete verdict must be reported as unattested, got %v", unattested)
	}
}

// D720, the resource-level twin. An in-context deny is otherwise AUTHORITATIVE and
// blocks the apply, so this is where a context-incomplete verdict does the most damage
// — and where dropping it silently would make --require-preflight report a certainty
// it does not have.
func TestResourcePreflightRoutesAContextIncompleteDenialToUnattested(t *testing.T) {
	f := &preflightFake{
		callerArn:   "arn:aws:iam::000000000000:role/deployer",
		regionGuard: true,
	}
	d := preflightDriver(t, f)
	d.Region = ""

	pid := "rds:eu-central-1:orders-db"
	denied, unattested, err := d.CheckResourcePermissions("rds", pid,
		[]string{"rds:ModifyDBInstance"})
	if err != nil {
		t.Fatalf("resource preflight: %v", err)
	}
	// The ARN names eu-central-1, so the driver CAN supply a region here even with
	// d.Region empty — the resource's own region is the region the call will use.
	if got := f.lastContext["aws:RequestedRegion"]; got != "eu-central-1" {
		t.Fatalf("the resource check ignored the region in the resource's own ARN "+
			"(context %v)", f.lastContext)
	}
	if len(denied) > 0 || len(unattested) > 0 {
		t.Fatalf("with the region taken from the ARN this action is allowed; "+
			"denied=%v unattested=%v", denied, unattested)
	}
}

// D720, found by an audit OF THE FIX: asserting a region we merely defaulted is worse
// than sending none. Route 53, CloudFront, IAM and Budgets are signed for us-east-1 and
// have no regional endpoint, so claiming eu-central-1 over `iam:*` against a guardrail
// written as "deny iam:* outside us-east-1" produces an explicitDeny with the key
// PRESENT — trustworthy, authoritative, unbypassable. That is the reported bug,
// re-created by its own fix. Omission is the safe direction: AWS reports the missing
// key and the verdict degrades to unattested.
func TestNoRegionIsClaimedForAServiceThatDoesNotRunInIt(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{"iam:CreateRole": "allowed", "ec2:CreateVpc": "allowed"},
	}
	f.contextByAction = map[string]map[string]string{}
	d := preflightDriver(t, f)

	if _, _, err := d.CheckPermissions("000000000000",
		[]string{"iam:CreateRole", "ec2:CreateVpc"}); err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if got := f.contextByAction["ec2:CreateVpc"]["aws:RequestedRegion"]; got != "eu-central-1" {
		t.Errorf("a regional action must carry the region, got %q", got)
	}
	if got, has := f.contextByAction["iam:CreateRole"]["aws:RequestedRegion"]; has {
		t.Errorf("iam:CreateRole was simulated with aws:RequestedRegion=%q — IAM has no "+
			"regional endpoint, so this asserts a region the real call will not carry, "+
			"and a guardrail written in that key then denies authoritatively", got)
	}
}

// D720: an action the simulator did not answer is not a denial. On the resource path
// anything that was not "allowed" was denied, so a TRUNCATED page — the simulator
// paginates, and this driver follows markers everywhere else — turned into a refusal
// naming permissions the caller holds.
func TestATruncatedSimulationIsFollowedNotTreatedAsDenial(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{
			"rds:ModifyDBInstance":    "allowed",
			"rds:DescribeDBInstances": "allowed",
			"rds:AddTagsToResource":   "allowed",
		},
		pageSize: 1, // force three pages
	}
	d := preflightDriver(t, f)

	denied, unattested, err := d.CheckResourcePermissions("rds", "rds:eu-central-1:orders-db",
		[]string{"rds:ModifyDBInstance", "rds:DescribeDBInstances", "rds:AddTagsToResource"})
	if err != nil {
		t.Fatalf("resource preflight: %v", err)
	}
	if len(denied) > 0 {
		t.Fatalf("permissions the caller holds reported as denied because the response "+
			"was paginated: %v", denied)
	}
	if len(unattested) > 0 {
		t.Fatalf("every action was answered allowed across the pages: %v", unattested)
	}
	if f.pages < 3 {
		t.Fatalf("the driver stopped after %d page(s) — the marker was not followed, and "+
			"the actions on later pages were never asked about", f.pages)
	}
}

// D720: the map lookup that could not tell "denied" from "never answered". On the
// resource path anything not "allowed" was denied, and a missing EvaluationResult
// reads as the zero value — so an action AWS said nothing about became an
// authoritative refusal. Absent is not a verdict.
func TestAnActionTheSimulatorNeverAnsweredIsNotDenied(t *testing.T) {
	f := &preflightFake{
		callerArn: "arn:aws:iam::000000000000:role/deployer",
		decisions: map[string]string{"rds:ModifyDBInstance": "allowed"},
		omit:      map[string]bool{"rds:AddTagsToResource": true},
	}
	d := preflightDriver(t, f)

	denied, unattested, err := d.CheckResourcePermissions("rds", "rds:eu-central-1:orders-db",
		[]string{"rds:ModifyDBInstance", "rds:AddTagsToResource"})
	if err != nil {
		t.Fatalf("resource preflight: %v", err)
	}
	if len(denied) > 0 {
		t.Fatalf("an action the simulator did not answer was reported as denied (%v) — "+
			"that refusal blocks an apply on evidence nobody produced", denied)
	}
	if len(unattested) != 1 || unattested[0] != "rds:AddTagsToResource" {
		t.Fatalf("an unanswered action must be unattested, got %v", unattested)
	}
}

// D731: the refusal an operator on a profile actually hits. "no AWS credentials in the
// environment" is true and teaches nothing, and it is false about their situation: they
// HAVE credentials, configured the way AWS recommends, in a place this narrow adapter
// does not read. A pilot created a separate MFA-less role to get past this sentence.
func TestTheCredentialRefusalNamesTheBridge(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	t.Run("with a profile set", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "acme-iac")
		err := noCredentialsError()
		for _, want := range []string{
			"AWS_PROFILE=acme-iac is set",
			"does not read ~/.aws/config",
			"aws configure export-credentials --profile acme-iac --format env",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q; it said:\n%s", want, err)
			}
		}
	})
	t.Run("with nothing set", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "")
		err := noCredentialsError()
		if !strings.Contains(err.Error(), "aws configure export-credentials") {
			t.Errorf("even with nothing set the refusal must name the bridge; it said:\n%s", err)
		}
	})
}

// D750, from the field: `apply` refused `s3:CreateBucket`, `s3:GetBucketTagging` and
// `s3:PutBucketPublicAccessBlock`, and the same role created a bucket by hand seconds
// later. Two independent faults met.
//
// The first is this one. D720 called omitting the region key "safe", because AWS would
// report it in MissingContextValues and the verdict would go unattested. That holds only
// for a policy that NEEDS the key. A guardrail written as Deny + StringNotEquals needs
// nothing — an absent key does not equal the allowed region, the deny fires, and nothing
// comes back as missing. A verdict we deliberately under-specified was then reported as
// an authoritative denial.
func TestADenyFromAContextWeChoseNotToSendIsNotADenial(t *testing.T) {
	f := &preflightFake{
		callerArn:          "arn:aws:iam::000000000000:role/deployer",
		negatedRegionGuard: true,
	}
	d := preflightDriver(t, f)

	// sts is genuinely ambiguous, so it is simulated without a region BY CHOICE —
	// which is exactly the state this test is about.
	denied, unattested, err := d.CheckPermissions("000000000000", []string{"sts:GetCallerIdentity"})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if len(denied) > 0 {
		t.Fatalf("reported %v as denied — the simulation left out the region on purpose, "+
			"so this verdict is about our question, not about the caller. The field was "+
			"told it lacked permissions it demonstrably had, and created the resource "+
			"outside apply (D750)", denied)
	}
	if len(unattested) != 1 {
		t.Fatalf("a knowingly contextless verdict must be unattested, got %v", unattested)
	}
}

// The second fault: s3 was listed among the services whose region cannot be claimed. It
// can. Every S3 call this project makes is signed against <bucket>.s3.<REGION>.amazonaws
// .com, so the driver's region IS the one the request carries — and with it supplied,
// the account's guardrail allows exactly what it allowed the operator by hand.
func TestS3IsSimulatedWithTheRegionItsCallsAreSignedIn(t *testing.T) {
	f := &preflightFake{
		callerArn:          "arn:aws:iam::000000000000:role/deployer",
		negatedRegionGuard: true,
		contextByAction:    map[string]map[string]string{},
	}
	d := preflightDriver(t, f)

	perms := []string{"s3:CreateBucket", "s3:GetBucketTagging", "s3:PutBucketPublicAccessBlock"}
	denied, unattested, err := d.CheckPermissions("000000000000", perms)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	for _, p := range perms {
		if got := f.contextByAction[p]["aws:RequestedRegion"]; got != d.Region {
			t.Errorf("%s was simulated with region %q, want %q — an S3 call is signed "+
				"regionally, so there is nothing ambiguous to withhold (D750)", p, got, d.Region)
		}
	}
	if len(denied) > 0 || len(unattested) > 0 {
		t.Fatalf("with the region supplied these are allowed; got denied=%v unattested=%v",
			denied, unattested)
	}
}
