package aws

import (
	"strings"
	"testing"
)

// D1231. `access.privileged` on a grant is now derived from the policy DOCUMENT for
// every policy whose NAME does not settle it — the evidence standard the sibling
// capability (`capability.authorization.role`) has always held.
//
// The asymmetry is the design, and these gates hold it from both sides:
//
//	positive evidence      -> emit true (measured)
//	no positive evidence   -> WITHHOLD, never false
//	document unreadable    -> WITHHOLD, naming the failed call
//
// "No escalation action found" is not "least privilege". The pattern set is curated,
// not exhaustive — `ssm:SendCommand` and `lambda:UpdateFunctionCode` are escalation
// paths that match nothing in it — so concluding `false` from a miss would rebuild
// the under-report D797 called the most dangerous direction this tool has.

func withFixtureDoc(t *testing.T, doc string) {
	t.Helper()
	prev := rolePolicyFixtureDoc
	rolePolicyFixtureDoc = doc
	t.Cleanup(func() { rolePolicyFixtureDoc = prev })
}

const custArn = "arn:aws:iam::123456789012:policy/Whatever"

// Positive evidence, in each of the shapes the classifier recognises.
func TestPrivilegeIsMeasuredTrueFromTheDocument(t *testing.T) {
	for name, doc := range map[string]string{
		"a bare wildcard action": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		"a service wildcard":     `{"Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}`,
		"iam:PassRole (escalation, no wildcard)": `{"Statement":[{"Effect":"Allow",` +
			`"Action":["iam:PassRole"],"Resource":"*"}]}`,
		"sts:AssumeRole": `{"Statement":[{"Effect":"Allow","Action":["sts:AssumeRole"],"Resource":"*"}]}`,
		"privilege in the SECOND statement (D797's shape)": `{"Statement":[` +
			`{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"},` +
			`{"Effect":"Allow","Action":["iam:AttachRolePolicy"],"Resource":"*"}]}`,
	} {
		withFixtureDoc(t, doc)
		obs, _ := awsPrivilegeDiag(t, custArn)
		if obs["access.privileged"] != true {
			t.Errorf("%s: must measure privileged=true, got %v", name, obs["access.privileged"])
		}
	}
}

// `Allow` + `NotAction` is "everything EXCEPT these" — the widest grant there is.
// The sibling refuses to ENUMERATE that set, correctly; refusing to enumerate is not
// a reason to withhold the CLASSIFICATION.
func TestComplementGrantIsPrivileged(t *testing.T) {
	withFixtureDoc(t, `{"Statement":[{"Effect":"Allow","NotAction":["s3:DeleteBucket"],"Resource":"*"}]}`)
	obs, _ := awsPrivilegeDiag(t, custArn)
	if obs["access.privileged"] != true {
		t.Fatalf("an Allow/NotAction complement is the widest grant there is, got %v",
			obs["access.privileged"])
	}
}

// The withholding half. A document full of narrow reads yields NO verdict — not false.
func TestNoEscalationActionWithholdsRatherThanClaimingLeastPrivilege(t *testing.T) {
	withFixtureDoc(t, `{"Statement":[{"Effect":"Allow","Action":`+
		`["s3:GetObject","ec2:DescribeInstances","ssm:SendCommand"],"Resource":"*"}]}`)
	obs, diag := awsPrivilegeDiag(t, custArn)
	if v, present := obs["access.privileged"]; present {
		t.Fatalf("a document with no escalation match must WITHHOLD, not conclude %v — "+
			"ssm:SendCommand in this very fixture is an escalation path the set misses", v)
	}
	if !strings.Contains(diag, "NOT proof of least privilege") {
		t.Fatalf("the withholding must say why it is not a least-privilege finding: %q", diag)
	}
}

// A Deny statement grants nothing, so it is not positive evidence.
func TestDenyStatementIsNotPositiveEvidence(t *testing.T) {
	withFixtureDoc(t, `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`)
	obs, _ := awsPrivilegeDiag(t, custArn)
	if v, present := obs["access.privileged"]; present {
		t.Fatalf("a Deny grants nothing — it cannot be positive evidence of privilege, got %v", v)
	}
}

// An unreadable document withholds and NAMES the failed call, because this slice adds
// iam:GetPolicy / iam:GetPolicyVersion to what an observing identity must hold, and an
// operator cannot grant a permission whose absence is reported as silence.
func TestUnreadableDocumentWithholdsAndNamesTheCall(t *testing.T) {
	srv := rolePolicyServer(t)
	d := rolePolicyDriver(t, srv)
	res := d.createRolePolicyAttachment("grant", "prod",
		map[string]any{"grant.role": custArn, "grant.principal": "reader",
			"access.scope": "account", "service.managed": true}, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	srv.Close() // the document read now fails at the transport
	obs, diags, err := d.observeRolePolicyAttachment("grant", res.ProviderID)
	if err != nil {
		return // an errored observe is also fail-closed; nothing is claimed
	}
	for _, o := range obs {
		if o.Path == "access.privileged" {
			t.Fatalf("an unreadable document must not yield a privilege verdict, got %v", o.Value)
		}
	}
	joined := strings.Join(diags, " ")
	if !strings.Contains(joined, "GetPolicy") {
		t.Fatalf("the withholding must name the call that failed, or the operator cannot "+
			"tell which permission to grant: %v", diags)
	}
}

// The document is read ONCE per sweep however many grants share the policy: a real
// account carried 87 grants over far fewer distinct policies.
func TestPolicyDocumentIsReadOncePerSweep(t *testing.T) {
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	before := rolePolicyGetPolicyHits
	for i := 0; i < 3; i++ {
		if _, _, err := d.grantPrivilegeFromDocumentForTest(custArn); err != nil {
			t.Fatal(err)
		}
	}
	if got := rolePolicyGetPolicyHits - before; got != 1 {
		t.Fatalf("the same policy document must be fetched once per sweep, got %d fetches", got)
	}
	// ...and a FRESH driver (a new sweep) reads it again rather than serving a stale
	// document under a new --at.
	d2 := rolePolicyDriver(t, srv)
	if _, _, err := d2.grantPrivilegeFromDocumentForTest(custArn); err != nil {
		t.Fatal(err)
	}
	if got := rolePolicyGetPolicyHits - before; got != 2 {
		t.Fatalf("a new sweep must re-read the document (the --at thesis), got %d total", got)
	}
}

// D1231 sub-finding: the classifier fired on `svc == "sts"` wholesale while the
// published vocabulary mapping said "sts:AssumeRole". That drift did not matter much
// while privilege came from a curated NAME; it matters now, because the classifier
// decides a MEASURED emission over arbitrary customer documents — and a clone of
// ReadOnlyAccess or SecurityAudit (both carry sts:GetCallerIdentity) would have
// measured privileged=true. A false alarm at estate scale erodes the alarm.
func TestOnlyCredentialMintingStsActionsArePrivileged(t *testing.T) {
	for action, want := range map[string]bool{
		"sts:AssumeRole":                 true,
		"sts:AssumeRoleWithWebIdentity":  true,
		"sts:GetFederationToken":         true,
		"sts:GetSessionToken":            true,
		"sts:GetCallerIdentity":          false, // the most harmless call in AWS
		"sts:DecodeAuthorizationMessage": false,
		"sts:TagSession":                 false,
	} {
		if got := awsActionPrivileged(action); got != want {
			t.Errorf("awsActionPrivileged(%q) = %v, want %v", action, got, want)
		}
	}
	// the escalation primitives must NOT be lost to the narrowing
	for _, a := range []string{"iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
		"iam:CreatePolicyVersion", "*", "s3:*"} {
		if !awsActionPrivileged(a) {
			t.Errorf("%s must stay privileged", a)
		}
	}
}

// The concrete estate shape the narrowing protects: a read-only baseline must not
// measure privileged.
func TestAReadOnlyBaselineDocumentDoesNotMeasurePrivileged(t *testing.T) {
	withFixtureDoc(t, `{"Statement":[{"Effect":"Allow","Action":`+
		`["s3:GetObject","s3:ListBucket","ec2:DescribeInstances","iam:ListRoles",`+
		`"sts:GetCallerIdentity"],"Resource":"*"}]}`)
	obs, _ := awsPrivilegeDiag(t, custArn)
	if v, present := obs["access.privileged"]; present && v == true {
		t.Fatalf("a read-only baseline must not measure privileged=true — that is the " +
			"false alarm the sts narrowing exists to prevent")
	}
}

// The iam half of the same correction: reading IAM is reconnaissance, not the power
// to grant. The vocabulary's own DEFINITION says privilege is "the power to grant
// further access"; its mapping shorthand said "any iam:*", which over-reached the
// definition. The definition wins.
func TestOnlyIAMWritesArePrivileged(t *testing.T) {
	for action, want := range map[string]bool{
		"iam:PassRole":                 true,
		"iam:AttachRolePolicy":         true,
		"iam:PutRolePolicy":            true,
		"iam:CreatePolicyVersion":      true,
		"iam:CreateAccessKey":          true,
		"iam:UpdateAssumeRolePolicy":   true,
		"iam:GetRole":                  false,
		"iam:GetPolicyVersion":         false,
		"iam:ListRoles":                false,
		"iam:ListAttachedRolePolicies": false,
		"iam:SimulatePrincipalPolicy":  false,
	} {
		if got := awsActionPrivileged(action); got != want {
			t.Errorf("awsActionPrivileged(%q) = %v, want %v", action, got, want)
		}
	}
	// The exemption is by READ prefix, so a verb nobody has thought of yet is
	// privileged by default — the safe direction for a floored attribute.
	if !awsActionPrivileged("iam:SomeFutureWriteVerb") {
		t.Fatalf("an unrecognised iam verb must default to privileged, not to safe")
	}
}
