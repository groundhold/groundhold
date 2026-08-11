package aws

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// D487: the claim path must check the account it acts on — ONCE, where the ARN is
// consumed, not per case where it is built.
//
// The first version of this gate demanded a guard in every claimARN case that binds an
// account from the providerId, and the fix satisfied it with twelve copies. That is the
// shape that produced the bug: twelve independent guards are twelve chances to add a
// thirteenth case without one, which is exactly how those cases drifted apart from
// claimLambda's. The Azure twin has always done it right — every case calls
// claimURLFor and the subscription check lives there, once.
//
// So the property is now structural: claimByARN, the single funnel every claim goes
// through, checks the account carried by the ARN it is about to tag.
func TestClaimChecksTheAccountAtTheFunnel(t *testing.T) {
	raw, err := os.ReadFile("claim_aws.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	funnel := regexp.MustCompile(`(?s)func \(d \*Driver\) claimByARN\(.*?\n\}\n`).FindString(src)
	if funnel == "" {
		t.Fatal("claimByARN not found — the gate would be vacuous (D328)")
	}
	if !strings.Contains(funnel, "d.sameAccount(arnAccount(arn))") {
		t.Error("claimByARN does not check the ARN's account against the acting one. " +
			"Claim stamps our ownership marker, so a claim that reaches the wrong " +
			"resource makes every later ownership check agree it is ours — the one write " +
			"that manufactures its own permission (D461/D487).")
	}
	// And the per-case copies must not come back: a guard duplicated per case is a
	// guard that will be forgotten on case thirteen.
	if n := strings.Count(src, "d.sameAccount(account)"); n > 0 {
		t.Errorf("%d per-case account guard(s) in claimARN — the check belongs at the "+
			"funnel (claimByARN), where it cannot be forgotten by a new case", n)
	}
}

// The funnel check must be a no-op for an ARN that carries no account (s3's
// arn:aws:s3:::bucket) and must refuse one that carries a foreign account.
func TestSameAccountOnARNShapes(t *testing.T) {
	d := &Driver{Account: "000000000000"}
	if err := d.sameAccount(arnAccount("arn:aws:s3:::pv-assets-abcd1234")); err != nil {
		t.Errorf("an account-less ARN has nothing to compare: %v", err)
	}
	if err := d.sameAccount(arnAccount("arn:aws:sqs:eu-central-1:000000000000:q")); err != nil {
		t.Errorf("our own account must pass: %v", err)
	}
	if err := d.sameAccount(arnAccount("arn:aws:sqs:eu-central-1:999999999999:q")); err == nil {
		t.Error("a foreign account in the ARN must refuse")
	}
}
