package aws

import (
	"strings"
	"testing"
)

// D1225 established that a withheld `access.privileged` must not be explained by a
// cause nothing measured — the diagnostic called every unclassifiable policy "custom"
// without asking, and in a real account 63 of 72 were AWS-MANAGED.
//
// D1231 SUPERSEDES the mechanism those gates pinned: observe no longer explains why
// the curated NAME set failed, because it now reads the DOCUMENT instead. The value
// survives unchanged and is what these gates hold now:
//
//   - a limit of groundhold's own knowledge is attributed to groundhold, never to the
//     estate ("your policy is custom" for what is really our curated list's edge);
//   - withholding never reads as a least-privilege finding;
//   - and the withholding still says what stopped it.
//
// The population that motivated D1225 is now SERVED rather than explained: an
// AWS-managed policy outside the curated set gets its document read like any other.

func awsPrivilegeDiag(t *testing.T, policyArn string) (obs map[string]any, diag string) {
	t.Helper()
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	res := d.createRolePolicyAttachment("grant", "prod",
		map[string]any{"grant.role": policyArn, "grant.principal": "reader",
			"access.scope": "account", "service.managed": true}, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create %s: %+v", policyArn, res)
	}
	o, diags, err := d.observeRolePolicyAttachment("grant", res.ProviderID)
	if err != nil {
		t.Fatalf("observe %s: %v", policyArn, err)
	}
	obs = map[string]any{}
	for _, x := range o {
		obs[x.Path] = x.Value
	}
	for _, dg := range diags {
		if strings.HasPrefix(dg, "access.privileged") {
			return obs, dg
		}
	}
	return obs, ""
}

// The surviving D1225 value: our gap is ours. A withheld privilege must never be
// explained by asserting something about the estate that nothing measured.
func TestWithheldPrivilegeBlamesGroundholdNotTheEstate(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser", // AWS-managed, outside the curated set
		"arn:aws:iam::123456789012:policy/BespokeOperator",            // customer-managed
	} {
		obs, diag := awsPrivilegeDiag(t, arn)
		if _, present := obs["access.privileged"]; present {
			t.Fatalf("%s: the fixture document grants no escalation action, so privilege "+
				"must be withheld, got %v", arn, obs["access.privileged"])
		}
		if diag == "" {
			t.Fatalf("%s: withholding must be diagnosed", arn)
		}
		if !strings.Contains(diag, "groundhold's escalation set") {
			t.Fatalf("%s: the diagnostic must attribute the limit to groundhold's own "+
				"curated set: %q", arn, diag)
		}
		// The D1225 defect verbatim: explaining OUR gap by calling the estate's policy
		// custom. It was false for 63 of 72 grants in a real account.
		if strings.Contains(strings.ToLower(diag), "is a custom") ||
			strings.Contains(strings.ToLower(diag), "custom policy's privilege") {
			t.Fatalf("%s: a limit of our curated set must not be reported as a property "+
				"of the estate's policy: %q", arn, diag)
		}
	}
}

// Withholding must not read as a finding of least privilege. This is the sentence a
// reader acts on, and "no match" is not "no privilege".
func TestWithheldPrivilegeDoesNotReadAsLeastPrivilege(t *testing.T) {
	_, diag := awsPrivilegeDiag(t, "arn:aws:iam::123456789012:policy/BespokeOperator")
	if !strings.Contains(diag, "NOT proof of least privilege") {
		t.Fatalf("the diagnostic must say plainly that no match is not proof of least "+
			"privilege, or a reader takes silence for safety: %q", diag)
	}
}

// The ARN discriminator D1225 built is still load-bearing — D1228 uses it to decide
// whether a NAME may be read as evidence at all — so it keeps its own gate.
func TestAWSPolicyIsAWSManagedAcrossPartitions(t *testing.T) {
	for arn, want := range map[string]bool{
		"arn:aws:iam::aws:policy/AdministratorAccess":        true,
		"arn:aws-us-gov:iam::aws:policy/AdministratorAccess": true,
		"arn:aws-cn:iam::aws:policy/AdministratorAccess":     true,
		"arn:aws:iam::123456789012:policy/Bespoke":           false,
		"arn:aws-us-gov:iam::123456789012:policy/Bespoke":    false,
	} {
		if got := awsPolicyIsAWSManaged(arn); got != want {
			t.Fatalf("awsPolicyIsAWSManaged(%q) = %v, want %v", arn, got, want)
		}
	}
}
