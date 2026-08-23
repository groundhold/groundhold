package aws

import "testing"

// D1228. `access.privileged` is a security-floored attribute — it is the
// least-privilege claim an auditor reads. The grant driver derived it from a
// SUBSTRING OF THE POLICY NAME, and applied that to customer-managed policies whose
// names their own authors chose. `CompanyReadOnlyBaseline` therefore measured
// privileged=false while its document may grant `"Action": "*"`.
//
// The sibling capability already knew better: capability.authorization.role derives
// privilege from the ACTION VERBS, and D797 fixed an under-report there while calling
// it "the most dangerous direction this tool has". The same attribute was held to two
// standards of evidence, and the weaker one governed exactly where the name is
// worthless.
//
// The gate is a property, not a word list: for any ARN a customer could mint, the
// classification must be UNKNOWN regardless of what the name suggests.

func TestCustomerNamedPolicyIsNeverClassifiedFromItsName(t *testing.T) {
	// Names deliberately chosen to hit every branch of the heuristic. Each is a
	// policy an account can create today, naming it whatever it likes.
	for _, arn := range []string{
		"arn:aws:iam::123456789012:policy/CompanyReadOnlyBaseline",
		"arn:aws:iam::123456789012:policy/TeamReadOnly",
		"arn:aws:iam::123456789012:policy/AdministratorAccess",
		"arn:aws:iam::123456789012:policy/BillingFullAccess",
		"arn:aws:iam::123456789012:policy/PowerUserAccess",
		"arn:aws-us-gov:iam::123456789012:policy/GovReadOnly",
	} {
		priv, known := classifyAWSPolicy(arn)
		if known {
			t.Fatalf("%s is CUSTOMER-managed — its name was chosen by its author and says "+
				"nothing about the document, so privilege must be unknown, got privileged=%v", arn, priv)
		}
	}
}

// The other direction, so the fix is not "classify nothing": AWS chose these names,
// so the heuristic still applies to them.
func TestAWSManagedPolicyIsStillClassifiedFromItsName(t *testing.T) {
	for arn, wantPriv := range map[string]bool{
		"arn:aws:iam::aws:policy/AdministratorAccess":        true,
		"arn:aws:iam::aws:policy/IAMFullAccess":              true,
		"arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess":    false,
		"arn:aws-us-gov:iam::aws:policy/AdministratorAccess": true,
	} {
		priv, known := classifyAWSPolicy(arn)
		if !known {
			t.Fatalf("%s is AWS-managed and matches the curated heuristic — it must stay classified", arn)
		}
		if priv != wantPriv {
			t.Fatalf("%s: privileged=%v, want %v", arn, priv, wantPriv)
		}
	}
}

// End to end through observe: a customer policy named like a read-only one must not
// emit access.privileged at all. Withholding makes a hard constraint unknown, which
// blocks — the honest outcome when the evidence is a name its author picked.
func TestObserveWithholdsPrivilegeForACustomerNamedReadOnlyPolicy(t *testing.T) {
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	const arn = "arn:aws:iam::123456789012:policy/CompanyReadOnlyBaseline"
	res := d.createRolePolicyAttachment("grant", "prod",
		map[string]any{"grant.role": arn, "grant.principal": "reader",
			"access.scope": "account", "service.managed": true}, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, diags, err := d.observeRolePolicyAttachment("grant", res.ProviderID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "access.privileged" {
			t.Fatalf("a customer-named policy must not yield a measured least-privilege "+
				"claim, got %v", o.Value)
		}
	}
	if len(diags) == 0 {
		t.Fatalf("withholding access.privileged must be diagnosed")
	}
}

// The create-time contradiction check must not become a licence either: it refuses a
// declared privilege that contradicts a KNOWN classification, and an unknown one
// simply cannot contradict. This pins that a declared claim on a customer policy is
// accepted (not silently "verified"), so the refusal below stays meaningful.
func TestDeclaredPrivilegeStillRefusedWhenItContradictsAnAWSManagedPolicy(t *testing.T) {
	_, err := BuildRolePolicyAttachment("prod", "grant", map[string]any{
		"grant.role":        "arn:aws:iam::aws:policy/AdministratorAccess",
		"grant.principal":   "reader",
		"access.scope":      "account",
		"access.privileged": false,
		"service.managed":   true,
	}, nil, 1)
	if err == nil {
		t.Fatalf("declaring least privilege over AdministratorAccess must be refused")
	}
}
