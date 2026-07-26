// Permission preflight (D75), the AWS half. The deterministic permission TABLE
// lives in provider.PermissionsFor ("aws" case); this is only the LIVE check, via
// IAM iam:SimulatePrincipalPolicy — AWS's policy simulator, which (unlike GCP's
// testIamPermissions) actually EVALUATES the acting principal's identity policies
// and permission boundary.
//
// A pass is EVIDENCE, not proof: the simulator cannot see resource-based policy
// conditions we do not feed it, session policies, tag/context conditions evaluated
// at mutation time, or propagation lag. Mid-apply denial stays possible; the
// write-ahead receipts remain the recovery story.
//
// Honesty (D78 applied to AWS). An EXPLICIT deny is always authoritative (denied).
// An IMPLICIT deny is authoritative ONLY when the simulation ran in the RESOURCE's
// context — CheckResourcePermissions builds the resource ARN, so a missing grant
// there is a real denial. Against "*" (the account-level CheckPermissions, and any
// create whose resource does not yet exist) an implicit deny may merely reflect a
// grant scoped to a specific ARN, so it is UNATTESTED — never a denial. groundhold
// must not refuse an authorized user.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// compile-time proof the AWS driver satisfies both preflight interfaces.
var (
	_ provider.Preflighter         = (*Driver)(nil)
	_ provider.ResourcePreflighter = (*Driver)(nil)
)

type simEvalResult struct {
	EvalActionName string `xml:"EvalActionName"`
	EvalDecision   string `xml:"EvalDecision"` // allowed | explicitDeny | implicitDeny
}

// simulate runs iam:SimulatePrincipalPolicy for the acting principal over actions,
// in the context of resourceArns (pass {"*"} for the account-level check). Returns
// the decision per action. A non-nil error means the simulation itself could not
// run (no simulatable principal, the simulate permission denied, transport/HTTP) —
// the executor maps that to preflight-inconclusive, never to a denial.
func (d *Driver) simulate(actions, resourceArns []string) (map[string]string, error) {
	_, arn, err := d.CallerIdentity()
	if err != nil {
		return nil, fmt.Errorf("caller identity: %w", err)
	}
	src, ok := simulatablePrincipal(arn)
	if !ok {
		return nil, fmt.Errorf("acting identity %q is not a simulatable IAM principal "+
			"(SimulatePrincipalPolicy needs a user or role ARN)", arn)
	}
	form := map[string]string{
		"Action": "SimulatePrincipalPolicy", "Version": iamVersion,
		"PolicySourceArn": src,
	}
	for i, a := range actions {
		form[fmt.Sprintf("ActionNames.member.%d", i+1)] = a
	}
	for i, r := range resourceArns {
		form[fmt.Sprintf("ResourceArns.member.%d", i+1)] = r
	}
	st, resp, cerr := d.iamPost(encodeForm(form))
	if cerr != nil {
		return nil, fmt.Errorf("SimulatePrincipalPolicy: %w", cerr)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("SimulatePrincipalPolicy HTTP %d "+
			"(the acting identity needs iam:SimulatePrincipalPolicy): %s", st, mutDetail(resp))
	}
	var out struct {
		Results []simEvalResult `xml:"SimulatePrincipalPolicyResult>EvaluationResults>member"`
	}
	if err := xml.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("SimulatePrincipalPolicy: bad response: %w", err)
	}
	dec := make(map[string]string, len(out.Results))
	for _, r := range out.Results {
		dec[r.EvalActionName] = r.EvalDecision
	}
	return dec, nil
}

// simulatablePrincipal normalizes the caller ARN to a form SimulatePrincipalPolicy
// accepts. An assumed-role SESSION arn is not accepted; its underlying role arn is.
// An IAM user/role arn is used as-is. Root, federated and SSO principals (and any
// role that carries an IAM path the session arn cannot reveal) are not simulatable
// here → ok=false, i.e. inconclusive, never a false denial.
func simulatablePrincipal(arn string) (string, bool) {
	if strings.Contains(arn, ":iam::") &&
		(strings.Contains(arn, ":user/") || strings.Contains(arn, ":role/")) {
		return arn, true
	}
	// arn:aws:sts::<acct>:assumed-role/<RoleName>/<session> → arn:aws:iam::<acct>:role/<RoleName>
	if strings.Contains(arn, ":sts::") && strings.Contains(arn, ":assumed-role/") {
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) < 6 {
			return "", false
		}
		acct := parts[4]
		seg := strings.SplitN(parts[5], "/", 3)
		if len(seg) < 2 || seg[0] != "assumed-role" {
			return "", false
		}
		return "arn:aws:iam::" + acct + ":role/" + seg[1], true
	}
	return "", false
}

// CheckPermissions implements provider.Preflighter — the account-level check, run
// against resource "*". allowed → granted; explicitDeny → denied (authoritative);
// implicitDeny (or an action the simulator did not return) → unattested, since a
// "*" implicit deny cannot distinguish "no grant" from "grant scoped to a specific
// ARN we did not simulate".
func (d *Driver) CheckPermissions(account string, permissions []string) (denied, unattested []string, err error) {
	if len(permissions) == 0 {
		return nil, nil, nil
	}
	dec, err := d.simulate(permissions, []string{"*"})
	if err != nil {
		return nil, nil, err
	}
	for _, p := range permissions {
		switch dec[p] {
		case "allowed":
			// granted
		case "explicitDeny":
			denied = append(denied, p)
		default: // implicitDeny or omitted — not authoritative against "*"
			unattested = append(unattested, p)
		}
	}
	sort.Strings(denied)
	sort.Strings(unattested)
	return denied, unattested, nil
}

// CheckResourcePermissions implements provider.ResourcePreflighter — the
// AUTHORITATIVE check for an EXISTING resource. We build the resource ARN from the
// providerID and simulate in that context, so an implicit deny IS a real denial
// (the grant, if any, would have matched the ARN). Services whose ARN cannot be
// reconstructed exactly from the providerID return ErrNoResourceSurface so the
// executor falls back to the account "*" check (where their implicit denies are
// unattested — safe). Any simulation error is inconclusive, never a denial.
func (d *Driver) CheckResourcePermissions(service, providerID string, permissions []string) ([]string, error) {
	if len(permissions) == 0 {
		return nil, nil
	}
	account, err := d.resolveAccount()
	if err != nil {
		return nil, err
	}
	arn, ok := awsResourceARN(service, providerID, account)
	if !ok {
		return nil, provider.ErrNoResourceSurface
	}
	dec, err := d.simulate(permissions, []string{arn})
	if err != nil {
		return nil, err
	}
	var denied []string
	for _, p := range permissions {
		if dec[p] != "allowed" { // in-context: explicit AND implicit deny are authoritative
			denied = append(denied, p)
		}
	}
	sort.Strings(denied)
	return denied, nil
}

// awsResourceARN reconstructs a resource ARN from a providerID for services whose
// ARN is a pure function of the providerID (no server-assigned random suffix).
// Conservative on purpose: a WRONG ARN would make an implicit deny falsely
// authoritative, so a service is mapped only when its ARN is exactly derivable;
// everything else returns ok=false → the account-level "*" fallback (unattested,
// never a false denial). More services can join as their ARN shape is confirmed.
func awsResourceARN(service, providerID, account string) (string, bool) {
	switch service {
	case "rds":
		region, id, err := splitRDSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:rds:" + region + ":" + account + ":db:" + id, true
	case "aurora":
		region, id, err := splitAuroraProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:rds:" + region + ":" + account + ":cluster:" + id, true
	case "dynamodb":
		region, acct, table, err := splitDynamoProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:dynamodb:" + region + ":" + acct + ":table/" + table, true
	case "sqs":
		region, acct, name, err := splitSQSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:sqs:" + region + ":" + acct + ":" + name, true
	case "sns":
		region, acct, name, err := splitSNSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:sns:" + region + ":" + acct + ":" + name, true
	case "kms":
		region, keyID, err := splitAWSKMSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:kms:" + region + ":" + account + ":key/" + keyID, true
	}
	return "", false
}
