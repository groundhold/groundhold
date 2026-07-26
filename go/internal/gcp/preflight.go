// Permission preflight (D75): the live half of the fail-fast permission
// guard. The deterministic permission TABLE lives in provider.PermissionsFor;
// this is only the network check — Cloud SQL has no per-resource IAM surface,
// so the mechanism is cloudresourcemanager projects.testIamPermissions.
//
// A pass is EVIDENCE, not proof: testIamPermissions answers for the project
// at that moment, for the checked permissions, over the same credentials —
// it cannot see IAM deny policies, conditional bindings evaluated at mutation
// time, propagation lag, org policy, VPC-SC perimeters, OAuth-scope limits,
// or Shared-VPC host-project permissions. Mid-apply permission failure stays
// possible; write-ahead receipts remain the recovery story.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

const crmBaseURL = "https://cloudresourcemanager.googleapis.com/v1"

func (d *Driver) crmBase() string {
	if d.CRMBaseURL != "" {
		return d.CRMBaseURL
	}
	return crmBaseURL
}

// crmAttests reports whether cloudresourcemanager projects.testIamPermissions
// is known to EVALUATE this permission at the project level — i.e. whether its
// omission from the response is an authoritative "denied" or merely silence.
//
// The CRM project surface has an allowlist. Proven live (D78, example-project,
// an Owner identity): it returned run.* and storage.buckets.create/delete/list
// but SILENTLY OMITTED storage.buckets.get/getIamPolicy/setIamPolicy/update the
// same identity demonstrably held (resource-level testIamPermissions + a real
// buckets.get 200 confirmed them). So a project-level omission of a resource-
// scoped storage permission is NOT a denial. We whitelist only the prefixes we
// have positive evidence the project surface evaluates; everything else is
// unattested (the safe default — a wrong "unattested" costs one lost fast-fail,
// recoverable via the real apply + write-ahead receipts; a wrong "denied" makes
// groundhold lie to an authorized user). A drift canary watches the dangerous
// direction of each row (see docs/DESIGN.md D78).
func crmAttests(permission string) bool {
	// resourcemanager.* is the CRM surface's OWN domain — definitively project-
	// evaluated. cloudsql./run. verified project-attested live (D78).
	for _, prefix := range []string{"cloudsql.", "run.", "resourcemanager."} {
		if strings.HasPrefix(permission, prefix) {
			return true
		}
	}
	return false
}

// CheckPermissions implements provider.Preflighter. A non-nil error means the
// check itself could not run (CRM API disabled, token/scope, connectivity) —
// the executor maps it to preflight-inconclusive. Of the permissions the CRM
// response did not return, only the CRM-ATTESTED ones are `denied` (a
// trustworthy negative); the rest are `unattested` (an omission the surface
// cannot vouch for — never a denial). See crmAttests and D78.
func (d *Driver) CheckPermissions(project string, permissions []string) (denied, unattested []string, err error) {
	if project == "" {
		return nil, nil, fmt.Errorf("no project pinned to preflight against")
	}
	if len(permissions) == 0 {
		return nil, nil, nil
	}
	url := d.crmBase() + "/projects/" + project + ":testIamPermissions"
	status, body, cerr := d.call("POST", url,
		map[string]any{"permissions": permissions})
	if cerr != nil {
		return nil, nil, fmt.Errorf("testIamPermissions: %v", cerr)
	}
	if status != http.StatusOK {
		// SERVICE_DISABLED (Cloud Resource Manager API off — the single most
		// likely operational surprise), 401/403 (scope or credentials), 429,
		// 5xx: the check did not run. Fail closed, distinctly from a denial.
		return nil, nil, fmt.Errorf(
			"testIamPermissions HTTP %d (enable the Cloud Resource Manager "+
				"API on %s and check the token's scope): %s",
			status, project, mutDetail(body))
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("testIamPermissions: bad response: %v", err)
	}
	granted := map[string]bool{}
	for _, p := range out.Permissions {
		granted[p] = true
	}
	for _, p := range permissions {
		if granted[p] {
			continue
		}
		if crmAttests(p) {
			denied = append(denied, p)
		} else {
			unattested = append(unattested, p)
		}
	}
	return denied, unattested, nil
}

// CheckResourcePermissions implements provider.ResourcePreflighter (D80): the
// AUTHORITATIVE check for an existing resource. testIamPermissions on the
// resource itself evaluates the permission at that scope, so its negative is a
// real denial (unlike the project surface's silence). Method drift is real
// here too (verified live): GCS uses GET /iam/testPermissions, Cloud Run v2
// uses POST :testIamPermissions. Cloud SQL has no such surface -> the caller
// falls back to the project check (its cloudsql.* are CRM-attested anyway).
func (d *Driver) CheckResourcePermissions(service, providerID string, permissions []string) ([]string, error) {
	if len(permissions) == 0 {
		return nil, nil
	}
	var granted map[string]bool
	switch service {
	case "cloudsql":
		return nil, provider.ErrNoResourceSurface
	case "gcs":
		project, bucket, err := splitGcsProviderID(providerID)
		if err != nil {
			return nil, err
		}
		if err := d.sameProject(project); err != nil {
			return nil, err
		}
		q := ""
		for _, p := range permissions {
			q += "&permissions=" + url.QueryEscape(p)
		}
		status, body, cerr := d.call("GET", d.bucketURL(bucket)+"/iam/testPermissions?"+q[1:], nil)
		if cerr != nil {
			return nil, fmt.Errorf("bucket testIamPermissions: %v", cerr)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("bucket testIamPermissions HTTP %d: %s", status, mutDetail(body))
		}
		var perr error
		if granted, perr = grantedSet(body); perr != nil {
			return nil, perr // a malformed 200 is inconclusive, NOT all-denied (D78)
		}
	case "cloudrun":
		project, region, name, err := splitRunProviderID(providerID)
		if err != nil {
			return nil, err
		}
		if err := d.sameProject(project); err != nil {
			return nil, err
		}
		status, body, cerr := d.call("POST",
			d.runServiceURL(project, region, name)+":testIamPermissions",
			map[string]any{"permissions": permissions})
		if cerr != nil {
			return nil, fmt.Errorf("service testIamPermissions: %v", cerr)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("service testIamPermissions HTTP %d: %s", status, mutDetail(body))
		}
		var perr error
		if granted, perr = grantedSet(body); perr != nil {
			return nil, perr // a malformed 200 is inconclusive, NOT all-denied (D78)
		}
	case "pubsub-topic", "pubsub-queue":
		// D94. Pub/Sub topics have a resource testIamPermissions surface
		// (POST :testIamPermissions, like Cloud Run) whose negative IS
		// authoritative — unlike the project surface's silence on pubsub.*.
		project, name, err := splitPubSubProviderID(providerID)
		if err != nil {
			return nil, err
		}
		if err := d.sameProject(project); err != nil {
			return nil, err
		}
		status, body, cerr := d.call("POST",
			d.topicURL(project, name)+":testIamPermissions",
			map[string]any{"permissions": permissions})
		if cerr != nil {
			return nil, fmt.Errorf("topic testIamPermissions: %v", cerr)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("topic testIamPermissions HTTP %d: %s", status, mutDetail(body))
		}
		var perr error
		if granted, perr = grantedSet(body); perr != nil {
			return nil, perr // a malformed 200 is inconclusive, NOT all-denied (D78)
		}
	default:
		return nil, provider.ErrNoResourceSurface
	}
	var denied []string
	for _, p := range permissions {
		if !granted[p] {
			denied = append(denied, p) // AUTHORITATIVE: the surface evaluated it
		}
	}
	return denied, nil
}

// grantedSet parses a testIamPermissions response. An unparseable 200 is an
// ERROR, never an empty grant set — otherwise a malformed body would turn every
// requested permission into an authoritative denial, resurrecting the D78 lie.
func grantedSet(body []byte) (map[string]bool, error) {
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("testIamPermissions: unparseable response")
	}
	g := map[string]bool{}
	for _, p := range out.Permissions {
		g[p] = true
	}
	return g, nil
}
