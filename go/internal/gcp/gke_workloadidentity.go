// GKE Workload Identity driver (D76 parity): the GCP half of
// capability.identity.podidentity — the SAME vocabulary AWS EKS Pod Identity
// fulfils (eks_podidentity.go). A Kubernetes ServiceAccount (KSA), identified by
// (namespace, serviceAccount), is bound to a Google Service Account (GSA) so pods
// running as that KSA obtain the GSA's identity WITHOUT downloadable keys. The
// mechanism is NOT a standalone resource: it is an IAM policy binding on the GSA
// granting roles/iam.workloadIdentityUser to the member
//
//	serviceAccount:<poolProject>.svc.id.goog[<namespace>/<serviceAccount>]
//
// so groundhold adds/removes exactly that {role, member} pair on the GSA's IAM policy
// (a read-modify-write, the iambinding.go pattern), never authoring a policy doc.
//
// The GSA (the target identity) is an OPERAND (implementation.gsaEmail, D26) — a
// separate capability (identity.serviceaccount). The pool project (the GKE
// cluster's project whose workload-identity pool the KSA lives in) defaults to the
// pinned project; implementation.clusterProject overrides it for cross-project WI.
// The binding is CONTENT-ADDRESSED — its identity IS (poolProject, gsaEmail,
// namespace, serviceAccount) — so there are NO ownership labels; groundhold touches
// ONLY the exact member it granted, never another KSA's access. Four-valued
// throughout (D29/D87). D53: never read a secret.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// wiRole is the fixed role a Workload Identity binding confers: it lets the member
// (a KSA acting as the GSA) impersonate the GSA. Nothing else is workload identity.
const wiRole = "roles/iam.workloadIdentityUser"

// k8sNameOK bounds a Kubernetes namespace / service-account name (RFC1123 label):
// lowercase alnum + hyphen, start/end alnum, <=63 chars. This is also a SECURITY
// boundary — the value is placed into the IAM member string and the providerId, and
// must never carry ':', '/', '[', ']' that would let a forged pid rewrite the split.
var k8sNameOK = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// gsaEmailOK bounds a Google service-account email. Strict charset (no ':', '/',
// '?', '#', '%') so the email can be interpolated into the serviceAccounts REST
// path without a confused-deputy path rewrite (the D73 boundary). Accepts the user
// (name@proj.iam.gserviceaccount.com) and default (num-compute@developer...) forms.
var gsaEmailOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{4,29}@[a-z0-9][a-z0-9.-]{1,61}\.gserviceaccount\.com$`)

// wiMemberRE parses a Workload Identity member back into (poolProject, namespace,
// serviceAccount) — used by discovery to reverse a GSA's IAM policy into pids.
var wiMemberRE = regexp.MustCompile(
	`^serviceAccount:([a-z][-a-z0-9]{4,28}[a-z0-9])\.svc\.id\.goog\[([a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)/([a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)\]$`)

// gkeWIProviderID is the pinned identity:
// gke-wi:<poolProject>:<gsaEmail>:<namespace>:<serviceAccount>. gsaEmail carries no
// ':' so a 5-way SplitN round-trips it; the pool project (not the GSA's project) is
// the FIRST component because it — with namespace/serviceAccount — reconstructs the
// member, while gsaEmail names the GSA whose IAM policy carries the binding.
func gkeWIProviderID(poolProject, gsaEmail, namespace, serviceAccount string) string {
	return "gke-wi:" + poolProject + ":" + gsaEmail + ":" + namespace + ":" + serviceAccount
}

func splitGKEWIProviderID(providerID string) (poolProject, gsaEmail, namespace, serviceAccount string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "gke-wi" {
		return "", "", "", "", fmt.Errorf(
			"providerId %q is not gke-wi:poolProject:gsaEmail:namespace:serviceAccount", providerID)
	}
	poolProject, gsaEmail, namespace, serviceAccount = parts[1], parts[2], parts[3], parts[4]
	if !projectOK.MatchString(poolProject) {
		return "", "", "", "", fmt.Errorf("providerId poolProject %q is invalid", poolProject)
	}
	if !gsaEmailOK.MatchString(gsaEmail) {
		return "", "", "", "", fmt.Errorf("providerId gsaEmail %q is invalid", gsaEmail)
	}
	if !k8sNameOK.MatchString(namespace) {
		return "", "", "", "", fmt.Errorf("providerId namespace %q is invalid", namespace)
	}
	if !k8sNameOK.MatchString(serviceAccount) {
		return "", "", "", "", fmt.Errorf("providerId serviceAccount %q is invalid", serviceAccount)
	}
	return poolProject, gsaEmail, namespace, serviceAccount, nil
}

// wiMember builds the IAM member a Workload Identity binding grants the role to.
func wiMember(poolProject, namespace, serviceAccount string) string {
	return "serviceAccount:" + poolProject + ".svc.id.goog[" + namespace + "/" + serviceAccount + "]"
}

// GKEWorkloadIdentityPlan is the attribute+operand-derived shape a create
// assembles. The IDENTITY (namespace, serviceAccount) is driven by CAPABILITY
// attributes; the GSA and pool project are OPERATOR operands (implementation, D26).
type GKEWorkloadIdentityPlan struct {
	Namespace      string // capability (required)
	ServiceAccount string // capability (required) — the KSA name
	GSAEmail       string // operand (required) — the Google SA whose IAM policy carries the binding
	PoolProject    string // operand (defaults to pinned project) — the WI pool / cluster project
}

// Member is the IAM member this plan binds workloadIdentityUser to.
func (p GKEWorkloadIdentityPlan) Member() string {
	return wiMember(p.PoolProject, p.Namespace, p.ServiceAccount)
}

// BuildGKEWorkloadIdentity maps capability.identity.podidentity attributes +
// implementation operands to a plan, or REFUSES. Every error is a preflight refusal
// (never a half-build): an unmapped attribute, or a missing required
// attribute/operand, is refused here, before the first IAM mutation (D26).
// generation is unused (the identity is namespace+serviceAccount+gsa, not a hash).
func BuildGKEWorkloadIdentity(project, environment, capability string,
	attrs, impl map[string]any, generation int) (GKEWorkloadIdentityPlan, error) {
	p := GKEWorkloadIdentityPlan{}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "workload.namespace":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace must be a non-empty string")
			}
			p.Namespace = strings.TrimSpace(v)
		case "workload.serviceAccount":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount must be a non-empty string")
			}
			p.ServiceAccount = strings.TrimSpace(v)
		case "service.managed":
			if raw != true {
				return GKEWorkloadIdentityPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by Workload Identity (a WI binding IS managed by construction)")
			}
		case "location.region":
			// location.region scopes a discover (not a build input); cost.monthly is
			// a projection — a WI binding is free. Neither reaches the IAM policy.
		default:
			return GKEWorkloadIdentityPlan{}, fmt.Errorf(
				"attribute %s has no GKE Workload Identity mapping — refusing rather than silently dropping it "+
					"(the identity.podidentity vocab governs workload.namespace + workload.serviceAccount)", path)
		}
	}
	if p.Namespace == "" {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace is required")
	}
	if p.ServiceAccount == "" {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount is required")
	}
	if !k8sNameOK.MatchString(p.Namespace) {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace %q is not a valid Kubernetes name", p.Namespace)
	}
	if !k8sNameOK.MatchString(p.ServiceAccount) {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount %q is not a valid Kubernetes name", p.ServiceAccount)
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	// gsaEmail is a REFERENCE (it names a GSA), never key material — safe to carry (D53).
	gsa, _ := impl["gsaEmail"].(string)
	p.GSAEmail = strings.TrimSpace(gsa)
	if p.GSAEmail == "" {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf(
			"implementation.gsaEmail is required (the Google service account the KSA impersonates — a separate identity.serviceaccount capability/operand)")
	}
	if !gsaEmailOK.MatchString(p.GSAEmail) {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf("implementation.gsaEmail %q is not a valid service-account email", p.GSAEmail)
	}
	// clusterProject is the WI pool project (the GKE cluster's project); it defaults
	// to the pinned project for the common same-project case.
	cp, _ := impl["clusterProject"].(string)
	p.PoolProject = strings.TrimSpace(cp)
	if p.PoolProject == "" {
		p.PoolProject = project
	}
	if !projectOK.MatchString(p.PoolProject) {
		return GKEWorkloadIdentityPlan{}, fmt.Errorf(
			"pool project %q (implementation.clusterProject or the pinned project) is invalid", p.PoolProject)
	}
	return p, nil
}

// classifyGKEWorkloadIdentityChange (D46): PURE. namespace + serviceAccount are the
// binding identity (immutable — a different KSA is a different member, a different
// resource, not an in-place patch). gsaEmail / clusterProject are OPERANDS, so a
// change there is a candidate-hash change the compiler handles as a replacement, not
// a vocab attribute reaching here. The rest are platform/projection (unsupported).
func classifyGKEWorkloadIdentityChange(path string) (string, string) {
	switch path {
	case "workload.namespace", "workload.serviceAccount":
		return "immutable", "the namespace/serviceAccount is the WI binding member identity — a different binding is a different resource, not an in-place patch"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GKE Workload Identity in-place mapping for " + path
	}
}
