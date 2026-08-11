// AKS Workload Identity driver (D76 parity): the Azure half of
// capability.identity.podidentity — the SAME vocabulary AWS EKS Pod Identity
// (eks_podidentity.go) and GKE Workload Identity (gke_workloadidentity.go)
// fulfil. A Kubernetes serviceAccount (namespace + name) is bound to a
// user-assigned managed identity (UAMI) so pods running as that KSA obtain the
// UAMI's tokens WITHOUT downloadable secrets.
//
// THE AZURE DIFFERENCE vs GCP: on GCP the binding is an IAM policy member on the
// GSA (a read-modify-write of a policy doc — no standalone resource). On Azure it
// is a REAL, separate ARM sub-resource — a federatedIdentityCredential under the
// UAMI:
//
//	Microsoft.ManagedIdentity/userAssignedIdentities/{uami}/federatedIdentityCredentials/{name}
//
// with PUT/GET/DELETE of its own. That makes Azure CLOSER to EKS (a resolvable
// association resource) than to GCP — but keyed by a DETERMINISTIC name, not a
// server-generated id, so no describe-to-resolve step is needed.
//
// The federated credential ties three things together:
//   - issuer    = the AKS cluster's OIDC issuer URL (OPERAND, impl.oidcIssuer)
//   - subject   = system:serviceaccount:<namespace>:<serviceAccount> (CAPABILITY)
//   - audiences = ["api://AzureADTokenExchange"] (the fixed AAD exchange audience)
//
// The UAMI (the target identity) and the OIDC issuer are OPERATOR OPERANDS (impl
// block, D26): the UAMI is a separate capability (identity.serviceaccount =
// managedidentity), the issuer a property of the AKS cluster substrate. A
// federated credential carries NO tags (ARM gives it no tags field), so there is
// NO ownership marker: ownership is proven by the DETERMINISTIC name PLUS a
// content match (subject+issuer+audience) — a name that exists with DIFFERENT
// content is foreign and refused (honest-refuse, like eks-podidentity/gke-wi).
// STATELESS: the credential holds no data; retirement removes only the mapping.
// Four-valued throughout (D29/D87). D53: never read a secret.
package azure

import (
	"fmt"
	"regexp"
	"strings"
)

// federatedCredentialAPIVersion is the ARM api-version for
// Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials
// (shares the managed-identity provider version).
const federatedCredentialAPIVersion = "2023-01-31"

// aksWIAudience is the ONE audience an AKS workload-identity federated credential
// uses — the fixed AAD token-exchange audience. Nothing else is workload identity.
const aksWIAudience = "api://AzureADTokenExchange"

// aksK8sNameOK bounds a Kubernetes namespace / serviceAccount name (RFC1123
// label): lowercase alnum + hyphen, start/end alnum, <=63. This is also a SECURITY
// boundary — the value is placed into the subject string and the providerId, and
// must never carry ':' that would let a forged pid or subject rewrite the split.
var aksK8sNameOK = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// oidcIssuerOK bounds the AKS OIDC issuer URL before it enters the ARM body: an
// https URL with no whitespace/quotes/control chars, length-bounded. The issuer
// rides in the JSON body (not the URL path), but a strict shape keeps a malformed
// operand from silently landing.
var oidcIssuerOK = regexp.MustCompile(`^https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,1000}$`)

// uamiResourceIDRE parses a UAMI ARM resource id into (sub, rg, uami) so an
// operator may pass a single impl.uamiResourceId instead of uamiName + rg.
var uamiResourceIDRE = regexp.MustCompile(
	`^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([A-Za-z0-9._()-]{1,90})/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])$`)

// aksWIProviderID is the pinned identity:
// aks-wi:<sub>:<rg>:<uami>:<credentialName>. The credential name is deterministic
// (derived from capability+environment), so the pid is knowable BEFORE the PUT
// (D29); the subject (namespace/serviceAccount) is recovered by reading the
// credential back, never re-encoded into the pid.
func aksWIProviderID(sub, rg, uami, credentialName string) string {
	return "aks-wi:" + sub + ":" + rg + ":" + uami + ":" + credentialName
}

func splitAKSWIProviderID(providerID string) (sub, rg, uami, credentialName string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "aks-wi" {
		return "", "", "", "", fmt.Errorf(
			"providerId %q is not aks-wi:sub:rg:uami:credentialName", providerID)
	}
	sub, rg, uami, credentialName = parts[1], parts[2], parts[3], parts[4]
	if !subOK.MatchString(sub) {
		return "", "", "", "", fmt.Errorf("providerId subscription %q is invalid", sub)
	}
	if !rgOK.MatchString(rg) {
		return "", "", "", "", fmt.Errorf("providerId resource group %q is invalid", rg)
	}
	if !azNameOK.MatchString(uami) {
		return "", "", "", "", fmt.Errorf("providerId uami %q is invalid", uami)
	}
	if !azNameOK.MatchString(credentialName) {
		return "", "", "", "", fmt.Errorf("providerId credentialName %q is invalid", credentialName)
	}
	return sub, rg, uami, credentialName, nil
}

// ficSubject builds the OIDC subject a federated credential matches — the exact
// string Kubernetes puts in the projected serviceAccount token's `sub` claim.
func ficSubject(namespace, serviceAccount string) string {
	return "system:serviceaccount:" + namespace + ":" + serviceAccount
}

// parseFICSubject reverses a subject back into (namespace, serviceAccount). ok is
// false for any subject that is not a well-formed system:serviceaccount:<ns>:<sa>
// with RFC1123 labels — discovery/observe then skips the reverse map rather than
// fabricating a namespace.
func parseFICSubject(subject string) (namespace, serviceAccount string, ok bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(subject, prefix) {
		return "", "", false
	}
	rest := subject[len(prefix):]
	ns, sa, found := strings.Cut(rest, ":")
	if !found || !aksK8sNameOK.MatchString(ns) || !aksK8sNameOK.MatchString(sa) {
		return "", "", false
	}
	return ns, sa, true
}

// AKSWorkloadIdentityPlan is the attribute+operand-derived shape a create
// assembles. The IDENTITY (namespace, serviceAccount) is driven by CAPABILITY
// attributes; the UAMI, its resource group and the OIDC issuer are OPERATOR
// operands (implementation: block, D26). CredentialName is deterministic.
type AKSWorkloadIdentityPlan struct {
	Namespace      string // capability (required)
	ServiceAccount string // capability (required)
	Subscription   string // the credential's subscription (driver's / uamiResourceId's)
	ResourceGroup  string // operand — the UAMI's resource group
	UAMIName       string // operand — the user-assigned managed identity name
	OIDCIssuer     string // operand — the AKS cluster OIDC issuer URL
	CredentialName string // deterministic federatedIdentityCredential name
}

// Subject is the OIDC subject this plan's federated credential matches.
func (p AKSWorkloadIdentityPlan) Subject() string {
	return ficSubject(p.Namespace, p.ServiceAccount)
}

// BuildAKSWorkloadIdentity maps capability.identity.podidentity attributes +
// implementation operands to a plan, or REFUSES. Every error is a preflight
// refusal (never a half-build): an unmapped attribute, or a missing required
// attribute/operand, is refused here, before the first ARM mutation (D26).
// The UAMI target may be given as impl.uamiResourceId (a full ARM id) OR as
// impl.uamiName + impl.resource_group. The credential name is deterministic
// (capability+environment+generation), so a replacement (D48) coexists with its
// predecessor under the same UAMI.
func BuildAKSWorkloadIdentity(subscription, environment, capability string,
	attrs, impl map[string]any, generation int) (AKSWorkloadIdentityPlan, error) {
	p := AKSWorkloadIdentityPlan{CredentialName: azResourceName("fic", environment, capability, generation)}
	for _, path := range sortedAttrKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "workload.namespace":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace must be a non-empty string")
			}
			p.Namespace = strings.TrimSpace(v)
		case "workload.serviceAccount":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount must be a non-empty string")
			}
			p.ServiceAccount = strings.TrimSpace(v)
		case "service.managed":
			if raw != true {
				return AKSWorkloadIdentityPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by AKS Workload Identity (a federated credential IS managed by construction)")
			}
		case "location.region":
			// location.region scopes a discover (not a build input); cost.monthly is a
			// projection — a federated credential is free. Neither enters the ARM body.
		default:
			return AKSWorkloadIdentityPlan{}, fmt.Errorf(
				"attribute %s has no AKS Workload Identity mapping — refusing rather than silently dropping it "+
					"(the identity.podidentity vocab governs workload.namespace + workload.serviceAccount)", path)
		}
	}
	if p.Namespace == "" {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace is required")
	}
	if p.ServiceAccount == "" {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount is required")
	}
	if !aksK8sNameOK.MatchString(p.Namespace) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.namespace %q is not a valid Kubernetes name", p.Namespace)
	}
	if !aksK8sNameOK.MatchString(p.ServiceAccount) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("workload.serviceAccount %q is not a valid Kubernetes name", p.ServiceAccount)
	}
	if !azNameOK.MatchString(p.CredentialName) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("derived federated credential name %q is invalid", p.CredentialName)
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	// The UAMI target: a full ARM id (which carries sub+rg+uami) OR uamiName + rg.
	if rid := strings.TrimSpace(implStringAz(impl, "uamiResourceId")); rid != "" {
		m := uamiResourceIDRE.FindStringSubmatch(rid)
		if m == nil {
			return AKSWorkloadIdentityPlan{}, fmt.Errorf(
				"implementation.uamiResourceId %q is not a valid userAssignedIdentities ARM id", rid)
		}
		p.Subscription, p.ResourceGroup, p.UAMIName = m[1], m[2], m[3]
	} else {
		p.UAMIName = strings.TrimSpace(implStringAz(impl, "uamiName"))
		p.ResourceGroup = strings.TrimSpace(implStringAz(impl, "resource_group"))
		p.Subscription = subscription
		if p.UAMIName == "" {
			return AKSWorkloadIdentityPlan{}, fmt.Errorf(
				"implementation.uamiName is required (the user-assigned managed identity the workload assumes — " +
					"a separate identity.serviceaccount capability/operand), or pass implementation.uamiResourceId")
		}
		if p.ResourceGroup == "" {
			return AKSWorkloadIdentityPlan{}, fmt.Errorf(
				"implementation.resource_group is required (the UAMI's resource group)")
		}
	}
	if !subOK.MatchString(p.Subscription) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("subscription %q is not a valid GUID", p.Subscription)
	}
	if !rgOK.MatchString(p.ResourceGroup) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("resource group %q is invalid", p.ResourceGroup)
	}
	if !azNameOK.MatchString(p.UAMIName) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("uami name %q is invalid", p.UAMIName)
	}
	// oidcIssuer is a REFERENCE (an AKS cluster property), never key material (D53).
	p.OIDCIssuer = strings.TrimSpace(implStringAz(impl, "oidcIssuer"))
	if p.OIDCIssuer == "" {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf(
			"implementation.oidcIssuer is required (the AKS cluster's OIDC issuer URL — a property of the cluster substrate)")
	}
	if !oidcIssuerOK.MatchString(p.OIDCIssuer) {
		return AKSWorkloadIdentityPlan{}, fmt.Errorf("implementation.oidcIssuer %q is not a valid https issuer URL", p.OIDCIssuer)
	}
	return p, nil
}

// classifyAKSWorkloadIdentityChange (D46): PURE. namespace + serviceAccount are
// the credential's subject identity (immutable — a different subject is a
// different binding, a different resource, not an in-place patch). The UAMI and
// the OIDC issuer are OPERANDS, so a change there is a candidate-hash change the
// compiler handles as a replacement, not a vocab attribute reaching here. The rest
// are platform/projection (unsupported). There is deliberately NO Update path
// wired for this service (immutable/replace-only, like eks-podidentity/gke-wi).
func classifyAKSWorkloadIdentityChange(path string) (string, string) {
	switch path {
	case "workload.namespace", "workload.serviceAccount":
		// D831: "a different binding is a different resource" is true on the twins, whose
		// providerId ENCODES the namespace and the service account — change one and the id
		// addresses something else. This driver is the exception, and says so twelve lines
		// above: the credential name is derived from capability+environment and "the subject
		// (namespace/serviceAccount) is recovered by reading the credential back, never
		// re-encoded into the pid". So the resource is the same resource, and its subject is
		// a property Azure updates with a PUT (federatedIdentityCredentials has PUT at the
		// pinned api-version; its properties are issuer, subject, audiences).
		return "unsupported", "in-place subject change is not wired for AKS Workload " +
			"Identity in this slice — Azure does support it (the federated credential's " +
			"subject is set by a PUT on the SAME credential, whose name this driver derives " +
			"from capability+environment rather than from the subject), so this is a gap in " +
			"groundhold rather than a different resource"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no AKS Workload Identity in-place mapping for " + path
	}
}

// implStringAz reads a string operand from the impl block ("" when absent/typed
// wrong) — the local mirror of the AWS driver's implString, so this driver stays
// self-contained within the azure package.
func implStringAz(impl map[string]any, key string) string {
	if impl == nil {
		return ""
	}
	s, _ := impl[key].(string)
	return s
}
