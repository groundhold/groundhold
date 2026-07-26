// GCP Certificate Manager request building (D117): the semantic core of the GCP
// capability.certificate.tls driver — the SAME vocabulary AWS ACM fulfils (Azure has
// no management-plane twin, so the domain is honestly two-cloud). A managed
// Certificate Manager certificate is DNS-validated (via a DnsAuthorization) and
// auto-renewing. The private KEY never transits groundhold (secrets excluded, D53).
// email validation is REFUSED — Certificate Manager validates via DNS authorization
// or the attached load balancer, never email.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

const certManagerBaseURL = "https://certificatemanager.googleapis.com/v1"

// certIDOK bounds a Certificate Manager certificate id (1-63, lowercase start).
var certIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// certDomainOK bounds a certificate domain (a FQDN; leading wildcard allowed).
var certDomainOK = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// CertManagerCertID is the deterministic certificate id (the idempotency handle).
func CertManagerCertID(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 63)
}

// CertManagerPlan is the attribute-derived shape a create assembles.
type CertManagerPlan struct {
	CertID           string
	Location         string
	Domain           string
	DNSAuthorization string // impl (a DnsAuthorization resource id/path) for DNS validation
}

// BuildCertManager maps capability.certificate.tls attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCertManager(project, environment, capability string,
	attrs, impl map[string]any, generation int) (CertManagerPlan, error) {
	p := CertManagerPlan{CertID: CertManagerCertID(project, environment, capability, generation)}
	validationSet, renewSet := false, false
	autoRenew := false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "domain":
			p.Domain, _ = raw.(string)
			p.Domain = strings.ToLower(strings.TrimSpace(p.Domain))
			if !certDomainOK.MatchString(p.Domain) {
				return CertManagerPlan{}, fmt.Errorf("domain %q is not a valid FQDN", p.Domain)
			}
		case "validation.method":
			validationSet = true
			switch raw {
			case "dns":
				// the only Certificate Manager managed-cert validation this driver wires
			case "email":
				return CertManagerPlan{}, fmt.Errorf(
					"validation.method=email cannot be honored by Certificate Manager — it validates " +
						"via DNS authorization or the attached load balancer, never email")
			default:
				return CertManagerPlan{}, fmt.Errorf("validation.method %v has no Certificate Manager mapping", raw)
			}
		case "auto.renew":
			renewSet = true
			autoRenew, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return CertManagerPlan{}, fmt.Errorf("service.managed=false cannot be honored by Certificate Manager")
			}
		default:
			return CertManagerPlan{}, fmt.Errorf(
				"attribute %s has no Certificate Manager mapping — refusing rather than silently dropping it "+
					"(SANs, key algorithm are implementation detail; the private key never transits groundhold)", path)
		}
	}
	if p.Location == "" {
		return CertManagerPlan{}, fmt.Errorf("certificate requires location.region")
	}
	if p.Domain == "" {
		return CertManagerPlan{}, fmt.Errorf("certificate requires domain")
	}
	if !validationSet {
		return CertManagerPlan{}, fmt.Errorf("certificate requires validation.method (dns | email)")
	}
	if renewSet && !autoRenew {
		return CertManagerPlan{}, fmt.Errorf(
			"auto.renew=false cannot be honored — a Certificate Manager managed certificate auto-renews; " +
				"a self-managed/imported cert is out of this capability's scope")
	}
	// DNS validation needs a DnsAuthorization (a prerequisite resource; topology/impl).
	p.DNSAuthorization, _ = impl["dns_authorization"].(string)
	if p.DNSAuthorization == "" {
		return CertManagerPlan{}, fmt.Errorf(
			"DNS validation requires implementation.dns_authorization (a Certificate Manager " +
				"DnsAuthorization resource that proves control of the domain)")
	}
	if !certIDOK.MatchString(p.CertID) {
		return CertManagerPlan{}, fmt.Errorf("derived certificate id %q is invalid", p.CertID)
	}
	if !projectOK.MatchString(project) {
		return CertManagerPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the certificates.create request body. Ownership is labels.
func (p CertManagerPlan) createBody(capability, environment string) map[string]any {
	return map[string]any{
		"managed": map[string]any{
			"domains":           []any{p.Domain},
			"dnsAuthorizations": []any{p.DNSAuthorization},
		},
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
}
