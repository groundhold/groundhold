// ACM request building (D117): the semantic core of the AWS capability.certificate.tls
// driver — the SAME vocabulary GCP Certificate Manager fulfils (Azure has no
// management-plane twin, so the domain is honestly two-cloud). AWS Certificate
// Manager issues a public, DNS-validated, auto-renewing TLS certificate. The
// certificate's PRIVATE KEY never transits groundhold (secrets excluded, D53). SANs and
// key algorithm are implementation detail; the domain, validation method and
// auto-renewal are the capability.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// acmDomainOK bounds a certificate domain (a FQDN; a leading wildcard is allowed).
var acmDomainOK = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ACMPlan is the attribute-derived shape a create assembles.
type ACMPlan struct {
	Domain           string
	ValidationDNS    bool // true = DNS validation, false = EMAIL
	AutoRenew        bool
	IdempotencyToken string
}

// BuildACM maps capability.certificate.tls attributes to a plan. Every error is a
// preflight refusal, never a silent drop.
func BuildACM(environment, capability string,
	attrs, impl map[string]any, generation int) (ACMPlan, error) {
	p := ACMPlan{
		ValidationDNS:    true,
		IdempotencyToken: "pv" + letterHash(environment+"|"+capability+genSuffix(generation), 24),
	}
	validationSet, renewSet := false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "domain":
			p.Domain, _ = raw.(string)
			p.Domain = strings.ToLower(strings.TrimSpace(p.Domain))
			if !acmDomainOK.MatchString(p.Domain) {
				return ACMPlan{}, fmt.Errorf("domain %q is not a valid FQDN", p.Domain)
			}
		case "validation.method":
			validationSet = true
			switch raw {
			case "dns":
				p.ValidationDNS = true
			case "email":
				p.ValidationDNS = false
			default:
				return ACMPlan{}, fmt.Errorf("validation.method %v has no ACM mapping", raw)
			}
		case "auto.renew":
			renewSet = true
			p.AutoRenew, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return ACMPlan{}, fmt.Errorf("service.managed=false cannot be honored by ACM")
			}
		default:
			return ACMPlan{}, fmt.Errorf(
				"attribute %s has no ACM mapping — refusing rather than silently dropping it "+
					"(SANs, key algorithm are implementation detail; the private key never transits groundhold)", path)
		}
	}
	if p.Domain == "" {
		return ACMPlan{}, fmt.Errorf("certificate requires domain")
	}
	if !validationSet {
		return ACMPlan{}, fmt.Errorf("certificate requires validation.method (dns | email)")
	}
	// a managed certificate auto-renews by definition; false is a self-managed cert.
	if renewSet && !p.AutoRenew {
		return ACMPlan{}, fmt.Errorf(
			"auto.renew=false cannot be honored — a managed ACM certificate auto-renews; a " +
				"manually-renewed/imported cert is self-managed, out of this capability's scope")
	}
	// auto-renewal requires DNS validation (email-validated ACM certs do not renew).
	if !p.ValidationDNS && (p.AutoRenew || renewSet) {
		return ACMPlan{}, fmt.Errorf(
			"auto.renew requires validation.method=dns — an email-validated ACM certificate " +
				"cannot auto-renew")
	}
	return p, nil
}

// createBody is the RequestCertificate request body. Ownership is tags.
func (p ACMPlan) createBody(capability, environment string) map[string]any {
	method := "DNS"
	if !p.ValidationDNS {
		method = "EMAIL"
	}
	return map[string]any{
		"DomainName":       p.Domain,
		"ValidationMethod": method,
		"KeyAlgorithm":     "RSA_2048",
		"IdempotencyToken": p.IdempotencyToken,
		"Tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
}
