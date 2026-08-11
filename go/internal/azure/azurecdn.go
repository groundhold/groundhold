// Azure Front Door Standard request building (D118, reimplemented D999): the semantic
// core of the Azure capability.cdn.distribution driver — the SAME vocabulary AWS
// CloudFront fulfils (GCP Cloud CDN is a backend-service flag, not a standalone
// resource, so the domain is honestly two-cloud). The classic "Azure CDN from
// Microsoft" (SKU Standard_Microsoft) was RETIRED for new profiles by Azure, so this
// targets Azure Front Door Standard (SKU Standard_AzureFrontDoor) — the same
// Microsoft.Cdn provider, a richer composite: a profile (SKU + ownership tags) holds
// an origin group + origin (the backend), an afdEndpoint (the edge hostname), and a
// route that ties them together and carries the viewer TLS posture + caching. Custom
// domains are afd customDomains sub-resources with tlsSettings (a managed cert, or a
// BYO Key Vault cert via a profile secret), associated on the route. Invariant #4:
// cache behaviors stay opaque impl config. Unlike classic CDN, AFD honors
// redirect-to-https NATIVELY (the route's httpsRedirect), so it is no longer refused.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const azureCDNAPIVersion = "2023-05-01"

// azCDNDomainOK bounds an origin domain (a FQDN).
var azCDNDomainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// azKVSecretIDOK bounds a Key Vault SECRET resource id — the Azure BYO-cert
// reference (a NAME, never key material, safe to carry; D53). Groups:
// 1=subscription 2=resource group 3=vault 4=secret 5=optional version.
var azKVSecretIDOK = regexp.MustCompile(
	`^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([A-Za-z0-9._()-]{1,90})` +
		`/providers/Microsoft\.KeyVault/vaults/([A-Za-z0-9-]{3,24})/secrets/([A-Za-z0-9-]{1,127})(?:/([0-9a-fA-F]{32}))?$`)

// azKVCertRef is a parsed Key Vault secret reference for a BYO custom-domain cert.
type azKVCertRef struct{ sub, rg, vault, secret, version string }

// AzureCDNPlan is the attribute-derived shape a create assembles into ARM bodies.
type AzureCDNPlan struct {
	Profile      string
	Endpoint     string // the afdEndpoint (edge hostname)
	OriginGroup  string // the origin group holding the backend origin
	Route        string // the route tying endpoint -> origin group
	OriginDomain string
	HTTPAllowed  bool // Http is in the route's supportedProtocols (allow-all / redirect)
	HTTPSAllowed bool // always true — Https is always supported
	Redirect     bool // viewer.protocol=redirect-to-https -> route httpsRedirect Enabled

	// CacheBypass attaches a global CacheExpiration delivery rule that BYPASSES the
	// cache (cache_policy: disabled). Unset keeps Azure's header-honoring default.
	CacheBypass bool

	// Aliases are the custom domain names the endpoint serves under — each becomes a
	// customDomains SUB-RESOURCE (a separate PUT), unlike CloudFront's inline Aliases.
	Aliases []string
	// CertManaged requests an Azure CDN-MANAGED certificate (certificateSource: Cdn) —
	// free, auto-provisioned and auto-renewed by Azure, with NO external cert resource.
	// This is the Azure-native path; AWS has no twin (CloudFront requires a BYO ACM
	// cert). Exactly one of CertManaged / CertKeyVault is set when a certificate is given.
	CertManaged bool
	// CertKeyVault is a BYO certificate stored as a Key Vault secret
	// (certificateSource: AzureKeyVault). Azure has NO capability.certificate.tls twin
	// (it is an honest AWS+GCP two-cloud domain — Key Vault certs are data-plane), so
	// there is nothing to $ref; a BYO cert is a literal Key Vault secret id.
	CertKeyVault *azKVCertRef
}

func azCDNProfileName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-cdn-" + hex.EncodeToString(sum[:])[:12]
}

// BuildAzureCDN maps capability.cdn.distribution attributes to a plan. Every error
// is a refusal apply surfaces in preflight.
func BuildAzureCDN(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureCDNPlan, error) {
	p := AzureCDNPlan{
		Profile:      azCDNProfileName(environment, capability, generation),
		Endpoint:     azResourceName("pv-ep", environment, capability, generation),
		OriginGroup:  azCDNOriginGroup,
		Route:        azCDNRoute,
		HTTPSAllowed: true,
	}
	viewerSet := false

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "origin.domain":
			p.OriginDomain, _ = raw.(string)
			p.OriginDomain = strings.ToLower(strings.TrimSpace(p.OriginDomain))
			if !azCDNDomainOK.MatchString(p.OriginDomain) {
				return AzureCDNPlan{}, fmt.Errorf("origin.domain %q is not a valid FQDN", p.OriginDomain)
			}
		case "viewer.protocol":
			viewerSet = true
			switch raw {
			case "https-only":
				p.HTTPAllowed, p.HTTPSAllowed, p.Redirect = false, true, false
			case "allow-all":
				p.HTTPAllowed, p.HTTPSAllowed, p.Redirect = true, true, false
			case "redirect-to-https":
				// AFD honors this natively: the route accepts Http+Https but its
				// httpsRedirect=Enabled issues a 301 to HTTPS (D999). Classic CDN could
				// not, and refused here.
				p.HTTPAllowed, p.HTTPSAllowed, p.Redirect = true, true, true
			default:
				return AzureCDNPlan{}, fmt.Errorf("viewer.protocol %v has no Azure CDN mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return AzureCDNPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure CDN")
			}
		default:
			return AzureCDNPlan{}, fmt.Errorf(
				"attribute %s has no Azure CDN mapping — refusing rather than silently dropping it "+
					"(cache behaviors, rules, TTLs are opaque implementation config)", path)
		}
	}

	// ---- cache_policy operand (D331): explicit cache control. Azure CDN honors the
	// origin's Cache-Control headers BY DEFAULT (safe for a dynamic origin that sets
	// no-store/no-cache), so unlike AWS there is no dangerous default to fix — the
	// operand adds explicit control only. Closed vocabulary; an unrecognized value
	// refuses. "optimized" is deliberately absent: forcing a fixed TTL is opaque
	// per-path cache tuning (invariant #4), and Azure has no managed cache-policy id
	// to name the way CloudFront's CachingOptimized does. ----
	if raw, has := impl["cache_policy"]; has {
		s, _ := raw.(string)
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "disabled":
			p.CacheBypass = true
		case "honor", "":
			// header-honoring default — no delivery rule
		default:
			return AzureCDNPlan{}, fmt.Errorf(
				"implementation.cache_policy %q is not supported — use \"disabled\" (bypass the cache) or "+
					"\"honor\" (respect the origin's Cache-Control headers, the Azure default)", s)
		}
	}

	// ---- aliases operand (D332): custom domain names. Each becomes a customDomains
	// sub-resource under the endpoint. Every entry is a validated FQDN. ----
	if raw, has := impl["aliases"]; has {
		list, ok := raw.([]any)
		if !ok {
			return AzureCDNPlan{}, fmt.Errorf(
				"implementation.aliases must be a list of domain names, got %T", raw)
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return AzureCDNPlan{}, fmt.Errorf(
					"implementation.aliases entries must be domain strings, got %T", e)
			}
			s = strings.ToLower(strings.TrimSpace(s))
			if !azCDNDomainOK.MatchString(s) {
				return AzureCDNPlan{}, fmt.Errorf("implementation.aliases %q is not a valid FQDN", s)
			}
			p.Aliases = append(p.Aliases, s)
		}
	}

	// ---- certificate operand (D332): the custom-domain TLS binding, enabled via a
	// SEPARATE enableCustomHttps operation (not an inline field like CloudFront's
	// ViewerCertificate). Azure's cert model differs from AWS's fundamentally:
	//   * "managed"  -> an Azure CDN-managed cert (certificateSource: Cdn) — free,
	//     auto-provisioned and auto-renewed, with NO external cert resource. AWS has
	//     no twin (CloudFront requires a BYO ACM cert).
	//   * a Key Vault SECRET resource id -> a BYO cert (certificateSource:
	//     AzureKeyVault). This is Azure's BYO shape; the id is a NAME, never key
	//     material (D53).
	// A $ref to capability.certificate.tls (the AWS shape) is REFUSED: certificate.tls
	// is an honest AWS+GCP two-cloud domain with NO Azure implementation, so there is
	// nothing to reference. ----
	certGiven := false
	if raw, has := impl["certificate"]; has {
		certGiven = true
		switch v := raw.(type) {
		case string:
			s := strings.TrimSpace(v)
			switch {
			case strings.EqualFold(s, "managed"):
				p.CertManaged = true
			case azKVSecretIDOK.MatchString(s):
				m := azKVSecretIDOK.FindStringSubmatch(s)
				p.CertKeyVault = &azKVCertRef{sub: m[1], rg: m[2], vault: m[3], secret: m[4], version: m[5]}
			default:
				return AzureCDNPlan{}, fmt.Errorf(
					"implementation.certificate %q is neither \"managed\" (an Azure CDN-managed cert) nor a "+
						"Key Vault secret resource id (a BYO cert) — Azure has no capability.certificate.tls "+
						"twin to $ref", s)
			}
		default:
			if isAzRefShape(raw) {
				return AzureCDNPlan{}, fmt.Errorf(
					"implementation.certificate is a $ref, but Azure has no capability.certificate.tls " +
						"implementation to reference (it is an AWS+GCP two-cloud domain) — use \"managed\" for " +
						"a free Azure CDN-managed cert, or a Key Vault secret id for a BYO cert")
			}
			return AzureCDNPlan{}, fmt.Errorf(
				"implementation.certificate must be \"managed\" or a Key Vault secret resource id, got %T", raw)
		}
	}

	if p.OriginDomain == "" {
		return AzureCDNPlan{}, fmt.Errorf("cdn distribution requires origin.domain")
	}
	if !viewerSet {
		return AzureCDNPlan{}, fmt.Errorf("cdn distribution requires viewer.protocol")
	}
	// A custom domain should serve HTTPS, which on Azure needs a certificate bound via
	// enableCustomHttps (a custom hostname without one cannot terminate TLS). Require
	// the two together in both directions so neither half is a silent no-op. (Azure
	// technically permits an HTTP-only custom domain; this driver requires a cert as a
	// safe default, mirroring the CloudFront pairing.)
	if len(p.Aliases) > 0 && !certGiven {
		return AzureCDNPlan{}, fmt.Errorf(
			"implementation.aliases requires implementation.certificate — a custom domain should serve " +
				"HTTPS; use certificate: managed for a free Azure CDN-managed cert, or a Key Vault secret id " +
				"for a BYO cert")
	}
	if certGiven && len(p.Aliases) == 0 {
		return AzureCDNPlan{}, fmt.Errorf(
			"implementation.certificate was given but implementation.aliases is empty — a certificate only " +
				"serves custom domains; refusing an ambiguous shape")
	}
	return p, nil
}

// isAzRefShape reports whether v is an unresolved intra-plan $ref operand
// ({$ref:{capability,output}}) — used only to give an honest refusal for a
// certificate $ref (Azure has no certificate.tls producer to reference).
func isAzRefShape(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, has := m["$ref"]
	return has
}

// customDomainResourceName maps a hostname to an ARM child resource name (alnum +
// hyphens): dots become hyphens (api.acme.eu -> api-acme-eu). The host is already
// a validated strict FQDN, so the result is injection-safe for the URL path (D73).
func customDomainResourceName(host string) string {
	return strings.ReplaceAll(host, ".", "-")
}

// cdnChildID builds the ARM resource id of a Microsoft.Cdn/profiles child — the route
// references its origin group by id, and (for aliases) its custom domains by id, so
// the wire needs the full id, not just the name.
func (p AzureCDNPlan) cdnChildID(sub, rg, child string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/%s",
		sub, rg, p.Profile, child)
}

// profileBody is the AFD profile PUT body (the constitutive substrate). SKU
// Standard_AzureFrontDoor — the classic Standard_Microsoft is retired for new profiles.
func (p AzureCDNPlan) profileBody(tags map[string]any) map[string]any {
	return map[string]any{
		"location": "Global",
		"sku":      map[string]any{"name": "Standard_AzureFrontDoor"},
		"tags":     tags,
	}
}

// originGroupBody is the origin group PUT body — load-balancing + health-probe defaults
// for the single backend origin.
func (p AzureCDNPlan) originGroupBody() map[string]any {
	return map[string]any{"properties": map[string]any{
		"loadBalancingSettings": map[string]any{
			"sampleSize":                      4,
			"successfulSamplesRequired":       3,
			"additionalLatencyInMilliseconds": 50,
		},
		"healthProbeSettings": map[string]any{
			"probePath":              "/",
			"probeRequestType":       "HEAD",
			"probeProtocol":          "Https",
			"probeIntervalInSeconds": 100,
		},
	}}
}

// originBody is the origin PUT body — the backend the edge fetches from
// (origin.domain), enabled, with the origin.domain echoed as the host header.
func (p AzureCDNPlan) originBody() map[string]any {
	return map[string]any{"properties": map[string]any{
		"hostName":                    p.OriginDomain,
		"originHostHeader":            p.OriginDomain,
		"httpPort":                    80,
		"httpsPort":                   443,
		"priority":                    1,
		"weight":                      1000,
		"enabledState":                "Enabled",
		"enforceCertificateNameCheck": true,
	}}
}

// afdEndpointBody is the AFD endpoint PUT body — the edge hostname (xxx.azurefd.net).
func (p AzureCDNPlan) afdEndpointBody() map[string]any {
	return map[string]any{
		"location":   "Global",
		"properties": map[string]any{"enabledState": "Enabled"},
	}
}

// routeBody is the route PUT body — it ties the endpoint to the origin group and
// carries the viewer TLS posture (supportedProtocols + httpsRedirect), the caching
// posture (cacheConfiguration present unless cache_policy=disabled), and any custom
// domains. sub/rg are needed to build the origin-group and custom-domain resource ids.
func (p AzureCDNPlan) routeBody(sub, rg string) map[string]any {
	supported := []any{"Https"}
	if p.HTTPAllowed {
		supported = []any{"Http", "Https"}
	}
	redirect := "Disabled"
	if p.Redirect {
		redirect = "Enabled"
	}
	props := map[string]any{
		"originGroup":         map[string]any{"id": p.cdnChildID(sub, rg, "originGroups/"+p.OriginGroup)},
		"supportedProtocols":  supported,
		"patternsToMatch":     []any{"/*"},
		"forwardingProtocol":  "MatchRequest",
		"linkToDefaultDomain": "Enabled",
		"httpsRedirect":       redirect,
		"enabledState":        "Enabled",
	}
	// cache_policy: honor (default) enables caching that respects the origin's
	// Cache-Control headers; disabled omits cacheConfiguration entirely (AFD's default
	// is no caching), the inverse wire of classic CDN's bypass rule.
	if !p.CacheBypass {
		props["cacheConfiguration"] = map[string]any{"queryStringCachingBehavior": "IgnoreQueryString"}
	}
	if len(p.Aliases) > 0 {
		cds := make([]any, 0, len(p.Aliases))
		for _, host := range p.Aliases {
			cds = append(cds, map[string]any{"id": p.cdnChildID(sub, rg, "customDomains/"+customDomainResourceName(host))})
		}
		props["customDomains"] = cds
	}
	return map[string]any{"properties": props}
}

// azCDNSecretName is the deterministic profile-secret name that wraps a BYO Key Vault
// certificate (AFD references a Key Vault cert through a profiles/secrets resource,
// not inline). One secret per distribution — every alias shares the same BYO cert.
func (p AzureCDNPlan) secretName() string {
	return "pv-sec-" + strings.TrimPrefix(p.Endpoint, "pv-ep-")
}

// secretBody is the profiles/secrets PUT body for a BYO Key Vault certificate. The
// secretSource id is the Key Vault SECRET resource id (a NAME, never key material,
// D53); useLatestVersion follows automatically unless a version was pinned.
func (p AzureCDNPlan) secretBody() map[string]any {
	kv := p.CertKeyVault
	params := map[string]any{
		"type": "CustomerCertificate",
		"secretSource": map[string]any{
			"id": fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s/secrets/%s",
				kv.sub, kv.rg, kv.vault, kv.secret),
		},
		"useLatestVersion": kv.version == "",
	}
	if kv.version != "" {
		params["secretVersion"] = kv.version
	}
	return map[string]any{"properties": map[string]any{"parameters": params}}
}

// customDomainBody is the AFD customDomains PUT body — the custom hostname plus its
// tlsSettings. A managed cert (certificate: managed) is certificateType
// ManagedCertificate (free, AFD-provisioned, needs domain validation out of band); a
// BYO cert is certificateType CustomerCertificate referencing the profile secret above.
// sub/rg build the secret id for the BYO case.
func (p AzureCDNPlan) customDomainBody(sub, rg, host string) map[string]any {
	tls := map[string]any{"minimumTlsVersion": "TLS12"}
	if p.CertManaged {
		tls["certificateType"] = "ManagedCertificate"
	} else if p.CertKeyVault != nil {
		tls["certificateType"] = "CustomerCertificate"
		tls["secret"] = map[string]any{"id": p.cdnChildID(sub, rg, "secrets/"+p.secretName())}
	}
	return map[string]any{"properties": map[string]any{
		"hostName":    host,
		"tlsSettings": tls,
	}}
}
