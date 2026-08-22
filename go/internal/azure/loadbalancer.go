// Azure load balancer reverse map (read-only slice): the pure, network-free half
// of the capability.network.loadbalancer driver. Two honest ARM shapes fulfil the
// SAME vocabulary at two OSI layers, and the reverse map never conflates them:
//
//   - Microsoft.Network/loadBalancers (L4): a frontendIPConfiguration carrying a
//     publicIPAddress ⇒ network.publicExposure=true (a public front door). An L4
//     balancer FORWARDS packets — it never terminates TLS — so encryption.inTransit
//     is FALSE by construction of the type. That is the honest answer, not a faked
//     true: TLS on an L4 balancer simply does not live here.
//   - Microsoft.Network/applicationGateways (L7): a public frontend ⇒
//     publicExposure=true, and an httpListener with protocol=Https ⇒
//     encryption.inTransit=true — L7 is where TLS termination actually lives.
//
// service.managed is always true: both are managed cloud load balancers, not a
// self-operated haproxy/nginx. This file is pure — it maps an already-parsed ARM
// document to observations; the shell (loadbalancer_net.go) does the bearer GET.
package azure

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// AppGatewayPlan is the provisioning shape of the L7 Application Gateway — the
// HONEST composite that fulfils BOTH governed attributes: a public frontend IP
// (network.publicExposure) and an Https listener with an SSL certificate
// REFERENCE (encryption.inTransit). One ARM PUT carries the whole internal
// composite (frontend IP config, frontend port, http listener, backend pool,
// backend http settings, request routing rule) — no multi-resource ordering.
//
// ATTRIBUTES drive SHAPE (D26): publicExposure=true -> a public frontend;
// inTransit=true -> an Https listener + SSL cert. OPERANDS supply the substrate
// groundhold does not create: the subnet, the public IP, the cert REFERENCE (a Key
// Vault secret id — never cert bytes), the backend targets. A required operand
// missing is a REFUSAL (never a half-built, exposed front door).
type AppGatewayPlan struct {
	Name        string
	Region      string
	Environment string
	Capability  string

	Public    bool // network.publicExposure -> a public frontend IP
	InTransit bool // encryption.inTransit -> an Https listener + SSL cert

	SubnetID string // impl.subnetId — the gateway's subnet (always required)
	PublicIP string // impl.publicIpId — an existing public IP (required iff public)
	CertRef  string // impl.sslCertificateId — a Key Vault secret id (required iff inTransit)
	SKU      string // impl.sku (default Standard_v2)
	Port     int64  // impl.port (default 443 for Https, 80 for Http)

	BackendFQDNs []string // impl.backendFqdns — pool targets (fqdn)
	BackendIPs   []string // impl.backendIps — pool targets (ipAddress)
}

func appGatewayName(environment, capability string, generation int) string {
	return azResourceName("pv-agw", environment, capability, generation)
}

// BuildAppGateway maps capability.network.loadbalancer attributes + candidate
// operands to an Application Gateway plan. Every error is a REFUSAL apply
// surfaces in preflight — the driver never half-builds an exposed gateway.
func BuildAppGateway(environment, capability string,
	attrs, impl map[string]any, generation int) (AppGatewayPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AppGatewayPlan{
		Environment: environment, Capability: capability,
		Name: appGatewayName(environment, capability, generation),
		SKU:  "Standard_v2",
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.inTransit":
			p.InTransit, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return AppGatewayPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored: an Application Gateway is a managed load balancer")
			}
		default:
			return AppGatewayPlan{}, fmt.Errorf(
				"attribute %s has no Azure Application Gateway mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}

	// operands (the substrate groundhold does not create).
	p.SubnetID, _ = impl["subnetId"].(string)
	p.PublicIP, _ = impl["publicIpId"].(string)
	p.CertRef, _ = impl["sslCertificateId"].(string)
	if s, ok := impl["sku"].(string); ok && s != "" {
		p.SKU = s
	}
	p.BackendFQDNs = toStringSlice(impl["backendFqdns"])
	p.BackendIPs = toStringSlice(impl["backendIps"])
	if v, ok := asInt64(impl["port"]); ok {
		p.Port = v
	}

	if p.Region == "" {
		return AppGatewayPlan{}, fmt.Errorf("azure application gateway requires location.region")
	}
	// subnet is ALWAYS required — an Application Gateway lives in a dedicated subnet.
	if p.SubnetID == "" {
		return AppGatewayPlan{}, fmt.Errorf(
			"azure application gateway requires implementation.subnetId (the gateway's dedicated subnet)")
	}
	// public=true REQUIRES a public IP — refuse rather than half-build a front door.
	if p.Public && p.PublicIP == "" {
		return AppGatewayPlan{}, fmt.Errorf(
			"network.publicExposure=true requires implementation.publicIpId (an existing public IP) " +
				"— refusing to half-build an exposed gateway without its front door")
	}
	// inTransit=true REQUIRES an SSL certificate REFERENCE (a Key Vault secret id) —
	// an Https listener without a cert is not a valid gateway. The reference is
	// NEVER the cert bytes (secrets are excluded from the request body).
	if p.InTransit && p.CertRef == "" {
		return AppGatewayPlan{}, fmt.Errorf(
			"encryption.inTransit=true requires implementation.sslCertificateId (a Key Vault secret " +
				"id — a REFERENCE, never the certificate bytes) for the Https listener — refusing to " +
				"build an Https listener with no certificate")
	}
	if p.Port == 0 {
		if p.InTransit {
			p.Port = 443
		} else {
			p.Port = 80
		}
	}
	return p, nil
}

// toStringSlice coerces a free-form impl value ([]any of strings, or a single
// string) into a []string, dropping non-strings — the candidate block is D26
// free-form so both shapes appear in the wild.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	}
	return 0, false
}

// lbDoc is the L4 loadBalancers projection: only the frontend public-IP presence
// governs exposure. Sizing, backend pools, load-balancing rules and health probes
// are operational noise the vocabulary deliberately excludes.
type lbDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		FrontendIPConfigurations []struct {
			Properties struct {
				PublicIPAddress *struct {
					ID string `json:"id"`
				} `json:"publicIPAddress"`
			} `json:"properties"`
		} `json:"frontendIPConfigurations"`
	} `json:"properties"`
}

// agwDoc is the L7 applicationGateways projection: frontend public-IP presence for
// exposure AND httpListeners protocol for TLS termination (the L4 shape has no
// listeners — the reverse map keeps the two types apart).
type agwDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		FrontendIPConfigurations []struct {
			Properties struct {
				PublicIPAddress *struct {
					ID string `json:"id"`
				} `json:"publicIPAddress"`
			} `json:"properties"`
		} `json:"frontendIPConfigurations"`
		HTTPListeners []struct {
			Name       string `json:"name"`
			Properties struct {
				Protocol string `json:"protocol"`
			} `json:"properties"`
		} `json:"httpListeners"`
		// D1195: the routing rules are read so a plaintext listener that ONLY
		// redirects to HTTPS is not counted against the gateway. Without them the
		// only honest rule would be "every listener must be Https", which reports
		// NOT-encrypted over the ordinary and correct shape of an :80 listener whose
		// single job is to send the caller to :443.
		RequestRoutingRules []struct {
			Properties struct {
				HTTPListener struct {
					ID string `json:"id"`
				} `json:"httpListener"`
				RedirectConfiguration *struct {
					ID string `json:"id"`
				} `json:"redirectConfiguration"`
			} `json:"properties"`
		} `json:"requestRoutingRules"`
		RedirectConfigurations []struct {
			Name       string `json:"name"`
			Properties struct {
				TargetListener *struct {
					ID string `json:"id"`
				} `json:"targetListener"`
				TargetURL string `json:"targetUrl"`
			} `json:"properties"`
		} `json:"redirectConfigurations"`
	} `json:"properties"`
}

// reverseMapLoadBalancer maps an L4 loadBalancer to the three governed attributes.
// inTransit is false BY CONSTRUCTION: an L4 balancer does not terminate TLS.
func reverseMapLoadBalancer(doc lbDoc) []provider.Observation {
	public := false
	for _, f := range doc.Properties.FrontendIPConfigurations {
		if f.Properties.PublicIPAddress != nil && f.Properties.PublicIPAddress.ID != "" {
			public = true
		}
	}
	return []provider.Observation{
		{Path: "network.publicExposure", Value: public, Derivation: "measured"},
		// An L4 load balancer forwards packets; it never terminates TLS. inTransit
		// is false by construction of the type — honest, not a fabricated true.
		{Path: "encryption.inTransit", Value: false, Derivation: "platform-invariant"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
}

// agwAllListenersEncrypted reports whether EVERY listener on the gateway is a TLS
// front door, or a plaintext listener whose ONLY routing rule redirects to HTTPS —
// i.e. there is no cleartext data path into the backend.
//
// D1195. The rule was "ANY listener speaks Https", so a gateway with an Http:80
// listener forwarding cleartext AND an Https:443 listener reported
// encryption.inTransit=true. That is a floored security posture (the `encryption.`
// namespace), which means the audit certifies it as WITNESSED — so the false-green
// was not merely a wrong field, it was a wrong field the audit was built to trust.
//
// This is the same defect D1186 fixed for the AWS load balancer and D1193 for the
// CDN's cache behaviors, and it is the same fix: ask every element and let the
// weakest one answer. It survived in this driver because that sweep changed only the
// files where the bug was found. The question that turns one fix into three is "was
// this applied to the siblings" — GCP was checked too and is clean BY CONSTRUCTION,
// because there a forwarding rule IS the capability, so a :80 rule and a :443 rule
// are two capabilities and each is measured on its own.
//
// An EMPTY listener set is not encrypted: there is no TLS front door to speak of.
func agwAllListenersEncrypted(doc agwDoc) bool {
	if len(doc.Properties.HTTPListeners) == 0 {
		return false
	}
	// redirect targets, by the listener id their rule points at
	redirectsToTLS := map[string]bool{}
	byName := map[string]string{} // redirectConfiguration name -> target listener id/url
	tlsListener := map[string]bool{}
	for _, l := range doc.Properties.HTTPListeners {
		if strings.EqualFold(l.Properties.Protocol, "Https") {
			tlsListener[strings.ToLower(l.Name)] = true
		}
	}
	for _, rc := range doc.Properties.RedirectConfigurations {
		target := rc.Properties.TargetURL
		if rc.Properties.TargetListener != nil {
			target = rc.Properties.TargetListener.ID
		}
		byName[strings.ToLower(rc.Name)] = target
	}
	for _, r := range doc.Properties.RequestRoutingRules {
		if r.Properties.RedirectConfiguration == nil {
			continue
		}
		target := byName[strings.ToLower(armLeaf(r.Properties.RedirectConfiguration.ID))]
		// A redirect counts only when it lands on TLS: a listener this gateway
		// serves over Https, or an absolute https:// URL. A redirect to another
		// plaintext listener is not a TLS front door.
		ok := strings.HasPrefix(strings.ToLower(target), "https://")
		if !ok && tlsListener[strings.ToLower(armLeaf(target))] {
			ok = true
		}
		if ok {
			redirectsToTLS[strings.ToLower(armLeaf(r.Properties.HTTPListener.ID))] = true
		}
	}
	for _, l := range doc.Properties.HTTPListeners {
		name := strings.ToLower(l.Name)
		if tlsListener[name] || redirectsToTLS[name] {
			continue
		}
		return false
	}
	return true
}

// armLeaf is the last segment of an ARM resource id ("/.../httpListeners/l1" -> "l1").
// A bare name passes through unchanged, so callers may hand it either shape.
func armLeaf(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

// reverseMapAppGateway maps an L7 applicationGateway: exposure from the public
// frontend, inTransit MEASURED from an HTTPS listener (this is where TLS lives).
func reverseMapAppGateway(doc agwDoc) []provider.Observation {
	public := false
	for _, f := range doc.Properties.FrontendIPConfigurations {
		if f.Properties.PublicIPAddress != nil && f.Properties.PublicIPAddress.ID != "" {
			public = true
		}
	}
	https := agwAllListenersEncrypted(doc)
	return []provider.Observation{
		{Path: "network.publicExposure", Value: public, Derivation: "measured"},
		{Path: "encryption.inTransit", Value: https, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
}
